//
//  LQQuicSession.cpp
//  LQVideoCore
//
//  Created by wb_Leo1 on 2019/2/19.
//  Copyright © 2019 LQVideoCore. All rights reserved.
//

#include "LQQuicSession.hpp"
#include <crypto/openssl_util.h>
#include <net/third_party/quic/core/tls_client_handshaker.h>
#include <net/cert/cert_verifier.h>
#include <net/cert/ct_policy_enforcer.h>
#include <net/cert/multi_log_ct_verifier.h>
#include <net/http/transport_security_state.h>
#include <net/third_party/quic/core/quic_utils.h>

//#include <net/third_party/quic/platform/api/quic_default_proof_providers.h>

LQQUIC_NAMESPACE_BEGIN
    
LQQuicSession::LQQuicSession(quic::QuicConnection* connection, const quic::QuicConfig& quic_config, QuicCryptoClientConfig* crypto_config, const QuicServerId& server_id)
    :quic::QuicSession(connection, &mSessionVisitor, quic_config, quic::CurrentSupportedVersions()), server_id_(server_id),crypto_config_(crypto_config)
{
    connection->set_debug_visitor(&quicTraceVisitor);
//    connection_ = std::move(connection);
//    insecureProofVerifier.reset(new InsecureProofVerifier());
//    crypto::EnsureOpenSSLInit();
    // = new quic::QuicCryptoClientConfig(std::move(insecureProofVerifier), quic::TlsClientHandshaker::CreateSslCtx());
//    ssl_config->GetCertVerifyFlags();
    
    // For secure QUIC we need to verify the cert chain.
//    std::unique_ptr<net::CertVerifier> cert_verifier(net::CertVerifier::CreateDefault());
//    std::unique_ptr<net::TransportSecurityState> transport_security_state(
//                                                                     new net::TransportSecurityState);
//    std::unique_ptr<net::MultiLogCTVerifier> ct_verifier(new net::MultiLogCTVerifier());
//    std::unique_ptr<net::CTPolicyEnforcer> ct_policy_enforcer(
//                                                              new net::DefaultCTPolicyEnforcer());
    
//    std::unique_ptr<quic::ProofVerifier> defProofVerifier = quic::CreateDefaultProofVerifier();
    
    cryptoClientStream = std::make_unique<quic::QuicCryptoClientStream>(
                                           server_id_, this,
                                           crypto_config_->proof_verifier()->CreateDefaultContext(), crypto_config_,
                                           this);
}

#pragma mark ----- overrride -----
quic::QuicStream* LQQuicSession::CreateIncomingStream(quic::QuicStreamId id)
{
    LOGD("CreateIncomingStream, call StreamId:%u", id);
    if (!ShouldCreateIncomingStream(id)) {
        return nullptr;
    }
    LQQuicStream* stream = new LQQuicStream(id, this, false, READ_UNIDIRECTIONAL);
    ActivateStream(QuicWrapUnique(stream));
    return stream;
}
quic::QuicStream* LQQuicSession::CreateIncomingStream(quic::PendingStream pending)
{
    LOGD(" not implemention !!!");
    return nullptr;
}

// Return the reserved crypto stream.
quic::QuicCryptoStream* LQQuicSession::GetMutableCryptoStream()
{
    LOGD("GetMutableCryptoStream, call ");
    return cryptoClientStream.get();
}

// Return the reserved crypto stream as a constant pointer.
const quic::QuicCryptoStream* LQQuicSession::GetCryptoStream() const
{
    LOGD("GetCryptoStream, call ");
    return cryptoClientStream.get();
}

void LQQuicSession::Initialize()
{
    QuicSession::Initialize();
    bool isConnected = CryptoConnect();
    LOGD("Initialize, call isConnected = %d", isConnected);
}

#pragma mark ----- QuicCryptoClientStream::ProofHandler ------

void LQQuicSession::OnProofValid( const QuicCryptoClientConfig::CachedState& cached)
{
    LOGD("OnProofValid, call ");
}

void LQQuicSession::OnProofVerifyDetailsAvailable( const ProofVerifyDetails& verify_details)
{
    LOGD("OnProofVerifyDetailsAvailable, call ");
}

#pragma mark ----- interface -----
bool LQQuicSession::CryptoConnect()
{
    return cryptoClientStream->CryptoConnect();
}

quic::QuicStream* LQQuicSession::CreateOutgoingBidirectionalStream()
{
    if (!ShouldCreateOutgoingBidirectionalStream()) {
        return nullptr;
    }
    QuicStreamId outStreamId = GetNextOutgoingBidirectionalStreamId();
#if 1
    // dynamic stream
    std::unique_ptr<LQQuicStream> newStream = std::make_unique<LQQuicStream>(outStreamId, this, false, BIDIRECTIONAL);
    quic::QuicStream* stream_ptr = newStream.get();
    ActivateStream(std::move(newStream));
#else
    // static stream
    std::unique_ptr<LQQuicStream> newStream = std::make_unique<LQQuicStream>(outStreamId, this, true, BIDIRECTIONAL);
    quic::QuicStream* stream_ptr = newStream.get();
#endif
    LOGD("CreateOutgoingBidirectionalStream StreamId = %u", outStreamId);
    
    if (newStream) {
        newStream->SetPriority(QuicStream::kDefaultPriority);
//        newStream->set_visitor(this);
        newStream->setDataVisitor(this);
    }
    
    return stream_ptr;
}

#pragma mark ----- private method -----
bool LQQuicSession::ShouldCreateIncomingStream(QuicStreamId id) {
    if (!connection()->connected()) {
        LOGD("ShouldCreateIncomingStream called when disconnected");
        return false;
    }
    if (goaway_received()) {
        LOGD("Failed to create a new outgoing stream. Already received goaway.");
        return false;
    }
    if (QuicUtils::IsClientInitiatedStreamId(connection()->transport_version(),
                                             id) ||
        (connection()->transport_version() == QUIC_VERSION_99 &&
         QuicUtils::IsBidirectionalStreamId(id))) {
            LOGD("Received invalid push stream id = %u", id);
            connection()->CloseConnection(
                                          QUIC_INVALID_STREAM_ID,
                                          "Server created non write unidirectional stream",
                                          ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
            return false;
        }
    return true;
}

bool LQQuicSession::ShouldCreateOutgoingBidirectionalStream() {
    if (!cryptoClientStream->encryption_established()) {
        LOGD("Encryption not active so no outgoing stream created.");
        return false;
    }
    if (!GetQuicReloadableFlag(quic_use_common_stream_check) &&
        connection()->transport_version() != QUIC_VERSION_99) {
        if (GetNumOpenOutgoingStreams() >=
            stream_id_manager().max_open_outgoing_streams()) {
            LOGD("Failed to create a new outgoing stream. Already = %lu open.", GetNumOpenOutgoingStreams());
            return false;
        }
        if (goaway_received()) {
            LOGD("Failed to create a new outgoing stream. Already received goaway.");
            return false;
        }
        return true;
    }
    if (goaway_received()) {
        LOGD("Failed to create a new outgoing stream. Already received goaway.");
        return false;
    }
//    QUIC_RELOADABLE_FLAG_COUNT_N(quic_use_common_stream_check, 1, 2);
    return CanOpenNextOutgoingBidirectionalStream();
}

bool LQQuicSession::OnPacket(const quic::QuicStringPiece packet,
                                  const quic::QuicStreamId streamId){
    if(dataVisitor){
        return dataVisitor->OnPacket(packet, streamId, this);
    }
    return true;
}

LQQUIC_NAMESPACE_END

