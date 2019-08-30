//
//  LQQuicSeverSession.cpp
//  quicServer
//
//  Created by yajun18 on 2019/8/22.
//  Copyright © 2019 wb_Leo1. All rights reserved.
//

#include "LQQuicSeverSession.hpp"

#include "LQQuicStream.hpp"
#include <crypto/openssl_util.h>
#include <net/third_party/quic/core/tls_client_handshaker.h>
#include <net/cert/cert_verifier.h>
#include <net/cert/ct_policy_enforcer.h>
#include <net/cert/multi_log_ct_verifier.h>
#include <net/http/transport_security_state.h>
#include <net/third_party/quic/core/quic_utils.h>

//#include <net/third_party/quic/platform/api/quic_default_proof_providers.h>
//bool FLAGS_quic_reloadable_flag_enable_quic_stateless_reject_support = true
LQQUIC_NAMESPACE_BEGIN

LQQuicSeverSession::LQQuicSeverSession(quic::QuicConnection* connection, const quic::QuicConfig& quic_config, const quic::QuicCryptoServerConfig* crypto_config, quic::QuicSession::Visitor* visitor, QuicCryptoServerStream::Helper* session_helper, QuicCompressedCertsCache* compressed_certs_cache)
:quic::QuicSession(connection, visitor, quic_config, quic::CurrentSupportedVersions()),crypto_config_(crypto_config),dataVisitor(nil),lastWriteStream(nil)
{
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
    
    cryptoServerStream = std::make_unique<quic::QuicCryptoServerStream>(crypto_config,
                                                                        compressed_certs_cache,
                                                                        GetQuicReloadableFlag(enable_quic_stateless_reject_support), this,
                                                                        session_helper);
}

#pragma mark ----- overrride -----
quic::QuicStream* LQQuicSeverSession::CreateIncomingStream(quic::QuicStreamId id)
{
    LOGD("CreateIncomingStream, call StreamId:%u", id);
    if (!ShouldCreateIncomingStream(id)) {
        return nullptr;
    }
    LQQuicStream* stream = new LQQuicStream(id, this, false, BIDIRECTIONAL);
    ActivateStream(QuicWrapUnique(stream));
    stream->setDataVisitor(this);
    return stream;
}
quic::QuicStream* LQQuicSeverSession::CreateIncomingStream(quic::PendingStream pending)
{
    LOGD(" not implemention !!!");
    return nullptr;
}

// Return the reserved crypto stream.
quic::QuicCryptoStream* LQQuicSeverSession::GetMutableCryptoStream()
{
    LOGD("GetMutableCryptoStream, call ");
    return cryptoServerStream.get();
}

// Return the reserved crypto stream as a constant pointer.
const quic::QuicCryptoStream* LQQuicSeverSession::GetCryptoStream() const
{
    LOGD("GetCryptoStream, call ");
    return cryptoServerStream.get();
}

void LQQuicSeverSession::Initialize()
{
    QuicSession::Initialize();
//    bool isConnected = CryptoConnect();
    LOGD("Initialize, call isConnected = ");//, isConnected);
}

quic::QuicStream* LQQuicSeverSession::GetOrCreateOutgoingStream(){
    if(lastWriteStream){
        return lastWriteStream;
    }else{
        return CreateOutgoingBidirectionalStream();
    }
}

quic::QuicStream* LQQuicSeverSession::CreateOutgoingBidirectionalStream()
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
        newStream->setDataVisitor(this);
        //        newStream->set_visitor(this);
    }
    lastWriteStream = stream_ptr;
    return stream_ptr;
}

#pragma mark ----- private method -----
bool LQQuicSeverSession::ShouldCreateIncomingStream(QuicStreamId id) {
    if (!connection()->connected()) {
        LOGD("ShouldCreateIncomingStream called when disconnected");
        return false;
    }
    if (QuicUtils::IsServerInitiatedStreamId(connection()->transport_version(),id)) {
            LOGD("Received invalid push stream id = %u", id);
            connection()->CloseConnection(
                                          QUIC_INVALID_STREAM_ID,
                                          "Server created non write unidirectional stream",
                                          ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
            return false;
        }
    return true;
}

bool LQQuicSeverSession::OnPacket(const quic::QuicStringPiece packet,
              const quic::QuicStreamId streamId){
    if(dataVisitor){
        return dataVisitor->OnPacket(packet, streamId, this);
    }
    return true;
}

bool LQQuicSeverSession::ShouldCreateOutgoingBidirectionalStream() {
    if (!cryptoServerStream->encryption_established()) {
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

LQQUIC_NAMESPACE_END

