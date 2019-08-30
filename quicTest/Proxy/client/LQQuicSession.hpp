//
//  LQQuicSession.hpp
//  LQVideoCore
//
//  Created by wb_Leo1 on 2019/2/19.
//  Copyright © 2019 LQVideoCore. All rights reserved.
//

#ifndef LQQuicSession_hpp
#define LQQuicSession_hpp

#include <net/third_party/quic/core/quic_session.h>
#include <net/third_party/quic/core/crypto/proof_verifier.h>
#include <net/third_party/quic/core/quic_server_id.h>
#include <net/third_party/quic/core/crypto/quic_crypto_client_config.h>
#include <net/third_party/quic/core/quic_crypto_client_stream.h>
#include "QuicCommon.h"
#include "QuicConnectionTraceVisitor.hpp"
#include "LQQuicStream.hpp"

LQQUIC_NAMESPACE_BEGIN

using namespace quic;

class InsecureProofVerifier : public quic::ProofVerifier{
public:
    InsecureProofVerifier() {}
    ~InsecureProofVerifier() override {}
    
    // ProofVerifier override.
    quic::QuicAsyncStatus VerifyProof(
                                      const quic::QuicString& hostname,
                                      const uint16_t port,
                                      const quic::QuicString& server_config,
                                      quic::QuicTransportVersion transport_version,
                                      quic::QuicStringPiece chlo_hash,
                                      const std::vector<quic::QuicString>& certs,
                                      const quic::QuicString& cert_sct,
                                      const quic::QuicString& signature,
                                      const quic::ProofVerifyContext* context,
                                      quic::QuicString* error_details,
                                      std::unique_ptr<quic::ProofVerifyDetails>* verify_details,
                                      std::unique_ptr<quic::ProofVerifierCallback> callback) override {
        return quic::QUIC_SUCCESS;
    }
    
    quic::QuicAsyncStatus VerifyCertChain(
                                          const quic::QuicString& hostname,
                                          const std::vector<quic::QuicString>& certs,
                                          const quic::ProofVerifyContext* context,
                                          quic::QuicString* error_details,
                                          std::unique_ptr<quic::ProofVerifyDetails>* details,
                                          std::unique_ptr<quic::ProofVerifierCallback> callback) override {
        return quic::QUIC_SUCCESS;
    }
    
    std::unique_ptr<quic::ProofVerifyContext> CreateDefaultContext() override {
        return nullptr;
    }
};
    
class LQQuicSession : public quic::QuicSession, public quic::QuicCryptoClientStream::ProofHandler, public LQQuicStream::Visitor
{
    
public:
    LQQuicSession(quic::QuicConnection* connection,
                  const quic::QuicConfig& quic_config, QuicCryptoClientConfig* crypto_config, const QuicServerId& server_id);
    class Visitor {
    public:
        virtual ~Visitor() {}
        virtual bool OnPacket(const quic::QuicStringPiece packet,
                              const quic::QuicStreamId streamId, LQQuicSession* session) = 0;
    };
#pragma mark ----- override -----
    // Creates a new stream to handle a peer-initiated stream.
    // Caller does not own the returned stream.
    // Returns nullptr and does error handling if the stream can not be created.
    virtual quic::QuicStream* CreateIncomingStream(quic::QuicStreamId id) override;
    virtual quic::QuicStream* CreateIncomingStream(quic::PendingStream pending) override;
    
    // Return the reserved crypto stream.
    virtual quic::QuicCryptoStream* GetMutableCryptoStream() override;
    
    // Return the reserved crypto stream as a constant pointer.
    virtual const quic::QuicCryptoStream* GetCryptoStream() const override;
    
    virtual void Initialize() override;
#pragma mark ----- QuicCryptoClientStream::ProofHandler ------
    // ProofHandler is an interface that handles callbacks from the crypto
    // stream when the client has proof verification details of the server.
    
    // Called when the proof in |cached| is marked valid.  If this is a secure
    // QUIC session, then this will happen only after the proof verifier
    // completes.
    virtual void OnProofValid(
                              const QuicCryptoClientConfig::CachedState& cached) override;
    
    // Called when proof verification details become available, either because
    // proof verification is complete, or when cached details are used. This
    // will only be called for secure QUIC connections.
    virtual void OnProofVerifyDetailsAvailable(
                                               const ProofVerifyDetails& verify_details) override;
#pragma mark ----- stream data visitor -----
    
    virtual bool OnPacket(const quic::QuicStringPiece packet,
                          const quic::QuicStreamId streamId)override;
    
    void setDataVisitor(Visitor* visitor){
        dataVisitor = visitor;
    }
#pragma mark ----- interface -----
    // Performs a crypto handshake with the server.
    virtual bool CryptoConnect();
    
    quic::QuicStream* CreateOutgoingBidirectionalStream();
    
#pragma mark ------ private scope ------
private:
    class LQQuicSessionVisitor : public quic::QuicSession::Visitor
    {
    public:
        // Called when the connection is closed after the streams have been closed.
        virtual void OnConnectionClosed(QuicConnectionId connection_id,
                                        QuicErrorCode error,
                                        const QuicString& error_details,
                                        ConnectionCloseSource source){
            LOGD("connection_id = %s, quicerrorCode = %d, errorString = %s, closeReason = %d", connection_id.ToString().c_str(), error, error_details.c_str(), source);
        }
        
        // Called when the session has become write blocked.
        virtual void OnWriteBlocked(QuicBlockedWriterInterface* blocked_writer){
            LOGD("blocked_writer = %p, isWriterBlocked = %d", blocked_writer, blocked_writer->IsWriterBlocked());
        }
        
        // Called when the session receives reset on a stream from the peer.
        virtual void OnRstStreamReceived(const QuicRstStreamFrame& frame){
            std::ostringstream ostr;
            ostr << frame;
            LOGD("quicRstStreamFrame = %s", ostr.str().c_str());
        }
        
        // Called when the session receives a STOP_SENDING for a stream from the
        // peer.
        virtual void OnStopSendingReceived(const QuicStopSendingFrame& frame){
            std::ostringstream ostr;
            ostr << frame;
            LOGD("quicStopSendingFrame = %s", ostr.str().c_str());
        }
    };
    
#pragma mark ---- private method -----
    
    bool ShouldCreateIncomingStream(QuicStreamId id);
    bool ShouldCreateOutgoingBidirectionalStream();
    
#pragma mark ---- property -----
    
    LQQuicSessionVisitor mSessionVisitor;
    
//    std::unique_ptr<quic::QuicConnection> connection_;
    
    quic::QuicCryptoClientConfig*      crypto_config_;
    
//    std::unique_ptr<InsecureProofVerifier>    insecureProofVerifier;
    
    // |server_id_| is a tuple (hostname, port, is_https) of the server.
    QuicServerId server_id_;
    
    std::unique_ptr<quic::QuicCryptoClientStream>   cryptoClientStream;
    quic::QuicConnectionTraceVisitor                      quicTraceVisitor;
    
    Visitor*     dataVisitor;
};

LQQUIC_NAMESPACE_END

#endif /* LQQuicSession_hpp */
