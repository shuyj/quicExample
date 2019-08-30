//
//  LQQuicSeverSession.hpp
//  quicServer
//
//  Created by yajun18 on 2019/8/22.
//  Copyright © 2019 wb_Leo1. All rights reserved.
//

#ifndef LQQuicSeverSession_hpp
#define LQQuicSeverSession_hpp

#include <net/third_party/quic/core/quic_session.h>
#include <net/third_party/quic/core/crypto/proof_verifier.h>
#include <net/third_party/quic/core/quic_server_id.h>
#include <net/third_party/quic/core/crypto/quic_crypto_server_config.h>
#include <net/third_party/quic/core/quic_crypto_server_stream.h>
#include "QuicCommon.h"
#include "LQQuicStream.hpp"

LQQUIC_NAMESPACE_BEGIN

using namespace quic;

class LQQuicSeverSession : public quic::QuicSession , public LQQuicStream::Visitor
{
    
public:
    LQQuicSeverSession(quic::QuicConnection* connection,
                       const quic::QuicConfig& quic_config, const quic::QuicCryptoServerConfig* crypto_config, quic::QuicSession::Visitor* visitor, QuicCryptoServerStream::Helper* session_helper, QuicCompressedCertsCache* compressed_certs_cache);
    class Visitor {
    public:
        virtual ~Visitor() {}
        virtual bool OnPacket(const quic::QuicStringPiece packet,
                              const quic::QuicStreamId streamId, LQQuicSeverSession* session) = 0;
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
    
#pragma mark ----- interface -----
//    // Performs a crypto handshake with the server.
//    virtual bool CryptoConnect();
    
    quic::QuicStream* CreateOutgoingBidirectionalStream();
    
    quic::QuicStream* GetOrCreateOutgoingStream();
    
#pragma mark ----- stream data visitor -----
    
    virtual bool OnPacket(const quic::QuicStringPiece packet,
                          const quic::QuicStreamId streamId)override;
    
    void setDataVisitor(Visitor* visitor){
        dataVisitor = visitor;
    }
    
#pragma mark ------ private scope ------
private:
//    class LQQuicSeverSessionVisitor : public quic::QuicSession::Visitor
//    {
//    public:
//        // Called when the connection is closed after the streams have been closed.
//        virtual void OnConnectionClosed(QuicConnectionId connection_id,
//                                        QuicErrorCode error,
//                                        const QuicString& error_details,
//                                        ConnectionCloseSource source){
//            LOGD("connection_id = %s, quicerrorCode = %d, errorString = %s, closeReason = %d", connection_id.ToString().c_str(), error, error_details.c_str(), source);
//        }
//
//        // Called when the session has become write blocked.
//        virtual void OnWriteBlocked(QuicBlockedWriterInterface* blocked_writer){
//            LOGD("blocked_writer = %p, isWriterBlocked = %d", blocked_writer, blocked_writer->IsWriterBlocked());
//        }
//
//        // Called when the session receives reset on a stream from the peer.
//        virtual void OnRstStreamReceived(const QuicRstStreamFrame& frame){
//            std::ostringstream ostr;
//            ostr << frame;
//            LOGD("quicRstStreamFrame = %s", ostr.str().c_str());
//        }
//
//        // Called when the session receives a STOP_SENDING for a stream from the
//        // peer.
//        virtual void OnStopSendingReceived(const QuicStopSendingFrame& frame){
//            std::ostringstream ostr;
//            ostr << frame;
//            LOGD("quicStopSendingFrame = %s", ostr.str().c_str());
//        }
//    };
    
#pragma mark ---- private method -----
    
    bool ShouldCreateIncomingStream(QuicStreamId id);
    bool ShouldCreateOutgoingBidirectionalStream();
    
#pragma mark ---- property -----
    
//    LQQuicSeverSessionVisitor mSessionVisitor;
    
    //    std::unique_ptr<quic::QuicConnection> connection_;
    
    const quic::QuicCryptoServerConfig*      crypto_config_;
    
    //    std::unique_ptr<InsecureProofVerifier>    insecureProofVerifier;
    
    // |server_id_| is a tuple (hostname, port, is_https) of the server.
    QuicServerId server_id_;
    
    std::unique_ptr<quic::QuicCryptoServerStream>   cryptoServerStream;
    
    Visitor*     dataVisitor;
    
    quic::QuicStream*       lastWriteStream;
};

LQQUIC_NAMESPACE_END

#endif /* LQQuicSeverSession_hpp */
