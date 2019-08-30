//
//  LQQuicClient.hpp
//  quicTest
//
//  Created by wb_Leo1 on 2019/2/25.
//  Copyright © 2019 wb_Leo1. All rights reserved.
//

#ifndef LQQuicClient_hpp
#define LQQuicClient_hpp

#include "LQQuicSession.hpp"
#include <net/quic/quic_chromium_connection_helper.h>
#include <net/third_party/quic/platform/impl/quic_chromium_clock.h>
#include <net/quic/quic_chromium_alarm_factory.h>
#include "quic_client_base.h"
#include "QuicCommon.h"

LQQUIC_NAMESPACE_BEGIN
using namespace quic;

class LQQuicClient : public QuicClientBase, public LQQuicSession::Visitor
{
public:
    LQQuicClient(const QuicServerId& server_id,
                   const ParsedQuicVersionVector& supported_versions,
                   const QuicConfig& config,
                   std::unique_ptr<ProofVerifier> proof_verifier);
    
    LQQuicClient(const LQQuicClient&) = delete;
    LQQuicClient& operator=(const LQQuicClient&) = delete;
    
    ~LQQuicClient() override;
    
    // TODO(rch): Move GetNumSentClientHellosFromSession and
    // GetNumReceivedServerConfigUpdatesFromSession into a new/better
    // QuicSpdyClientSession class. The current inherits dependencies from
    // Spdy. When that happens this class and all its subclasses should
    // work with QuicSpdyClientSession instead of QuicSession.
    // That will obviate the need for the pure virtual functions below.
    
    // Extract the number of sent client hellos from the session.
    virtual int GetNumSentClientHellosFromSession() override;
    
    // The number of server config updates received.  We assume no
    // updates can be sent during a previously, statelessly rejected
    // connection, so only the latest session is taken into account.
    virtual int GetNumReceivedServerConfigUpdatesFromSession() override;
    
    // If this client supports buffering data, resend it.
    virtual void ResendSavedData() override;
    
    // If this client supports buffering data, clear it.
    virtual void ClearDataToResend() override;
    
    // Takes ownership of |connection|. If you override this function,
    // you probably want to call ResetSession() in your destructor.
    // TODO(rch): Change the connection parameter to take in a
    // std::unique_ptr<QuicConnection> instead.
    virtual std::unique_ptr<QuicSession> CreateQuicClientSession(
                                                                 const ParsedQuicVersionVector& supported_versions,
                                                                 QuicConnection* connection) override;
    
    
    // Calls session()->Initialize(). Subclasses may override this if any extra
    // initialization needs to be done. Subclasses should expect that session()
    // is non-null and valid.
    virtual void InitializeSession() override;
#pragma mark ------- stream data visitor -----
    virtual bool OnPacket(const quic::QuicStringPiece packet,
                          const quic::QuicStreamId streamId, LQQuicSession* session)override;
    
#pragma mark ----- public interface -----
    
    LQQuicSession*      client_session();
private:
    net::QuicChromiumAlarmFactory* CreateQuicAlarmFactory();
    net::QuicChromiumConnectionHelper* CreateQuicConnectionHelper();
    
    
    //  Used by |helper_| to time alarms.
    quic::QuicChromiumClock clock_;
};

LQQUIC_NAMESPACE_END

#endif /* LQQuicClient_hpp */
