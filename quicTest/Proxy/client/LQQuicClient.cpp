//
//  LQQuicClient.cpp
//  quicTest
//
//  Created by wb_Leo1 on 2019/2/25.
//  Copyright © 2019 wb_Leo1. All rights reserved.
//

#include "LQQuicClient.hpp"
#include <net/third_party/quic/platform/api/quic_ptr_util.h>
#include "quic_client_message_loop_network_helper.h"


LQQUIC_NAMESPACE_BEGIN

LQQuicClient::LQQuicClient(const QuicServerId& server_id,
             const ParsedQuicVersionVector& supported_versions,
             const QuicConfig& config,
             std::unique_ptr<ProofVerifier> proof_verifier):
QuicClientBase(server_id, quic::CurrentSupportedVersions(), config,//quic::QuicConfig(),
               CreateQuicConnectionHelper(),
               CreateQuicAlarmFactory(), quic::QuicWrapUnique(new net::QuicClientMessageLooplNetworkHelper(&clock_, this)), std::move(proof_verifier))
{
    quic::QuicIpAddress ip;
    ip.FromString(server_id.host());
    set_server_address(quic::QuicSocketAddress(ip, server_id.port()));
    LOGD("LQQuicClient create, call ");
}

LQQuicClient::~LQQuicClient()
{
    LOGD("LQQuicClient destory, call ");
}

net::QuicChromiumConnectionHelper* LQQuicClient::CreateQuicConnectionHelper() {
    return new net::QuicChromiumConnectionHelper(&clock_,
                                            quic::QuicRandom::GetInstance());
}

net::QuicChromiumAlarmFactory* LQQuicClient::CreateQuicAlarmFactory() {
    return new net::QuicChromiumAlarmFactory(base::ThreadTaskRunnerHandle::Get().get(),
                                        &clock_);
}

// Extract the number of sent client hellos from the session.
int LQQuicClient::GetNumSentClientHellosFromSession()
{
    LOGD("GetNumSentClientHellosFromSession, call ");
    return 0;
}

// The number of server config updates received.  We assume no
// updates can be sent during a previously, statelessly rejected
// connection, so only the latest session is taken into account.
int LQQuicClient::GetNumReceivedServerConfigUpdatesFromSession()
{
    LOGD("GetNumReceivedServerConfigUpdatesFromSession, call ");
    return 0;
}

// If this client supports buffering data, resend it.
void LQQuicClient::ResendSavedData()
{
    LOGD("ResendSavedData, call ");
}

// If this client supports buffering data, clear it.
void LQQuicClient::ClearDataToResend()
{
    LOGD("ClearDataToResend, call ");
}

// Takes ownership of |connection|. If you override this function,
// you probably want to call ResetSession() in your destructor.
// TODO(rch): Change the connection parameter to take in a
// std::unique_ptr<QuicConnection> instead.
std::unique_ptr<QuicSession> LQQuicClient::CreateQuicClientSession(
                                                             const ParsedQuicVersionVector& supported_versions,
                                                             QuicConnection* connection)
{
    LOGD("CreateQuicClientSession, call ");
    std::unique_ptr<LQQuicSession> session = std::make_unique<LQQuicSession>(connection, *config(), crypto_config(), server_id());
    session->setDataVisitor(this);
    return std::move(session);
}

void LQQuicClient::InitializeSession() {
    LOGD("InitializeSession, call ");
    session()->Initialize();
//    ((LQQuicSession*)session())->CryptoConnect();
}

LQQuicSession*  LQQuicClient::client_session()
{
    return (LQQuicSession*)session();
}

bool LQQuicClient::OnPacket(const quic::QuicStringPiece packet,
              const quic::QuicStreamId streamId, LQQuicSession* session){
    LOGD("Client Recv Message session:%s streamId:%u content:%s", session->connection_id().ToString().c_str(), streamId, packet.as_string().c_str());
    return true;
}

LQQUIC_NAMESPACE_END
