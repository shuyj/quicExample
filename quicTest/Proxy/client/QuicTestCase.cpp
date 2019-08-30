//
//  QuicTestCase.cpp
//  LQVideoCore
//
//  Created by wb_Leo1 on 2019/2/20.
//  Copyright © 2019 LQVideoCore. All rights reserved.
//

#include "QuicTestCase.hpp"
#include "LQQuicSession.hpp"
#include "LQQuicClient.hpp"
#include <net/quic/quic_chromium_connection_helper.h>
#include <net/third_party/quic/platform/impl/quic_chromium_clock.h>
#include <net/quic/quic_chromium_alarm_factory.h>
#include "quic_client_message_loop_network_helper.h"
#include <base/at_exit.h>
#include <base/message_loop/message_loop.h>
#include <base/task/sequence_manager/sequence_manager.h>

#include <base/task/task_scheduler/task_scheduler.h>

#include <crypto/openssl_util.h>
#include <net/third_party/quic/core/tls_client_handshaker.h>
using namespace net;
#include <net/socket/udp_client_socket.h>
#include <base/logging.h>
#include <base/bind.h>
#include <net/base/net_errors.h>
#include <net/quic/quic_chromium_packet_reader.h>
#include <net/quic/quic_chromium_packet_writer.h>
#include <net/log/trace_net_log_observer.h>
#include <future>

void QuicTestCase::testProxySocket()
{
    
}

void QuicTestCase::testQuicClient()
{
    bool success = base::CommandLine::Init(0, nullptr);
    logging::SetMinLogLevel(logging::LOG_VERBOSE);
    logging::LoggingSettings logsettings;
    logsettings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
    CHECK(logging::InitLogging(logsettings));
//    auto type = base::MessageLoop::TYPE_DEFAULT;
//    auto settings = base::sequence_manager::SequenceManager::Settings{.message_loop_type = type};
//    std::unique_ptr<base::sequence_manager::SequenceManager> sequence_manager_ = base::sequence_manager::CreateSequenceManagerOnCurrentThreadWithPump(base::MessageLoop::CreateMessagePumpForType(type), std::move(settings));
//    scoped_refptr<base::sequence_manager::TaskQueue> default_task_queue = sequence_manager_->CreateTaskQueueWithType<base::sequence_manager::TaskQueue>(base::sequence_manager::TaskQueue::Spec("default_tq"));
//    CHECK(!base::ThreadTaskRunnerHandle::IsSet());
//    scoped_refptr<base::SingleThreadTaskRunner> task_runner_ = default_task_queue->task_runner();
//    sequence_manager_->SetDefaultTaskRunner(default_task_queue->task_runner());
//    CHECK(base::ThreadTaskRunnerHandle::IsSet());
    
    base::MessageLoopForIO message_loop;
    base::AtExitManager at_exit_manager;
    
    quic::QuicServerId server_id("127.0.0.1", 8989, false);
    
    std::unique_ptr<quic::ProofVerifier> insecureProofVerifier = std::make_unique<lqcore::InsecureProofVerifier>();
    
    lqcore::LQQuicClient* lqclient = new lqcore::LQQuicClient(server_id, quic::CurrentSupportedVersions(), quic::QuicConfig(), std::move(insecureProofVerifier));
    bool isInitialize = lqclient->Initialize();
    bool isConnect = lqclient->Connect();
    LOG(INFO) << "isInitialize = " << isInitialize << " Connect :" << isConnect;
    if(!isConnect){
        LOG(INFO) << "isInitialize = " << isInitialize << " Connect failed:" << isConnect;
        return;
    }
    bool isCryptoHandshakeConfirmed = lqclient->WaitForCryptoHandshakeConfirmed();
    LOG(INFO) << "isInitialize = " << isInitialize << " Connect :" << isConnect << "isCryptoHandshakeConfirmed" << isCryptoHandshakeConfirmed;
    std::string hello = "Hello Quic Server";
    lqcore::QuicIpAddress self_address;
    lqcore::QuicSocketAddress peer_address;
    
//    quic::WriteResult rs = lqclient->writer()->WritePacket(hello.c_str(), hello.size(), self_address, peer_address, nil);
    
    quic::QuicStream* qstream = lqclient->client_session()->CreateOutgoingBidirectionalStream();
    char sendbuf[256] = {0};
    std::sprintf( sendbuf, "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111 = %u", qstream->id());
    qstream->WriteOrBufferData(quic::QuicStringPiece(sendbuf, strlen(sendbuf)), false, nullptr);
    qstream->WriteOrBufferData(quic::QuicStringPiece(sendbuf, strlen(sendbuf)), false, nullptr);
    qstream->WriteOrBufferData(quic::QuicStringPiece(sendbuf, strlen(sendbuf)), false, nullptr);
    qstream->WriteOrBufferData(quic::QuicStringPiece(sendbuf, strlen(sendbuf)), false, nullptr);
//    LOG(INFO) << "isInitialize = " << isInitialize << " WriteResult = " << rs;
//    rs = lqclient->writer()->Flush();
//    LOG(INFO) << "isInitialize = " << isInitialize << " WriteResult1 = " << rs;
    std::unique_ptr<base::RunLoop> runloop = std::make_unique<base::RunLoop>();
    base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(FROM_HERE, base::BindOnce([](lqcore::LQQuicClient* lqclient){
        LOG(INFO) << "=========Close Connection: ";
        lqclient->Disconnect();
    }, lqclient), base::TimeDelta::FromSeconds(3));
    base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(FROM_HERE, base::BindOnce([](base::RunLoop* runloop){
        LOG(INFO) << "=========Quit Runloop : ";
        runloop->QuitWhenIdle();
    }, runloop.get()), base::TimeDelta::FromSeconds(5));
    
    LOG(INFO) << "=========HasBufferedData: " <<  qstream->HasBufferedData();
    runloop->Run();
//    base::PlatformThread::Sleep(base::TimeDelta::FromSeconds(5));
    LOG(INFO) << "=========HasBufferedData: " <<  qstream->HasBufferedData();
}
NetLog net_log_;
TraceNetLogObserver observer;
std::unique_ptr<UDPClientSocket> CreateUDPSocketAndBind(
                            quic::QuicSocketAddress server_address,
                            quic::QuicIpAddress bind_to_address,
                            int bind_to_port)
{
//    net_log_.UpdateIsCapturing()
    
    quic::QuicSocketAddress client_address_;
    auto socket = std::make_unique<UDPClientSocket>(DatagramSocket::DEFAULT_BIND,
                                                    &net_log_, NetLogSource());
    
    if (bind_to_address.IsInitialized()) {
//        client_address_ =
//        quic::QuicSocketAddress(bind_to_address, client_->local_port());
    } else if (server_address.host().address_family() ==
               quic::IpAddressFamily::IP_V4) {
        client_address_ =
        quic::QuicSocketAddress(quic::QuicIpAddress::Any4(), bind_to_port);
    } else {
        client_address_ =
        quic::QuicSocketAddress(quic::QuicIpAddress::Any6(), bind_to_port);
    }
    
    int rc = socket->Connect(server_address.impl().socket_address());
    if (rc != OK) {
        LOG(ERROR) << "Connect failed: " << ErrorToShortString(rc);
        return nullptr;
    }
    
    rc = socket->SetReceiveBufferSize(quic::kDefaultSocketReceiveBuffer);
    if (rc != OK) {
        LOG(ERROR) << "SetReceiveBufferSize() failed: " << ErrorToShortString(rc);
        return nullptr;
    }
    
    rc = socket->SetSendBufferSize(quic::kDefaultSocketReceiveBuffer);
    if (rc != OK) {
        LOG(ERROR) << "SetSendBufferSize() failed: " << ErrorToShortString(rc);
        return nullptr;
    }
    
    IPEndPoint address;
    rc = socket->GetLocalAddress(&address);
    if (rc != OK) {
        LOG(ERROR) << "GetLocalAddress failed: " << ErrorToShortString(rc);
        return nullptr;
    }
    client_address_ =
    quic::QuicSocketAddress(quic::QuicSocketAddressImpl(address));
    
    LOG(INFO) << "udp local port = " << client_address_.host().ToString() << ":" << client_address_.port();
//    if (socket != nullptr) {
//        socket->Close();
//    }
    
    return socket;
}

bool CLogMessageHandlerFunction(int severity, const char* file, int line, size_t message_start, const std::string& str)
{
    printf("%s:%d %s", file, line, str.c_str());
    return true;
}

void QuicTestCase::testLQQuicSession()
{
    bool success = base::CommandLine::Init(0, nullptr);
    logging::SetMinLogLevel(logging::LOG_VERBOSE);
    logging::SetLogMessageHandler( CLogMessageHandlerFunction );
    
    logging::LoggingSettings logsettings;
    logsettings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
    CHECK(logging::InitLogging(logsettings));
    
//    auto type = base::MessageLoop::TYPE_DEFAULT;
//    auto settings = base::sequence_manager::SequenceManager::Settings{.message_loop_type = type};
//    std::unique_ptr<base::sequence_manager::SequenceManager> sequence_manager_ = base::sequence_manager::CreateSequenceManagerOnCurrentThreadWithPump(base::MessageLoop::CreateMessagePumpForType(type), std::move(settings));
//    scoped_refptr<base::sequence_manager::TaskQueue> default_task_queue = sequence_manager_->CreateTaskQueueWithType<base::sequence_manager::TaskQueue>(base::sequence_manager::TaskQueue::Spec("default_tq"));
//    CHECK(!base::ThreadTaskRunnerHandle::IsSet());
//    scoped_refptr<base::SingleThreadTaskRunner> task_runner_ = default_task_queue->task_runner();
//    sequence_manager_->SetDefaultTaskRunner(default_task_queue->task_runner());
//    CHECK(base::ThreadTaskRunnerHandle::IsSet());
    
//    base::TaskScheduler::CreateAndStartWithDefaultParams("quic_client");
    base::MessageLoopForIO message_loop;
    
    base::AtExitManager at_exit_manager;
    
    quic::Perspective perspective = quic::Perspective::IS_CLIENT;

    quic::QuicRandom* quic_random = quic::QuicRandom::GetInstance();
    quic::QuicChromiumClock* clock = quic::QuicChromiumClock::GetInstance();

    // The P2PQuicSession owns these chromium specific objects required
    // by the QuicConnection. These outlive the QuicConnection itself.
    std::unique_ptr<net::QuicChromiumConnectionHelper> helper = std::make_unique<net::QuicChromiumConnectionHelper>(clock, quic_random);
    
    //    P2PQuicPacketWriter* packet_writer = new P2PQuicPacketWriter(packet_transport);
    quic::QuicAlarmFactory* alarm_factory = new net::QuicChromiumAlarmFactory(base::ThreadTaskRunnerHandle::Get().get(), clock);

    quic::QuicIpAddress ip;
    std::string host("10.235.61.27");
    bool isSuc = ip.FromString(host);
    quic::QuicSocketAddress dummy_address(ip, 8989 /* Port */);
    LOG(INFO) << "udp server address = " << dummy_address.host().ToString() << ":" << dummy_address.port();
    
    observer.WatchForTraceStart(&net_log_);
    
    CHECK(!net_log_.IsCapturing());
    
    base::trace_event::TraceLog::GetInstance()->SetEnabled(
                                                           base::trace_event::TraceConfig("netlog", ""), base::trace_event::TraceLog::RECORDING_MODE);
    // AsyncEnabledStateObserver will receive enabled notification one message
    // loop iteration later.
    base::RunLoop().RunUntilIdle();
    
    CHECK(net_log_.IsCapturing());
    
    std::unique_ptr<UDPClientSocket> socket_ = CreateUDPSocketAndBind(dummy_address, ip, 12345);
    
    class : public net::QuicChromiumPacketReader::Visitor
    {
    public:
        virtual void OnReadError(int result,
                                 const DatagramClientSocket* socket){
            LOG(INFO) << "OnReadError " << result << "socket:" << socket;
        }
        virtual bool OnPacket(const quic::QuicReceivedPacket& packet,
                              const quic::QuicSocketAddress& local_address,
                              const quic::QuicSocketAddress& peer_address){
            LOG(INFO) << "OnPacket:" << peer_address.host().ToString() << ":" << peer_address.port() << " " << packet.headers_length() << " ttl:" << packet.ttl();
            if( session_ ){
                session_->ProcessUdpPacket(local_address, peer_address, packet);
            }
            return true;
        }
        void setQuicSession(lqcore::LQQuicSession* session){ session_ = session; }
    private:
        lqcore::LQQuicSession* session_ = nullptr;
    } quicReaderVisitor;

    
    net::QuicChromiumPacketReader* packet_reader = new net::QuicChromiumPacketReader(
                                                                                    socket_.get(), clock, &quicReaderVisitor, kQuicYieldAfterPacketsRead,
                                                                                     quic::QuicTime::Delta::FromMilliseconds(kQuicYieldAfterDurationMilliseconds),
                                                                                     NetLogWithSource::Make(&net_log_, NetLogSourceType::UDP_SOCKET));//NetLogWithSource());
    
    quic::QuicPacketWriter* packet_writer = //nullptr;// QuicChromiumPacketWriter* writer =
            new net::QuicChromiumPacketWriter(socket_.get(), base::ThreadTaskRunnerHandle::Get().get());
    
    packet_reader->StartReading();
    base::RunLoop().RunUntilIdle();
    
    quic::QuicConnectionId dummy_connection_id;
    if (GetQuicRestartFlag(quic_variable_length_connection_ids_client)) {
        char connection_id_bytes[8] = {0, 0, 0, 0, 0, 0, 1, 2};
        dummy_connection_id = quic::QuicConnectionId(connection_id_bytes,
                                                     sizeof(connection_id_bytes));
    } else {
        dummy_connection_id = quic::EmptyQuicConnectionId();
    }
    quic::QuicConnection* qConnection = new quic::QuicConnection(
                                                                                               dummy_connection_id, dummy_address, helper.get(), alarm_factory, packet_writer,
                                                                                               /* owns_writer */ true, perspective, quic::CurrentSupportedVersions());
    quic::QuicServerId server_id(dummy_address.host().ToString(), 8989, false);
    quic::QuicConfig quic_config;
    std::unique_ptr<quic::ProofVerifier> insecureProofVerifier = std::make_unique<lqcore::InsecureProofVerifier>();
    crypto::EnsureOpenSSLInit();
    quic::QuicCryptoClientConfig* cryptoConfig = new quic::QuicCryptoClientConfig(std::move(insecureProofVerifier), quic::TlsClientHandshaker::CreateSslCtx());

    
    std::shared_ptr<lqcore::LQQuicSession> lqs(new lqcore::LQQuicSession(qConnection, quic_config, cryptoConfig, server_id));
    
    quicReaderVisitor.setQuicSession(lqs.get());
    
    lqs->Initialize();
//    bool isConnected = lqs->CryptoConnect();
    // rtc_enable_protobuf = false is_proto_quic = true blink_symbol_level = 2
    
    LOG(ERROR) << "established:" << lqs->IsEncryptionEstablished() << " connected:" << lqs->connection()->connected() << "CryptoConnect:" ;//<< isConnected;
    int maxRunNum = 20;
    while( !lqs->IsEncryptionEstablished() && lqs->connection()->connected() && maxRunNum > 0 ){
        base::RunLoop().RunUntilIdle();
        LOG_IF(ERROR, maxRunNum%5==0) << "w-established:" << lqs->IsEncryptionEstablished() << " connected:" << lqs->connection()->connected() << "RunNum:" << maxRunNum;
        maxRunNum--;
    }
    
    LOG(ERROR) << "w-established:" << lqs->IsEncryptionEstablished() << " connected:" << lqs->connection()->connected() << "RunNum:" << maxRunNum;
    
    LOG(INFO) << "session error:" << lqs->error() ;
    
    quic::QuicStream* normalStream = lqs->CreateOutgoingBidirectionalStream();
    
    normalStream->WriteOrBufferData(quic::QuicStringPiece("hello quic"), false, nullptr);
    maxRunNum = 10;
    while( lqs->num_active_requests() && maxRunNum > 0 ){
        base::RunLoop().RunUntilIdle();
        LOG_IF(INFO, maxRunNum%5==0) << "RunLoop :" << maxRunNum ;
        maxRunNum--;
    }
    
//    qConnection->CloseConnection( quic::QUIC_PEER_GOING_AWAY, "Client disconnecting", quic::ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET );
    
    observer.StopWatchForTraceStart();
    CHECK(!net_log_.IsCapturing());
    
    base::trace_event::TraceLog::GetInstance()->SetDisabled();
    // AsyncEnabledStateObserver will receive disabled notification one message
    // loop iteration later.
    base::RunLoop().RunUntilIdle();
}

