//
//  QuicTestServerCase.cpp
//  quicTest
//
//  Created by yajun18 on 2019/8/20.
//  Copyright © 2019 wb_Leo1. All rights reserved.
//

#include "quic_simple_server.h"
#include "QuicTestServerCase.hpp"
#include <iostream>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "base/message_loop/message_loop.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/task/task_scheduler/task_scheduler.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/quic/crypto/proof_source_chromium.h"
#include "net/third_party/quic/core/quic_packets.h"
#include "net/third_party/quic/tools/quic_memory_cache_backend.h"
#include "net/third_party/quic/tools/quic_simple_server_backend.h"
#include "net/tools/quic/quic_http_proxy_backend.h"

int32_t FLAGS_port = 8989;
// Mode of operations: currently only support in-memory cache
std::string FLAGS_quic_mode = "cache";
// Specifies the directory used during QuicHttpResponseCache
// construction to seed the cache. Cache directory can be
// generated using `wget -p --save-headers <url>`
std::string FLAGS_quic_response_cache_dir = "";
// URL with http/https, IP address or host name and the port number of the
// backend server
std::string FLAGS_quic_proxy_backend_url = "";

std::unique_ptr<quic::ProofSource> CreateProofSource(
                                                     const base::FilePath& cert_path,
                                                     const base::FilePath& key_path) {
    std::unique_ptr<net::ProofSourceChromium> proof_source(
                                                           new net::ProofSourceChromium());
    CHECK(proof_source->Initialize(cert_path, key_path, base::FilePath()));
    return std::move(proof_source);
}

// Used by QuicCryptoServerConfig to provide dummy proof credentials
// (taken from quic/quartc).
class DummyProofSource : public quic::ProofSource {
public:
    DummyProofSource() {}
    ~DummyProofSource() override {}
    
    // ProofSource override.
    void GetProof(const quic::QuicSocketAddress& server_addr,
                  const quic::QuicString& hostname,
                  const quic::QuicString& server_config,
                  quic::QuicTransportVersion transport_version,
                  quic::QuicStringPiece chlo_hash,
                  std::unique_ptr<Callback> callback) override {
        quic::QuicCryptoProof proof;
        proof.signature = "Dummy signature";
        proof.leaf_cert_scts = "Dummy timestamp";
        callback->Run(true, GetCertChain(server_addr, hostname), proof,
                      nullptr /* details */);
    }
    
    quic::QuicReferenceCountedPointer<Chain> GetCertChain(
                                                          const quic::QuicSocketAddress& server_address,
                                                          const quic::QuicString& hostname) override {
        std::vector<quic::QuicString> certs;
        certs.push_back("Dummy cert");
        return quic::QuicReferenceCountedPointer<Chain>(
                                                        new quic::ProofSource::Chain(certs));
    }
    void ComputeTlsSignature(
                             const quic::QuicSocketAddress& server_address,
                             const quic::QuicString& hostname,
                             uint16_t signature_algorithm,
                             quic::QuicStringPiece in,
                             std::unique_ptr<SignatureCallback> callback) override {
        callback->Run(true, "Dummy signature");
    }
};

void QuicTestServerCase::testQuicServer(){
    base::TaskScheduler::CreateAndStartWithDefaultParams("quic_server");
    base::AtExitManager exit_manager;
    base::MessageLoopForIO message_loop;
    
    base::CommandLine::Init(0, nullptr);
//    base::CommandLine* line = base::CommandLine::ForCurrentProcess();
    
    logging::LoggingSettings settings;
    settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
    CHECK(logging::InitLogging(settings));
    logging::SetMinLogLevel(-1);
    
    
    std::unique_ptr<quic::QuicSimpleServerBackend> quic_simple_server_backend;
//    = std::make_unique<quic::QuicMemoryCacheBackend>();
//    quic_simple_server_backend->InitializeBackend(FLAGS_quic_response_cache_dir);
    
    net::IPAddress ip = net::IPAddress::IPv6AllZeros();
    
    quic::QuicConfig config;
    std::unique_ptr<quic::ProofSource> proofSource = std::make_unique<DummyProofSource>();
    net::QuicSimpleServer server(
//                                 CreateProofSource(line->GetSwitchValuePath("certificate_file"),
//                                                   line->GetSwitchValuePath("key_file")),
                                 std::move(proofSource),
                                 config, quic::QuicCryptoServerConfig::ConfigOptions(),
                                 quic::AllSupportedVersions(), quic_simple_server_backend.get());
    
    int rc = server.Listen(net::IPEndPoint(ip, FLAGS_port));
    if (rc < 0) {
        return;
    }
    
    base::RunLoop().Run();
}

