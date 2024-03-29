// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_THIRD_PARTY_QUIC_TOOLS_QUIC_SIMPLE_DISPATCHER_H_
#define NET_THIRD_PARTY_QUIC_TOOLS_QUIC_SIMPLE_DISPATCHER_H_
#include "LQQuicSeverSession.hpp"
#include "LQQuicStream.hpp"
#include "net/third_party/quic/core/http/quic_server_session_base.h"
#include "net/third_party/quic/core/quic_dispatcher.h"
#include "net/third_party/quic/tools/quic_simple_server_backend.h"

namespace quic {
    
class QuicSimpleDispatcher : public QuicDispatcher, public lqcore::LQQuicSeverSession::Visitor {
 public:
  QuicSimpleDispatcher(
      const QuicConfig& config,
      const QuicCryptoServerConfig* crypto_config,
      QuicVersionManager* version_manager,
      std::unique_ptr<QuicConnectionHelperInterface> helper,
      std::unique_ptr<QuicCryptoServerStream::Helper> session_helper,
      std::unique_ptr<QuicAlarmFactory> alarm_factory,
      QuicSimpleServerBackend* quic_simple_server_backend);

  ~QuicSimpleDispatcher() override;

  int GetRstErrorCount(QuicRstStreamErrorCode rst_error_code) const;

  void OnRstStreamReceived(const QuicRstStreamFrame& frame) override;

#pragma mark ----- stream data visitor -----
    
    virtual bool OnPacket(const quic::QuicStringPiece packet,
                          const quic::QuicStreamId streamId, lqcore::LQQuicSeverSession* session)override;
    
 protected:
    lqcore::LQQuicSeverSession* CreateQuicSession(
      QuicConnectionId connection_id,
      const QuicSocketAddress& client_address,
      QuicStringPiece alpn,
      const ParsedQuicVersion& version) override;

  QuicSimpleServerBackend* server_backend() {
    return quic_simple_server_backend_;
  }

 private:
  QuicSimpleServerBackend* quic_simple_server_backend_;  // Unowned.

  // The map of the reset error code with its counter.
  std::map<QuicRstStreamErrorCode, int> rst_error_map_;
};

}  // namespace quic

#endif  // NET_THIRD_PARTY_QUIC_TOOLS_QUIC_SIMPLE_DISPATCHER_H_
