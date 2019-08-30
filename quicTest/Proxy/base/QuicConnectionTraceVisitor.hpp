//
//  QuicConnectionTraceVisitor.hpp
//  quicTest
//
//  Created by yajun18 on 2019/8/28.
//  Copyright © 2019 wb_Leo1. All rights reserved.
//

#ifndef QuicConnectionTraceVisitor_hpp
#define QuicConnectionTraceVisitor_hpp

#include "net/third_party/quic/core/quic_connection.h"

namespace quic{

class QuicConnectionTraceVisitor : public QuicConnectionDebugVisitor {
public:
    
    // Called when the unauthenticated portion of the header has been parsed.
    virtual void OnUnauthenticatedHeader(const QuicPacketHeader& header) {
        
    }
    
    // Called when a packet is received with a connection id that does not
    // match the ID of this connection.
//    virtual void OnIncorrectConnectionId(QuicConnectionId connection_id) {}
    
    // Called when an undecryptable packet has been received.
//    virtual void OnUndecryptablePacket() {}
    
    // Called when a duplicate packet has been received.
//    virtual void OnDuplicatePacket(QuicPacketNumber packet_number) {}
    
    // Called when the protocol version on the received packet doensn't match
    // current protocol version of the connection.
//    virtual void OnProtocolVersionMismatch(ParsedQuicVersion version) {}
    
    // Called when the complete header of a packet has been parsed.
//    virtual void OnPacketHeader(const QuicPacketHeader& header) {}
    
    // Called when a StreamFrame has been parsed.
    virtual void OnStreamFrame(const QuicStreamFrame& frame) {
        QUIC_DLOG(INFO) << "======Debug OnStreamFrame=" << frame.stream_id << std::string(frame.data_buffer, frame.data_length);
    }
};
    
};

#endif /* QuicConnectionTraceVisitor_hpp */
