//
//  LQQuicStream.cpp
//  quicTest
//
//  Created by wb_Leo1 on 2019/2/25.
//  Copyright © 2019 wb_Leo1. All rights reserved.
//
#include <string>
#include "LQQuicStream.hpp"

LQQUIC_NAMESPACE_BEGIN

LQQuicStream::LQQuicStream(QuicStreamId id,
             QuicSession* session,
             bool is_static,
                           StreamType type):
    quic::QuicStream(id, session, is_static, type),dataVisitor(nil)
{
    LOGD("quicStream create id = %lu, session = %p, isstatic = %d, type = %d", id, session, is_static, type);
}
  
void LQQuicStream::OnDataAvailable()
{
    LOGD("onDataAvailable this = %p, streamId=%u type=%d", this, this->id(), this->type());
//    if ( session()->connection()->transport_version() != QUIC_VERSION_99 ) {
////        OnBodyAvailable();
//        return;
//    }
    
    iovec iov;
//    bool has_payload = false;
//    while (sequencer()->PrefetchNextRegion(&iov)) {
//        decoder_.ProcessInput(reinterpret_cast<const char*>(iov.iov_base),
//                              iov.iov_len);
//        if (decoder_.has_payload()) {
//            has_payload = true;
//        }
//        LOGD("Recv Content = %s", std::string((char*)iov.iov_base, iov.iov_len).c_str());
//    }
    while (sequencer()->HasBytesToRead()) {
        if( !sequencer()->GetReadableRegion(&iov) )
            break;
        quic::QuicStringPiece cc((char*)iov.iov_base, iov.iov_len);
        sequencer()->MarkConsumed(iov.iov_len);
        if(dataVisitor){
            dataVisitor->OnPacket(cc, this->id());
        }
    }
    
//    if (has_payload) {
//        OnBodyAvailable();
//        return;
//    }
    
    if (sequencer()->IsClosed()) {
//        OnBodyAvailable();
        OnFinRead();
    }else{
        sequencer()->SetUnblocked();
    }
}

LQQUIC_NAMESPACE_END
