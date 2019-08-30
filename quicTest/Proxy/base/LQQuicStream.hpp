//
//  LQQuicStream.hpp
//  quicTest
//
//  Created by wb_Leo1 on 2019/2/25.
//  Copyright © 2019 wb_Leo1. All rights reserved.
//

#ifndef LQQuicStream_hpp
#define LQQuicStream_hpp

#include "QuicCommon.h"
#include <net/third_party/quic/core/quic_stream.h>

LQQUIC_NAMESPACE_BEGIN

using namespace quic;
class LQQuicStream : public quic::QuicStream
{
public:
    LQQuicStream(QuicStreamId id,
               QuicSession* session,
               bool is_static,
               StreamType type);
    class Visitor {
    public:
        virtual ~Visitor() {}
        virtual bool OnPacket(const quic::QuicStringPiece packet,
                              const quic::QuicStreamId streamId) = 0;
    };
    // Called when new data is available to be read from the sequencer.
    virtual void OnDataAvailable();
    
    void setDataVisitor(Visitor* visitor){
        dataVisitor = visitor;
    }
private:
    Visitor*     dataVisitor;
};
    
LQQUIC_NAMESPACE_END

#endif /* LQQuicStream_hpp */
