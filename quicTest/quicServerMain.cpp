//
//  quicServerMain.cpp
//  quicServer
//
//  Created by yajun18 on 2019/8/20.
//  Copyright © 2019 wb_Leo1. All rights reserved.
//

#include "Proxy/server/QuicTestServerCase.hpp"

int main(int argc, const char * argv[]) {
    // insert code here...
    //    std::cout << "Hello, World!\n";
    
    //    QuicTestCase::testLQQuicSession();
    
    
    //    QuicTestCase::testQuicClient();
    
    QuicTestServerCase::testQuicServer();
    return 0;
}
