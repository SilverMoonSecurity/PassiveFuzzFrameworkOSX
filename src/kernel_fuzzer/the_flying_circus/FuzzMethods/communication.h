//
//  communication.h
//  the_flying_circus
//
//  Created by jack on 11/10/15.
//  Copyright © 2015 reverser. All rights reserved.
//

#ifndef communication_h
#define communication_h

#include <sys/kpi_socket.h>
#include <netinet/in.h>
#include "is_io_connect_method_trampline.h"


#define DST_PORT 9999
/*
#define IPv4_PART1 192
#define IPv4_PART2 168
#define IPv4_PART3 201
#define IPv4_PART4 1
*/
#define IPv4_PART1 10
#define IPv4_PART2 64
#define IPv4_PART3 20
#define IPv4_PART4 160



//init communication
//args: <pSocket>: out for socket
//return >=0: success,  <0 fail
extern int comm_init(socket_t* pSocket);

//connect
//return >=0: success,  <0 fail
extern int comm_connect(socket_t socket);



//is connect?
//return =0: not connected,  =1 connected
extern int comm_is_connect(socket_t socket);



//send buf
//return >=0: success,  <0 fail
extern int comm_sendbuf(socket_t socket, const void* buffer, size_t length);

//send fuzz infomatin, this function will serialize <fuzzInfo> into a buffer and send.
//return >=0: success,  <0 fail
extern int comm_sendfuzzinfo(socket_t socket, fuzz_sample_info_t* fuzzInfo);



//close the connection
//return >=0: success,  <0 fail
extern int comm_closeconnect(socket_t socket);

//release resource for this communication
//return >=0: success,  <0 fail
extern int comm_deinit(socket_t pSocket);


#endif /* communication_h */
