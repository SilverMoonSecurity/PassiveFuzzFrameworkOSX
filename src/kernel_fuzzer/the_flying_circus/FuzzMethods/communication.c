//
//  communication.c
//  the_flying_circus
//
//  Created by jack on 11/11/15.
//  Copyright © 2015 reverser. All rights reserved.
//

#include <mach/mach_types.h>
#include <libkern/libkern.h>
#include <IOKit/IOLib.h>
#include <sys/errno.h>
#include <sys/kpi_mbuf.h>
#include <sys/kpi_socket.h>

#include "communication.h"


static lck_grp_t * mtxGroup = NULL;
static lck_mtx_t * connMutex = NULL;

typedef enum{
    e_comm_init,
    e_comm_connected
} enum_state_t;

typedef struct conn_state
{
    enum_state_t state;  //recored current state
    int connect_state;   //0: connect success, -1: connect fail
    
    
} conn_state_t, * pconn_state_t ;

static conn_state_t s_conn_state;


//socket call back event
static void cb_sock_event(socket_t so, void * cookie, int waitf)
{
    printf ("enter cb_sock_event, state: %d \n", s_conn_state.state);
    if(s_conn_state.state == e_comm_init)
    {
        if (!sock_isconnected(so))
        {
            s_conn_state.connect_state = -1;
            
        }
        else
        {
            s_conn_state.connect_state = 0;
        }
        
        
        lck_mtx_unlock(connMutex);
        
    }
    
}


//init communication
//args: <pSocket>: out for socket
//return >=0: success,  <0 fail
int comm_init(socket_t* pSocket)
{
    socket_t sk = 0;
    errno_t error;
    
    mtxGroup = lck_grp_alloc_init("comm_mutext", LCK_GRP_ATTR_NULL);
    if (!mtxGroup) {
        printf("zday comm: lck_grp_alloc_init failed\n");
        return -1;
    }
    connMutex = lck_mtx_alloc_init(mtxGroup, LCK_ATTR_NULL);
    if (!connMutex) {
        
        lck_grp_free(mtxGroup);
        mtxGroup = NULL;
        connMutex = NULL;
        printf("zday comm: lck_mtx_alloc_init failed\n");
        
        return -1;
    }
    
    s_conn_state.state = e_comm_init;
    
    error = sock_socket(AF_INET, SOCK_STREAM, 0, cb_sock_event, 0, &sk);
    if(error)
    {
        printf("zday comm: sock_socket() fail! ret: %d\n", error);
        return -1;
    }
    
    *pSocket = sk;
    
    
    lck_mtx_lock(connMutex);
    
    return 0;
    
}

//connect
//return >=0: success,  <0 fail
int comm_connect(socket_t socket)
{
    errno_t error;
    struct sockaddr_in addr;
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_len = sizeof(addr);
    addr.sin_port = htons(DST_PORT);
    addr.sin_addr.s_addr = htonl(IPv4_PART1<<24 | IPv4_PART2<<16 | IPv4_PART3<<8 | IPv4_PART4);
    
    
    
    error = sock_connect(socket, (const struct sockaddr*)&addr, MSG_DONTWAIT);
    
    if(error != EINPROGRESS && error)
    {
        lck_mtx_unlock(connMutex);
        printf("zday comm: sock_coonect immediate fail! ret: %d\n", error);
        return -1;
    }
    
    //wait the call back to release the mutex;
    lck_mtx_lock(connMutex);
    
    if(s_conn_state.connect_state < 0)
    {
        lck_mtx_unlock(connMutex);
        printf("zday comm: sock_coonect fail! ret: %d\n", error);
        return -1;
        
    }
    
    s_conn_state.state = e_comm_connected;
    return 0;
    
}


int comm_is_connect(socket_t socket)
{
    return sock_isconnected(socket);
    
}




//ret: 1: all content is sent,  0: part conent is sent,  -1; send fail
int sendAgain(socket_t socket,  mbuf_t* packet_total )
{
    mbuf_t packet;
    errno_t error;
    size_t sendCount = 0;
    
    printf("zday comm: before mbuf_dup");
    
    mbuf_dup(*packet_total, MBUF_WAITOK, &packet);
    
    printf("zday comm: before sock_sendmbuf, socket: %p, %p\n", socket, packet_total);
    
    error = sock_sendmbuf(socket, NULL, packet, MSG_WAITALL, &sendCount);
    printf("zday comm: after sock_sendmbuf\n");
    
    if(error != 0 )
    {
        
        printf("zday comm: sock_sendmbuf fail! ret: %d \n", error);
        return -1;
    }
    
    if(sendCount == mbuf_len(*packet_total))
    {
        return 1;
    }
   
    mbuf_adj(*packet_total, (int)sendCount);
    return 0;
    
    
}


//send buf
//return >=0: success,  <0 fail
int comm_sendbuf(socket_t socket , const void* buffer, size_t length)
{
    int ret = 0;
    mbuf_t packet_total;
    
    printf("zday comm: before mbuf_allocpacket(MBUF_WAITOK \n");

    if (mbuf_allocpacket(MBUF_WAITOK, length, NULL, &packet_total))
    {
        printf("zday comm: mbuf_allocpacket fail! \n");
        return -1;
        
    }
    printf("zday comm: before mbuf_copyback\n");
    mbuf_copyback(packet_total, 0, length, buffer, MBUF_WAITOK);
    printf("zday comm: before mbuf_settype \n");
    mbuf_settype(packet_total, MBUF_TYPE_DATA);
    printf("zday comm: before mbuf_setlen\n");
    mbuf_setlen(packet_total, length);
    
    while(1)
    {
        printf("jack: before send again\n");
        ret = sendAgain(socket, &packet_total);
        if(ret == 1)
            break;
        if (ret == -1)
            goto __error;
    }
    
    mbuf_free(packet_total);
    return 0;
    
__error:
    mbuf_free(packet_total);
    return -1;
    
}



//send fuzz infomatin
//return >=0: success,  <0 fail
int comm_sendfuzzinfo(socket_t socket, fuzz_sample_info_t* fuzzInfo)
{
    is_io_connect_method_t* pSrc = &fuzzInfo->now.entry;
    char content[0x2000] = {0};
    int pos = 0;
    uint32_t size = 0;
    
    size =  PATH_MAX+1;
    memcpy(content+pos, &size, sizeof(size));
    pos += sizeof(size);
    memcpy(content+pos, pSrc->szClassName, PATH_MAX+1);  //size: 1025
    pos += PATH_MAX+1;
    
    size = sizeof(pSrc->selector);
    memcpy(content+pos, &size, sizeof(size));
    pos += sizeof(size);
    memcpy(content+pos, &pSrc->selector, sizeof(pSrc->selector));   //size: 4
    pos += sizeof(pSrc->selector);
    
    size =  PATH_MAX+1;
    memcpy(content+pos, &size, sizeof(size));
    pos += sizeof(size);
    memcpy(content+pos, pSrc->szProcName, PATH_MAX+1);  //size: 1025
    pos += PATH_MAX+1;
    
    
    size = sizeof(pSrc->scalar_input);
    memcpy(content+pos, &size, sizeof(size));
    pos += sizeof(size);
    memcpy(content+pos, pSrc->scalar_input, sizeof(pSrc->scalar_input)); //size: 128
    pos += sizeof(pSrc->scalar_input);
    
    size = sizeof(pSrc->scalar_inputCnt);
    memcpy(content+pos, &size, sizeof(size));
    pos += sizeof(size);
    memcpy(content+pos, &pSrc->scalar_inputCnt, sizeof(pSrc->scalar_inputCnt));   //size: 4
    pos +=  sizeof(pSrc->scalar_inputCnt);
    
    size = sizeof(pSrc->inband_input);
    memcpy(content+pos, &size, sizeof(size));
    pos += sizeof(size);
    memcpy(content+pos, pSrc->inband_input, sizeof(pSrc->inband_input));  //size: 4096
    pos +=  sizeof(pSrc->inband_input);
    
    size = sizeof(pSrc->inband_inputCnt);
    memcpy(content+pos, &size, sizeof(size));
    pos += sizeof(size);
    memcpy(content+pos, &pSrc->inband_inputCnt, sizeof(pSrc->inband_inputCnt)); //size:4
    pos +=  sizeof(pSrc->inband_inputCnt);
    
    printf("zday comm: comm_sendfuzzinfo pos: %d\n", pos);
    
    if(comm_sendbuf(socket, content, sizeof(content)) < 0)
        return -1;
    
    return 0;
}



//close the connection
//return >=0: success,  <0 fail
int comm_closeconnect(socket_t socket)
{
    errno_t error;
    error = sock_shutdown(socket, SHUT_RDWR);
    if(error != 0 )
    {
        
        printf("zday comm: sock_shutdown fail! ret: %d \n", error);
        return -1;
    }
    
    return 0;
    
}

//release resource for this communication
//return >=0: success,  <0 fail
int comm_deinit(socket_t pSocket)
{
    
    sock_close(pSocket);
    if (connMutex && mtxGroup) {
        lck_mtx_free(connMutex, mtxGroup);
        lck_grp_free(mtxGroup);

    }
    
    return 0;
    
}


