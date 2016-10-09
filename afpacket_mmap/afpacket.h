/****************************************************************
 * Version : V1.00
 * Author :  CCH
 * Create Date: 2014:11:26
 * FileName :
 * Description:
 *
 * Modify Log: 
 * 
 ****************************************************************/ 
#ifndef __AFPACKET_H__
#define __AFPACKET_H__
//头文件引用
#include "pub.h"
#include <sys/socket.h>
#include <linux/if_arp.h>
#include <sys/mman.h>


#ifdef __cplusplus
extern "C" {
#endif


//宏定义
#define STATE_STOPPED   0
#define STATE_STARTED   1
#define VLAN_TAG_LEN    4
#define DEFAULT_ORDER   3

#define RING_SIZE       2000 //unit:k
#define AF_MTU          2000
#define AF_SUCCESS      0
#define AF_ERROR        -1
#define AF_VLAN_ENABLE  1

//变量声明
union thdr
{
    struct tpacket2_hdr     *h2;
    u_int8_t                *raw;
};

typedef struct af_packet_entry
{
    struct af_packet_entry      *next;
    union thdr                  hdr;
} AFPacketEntry;

typedef struct af_packet_ring
{
    struct tpacket_req  layout;
    unsigned int        size;
    void                *start;
    AFPacketEntry       *entries;
    AFPacketEntry       *cursor;
} AFPacketRing;
typedef struct af_stats
{
    u_int64_t       hw_packets_received;       /* Packets received by the hardware */
    u_int64_t       hw_packets_dropped;        /* Packets dropped by the hardware */
    u_int64_t       packets_received;          /* Packets received by this instance */
    u_int64_t       packets_filtered;          /* Packets filtered by this instance's BPF */
} Af_Stats;
typedef struct af_packet_instance
{
    char            *name;
    int             fd;
    u_int32_t       ring_size;
    u_int32_t       snaplen;
    u_int32_t       index;
    struct          sockaddr_ll sll;
    unsigned        tp_version;
    unsigned        tp_hdrlen;
    AFPacketRing    rx_ring;
    AFPacketRing    tx_ring;
    void            *buffer;

    Af_Stats        stats;
} AFPacketInstance;

//函数声明
extern u_int8_t afpacket_init(const char *dev_name, void **ctxt_ptr);
extern int afpacket_start(void *handle, u_int8_t send0_recv1);
extern int afpacket_acquire(void *handle, Pkt_Buf *p_pkt_buf, u_int32_t buffer_len);
extern int afpacket_send(void *handle, Pkt_Buf *send_pkt);
extern int afpacket_close(void *handle);


#ifdef __cplusplus
}
#endif

#endif