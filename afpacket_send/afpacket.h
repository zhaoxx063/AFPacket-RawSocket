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
//ͷ�ļ�����
#include "pub.h"
#include <sys/socket.h>
#include <linux/if_arp.h>

#ifdef __cplusplus
extern "C" {
#endif


//�궨��
#define STATE_STOPPED 0
#define STATE_STARTED 1

//��������
typedef struct af_packet_instance
{
    char        *name;
    int         fd;
    int         index;
    struct      sockaddr_ll sll;
    u_int8_t    state;
} AFPacketInstance;


//��������
extern u_int8_t afpacket_init(const char *dev_name, void **ctxt_ptr);
extern int afpacket_start(void *handle);
extern int afpacket_acquire(void *handle, Pkt_Buf *p_pkt_buf, u_int32_t buffer_len);
extern int afpacket_send(void *handle, Pkt_Buf *send_pkt);
extern int afpacket_close(void *handle);


#ifdef __cplusplus
}
#endif

#endif