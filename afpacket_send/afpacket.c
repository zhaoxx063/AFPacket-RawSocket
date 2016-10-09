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
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include "afpacket.h"

#ifdef __cplusplus
extern "C" {
#endif


int get_nic_index(int fd, const char* nic_name)
{
    struct ifreq    ifr;


    if (nic_name == NULL)   return -1;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, nic_name, IFNAMSIZ);

    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1)
    {
        printf("%s: SIOCGIFINDEX ioctl error: %s\n", __FUNCTION__, strerror(errno));
        return -1;
    }

    return ifr.ifr_ifindex;
}

static void destroy_instance(AFPacketInstance *instance)
{
    if (instance)
    {
        if (instance->fd != -1)
        {
            close(instance->fd);
        }
        if (instance->name)
        {
            free(instance->name);
            instance->name = NULL;
        }
        free(instance);
    }
}
static AFPacketInstance *create_instance(const char *device)
{
    AFPacketInstance *instance = NULL;
    struct ifreq ifr;

    //instance
    instance = calloc(1, sizeof(AFPacketInstance));
    if (!instance)
    {
        printf("%s: Could not allocate a new instance structure.\n", __FUNCTION__);
        goto err;
    }

    //instance->name
    if ((instance->name = strdup(device)) == NULL)
    {
        printf("%s: Could not allocate a copy of the device name.\n", __FUNCTION__);
        goto err;;
    }

    //instance->fd
    instance->fd    = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (instance->fd == -1)
    {
        printf("%s: Could not open the PF_PACKET socket: %s\n", __FUNCTION__, strerror(errno));
        goto err;
    }

    //instance->index
    instance->index = get_nic_index(instance->fd, instance->name);
    if (instance->index == -1)
    {
        printf("%s: Could not find index for device %s\n", __FUNCTION__, instance->name);
        goto err;
    }

    //instance->sll
    instance->sll.sll_family    = AF_PACKET;
    instance->sll.sll_ifindex   = instance->index;
    instance->sll.sll_protocol  = htons(ETH_P_ALL);

    //instance->sll.state
    instance->state             = STATE_STOPPED;


    return instance;

err:
    destroy_instance(instance);
    return NULL;
}



static int bind_interface( AFPacketInstance *instance)
{
    int ret = 0;


    if (bind(instance->fd, (struct sockaddr *) &(instance->sll), sizeof(instance->sll)) != 0)
    {
        printf("%s: bind error: %s\n", __FUNCTION__, strerror(errno));
        ret = -1;
    }

    return ret;
}


static int set_nic_promisc(AFPacketInstance *instance)
{
    struct ifreq ethreq;
    int    ret = 0;


    strncpy(ethreq.ifr_name, instance->name, IFNAMSIZ);
    ioctl(instance->fd, SIOCGIFFLAGS, &ethreq);

    ethreq.ifr_flags |= IFF_PROMISC;
    ioctl(instance->fd, SIOCSIFFLAGS, &ethreq);


    return ret;
}


u_int8_t afpacket_init(const char *dev_name, void **ctxt_ptr)
{
    AFPacketInstance    *instance;
    int                 ret     = 1;

    
    instance        = create_instance(dev_name);
    *ctxt_ptr       = instance;
    if(instance == NULL)
    {
        ret = 0;
    }


    return ret;
}


int afpacket_start(void *handle)
{
    int ret = 0;
    AFPacketInstance *instance = (AFPacketInstance *) handle;


    ret = bind_interface(instance);
    ret = set_nic_promisc(instance);
    instance->state = STATE_STARTED;


    return ret;
}

int afpacket_acquire(void *handle, Pkt_Buf *p_pkt_buf, u_int32_t buffer_len)
{
    AFPacketInstance *instance  = (AFPacketInstance *) handle;
    int  fromlen                = 0;
    Dlc_Header  *pdlc_header	= NULL;
    Ip_Header   *pip_header	    = NULL;
    Tcp_Header  *ptcp_header    = NULL;
    u_int8_t    *buffer         = p_pkt_buf->buf;

    fromlen = recv(instance->fd, buffer, buffer_len, MSG_TRUNC);
    if (fromlen>0)
    {
        //mac
        pdlc_header     = (Dlc_Header *) buffer;
        if (ntohs(pdlc_header->ethertype) != IP_TYPE)
        {
            return 0;
        }

        //IP
        pip_header              = (Ip_Header *) (buffer+sizeof(Dlc_Header));
        p_pkt_buf->p_ip_header	= (u_int8_t *)pip_header;
        if (pip_header->proto != TCP_TYPE)
        {
            return 0;
        }

        //TCP
        ptcp_header             = (Tcp_Header *) ((u_int8_t*)pip_header+((pip_header->ver_len&0x0f)<<2));
        p_pkt_buf->p_tcp_header	= (u_int8_t *)ptcp_header;
        if (ntohs(ptcp_header->dstport) != HTTP_PORT)
        {
            return 0;
        }
        p_pkt_buf->p_http_header=( (u_int8_t *)ptcp_header) + 20;
    }

    return fromlen;
}

int afpacket_send(void *handle, Pkt_Buf *send_pkt)
{
    AFPacketInstance *instance  = (AFPacketInstance *) handle;
    int  send_success           = 0;

    send_success    = send(instance->fd, send_pkt->buf, send_pkt->buf_len, MSG_DONTROUTE);
    
    return send_success;
}

int afpacket_close(void *handle)
{
    int ret = 0;
    AFPacketInstance *instance = (AFPacketInstance *) handle;


    destroy_instance(instance);
    instance->state = STATE_STOPPED;


    return ret;
}




#ifdef __cplusplus
}
#endif
