/****************************************************************
 * Version : V1.00
 * Author :  CCH
 * Create Date: 2014:11:26
 * FileName :
 * Description:
 *
 * Modify Log: 2015:7:2 modify afpacket recv use ring mmap
 *
 ****************************************************************/
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include "afpacket.h"

#ifdef __cplusplus
extern "C" {
#endif

//fd use nic_name to get ifr_ifindex
int get_nic_index(int fd, const char* p_nic_name)
{
    if (p_nic_name == NULL)
    {
        return AF_ERROR;
    }

    struct ifreq    ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, p_nic_name, IFNAMSIZ);

    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1)
    {
        printf("SIOCGIFINDEX ioctl error: %s\n",  strerror(errno));
        return AF_ERROR;
    }

    return ifr.ifr_ifindex;
}

//destroy instance
static void destroy_instance(AFPacketInstance *p_instance)
{
    if (p_instance)
    {
        if (p_instance->fd != -1)
        {
            close(p_instance->fd);
        }
        if (p_instance->name != NULL)
        {
            free(p_instance->name);
            p_instance->name = NULL;
        }

        free(p_instance);
    }
}

//create instance
static AFPacketInstance *create_instance(const char *p_device)
{
    if (p_device == NULL)
    {
        printf("p_device is NULL\n");
        return NULL;
    }

    AFPacketInstance    *p_instance = NULL;
    struct ifreq ifr;

    //p_instance
    p_instance = calloc(1, sizeof(AFPacketInstance));
    if (!p_instance)
    {
        printf("%s: Could not allocate a new instance structure.\n", __FUNCTION__);
        goto err;
    }
    //p_instance->name
    if ((p_instance->name = strdup(p_device)) == NULL)
    {
        printf("%s: Could not allocate a copy of the device name.\n", __FUNCTION__);
        goto err;
    }
    //p_instance->fd
    p_instance->fd    = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (p_instance->fd == -1)
    {
        printf("%s: Could not open the PF_PACKET socket: %s\n", __FUNCTION__, strerror(errno));
        goto err;
    }
    //p_instance->index
    p_instance->index = get_nic_index(p_instance->fd, p_instance->name);
    if (p_instance->index == -1)
    {
        printf("%s: Could not find index for device %s\n", __FUNCTION__, p_instance->name);
        goto err;
    }
    //p_instance->sll
    p_instance->sll.sll_family      = AF_PACKET;
    p_instance->sll.sll_ifindex     = p_instance->index;
    p_instance->sll.sll_protocol    = htons(ETH_P_ALL);
    //p_instance->ring_size
    p_instance->ring_size           = RING_SIZE*1024;
    //p_instance->snaplen
    p_instance->snaplen             = AF_MTU;

    return p_instance;

err:
    destroy_instance(p_instance);
    return NULL;
}



static int bind_instance_interface( AFPacketInstance *p_instance)
{
    //bind to choice device
    if (bind(p_instance->fd, (struct sockaddr *) &(p_instance->sll), sizeof(p_instance->sll)) != 0)
    {
        printf("%s: bind error: %s\n", __FUNCTION__, strerror(errno));
        return AF_ERROR;
    }

    //check any pending errors
    int         err;
    socklen_t   errlen  = sizeof(err);
    if (getsockopt(p_instance->fd, SOL_SOCKET, SO_ERROR, &err, &errlen) || err)
    {
        printf("%s: getsockopt: %s", __FUNCTION__, strerror(errno));
        return AF_ERROR;
    }

    return AF_SUCCESS;
}

// Turn on promiscuous mode for the device.
static int set_nic_promisc(AFPacketInstance *p_instance)
{
    struct packet_mreq  mr;

    memset(&mr, 0, sizeof(mr));
    mr.mr_ifindex   = p_instance->index;
    mr.mr_type      = PACKET_MR_PROMISC;
    if (setsockopt(p_instance->fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) == -1)
    {
        printf("%s: setsockopt: %s", __FUNCTION__, strerror(errno));
        return AF_ERROR;
    }

    return AF_SUCCESS;
}
static int iface_get_arptype(AFPacketInstance *p_instance)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, p_instance->name, sizeof(ifr.ifr_name));
    if (ioctl(p_instance->fd, SIOCGIFHWADDR, &ifr) == -1)
    {
        return AF_ERROR;
    }

    return ifr.ifr_hwaddr.sa_family;
}
// The function below was heavily influenced by LibPCAP's pcap-linux.c.  Thanks!
static int determine_version(AFPacketInstance *p_instance)
{
    socklen_t   len;
    int         val;

    // Probe whether kernel supports TPACKET_V2
    val     = TPACKET_V2;
    len     = sizeof(val);
    if (getsockopt(p_instance->fd, SOL_PACKET, PACKET_HDRLEN, &val, &len) < 0)
    {
        return AF_ERROR;
    }
    p_instance->tp_hdrlen = val;

    /* Tell the kernel to use TPACKET_V2 */
    val = TPACKET_V2;
    if (setsockopt(p_instance->fd, SOL_PACKET, PACKET_VERSION, &val, sizeof(val)) < 0)
    {
        return AF_ERROR;
    }
    p_instance->tp_version = TPACKET_V2;

    /* Reserve space for VLAN tag reconstruction */
    val = VLAN_TAG_LEN;
    if (setsockopt(p_instance->fd, SOL_PACKET, PACKET_RESERVE, &val, sizeof(val)) < 0)
    {
        return AF_ERROR;
    }

    return AF_SUCCESS;
}
//calculate layout
static int calculate_layout(AFPacketInstance    *p_instance,
                            struct tpacket_req  *layout,
                            u_int32_t           tp_hdrlen,
                            u_int32_t           order)
{
    u_int32_t tp_hdrlen_sll, netoff, frames_per_block;

    //tp_frame_size
    tp_hdrlen_sll           = TPACKET_ALIGN(tp_hdrlen) + sizeof(struct sockaddr_ll);
    netoff                  = TPACKET_ALIGN(tp_hdrlen_sll + ETH_HLEN) + VLAN_TAG_LEN;
    layout->tp_frame_size   = TPACKET_ALIGN(netoff - ETH_HLEN + p_instance->snaplen);
    //tp_block_size
    layout->tp_block_size   = getpagesize() << order;
    while (layout->tp_block_size < layout->tp_frame_size)
        layout->tp_block_size <<= 1;
    //tp_block_nr & tp_frame_nr
    frames_per_block        = layout->tp_block_size / layout->tp_frame_size;
    if (frames_per_block == 0)
    {
        printf("Invalid frames per block\n");
        return AF_ERROR;
    }
    layout->tp_frame_nr     = p_instance->ring_size / layout->tp_frame_size;
    layout->tp_block_nr     = layout->tp_frame_nr / frames_per_block;
    layout->tp_frame_nr     = layout->tp_block_nr * frames_per_block;

    return AF_SUCCESS;
}

static int create_ring(AFPacketInstance *p_instance, AFPacketRing *ring, int optname)
{
    u_int32_t     order;

    //Starting with page allocations of order 3, try to allocate an RX ring in the kernel.
    for (order = DEFAULT_ORDER; order >= 0; order--)
    {
        if (calculate_layout(p_instance,
                            &ring->layout,
                            p_instance->tp_hdrlen,
                            order) != AF_SUCCESS)
        {
            return AF_ERROR;
        }
        // Ask the kernel to create the ring.
        if (setsockopt( p_instance->fd,
                        SOL_PACKET,
                        optname,
                        (void*) &ring->layout,
                        sizeof(struct tpacket_req)) != AF_SUCCESS)
        {
            if (errno == ENOMEM)
            {
                printf("%s: Allocation of kernel packet ring failed with order %d, retrying...\n", p_instance->name, order);
                continue;
            }
            return AF_ERROR;
        }
        // Store the total ring size for later.
        ring->size  = ring->layout.tp_block_size * ring->layout.tp_block_nr;
        return AF_SUCCESS;
    }

    return AF_ERROR;
}

static int mmap_rings(AFPacketInstance *p_instance)
{
    u_int32_t ring_size;

    // Map the ring into userspace.
    ring_size               = p_instance->rx_ring.size + p_instance->tx_ring.size;
    p_instance->buffer      = mmap(0, ring_size, PROT_READ|PROT_WRITE, MAP_SHARED, p_instance->fd, 0);
    if (p_instance->buffer == MAP_FAILED)
    {
        printf("Could not MMAP the ring!\n");
        return AF_ERROR;
    }
    p_instance->rx_ring.start = p_instance->buffer;
    p_instance->tx_ring.start = (u_int8_t *) p_instance->buffer + p_instance->rx_ring.size;

    return AF_SUCCESS;
}

static int set_up_ring(AFPacketRing *ring)
{
    u_int32_t idx, block, block_offset, frame, frame_offset;

    //Allocate a ring to hold packet pointers.
    ring->entries   = calloc(ring->layout.tp_frame_nr, sizeof(AFPacketEntry));
    if (!ring->entries)
    {
        return AF_ERROR;
    }

    //Set up the buffer entry pointers in the ring.
    for (idx=0, block=0; block<(ring->layout.tp_block_nr); block++)
    {
        block_offset    = block * ring->layout.tp_block_size;
        for (frame=0; frame<(ring->layout.tp_block_size/ring->layout.tp_frame_size) && idx<(ring->layout.tp_frame_nr); frame++)
        {
            frame_offset                = frame * ring->layout.tp_frame_size;
            ring->entries[idx].hdr.raw  = (u_int8_t *) ring->start + block_offset + frame_offset;
            ring->entries[idx].next     = &(ring->entries[idx + 1]);
            idx++;
        }
    }
    //Make this a circular buffer ... a RING if you will!
    ring->entries[ring->layout.tp_frame_nr - 1].next = &ring->entries[0];
    //printf("ring->layout.tp_frame_nr%d\n", ring->layout.tp_frame_nr);
    //Initialize our entry point into the ring as the first buffer entry.
    ring->cursor    = &ring->entries[0];

    return AF_SUCCESS;
}
static void reset_stats(AFPacketInstance *p_instance)
{
    memset(&p_instance->stats, 0, sizeof(Af_Stats));

    struct      tpacket_stats kstats;
    socklen_t   len = sizeof (struct tpacket_stats);
    getsockopt(p_instance->fd, SOL_PACKET, PACKET_STATISTICS, &kstats, &len);
}

u_int8_t afpacket_init(const char *dev_name, void **ctxt_ptr)
{
    AFPacketInstance    *p_instance;

    p_instance          = create_instance(dev_name);
    *ctxt_ptr           = p_instance;

    if(p_instance == NULL)
    {
        return AF_ERROR;
    }

    return AF_SUCCESS;
}


int afpacket_start(void *handle, u_int8_t send0_recv1)
{
    AFPacketInstance *p_instance = (AFPacketInstance *) handle;

    //bind
    if (bind_instance_interface(p_instance) != AF_SUCCESS)
    {
        printf("bind fail!\n");
        return AF_ERROR;
    }
    if (send0_recv1 == 0)
    {
        return AF_SUCCESS;
    }
    //set promiscuous
    if (set_nic_promisc(p_instance) != AF_SUCCESS)
    {
        return AF_ERROR;
    }
    //get the link-layer type
    int     arptype;
    arptype     = iface_get_arptype(p_instance);
    if (arptype < 0)
    {
        printf("get arptype fail!\n");
        return AF_ERROR;
    }
    if (arptype != ARPHRD_ETHER)
    {
        printf("arptype != ARPHRD_ETHER!\n");
        return AF_ERROR;
    }
    //determine TPACKET_V2
    if (determine_version(p_instance) != AF_SUCCESS)
    {
        printf("determine_version fail!\n");
        return AF_ERROR;
    }
    //create rx ring
    if (create_ring(p_instance, &p_instance->rx_ring, PACKET_RX_RING) != AF_SUCCESS)
    {
        printf("create rx_ring fail!\n");
        return AF_ERROR;
    }
    //create tx ring
    if (create_ring(p_instance, &p_instance->tx_ring, PACKET_TX_RING) != AF_SUCCESS)
    {
        printf("create tx_ring fail!\n");
        return AF_ERROR;
    }
    //mmap_rings
    if (mmap_rings(p_instance) != AF_SUCCESS)
    {
        printf("mmap_rings fail!\n");
        return AF_ERROR;
    }
    //set_up_ring
    if (set_up_ring(&p_instance->rx_ring) != AF_SUCCESS)
    {
        printf("set_up_ rx_ring fail!\n");
        return AF_ERROR;
    }
    if (set_up_ring(&p_instance->tx_ring) != AF_SUCCESS)
    {
        printf("set_up_ tx_ring fail!\n");
        return AF_ERROR;
    }
    //reset_stats
    reset_stats(p_instance);

    return AF_SUCCESS;
}


inline int afpacket_acquire(void *handle, Pkt_Buf *p_pkt_buf, u_int32_t buffer_len)
{
    AFPacketInstance    *p_instance  = (AFPacketInstance *) handle;

    union thdr          hdr;
    u_int32_t           tp_mac, tp_snaplen;
    const u_int8_t      *p_data;

    hdr = p_instance->rx_ring.cursor->hdr;
    if (hdr.h2->tp_status & TP_STATUS_USER)
    {
        tp_mac                      = hdr.h2->tp_mac;
        tp_snaplen                  = hdr.h2->tp_snaplen;

        //tp_mac + tp_snaplen check
        if (tp_snaplen == 0)
        {
            tp_snaplen  = 0;
            goto RING_NEXT;
        }
        if (tp_mac + tp_snaplen > p_instance->rx_ring.layout.tp_frame_size)
        {
            tp_snaplen  = 0;
            goto RING_NEXT;
        }
        //vlan
        if (hdr.h2->tp_vlan_tci && AF_VLAN_ENABLE)
        {
            u_int32_t   tp_vlan_tci = hdr.h2->tp_vlan_tci;
        }
        //p_data
        if (tp_snaplen > buffer_len)
        {
            tp_snaplen  = buffer_len;
        }
        p_data      = p_instance->rx_ring.cursor->hdr.raw + tp_mac;
        u_int8_t    *p_buffer             = p_pkt_buf->buf;
        memcpy(p_buffer, p_data, tp_snaplen);
        //pkt handle
        Dlc_Header  *pdlc_header    = NULL;
        Ip_Header   *pip_header     = NULL;
        Tcp_Header  *ptcp_header    = NULL;
        u_int8_t    vlan_tag_len    = 0;
        //mac
        pdlc_header     = (Dlc_Header *) p_buffer;
        if (pdlc_header->ethertype == VLAN_TAG)
        {
            if (*((u_int16_t*)(p_buffer+16)) != IP_TYPE_NET)
            {
                tp_snaplen  = 0;
                goto RING_NEXT;
            }
            vlan_tag_len    = 4;
        }
        else if (pdlc_header->ethertype != IP_TYPE_NET)
        {
            tp_snaplen  = 0;
            goto RING_NEXT;
        }
        //IP
        pip_header              = (Ip_Header *) (p_buffer+sizeof(Dlc_Header)+vlan_tag_len);
        p_pkt_buf->p_ip_header  = (u_int8_t *)pip_header;
        if (pip_header->proto != TCP_TYPE)
        {
            tp_snaplen  = 0;
            goto RING_NEXT;
        }
        //TCP
        ptcp_header             = (Tcp_Header *) ((u_int8_t*)pip_header+((pip_header->ver_len&0x0f)<<2));
        p_pkt_buf->p_tcp_header = (u_int8_t *)ptcp_header;
        //HTTP
        if (ptcp_header->dstport != HTTP_PORT_NET)
        {
            p_pkt_buf->pkt_http = 0;
        }
        else
        {
            p_pkt_buf->pkt_http = 1;
            p_pkt_buf->p_http_header= ((u_int8_t *)ptcp_header) + ((ptcp_header->dataoff&0xf0)>>2);
        }
        //p2p
        p_pkt_buf->pkt_type     = 0;

RING_NEXT:
        hdr.h2->tp_status               = TP_STATUS_KERNEL;
        p_instance->rx_ring.cursor      = p_instance->rx_ring.cursor->next;
        return tp_snaplen;
    }

    struct pollfd   pfd;
    pfd.fd          = p_instance->fd;
    pfd.revents     = 0;
    pfd.events      = POLLIN;
    while(poll(&pfd, 1, -1)<=0);
    return 0;
}
inline int afpacket_send(void *handle, Pkt_Buf *p_send_pkt)
{
    AFPacketInstance *p_instance    = (AFPacketInstance *) handle;
    int  send_success               = 0;

    send_success    = send(p_instance->fd, p_send_pkt->buf, p_send_pkt->buf_len, MSG_DONTROUTE);

    return send_success;
}

int afpacket_close(void *handle)
{
    int ret = 0;
    AFPacketInstance *p_instance = (AFPacketInstance *) handle;

    destroy_instance(p_instance);

    return ret;
}




#ifdef __cplusplus
}
#endif
