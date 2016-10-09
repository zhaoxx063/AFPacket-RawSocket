#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "afpacket.h"
#include "dictionary.h"
#include "iniparser.h"
#include "pub.h"
typedef struct send_arg
{
    u_int32_t           repick_times;
    u_int32_t           send_num;
    u_int32_t           gap_time;
    u_int8_t            p_eth[256];
    Pkt_Buf             *p_http_pkt;
}SEND_ARG;

u_int32_t   g_repick_time;
void *pkt_send(void *data)
{
    AFPacketInstance    *instance;
    SEND_ARG            *p_send_arg     = (SEND_ARG*)data;
    u_int32_t           send_num        = p_send_arg->send_num;
    u_int32_t           gap_time        = p_send_arg->gap_time;
    u_int32_t           repick_times    = p_send_arg->repick_times;
    Pkt_Buf             *p_http_pkt     = p_send_arg->p_http_pkt;
    u_int8_t            *p_eth          = p_send_arg->p_eth; 
    u_int32_t           i;
    if (afpacket_init(p_eth, (void **)(&instance)) == 0)
    {
        printf("afpacket_init fail , pkt_recv thread quit!\n");
        return ;
    }
    if (afpacket_start((void *)instance) == -1)
    {
        printf("afpacket_start fail , pkt_send thread quit!\n");
        return ;
    }
    
    printf("into pkt_send thread\n");
    for(i=0; (i<send_num)||(send_num==0); i++)
    {
        u_int8_t send_success;
        g_repick_time++;
        if ((g_repick_time%repick_times) == 0)
        {
            (((Ip_Header*)(p_http_pkt->p_ip_header))->sourceIP)++;  //sourceip change for test
        }
        
        send_success = afpacket_send(instance,p_http_pkt);
    
        if (gap_time != 0)
        {
            usleep(gap_time);
        }
        
        if (send_success<=0)
        { 
            printf("afpcket_send fail!\n");
        }
    }

}
int thread_set_cpu(pthread_t pid, int cpu_index, int cpu_num)
{
    cpu_set_t   mask;
    cpu_set_t   get;
    int         i;


    CPU_ZERO(&mask);
    CPU_SET(cpu_index, &mask);
    if (pthread_setaffinity_np(pid, sizeof(mask), &mask) < 0)
    {
        printf("set thread affinity process%d failed!\n", cpu_index);
        return 0;
    }
    CPU_ZERO(&get);
    if (pthread_getaffinity_np(pid, sizeof(get), &get) < 0)
    {
        printf("get thread affinity process%d failed!\n", cpu_index);
        return 0;
    }
    for (i=0; i<cpu_num; i++)
    {
        if (CPU_ISSET(i, &get))
        {
            printf("thread %d is running in processor %d\n", (int)pid, i);
        }
    }

    return 1;
}

void replace_rn(char *p_value)
{
    int i;
    for (i=0; i<strlen(p_value); i++)
    {
        if (p_value[i] == '$')
        {
            p_value[i]  = '\r';
        }
        if (p_value[i] == '^')
        {
            p_value[i]  = '\n';
        }
    }
}
void main(int argc, char* argv[])
{
    AFPacketInstance    *instance;
    Pkt_Buf             http_pkt;
    http_pkt.buf        = calloc(2000,1);
    
    if (argc != 7)
    {
        printf("argv: eth_xx gap_time(us 0:as fast as possible) send_num(0:no stop) thread_num cpu_start repick_times\n");
        return;
    }
    u_int32_t   gap_time    = atol(argv[2]);
    u_int32_t   send_num    = atol(argv[3]);
    u_int32_t   thread_num  = atol(argv[4]);
    u_int32_t   cpu_start   = atol(argv[5]);
    u_int32_t   repick_times= atol(argv[6]);
    
    Dlc_Header  mac;
    Ip_Header   ip;
    Tcp_Header  tcp;
    dictionary  *p_dic;
    char        *p_value        = NULL;
    char        *p_value_start  = NULL;
    u_int32_t   value;
    u_int32_t   i;
    u_int32_t   len;
    
    p_dic   = iniparser_load("pkt.ini");
    if (p_dic == NULL)
    {
        return;
    }
    
    //mac
    p_value = iniparser_getstring(p_dic, "mac:desmac", "desmac");
    if (p_value == NULL)
    {
        return;
    }
    printf("%s\n", p_value);
    for(p_value_start   = p_value,i=0; *p_value != '\0'&&i<6; p_value++)
    {
        
        if(*p_value != ' ' && *(p_value+1)!='\0')
        {
            continue;
        }
        if (*p_value==' ')
        {
            *p_value ='\0';
        }
        
        if (strlen(p_value_start)>0)
        {
            mac.desmac[i]   = strtol(p_value_start, NULL, 16);
            i++;
        }
        p_value_start       = p_value+1;
    }

    p_value = iniparser_getstring(p_dic, "mac:srcmac", "srcmac");
    if (p_value == NULL)
    {
        return;
    }
    printf("%s\n", p_value);
    for(p_value_start   = p_value,i=0; *p_value != '\0'&&i<6; p_value++)
    {
        
        if(*p_value != ' ' && *(p_value+1)!='\0')
        {
            continue;
        }
        if (*p_value==' ')
        {
            *p_value ='\0';
        }
        
        if (strlen(p_value_start)>0)
        {
            mac.srcmac[i]   = strtol(p_value_start, NULL, 16);
            printf("0x%x ", mac.srcmac[i]);
            i++;
        }
        p_value_start       = p_value+1;
    }
    
    value = iniparser_getint(p_dic, "mac:ethertype", 0);
    printf("ethertype:%d\n", value);
    mac.ethertype               = htons(value);
    
    memcpy(http_pkt.buf, &mac, sizeof(mac));
    len                         = sizeof(mac);
    
    //ip
    http_pkt.p_ip_header    = http_pkt.buf+len;
    value = iniparser_getint(p_dic, "ip:ver_len", 0);
    printf("ver_len:%d\n", value);
    ip.ver_len             = value;
    
    value = iniparser_getint(p_dic, "ip:tos", 0);
    printf("tos:%d\n", value);
    ip.tos             = value;
    
    value = iniparser_getint(p_dic, "ip:total_len", 0);
    printf("total_len:%d\n", value);
    ip.total_len             = htons(value);
    
    value = iniparser_getint(p_dic, "ip:ident", 0);
    printf("ident:%d\n", value);
    ip.ident             = htons(value);
    
    value = iniparser_getint(p_dic, "ip:frag_and_flags", 0);
    printf("frag_and_flags:%d\n", value);
    ip.frag_and_flags             = htons(value);
    
    value = iniparser_getint(p_dic, "ip:ttl", 0);
    printf("ttl:%d\n", value);
    ip.ttl             = value;
    
    value = iniparser_getint(p_dic, "ip:proto", 0);
    printf("proto:%d\n", value);
    ip.proto             = value;
    
    value = iniparser_getint(p_dic, "ip:checksum", 0);
    printf("checksum:%d\n", value);
    ip.checksum             = htons(value);
    
    p_value = iniparser_getstring(p_dic, "ip:sourceIP", NULL);
    printf("sourceIP:%s\n", p_value);
    ip.sourceIP             = inet_addr(p_value);
    printf("sourceIP:%x\n", ip.sourceIP);

    p_value = iniparser_getstring(p_dic, "ip:destIP", NULL);
    printf("destIP:%s\n", p_value);
    ip.destIP               = inet_addr(p_value);
    printf("destIP:%x\n", ip.destIP);
    
    memcpy(http_pkt.buf+len, &ip, sizeof(ip));
    len                         += sizeof(ip);
    
    //tcp
    value = iniparser_getint(p_dic, "tcp:srcport", 0);
    printf("srcport:%d\n", value);
    tcp.srcport             = htons(value);
    
    value = iniparser_getint(p_dic, "tcp:dstport", 0);
    printf("dstport:%d\n", value);
    tcp.dstport             = htons(value);
    
    value = iniparser_getint(p_dic, "tcp:seqnum", 0);
    printf("seqnum:%x\n", (u_int32_t)value);
    tcp.seqnum             = htonl(value);
    
    value = iniparser_getint(p_dic, "tcp:acknum", 0);
    printf("acknum:%x\n", (u_int32_t)value);
    tcp.acknum             = htonl(value);
    
    value = iniparser_getint(p_dic, "tcp:dataoff", 0);
    printf("dataoff:%d\n", value);
    tcp.dataoff             = value;
    
    value = iniparser_getint(p_dic, "tcp:flags", 0);
    printf("flags:%d\n", value);
    tcp.flags             = value;
    
    value = iniparser_getint(p_dic, "tcp:window", 0);
    printf("window:%d\n", value);
    tcp.window             = htons(value);
    
    value = iniparser_getint(p_dic, "tcp:chksum", 0);
    printf("chksum:%d\n", value);
    tcp.chksum             = htons(value);
    
    value = iniparser_getint(p_dic, "tcp:urgptr", 0);
    printf("urgptr:%d\n", value);
    tcp.urgptr             = htons(value);
    
    memcpy(http_pkt.buf+len, &tcp, sizeof(tcp));
    len                         += sizeof(tcp);
    
    //http
    p_value = iniparser_getstring(p_dic, "http:reqline", NULL);
    if (p_value != NULL)
    {
        printf("reqline:%s\n", p_value);
        replace_rn(p_value);
        memcpy(http_pkt.buf+len, p_value, strlen(p_value));
        len                         += strlen(p_value);
    }
    p_value = iniparser_getstring(p_dic, "http:host", NULL);
    if (p_value != NULL)
    {
        printf("host:%s\n", p_value);
        replace_rn(p_value);
        memcpy(http_pkt.buf+len, p_value, strlen(p_value));
        len                         += strlen(p_value);
    }
    
    p_value = iniparser_getstring(p_dic, "http:connection", NULL);
    if (p_value != NULL)
    {
        printf("connection:%s\n", p_value);
        replace_rn(p_value);
        memcpy(http_pkt.buf+len, p_value, strlen(p_value));
        len                         += strlen(p_value);
    }
    p_value = iniparser_getstring(p_dic, "http:accept", NULL);
    if (p_value != NULL)
    {
        printf("accept:%s\n", p_value);
        replace_rn(p_value);
        memcpy(http_pkt.buf+len, p_value, strlen(p_value));
        len                         += strlen(p_value);
    }
    p_value = iniparser_getstring(p_dic, "http:useragent", NULL);
    if (p_value != NULL)
    {
        printf("useragent:%s\n", p_value);
        replace_rn(p_value);
        memcpy(http_pkt.buf+len, p_value, strlen(p_value));
        len                         += strlen(p_value);
    }
    p_value = iniparser_getstring(p_dic, "http:referer", NULL);
    if (p_value != NULL)
    {
        printf("referer:%s\n", p_value);
        replace_rn(p_value);
        memcpy(http_pkt.buf+len, p_value, strlen(p_value));
        len                         += strlen(p_value);
    }
    p_value = iniparser_getstring(p_dic, "http:accepte", NULL);
    if (p_value != NULL)
    {
        printf("accepte:%s\n", p_value);
        replace_rn(p_value);
        memcpy(http_pkt.buf+len, p_value, strlen(p_value));
        len                         += strlen(p_value);
    }
    p_value = iniparser_getstring(p_dic, "http:acceptl", NULL);
    if (p_value != NULL)
    {
        printf("acceptl:%s\n", p_value);
        replace_rn(p_value);
        memcpy(http_pkt.buf+len, p_value, strlen(p_value));
        len                         += strlen(p_value);
    }
    http_pkt.buf_len    = len;
    printf("len:%d\n", len);
//    for(i=0; i<len; i++)
//    {
//        printf("0x%02x ", http_pkt.buf[i]);
//    }
//    printf("\n");
    

    pthread_t       p_th_send[100];
    SEND_ARG        p_send_arg[100];
    int             cpu_index;
    if (thread_num>100)
    {
        printf("thread num >100");
    }
    for(i=0; i<thread_num; i++)
    {
        p_send_arg[i].send_num          = send_num;
        p_send_arg[i].gap_time          = gap_time;
        p_send_arg[i].p_http_pkt        = &http_pkt;
        p_send_arg[i].repick_times      = repick_times;
        strcpy(p_send_arg[i].p_eth,  argv[1]);
        if (pthread_create(&p_th_send[i], NULL, pkt_send, (void*)&p_send_arg[i]) != 0)
        {
            printf("create pkt_send thread failed!\n");
            return;
        }
        cpu_index   = (i+cpu_start)%(sysconf(_SC_NPROCESSORS_CONF));
        if (thread_set_cpu(p_th_send[i], cpu_index, sysconf(_SC_NPROCESSORS_CONF)) == 0)
        {
            printf("recv thread%d set cpu failed!\n", i);
            return;
        }
    }
    
    while(1)
    {
        sleep(100);
    }
}
