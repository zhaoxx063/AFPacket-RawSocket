#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "afpacket.h"
#include "pub.h"



int main(int argc, char* argv[])
{

//    p_recv_arg[i].send_num          = send_num;
//    p_recv_arg[i].gap_time          = gap_time;
//    p_recv_arg[i].p_http_pkt        = &http_pkt;
//    strcpy(p_recv_arg[i].p_eth,  argv[1]);
//    if (pthread_create(&p_th_send[i], NULL, pkt_recv, (void*)&p_recv_arg[i]) != 0)
//    {
//        printf("create pkt_recv thread failed!\n");
//        return;
//    }
//    cpu_index   = i%(sysconf(_SC_NPROCESSORS_CONF));
//    if (thread_set_cpu(p_th_send[i], cpu_index, sysconf(_SC_NPROCESSORS_CONF)) == 0)
//    {
//        printf("recv thread%d set cpu failed!\n", i);
//        return;
//    }

    AFPacketInstance    *instance;
    Pkt_Buf             http_pkt;
    http_pkt.buf        = calloc(200000,1);
    u_int64_t           pkt_len;
    double              pkt_len_all;
    u_int64_t           recv_pkt_num= 0;
    struct      timeval begin, end;
    double      time_interval;
    
    if (argc!=3)
    {
            printf("ethx num_per_printf !\n");
            exit(0);
    }
    double           print_num   = atol(argv[2]);
    if ((u_int64_t)print_num == 0)
    {
        printf("num_per_printf is 0 \n");
        return 0;
    }
    
    //afpacket init
    if (afpacket_init(argv[1], (void **)(&instance)) == AF_ERROR)
    {
        printf("afpacket_init fail , pkt_recv thread quit!\n");
        return ;
    }
    if (afpacket_start((void *)instance, 1) == AF_ERROR)
    {
        printf("afpacket_start fail , pkt_recv thread quit!\n");
        return ;
    }
    
    gettimeofday(&begin, NULL);
    while(1)
    {
        pkt_len = afpacket_acquire(instance,&http_pkt, 200000);
        if (pkt_len>0)
        { 
            recv_pkt_num++;
            http_pkt.buf_len    = pkt_len;
            pkt_len_all += pkt_len;
            if (recv_pkt_num%(u_int64_t)(print_num) == 0)
            {
                gettimeofday(&end, NULL);
                time_interval = (1000000 * (end.tv_sec - begin.tv_sec) + end.tv_usec - begin.tv_usec)/ 1000000.0;
                gettimeofday(&begin, NULL);
                if (time_interval<0.0000001)
                {
                    printf("num_per_printf is too smaller \n");
                    pkt_len_all     = 0;
                    continue;
                }
                printf("speed:%f Gbit/s\n", (pkt_len_all*8)/(time_interval*1024*1024*1024));
                printf("speed:%f pkt/s\n", print_num/time_interval);
                pkt_len_all = 0;
            }
        }
    }
}
