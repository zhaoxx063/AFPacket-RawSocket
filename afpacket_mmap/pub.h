/****************************************************************
 * Version : V1.00
 * Author :  CCH
 * Create Date: 2014:11:28
 * FileName :
 * Description:
 *
 * Modify Log:
 *
 ****************************************************************/
#ifndef __PUB_H__
#define __PUB_H__
//头文件引用
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif


//宏定义
#define NORMAL_PORT         0
#define MANAGE_PORT         1
#define MIRROR_PORT         8
#define INIT_PORT           32
#define BRIDGE_PORT         16
#define DOWNLOAD_PORT       2
#define OUTPUT_PORT         4
#define INJECT_PORT         64

#define CACHE_TABLE_SIZE    10000000
#define CACHE_DEEP_MAX      10
#define DOMAIN_TABLE_SIZE   100000
#define DOMAIN_DEEP_MAX     20
#define STR_MAX_LEN         (256)
#define MTU_MAX             (2000)
#define PLUGIN_MAX_NUM      (100)
#define RULE_MAX_NUM        (5)

#define IP_TYPE_NET         (0x0008)
#define VLAN_TAG            (0x0081)
#define TCP_TYPE            (0x06)
#define HTTP_PORT_NET       (0x5000)

#define NCS_HOST_MAX_NUM    10
#define INTRANET_MAX_NUM    5
#define BLACKLIST_MAX_NUM   50
#define WHITELIST_MAX_NUM   50
#define BLACKLIST_TYPE      0
#define WHITELIST_TYPE      1

#define UINT32_TO_UINT64(u1, u2)    ((((long long)u2<<32)&0xffffffff00000000)+(u1&0x00000000ffffffff))
#define UINT64H_TO_UINT32(u64)      (((u64)>>32)&0x00000000ffffffff)
#define UINT64L_TO_UINT32(u64)      ((u64)&0x00000000ffffffff)

#define PKT_MAX_LEN         2000
#define QUENE_MAX_SIZE      256
#define THREAD_NUM_MAX      16
#define MIRROR_NUM_MAX      6
#define INJECT_NUM_MAX      6
#define BRIDGE_NUM_MAX      6
#define HASH_LOCK_MAX       (THREAD_NUM_MAX+2)
#define HASH_LOCK_0         0
#define HASH_LOCK_1         1
#define HASH_LOCK_2         2
#define HASH_LOCK_3         3
#define HASH_LOCK_4         4
#define HASH_LOCK_5         5

#define DISK_MAX_NUM        10000

#define FRT_SHM_ID          0x5209

//变量声明
#pragma pack(1)
typedef struct ip_pair
{
    u_int8_t    src0_dst1;   //0: source ip; 1:dst ip
    u_int32_t   ip_range_l;
    u_int32_t   ip_range_h;
}Ip_Pair;

typedef struct ip_filter
{
    Ip_Pair     ip_rule_ncs_host[NCS_HOST_MAX_NUM];     //ncs host ip
    u_int32_t   ip_rule_ncs_host_num;
    Ip_Pair     ip_rule_intranet[INTRANET_MAX_NUM];     //intranet ip
    u_int32_t   ip_rule_intranet_num;
    Ip_Pair     ip_rule_blacklist[BLACKLIST_MAX_NUM];   //blacklist ip
    u_int32_t   ip_rule_blacklist_num;
    Ip_Pair     ip_rule_whitelist[WHITELIST_MAX_NUM];   //whitelist ip
    u_int32_t   ip_rule_whitelist_num;
} Ip_Filter;

typedef struct cache_type_filter
{
    u_int32_t   cache_type_id[PLUGIN_MAX_NUM];
    u_int32_t   cache_type_second_id[PLUGIN_MAX_NUM];
} Cache_Type_Filter;

typedef struct hash_node
{
    void    *p_next;
}Hash_Node;
typedef struct hash_table
{
    Hash_Node   *p_hash_node_array;
    u_int32_t   deep_max;
    u_int32_t   size;
    u_int32_t   all_obj_num;
}Hash_Table;

typedef struct ncs_conf_info
{
   u_int8_t         *pp_mirror_port[MIRROR_NUM_MAX];
   u_int32_t        mirror_port_num;
   u_int8_t         *pp_inject_port[INJECT_NUM_MAX];
   u_int8_t         inject_port_num;
   u_int8_t         *p_download_ip;
   u_int8_t         *p_download_netmask;
   u_int8_t         *p_download_gateway;
   u_int8_t         getway302_enable;
   u_int8_t         *p_output_ip;
   u_int8_t         thread_num;
   u_int8_t         all_cpu_num;
   u_int8_t         recv_cpu_num;
   u_int8_t         handle_cpu_num;
   u_int8_t         ip_filter_mode;       //0:no filter 1:blacklist filter 2:whitelist filter
   Ip_Filter        p_ncs_ip_filter[2];
   u_int8_t         which_ip_filter;
   Hash_Table       cache_hash_table;
   Hash_Table       p2p_cache_hash_table;
   u_int8_t         domain_filter_mode; 
   Hash_Table       domain_hash_table;
   Hash_Table       domain_black_table;
   u_int8_t         domain_lock;
   Hash_Table       type_hash_table_0;
   Hash_Table       type_hash_table_1;
   u_int16_t        *p_disk_filter;
   u_int8_t         p_xml_path[STR_MAX_LEN];
   u_int32_t        update_times;
   volatile  u_int32_t   p2p_times_download;
   volatile  u_int8_t    p2p_enable;
}Ncs_Conf_Info;

typedef struct dlc_header
{
   u_int8_t     desmac[6];
   u_int8_t     srcmac[6];
   u_int16_t    ethertype;
}Dlc_Header;

typedef struct ip_header
{
     u_int8_t   ver_len;
     u_int8_t   tos;
     u_int16_t  total_len;
     u_int16_t  ident;
     u_int16_t  frag_and_flags;
     u_int8_t   ttl;
     u_int8_t   proto;
     u_int16_t  checksum;
     u_int32_t  sourceIP;
     u_int32_t  destIP;
}Ip_Header;

typedef struct tcp_header
{
     u_int16_t  srcport;
     u_int16_t  dstport;
     u_int32_t  seqnum;
     u_int32_t  acknum;
     u_int8_t   dataoff;
     u_int8_t   flags;
     u_int16_t  window;
     u_int16_t  chksum;
     u_int16_t  urgptr;
}Tcp_Header;

typedef struct tcp_psd_header
{
    u_int32_t   sourceip;
    u_int32_t   destip;
    u_int8_t    mbz;
    u_int8_t    ptcl;
    u_int16_t   tcpl;
}Tcp_Psd_Header;

typedef struct pkt_buf
{
   u_int8_t     *buf;
   u_int32_t    buf_len;
   u_int8_t     *p_ip_header;
   u_int8_t     *p_tcp_header;
   u_int8_t     *p_http_header;
   u_int8_t     pkt_http;    
   u_int8_t     pkt_type;   // 0:normal  1:p2p
}Pkt_Buf;

typedef struct http_get_info
{
    u_int32_t       hash_key_1;
    u_int32_t       hash_key_2;
    u_int8_t        flow_flag;
    u_int8_t        method;
    u_int8_t        *p_file_name;
    u_int32_t       file_name_len;
    u_int8_t        *p_type;
    u_int32_t       type_len;
    u_int8_t        *p_url;
    u_int32_t       url_len;
    u_int8_t        *p_version;
    u_int32_t       version_len;
    u_int8_t        *p_host;
    u_int32_t       host_len;
    u_int8_t        *p_if_match;
    u_int32_t       if_match_len;
    u_int8_t        *p_if_modified_since;
    u_int32_t       if_modified_since_len;
    u_int8_t        *p_if_none_match;
    u_int32_t       if_none_match_len;
    u_int8_t        *p_if_range;
    u_int32_t       if_range_len;
    u_int8_t        *p_range;
    u_int32_t       range_len;
    u_int8_t        *p_cookie;
    u_int32_t       cookie_len;
    u_int8_t        *p_referer;
    u_int32_t       referer_len;
    u_int8_t        *p_user_agent;
    u_int32_t       user_agent_len;
}Http_Get_Info;


typedef struct p2p_info
{
    u_int32_t       hash_key_1;
    u_int32_t       hash_key_2;
    u_int8_t        flow_flag;
    u_int8_t        method;
    u_int8_t        *p_file_name;
    u_int32_t       file_name_len;
    u_int8_t        *p_type;
    u_int32_t       type_len;
    u_int8_t        *p_url;
    u_int32_t       url_len;
    u_int8_t        *p_version;
    u_int32_t       version_len;
    u_int8_t        *p_host;
    u_int32_t       host_len;
    u_int8_t        *p_if_match;
    u_int32_t       if_match_len;
    u_int8_t        *p_if_modified_since;
    u_int32_t       if_modified_since_len;
    u_int8_t        *p_if_none_match;
    u_int32_t       if_none_match_len;
    u_int8_t        *p_if_range;
    u_int32_t       if_range_len;
    u_int8_t        *p_range;
    u_int32_t       range_len;
    u_int8_t        *p_cookie;
    u_int32_t       cookie_len;
    u_int8_t        *p_referer;
    u_int32_t       referer_len;
    u_int8_t        *p_user_agent;
    u_int32_t       user_agent_len;
}P2p_Info;


typedef struct ncs_download
{
    u_int32_t       hash_key_1;     //BKD
    u_int32_t       hash_key_2;     //Tianl
    u_int8_t        p_host[MTU_MAX];
    u_int32_t       secondary_id;
    u_int32_t       domain_id;
    u_int8_t        p_hash_url[MTU_MAX];
    u_int8_t        p_down_url_1[MTU_MAX];
    u_int8_t        p_down_url_2[MTU_MAX];
    u_int8_t        p_down_url_3[MTU_MAX];
    u_int8_t        p_cookie[MTU_MAX];
}Ncs_Download;

typedef struct ncs_p2p_download
{
    u_int32_t       hash_key;     //BKD
    u_int8_t        *p_info_hash;

}Ncs_P2P_Download;


//plugin rule info
typedef struct rule_entry
{
    u_int8_t    type;       //0:URL 1:host  2:referer
    u_int8_t    match_str[STR_MAX_LEN];
    u_int32_t   match_str_len;
    int32_t     index;
}Rule_Entry;
//plugin info
typedef u_int8_t    (*PF)(Http_Get_Info *a, Ncs_Download *b);
typedef struct plugin
{
    u_int8_t    name[STR_MAX_LEN];
    u_int8_t    path[STR_MAX_LEN];
    u_int8_t    entry[STR_MAX_LEN];
    u_int32_t   times_to_down;
    u_int32_t   version;
    u_int32_t   second_id;
    u_int32_t   domain_id;
    void        *flib;
    PF          pfunc;
    Rule_Entry  rule[RULE_MAX_NUM];
    u_int8_t    rule_entry_num;
}Plugin;
//plugin array
typedef struct plugin_array
{
    Plugin              a_plugin_0[PLUGIN_MAX_NUM];
    u_int32_t           array_0_num;
    u_int32_t           array_0_state;
    Hash_Table          *p_tpye_hash_table_0;

    Plugin              a_plugin_1[PLUGIN_MAX_NUM];
    u_int32_t           array_1_num;
    u_int32_t           array_1_state;
    Hash_Table          *p_tpye_hash_table_1;

    Cache_Type_Filter   cache_type_filter;
    u_int8_t    which_array_in_use;  //0: array0  1:array1
}Plugin_Array;

typedef struct frt_recv_st
{
    u_int32_t rx_count;
    u_int32_t load_filter;  
}FRT_RECV_ST;
typedef struct frt_handle_st
{
    u_int32_t   rx_count;
    u_int32_t   pkt302send_count;
    u_int32_t   download_count;
    
    u_int32_t   reqline_filter;
    u_int32_t   deploy_filter;
    u_int32_t   modify_filter;
    u_int32_t   iphost_filter;
    u_int32_t   ipintranet_filter;
    u_int32_t   ipblk_filter;
    u_int32_t   ipwhite_filter;
    u_int32_t   domainlock_filter;
    u_int32_t   domainblk_filter;
    u_int32_t   domainwhite_filter;
    u_int32_t   suffix_filter;
    u_int32_t   ua_filter;
    u_int32_t   plugin_filter;
    u_int32_t   expiry_filter;
    u_int32_t   diskumount_filter;
    u_int32_t   nocache_filter;
    
    u_int32_t   cacheobjerr_fail;
    u_int32_t   diskiderr_fail;
    u_int32_t   redirect_fail;
    u_int32_t   pkt302send_fail;

    u_int32_t   debug[16];
    
}FRT_HANDLE_ST;
typedef struct frt_st
{
    u_int32_t       run_count;
    u_int32_t       debug[8];
    FRT_RECV_ST     recv_st[MIRROR_NUM_MAX];
    FRT_HANDLE_ST   hdle_st[THREAD_NUM_MAX];
}FRT_ST;

typedef struct getway_info
{
    u_int8_t    *p_getway_enable;
    u_int32_t   net_mask;
    u_int8_t    *p_getway_mac;
    u_int8_t    *p_lock;
}GETWAY_INFO;

extern FRT_ST  *gp_frt_shm;

#pragma pack()

//函数声明



#ifdef __cplusplus
}
#endif

#endif
