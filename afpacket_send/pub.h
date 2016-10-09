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
#ifndef __USE_GNU
#define __USE_GNU
#endif
#include <pthread.h>
#ifdef __cplusplus
extern "C" {
#endif


//宏定义
#define STR_MAX_LEN         (256)
#define MTU_MAX             (2000)
#define PLUGIN_MAX_NUM      (100)
#define RULE_MAX_NUM        (5)

#define IP_TYPE             (0x0800)
#define TCP_TYPE            (0x06)
#define HTTP_PORT           (0x0050)

#define NCS_HOST_MAX_NUM    10
#define INTRANET_MAX_NUM    5
#define BLACKLIST_MAX_NUM   50
#define WHITELIST_MAX_NUM   50

#define UINT32_TO_UINT64(u1, u2)    ((((long long)u2<<32)&0xffffffff00000000)+(u1&0x00000000ffffffff))
#define UINT64H_TO_UINT32(u64)      (((u64)>>32)&0x00000000ffffffff)
#define UINT64L_TO_UINT32(u64)      ((u64)&0x00000000ffffffff)
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
   u_int8_t         *p_mirror_port;
   u_int8_t         *p_manage_port;
   u_int8_t         *p_manage_ip;
   u_int8_t         thread_num;
   u_int8_t         filter_mode;       //0:no filter 1:blacklist filter 2:whitelist filter
   Ip_Filter        ncs_ip_filter;
   Hash_Table       cache_hash_table;
   Hash_Table       domain_hash_table;
   Hash_Table       type_hash_table_0;
   Hash_Table       type_hash_table_1;
   u_int8_t         p_xml_path[STR_MAX_LEN];
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
}Pkt_Buf;

typedef struct http_get_info
{
    u_int32_t       hash_key_1;
    u_int32_t       hash_key_2;
    u_int8_t        method;
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
}Http_Get_Info;

typedef struct ncs_download
{
    u_int32_t       hash_key_1;     //BKD
    u_int32_t       hash_key_2;     //Tianl
    u_int8_t        p_host[MTU_MAX];
    u_int32_t       secondary_id;
    u_int8_t        p_hash_url[MTU_MAX];
    u_int8_t        p_down_url_1[MTU_MAX];
    u_int8_t        p_down_url_2[MTU_MAX];
    u_int8_t        p_cookie[MTU_MAX];
}Ncs_Download;

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

#pragma pack()

//函数声明



#ifdef __cplusplus
}
#endif

#endif
