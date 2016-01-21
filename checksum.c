#include	<stdio.h>
#include	<string.h>
#include	<unistd.h>
#include	<poll.h>
#include	<errno.h>
#include	<signal.h>
#include	<stdarg.h>
#include	<sys/ioctl.h>
#include	<arpa/inet.h>
#include	<sys/socket.h>
#include	<linux/if.h>
#include	<net/ethernet.h>
#include	<netpacket/packet.h>
#include	<netinet/if_ether.h>
#include	<netinet/ip.h>
#include	<netinet/ip6.h>
#include	<netinet/ip_icmp.h>
#include	<netinet/icmp6.h>
#include	<netinet/tcp.h>
#include	<netinet/udp.h>
#include	<netinet/in.h>
#include	<arpa/inet.h>


#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6  0x86dd
#endif

#include "checksum.h"


struct pseudo_ip{
        struct in_addr  ip_src;
        struct in_addr  ip_dst;
        unsigned char   dummy;
        unsigned char   ip_p;
        unsigned short  ip_len;
};

struct pseudo_ip6_hdr{
        struct in6_addr src;
        struct in6_addr dst;
        unsigned long   plen;
        unsigned short  dmy1;
        unsigned char   dmy2;
        unsigned char   nxt;
};


u_int16_t CheckSum(u_char *data, int len)
{
  register u_int32_t       sum;
  register u_int16_t       *ptr;
  register int     c;

  sum = 0;
  ptr = (u_int16_t *)data;

  for(c = len; c > 1; c -= 2){
    sum += (*ptr);
    if(sum & 0x80000000){
      sum=(sum & 0xFFFF) + (sum >> 16);
    }
    ptr++;
  }
  if(c == 1){
    u_int16_t       val;
    val = 0;
    memcpy(&val, ptr, sizeof(u_int8_t));
    sum += val;
  }
  
  while(sum >> 16){
    sum = (sum & 0xFFFF) + (sum >> 16);
  }
   
  return(~sum);
}

u_int16_t CheckSum2(u_char *data1,int len1,u_char *data2,int len2)
{
  register u_int32_t       sum;
  register u_int16_t       *ptr;
  register int     c;

  sum = 0;
  ptr = (u_int16_t *)data1;
  for(c = len1; c > 1; c -= 2){
    sum += (*ptr);
    if(sum & 0x80000000){
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    ptr++;
  }
  
  if(c==1){
    u_int16_t       val;
    val=0;
    memcpy(&val, ptr, sizeof(u_int8_t));

    if(len2 != 0){
      val = (val << 8) + (*data2);
    }else{
      val = (val << 8) + 0;				
    }
    sum += val;
    if(sum & 0x80000000){
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    ptr = (u_int16_t *)(data2 + 1);
    len2--;
  }
  else{
    ptr=(u_int16_t *)data2;
  }
  for(c = len2; c > 1; c -= 2){
    sum += (*ptr);
    if(sum & 0x80000000){
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    ptr++;
  }
  if(c == 1){
    u_int16_t       val;
    val = 0;
    memcpy(&val, ptr, sizeof(u_int8_t));
    sum += val;
  }
  
  while(sum >> 16){
    sum = (sum & 0xFFFF) + (sum >> 16);
  }
  
  
  return(~sum);
}

u_int16_t IpHeaderCheckSum(struct iphdr *iphdr)
{
  struct iphdr       iptmp;
  unsigned short	sum;
  u_char* option;
  int optionLen;

  memcpy(&iptmp, iphdr, sizeof(struct iphdr));
  
  optionLen = iptmp.ihl * 4 - sizeof(struct iphdr);
  if(optionLen > 0){
    option = (u_char*)&iptmp + sizeof(struct iphdr);
  }else{
    option = 0;
    optionLen = 0;
  }

  if(optionLen == 0){
    sum = CheckSum((u_char *)&iptmp, sizeof(struct iphdr));
  }
  else{
    sum = CheckSum2((u_char *)&iptmp, sizeof(struct iphdr), option, optionLen);
  }
  return sum;
}


u_int16_t IpDataCheckSum(struct iphdr *iphdr, unsigned char *data, int len)
{
  struct pseudo_ip p_ip;
  unsigned short sum;

  memset(&p_ip, 0, sizeof(struct pseudo_ip));
  p_ip.ip_src.s_addr = iphdr->saddr;
  p_ip.ip_dst.s_addr = iphdr->daddr;
  p_ip.ip_p = iphdr->protocol;
  p_ip.ip_len = htons(len);
  
  sum = CheckSum2((unsigned char *)&p_ip, sizeof(struct pseudo_ip), data, len);
  
  return sum;
}
