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

#include "debugprint.h"
#include "castnet.h"

struct ether_header* Cast2EthHeader(u_char* data, int size, u_char** ppdata, int* restptr)
{
  struct ether_header* rethdr = 0;
  u_char* ptr;
  int rest;

  ptr = data;
  rest = size;
  if(!ptr){
    *restptr = 0;
    return 0;
  }

  if(rest < sizeof(struct ether_header)){
      DebugPrintf("rest[%d] < sizeof(struct ether_header) !!!\n\n\n",rest);
      rethdr = 0;
  }else{
    rethdr = (struct ether_header*)ptr;
    rest -= sizeof(struct ether_header);
  }

  *restptr = rest;
  *ppdata = data + size - rest;
  return rethdr;
}

struct ether_arp* Cast2EthArp(u_char* data, int size, u_char** ppdata, int* restptr)
{
  struct ether_arp* rethdr = 0;
  u_char* ptr;
  int rest;

  ptr = data;
  rest = size;
  if(!ptr){
    *restptr = 0;
    return 0;
  }

  if(rest < sizeof(struct ether_arp)){
    DebugPrintf("rest(%d) < sizeof(struct ether_arp)\n",rest);
    rethdr = 0;
  }else{
    rethdr = (struct ether_arp*)ptr;
    rest -= sizeof(struct ether_arp);
  }
  
  *restptr = rest;
  *ppdata = data + size - rest;
  return rethdr;
}

struct iphdr* Cast2Ip4Header(u_char* data, int size, u_char** ppdata, int* restptr)
{
  struct iphdr* rethdr = 0;
  struct iphdr* tmphdr = 0;
  u_char* ptr;
  int rest;
  int hlen = 0;

  ptr = data;
  rest = size;
  if(!ptr){
    *restptr = 0;
    return 0;
  }

  if(rest < sizeof(struct iphdr)){
    DebugPrintf("rest(%d) < sizeof(struct iphdr) !!!\n\n\n",rest);
    rethdr = 0;
  }else{
    tmphdr = (struct iphdr*)ptr;
    ptr += sizeof(struct iphdr);
    rest -= sizeof(struct iphdr);
    
    hlen = tmphdr->ihl * 4;
    if(size < hlen){
      DebugPrintf("iphdr + option size overflow %d, %d error !!!\n\n\n", size, hlen);
      rethdr = 0;
    }else{
      rethdr = tmphdr;
      rest = size - hlen;
    }
  }

  *restptr = rest;
  *ppdata = data + hlen;
  return rethdr;
}

struct ip6_hdr* Cast2Ip6Header(u_char* data, int size, u_char** ppdata, int* restptr)
{
  struct ip6_hdr* rethdr = 0;
  u_char* ptr;
  int rest;

  ptr = data;
  rest = size;
  if(!ptr){
    *restptr = 0;
    return 0;
  }

  if(rest < sizeof(struct ip6_hdr)){
    DebugPrintf("rest(%d) < sizeof(struct ip6_hdr) !!!\n\n\n",rest);
    rethdr = 0;
  }else{
    rethdr = (struct ip6_hdr*)ptr;
    rest -= sizeof(struct ip6_hdr);
  }

  *restptr = rest;
  *ppdata = data + sizeof(struct ip6_hdr);
  return rethdr;
}

struct icmp* Cast2Icmp4(u_char* data, int size, u_char** ppdata, int* restptr)
{

  struct icmp* rethdr = 0;
  u_char* ptr;
  int rest;

  ptr = data;
  rest = size;
  if(!ptr){
    *restptr = 0;
    return 0;
  }

  if(rest < sizeof(struct icmp)){
    DebugPrintf("rest(%d) < sizeof(struct icmp)\n",rest);
    rethdr = 0;
  }else{
    rethdr = (struct icmp*)ptr;
    rest -= sizeof(struct icmp);
  }

  *restptr = rest;
  *ppdata = data + sizeof(struct icmp);
  return rethdr;

}

struct icmp6_hdr* Cast2Icmp6(u_char* data, int size, u_char** ppdata, int* restptr)
{
  struct icmp6_hdr* rethdr = 0;
  u_char* ptr;
  int rest;

  ptr = data;
  rest = size;
  if(!ptr){
    *restptr = 0;
    return 0;
  }

  if(rest < sizeof(struct icmp6_hdr)){
    DebugPrintf("rest(%d) < sizeof(struct icmp6)\n",rest);
    rethdr = 0;
  }else{
    rethdr = (struct icmp6_hdr*)ptr;
    rest -= sizeof(struct icmp6_hdr);
  }

  *restptr = rest;
  *ppdata = data + sizeof(struct icmp6_hdr);
  return rethdr;
}

struct tcphdr* Cast2TcpHeader(u_char* data, int size, u_char** ppdata, int* restptr)
{
  struct tcphdr* rethdr = 0;
  struct tcphdr* tmphdr = 0;
  u_char* ptr;
  int rest;
  int hlen = 0;

  ptr = data;
  rest = size;
  if(!ptr){
    *restptr = 0;
    return 0;
  }


  if(rest < sizeof(struct tcphdr)){
    DebugPrintf("rest(%d) < sizeof(struct tcphdr) !!!\n\n\n", rest);
    rethdr = 0;
  }else{
    tmphdr = (struct tcphdr*)ptr;
    rest -= sizeof(struct tcphdr);

    hlen = tmphdr->doff * 4;
    if(size < hlen){
      DebugPrintf("rest < tcphdr->doff %d %d !!!\n\n\n", rest, hlen);
      rethdr = 0;
    }else{
      rethdr = tmphdr;
      rest = size - hlen;
    }
  }

  *restptr = rest;
  *ppdata = data + hlen;
  return rethdr;
}


struct udphdr* Cast2UdpHeader(u_char* data, int size, u_char** ppdata, int* restptr)
{
  struct udphdr* rethdr = 0;
  u_char* ptr;
  int rest;

  ptr = data;
  rest = size;
  if(!ptr){
    *restptr = 0;
    return 0;
  }

  
  if(rest < sizeof(struct udphdr)){
    DebugPrintf("rest(%d) < sizeof(struct udphdr) !!!\n\n\n",rest);
    rethdr = 0;
  }else{
    rethdr = (struct udphdr*)ptr;
    rest -= sizeof(struct udphdr);
  }

  *restptr = rest;
  *ppdata = data + sizeof(struct udphdr);
  return rethdr;

}
