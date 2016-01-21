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

#define DEBUGPRINT 1


int DebugPrintf(char* fmt, ...)
{
#ifdef DEBUGPRINT
  va_list	 args;
    
  va_start(args,fmt);
  vfprintf(stderr,fmt,args);
  va_end(args);
#endif
  return(0);
}

int DebugPerror(char* msg)
{
#ifdef DEBUGPRINT
  fprintf(stderr, "%s : %s\n", msg, strerror(errno));
#endif
  return(0);
}

char* mac2str(u_char* hwaddr, char* buf, int size)
{
  snprintf(buf,size, "%02x:%02x:%02x:%02x:%02x:%02x",
	   hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
  
  return(buf);
}

char* inaddr2str(struct in_addr* addr, char* buf, int size)
{
  inet_ntop(PF_INET, addr, buf, size);

  return(buf);
}

char* inaddrt2str(in_addr_t addr, char* buf, int size)
{
  struct in_addr  a;

  a.s_addr = addr;
  inet_ntop(PF_INET, &a,buf, size);
  
  return(buf);
}

char* ipi82str(u_int8_t* ip, char* buf, int size)
{
  snprintf(buf,size, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);

  return(buf);
}

char* ip322str(u_int32_t ip, char* buf, int size)
{
  struct in_addr  *addr;

  addr=(struct in_addr*)&ip;
  inet_ntop(AF_INET, addr, buf, size);
  
  return(buf);
}



int DbgPrintEthHeader(struct ether_header* eh)
{
#ifdef DEBUGPRINT
  char	buf[80];
  
  DebugPrintf("ether_header----------------------------\n");
  DebugPrintf("ether_dhost=%s\n", mac2str(eh->ether_dhost, buf, sizeof(buf)));
  DebugPrintf("ether_shost=%s\n", mac2str(eh->ether_shost, buf, sizeof(buf)));
  DebugPrintf("ether_type=%02X", ntohs(eh->ether_type));
  switch(ntohs(eh->ether_type)){
  case	ETH_P_IP:
    DebugPrintf("(IP)\n");
    break;
  case	ETH_P_IPV6:
    DebugPrintf("(IPv6)\n");
    break;
  case	ETH_P_ARP:
    DebugPrintf("(ARP)\n");
    break;
  default:
    DebugPrintf("(unknown)\n");
    break;
  }
#endif  
  return(0);
}

int DbgPrintArp(struct ether_arp* arp)
{
#ifdef DEBUGPRINT
  static char* hrd[]={
    "From KA9Q: NET/ROM pseudo.",
    "Ethernet 10/100Mbps.",
    "Experimental Ethernet.",
    "AX.25 Level 2.",
    "PROnet token ring.",
    "Chaosnet.",
    "IEEE 802.2 Ethernet/TR/TB.",
    "ARCnet.",
    "APPLEtalk.",
    "undefine",
    "undefine",
    "undefine",
    "undefine",
    "undefine",
    "undefine",
    "Frame Relay DLCI.",
    "undefine",
    "undefine",
    "undefine",
    "ATM.",
    "undefine",
    "undefine",
    "undefine",
    "Metricom STRIP (new IANA id)."
  };
  static char* op[]={
    "undefined",
    "ARP request.",
    "ARP reply.",
    "RARP request.",
    "RARP reply.",
    "undefined",
    "undefined",
    "undefined",
    "InARP request.",
    "InARP reply.",
    "(ATM)ARP NAK."
  };
  char	buf[80];

  DebugPrintf("arp-------------------------------------\n");
  DebugPrintf("arp_hrd=%u", ntohs(arp->arp_hrd));
  if(ntohs(arp->arp_hrd) <= 23){
    DebugPrintf("(%s),", hrd[ntohs(arp->arp_hrd)]);
  }
  else{
    DebugPrintf("(undefined),");
  }
  DebugPrintf("arp_pro=%u", ntohs(arp->arp_pro));
  switch(ntohs(arp->arp_pro)){
  case	ETHERTYPE_IP:
    DebugPrintf("(IP)\n");
    break;
  case	ETHERTYPE_ARP:
    DebugPrintf("(Address resolution)\n");
    break;
  case	ETHERTYPE_REVARP:
    DebugPrintf("(Reverse ARP)\n");
    break;
  case	ETHERTYPE_IPV6:
    DebugPrintf("(IPv6)\n");
    break;
  default:
    DebugPrintf("(unknown)\n");
    break;
  }
  DebugPrintf("arp_hln=%u,", arp->arp_hln);
  DebugPrintf("arp_pln=%u,", arp->arp_pln);
  DebugPrintf("arp_op=%u", ntohs(arp->arp_op));
  if(ntohs(arp->arp_op) <= 10){
    DebugPrintf("arpop : (%s)\n", op[ntohs(arp->arp_op)]);
  }
  else{
    DebugPrintf("(undefine)\n");
  }
  DebugPrintf("arp_sha=%s\n", mac2str(arp->arp_sha, buf, sizeof(buf)));
  DebugPrintf("arp_spa=%s\n", ipi82str(arp->arp_spa, buf, sizeof(buf)));
  DebugPrintf("arp_tha=%s\n", mac2str(arp->arp_tha, buf, sizeof(buf)));
  DebugPrintf("arp_tpa=%s\n", ipi82str(arp->arp_spa, buf, sizeof(buf)));
#endif
  
  return(0);
}


static char*  Proto[]={
  "undefined",
  "ICMP",
  "IGMP",
  "undefined",
  "IPIP",
  "undefined",
  "TCP",
  "undefined",
  "EGP",
  "undefined",
  "undefined",
  "undefined",
  "PUP",
  "undefined",
  "undefined",
  "undefined",
  "undefined",
  "UDP"
};

int DbgPrintIp4Header(struct iphdr* iphdr)
{
#ifdef DEBUGPRINT
  int	i;
  char	buf[80];
  u_char* option;
  int optionLen;
  
  optionLen = iphdr->ihl * 4 - sizeof(struct iphdr);
  if(optionLen > 0){
    if(optionLen >= 1500){
      fprintf(stderr,"IP optionLen(%d):too big !!!\n\n\n",optionLen);
      return(-1);
    }
    option = (u_char*)iphdr + sizeof(struct iphdr);
  }else{
    option = 0;
    optionLen = 0;
  }

  DebugPrintf("ip--------------------------------------\n");
  DebugPrintf("version=%u,", iphdr->version);
  DebugPrintf("ihl=%u,", iphdr->ihl);
  DebugPrintf("tos=%x,", iphdr->tos);
  DebugPrintf("tot_len=%u,", ntohs(iphdr->tot_len));
  DebugPrintf("id=%u\n", ntohs(iphdr->id));
  DebugPrintf("frag_off=%x,%u,", (ntohs(iphdr->frag_off) >> 13) & 0x07, 
    ntohs(iphdr->frag_off) & 0x1FFF);
  DebugPrintf("ttl=%u,", iphdr->ttl);
  DebugPrintf("protocol=%u", iphdr->protocol);
  if(iphdr->protocol <= 17){
    DebugPrintf("(%s),", Proto[iphdr->protocol]);
  }
  else{
    DebugPrintf("(undefined),");
  }
  DebugPrintf("check=%x\n", iphdr->check);
  DebugPrintf("saddr=%s,", ip322str(iphdr->saddr, buf, sizeof(buf)));
  DebugPrintf("daddr=%s\n", ip322str(iphdr->daddr, buf, sizeof(buf)));
  if(optionLen > 0){
    DebugPrintf("option:");
    for(i = 0; i < optionLen; i++){
      if(i != 0){
	DebugPrintf(":%02x", option[i]);
      }
      else{
	DebugPrintf("%02x", option[i]);
      }
    }
  }
#endif
  
  return(0);
}

int DbgPrintIp6Header(struct ip6_hdr* ip6)
{
#ifdef DEBUGPRINT
  char	buf[80];
  
  DebugPrintf("ip6-------------------------------------\n");
  
  DebugPrintf("ip6_flow=%x,", ip6->ip6_flow);
  DebugPrintf("ip6_plen=%d,", ntohs(ip6->ip6_plen));
  DebugPrintf("ip6_nxt=%u", ip6->ip6_nxt);
  if(ip6->ip6_nxt <= 17){
    DebugPrintf("(%s),", Proto[ip6->ip6_nxt]);
  }
  else{
    DebugPrintf("(undefined),");
  }
  DebugPrintf("ip6_hlim=%d,", ip6->ip6_hlim);
  
  DebugPrintf("ip6_src=%s\n", inet_ntop(AF_INET6, &ip6->ip6_src, buf, sizeof(buf)));
  DebugPrintf("ip6_dst=%s\n", inet_ntop(AF_INET6, &ip6->ip6_dst, buf, sizeof(buf)));
#endif  

  return(0);
}

int DbgPrintIcmp(struct icmp* icmp, int icmplen)
{
#ifdef DEBUGPRINT
  static char	*icmp_type[]={
    "Echo Reply",
    "undefined",
    "undefined",
    "Destination Unreachable",
    "Source Quench",
    "Redirect",
    "undefined",
    "undefined",
    "Echo Request",
    "Router Adverisement",
    "Router Selection",
    "Time Exceeded for Datagram",
    "Parameter Problem on Datagram",
    "Timestamp Request",
    "Timestamp Reply",
    "Information Request",
    "Information Reply",
    "Address Mask Request",
    "Address Mask Reply"
  };
  
  DebugPrintf("icmp------------------------------------\n");
  
  DebugPrintf("icmp_type=%u", icmp->icmp_type);
  if(icmp->icmp_type <= 18){
    DebugPrintf("(%s),", icmp_type[icmp->icmp_type]);
  }
  else{
    DebugPrintf("(undefined),");
  }
  DebugPrintf("icmp_code=%u,", icmp->icmp_code);
  DebugPrintf("icmp_cksum=%u\n", ntohs(icmp->icmp_cksum));
  
  if((icmp->icmp_type == 0) || (icmp->icmp_type == 8)){
    DebugPrintf("icmp_id=%u,", ntohs(icmp->icmp_id));
    DebugPrintf("icmp_seq=%u\n", ntohs(icmp->icmp_seq));
  }
  
  
  if(icmplen >= (8 + sizeof(struct iphdr))){
    DebugPrintf("icmp data : iphdr : \n");
    struct iphdr* iphdr = (struct iphdr*)((u_char*)icmp + 8);
    DbgPrintIp4Header(iphdr);
    
    
    if(iphdr->protocol == IPPROTO_TCP){
      int tcplen;
      tcplen = icmplen - 8 - iphdr->ihl * 4;
      if(tcplen >= sizeof(struct tcphdr)){
	struct tcphdr* tcphdr;
	tcphdr = (struct tcphdr*)((u_char*)iphdr + iphdr->ihl * 4);
	
	DebugPrintf( "icmp data : tcphdr : \n");
	DbgPrintTcpHeader(tcphdr);
      }
    }else if(iphdr->protocol == IPPROTO_UDP){
      int udplen;
      udplen = icmplen - 8 - iphdr->ihl * 4;
      if(udplen >= sizeof(struct udphdr)){
	struct udphdr* udphdr;
	udphdr = (struct udphdr*)((u_char*)iphdr + iphdr->ihl * 4);
	
	DebugPrintf( "icmp data : udphdr : \n");
	DbgPrintUdpHeader(udphdr);
      }
    }
  }
#endif
  
  return(0);
}

int DbgDbgPrintIcmp6(struct icmp6_hdr* icmp6)
{
#ifdef DEBUGPRINT  
  DebugPrintf("icmp6-----------------------------------\n");
  
  DebugPrintf("icmp6_type=%u", icmp6->icmp6_type);
  if(icmp6->icmp6_type == 1){
    DebugPrintf("(Destination Unreachable),");
  }
  else if(icmp6->icmp6_type == 2){
    DebugPrintf("(Packet too Big),");
  }
  else if(icmp6->icmp6_type == 3){
    DebugPrintf("(Time Exceeded),");
  }
  else if(icmp6->icmp6_type == 4){
    DebugPrintf("(Parameter Problem),");
  }
  else if(icmp6->icmp6_type == 128){
    DebugPrintf("(Echo Request),");
  }
  else if(icmp6->icmp6_type == 129){
    DebugPrintf("(Echo Reply),");
  }
  else{
    DebugPrintf("(undefined),");
  }
  DebugPrintf("icmp6_code=%u,", icmp6->icmp6_code);
  DebugPrintf("icmp6_cksum=%u\n", ntohs(icmp6->icmp6_cksum));
  
  if((icmp6->icmp6_type == 128) || (icmp6->icmp6_type == 129)){
    DebugPrintf("icmp6_id=%u,", ntohs(icmp6->icmp6_id));
    DebugPrintf("icmp6_seq=%u\n", ntohs(icmp6->icmp6_seq));
  }
#endif

  return(0);
}

int DbgPrintTcpHeader(struct tcphdr* tcphdr)
{
#ifdef DEBUGPRINT
  DebugPrintf("tcp-------------------------------------\n");
  
  DebugPrintf("source=%u,", ntohs(tcphdr->source));
  DebugPrintf("dest=%u\n", ntohs(tcphdr->dest));
  DebugPrintf("seq=%u\n", ntohl(tcphdr->seq));
  DebugPrintf("ack_seq=%u\n", ntohl(tcphdr->ack_seq));
  DebugPrintf("doff=%u,", tcphdr->doff);
  DebugPrintf("urg=%u,", tcphdr->urg);
  DebugPrintf("ack=%u,", tcphdr->ack);
  DebugPrintf("psh=%u,", tcphdr->psh);
  DebugPrintf("rst=%u,", tcphdr->rst);
  DebugPrintf("syn=%u,", tcphdr->syn);
  DebugPrintf("fin=%u,", tcphdr->fin);
  DebugPrintf("th_win=%u\n", ntohs(tcphdr->window));
  DebugPrintf("th_sum=%u,", ntohs(tcphdr->check));
  DebugPrintf("th_urp=%u\n", ntohs(tcphdr->urg_ptr));
#endif
  
  return(0);
}

int DbgPrintUdpHeader(struct udphdr* udphdr)
{
#ifdef DEBUGPRINT
  DebugPrintf("udp-------------------------------------\n");
  
  DebugPrintf("source=%u,", ntohs(udphdr->source));
  DebugPrintf("dest=%u\n", ntohs(udphdr->dest));
  DebugPrintf("len=%u,", ntohs(udphdr->len));
  DebugPrintf("check=%x\n", ntohs(udphdr->check));
#endif
  
  return(0);
}
