#include	<stdio.h>
#include	<string.h>
#include	<unistd.h>
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



#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netdb.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <sysexits.h>



#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6  0x86dd
#endif

#include "base.h"
#include "debugprint.h"
#include "checksum.h"
#include "timeexceeded.h"


extern NETDEVICE Device[2];


int SendIcmpTimeExceeded(int deviceNo, struct ether_header* eh, struct iphdr* iphdr, u_char* data, int size)
{
  struct ether_header	reh;
  struct iphdr	rih;
  struct icmp	icmp;
  u_char* ipptr;
  u_char* ptr;
  u_char buf[65536];
  int	len;
  
  memcpy(reh.ether_dhost, eh->ether_shost, 6);
  memcpy(reh.ether_shost, Device[deviceNo].hwaddr, 6);
  reh.ether_type = htons(ETHERTYPE_IP);
  
  rih.version = 4;
  rih.ihl = 20 / 4;
  rih.tos = 0;
  rih.tot_len = htons(sizeof(struct icmp) + 64);
  rih.id = 0;
  rih.frag_off = 0;
  rih.ttl = 64;
  rih.protocol = IPPROTO_ICMP;
  rih.check = 0;
  rih.saddr = Device[deviceNo].addr.s_addr;
  rih.daddr = iphdr->saddr;
  
  rih.check = CheckSum((u_char *)&rih, sizeof(struct iphdr));
  
  icmp.icmp_type = ICMP_TIME_EXCEEDED;
  icmp.icmp_code = ICMP_TIMXCEED_INTRANS;
  icmp.icmp_cksum = 0;
  icmp.icmp_void = 0;
  
  ipptr = data + sizeof(struct ether_header);
  
  icmp.icmp_cksum = CheckSum2((u_char *)&icmp, 8, ipptr, 64);
  
  ptr = buf;
  memcpy(ptr, &reh, sizeof(struct ether_header));
  ptr += sizeof(struct ether_header);
  memcpy(ptr, &rih, sizeof(struct iphdr));
  ptr += sizeof(struct iphdr);
  memcpy(ptr, &icmp, 8);
  ptr += 8;
  memcpy(ptr, ipptr, 64);//データとして
  ptr += 64;
  len = ptr - buf;
  
  DebugPrintf("write:SendIcmpTimeExceeded:[%d] %dbytes\n", deviceNo, len);
  write(Device[deviceNo].soc, buf, len);
  
  return(0);
}
