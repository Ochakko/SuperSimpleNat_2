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

#include "base.h"
#include "debugprint.h"
#include "initdevice.h"



#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6  0x86dd
#endif

int GetDeviceInfo(char* ifname, NETDEVICE* dstdev)
{
  struct ifreq ifreq;
  struct sockaddr_in addr;
  int soc;
  u_char *p;

  if((soc = socket(PF_INET, SOCK_DGRAM, 0)) < 0){
    DebugPerror("socket");
    return(-1);
  }
  
  memset(&ifreq, 0, sizeof(struct ifreq));
  strncpy(ifreq.ifr_name, ifname, sizeof(ifreq.ifr_name) - 1);
  
  if(ioctl(soc, SIOCGIFHWADDR, &ifreq) == -1){
    DebugPerror("ioctl");
    close(soc);
    return(-1);
  }
  else{
    p = (u_char *)&ifreq.ifr_hwaddr.sa_data;
    memcpy(dstdev->hwaddr, p, 6);
  }
  
  if(ioctl(soc, SIOCGIFADDR, &ifreq) == -1){
    DebugPerror("ioctl");
    close(soc);
    return(-1);
  }
  else if(ifreq.ifr_addr.sa_family != PF_INET){
    DebugPrintf("%s not PF_INET\n", ifname);
    close(soc);
    return(-1);
  }
  else{
    memcpy(&addr, &ifreq.ifr_addr, sizeof(struct sockaddr_in));
    dstdev->addr = addr.sin_addr;
  }
  
  
  if(ioctl(soc, SIOCGIFNETMASK, &ifreq) == -1){
    DebugPerror("ioctl");
    close(soc);
    return(-1);
  }
  else{
    memcpy(&addr, &ifreq.ifr_addr, sizeof(struct sockaddr_in));
    dstdev->netmask = addr.sin_addr;
  }
  
  dstdev->subnet.s_addr = ((dstdev->addr.s_addr) & (dstdev->netmask.s_addr));
  
  close(soc);
  
  return(0);
}

int InitRawSocket(char* ifname, int promiscFlag, int ipOnly)
{
  struct ifreq ifreq;
  struct sockaddr_ll sa;
  int soc;

  if(ipOnly){
    if((soc=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0){
      DebugPerror("socket");
      return(-1);
    }
  }
  else{
    if((soc=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0){
      DebugPerror("socket");
      return(-1);
    }
  }
  
  memset(&ifreq, 0, sizeof(struct ifreq));
  strncpy(ifreq.ifr_name, ifname, sizeof(ifreq.ifr_name) - 1);
  if(ioctl(soc, SIOCGIFINDEX, &ifreq) < 0){
    DebugPerror("ioctl");
    close(soc);
    return(-1);
  }
  sa.sll_family = PF_PACKET;
  if(ipOnly){
    sa.sll_protocol = htons(ETH_P_IP);
  }
  else{
    sa.sll_protocol = htons(ETH_P_ALL);
  }
  sa.sll_ifindex = ifreq.ifr_ifindex;
  if(bind(soc, (struct sockaddr *)&sa, sizeof(sa)) < 0){
    DebugPerror("bind");
    close(soc);
    return(-1);
  }
  
  if(promiscFlag){
    if(ioctl(soc, SIOCGIFFLAGS, &ifreq) < 0){
      DebugPerror("ioctl");
      close(soc);
      return(-1);
    }
    ifreq.ifr_flags = ifreq.ifr_flags | IFF_PROMISC;
    if(ioctl(soc, SIOCSIFFLAGS, &ifreq) < 0){
      DebugPerror("ioctl");
      close(soc);
      return(-1);
    }
  }
  
  return(soc);
}



