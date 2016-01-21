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
#include	<pthread.h>


#include "base.h"
#include "castnet.h"
#include "debugprint.h"
#include "convport.h"
#include "convmac.h"
#include "convip.h"
#include "initdevice.h"

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6  0x86dd
#endif


PARAM Param={"eth0", "eth1", "192.168.12.1"};//{NAT内側IF, NAT外側IF, 上位ルータIP}
NETDEVICE Device[2];
int EndFlag = 0;
struct in_addr NextRouter;



int AnalyzePacket(int deviceNo,u_char *data,int size, short kind)
{
  u_char* ptr;
  u_char* tmpptr;
  int rest, tmprest;
  struct ether_header	*eh;
  struct ether_arp	*arp;
  char	buf[65536];
  short ethtype;

  
  ptr = data;
  rest = size;
  
  tmpptr = 0;
  tmprest = 0;
  eh = Cast2EthHeader(ptr, rest, &tmpptr, &tmprest);
  if(!eh || !tmpptr){
    if(kind == POLLERR){
      DebugPrintf("POLLERR: ");
    }
    DebugPrintf("AnalyzePacket : Cast2Eth error !!!\n\n");
    return -1;
  }
  ptr = tmpptr;
  rest = tmprest;

  
  ethtype = ntohs(eh->ether_type);
  DebugPrintf("Ether Type %02x\n", ethtype);
  
  DebugPrintf("[%d]: Ether : source !!!%s\n",deviceNo,
	      mac2str((u_char *)&eh->ether_shost, buf, sizeof(buf)));
  DebugPrintf("[%d]: Ether : dest !!!%s\n",deviceNo,
	      mac2str((u_char *)&eh->ether_dhost, buf, sizeof(buf)));
  
  //MACが自分宛てか調べる
  if(memcmp(&eh->ether_dhost, Device[deviceNo].hwaddr, 6) != 0){
    if(kind == POLLERR){
      DebugPrintf("POLLERR : \n");
    }
    DebugPrintf("[%d]:Ether Dest Not Match !!!\n", deviceNo);
    if(ntohs(eh->ether_type) == ETHERTYPE_IP){
      AnalyzeIp(deviceNo, data, size, POLLERR);
    }
    DebugPrintf("\n\n");
    return(-1);
  }


  if((ntohs(eh->ether_type) == ETHERTYPE_ARP) || (ntohs(eh->ether_type) == ETHERTYPE_REVARP)){
    tmpptr = 0;
    tmprest = 0;
    arp  = Cast2EthArp(ptr, rest, &tmpptr, &tmprest);
    if(!arp || !tmpptr){
      if(kind == POLLERR){
	DebugPrintf("POLLERR: ");
      }
      DebugPrintf("AnalyzePacket : Cast2EthArp error !!!\n\n");
      return -1;
    }
    ptr = tmpptr;
    rest = tmprest;
    
    if(arp->arp_op == htons(ARPOP_REQUEST)){
      if(kind == POLLIN){
	DebugPrintf("[%d]recv:ARP REQUEST:%dbytes\n", deviceNo, size);
      }else{
	DebugPrintf("POLLERR : [%d]recv:ARP REQUEST:%dbytes !!!\n\n\n", deviceNo, size);				
      }
      DbgPrintArp(arp);
    }
    if(arp->arp_op == htons(ARPOP_REPLY)){
      if(kind == POLLIN){
	DebugPrintf("[%d]recv:ARP REPLY:%dbytes\n", deviceNo, size);
      }else{
	DebugPrintf("POLLERR : [%d]recv:ARP REPLY:%dbytes !!!\n\n\n", deviceNo, size);				
      }
      DbgPrintArp(arp);
    }
  }else if(ntohs(eh->ether_type) == ETHERTYPE_IP){

    AnalyzeIp(deviceNo, data, size, kind);

  }
  
  
  return(0);
}

int Router()
{
  struct pollfd	targets[2];
  int	nready,i,size;
  u_char	buf[2][65536];
   
  targets[0].fd = Device[0].soc;
  targets[0].events = POLLIN | POLLERR;
  targets[1].fd = Device[1].soc;
  targets[1].events = POLLIN | POLLERR;
  
  while(EndFlag == 0){
    switch(nready = poll(targets, 2, 100)){
    case -1:
      if(errno != EINTR){//割り込みかどうか
	DebugPerror("poll");
      }
      break;
    case 0:
      break;
    default:
      for(i=0;i<2;i++){
	if(targets[i].revents & (POLLIN | POLLERR)){
	//if(targets[i].revents & (POLLIN)){
	  if((size = read(Device[i].soc, &(buf[i][0]), 65536)) <= 0){
	    DebugPerror("read");
	  }
	  else{
	    AnalyzePacket(i, &(buf[i][0]), size, POLLIN);
	  }
	}
      }
      break;
    }
  }
  
  return(0);
}

int DisableIpForward()
{
  FILE    *fp;
  
  if((fp = fopen("/proc/sys/net/ipv4/ip_forward", "w")) == NULL){
    DebugPrintf("cannot write /proc/sys/net/ipv4/ip_forward\n");
    return(-1);
  }
  fputs("0", fp);
  fclose(fp);
  
  return(0);
}

void EndSignal(int sig)
{
  EndFlag=1;
}

int main(int argc, char *argv[], char *envp[])
{
  char	buf[65536];

    
  inet_aton(Param.NextRouter,&NextRouter);
  DebugPrintf("NextRouter=%s\n",inaddr2str(&NextRouter,buf,sizeof(buf)));

  if(GetDeviceInfo(Param.IfName0, &Device[0]) == -1){
    DebugPrintf("GetDeviceInfo:error:%s\n", Param.IfName0);
    return(-1);
  }
  if((Device[0].soc = InitRawSocket(Param.IfName0, 0, 0)) == -1){
    DebugPrintf("InitRawSocket:error:%s\n", Param.IfName0);
    return(-1);
  }
  DebugPrintf("%s OK\n",Param.IfName0);
  DebugPrintf("addr=%s\n",inaddr2str(&Device[0].addr, buf, sizeof(buf)));
  DebugPrintf("subnet=%s\n",inaddr2str(&Device[0].subnet, buf, sizeof(buf)));
  DebugPrintf("netmask=%s\n",inaddr2str(&Device[0].netmask, buf, sizeof(buf)));
  DebugPrintf("hwaddr=%s\n",mac2str((u_char*)(&Device[0].hwaddr[0]), buf, sizeof(buf)));

  if(GetDeviceInfo(Param.IfName1,&Device[1]) == -1){
    DebugPrintf("GetDeviceInfo:error:%s\n", Param.IfName1);
    return(-1);
  }
  if((Device[1].soc = InitRawSocket(Param.IfName1, 0, 0)) == -1){
    DebugPrintf("InitRawSocket:error:%s\n", Param.IfName1);
    return(-1);
  }
  DebugPrintf("%s OK\n",Param.IfName1);
  DebugPrintf("addr=%s\n",inaddr2str(&Device[1].addr, buf, sizeof(buf)));
  DebugPrintf("subnet=%s\n",inaddr2str(&Device[1].subnet, buf, sizeof(buf)));
  DebugPrintf("netmask=%s\n",inaddr2str(&Device[1].netmask, buf, sizeof(buf)));
  DebugPrintf("hwaddr=%s\n",mac2str((u_char*)(&Device[1].hwaddr[0]), buf, sizeof(buf)));
  
  InitConvPort();
  InitConvMac(&Device[0]);


  DisableIpForward();
 
  signal(SIGINT,EndSignal);
  signal(SIGTERM,EndSignal);
  signal(SIGQUIT,EndSignal);
  
  signal(SIGPIPE,SIG_IGN);
  signal(SIGTTIN,SIG_IGN);
  signal(SIGTTOU,SIG_IGN);
  
  DebugPrintf("NAT start\n");
  Router();
  DebugPrintf("NAT end\n");

  close(Device[0].soc);
  close(Device[1].soc);

  return(0);
}

