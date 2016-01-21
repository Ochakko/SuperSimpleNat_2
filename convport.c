#include	<stdio.h>
#include	<string.h>
#include	<unistd.h>
#include	<poll.h>
#include	<errno.h>
#include	<signal.h>
#include	<stdarg.h>
#include	<time.h>
#include   <sys/time.h>
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


#include	"base.h"
#include	"convport.h"


CONVPORT g_convport[CONVPORTNUM];


static CONVPORT* ConvPortTimeOut();



int InitConvPort()
{
  memset((void*)&(g_convport[0]), 0, sizeof(CONVPORT) * CONVPORTNUM);
	
  int cpno;
  for(cpno = 0; cpno < CONVPORTNUM; cpno++){
    CONVPORT* curcp = g_convport + cpno;
    curcp->convport = CONVPORTSTART + cpno;
  }
  
  return 0;
}


CONVPORT* GetConvPortC2S(u_short serviceport, u_short orgport, in_addr_t clientip)
{
  CONVPORT* retcp = 0;
  CONVPORT* freecp = 0;
  
  freecp = ConvPortTimeOut();
  if(!freecp){
    return NULL;
  }
  
  
  int cpno;
  
  //既存のものを探す
  for(cpno = 0; cpno < CONVPORTNUM; cpno++){
    CONVPORT* curcp = g_convport + cpno;
    if(curcp->validflag == 1){
      if(curcp->serviceport == serviceport){
	if((curcp->orgport == orgport) && (curcp->clientip == clientip)){
	  retcp = curcp;
	  retcp->updatetime = time(NULL);//!!!!!!!!!!!!!!
	  break;
	}
      }
    }
  }
  
  //新規エントリー
  if(!retcp){
    freecp->orgport = orgport;
    freecp->serviceport = serviceport;
    freecp->clientip = clientip;
    freecp->updatetime = time(NULL);//!!!!!!!!!!!!!!
    freecp->validflag = 1;
    retcp = freecp;
  }
  
  return retcp;
}


CONVPORT* GetConvPortS2C(u_short serviceport, u_short convport)
{
  CONVPORT* retcp = 0;
  
  ConvPortTimeOut();
  
  if((convport >= CONVPORTSTART) && (convport < (CONVPORTSTART + CONVPORTNUM))){
    CONVPORT* cmpcp = g_convport + (convport - CONVPORTSTART);
    if(cmpcp->validflag == 1){
      if(cmpcp->serviceport == serviceport){
	if(cmpcp->convport == convport){
	  retcp = cmpcp;
	  retcp->updatetime = time(NULL);//!!!!!!!!!!!!!!
	}
      }
    }
  }
  
  return retcp;
}

CONVPORT* ConvPortTimeOut()
{
  CONVPORT* freecp = 0;
  
  time_t curtime;
  curtime = time(NULL);
  
  int cpno;
  for(cpno = 0; cpno < CONVPORTNUM; cpno++){
    CONVPORT* curcp = g_convport + cpno;
    
    if((curtime - curcp->updatetime) > CONVPORTTIMEOUT){
      curcp->validflag = 0;
    }
    
    if(!freecp && (curcp->validflag == 0)){
      freecp = curcp;
    }
  }
  return freecp;
}



