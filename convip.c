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

#include "base.h"
#include "debugprint.h"
#include "castnet.h"
#include "checksum.h"
#include "convport.h"
#include "convmac.h"
#include "debugprint.h"
#include "timeexceeded.h"
#include "convip.h"

extern PARAM Param;
extern NETDEVICE Device[2];
extern struct in_addr NextRouter;


//static int TranslateIcmp(int deviceNo, struct ether_header *eh, struct iphdr *iphdr, struct icmp *icmp, int icmplen, u_char *data, int size);
static int TranslateTcp(int deviceNo, struct ether_header *eh, struct iphdr *iphdr, struct tcphdr *tcphdr, u_char *data, int size);
static int TranslateUdp(int deviceNo, struct ether_header *eh, struct iphdr *iphdr, struct udphdr *udphdr, u_char *data, int size);

static int ChangeIpAndTcpPort(int deviceNo, struct iphdr *iphdr, struct tcphdr *tcphdr);
static int ChangeIpAndUdpPort(int deviceNo, struct iphdr *iphdr, struct udphdr *udphdr);
static int SetCheckSumTcp(struct iphdr *iphdr, struct tcphdr *tcphdr);
static int SetCheckSumUdp(struct iphdr *iphdr, struct udphdr *udphdr);



int AnalyzeIp(int deviceNo, u_char *data, int size, short kind)
{
  u_char* ptr;
  u_char* tmpptr;
  int	rest, tmprest;
  struct ether_header* eh;
  struct iphdr* iphdr;
  struct icmp* icmp;
  struct tcphdr* tcphdr;
  struct udphdr* udphdr;
  int len;
  unsigned short sum;


  ptr=data;
  rest=size;

  tmpptr = 0;
  tmprest = 0;
  eh = Cast2EthHeader(ptr, rest, &tmpptr, &tmprest);
  if(!eh || !tmpptr){
    if(kind == POLLERR){
      DebugPrintf("POLLERR: ");
    }
    DebugPrintf("convip : Cast2Eth error !!!\n\n");
    return -1;
  }
  ptr = tmpptr;
  rest = tmprest;

  tmpptr = 0;
  tmprest = 0;
  iphdr = Cast2Ip4Header(ptr, rest, &tmpptr, &tmprest);
  if(!iphdr || !tmpptr){
    if(kind == POLLERR){
      DebugPrintf("POLLERR: ");
    }
    DebugPrintf("convip : Cast2Ip4 error !!!\n\n");
    return -1;
  }
  ptr = tmpptr;
  rest = tmprest;


  sum = IpHeaderCheckSum(iphdr);
  if((sum != 0) && (sum != 0xFFFF)){
    if(kind == POLLERR){
      DebugPrintf("POLLERR : ");
    }
    DebugPrintf("bad ip checksum : sum %04X\n", sum);
    fprintf(stderr,"ip header : \n");
    DbgPrintIp4Header(iphdr);
    DebugPrintf("\n\n");
    return(-1);
  }
  if(kind == POLLERR){
    DbgPrintIp4Header(iphdr);
  }
  
  len = ntohs(iphdr->tot_len) - iphdr->ihl * 4;
  
  if(iphdr->protocol == IPPROTO_ICMP){
    tmpptr = 0;
    tmprest = 0;
    icmp = Cast2Icmp4(ptr, rest, &tmpptr, &tmprest);
    if(!icmp || !tmpptr){
      if(kind == POLLERR){
	DebugPrintf("POLLERR: ");
      }
      DebugPrintf("convip : Cast2Icmp4 error !!!\n\n");
      return -1;
    }
    ptr = tmpptr;
    rest = tmprest;

    sum = CheckSum(ptr, len);
    if((sum != 0)&&(sum != 0xFFFF)){
      if(kind == POLLERR){
        DebugPrintf("POLLERR : bad icmp checksum !!!\n\n\n");
      }else{
	DebugPrintf("bad icmp checksum !!!\n\n\n");
      }
      return(-1);
    }
        
    if(kind == POLLERR){
      DebugPrintf("POLLERR : ");
      DbgPrintIcmp(icmp, len);
      DebugPrintf("\n\n");
    }else{
      DebugPrintf("[%d]recv ICMP\n", deviceNo);
      DbgPrintIp4Header(iphdr);
      DbgPrintIcmp(icmp, len);
      //TranslateIcmp(deviceNo, eh, iphdr, icmp, len, data, size);
    }
  }
  else if(iphdr->protocol == IPPROTO_TCP){
    tmpptr = 0;
    tmprest = 0;
    tcphdr = Cast2TcpHeader(ptr, rest, &tmpptr, &tmprest);
    if(!tcphdr || !tmpptr){
      if(kind == POLLERR){
	DebugPrintf("POLLERR: ");
      }
      DebugPrintf("convip : Cast2Tcp error !!!\n\n");
      return -1;
    }
    // ptr = tmpptr;
    //rest = tmprest;

    sum = IpDataCheckSum(iphdr, ptr, len);
    if((sum != 0) && (sum != 0xFFFF)){
      if(kind == POLLERR){
	DebugPrintf("POLLERR : bad tcp checksum !!!\n\n\n");
      }else{
	DebugPrintf("bad tcp checksum !!!\n\n\n");
      }
      return(-1);
    }

    if(kind == POLLERR){
      DebugPrintf("POLLERR : ");
      DbgPrintTcpHeader(tcphdr);
      DebugPrintf("\n\n");
    }else{
      TranslateTcp(deviceNo, eh, iphdr, tcphdr, data, size);
    }
  }
  else if(iphdr->protocol == IPPROTO_UDP){
    tmpptr = 0;
    tmprest = 0;
    udphdr = Cast2UdpHeader(ptr, rest, &tmpptr, &tmprest);
    if(!udphdr || !tmpptr){
      if(kind == POLLERR){
	DebugPrintf("POLLERR: ");
      }
      DebugPrintf("convip : Cast2Udp error !!!\n\n");
      return -1;
    }
    //ptr = tmpptr;
    //rest = tmprest;

    sum = IpDataCheckSum(iphdr, ptr, len);
    if((sum != 0) && (sum != 0xFFFF)){
      if(kind == POLLERR){
	DebugPrintf("POLLERR : bad udp checksum !!!\n\n\n");
      }else{
	DebugPrintf("bad udp checksum !!!\n\n\n");
      }
      return(-1);
    }

    if(kind == POLLERR){
      DebugPrintf("POLLERR : ");
      DbgPrintUdpHeader(udphdr);
      DebugPrintf("\n\n");
    }else{
      TranslateUdp(deviceNo, eh, iphdr, udphdr, data, size);
    }
  }

  return(0);
}

int ChangeIpAndTcpPort(int deviceNo, struct iphdr *iphdr, struct tcphdr *tcphdr)
{
  u_short orgsrc, orgdest, trasrc, tradest;
  int mineflag = 0;
  int myipflag;
  char buf[80];
  char buf2[80];

  orgsrc = ntohs(tcphdr->source);
  orgdest = ntohs(tcphdr->dest);
  
  if(iphdr->daddr == Device[deviceNo].addr.s_addr){
    myipflag = 1;
  }else{
    myipflag = 0;
  }
  
  DebugPrintf("[%d->]:TCP CHANGE!!!: before : src(%s, %hu), dst(%s, %hu)\n",
	      deviceNo, 
	      inaddrt2str(iphdr->saddr,buf,sizeof(buf)), ntohs(tcphdr->source), 
	      inaddrt2str(iphdr->daddr,buf2,sizeof(buf2)), ntohs(tcphdr->dest)
	      );
  
  if(deviceNo == 0){
    CONVPORT* cpc2s = GetConvPortC2S(orgdest, orgsrc, iphdr->saddr);
    if(!cpc2s){
      return -1;
    }		
    
    tradest = orgdest;
    if(myipflag == 0){
      trasrc = cpc2s->convport;
      iphdr->saddr = *((u_int32_t *)&(Device[1].addr));//!!!!!!!!!!!!!!!!!
    }			
    mineflag = myipflag;
  }else{
    CONVPORT* cps2c = GetConvPortS2C(orgsrc, orgdest);
    
    trasrc = orgsrc;
    if(cps2c){
      tradest = cps2c->orgport;
      iphdr->daddr = *((u_int32_t *)&(cps2c->clientip));//!!!!!!!!!!!!!
      mineflag = 0;		
    }else{
      return -1;
    }
  }
  tcphdr->source = htons(trasrc);
  tcphdr->dest = htons(tradest);
  
  DebugPrintf("[%d->]:TCP CHANGE!!!: after  : src(%s, %hu), dst(%s, %hu)\n",
	      deviceNo, 
	      inaddrt2str(iphdr->saddr,buf,sizeof(buf)), ntohs(tcphdr->source), 
	      inaddrt2str(iphdr->daddr,buf2,sizeof(buf2)), ntohs(tcphdr->dest)
	      );
  
  return mineflag;
}

int ChangeIpAndUdpPort(int deviceNo, struct iphdr *iphdr, struct udphdr *udphdr)
{
  u_short orgsrc, orgdest, trasrc, tradest;
  int mineflag = 0;
  int myipflag;
  char buf[80];
  char buf2[80];
  
   orgsrc = ntohs(udphdr->source);
  orgdest = ntohs(udphdr->dest);
  
  if(iphdr->daddr==Device[deviceNo].addr.s_addr){
    myipflag = 1;
  }else{
    myipflag = 0;
  }
  
  DebugPrintf("[%d->]:UDP CHANGE!!!: before : src(%s, %hu), dst(%s, %hu)\n",
	      deviceNo, 
	      inaddrt2str(iphdr->saddr,buf,sizeof(buf)), ntohs(udphdr->source), 
	      inaddrt2str(iphdr->daddr,buf2,sizeof(buf2)), ntohs(udphdr->dest)
	      );
  
  if(deviceNo == 0){
    CONVPORT* cpc2s = GetConvPortC2S(orgdest, orgsrc, iphdr->saddr);
    if(!cpc2s){
      return -1;
    }			
    
    tradest = orgdest;
    if(myipflag == 0){
      trasrc = cpc2s->convport;
      iphdr->saddr = *((u_int32_t *)&(Device[1].addr));//!!!!!!!!!!!!!!!!!
    }			
    mineflag = myipflag;
  }else{
    CONVPORT* cps2c = GetConvPortS2C(orgsrc, orgdest);
    
    trasrc = orgsrc;
    if(cps2c){
      tradest = cps2c->orgport;
      iphdr->daddr = *((u_int32_t *)&(cps2c->clientip));//!!!!!!!!!!!!!
      mineflag = 0;		
    }else{
      return -1;
    }
  }
  udphdr->source = htons(trasrc);
  udphdr->dest = htons(tradest);
  
  DebugPrintf("[%d->]:UDP CHANGE!!!: after   : src(%s, %hu), dst(%s, %hu)\n",
	      deviceNo, 
	      inaddrt2str(iphdr->saddr,buf,sizeof(buf)), ntohs(udphdr->source), 
	      inaddrt2str(iphdr->daddr,buf2,sizeof(buf2)), ntohs(udphdr->dest)
	      );
  
  return mineflag;
}

int SetCheckSumTcp(struct iphdr *iphdr, struct tcphdr *tcphdr)
{
  u_char* option;
  int optionLen;
  int len;
  
  option = (u_char*)iphdr + sizeof(struct iphdr);
  optionLen = iphdr->ihl * 4 - sizeof(struct iphdr);
  
  iphdr->check = 0;
  iphdr->check = CheckSum2((u_char *)iphdr, sizeof(struct iphdr), option, optionLen);
  
  tcphdr->check = 0;
  len = ntohs(iphdr->tot_len) - iphdr->ihl * 4;
  tcphdr->check = IpDataCheckSum(iphdr, (u_char*)tcphdr, len);
  
  return 0;
}

int SetCheckSumUdp(struct iphdr *iphdr, struct udphdr *udphdr)
{
  u_char* option;
  int optionLen;
  int len;
  
  option = (u_char*)iphdr + sizeof(struct iphdr);
  optionLen = iphdr->ihl * 4 - sizeof(struct iphdr);
  
  iphdr->check = 0;
  iphdr->check = CheckSum2((u_char *)iphdr, sizeof(struct iphdr), option, optionLen);
  
  udphdr->check = 0;
  len = ntohs(iphdr->tot_len) - iphdr->ihl * 4;
  udphdr->check = IpDataCheckSum(iphdr, (u_char*)udphdr, len);
  
  return 0;
}

/*
int TranslateIcmp(int deviceNo, struct ether_header *eh, struct iphdr *iphdr, struct icmp *icmp, int icmplen, u_char *data, int size)
{


	return 0;
}
*/

int TranslateTcp(int deviceNo, struct ether_header *eh, struct iphdr *iphdr, struct tcphdr *tcphdr, u_char *data, int size)
{
  
  char	buf[80];
  char	buf2[80];
  int mineflag = 0;
  int senddevno = 0;
  
  if(iphdr->ttl - 1 == 0){
    DebugPrintf("[%d]:iphdr->ttl==0 error\n", deviceNo);
    SendIcmpTimeExceeded(deviceNo, eh, iphdr, data, size);
    return(-1);
  }  
  
  mineflag = ChangeIpAndTcpPort(deviceNo, iphdr, tcphdr);
  
  if(mineflag == 1){
    DebugPrintf("[%d]:recv:myaddr: TCP :mine!!!\n", deviceNo);
    return 0;
  }else if(mineflag < 0){
    DebugPrintf("[%d]:No Need Translate: TCP !!!\n", deviceNo);
    return 0;
  }
  
  if((iphdr->daddr & Device[0].netmask.s_addr) == Device[0].subnet.s_addr){
    senddevno = 0;
  }else if((iphdr->daddr & Device[1].netmask.s_addr) == Device[1].subnet.s_addr){
    senddevno = 1;
  }else{
    senddevno = 1;
  }
  
  DebugPrintf("[%d]:%s to TargetSegment\n", deviceNo, 
	      inaddrt2str(iphdr->daddr, buf, sizeof(buf)));
  
  iphdr->ttl--;
  
  CONVMAC* dstmac = GetConvMac(iphdr->daddr);
  if(!dstmac){
    DebugPrintf("TranslateTCP : GetConvMac dest NULL error !!!\n\n");
    return 0;
  }
  
  memcpy(eh->ether_dhost,dstmac->mac,6);
  memcpy(eh->ether_shost,Device[senddevno].hwaddr,6);
  
  SetCheckSumTcp(iphdr, tcphdr);
  write(Device[senddevno].soc,data,size);


  DebugPrintf("[%d->%d]:TCP send: src(%s, %hu), dst(%s, %hu)\n",deviceNo, senddevno, 
	      inaddrt2str(iphdr->saddr, buf, sizeof(buf)), ntohs(tcphdr->source),
	      inaddrt2str(iphdr->daddr, buf2, sizeof(buf2)), ntohs(tcphdr->dest)
	      );
  DebugPrintf("[%d->%d]:TCP send: Ether : source : %s\n",deviceNo,
	      senddevno, mac2str((u_char *)&eh->ether_shost, buf, sizeof(buf)));
  DebugPrintf("[%d->%d]:TCP send: Ether : dest : %s\n",deviceNo,
	      senddevno,mac2str((u_char *)&eh->ether_dhost, buf, sizeof(buf)));
  DebugPrintf("[%d->%d]:TCP send: TCP header : ");
  DbgPrintTcpHeader(tcphdr);
  DebugPrintf("\n\n");
  
  
  return 0;
}


int TranslateUdp(int deviceNo, struct ether_header *eh, struct iphdr *iphdr, struct udphdr *udphdr, u_char *data, int size)
{
  char	buf[80];
  char	buf2[80];
  int mineflag = 0;
  int senddevno = 0;
  
  if(iphdr->ttl-1==0){
    DebugPrintf("[%d]:iphdr->ttl==0 error\n",deviceNo);
    SendIcmpTimeExceeded(deviceNo, eh, iphdr, data, size);
    return(-1);
  }
  
  mineflag = ChangeIpAndUdpPort(deviceNo, iphdr, udphdr);
  
  if(mineflag == 1){
    DebugPrintf("[%d]:recv:myaddr: UDP :mine!!!\n", deviceNo);
    return 0;
  }else if(mineflag < 0){
    DebugPrintf("[%d]:No Need Translate: UDP !!!\n", deviceNo);
    return 0;
  }
  
  if((iphdr->daddr & Device[0].netmask.s_addr) == Device[0].subnet.s_addr){
    senddevno = 0;
  }else if((iphdr->daddr & Device[1].netmask.s_addr) == Device[1].subnet.s_addr){
    senddevno = 1;
  }else{
    senddevno = 1;
  }
  
  
  iphdr->ttl--;
  
  DebugPrintf("[%d]:%s to TargetSegment\n",deviceNo, 
	      inaddrt2str(iphdr->daddr, buf, sizeof(buf)));
  
  CONVMAC* dstmac = GetConvMac(iphdr->daddr);
  if(!dstmac){
    DebugPrintf("TranslateUDP : GetConvMac dest NULL error !!!\n\n");
    return 0;
  }
  
  memcpy(eh->ether_dhost, dstmac->mac, 6);
  memcpy(eh->ether_shost, Device[senddevno].hwaddr, 6);
  
  SetCheckSumUdp(iphdr, udphdr);
  write(Device[senddevno].soc, data, size);
  DebugPrintf("[%d->%d]:UDP send: src(%s, %hu), dst(%s, %hu)\n\n",deviceNo, senddevno, 
	      inaddrt2str(iphdr->saddr, buf, sizeof(buf)), ntohs(udphdr->source),
	      inaddrt2str(iphdr->daddr, buf2, sizeof(buf2)), ntohs(udphdr->dest)
	      );
  DebugPrintf("[%d->%d]:UDP send: Ether : source : %s\n",deviceNo,
	      senddevno, mac2str((u_char *)&eh->ether_shost, buf, sizeof(buf)));
  DebugPrintf("[%d->%d]:UDP send: Ether : dest : %s\n\n",deviceNo,
	      senddevno,mac2str((u_char *)&eh->ether_dhost, buf, sizeof(buf)));
  
  return 0;
}


