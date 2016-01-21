#include	<stdio.h>
#include	<string.h>
#include	<unistd.h>
#include	<poll.h>
#include	<errno.h>
#include	<signal.h>
#include	<stdarg.h>
#include	<time.h>
#include        <sys/time.h>
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
#include "convmac.h"


CONVMAC g_convmac[CONVMACNUM];

int InitConvMac(NETDEVICE* srcdev)
{
  char buf[80];

  strcpy(g_convmac[0].strip, "192.168.12.1");//上位ルータ、インターネットへのプロクシ
  strcpy(g_convmac[1].strip, "192.168.12.200");//LAN内のサーバ
  strcpy(g_convmac[2].strip, "192.168.13.100");//クライアント
  //strcpy(g_convmac[3].strip, "192.168.13.1");//NATの内側のNIC
  //strcpy(g_convmac[4].strip, "192.168.12.222");//NATの外側のNIC

  u_char mac0[6] = {0x00, 0x00, 0x00, 0x01, 0x02, 0x03};
  u_char mac1[6] = {0x00, 0x00, 0x00, 0x02, 0x03, 0x04};
  u_char mac2[6] = {0x00, 0x00, 0x00, 0x03, 0x04, 0x05};
  //u_char mac3[6] = {0x00, 0x00, 0x00, 0x04, 0x05  , 0x06};
  //u_char mac4[6] = {0x00, 0x00, 0x00, 0x05, 0x06, 0x07};
  
  memcpy((u_char*)g_convmac[0].mac, (u_char*)mac0, 6);
  memcpy((u_char*)g_convmac[1].mac, (u_char*)mac1, 6);
  memcpy((u_char*)g_convmac[2].mac, (u_char*)mac2, 6);


  //NATマシンの2枚のNIC情報をセット
  strcpy(g_convmac[3].strip, inaddr2str(&srcdev->addr, buf, sizeof(buf)));
  strcpy(g_convmac[4].strip, inaddr2str(&(srcdev + 1)->addr, buf, sizeof(buf)));
  memcpy((u_char*)g_convmac[3].mac, (u_char*)(srcdev->hwaddr), 6);
  memcpy((u_char*)g_convmac[4].mac, (u_char*)((srcdev + 1)->hwaddr), 6);


  int cmno;
  for(cmno = 0; cmno < CONVMACNUM; cmno++){
    CONVMAC* curcm = g_convmac + cmno;
    
    struct in_addr indaddr;
    inet_aton(curcm->strip, &indaddr);
    curcm->i32addr = *((u_int32_t *)&(indaddr));//!!!!!!!!!!!!!
    curcm->validflag = 1;
  }
  
  return 0;
}
CONVMAC* GetConvMac(u_int32_t srcinaddr)
{
  CONVMAC* retmac = 0;
  
  int cmno;
  for(cmno = 0; cmno < CONVMACNUM; cmno++){
    CONVMAC* curcm = g_convmac + cmno;
    if(curcm->validflag == 1){
      if(curcm->i32addr == srcinaddr){
	retmac = curcm;
	break;
      }
    }
  }
  
  if(!retmac){
    retmac = g_convmac + 0;//上位ルータに任せる。
  }
    
  return retmac;
}


