int DebugPrintf(char *fmt,...);
int DebugPerror(char *msg);

char* mac2str(u_char *hwaddr,char *buf, int size);
char* inaddr2str(struct in_addr *addr,char *buf, int size);
char* inaddrt2str(in_addr_t addr,char *buf, int size);
char* ipi82str(u_int8_t *ip,char *buf, int size);
char* ip322str(u_int32_t ip,char *buf, int size);

int DbgPrintEthHeader(struct ether_header *eh);
int DbgPrintArp(struct ether_arp *arp);
int DbgPrintIp4Header(struct iphdr *iphdr);
int DbgPrintIp6Header(struct ip6_hdr *ip6);
int DbgPrintIcmp(struct icmp *icmp, int icmplen);
int DbgPrintIcmp6(struct icmp6_hdr *icmp6);
int DbgPrintTcpHeader(struct tcphdr *tcphdr);
int DbgPrintUdpHeader(struct udphdr *udphdr);


