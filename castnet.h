struct ether_header* Cast2EthHeader(u_char* data, int size, u_char** ppdata, int* restptr);
struct ether_arp* Cast2EthArp(u_char* data, int size, u_char** ppdata, int* restptr);
struct iphdr* Cast2Ip4Header(u_char* data, int size, u_char** ppdata, int* restptr);
struct ip6_hdr* Cast2Ip6Header(u_char* data, int size, u_char** ppdata, int* restptr);
struct icmp* Cast2Icmp4(u_char* data, int size, u_char** ppdata, int* restptr);
struct icmp6_hdr* Cast2Icmp6(u_char* data, int size, u_char** ppdata, int* restptr);
struct tcphdr* Cast2TcpHeader(u_char* data, int size, u_char** ppdata, int* restptr);
struct udphdr* Cast2UdpHeader(u_char* data, int size, u_char** ppdata, int* restptr);

