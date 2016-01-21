u_int16_t CheckSum(unsigned char *data,int len);
u_int16_t CheckSum2(unsigned char *data1,int len1,unsigned char *data2,int len2);
u_int16_t IpHeaderCheckSum(struct iphdr *iphdr);
u_int16_t IpDataCheckSum(struct iphdr *iphdr,unsigned char *data,int len);
