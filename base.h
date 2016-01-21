typedef struct	{
  int soc;
  u_char hwaddr[6];
  struct in_addr addr, subnet, netmask;
}NETDEVICE;

typedef struct	{
  char* IfName0;
  char* IfName1;
  char* NextRouter;
}PARAM;

#define STRIPLEN	20
#define MACLEN	6
#define CONVMACNUM	5
typedef struct {
	int validflag;
	char strip[STRIPLEN];
	u_char mac[MACLEN];
	u_int32_t i32addr;
}CONVMAC;


typedef struct {
	int validflag;
	u_short orgport;
	u_short serviceport;
	u_short convport;
	in_addr_t clientip;
	time_t updatetime; 
}CONVPORT;

#define CONVPORTTIMEOUT	180
#define CONVPORTNUM 1024
#define CONVPORTSTART 57000
