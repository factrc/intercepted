/*
****************************
Author: lomaster
****************************
*/

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h> 
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>

#define DEFPID  "/var/run/interceptd.pid"
#define DEFDEV  "eth0"
#define MAXPATH  1024
#define IDIRECT_PAYLOAD 8

struct s_stat{
  unsigned int rx;
  unsigned int tx;
  unsigned int ip;
  unsigned int error;
  unsigned int match;
}stat;


struct pSeq{
 unsigned char num[3];
}__attribute__((packed));

struct pLL{
 unsigned int subtype:6;
 unsigned int type:2;
 struct pSeq seq;
}__attribute__((packed));

struct piDirect{
  unsigned short hdlc_addr;
  struct pLL  ll_ctl;
  unsigned short vlan;
  struct iphdr hdr; 
}__attribute__((packed));


int gDaemon;
unsigned char gMac[ETH_ALEN];
unsigned char gSrcMac[ETH_ALEN];
unsigned int gVlan[4096/32];
unsigned short gPort;
struct in_addr gBindAddr;
struct in_addr gRemoteAddr;
struct sockaddr_ll gSockAddr;
unsigned char gBuffer[ETH_FRAME_LEN+IDIRECT_PAYLOAD];


int match_vlan(int vlan )
{
  int off_bit =  vlan & 0x1F;
  int off_dwd =  (vlan >> 5)&0x7F;
  if ( gVlan[off_dwd] & (0x80000000>>off_bit) ) 
    return 1;
  return 0; 
}

void set_vlan( int vlan )
{
  int off_bit =  vlan & 0x1F;
  int off_dwd =  (vlan >> 5)&0x7F;
  gVlan[off_dwd] = gVlan[off_dwd] | (0x80000000>>off_bit);
}


int device_info( int fd, const char *devname, int *dev_index, unsigned char *mac )
{
  struct ifreq ifr;
  strncpy(ifr.ifr_name,devname, IFNAMSIZ);
  if(ioctl(fd, SIOCGIFINDEX, &ifr)<0)   return -1; 
  *dev_index = ifr.ifr_ifindex;
  if(!gDaemon) fprintf(stdout,"index interface(%s)=%d\n",devname,ifr.ifr_ifindex);
  if (ioctl(fd, SIOCGIFHWADDR, &ifr)<0) return -1;
  if(!gDaemon) fprintf(stdout,"mac interface(%s) ",devname);
  for (int i = 0; i < 6; i++) {
    mac[i] = ifr.ifr_hwaddr.sa_data[i];
    if(i!=5) 
     if(!gDaemon) fprintf(stdout,"%02x:",mac[i]);
  } 
  if(!gDaemon) fprintf(stdout,"%02x\n",mac[5]);
  return 0;
}

int init_rawsocket( char *device )
{
   struct ifreq ifr;
   int index;
   
   int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); 
   if ( fd < 0 ){  perror("socket():");  exit(-1);  } 
   if(device_info(fd,device,&index,gSrcMac)<0) { perror("device_info"); exit(-1); }

   gSockAddr.sll_family   = PF_PACKET;
   gSockAddr.sll_protocol = htons(ETH_P_IP);
   gSockAddr.sll_ifindex  = index;
   gSockAddr.sll_hatype   = ARPHRD_ETHER;
   gSockAddr.sll_pkttype  = PACKET_OTHERHOST;
   gSockAddr.sll_halen    = ETH_ALEN;
   gSockAddr.sll_addr[0]  = gMac[0];
   gSockAddr.sll_addr[1]  = gMac[1];
   gSockAddr.sll_addr[2]  = gMac[2];
   gSockAddr.sll_addr[3]  = gMac[3];
   gSockAddr.sll_addr[4]  = gMac[4];
   gSockAddr.sll_addr[5]  = gMac[5];
   gSockAddr.sll_addr[6]  = 0x00; 
   gSockAddr.sll_addr[7]  = 0x00; 
   return fd;
}

int init_udpsocket( void )
{
  struct sockaddr_in si_me;
  int fd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  memset((char *) &si_me, 0, sizeof(si_me));
  si_me.sin_family = AF_INET;
  si_me.sin_port = htons(gPort);
  si_me.sin_addr.s_addr = gBindAddr.s_addr;
  if (bind(fd, (struct sockaddr*)&si_me, sizeof(si_me))<0){
   close(fd);
   return -1;
  }
  return fd;
}

int read_udp ( int fd, void *buffer, int count )
{
  int recv;
  struct sockaddr_in s_remote;
  socklen_t s_len = sizeof(s_remote);
  recv = recvfrom(fd, buffer, count, 0, (struct sockaddr*)&s_remote, &s_len);
  if(!gDaemon && recv>0){ 
    fprintf(stdout,"Received packet from %s:%d\n",inet_ntoa(s_remote.sin_addr), ntohs(s_remote.sin_port));
  }
  if ( gRemoteAddr.s_addr && s_remote.sin_addr.s_addr != gRemoteAddr.s_addr ) {
   if ( !gDaemon )
     fprintf(stdout,"Illegal packet from %s:%d\n",inet_ntoa(s_remote.sin_addr), ntohs(s_remote.sin_port));
   return 0;
  } 
  return recv;  
}


int send_packet( int fd, void *src, int count )
{
  int size = count+ETH_HLEN; 
  struct ethhdr *eh = (struct ethhdr *)gBuffer;
  if ( count+ETH_HLEN < ETH_ZLEN ) size = ETH_ZLEN;
  memcpy((void*)(eh->h_dest),(void*)gMac,ETH_ALEN); 
  memcpy((void*)(eh->h_source),(void*)gSrcMac,ETH_ALEN);
  eh->h_proto = htons(ETH_P_IP);
  return sendto(fd,gBuffer,size,0,(struct sockaddr*)&gSockAddr, sizeof(gSockAddr));
}


int process_packet( struct piDirect *pkt, int count )
{
  /* network control data skip */
  if ( (pkt->hdlc_addr & 0xFF) == 0xFF ) 
    return 0;
/*
  if(!gDaemon) 
    fprintf(stdout,"ll_control=(type=%x,subtype=%x,seq=(%x,%x,%x))\n",pkt->ll_ctl.type,pkt->ll_ctl.subtype,pkt->ll_ctl.seq.num[0],pkt->ll_ctl.seq.num[1],pkt->ll_ctl.seq.num[2]); 
*/
  if ( pkt->hdr.version != 4 || pkt->hdr.ihl < 5 )
    return -1;
  
  stat.ip++;
  
  if ( !match_vlan (htons(pkt->vlan)) )
   return -1;
  
  stat.match++;
  
  if ( !gDaemon ) 
  {
    char saddr[18],daddr[18];
    struct in_addr iaddr;

    iaddr.s_addr = pkt->hdr.saddr;
    strcpy(saddr,inet_ntoa(iaddr));
    iaddr.s_addr = pkt->hdr.daddr;
    strcpy(daddr,inet_ntoa(iaddr));
    int asize = ((pkt->hdr.tot_len&0xFF)<<8) | ((pkt->hdr.tot_len>>8)&0xFF);
    fprintf(stdout,"%-10d %-10d %-10d %-16s %-16s %10d(%d)\n", 
      ((pkt->vlan>>8)&0xFF)|((pkt->vlan&0xFF)<<8),
      pkt->hdr.protocol,
      pkt->hdr.ttl,
      saddr,
      daddr,
      asize,
      count-8
    );
  }    
  return 1;
}

void stat_log ( int a )
{
  syslog(LOG_INFO,"RX=%d,TX=%d,IP=%d,MATCH=%d,ERR=%d",stat.rx,stat.tx,stat.ip,stat.match,stat.error);    
}

static void usage(void)
{
  fprintf(stdout,"command line:\n"
  "\t-d\t daemon\n"
  "\t-p\t port. Example(1234)\n"
  "\t-s\t bind address. Example(192.168.1.1)\n"
  "\t-S\t remote address. Example(192.168.1.2)\n"
  "\t-D\t destination mac address. Example(12:34:56:78:90:ab)\n"
  "\t-i\t output interface. Example(eth0)\n"
  "\t-v\t number vlan filter. Example(10),Example(10,20,30)\n"
  "\t-h\t help\n"
  );
}

void make_mac_address(unsigned char *mac, char *str)
{
 int m1,m2,m3,m4,m5,m6;
 if(sscanf(str,"%x:%x:%x:%x:%x:%x",&m1,&m2,&m3,&m4,&m5,&m6)!=6){
   fprintf(stdout,"error:\n");
   usage();
   exit(-1);
 }
 mac[0] = m1; mac[1] = m2;
 mac[2] = m3; mac[3] = m4;
 mac[4] = m5; mac[5] = m6;
}


int read_vlan_list( char *vlans )
{
  int i,idx;
  char buf[255];
  for ( i = idx = 0;i<strlen(vlans);i++ )
  {
     if ( vlans[i] == ',' ){
       if ( i-idx > sizeof(buf) ) return -1; 
       strncpy(buf,(vlans+idx),i-idx);
       buf[i-idx] = 0;
       idx = i+1;
       if ( !atoi(buf) ) return -1;
       set_vlan(atoi(buf));
     }
  }
  if ( i-idx > sizeof(buf) ) return -1; 
  strncpy(buf,(vlans+idx),i-idx);
  buf[i-idx] = 0;
  set_vlan(atoi(buf));
  return 0;
}



int main ( int argc, char *argv[] )
{
  int ch,fd,listen,size;
  int req_param = 0;
  char device[IFNAMSIZ+1];
  unsigned char buffer[ETH_DATA_LEN+IDIRECT_PAYLOAD],*piDirectBuffer;
  char pidstr[MAXPATH];
  
  strcpy(device,DEFDEV);
  strcpy(pidstr,DEFPID);
  while ((ch = getopt(argc, argv, "dhp:s:i:v:D:S:r:")) != -1) {
   switch ( ch ){
    case 'd': 
	    gDaemon = 1; 
	    break;
    case 'r':
            strncpy(pidstr,optarg,MAXPATH-1);
            break;
    case 'p': 
	    gPort = atoi(optarg); 
	    req_param++;
	    break;
    case 's': 
	    gBindAddr.s_addr = inet_addr(optarg);
	    req_param++;
	    break;
    case 'S': 
	    gRemoteAddr.s_addr = inet_addr(optarg);
	    break;
    case 'i': 
	    strncpy(device,optarg,IFNAMSIZ); 
	    req_param++;
	    break;
    case 'v':
	    if(!read_vlan_list(optarg))
		req_param++;
	    break;
    case 'D':
	    make_mac_address(gMac,optarg);
	    req_param++;
	    break;
    case 'h': 
	    usage();
	    exit(0);

   }
  }
  
  if ( req_param < 5 ) {  usage();  exit(-1);  }

  fd = init_rawsocket(device); 
  listen = init_udpsocket();
  if ( listen<0 ){
    printf("error listen\n");
    exit(-1);
  }
 
  if(gDaemon) 
  {
    int pid;
    if((pid = fork())<0) exit(-1);
    if(pid)
     exit(0);
    setsid();
    signal(SIGUSR1,stat_log);
    openlog("interceptd",LOG_PID|LOG_NDELAY,LOG_DAEMON);
  }
  if ( !gDaemon ) {
    printf("port=%d,device=%s,addr=%s\n",gPort,device,inet_ntoa(gBindAddr));
  }
  
 /* vlan protocol ttl saddr daddr len*/
  if(!gDaemon) fprintf(stdout,"%-10s %-10s %-10s %-16s %-16s %-10s\n","vlan","protocol","ttl","saddr","daddr","len");
  
  piDirectBuffer = gBuffer+ETH_ALEN;
  size = sizeof(gBuffer)-ETH_ALEN;
  while(1)
  {
    int count = read_udp(listen,(void*)piDirectBuffer,size);
    if ( count < 0 || !count  ){ stat.error++; usleep(2); continue;}
    if ( count < sizeof(struct piDirect) ) continue;
    stat.rx++;
    
    if( process_packet((struct piDirect*)piDirectBuffer,count)>0 ){
      if ( send_packet(fd,gBuffer,count-IDIRECT_PAYLOAD)>=0 ) 
       stat.tx++;
    }  
  }
  closelog();
  return 0;
}
