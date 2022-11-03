#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <signal.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "twrmond.h"
#include "rmon.h"
#include "rmonTable.h"


int bWLan = 0;

static	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
static	pcap_t *pPcapH =NULL;				/* packet capture handle */

static struct tw_ipfrag IpFragList[MAX_IP_FRAG];


void GotPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

static int keep_running =1;

static time_t nTimeNow =0;

int nTimeMarkMode = 0; // 0=  High Speed,1= Zero Only,2 = RFC Mode

RETSIGTYPE
stop_server(int a) {
    keep_running = 0;
}

#define MAX_CAP_FIFO 10000   // 13MB

typedef struct tagCapFIFO {
	int nPLen;
	char pCap[2300];
} TW_CAP_FIFO;

TW_CAP_FIFO  CapFIFO[MAX_CAP_FIFO];
int nCapFIFOWPtr =0;
int nCapFIFORPtr =0;
int nCapFIFOSize = 0;
int nCapFIFODrop = 0;
pthread_t   PcapThreadTid;
pthread_mutex_t CapFIFOMutex = PTHREAD_MUTEX_INITIALIZER; // Lock FIFO

void AddCapFIFO(u_char *p,int nPLen,int nCLen)
{
	pthread_mutex_lock(&CapFIFOMutex);
	if( nCapFIFOSize >= MAX_CAP_FIFO ) {
		nCapFIFODrop++;
		pthread_mutex_unlock(&CapFIFOMutex);
		return;
	}
	CapFIFO[nCapFIFOWPtr].nPLen = nPLen;
	if( nCLen > 2300 ) nCLen = 2300;
	memcpy(CapFIFO[nCapFIFOWPtr].pCap,p,nCLen);
	nCapFIFOWPtr++;
	if( nCapFIFOWPtr >= MAX_CAP_FIFO ) nCapFIFOWPtr=0;
	nCapFIFOSize++;
	pthread_mutex_unlock(&CapFIFOMutex);
	return;
}

int GetCapFIFO()
{
	if( nCapFIFOSize < 1 ) return(-1);
	return(nCapFIFORPtr);
}

void FreeCapFIFO()
{
	if( nCapFIFOSize < 1 ) return;
	pthread_mutex_lock(&CapFIFOMutex);
	nCapFIFORPtr++;
	nCapFIFOSize--;
	if( nCapFIFORPtr >= MAX_CAP_FIFO ) nCapFIFORPtr=0;
	pthread_mutex_unlock(&CapFIFOMutex);
	return;
}

int   CheckTwpcd()
{
	FILE *fp;
	int bOK = 0;
	char szTmp[256];
	fp = popen("ps","r");
	if( fp == NULL) return(bOK);
	while( fgets(szTmp,sizeof(szTmp),fp) ) {
		if( strstr(szTmp,"twpcd") != NULL ) {
			bOK = 1;
			break;
		}
	}
	pclose(fp);
	return(bOK);
}


void GotPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	AddCapFIFO((u_char*)packet,header->len+4,header->caplen);
	return;
}

void * PcapThread(void *pDummy)
{
	
	if( pPcapH == NULL ) return(NULL);
	pcap_loop(pPcapH, -1,GotPacket,NULL); // Read All Packet
	return(NULL);
}


static void usage(void) {
   printf("usage: twrmond [-i <Monitor IF>] [-D<tokens>] [-f] [-L] [-M] [-H] [-T <TimemarkMode>] [LISTENING ADDRESSES]\n"
          "\t-f      Do not fork() from the calling shell.\n"
          "\t-DTOKEN[,TOKEN,...]\n"
          "\t\tTurn on debugging output for the given TOKEN(s).\n"
          "\t\tWithout any tokens specified, it defaults to printing\n"
          "\t\tall the tokens (which is equivalent to the keyword 'ALL').\n"
          "\t\tYou might want to try ALL for extremely verbose output.\n"
          "\t\tNote: You can't put a space between the -D and the TOKENs.\n"
          "\t-H\tDisplay a list of configuration file directives\n"
          "\t\tunderstood by the agent and then exit.\n"
          "\t-M\tRun as a normal SNMP Agent instead of an AgentX sub-agent.\n"
          "\t-x ADDRESS\tconnect to master agent at ADDRESS (default /var/agentx/master).\n"
          "\t-L\tDo not open a log file; print all messages to stderr.\n");
  exit(0);
}


int FindOrNewIpFragEntry( struct tw_ip *pIP)
{
	int i;
	time_t nLowTime = 0xffffffff;
	int nNew = -1;
	for( i = 0; i < MAX_IP_FRAG;i++ ) {
		if( nLowTime > IpFragList[i].nTime ) {
			nLowTime = IpFragList[i].nTime;
			nNew = i;
		}
		if( IpFragList[i].nTime == 0 ) continue;
		if( IpFragList[i].flow.ip_src == pIP->ip_src &&
		    IpFragList[i].flow.ip_dst == pIP->ip_dst &&
		    IpFragList[i].ip_id == pIP->ip_id ) {
			IpFragList[i].nTime =nTimeNow;
			return(i);
		}
	}
	i = nNew;
	IpFragList[i].nTime =0;
	return(i);
}

int nSnapLen = SNAP_LEN;

int CheckPcapDev(char *pDev)
{
	pcap_t *handle;				/* packet capture handle */
	int nBufSize = 1024*1024*8; // Rx Buffer is 8MB 
	int nRet = 1;
	int ltype;
	if( pDev == NULL ) return(0);
	/* open capture device */
	handle = pcap_open_live(pDev, nSnapLen, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", pDev, errbuf);
		return(0);
	}
	if (setsockopt(pcap_fileno(handle), SOL_SOCKET, SO_RCVBUF, &nBufSize, sizeof(nBufSize)) < 0){
		fprintf(stderr, "Could not set RCV BUFFER SIZE\n");
		nRet = 0;
	}
	/* make sure we're capturing on an Ethernet device [2] */
	ltype = pcap_datalink(handle);
	if( ltype != DLT_IEEE802_11_RADIO  && ltype !=  DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n",pDev);
		nRet =0;
	}
	if( ltype == DLT_IEEE802_11_RADIO ) nSnapLen = 2300;
	pcap_close(handle);
	return(nRet);
}


int InitPcap(char *pDev)
{
	int nBufSize = 1024*1024*8; // Rx Buffer is 8MB 
	int nNonBlock = 1;
	if( pDev == NULL ) return(0);
	/* open capture device */
	pPcapH = pcap_open_live(pDev, nSnapLen, 1, 1000, errbuf);
	if (pPcapH == NULL) {
		return(0);
	}
	if( pcap_datalink(pPcapH) ==  DLT_IEEE802_11_RADIO ) {
		bWLan = 1;
	}
	setsockopt(pcap_fileno(pPcapH), SOL_SOCKET, SO_RCVBUF, &nBufSize, sizeof(nBufSize));
	return(1);
}

/*
 */
void CheckPacket(u_char *p,int nPLen)
{
	/* declare pointers to packet headers */
	struct tw_eth *pEth=NULL;  /* The ethernet header */
	struct tw_ip *pIP =NULL;              /* The IP header */
	struct tw_tcp *pTCP =NULL;            /* The TCP header */
	struct tw_udp *pUDP = NULL;            /* The UDP header */
	struct tw_icmp *pICMP = NULL;		/* The ICMP header */
	struct tw_flow Flow;
	u_short nEType;
	u_short nIPFrag;
	int     nIPSize;
	int     nTCPSize;
	int     nIPVer;
	int     nIPFragIndex;
	/* define ethernet header */
	if( bWLan ) {
		nPLen-=4;
		p = WLanPktProc(p,&nPLen); // Wireless LAN  Mode
		if( p == NULL ) return;
	}
	pEth = (struct tw_eth*)(p);
	nEType = ntohs(pEth->ether_type);
	UpdateRmonEth(pEth,nPLen); // Host And Matrix
	p+= SIZE_ETHERNET;
	if( nEType == 0x8100 ) {
		p+=2; // Skip VLAN Header
		nEType = (p[0] << 8) +p[1];
		p+=2;
	}
	if( nEType <= MAX_8023_LEN ) {
		/* assume 802.3+802.2 header */
		/* check for SNAP */
		if(p[0] == 0xAA && p[1] == 0xAA && p[2] == 0x03) {
			p += 3;
			if(p[0] != 0 || p[1] != 0 ||  p[2] != 0) {
				return; /* no further decode for vendor-specific protocol */
			}
			p += 3;
			/* OUI == 00-00-00 means the next two bytes are the ethernet type (RFC 2895) */
			nEType = (p[0] << 8) + p[1];
			p += 2;
		}  else {
			if (p[0] == 0x06 &&  p[1] == 0x06 && (p[2] & 0x01)) {
				/* IP over 8022 */
				p += 3;
				/* force the type_len to be IP so we can inline the IP decode below */
				nEType = 0x0800;
			}
		}
	}
	if( nEType == 0x8864 ) {
		if (p[6] == 0x00 &&  p[7] == 0x21 ) {
			/* PPPoE IP */
			p += 8;
			/* force the type_len to be IP so we can inline the IP decode below */
			nEType = 0x0800;
		}
	}
	if( nEType != 0x0800 ) return; // Not IP
	pIP = (struct tw_ip*) p;
	
	nIPSize =(int) IP_HL(pIP)*4;
	nIPVer = (int) IP_V(pIP) & 0x0f;
	if (nIPSize < 20 || nIPVer != 4) {
		// Not IPv4
		return;
	}
	UpdateRmonIP(pEth,pIP,nPLen);
	nIPFrag = htons(pIP->ip_off);
	p+=nIPSize;
// �����Ńt���O�����g�̃`�F�b�N���s���B
	if ( (nIPFrag &( IP_OFFMASK | IP_MF)) != 0  ) {
		nIPFragIndex = FindOrNewIpFragEntry(pIP);
	} else {
		nIPFragIndex = -1;
	}
	if( nIPFragIndex == -1  || IpFragList[nIPFragIndex].nTime == 0 ) {
		/* determine protocol */	
		switch(pIP->ip_p) {
			case IPPROTO_TCP:
				pTCP =(struct tw_tcp*) p;
				break;
			case IPPROTO_UDP:
				pUDP= (struct tw_udp*)p;
				break;
			case IPPROTO_ICMP:
				pICMP = (struct tw_icmp*)p;
				break;
			default:
				return;
		}
		Flow.ip_src = pIP->ip_src;
		Flow.ip_dst = pIP->ip_dst;
		Flow.ip_p = pIP->ip_p;
		if( pTCP ) {
			Flow.sport = pTCP->th_sport;
			Flow.dport = pTCP->th_dport;
		} else if (pUDP) {
			Flow.sport = pUDP->uh_sport;
			Flow.dport = pUDP->uh_dport;
		} else if (pICMP ) {
			Flow.sport = pICMP->type;
			Flow.dport = pICMP->code;
		}
		if( nIPFragIndex != -1 ) {
			IpFragList[nIPFragIndex].flow = Flow;
			IpFragList[nIPFragIndex].nTime = nTimeNow;
		}
	} else {
		Flow = IpFragList[nIPFragIndex].flow;
	}
	Flow.bMCas = (pEth->ether_dhost[0] & 0x01 ); 
	UpdateRmonFlow(&Flow,nPLen);
	return;
}


extern void CtlTableSort(int bSort);


int tw_agent_check_and_process()
{
    int             numfds;
    fd_set          fdset;
    struct timeval  timeout = { 0, 100 }, *tvp = &timeout;
    int             count;
    int             fakeblock = 0;
	struct pcap_stat ps;
	nTimeNow = time(0);
    numfds = 0;
    FD_ZERO(&fdset);
    snmp_select_info(&numfds, &fdset, tvp, &fakeblock);
    count = select(numfds, &fdset, 0, 0, tvp);
    if( count > 0 ) {
     	CtlTableSort(1);
		snmp_read(&fdset);
     	CtlTableSort(0);
	} else {
		snmp_timeout();
	}
    /*
     * Run requested alarms.  
     */
    run_alarms();
    netsnmp_check_outstanding_agent_requests();
	pcap_stats(pPcapH,&ps);
	UpdateRmonDrop(ps.ps_drop+ps.ps_ifdrop+nCapFIFODrop);
    return count;
}


int CheckCapFIFO()
{
	int f;
	int i;
	time_t nT = time(0);
	for( i =0; i < 1000;i++ ) {
	  f =  GetCapFIFO();
	  if( f < 0 ) return(i);
	  CheckPacket(CapFIFO[f].pCap,CapFIFO[f].nPLen);
	  FreeCapFIFO();
	}
	if( (time(0) - nT)  > 1){
		printf("Long Process =%d\n",time(0)-nT);
	} 
	return(i);
}

int main(int argc, char **argv)
{
  int agentx_subagent=1; /* change this if you want to be a SNMP master agent */
  int background = 1; /* change this if you want to run in the background */
  int syslog = 1; /* change this if you want to use syslog */
  int          ch;
  extern char *optarg;
  char *agentx_socket = NULL;
  char *pDev = NULL;
  time_t nLastTime = time(0);

  while ((ch = getopt(argc, argv, "i:D:fHLMx:T:")) != EOF)
    switch(ch) {
    case 'D':
      debug_register_tokens(optarg);
      snmp_set_do_debugging(1);
      break;
    case 'f':
      background = 0;
      break;
    case 'H':
      netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID,
                             NETSNMP_DS_AGENT_NO_ROOT_ACCESS, 1);
      init_agent("twrmond");        /* register our .conf handlers */
	  init_rmon();  
	  init_rmonTable();  
      init_snmp("twrmond");
      fprintf(stderr, "Configuration directives understood:\n");
      read_config_print_usage("  ");
      exit(0);
    case 'M':
      agentx_subagent = 0;
      break;
    case 'L':
      syslog = 0; /* use stderr */
      break;
    case 'x':
      agentx_socket = optarg;
      break;
    case 'i':
      pDev = optarg;
      break;
    case 'T':
      nTimeMarkMode = atoi(optarg);
      if( nTimeMarkMode < 0 ||  nTimeMarkMode > 3) nTimeMarkMode =0;
      break;
    default:
      fprintf(stderr,"unknown option %c\n", ch);
      usage();
  }
  if (optind < argc) {
      int i;
      /*
       * There are optional transport addresses on the command line.
       */
      DEBUGMSGTL(("snmpd/main", "optind %d, argc %d\n", optind, argc));
      for (i = optind; i < argc; i++) {
          char *c, *astring;
          if ((c = netsnmp_ds_get_string(NETSNMP_DS_APPLICATION_ID,
                                         NETSNMP_DS_AGENT_PORTS))) {
              astring = malloc(strlen(c) + 2 + strlen(argv[i]));
              if (astring == NULL) {
                  fprintf(stderr, "malloc failure processing argv[%d]\n", i);
                  exit(1);
              }
              sprintf(astring, "%s,%s", c, argv[i]);
              netsnmp_ds_set_string(NETSNMP_DS_APPLICATION_ID,
                                    NETSNMP_DS_AGENT_PORTS, astring);
              SNMP_FREE(astring);
          } else {
              netsnmp_ds_set_string(NETSNMP_DS_APPLICATION_ID,
                                    NETSNMP_DS_AGENT_PORTS, argv[i]);
          }
      }
      DEBUGMSGTL(("snmpd/main", "port spec: %s\n",
                  netsnmp_ds_get_string(NETSNMP_DS_APPLICATION_ID,
                                        NETSNMP_DS_AGENT_PORTS)));
  }
	if( !CheckPcapDev(pDev) ) {
		fprintf(stderr, "pcap device error\n");
		exit(2);
	}
  /* we're an agentx subagent? */
  if (agentx_subagent) {
    /* make us a agentx client. */
    netsnmp_enable_subagent();
    if (NULL != agentx_socket)
        netsnmp_ds_set_string(NETSNMP_DS_APPLICATION_ID,
                              NETSNMP_DS_AGENT_X_SOCKET, agentx_socket);
  }
	memset(IpFragList,0,sizeof(IpFragList));
  snmp_disable_log(); 
  /* print log errors to syslog or stderr */
  if (syslog)
    snmp_enable_calllog();
  else
    snmp_enable_stderrlog();

  /* we're an agentx subagent? */
  if (agentx_subagent) {
    /* make us a agentx client. */
    netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_ROLE, 1);
  }

  /* run in background, if requested */
  if (background && netsnmp_daemonize(1, !syslog))
      exit(1);

  /* initialize tcpip, if necessary */
  SOCK_STARTUP;

	InitPcap(pDev);
  /* initialize the agent library */
  init_agent("twrmond");

  /* initialize mib code here */
  SetDataSource(pDev);
  
  init_rmon();  
  init_rmonTable();  
	if( bWLan ) {
		TwWLanInit();
		TwWLanLoadKeys("/etc/wkeys.txt");
		init_twWRMon();
		init_twWRMonTable();
	}
  /* initialize vacm/usm access control  */
  if (!agentx_subagent) {
      init_vacm_vars();
      init_usmUser();
  }

  /* example-demon will be used to read example-demon.conf files. */
  init_snmp("twrmond");

  /* If we're going to be a snmp master agent, initial the ports */
  if (!agentx_subagent)
    init_master_agent();  /* open the port to listen on (defaults to udp:161) */

  /* In case we recevie a request to stop (kill -TERM or kill -INT) */
  keep_running = 1;
  signal(SIGTERM, stop_server);
  signal(SIGINT, stop_server);

	LoadTwRmonConf();
	if( bWLan) LoadTwWRmonConf();
  snmp_log(LOG_INFO,"twrmond is up and running.\n");

  pthread_create(&PcapThreadTid,NULL,PcapThread,(void*)NULL);

  /* your main loop here... */
 	CtlTableSort(0);
  while(keep_running) {
	CheckCapFIFO();
    tw_agent_check_and_process(); // Time Out 1Sec 
    if( bWLan ) {
		CheckWRmonTrap();
		CheckDelMtx();
		CheckDelSta();
		OutApList();
	}
	if( !background ) continue;
    if( time(0) >(nLastTime+120) ) {
		nLastTime = time(0);
		if( !CheckTwpcd() ) {
			keep_running = 0;
		}
	}
  }
  	system("enable");
	SaveTwRmonConf();
	if( bWLan) SaveTwWRmonConf();
	system("disable");
  /* at shutdown time */
  snmp_shutdown("twrmond");
  SOCK_CLEANUP;
  pcap_breakloop(pPcapH);
  pcap_close(pPcapH);
  pthread_join(PcapThreadTid,NULL);                 /*  PCAP�X���b�h�I���҂�        */
 	if( bWLan ) {
		TwWLanCleanup();
	}
  return 0;
}

