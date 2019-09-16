/* 
 *  File name          :   routine_manager.c
 *  File description   :   Manager for Always Unicast routine
 *  Author             :   Chenhsun Chai
 *  Created at         :   2019/7/17
 *
 */

#include "routine_manager.h"

struct timeval tvrecv;

typedef struct _TROUTINEManager
{
	char acDstIPaddress[INET6_ADDRSTRLEN];
	int iRecvTimeout; 			// ms, default = 5000: 5 secs
	int iRoutineInterval; 		// ms, default = 120000: 2 mins
	int iNumberofSendPackets; 	// default = 5: send 5 pings every routine

	EROUTINEManagerStatus eCurrRTMgrStatus;
	EROUTINEManagerStatus eLastRTMgrStatus;
	bool bStatusChanged;
	bool bRoutineStart;

	int pid;
	int sockfd;
	struct addrinfo tDestAddrInfo;
	struct sockaddr_storage tFromAddr;

	int iLastSendICMPEchoIndex;
	DWORD dwLastSendTimeSec;

	int iLastRecvICMPEchoIndex;
	DWORD dwLastRecvTimeSec;

	char sendpacket[PACKET_SIZE];
	char recvpacket[PACKET_SIZE];
	int datalen;

	int nCurSend;
	int nCurReceived;

	uint16_t usSendSeq;

	double temp_rtt[MAX_NO_PACKETS];
	double all_time;
	double min;
	double max;
	double avg;
	double mdev;
} TROUTINEManager;

void *get_in_addr(struct sockaddr *sa);

void statistics(TROUTINEManager *ptRTMgr);
void statistics_reset(TROUTINEManager *ptRTMgr);
void send_packet(TROUTINEManager *ptRTMgr);
void recv_packet(TROUTINEManager *ptRTMgr);
void computer_rtt(TROUTINEManager *ptRTMgr);
void tv_sub(struct timeval *out,struct timeval *in);
int timeSec2MSec_sub(DWORD dwStartTime, DWORD dwEndTime);

void icmp_ping_sendout(TROUTINEManager *ptRTMgr);
int icmp_echo_pack(TROUTINEManager *ptRTMgr, uint16_t pack_no);
int icmp_unpack(TROUTINEManager *ptRTMgr, char *buf, int len);

unsigned short cal_chksum(unsigned short *addr,int len);

SCODE RoutineMgr_SetStatus(TROUTINEManager *ptRTMgr, EROUTINEManagerStatus eStatus);

void RoutineMgr_LOG(int iLevel, const char *format, ...)
{
	char acMsg[512] = {0};

	va_list ap;
	va_start(ap, format);
	vsnprintf(acMsg, sizeof(acMsg), format, ap);
	va_end(ap);

	printf("%s", acMsg);

	switch (iLevel)
	{
		case LOG_ERR:
			syslog(LOG_ERR, "[Routine Manager] %s", acMsg);
		break;
	}
}

void dumpRTMgrStatus(TROUTINEManager *ptRTMgr)
{
	if (!ptRTMgr)
	{
		return;
	}

	char acStatus[128] = {0};

	switch (ptRTMgr->eCurrRTMgrStatus)
	{
	case ERTMgrStatus_Stoped:
		snprintf(acStatus, sizeof(acStatus), "ERTMgrStatus_Stoped");
		break;
	case ERTMgrStatus_Fail_NoResponse:
		snprintf(acStatus, sizeof(acStatus), "ERTMgrStatus_Fail_NoResponse");
		break;
	case ERTMgrStatus_Fail_SocketError:
		snprintf(acStatus, sizeof(acStatus), "ERTMgrStatus_Fail_SocketError");
		break;
	case ERTMgrStatus_Initial:
		snprintf(acStatus, sizeof(acStatus), "ERTMgrStatus_Initial");
		break;
	case ERTMgrStatus_EchoRequest_Sent:
		snprintf(acStatus, sizeof(acStatus), "ERTMgrStatus_EchoRequest_Sent");
		break;
	case ERTMgrStatus_EchoReply_Received:
		snprintf(acStatus, sizeof(acStatus), "ERTMgrStatus_EchoReply_Received");
		break;
	default:
		snprintf(acStatus, sizeof(acStatus), "UNKNOWN STATUS");
		break;
	}

	printf("%s Status is %d %s bChanged=%d\n", __FUNCTION__,
			ptRTMgr->eCurrRTMgrStatus, acStatus, ptRTMgr->bStatusChanged);
}

void computer_rtt(TROUTINEManager *ptRTMgr)
{
	if (!ptRTMgr)
	{
		return;
	}

	//printf("%s-%d nreceived=%d\n", __FUNCTION__, __LINE__, ptRTMgr->nreceived);
	if (ptRTMgr->nCurReceived <= 0)
	{
		printf("%s-%d nreceived=%d, return!!!\n", __FUNCTION__, __LINE__, ptRTMgr->nCurReceived);
		return;
	}

	double sum_avg = 0;
	int i;
	ptRTMgr->min = ptRTMgr->max = ptRTMgr->temp_rtt[0];
	ptRTMgr->avg = ptRTMgr->all_time / ptRTMgr->nCurReceived;

	for(i = 0; i < ptRTMgr->nCurReceived; i++)
	{
		if( ptRTMgr->temp_rtt[i] < ptRTMgr->min)
		{
			ptRTMgr->min = ptRTMgr->temp_rtt[i];
		}
		else if(ptRTMgr->temp_rtt[i] > ptRTMgr->max)
		{
			ptRTMgr->max = ptRTMgr->temp_rtt[i];
		}

		if((ptRTMgr->temp_rtt[i]-ptRTMgr->avg) < 0)
		{
			sum_avg += ptRTMgr->avg - ptRTMgr->temp_rtt[i];
		}
		else
		{
			sum_avg += ptRTMgr->temp_rtt[i] - ptRTMgr->avg;
		}
	}

	ptRTMgr->mdev = sum_avg / ptRTMgr->nCurReceived;
}

void statistics_reset(TROUTINEManager *ptRTMgr)
{
	if (!ptRTMgr)
	{
		return;
	}

	ptRTMgr->nCurSend = 0;
	ptRTMgr->nCurReceived = 0;

	ptRTMgr->all_time = 0;
	ptRTMgr->min = 0;
	ptRTMgr->avg = 0;
	ptRTMgr->max = 0;
	ptRTMgr->mdev = 0;

	return;
}

void statistics(TROUTINEManager *ptRTMgr)
{
	if (!ptRTMgr)
	{
		return;
	}

	computer_rtt(ptRTMgr);
	printf("\n------ %s ping statistics ------\n", ptRTMgr->acDstIPaddress);
	printf("RoutineInterval=%d ms / RecvTimeOut=%d ms / OutSendNumber=%d \n",
			ptRTMgr->iRoutineInterval, ptRTMgr->iRecvTimeout, ptRTMgr->iNumberofSendPackets);
	printf("%d packets transmitted, %d received, %d%% packet loss, time %.f ms\n",
			ptRTMgr->nCurSend,
			ptRTMgr->nCurReceived,
			(ptRTMgr->nCurSend - ptRTMgr->nCurReceived) / ptRTMgr->nCurSend*100,
			ptRTMgr->all_time);
	printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n",
			ptRTMgr->min,
			ptRTMgr->avg,
			ptRTMgr->max,
			ptRTMgr->mdev);
	printf("------------ ping statistics ------------\n\n");

	if (ptRTMgr->nCurReceived <= 0)
	{
		RoutineMgr_SetStatus(ptRTMgr, ERTMgrStatus_Fail_NoResponse);
		RoutineMgr_LOG(LOG_ERR, "ICMP Routine receive timeout. No response received!\n");
	}
}

unsigned short cal_chksum(unsigned short *addr,int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short check_sum = 0;

	while(nleft>1) //ICMP header 2 bytes
	{
		sum += *w++;
		nleft -= 2;
	}

	if(nleft == 1)
	{
		*(unsigned char *)(&check_sum) = *(unsigned char *)w;
		sum += check_sum;
	}
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	check_sum = ~sum;
	return check_sum;
}

/*
 * RFC 792
 * ICMP Echo or Echo Reply Message
 *
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Identifier          |        Sequence Number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Data ...
   +-+-+-+-+-

 * Type:
 * 8 for echo message;
 * 0 for echo reply message.
 *
 * Code: 0
 *
 * Identifier:
 * If code = 0, an identifier to aid in matching echos and replies, may be zero.
 *
 * Sequence Number
 * If code = 0, a sequence number to aid in matching echos and replies, may be zero.
 *
 * Description
 * The data received in the echo message must be returned in the echo reply message.
 *
 *
 */

int icmp_echo_pack(TROUTINEManager *ptRTMgr, uint16_t pack_no)
{
	int packsize = 0;
	struct icmp *icmp;
	struct timeval *tval;
	icmp = (struct icmp*)ptRTMgr->sendpacket;
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_cksum = 0;
	icmp->icmp_seq = pack_no;
	icmp->icmp_id = ptRTMgr->pid;

	packsize = 8 + ptRTMgr->datalen;
	tval = (struct timeval *)icmp->icmp_data;
	gettimeofday(tval,NULL);

	icmp->icmp_cksum =  cal_chksum((unsigned short *)icmp, packsize);
	return packsize;
}

void send_packet(TROUTINEManager *ptRTMgr)
{
	int packetsize = 0;
	if(ptRTMgr->nCurSend < MAX_NO_PACKETS)
	{
		ptRTMgr->nCurSend++;
		ptRTMgr->usSendSeq++;
		packetsize = icmp_echo_pack(ptRTMgr, ptRTMgr->usSendSeq);

		int iSendbytes = 0;

		if ( (iSendbytes = sendto(ptRTMgr->sockfd,
				ptRTMgr->sendpacket,
				packetsize,
				0,
				ptRTMgr->tDestAddrInfo.ai_addr,
				ptRTMgr->tDestAddrInfo.ai_addrlen)) < 0 )
		{
			printf("%s-%d sendto error (%d %s)\n", __FUNCTION__, __LINE__,
					errno, strerror(errno));
			RoutineMgr_SetStatus(ptRTMgr, ERTMgrStatus_Fail_SocketError);
		}
		else if (iSendbytes != packetsize)
		{
			printf("%s-%d iSendbytes %d != packetsize %d ======\n", __FUNCTION__, __LINE__,
					iSendbytes, packetsize);
			RoutineMgr_SetStatus(ptRTMgr, ERTMgrStatus_Fail_SocketError);
		}
		else
		{
			ptRTMgr->iLastSendICMPEchoIndex = ptRTMgr->usSendSeq;
			printf("%s-%d iSendbytes %d \n", __FUNCTION__, __LINE__, iSendbytes);
			RoutineMgr_SetStatus(ptRTMgr, ERTMgrStatus_EchoRequest_Sent);
		}
	}
}

void recv_packet(TROUTINEManager *ptRTMgr)
{
	int iRecvBytes = 0;

	memset(&ptRTMgr->tFromAddr, 0, sizeof(ptRTMgr->tFromAddr));
	memset(ptRTMgr->recvpacket, 0, sizeof(ptRTMgr->recvpacket));

	socklen_t tlen = sizeof(ptRTMgr->tFromAddr);
	if( (iRecvBytes = recvfrom(ptRTMgr->sockfd, ptRTMgr->recvpacket, sizeof(ptRTMgr->recvpacket), 0,
			(struct sockaddr *)&ptRTMgr->tFromAddr, &tlen)) < 0 )
	{
		if (errno == EAGAIN)
		{
			printf("%s-%d EAGAIN (%d %s)\n", __FUNCTION__, __LINE__, errno, strerror(errno));
			return;
		}
		else
		{
			printf("%s-%d recvfrom error\n", __FUNCTION__, __LINE__);
			RoutineMgr_SetStatus(ptRTMgr, ERTMgrStatus_Fail_SocketError);
		}
	}
	else if (iRecvBytes == 0)
	{
		printf("%s-%d Connection closed\n", __FUNCTION__, __LINE__);
		RoutineMgr_SetStatus(ptRTMgr, ERTMgrStatus_Fail_SocketError);
	}
	else
	{
		printf("%s-%d iRecvBytes=%d\n", __FUNCTION__, __LINE__, iRecvBytes);
		gettimeofday(&tvrecv,NULL);
		icmp_unpack(ptRTMgr, ptRTMgr->recvpacket, iRecvBytes);
	}
}

int checkICMPReplyIsValid(TROUTINEManager *ptRTMgr, struct icmp *icmp)
{
	if( (icmp->icmp_type == ICMP_ECHOREPLY) &&
			(ptRTMgr->pid == icmp->icmp_id) )
	{
		if (ptRTMgr->usSendSeq >= icmp->icmp_seq &&
				(ptRTMgr->usSendSeq - icmp->icmp_seq <= ptRTMgr->iNumberofSendPackets) )
		{
			return S_OK;
		}
		else if (ptRTMgr->usSendSeq < icmp->icmp_seq &&
				(ptRTMgr->usSendSeq + (0xFFFF - icmp->icmp_seq)) <= ptRTMgr->iNumberofSendPackets )
		{
			/* uint16_t rollover */
			return S_OK;
		}
		else
		{
			printf("%s-%d received icmp echo reply seq %d is too old !!!\n", __FUNCTION__, __LINE__, icmp->icmp_seq);
			return S_FAIL;
		}
	}
	else if (icmp->icmp_type == ICMP_DEST_UNREACH)
	{
		char acUnreachReason[32] = {0};
		switch (icmp->icmp_code)
		{
		case ICMP_NET_UNREACH:
			snprintf(acUnreachReason, sizeof(acUnreachReason), "Network Unreachable");
			break;
		case ICMP_HOST_UNREACH:
			snprintf(acUnreachReason, sizeof(acUnreachReason), "Host Unreachable");
			break;
		case ICMP_PROT_UNREACH:
			snprintf(acUnreachReason, sizeof(acUnreachReason), "Protocol Unreachable");
			break;
		case ICMP_PORT_UNREACH:
			snprintf(acUnreachReason, sizeof(acUnreachReason), "Port Unreachable");
			break;
		default:
			snprintf(acUnreachReason, sizeof(acUnreachReason), "ICMP CODE=%d", icmp->icmp_code);
			break;
		}
		printf("%s-%d received ICMP Dest. Unreachable (%s)\n", __FUNCTION__, __LINE__, acUnreachReason);
		return 2; // other type
	}
	else
	{
		printf("%s-%d received other icmp msg (type=%d code=%d id=%d) \n", __FUNCTION__, __LINE__,
				icmp->icmp_type, icmp->icmp_code, icmp->icmp_id);
		return 3; // other type
	}
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	struct sockaddr_in *ptSockaddr = NULL;
	struct sockaddr_in6 *ptSockaddr6 = NULL;

	switch (sa->sa_family)
	{
	case AF_INET:
		ptSockaddr = (struct sockaddr_in *)&sa;
		return &(ptSockaddr->sin_addr);
		break;
	case AF_INET6:
		ptSockaddr6 = (struct sockaddr_in6 *)&sa;
		return &(ptSockaddr6->sin6_addr);
		break;
	default:
		printf("%s-%d UNKNOWN sa_family %d!!!!\n", __FUNCTION__, __LINE__, sa->sa_family);
		return NULL;
	}
}

int icmp_unpack(TROUTINEManager *ptRTMgr, char *buf,int len)
{
	// TODO: ICMPv6 version
	int iphdrlen;
	struct ip *ip;
	struct icmp *icmp;
	struct timeval *tvsend;
	double rtt;

	ip = (struct ip *)buf;
	iphdrlen = ip->ip_hl << 2;
	icmp = (struct icmp *)(buf + iphdrlen);
	len -= iphdrlen;
	if(len < 8)
	{
		printf("ICMP packet\'s length is less than 8\n");
		return -1;
	}

	if( checkICMPReplyIsValid(ptRTMgr, icmp) == S_OK )
	{
		// received desired ICMP Echo Reply msg
		ptRTMgr->nCurReceived++;
		ptRTMgr->iLastRecvICMPEchoIndex = icmp->icmp_seq;
		OSTime_GetTimer(&ptRTMgr->dwLastRecvTimeSec, NULL);
		RoutineMgr_SetStatus(ptRTMgr, ERTMgrStatus_EchoReply_Received);

		tvsend = (struct timeval *)icmp->icmp_data;
		tv_sub(&tvrecv,tvsend);

		rtt = tvrecv.tv_sec*1000 + tvrecv.tv_usec/1000;
		ptRTMgr->temp_rtt[ptRTMgr->nCurReceived] = rtt;
		ptRTMgr->all_time += rtt;

		char acFromAddr[INET6_ADDRSTRLEN] = {0};
		void *pFromAddr = NULL;
		if ( (pFromAddr = get_in_addr((struct sockaddr *)&ptRTMgr->tFromAddr)) != NULL )
		{
			inet_ntop(ptRTMgr->tFromAddr.ss_family, pFromAddr, acFromAddr, sizeof(acFromAddr));
			printf("%s-%d %d bytes from %s: icmp_seq=%u ttl=%d time=%.1f ms\n",
					__FUNCTION__, __LINE__,
					len,
					acFromAddr,
					icmp->icmp_seq,
					ip->ip_ttl,
					rtt);
		}
		else
		{
			printf("%s-%d convert From Address failed!!\n", __FUNCTION__, __LINE__);
		}
	}
	else
	{
		return -1;
	}

	return 0;
}


void tv_sub(struct timeval *recvtime,struct timeval *sendtime)
{
	long sec = recvtime->tv_sec - sendtime->tv_sec;
	long usec = recvtime->tv_usec - sendtime->tv_usec;

	if(usec >= 0)
	{
		recvtime->tv_sec = sec;
		recvtime->tv_usec = usec;
	}
	else
	{
		recvtime->tv_sec = sec - 1;
		recvtime->tv_usec = -usec;
	}
}

int timeSec2MSec_sub(DWORD dwStartTime, DWORD dwEndTime)
{

	int iDiff = 0;

	if (dwEndTime >= dwStartTime)
	{
		iDiff = (dwEndTime - dwStartTime) * 1000;
	}
	else
	{
		iDiff = -1;
	}

	return iDiff;
}

void icmp_ping_test(TROUTINEManager *ptRTMgr)
{
	if (!ptRTMgr)
	{
		return;
	}

	int iTest = 0;
	for (iTest = 0; iTest < ptRTMgr->iNumberofSendPackets; iTest++)
	{
		send_packet(ptRTMgr);
		recv_packet(ptRTMgr);
	}

	statistics(ptRTMgr);

}

void icmp_ping_sendout(TROUTINEManager *ptRTMgr)
{
	if (!ptRTMgr)
	{
		return;
	}

	int iSendNum = 0;
	for (iSendNum = 0; iSendNum < ptRTMgr->iNumberofSendPackets; iSendNum++)
	{
		send_packet(ptRTMgr);
	}
}

SCODE RoutineMgr_checkOptionisValid(TROUTINEManagerOption *ptRTMgrOpt)
{
	SCODE sReturn = S_OK;

	if ( (ptRTMgrOpt->iRoutineInterval < MIN_ROUTINE_INTERVAL) ||
			(ptRTMgrOpt->iRoutineInterval > MAX_ROUTINE_INTERVAL) )
	{
		RoutineMgr_LOG(LOG_ERR, "%s Routine interval %d is OUT OF RANGE (%d - %d), use default value %d !!\n",
				__FUNCTION__,
				ptRTMgrOpt->iRoutineInterval,
				MIN_ROUTINE_INTERVAL,
				MAX_ROUTINE_INTERVAL,
				DEFAULT_ROUTINE_INTERVAL);

		ptRTMgrOpt->iRoutineInterval = DEFAULT_ROUTINE_INTERVAL;
		sReturn = S_FAIL;
	}

	if ( (ptRTMgrOpt->iRecvTimeout < MIN_RECV_PING_TIMEOUT) ||
			(ptRTMgrOpt->iRecvTimeout > MAX_RECV_PING_TIMEOUT) )
	{
		RoutineMgr_LOG(LOG_ERR, "%s Receive PING Timeout %d is OUT OF RANGE (%d - %d), use default value %d !! \n",
				__FUNCTION__,
				ptRTMgrOpt->iRecvTimeout,
				MIN_RECV_PING_TIMEOUT,
				MAX_RECV_PING_TIMEOUT,
				DEFAULT_RECV_PING_TIMEOUT);

		ptRTMgrOpt->iRecvTimeout = DEFAULT_RECV_PING_TIMEOUT;
		sReturn = S_FAIL;
	}

	if ( ptRTMgrOpt->iRecvTimeout > ptRTMgrOpt->iRoutineInterval )
	{
		ptRTMgrOpt->iRecvTimeout = ptRTMgrOpt->iRoutineInterval - 500;

		RoutineMgr_LOG(LOG_ERR, "%s Receive PING Timeout CANNOT larger than Routine interval, set value to %d !!\n",
				__FUNCTION__, ptRTMgrOpt->iRecvTimeout);

		sReturn = S_FAIL;
	}

	if ( (ptRTMgrOpt->iNumberofSendPackets < MIN_SEND_PING_NUMBER) ||
			(ptRTMgrOpt->iNumberofSendPackets > MAX_SEND_PING_NUMBER) )
	{
		RoutineMgr_LOG(LOG_ERR, "%s Number of Send Packets %d is OUT OF RANGE (%d - %d), use default value %d !! \n",
				__FUNCTION__,
				ptRTMgrOpt->iNumberofSendPackets,
				MIN_SEND_PING_NUMBER,
				MAX_SEND_PING_NUMBER,
				DEFAULT_SEND_PING_NUMBER);

		ptRTMgrOpt->iNumberofSendPackets = DEFAULT_SEND_PING_NUMBER;
		sReturn = S_FAIL;
	}

	return sReturn;
}

HANDLE RoutineMgr_Init(TROUTINEManagerOption *ptRTMgrOpt)
{
	if (!ptRTMgrOpt)
	{
		return NULL;
	}

	TROUTINEManager *ptRTMgr = (TROUTINEManager *)calloc(sizeof(TROUTINEManager), 1);

	snprintf(ptRTMgr->acDstIPaddress, sizeof(ptRTMgr->acDstIPaddress), "%s", ptRTMgrOpt->acDstIPaddress);
	ptRTMgr->iRecvTimeout = ptRTMgrOpt->iRecvTimeout;
	ptRTMgr->iRoutineInterval = ptRTMgrOpt->iRoutineInterval;
	ptRTMgr->iNumberofSendPackets = ptRTMgrOpt->iNumberofSendPackets;

	ptRTMgr->datalen = 56;
	ptRTMgr->pid = getpid();

	struct addrinfo hint;
	memset(&hint, 0, sizeof(hint));
	hint.ai_family = AF_UNSPEC;
	hint.ai_socktype = SOCK_RAW;
	hint.ai_protocol = IPPROTO_ICMP;
	hint.ai_flags |= AI_NUMERICHOST;

	struct addrinfo *resultAddress;
	int gai_error;
	gai_error = getaddrinfo(ptRTMgr->acDstIPaddress, NULL, &hint, &resultAddress);
	if (gai_error != 0)
	{
		printf("%s-%d getaddrinfo: %s\n", __FUNCTION__, __LINE__, gai_strerror(gai_error));
		return NULL;
	}

	ptRTMgr->sockfd = socket(resultAddress->ai_family,
			resultAddress->ai_socktype,
			resultAddress->ai_protocol);

	if (ptRTMgr->sockfd <= 0)
	{
		printf("%s-%d socket() error\n", __FUNCTION__, __LINE__);
		return NULL;
	}

	int size = 50 * 1024;
	setsockopt(ptRTMgr->sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

	if (fcntl(ptRTMgr->sockfd, F_SETFL, O_NONBLOCK) == -1)
	{
		printf("%s-%d set nonblock error\n", __FUNCTION__, __LINE__);
		return NULL;
	}

	memcpy(&ptRTMgr->tDestAddrInfo, resultAddress, sizeof(struct addrinfo));

	ptRTMgr->eCurrRTMgrStatus = ptRTMgr->eLastRTMgrStatus = ERTMgrStatus_Initial;
	ptRTMgr->bRoutineStart = TRUE;

	RoutineMgr_LOG(LOG_ERR, "%s Initial ICMP Ping Routine to check reachability for %s\n", __func__, ptRTMgr->acDstIPaddress);
	printf("%s RoutineInterval=%d RecvTimeout=%d nSendPackets=%d\n", __func__,
			ptRTMgr->iRoutineInterval,
			ptRTMgr->iRecvTimeout,
			ptRTMgr->iNumberofSendPackets);

	return (HANDLE) ptRTMgr;
}

SCODE RoutineMgr_Close(HANDLE *phRTMgrHandle)
{
	if (!*phRTMgrHandle)
	{
		return S_FAIL;
	}

	TROUTINEManager *ptRTMgr = (TROUTINEManager *) *phRTMgrHandle;

	printf("%s-%d STOP ICMP Ping Routine for %s\n", __FUNCTION__, __LINE__, ptRTMgr->acDstIPaddress);
	close(ptRTMgr->sockfd);
	free(ptRTMgr);

	*phRTMgrHandle = NULL;

	return S_OK;
}

SCODE RoutineMgr_SelectAddSockets(HANDLE hRTMgrHandle, fd_set *pReadSet, int *piMaxFd)
{
	if (!hRTMgrHandle)
	{
		return S_FAIL;
	}

	TROUTINEManager *ptRTMgr = (TROUTINEManager *) hRTMgrHandle;

	if(ptRTMgr->sockfd > 0)
	{
		FD_SET(ptRTMgr->sockfd, pReadSet);
	}

	if (*piMaxFd < ptRTMgr->sockfd)
	{
		*piMaxFd = ptRTMgr->sockfd;
	}

	return S_OK;
}

int RoutineMgr_DetectRoutine(HANDLE hRTMgrHandle, fd_set *pReadSet)
{
	//printf("%s-%d <<<<<<<<<<<<<< \n", __FUNCTION__, __LINE__);
	if (!hRTMgrHandle)
	{
		return FALSE;
	}

	TROUTINEManager *ptRTMgr = (TROUTINEManager *) hRTMgrHandle;

	if (ptRTMgr->bRoutineStart == FALSE)
	{
		return FALSE;
	}

	if (FD_ISSET(ptRTMgr->sockfd, pReadSet))
	{
		recv_packet(ptRTMgr);
		printf("%s-%d >>>>>>>>>>>>>> 111 recv state\n", __FUNCTION__, __LINE__);
		dumpRTMgrStatus(ptRTMgr);
		return ptRTMgr->bStatusChanged;
	}

	DWORD dwCurTimeSec = 0;
	OSTime_GetTimer(&dwCurTimeSec, NULL);

	if ( ptRTMgr->dwLastSendTimeSec > 0 &&
			ptRTMgr->nCurSend > 0 &&
			timeSec2MSec_sub(ptRTMgr->dwLastSendTimeSec, dwCurTimeSec) >= ptRTMgr->iRecvTimeout )
	{
		statistics(ptRTMgr);
		statistics_reset(ptRTMgr);
		printf("%s-%d >>>>>>>>>>>>>> 222 statistic state\n", __FUNCTION__, __LINE__);
		dumpRTMgrStatus(ptRTMgr);
		return ptRTMgr->bStatusChanged;
	}

	if ( ptRTMgr->dwLastSendTimeSec == 0 ||
			((ptRTMgr->dwLastSendTimeSec > 0) &&
					timeSec2MSec_sub(ptRTMgr->dwLastSendTimeSec, dwCurTimeSec) >= ptRTMgr->iRoutineInterval) )
	{
		ptRTMgr->dwLastSendTimeSec = dwCurTimeSec;
		icmp_ping_sendout(ptRTMgr);
		printf("%s-%d >>>>>>>>>>>>>> 333 send state\n", __FUNCTION__, __LINE__);
		dumpRTMgrStatus(ptRTMgr);
		return ptRTMgr->bStatusChanged;
	}

	return FALSE;
}

SCODE RoutineMgr_SetStatus(TROUTINEManager *ptRTMgr, EROUTINEManagerStatus eStatus)
{
	if (!ptRTMgr)
	{
		return S_FAIL;
	}

	if (ptRTMgr->eCurrRTMgrStatus != eStatus)
	{
		ptRTMgr->eLastRTMgrStatus = ptRTMgr->eCurrRTMgrStatus;
		ptRTMgr->eCurrRTMgrStatus = eStatus;
		ptRTMgr->bStatusChanged = TRUE;
	}

	return 0;
}

int RoutineMgr_GetStatus(HANDLE hRTMgrHandle)
{
	if (!hRTMgrHandle)
	{
		return S_FAIL;
	}

	TROUTINEManager *ptRTMgr = (TROUTINEManager *) hRTMgrHandle;

	ptRTMgr->bStatusChanged = FALSE;

	return ptRTMgr->eCurrRTMgrStatus;

}
