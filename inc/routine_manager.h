/* 
 *  File name          :   routine_manager.h
 *  File description   :   Manager for Always Unicast routine
 *  Author             :   Chenhsun Chai
 *  Created at         :   2019/7/17
 *
 */

#ifndef RTSPSERVER_SRC_ROUTINE_MANAGER_H_
#define RTSPSERVER_SRC_ROUTINE_MANAGER_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <setjmp.h>

#include "typedef.h"
#include "osisolate.h"

#define DEFAULT_ROUTINE_INTERVAL 120000 // ms
#define DEFAULT_RECV_PING_TIMEOUT 5000 // ms
#define DEFAULT_SEND_PING_NUMBER 5 // 5 pings every routine

// parameter range
#define MIN_ROUTINE_INTERVAL 30000 // 30 secs
#define MAX_ROUTINE_INTERVAL 3600000 // 1 hr

#define MIN_RECV_PING_TIMEOUT 1000 // 1 sec
#define MAX_RECV_PING_TIMEOUT 60000 // 1 min

#define MIN_SEND_PING_NUMBER 1
#define MAX_SEND_PING_NUMBER 10
// parameter range

#define ROUTINE_MANAGER_XPATH_DESTIP			"network_rtsp_s1_multicast_videoipaddress"
#define ROUTINE_MANAGER_XPATH_INTERVAL			"routinemanager_interval"
#define ROUTINE_MANAGER_XPATH_TIMEOUT			"routinemanager_recvtimeout"
#define ROUTINE_MANAGER_XPATH_OUTSENDNUMBER		"routinemanager_outsendnumber"
#define ROUTINE_MANAGER_XPATH_STATUS			"routinemanager_status"

#define PACKET_SIZE 128
#define MAX_NO_PACKETS  (MAX_SEND_PING_NUMBER + 5)

typedef enum
{
	ERTMgrStatus_Stoped					= -3,
	ERTMgrStatus_Fail_NoResponse		= -2,
	ERTMgrStatus_Fail_SocketError 		= -1,
	ERTMgrStatus_Initial				=  0,
	ERTMgrStatus_EchoRequest_Sent		=  1,
	ERTMgrStatus_EchoReply_Received		=  2
} EROUTINEManagerStatus;

typedef struct _TROUTINEManagerOption
{
	char acDstIPaddress[INET6_ADDRSTRLEN];
	int iRecvTimeout; 			// ms, default = 5000: 5 secs
	int iRoutineInterval; 		// ms, default = 120000: 2 mins
	int iNumberofSendPackets; 	// default = 5: send 5 pings every routine
} TROUTINEManagerOption;


HANDLE RoutineMgr_Init(TROUTINEManagerOption *ptRTMgrOpt);
SCODE RoutineMgr_Close(HANDLE *phRTMgrHandle);
SCODE RoutineMgr_checkOptionisValid(TROUTINEManagerOption *ptRTMgrOpt);
SCODE RoutineMgr_SelectAddSockets(HANDLE hRTMgrHandle, fd_set *pReadSet, int *piMaxFd);
int RoutineMgr_DetectRoutine(HANDLE hRTMgrHandle, fd_set *pReadSet);
int RoutineMgr_GetStatus(HANDLE hRTMgrHandle);


#ifdef __cplusplus
}
#endif

#endif /* RTSPSERVER_SRC_ROUTINE_MANAGER_H_ */
