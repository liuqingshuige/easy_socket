#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include "easy_socket.h"

static char *log_time(void)
{
    static char ctime_buf[128] = {0};
    struct tm* t;
    struct timeval tv;
    gettimeofday(&tv, NULL);

    t = localtime(&tv.tv_sec);
    snprintf(ctime_buf, sizeof(ctime_buf), "%04d-%02d-%02d %02d:%02d:%02d.%03d", 
        t->tm_year+1900,
        t->tm_mon+1,
        t->tm_mday,
        t->tm_hour,
        t->tm_min,
        t->tm_sec,
        (int)tv.tv_usec/1000);
    return ctime_buf;
}
#define LOG(fmt, ...) printf("[%s %s:%d] " fmt, log_time(), __FUNCTION__, __LINE__, ##__VA_ARGS__)

// 获取值
static int XmlGetValueA(const char *pstrXml, const char *pstrKey, char *pstrValue, int maxValueLength)
{
	char key[128];
	snprintf(key, sizeof(key), "<%s>", pstrKey);
	char *pstrStar = strstr(pstrXml, key);
	if (pstrStar == NULL)
		return 0;
	pstrStar += strlen(key);

	snprintf(key, sizeof(key), "</%s>", pstrKey);
	char *pstrEnd = strstr(pstrStar, key);
	if (pstrEnd == NULL)
		return 0;

	if (maxValueLength < pstrEnd - pstrStar + 1)
		return 0;

	strncpy(pstrValue, pstrStar, pstrEnd - pstrStar);
	pstrValue[pstrEnd - pstrStar] = 0;

	return 1;
}

static inline int make_thread(void *(*pfn)(void *), void *arg, int detach, pthread_t *thid)
{
    int err = 0;
    pthread_t tid;
    pthread_t *ptid = &tid;
    pthread_attr_t attr;

    if (thid)
        ptid = thid;

    err = pthread_attr_init(&attr);
    if (err != 0)
        return err;

    if (detach)
        err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    if (err == 0)
        err = pthread_create(ptid, &attr, pfn, arg);

    pthread_attr_destroy(&attr);
    return err;
}

static inline int make_thread_detached(void *(*pfn)(void *), void *arg)
{
    return make_thread(pfn, arg, 1, 0);
}

static void *pfn1(void *param)
{
	int sockfd = CreateUdpSocket4();
	LOG("sockfd: %d\n", sockfd);
	
	// 组播组
	struct sockaddr_in dest_addr;
	dest_addr.sin_port = htons(30008);
	dest_addr.sin_addr.s_addr = inet_addr("239.2.3.9");
	dest_addr.sin_family = AF_INET;
	
	const char *fmt = "<? xml version=\"1.0\" encoding=\"GB2312\" ?>"
		"<XML_MSG_BODY>"
		"<XML_MSG_TYPE>alarm</XML_MSG_TYPE>"
		"<XML_MSG_EVENT>pressed_alarm</XML_MSG_EVENT>"
		"<XML_ENDPORT_IP>192.168.8.10</XML_ENDPORT_IP>"
		"<XML_TIME>%s</XML_TIME>"
		"</XML_MSG_BODY>";
	char msg[512] = {0};
	int ret = -1;
	
    while (1)
    {
		snprintf(msg, sizeof msg, fmt, log_time());
		ret = UdpSendSocket(sockfd, (struct sockaddr *)&dest_addr, sizeof(dest_addr), msg,  strlen(msg));
		LOG("send ret: %d\n", ret);
		sleep(5);
    }

    return 0;
}

int main(int argc, char **argv)
{
	int sockfd = UdpListenSocket("0.0.0.0", "30008");
	if (sockfd < 0)
	{
		return -1;
	}
	
	char temp[64] = {0};
	const char *result = GetLocalIpv4(temp, 64);
	LOG("localip: %s\n", result);
	
	result = GetLocalIpv6(temp, 64);
	LOG("localip6: %s\n", result);
	
	char dest[32][64];
	int i = 0;
	int cnt = GetLocalNetcard(dest, 32);
	LOG("card cnt: %d\n", cnt);
	for (i=0; i<cnt; i++)
	{
		LOG("card %d: %s\n", i, dest[i]);
		GetMacAddr2(dest[i], temp, 64, ':');
		LOG("MAC: %s\n", temp);
	}
	
	char value[128];
	char msg[1024] = {0};
	struct sockaddr_storage addr;
	
	// 加入组播组
	struct sockaddr_in grp;
	grp.sin_port = htons(30008);
	grp.sin_addr.s_addr = inet_addr("239.2.3.9");
	grp.sin_family = AF_INET;
	i = UdpJoinMcast(sockfd, (struct sockaddr *)&grp, sizeof(grp), "ens33", 0);
	LOG("join mcast ret: %d\n", i);
	
	make_thread_detached(pfn1, 0);

	while (1)
	{
		// 等待接收消息
		int ret = UdpRecvSocket(sockfd, msg, sizeof(msg), 5000, &addr);
		
		if (ret > 0)
		{
			char ipstr[128] = {0};
			const char *ptr = inet_ntop3((struct sockaddr *)&addr, ipstr, 127);
			LOG("recv addr: %s\n", ipstr);
			LOG("recv ret: %d\nmsg: %s\n\n", ret, msg);
			
			// 取出事件名称
			int ret = XmlGetValueA(msg, "XML_MSG_TYPE", value, 127);
			if (ret == 1 && !strcmp(value, "alarm")) // 分机报警事件
			{
/*
<?xml version=\"1.0\" encoding=\"GB2312\" ?>
<XML_MSG_BODY>
<XML_MSG_TYPE>alarm</XML_MSG_TYPE>
<XML_MSG_EVENT>pressed_alarm</XML_MSG_EVENT>
<XML_ENDPORT_IP>192.168.8.10</XML_ENDPORT_IP>
<XML_TIME>2016-08-16 18:45:30</XML_TIME>
</XML_MSG_BODY>
*/
				// 取出报警类型
				ret = XmlGetValueA(msg, "XML_MSG_EVENT", value, 127);
				LOG("alarm type: %s\n", ret ? value : "-");
				
				// 取出报警分机IP
				ret = XmlGetValueA(msg, "XML_ENDPORT_IP", value, 127);
				LOG("XML_ENDPORT_IP: %s\n", ret ? value : "-");
				
				// 取出报警时间
				ret = XmlGetValueA(msg, "XML_TIME", value, 127);
				LOG("XML_TIME: %s\n\n", ret ? value : "-");
			}
			else if (ret == 1 && !strcmp(value, "call")) // 呼叫事件
			{
/*
<?xml version="1.0" encoding="GB2312" ?>
<XML_MSG_BODY>
<XML_MSG_TYPE>call</XML_MSG_TYPE>
<XML_MSG_EVENT>endpoint-call-host</XML_MSG_EVENT>
<XML_HOST_IP>192.168.8.8</XML_HOST_IP>
<XML_ENDPORT_IP>192.168.8.10</XML_ENDPORT_IP>
<XML_TIME>2016-08-16 18:45:30</XML_TIME>
</XML_MSG_BODY>
*/
				// 取出呼叫类型
				ret = XmlGetValueA(msg, "XML_MSG_EVENT", value, 127);
				LOG("call type: %s\n", ret ? value : "-");

				// 取出主机IP
				ret = XmlGetValueA(msg, "XML_HOST_IP", value, 127);
				LOG("XML_HOST_IP: %s\n", ret ? value : "-");

				// 取出分机IP
				ret = XmlGetValueA(msg, "XML_ENDPORT_IP", value, 127);
				LOG("XML_ENDPORT_IP: %s\n", ret ? value : "-");
				
				// 取出事件时间
				ret = XmlGetValueA(msg, "XML_TIME", value, 127);
				LOG("XML_TIME: %s\n", ret ? value : "-");
			}
			else
			{
				LOG("unknown event\n");
			}
		}
	}

	CloseSocket(sockfd);
	return 0;
}

