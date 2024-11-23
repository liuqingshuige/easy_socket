#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <ctype.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <net/if.h>

#include "easy_socket.h"

/*
 * 获取套接字地址族
 */
static int sockfd_to_family(int sockfd)
{
	struct sockaddr_storage ss;
	socklen_t len;

	len = sizeof(ss);
	if (getsockname(sockfd, (struct sockaddr *)&ss, &len) < 0)
		return -1;

	return ss.ss_family;
}

static int family_to_level(int family)
{
	int level = IPPROTO_IP;
	switch (family)
	{
	case AF_INET: level = IPPROTO_IP; break;
	case AF_INET6: level = IPPROTO_IPV6; break;
	}
	return level;
}

/*
 * 将网络字节序的IPv4地址转换为点分十进制格式
 * src：待转换的IP地址
 * dest：保存转换结果
 * size：dest长度，单位字节
 * return：成功返回指向dest的指针，失败返回NULL
 */
static const char *inet_ntop4(const unsigned char *src, char *dest, size_t size)
{
	const char *fmt = "%u.%u.%u.%u";
	char temp[20] = {0};
	int ret = snprintf(temp, sizeof(temp), fmt, src[0], src[1], src[2], src[3]);
	return (ret >= size) ? NULL : strcpy(dest, temp);
}

/*
 * 将网络字节序的IPv6地址（16byte，128bit）转换为x:x:x:x:x:x:x:x格式
 * src：待转换的IP地址
 * dest：保存转换结果
 * size：dest长度，单位字节
 * return：成功返回指向dest的指针，失败返回NULL
 */
static const char *inet_ntop6(const unsigned char *src, char *dest, size_t size)
{
	char *tp = 0;
	char tmp[128] = {0};
	struct
	{
		int base;
		int len;
	} best = {-1, 0}, cur = {-1, 0};
	unsigned int words[8];
	int i;

	// 将字节转换为字
	for (i=0; i<16; i+=2)
	{
		words[i/2] = (src[i] << 8) | (src[i+1]);
	}

	for (i=0; i<8; i++)
	{
		if (words[i] == 0)
		{
			if (cur.base == -1)
			{
				cur.base = i, cur.len = 1;
			}
			else
			{
				cur.len++;
			}
		}
		else
		{
			if (cur.base != -1)
			{
				if (best.base == -1 || cur.len > best.len)
				{
					best = cur;
				}
				cur.base = -1;
			}
		}
	}

	if (cur.base != -1)
	{
		if (best.base == -1 || cur.len > best.len)
		{
			best = cur;
		}
	}

	if (best.base != -1 && best.len < 2)
	{
		best.base = -1;
	}

	tp = tmp;
	for (i=0; i<8; i++)
	{
		if (best.base != -1 && i >= best.base && i < (best.base + best.len))
		{
			if (i == best.base)
				*tp++ = ':';
			continue;
		}

		if (i != 0)
		{
			*tp++ = ':';
		}

		if (i == 6 && best.base == 0 && (best.len == 6 || (best.len == 5 && words[5] == 0xFFFF)))
		{
			if (!inet_ntop4(src + 12, tp, sizeof(tmp) - (tp - tmp)))
				return NULL;
			tp += strlen(tp);
			break;
		}

		tp += sprintf(tp, "%x", words[i]);
	}

	if (best.base != -1 && (best.base + best.len) == 8)
	{
		*tp++ = ':';
	}
	*tp++ = '\0';

	return ((size_t)(tp - tmp) >= size) ? NULL : strcpy(dest, tmp);
}

const char *inet_ntop2(int family, const void *src, char *dst, size_t size)
{
	switch (family)
	{
		case AF_INET: return inet_ntop4((const unsigned char *)src, dst, size);
		case AF_INET6: return inet_ntop6((const unsigned char *)src, dst, size);
	}
	return NULL;
}

const char *inet_ntop3(const struct sockaddr *sa, char *dst, size_t size)
{
	switch (sa->sa_family)
	{
		case AF_INET:
		{
			struct sockaddr_in *sin = (struct sockaddr_in *)sa;
			return inet_ntop4((const unsigned char *)&sin->sin_addr.s_addr, dst, size);
		}

		case AF_INET6:
		{
			struct sockaddr_in6 *sin = (struct sockaddr_in6 *)sa;
			return inet_ntop6((const unsigned char *)&sin->sin6_addr, dst, size);
		}
	}
	return NULL;
}

/*
 * 域名转IP地址
 * host：主机名/域名/IP地址
 * serv：端口号/服务名（如NTP、FTP、SIP等）
 * addr：保存返回的地址信息数组
 * count：addr数组大小
 * return：num of actual addr on success，-1 on error
 */
int DomainName2Addr(const char *host, const char *serv, struct sockaddr_storage *addr, int count)
{
	struct addrinfo hints, *result, *tmp;
	int ret = 0, n = 0, idx = 0, exist = 0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;

	ret = getaddrinfo(host, serv, &hints, &result);
	if (ret != 0)
		return -1;

	tmp = result;
	while (tmp)
	{
		exist = 0;
		for (idx=0; idx<n; idx++) // 去重
		{
			if (addr[idx].ss_family == tmp->ai_family)
			{
				if (0 == memcmp(&addr[idx], tmp->ai_addr, tmp->ai_addrlen))
				{
					exist = 1;
					break;
				}
			}
		}

		if (exist)
		{
			tmp = tmp->ai_next;
			continue;
		}

		memcpy(&addr[n++], tmp->ai_addr, tmp->ai_addrlen);
		if (n >= count)
			break;
		tmp = tmp->ai_next;
	}
    freeaddrinfo(result); /* No longer needed */
    return n;
}

/*
 * 获取本机IPv4地址
 * dest：保存点分十进制IP地址
 * size：dest长度，单位字节
 * return：成功返回指向dest的指针，失败返回NULL
 */
const char *GetLocalIpv4(char *dest, size_t size)
{
	struct ifaddrs *ifaddr, *ifa;
	int family;
	const char *ptr = NULL;

	if (getifaddrs(&ifaddr) == -1)
	{
		return NULL;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
		if (ifa->ifa_addr == NULL)
			continue;

		family = ifa->ifa_addr->sa_family;
		if (family == AF_INET && strcmp("lo", ifa->ifa_name))
		{
			struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
			ptr = inet_ntop4((unsigned char *)&addr->sin_addr, dest, size);
			break;
		}
	}

	freeifaddrs(ifaddr);
	return ptr;
}

/*
 * 获取本机IPv6地址
 * dest：保存IP地址
 * size：dest长度，单位字节
 * return：成功返回指向dest的指针，失败返回NULL
 */
const char *GetLocalIpv6(char *dest, size_t size)
{
	struct ifaddrs *ifaddr, *ifa;
	int family;
	const char *ptr = NULL;

	if (getifaddrs(&ifaddr) == -1)
	{
		return NULL;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
		if (ifa->ifa_addr == NULL)
			continue;
		
		family = ifa->ifa_addr->sa_family;
		if (family == AF_INET6 && strcmp("lo", ifa->ifa_name))
		{
			struct sockaddr_in6 *addr = (struct sockaddr_in6 *)ifa->ifa_addr;
			ptr = inet_ntop6((unsigned char *)&addr->sin6_addr, dest, size);
			break;
		}
	}

	freeifaddrs(ifaddr);
	return ptr;
}

/*
 * 获取本机网卡名称
 * dest：保存网卡名称数组
 * size：dest数组元素个数
 * return：成功返回网卡数量，失败返回-1
 */
int GetLocalNetcard(char dest[][64], size_t size)
{
	struct ifaddrs *ifaddr, *ifa;
	int i, exist = 0, n = 0;

	if (getifaddrs(&ifaddr) == -1)
	{
		return -1;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
		if (ifa->ifa_addr == NULL)
			continue;

		exist = 0;
		for (i=0; i<n; i++) // 去重
		{
			if (!strcmp(dest[i], ifa->ifa_name))
			{
				exist = 1;
				break;
			}
		}
		if (exist)
			continue;

		if (n < size)
			strcpy(dest[n++], ifa->ifa_name);
	}

	freeifaddrs(ifaddr);
	return n;
}

/*
 * 获取本机指定网卡MAC地址
 * interface：网卡名称
 * mac：保存MAC地址
 * return：0 on success，-1 on fail
 */
int GetMacAddr(const char *interface, unsigned char mac[6])
{
	int sockfd = -1;
	struct ifreq ifr;
	int ret = -1;

	sockfd = CreateUdpSocket4();
	if (sockfd < 0)
		return -1;

	if (!interface)
		interface = "eth0";

	strncpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name));

	ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
	if (ret < 0)
	{
		CloseSocket(sockfd);
		return -1;
	}

	if (mac)
	{
		memcpy(mac, ifr.ifr_hwaddr.sa_data, sizeof(ifr.ifr_hwaddr.sa_data));
	}

	CloseSocket(sockfd);
	return 0;
}

/*
 * 获取本机指定网卡MAC地址并格式化
 * interface：网卡名称
 * buff：保存格式化后的MAC地址
 * size：buff长度，单位字节
 * separator：分隔符
 * return：0 on success，-1 on fail
 */
int GetMacAddr2(const char *interface, unsigned char *buff, size_t size, const char separator)
{
    char macStr[64] = {0};
    unsigned char mac[6] = {0};

    if (GetMacAddr(interface, mac) == -1)
		return -1;
	
    if (isprint(separator))
	{
        snprintf(macStr, sizeof(macStr), "%02x%c%02x%c%02x%c%02x%c%02x%c%02x",
			mac[0], separator, mac[1], separator, mac[2], separator,
			mac[3], separator, mac[4], separator, mac[5]);
	}
    else
	{
        snprintf(macStr, sizeof(macStr), "%02x%02x%02x%02x%02x%02x",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	}

    if (buff && size>=strlen(macStr))
        strcpy(buff, macStr);

	return 0;
}

/*
 * 创建套接字
 * family：AF_INET/AF_INET6/AF_UNIX(AF_LOCAL)/AF_PACKET
 * type：SOCK_STREAM/SOCK_DGRAM/SOCK_RAW/SOCK_PACKET
 * return：sockfd on success，-1 on fail
 */
int CreateSocket(int family, int type)
{
	int sockfd = socket(family, type | SOCK_CLOEXEC, 0);
	return sockfd;
}

/*
 * 关闭套接字
 * return：0 on success，-1 on fail
 */
int CloseSocket(int sockfd)
{
	return (sockfd != -1) ? close(sockfd) : -1;
}

/*
 * 创建一个TCP套接字
 * family：AF_INET/AF_INET6
 * return：sockfd on success, -1 on fail
 */
int CreateTcpSocket(int family)
{
	return CreateSocket(family, SOCK_STREAM);
}

/*
 * 创建一个IPv4的TCP套接字
 * return：sockfd on success, -1 on fail
 */
int CreateTcpSocket4(void)
{
	return CreateTcpSocket(AF_INET);
}

/*
 * 创建一个IPv6的TCP套接字
 * return：sockfd on success, -1 on fail
 */
int CreateTcpSocket6(void)
{
	return CreateTcpSocket(AF_INET6);
}

/*
 * 创建一个UDP套接字
 * return：sockfd on success, -1 on fail
 */
int CreateUdpSocket(int family)
{
	return CreateSocket(family, SOCK_DGRAM);
}

/*
 * 创建一个IPv4的UDP套接字
 * return：sockfd on success, -1 on fail
 */
int CreateUdpSocket4(void)
{
	return CreateUdpSocket(AF_INET);
}

/*
 * 创建一个IPv6的UDP套接字
 * return：sockfd on success, -1 on fail
 */
int CreateUdpSocket6(void)
{
	return CreateUdpSocket(AF_INET6);
}

/*
 * 套接字绑定IP地址和端口
 * sockfd：套接字句柄
 * sa：待绑定的地址
 * salen：sa大小
 * return：0 on success，-1 on fail
 */
int BindSocket(int sockfd, const struct sockaddr *sa, socklen_t salen)
{
	return bind(sockfd, sa, salen);
}

/*
 * 套接字绑定IPv4的IP地址和端口
 * sockfd：套接字句柄
 * ipaddr：待绑定的IPv4地址，格式如：ddd.ddd.ddd.ddd
 * port：待绑定的端口
 * return：0 on success，-1 on fail
 */
int BindSocket4(int sockfd, const char *ipaddr, unsigned short port)
{
	struct sockaddr_in addr = {0};

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = ipaddr ? inet_addr(ipaddr) : 0;

	return BindSocket(sockfd, (struct sockaddr *)&addr, sizeof(addr));
}

/*
 * 套接字绑定IPv6的IP地址和端口
 * sockfd：套接字句柄
 * ipv6addr：待绑定的IPv6地址，格式如：x:x:x:x:x:x:x:x/x:x:x:x:x:x:d.d.d.d，一般设置为"::"
 * port：待绑定的端口
 * return：0 on success，-1 on fail
 */
int BindSocket6(int sockfd, const char *ipv6addr, unsigned short port)
{
	struct sockaddr_in6 addr;
	memset(&addr, 0, sizeof(addr));

	int ret = inet_pton(AF_INET6, ipv6addr, &addr.sin6_addr);
	if (ret <= 0)
		return -1;

	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(port);
	//addr.sin6_scope_id = if_nametoindex("ens33");

	return BindSocket(sockfd, (struct sockaddr *)&addr, sizeof(addr));
}

/*
 * 在套接字上开启监听
 * sockfd：套接字句柄
 * backlog：套接字的未完成连接队列的最大长度
 * return：0 on success，-1 on fail
 */
int ListenSocket(int sockfd, int backlog)
{
	return listen(sockfd, backlog);
}

/*
 * 接收客户端连接
 * sockfd：套接字句柄
 * sa：保存客户端地址信息
 * len：作为输入时表示sa大小，作为输出时表示客户端地址实际大小
 * return：client fd on success，-1 on fail
 */
int AcceptSocket(int sockfd, struct sockaddr_storage *sa, socklen_t *len)
{
	int fd = -1;
	while (1)
	{
		fd = accept(sockfd, (struct sockaddr *)sa, len);
		if (fd == -1)
		{
			if (errno == EINTR)
				continue;
			else
				return -1;
		}
		break;
	}
	return fd;
}

/*
 * 非阻塞连接指定的服务地址
 * sockfd：套接字句柄
 * saptr：待连接的服务地址
 * salen：saptr大小
 * ms：超时时间
 * return：0 on success，-1 on fail
 */
int ConnectSocket(int sockfd, const struct sockaddr *saptr, socklen_t salen, unsigned int ms)
{
	int flags = -1, n = 0, error = 0;
	socklen_t len;
	fd_set rset, wset;
	struct timeval tval;

	error = GetSocketFlag(sockfd, &flags);
	if (error == -1)
		goto exit_;

	error = SetSocketFlag(sockfd, flags | O_NONBLOCK);
	if (error == -1)
		goto exit_;

	n = connect(sockfd, saptr, salen);
	if (n < 0)
	{
		if (errno != EINPROGRESS)
		{
			CloseSocket(sockfd);
			return -1;
		}
	}

	if (n == 0) // 连接成功了
		goto exit_;

	FD_ZERO(&rset);
	FD_SET(sockfd, &rset);
	wset = rset;

	tval.tv_sec = ms / 1000;
	tval.tv_usec = (ms % 1000) * 1000;

	n = select(sockfd+1, &rset, &wset, NULL, &tval);
	if (n == 0) // 超时
	{
		CloseSocket(sockfd);
		return -1;
	}

	if (FD_ISSET(sockfd, &rset) || FD_ISSET(sockfd, &wset))
	{
		len = sizeof(error);
		n = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
		if (n < 0)
		{
			CloseSocket(sockfd);
			return -1;
		}
	}

exit_:
	SetSocketFlag(sockfd, flags);
	if (error) /* connect failed, while error = 0 means connect success */
	{
		CloseSocket(sockfd);
		return -1;
	}
	return 0;
}

/*
 * TCP连接指定的主机
 * host：主机名、域名或者点分十进制IP地址、或者IPv6的16进制串
 * service：端口或者服务名如ftp、ntp等
 * timeout：超时时间，单位ms
 * return：sockfd on success，-1 on failed
 */
int TcpConnectSocket(const char *host, const char *service, unsigned int timeout)
{
	int ret = -1, n = 0;
	int sockfd = -1;
	struct sockaddr_storage addr[32]; /* guess should be enough */

	ret = DomainName2Addr(host, service, addr, 32);
	if (ret <= 0)
	{
		return -1;
	}

	for (n=0; n<ret; n++)
	{
		sockfd = CreateTcpSocket(addr[n].ss_family);
		if (sockfd < 0)
		{
			continue;
		}

		SetSocketBlock(sockfd, 0); // 设置非阻塞
		socklen_t salen = (addr[n].ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
		if (ConnectSocket(sockfd, (struct sockaddr *)&addr[n], salen, timeout) == 0)
		{
			break;
		}

		sockfd = -1; // 连接失败
	}
	return sockfd;
}

/*
 * 开启TCP监听，返回监听套接字
 * host：主机名、域名或者点分十进制IP地址、或者IPv6的16进制串
 * service：端口或者服务名如ftp、ntp等
 * backlo：套接字的未完成连接队列的最大长度
 * return：sockfd on success，-1 on failed
 */
int TcpListenSocket(const char *host, const char *service, int backlog)
{
	int ret = -1, n = 0;
	int sockfd = -1;
	struct sockaddr_storage addr[32]; /* guess should be enough */

	ret = DomainName2Addr(host, service, addr, 32);
	if (ret <= 0)
	{
		return -1;
	}

	for (n=0; n<ret; n++)
	{
		sockfd = CreateTcpSocket(addr[n].ss_family);
		if (sockfd < 0)
		{
			continue;
		}

		SetSocketBlock(sockfd, 0); // 设置非阻塞
		SetSocketReuseAddr(sockfd, 1);
		SetSocketReusePort(sockfd, 1);

		socklen_t salen = (addr[n].ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
		if (BindSocket(sockfd, (struct sockaddr *)&addr[n], salen) == 0)
		{
			if (ListenSocket(sockfd, backlog) == 0)
			{
				break;
			}
		}

		CloseSocket(sockfd);
		sockfd = -1; // 绑定失败
	}

	return sockfd;
}

/*
 * TCP读取数据
 * sockfd：套接字描述符
 * msg：保存数据的缓存
 * length：msg缓存大小，单位字节
 * timeout：超时时间(ms)
 * return：num of read bytes on success，-1 on failed
 */
int TcpRecvSocket(int sockfd, void *msg, size_t length, int timeout)
{
	int ret = 0;
	fd_set rset;
	struct timeval tv;

retry_:
	do
	{
		ret = recv(sockfd, msg, length, 0);
	} while (ret == -1 && errno == EINTR);
	
	if (ret == -1)
	{
		if (errno != EAGAIN)
		{
			return -1;
		}
		
		FD_ZERO(&rset);
		FD_SET(sockfd, &rset);
		
		tv.tv_sec = timeout / 1000;
		tv.tv_usec = (timeout % 1000) * 1000;
		do
		{
			ret = select(sockfd+1, &rset, NULL, NULL, &tv);
		} while (ret == -1 && errno == EINTR);
		
		if (ret == -1 || ret == 0)
			return -1;
		goto retry_;
	}
	
	return ret;
}

/*
 * TCP发送数据
 * sockfd：套接字描述符
 * msg：待发送的数据
 * length：msg数据大小，单位字节
 * timeout：超时时间(ms)
 * return：num of send on success，-1 on failed
 */
int TcpSendSocket(int sockfd, const void *msg, size_t length, int timeout)
{
    int ret;
    size_t pos;
    fd_set wset;
    struct timeval tv;
    char *pmsg = (char *)msg;

    for (pos=0; pos<length;)
    {
        do {
            ret = send(sockfd, pmsg + pos, length - pos, 0);
        } while (ret == -1 && errno == EINTR);

        if (ret == -1)
        {
            if (errno != EAGAIN)
            {
				return -1;
			}

            FD_ZERO(&wset);
            FD_SET(sockfd, &wset);

            tv.tv_sec = timeout / 1000;
            tv.tv_usec = (timeout % 1000) * 1000;

            do {
                ret = select(sockfd + 1, NULL, &wset, NULL, &tv); 
            } while (ret == -1 && errno == EINTR);

            if (ret == -1 || ret == 0)
            {
                return -1;
            }
        }
        pos += ret;
    }

    return pos;
}

/*
 * 开启UDP监听
 * host：主机名、域名或者点分十进制IP地址、或者IPv6的16进制串
 * servic：端口或者服务名如ftp、ntp等
 * return：sockfd on success，-1 on failed
 */
int UdpListenSocket(const char *host, const char *service)
{
	int ret = -1, n = 0;
	int sockfd = -1;
	struct sockaddr_storage addr[32]; /* guess should be enough */

	ret = DomainName2Addr(host, service, addr, 32);
	if (ret <= 0)
	{
		return -1;
	}

	for (n=0; n<ret; n++)
	{
		sockfd = CreateUdpSocket(addr[n].ss_family);
		if (sockfd < 0)
		{
			continue;
		}

		SetSocketBlock(sockfd, 0); // 非阻塞
		SetSocketReuseAddr(sockfd, 1);
		SetSocketReusePort(sockfd, 1);

		socklen_t salen = (addr[n].ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
		if (BindSocket(sockfd, (struct sockaddr *)&addr[n], salen) == 0)
		{
			break;
		}

		CloseSocket(sockfd);
		sockfd = -1; // 绑定失败
	}

	return sockfd;
}

/*
 * UDP读取数据
 * sockfd：套接字描述符
 * msg：保存数据的缓存
 * length：msg缓存大小，单位字节
 * timeout：超时时间(ms)
 * peer_addr：对端IP信息，可选
 * return：num of read bytes on success，-1 on failed
 */
int UdpRecvSocket(int sockfd, void *msg, size_t length, int timeout, struct sockaddr_storage *peer_addr)
{
	int ret = 0;
	fd_set rset;
	struct timeval tv;
	struct sockaddr_storage user_addr;
	unsigned int usize = sizeof(user_addr);

retry_:
	do
	{
		ret = recvfrom(sockfd, msg, length, 0, (struct sockaddr *)&user_addr, &usize);
	} while (ret == -1 && errno == EINTR);

	if (ret == -1)
	{
		if (errno != EAGAIN)
		{
			return -1;
		}

		FD_ZERO(&rset);
		FD_SET(sockfd, &rset);

		tv.tv_sec = timeout / 1000;
		tv.tv_usec = (timeout % 1000) * 1000;
		do
		{
			ret = select(sockfd+1, &rset, NULL, NULL, &tv);
		} while (ret == -1 && errno == EINTR);

		if (ret == -1 || ret == 0)
			return -1;
		goto retry_;
	}

	if (peer_addr)
		memcpy(peer_addr, &user_addr, sizeof(user_addr));

	return ret;
}

/*
 * UDP发送数据
 * sockfd：套接字描述符
 * msg：待发送的数据
 * length：msg数据大小，单位字节
 * dest_addr：目的IP地址
 * addrlen：dest_addr大小
 * return：num of send on success，-1 on failed
 */
int UdpSendSocket(int sockfd, const struct sockaddr *dest_addr, int addrlen, const void *msg, size_t length)
{
	int ret = sendto(sockfd, msg, length, 0, dest_addr, addrlen);
	return ret;
}

/*
 * UDP发送数据
 * sockfd：套接字描述符
 * msg：待发送的数据
 * length：msg数据大小，单位字节
 * dest_addr：目的IPv4地址
 * port：目的端口
 * return：num of send on success，-1 on failed
 */
int UdpSendSocket4(int sockfd, const char *dest_addr, unsigned short port, const void *msg, size_t length)
{
    int ret;
	struct sockaddr_in dst_addr;

	memset(&dst_addr, 0, sizeof(dst_addr));
	dst_addr.sin_family = AF_INET;
	dst_addr.sin_port = htons(port);
	dst_addr.sin_addr.s_addr = inet_addr(dest_addr);

    ret = sendto(sockfd, msg, length, 0, (struct sockaddr *)&dst_addr, sizeof(dst_addr));
    return ret == length ? ret : -1;
}

/*
 * 加入组播，取自UNP
 * grp：要加入的多播组
 * netcardName：加入多播组的本机接口，如eth0
 * ifindex：本机接口索引，应大于0，为0则根据接口名获取本机IP地址
 * return：0 on success，-1 on fail
 */
int UdpJoinMcast(int sockfd, const struct sockaddr *grp, socklen_t grplen, const char *netcardName, unsigned int ifindex)
{
#ifdef MCAST_JOIN_GROUP
	struct group_req req;
	if (ifindex > 0)
	{
		req.gr_interface = ifindex;
	}
	else if (netcardName != 0)
	{
		if ((req.gr_interface = if_nametoindex(netcardName)) == 0)
		{
			errno = ENXIO; // not found this if
			return -1;
		}
	}
	else
	{
		req.gr_interface = 0; // let kernel to choose if
	}

	if (grplen > sizeof(req.gr_group))
	{
		errno = EINVAL;
		return -1;
	}
	memcpy(&req.gr_group, grp, grplen);
	return setsockopt(sockfd, family_to_level(grp->sa_family), MCAST_JOIN_GROUP, &req, sizeof(req));

#else

	switch (grp->sa_family)
	{
	case AF_INET:
		{
			struct ip_mreq mreq;
			struct ifreq ifreq;

			memcpy(&mreq.imr_multiaddr, &((const struct sockaddr_in *)grp)->sin_addr, sizeof(struct in_addr));
			if (ifindex > 0)
			{
				if (if_indextoname(ifindex, ifreq,ifr_name)==NULL)
				{
					errno = ENXIO;
					return -1;
				}
				goto doioctl;
			}
			else if (netcardName)
			{
				strncpy(ifreq.ifr_name, netcardName, sizeof(ifreq.ifr_name));
doioctl:
				if (ioctl(sockfd, SIOCGIFADDR, &ifreq) < 0)
				{
					return -1;
				}
				memcpy(&mreq.imr_interface, &((const struct sockaddr_in *)&ifreq.ifr_addr)->sin_addr, sizeof(struct in_addr));
			}
			else
			{
				mreq.imr_interface.s_addr = htonl(INADDR_ANY);
			}
			return setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
		}

#ifdef IPV6ADDR_ANY_INIT
	case AF_INET6:
		{
			struct ipv6_mreq mreq6;
			memcpy(&mreq6.ipv6mr_multiaddr, &((const struct sockaddr_in6 *)grp)->sin6_addr, sizeof(struct in6_addr));
			if (ifindex > 0)
			{
				mreq6.ipv6mr_interface = ifindex;
			}
			else if (netcardName)
			{
				if ((mreq6.ipv6mr_interface = if_nametoindex(netcardName)) == 0)
				{
					errno = ENXIO;// not found
					return -1;
				}
			}
			else
			{
				mreq6.ipv6mr_interface = 0;
			}
			return setsockopt(sockfd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6, sizeof(mreq6));
		}
#endif

	default:
		errno = EAFNOSUPPORT;
		return -1;
	}
#endif
}

/*
 * 退出组播，取自UNP
 * grp：要退出的多播组
 * return：0 on success，-1 on fail
 */
int UdpLeaveMcast(int sockfd, const struct sockaddr *grp, socklen_t grplen)
{
#ifdef MCAST_JOIN_GROUP
	struct group_req req;
	req.gr_interface = 0;
	if (grplen > sizeof(req.gr_group))
	{
		errno = EINVAL;
		return -1;
	}
	memcpy(&req.gr_group, grp, grplen);
	return setsockopt(sockfd, family_to_level(grp->sa_family), MCAST_LEAVE_GROUP, &req, sizeof(req));

#else

	switch (grp->sa_family)
	{
	case AF_INET:
		{
			struct ip_mreq mreq;
			memcpy(&mreq.imr_multiaddr, &((struct sockaddr_in *)grp)->sin_addr, sizeof(struct in_addr));
			mreq.imr_interface.s_addr = 0;
			return setsockopt(sockfd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));
		}

#ifdef IPV6ADDR_ANY_INIT
	case AF_INET6:
		{
			struct ipv6_mreq mreq6;
			memcpy(&mreq6.ipv6mr_multiaddr, &((struct sockaddr_in6 *)grp)->sin6_addr, sizeof(struct in6_addr));
			mreq.ipv6mr_interface.s_addr = 0;
			return setsockopt(sockfd, IPPROTO_IPV6, IPV6_LEAVE_GROUP, &mreq6, sizeof(mreq6));
		}
#endif

	default:
		errno = EAFNOSUPPORT;
		return -1;
	}
#endif
}

/*
 * 设置多播TTL，取自UNP
 * ttl：1~255
 * return：0 on success，-1 on fail
 */
int UdpSetMcastTTL(int sockfd, int ttl)
{
	switch (sockfd_to_family(sockfd))
	{
	case AF_INET:
		{
			unsigned char ttl_;
			ttl_ = ttl;
			return setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl_, sizeof(ttl_));
		}

#ifdef IPV6ADDR_ANY_INIT
	case AF_INET6:
		{
			int hop;
			hop = ttl;
			return setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hop, sizeof(hop)));
		}
#endif

	default:
		errno = EAFNOSUPPORT;
		return -1;
	}
}

/*
 * 设置多播数据包本地回环是否开启，取自UNP
 * flag：0 or 1
 * return：0 on success，-1 on fail
 */
int UdpSetMcastLoop(int sockfd, int flag)
{
	/*
	用于控制是否将发送的多播数据包回送到本地套接字
	这个选项设置了一个布尔值，决定了发送的多播数据包是否应该被回环到发送它的主机上的其他套接字
	在Linux系统中，IP_MULTICAST_LOOP 选项自Linux 1.2版本起可用，并且应用于发送端。
	当设置为1（默认值）时，表示允许回环，即发送的多播数据包会被回送到本地的套接字；
	当设置为0时，表示禁止回环，发送的多播数据包不会被回送到本地的套接字
	*/
	switch (sockfd_to_family(sockfd))
	{
	case AF_INET: 
		{
			unsigned char flag_;
			flag_ = flag;
			return setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_LOOP, &flag_, sizeof(flag_));
		}

#ifdef IPV6ADDR_ANY_INIT
	case AF_INET6:
		{
			int flg;
			flg = flag;
			return setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &flg, sizeof(flg)));
		}
#endif

	default:
		errno = EAFNOSUPPORT;
		return -1;
	}
}

/*
 * 设置多播数据包外出接口，取自UNP
 * ifname：网卡名
 * ifindex：接口索引
 * return：0 on success，-1 on fail
 */
int UdpSetMcastIf(int sockfd, const char *ifname, unsigned int ifindex)
{
	switch (sockfd_to_family(sockfd))
	{
	case AF_INET:
		{
			struct in_addr inaddr;
			struct ifreq ifreq;

			if (ifindex > 0)
			{
				if (if_indextoname(ifindex, ifreq.ifr_name) == 0)
				{
					errno = ENXIO;
					return -1;
				}
				goto doioctl;
			}
			else if (ifname != 0)
			{
				strncpy(ifreq.ifr_name, ifname, sizeof(ifreq.ifr_name));
doioctl:
				if (ioctl(sockfd, SIOCGIFADDR, &ifreq) < 0)
				{
					return -1;
				}
				memcpy(&inaddr, &((struct sockaddr_in *)&ifreq.ifr_addr)->sin_addr, sizeof(inaddr));
			}
			else
				inaddr.s_addr = htonl(INADDR_ANY);

			return setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_IF, &inaddr, sizeof(inaddr));
		}

#ifdef IPV6ADDR_ANY_INIT
	case AF_INET6:
		{
			unsigned int idx;
			idx = ifindex;
			if (idx == 0)
			{
				if (ifname == 0)
				{
					errno = EINVAL;
					return -1;
				}

				if ( (idx = if_nametoindex(ifname)) == 0 )
				{
					errno = ENXIO;
					return -1;
				}
			}
			return setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &idx, sizeof(idx)));
		}
#endif

	default:
		errno = EAFNOSUPPORT;
		return -1;
	}
}

/*
 * 获取套接字当前文件标志
 * sockfd：套接字句柄
 * flag：保存标志
 * return：0 on success，-1 on fail
 */
int GetSocketFlag(int sockfd, int *flag)
{
	int flg = fcntl(sockfd, F_GETFL, 0);
	if (flg == -1)
		return -1;
	if (flag)
		*flag = flg;
	return 0;
}

/*
 * 设置套接字标志
 * sockfd：套接字句柄
 * flag：待设置的标志
 * return：0 on success，-1 on fail
 */
int SetSocketFlag(int sockfd, int flag)
{
	return fcntl(sockfd, F_SETFL, flag);
}

/*
 * 获取套接字当前未读数据大小
 * sockfd：套接字句柄
 * size：保存数据大小
 * return：0 on success，-1 on fail
 */
int GetSocketUnread(int sockfd, int *size)
{
	int sz = 0, ret = -1;
	ret = ioctl(sockfd, FIONREAD, &sz);
	if (size)
	{
		*size = sz;
	}
	return ret;
}

/*
 * 获取对端套接字的端口
 * sockfd：套接字句柄
 * return：peer port（主机字节序）on success，-1 on fail
 */
int GetSocketPeerPort(int sockfd)
{
	struct sockaddr_storage addr = {0};
	socklen_t len = sizeof(addr);
	if (getpeername(sockfd, (struct sockaddr *)&addr, &len) == 0)
	{
		if (addr.ss_family == AF_INET)
			return ntohs(((struct sockaddr_in *)&addr)->sin_port);
		else if (addr.ss_family == AF_INET6)
			return ntohs(((struct sockaddr_in6 *)&addr)->sin6_port);
	}
	return -1;
}

/*
 * 获取对端套接字的IP地址
 * sockfd：套接字句柄
 * dst：保存IP地址（网络字节序）
 * size：dst大小，单位字节
 * return：0 on success，-1 on fail
 */
int GetSocketPeerAddr(int sockfd, void *dst, int size)
{
	struct sockaddr_storage addr = {0};
	socklen_t len = sizeof(addr);
	if (getpeername(sockfd, (struct sockaddr *)&addr, &len) == 0)
	{
		if (addr.ss_family == AF_INET)
		{
			int len = sizeof(((struct sockaddr_in *)&addr)->sin_addr.s_addr);
			if (size >= len)
				*(unsigned int *)dst = ((struct sockaddr_in *)&addr)->sin_addr.s_addr;
			return 0;
		}
		else if (addr.ss_family == AF_INET6)
		{
			int len = sizeof(((struct sockaddr_in6 *)&addr)->sin6_addr);
			if (size >= len)
				memcpy(dst, &(((struct sockaddr_in6 *)&addr)->sin6_addr), len);
			return 0;
		}
	}
	return -1;
}

/*
 * 获取对端套接字的IP地址
 * sockfd：套接字句柄
 * buff：保存对端IP地址缓冲区
 * size：buff长度，单位字节
 * return：0 on success，-1 on fail
 */
int GetSocketPeerAddr2(int sockfd, char *buff, int size)
{
	struct sockaddr_storage addr = {0};
	socklen_t len = sizeof(addr);
	if (getpeername(sockfd, (struct sockaddr *)&addr, &len) == 0)
	{
		char tmp[128] = {0};
		void *src = NULL;
		
		if (addr.ss_family == AF_INET)
			src = &(((struct sockaddr_in *)&addr)->sin_addr);
		else if (addr.ss_family == AF_INET6)
			src = &(((struct sockaddr_in6 *)&addr)->sin6_addr);
		else
			return -1;

		const char *ptr = inet_ntop2(addr.ss_family, src, tmp, sizeof(tmp));
		if (ptr)
		{
			if (buff && (strlen(ptr) < size))
			{
				strcpy(buff, ptr);
			}
			return 0;
		}
	}
	return -1;
}

/*
 * 获取本地套接字的端口
 * sockfd：套接字句柄
 * return：port（主机字节序）on success，-1 on fail
 */
int GetSocketPort(int sockfd)
{
	struct sockaddr_storage addr = {0};
	socklen_t len = sizeof(addr);
	if (getsockname(sockfd, (struct sockaddr *)&addr, &len) == 0)
	{
		if (addr.ss_family == AF_INET)
			return ntohs(((struct sockaddr_in *)&addr)->sin_port);
		else if (addr.ss_family == AF_INET6)
			return ntohs(((struct sockaddr_in6 *)&addr)->sin6_port);
	}
	return -1;
}

/*
 * 获取本地套接字的IP地址
 * sockfd：套接字句柄
 * dst：保存IP地址（网络字节序）
 * size：dst大小，单位字节
 * return：0 on success，-1 on fail
 */
int GetSocketAddr(int sockfd, void *dst, int size)
{
	struct sockaddr_storage addr = {0};
	socklen_t len = sizeof(addr);
	if (getsockname(sockfd, (struct sockaddr *)&addr, &len) == 0)
	{
		if (addr.ss_family == AF_INET)
		{
			int len = sizeof(((struct sockaddr_in *)&addr)->sin_addr.s_addr);
			if (size >= len)
				*(unsigned int *)dst = ((struct sockaddr_in *)&addr)->sin_addr.s_addr;
			return 0;
		}
		else if (addr.ss_family == AF_INET6)
		{
			int len = sizeof(((struct sockaddr_in6 *)&addr)->sin6_addr);
			if (size >= len)
				memcpy(dst, &(((struct sockaddr_in6 *)&addr)->sin6_addr), len);
			return 0;
		}
	}
	return -1;
}

/*
 * 获取本地套接字的IP地址
 * sockfd：套接字句柄
 * buff：保存本地IP地址缓冲区
 * size：buff长度，单位字节
 * return：0 on success，-1 on fail
 */
int GetSocketAddr2(int sockfd, char *buff, int size)
{
	struct sockaddr_storage addr = {0};
	socklen_t len = sizeof(addr);
	if (getsockname(sockfd, (struct sockaddr *)&addr, &len) == 0)
	{
		char tmp[128] = {0};
		void *src = NULL;
		
		if (addr.ss_family == AF_INET)
			src = &(((struct sockaddr_in *)&addr)->sin_addr);
		else if (addr.ss_family == AF_INET6)
			src = &(((struct sockaddr_in6 *)&addr)->sin6_addr);
		else
			return -1;

		const char *ptr = inet_ntop2(addr.ss_family, src, tmp, sizeof(tmp));
		if (ptr)
		{
			if (buff && (strlen(ptr) < size))
			{
				strcpy(buff, ptr);
			}
			return 0;
		}
	}
	return -1;
}

/*
 * 设置套接字阻塞与否
 * sockfd：套接字句柄
 * block：0：非阻塞，1：阻塞
 * return：0 on success，-1 on fail
 */
int SetSocketBlock(int sockfd, int block)
{
	int flag;
	flag = fcntl(sockfd, F_GETFL, 0);
	if (flag == -1)
	{
		return -1;
	}
	return fcntl(sockfd, F_SETFL, block ? (flag & (~O_NONBLOCK)) : (flag | O_NONBLOCK));
}

/*
 * 设置套接字发送超时时间
 * sockfd：套接字句柄
 * ms：超时时间
 * return：0 on success，-1 on fail
 */
int SetSocketSndTimeout(int sockfd, int ms)
{
	if (ms > 0)
	{
		struct timeval tv = {0};
		tv.tv_sec = ms / 1000;
		tv.tv_usec = (ms % 1000) * 1000;
		return setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	}
	return -1;
}

/*
 * 设置套接字接收超时时间
 * sockfd：套接字句柄
 * ms：超时时间
 * return：0 on success，-1 on fail
 */
int SetSocketRcvTimeout(int sockfd, int ms)
{
	if (ms > 0)
	{
		struct timeval tv = {0};
		tv.tv_sec = ms / 1000;
		tv.tv_usec = (ms % 1000) * 1000;
		return setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}
	return -1;
}

/*
 * 设置套接字地址复用与否
 * sockfd：套接字句柄
 * on：0：不复用，1：复用
 * return：0 on success，-1 on fail
 */
int SetSocketReuseAddr(int sockfd, int on)
{
	int opt = !!on;
	return setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
}

/*
 * 设置套接字端口复用与否
 * sockfd：套接字句柄
 * on：0：不复用，1：复用
 * return：0 on success，-1 on fail
 */
int SetSocketReusePort(int sockfd, int on)
{
	int opt = !!on;
	return setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
}

/*
 * 设置套接字发送接收缓冲区大小
 * sockfd：套接字句柄
 * snd_size：待设置的发送缓冲大小，单位字节，为0表示不设置
 * rcv_size：待设置的接收缓冲大小，单位字节，为0表示不设置
 * return：0 on success，-1 on fail
 */
int SetSocketBufSize(int sockfd, int snd_size, int rcv_size)
{
	if (snd_size > 0)
	{
		setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &snd_size, sizeof(snd_size));
	}
	if (rcv_size > 0)
	{
		setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcv_size, sizeof(rcv_size));
	}
	return 0;
}

/*
 * 设置套接字忽略管道错误
 * sockfd：套接字句柄
 * return：0 on success，-1 on fail
 */
int SetSocketIgnPipe(int sockfd)
{
	int opt = 1;
	return setsockopt(sockfd, SOL_SOCKET, MSG_NOSIGNAL, &opt, sizeof(opt));
}

/*
 * 设置套接字禁止Nagle算法与否
 * sockfd：套接字句柄
 * on：0：不禁止，1：禁止
 * return：0 on success，-1 on fail
 */
int SetSocketNoDelay(int sockfd, int on)
{
	int opt = !!on;
	return setsockopt(sockfd, SOL_SOCKET, TCP_NODELAY, &opt, sizeof(opt));
}

/*
 * 设置套接字启用保活与否
 * sockfd：套接字句柄
 * on：0：不启用，1：启用
 * return：0 on success，-1 on fail
 */
int SetSocketKeepalive(int sockfd, int on)
{
	int opt = !!on;
	return setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
}

/*
 * 设置套接字启用保活与否
 * sockfd：套接字句柄
 * on：0：不启用，1：启用
 * interval：保活间隔，单位秒
 * retry_interval：重试间隔，单位秒
 * retry_count：重试次数
 * return：0 on success，-1 on fail
 */
int SetSocketKeepalive2(int sockfd, int on, int interval, int retry_interval, int retry_count)
{
	SetSocketKeepalive(sockfd, on);
	if (on)
	{
		setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE, &interval, sizeof(interval));
		setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &retry_interval, sizeof(retry_interval));
		setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPCNT, &retry_count, sizeof(retry_count));
	}
	return 0;
}

/*
 * 连接建立成功后且收到第一组数据时accept函数才返回
 * TCP_DEFER_ACCEPT选项可以让服务器在完成TCP三次握手后不立即将连接从SYN_RECV状态
 * 转换到ESTABLISHED状态，而是等待客户端发送数据
 * 如果在指定的时间内没有收到数据，连接将被丢弃；如果收到了数据，连接才会被接受
 * return: 0 on success, -1 on fail
 */
int SetSocketDeferAccept(int sock)
{
#ifdef TCP_DEFER_ACCEPT
    int one = 1; // 设置延迟接受的时间，单位为秒
    return setsockopt(sock, IPPROTO_TCP, TCP_DEFER_ACCEPT, &one, sizeof(one));
#endif
    return 0;
}


