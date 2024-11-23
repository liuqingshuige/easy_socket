/*
 * socket操作封装: C接口方式
 * Copyright FreeCode. All Rights Reserved.
 * MIT License (https://opensource.org/licenses/MIT)
 * 2024 by liuqingshuige
 */
#ifndef __FREE_EASY_SOCKET_H__
#define __FREE_EASY_SOCKET_H__

#include <sys/types.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 将网络字节序的IPv4地址转换为点分十进制格式
 * 将网络字节序的IPv6地址（16byte，128bit）转换为x:x:x:x:x:x:x:x格式
 * family：AF_INET/AF_INET6
 * src：待转换的IP地址
 * dest：保存转换结果
 * size：dest长度，单位字节
 * return：成功返回指向dest的指针，失败返回NULL
 */
const char *inet_ntop2(int family, const void *src, char *dest, size_t size);
const char *inet_ntop3(const struct sockaddr *sa, char *dest, size_t size);

/*
 * 域名转IP地址
 * host：主机名/域名/IP地址
 * serv：端口号/服务名（如NTP、FTP、SIP等）
 * addr：保存返回的地址信息数组
 * count：addr数组大小
 * return：num of actual addr on success，-1 on error
 */
int DomainName2Addr(const char *host, const char *serv, struct sockaddr_storage *addr, int count);

/*
 * 获取本机IPv4地址
 * dest：保存点分十进制IP地址
 * size：dest长度，单位字节
 * return：成功返回指向dest的指针，失败返回NULL
 */
const char *GetLocalIpv4(char *dest, size_t size);

/*
 * 获取本机IPv6地址
 * dest：保存IP地址
 * size：dest长度，单位字节
 * return：成功返回指向dest的指针，失败返回NULL
 */
const char *GetLocalIpv6(char *dest, size_t size);

/*
 * 获取本机网卡名称
 * dest：保存网卡名称数组
 * size：dest数组元素个数
 * return：成功返回网卡数量，失败返回-1
 */
int GetLocalNetcard(char dest[][64], size_t size);

/*
 * 获取本机指定网卡MAC地址
 * interface：网卡名称
 * mac：保存MAC地址
 * return：0 on success，-1 on fail
 */
int GetMacAddr(const char *interface, unsigned char mac[6]);

/*
 * 获取本机指定网卡MAC地址并格式化
 * interface：网卡名称
 * buff：保存格式化后的MAC地址
 * size：buff长度，单位字节
 * separator：分隔符
 * return：0 on success，-1 on fail
 */
int GetMacAddr2(const char *interface, unsigned char *buff, size_t size, const char separator);

/*
 * 创建套接字
 * family：AF_INET/AF_INET6/AF_UNIX(AF_LOCAL)/AF_PACKET
 * type：SOCK_STREAM/SOCK_DGRAM/SOCK_RAW/SOCK_PACKET
 * return：sockfd on success，-1 on fail
 */
int CreateSocket(int family, int type);

/*
 * 关闭套接字
 * return：0 on success，-1 on fail
 */
int CloseSocket(int sockfd);

/*
 * 创建一个TCP套接字
 * family：AF_INET/AF_INET6
 * return：sockfd on success, -1 on fail
 */
int CreateTcpSocket(int family);

/*
 * 创建一个IPv4的TCP套接字
 * return：sockfd on success, -1 on fail
 */
int CreateTcpSocket4(void);

/*
 * 创建一个IPv6的TCP套接字
 * return：sockfd on success, -1 on fail
 */
int CreateTcpSocket6(void);

/*
 * 创建一个UDP套接字
 * return：sockfd on success, -1 on fail
 */
int CreateUdpSocket(int family);

/*
 * 创建一个IPv4的UDP套接字
 * return：sockfd on success, -1 on fail
 */
int CreateUdpSocket4(void);

/*
 * 创建一个IPv6的UDP套接字
 * return：sockfd on success, -1 on fail
 */
int CreateUdpSocket6(void);

/*
 * 套接字绑定IP地址和端口
 * sockfd：套接字句柄
 * sa：待绑定的地址
 * salen：sa大小
 * return：0 on success，-1 on fail
 */
int BindSocket(int sockfd, const struct sockaddr *sa, socklen_t salen);

/*
 * 套接字绑定IPv4的IP地址和端口
 * sockfd：套接字句柄
 * ipaddr：待绑定的IPv4地址，格式如：ddd.ddd.ddd.ddd
 * port：待绑定的端口
 * return：0 on success，-1 on fail
 */
int BindSocket4(int sockfd, const char *ipaddr, unsigned short port);

/*
 * 套接字绑定IPv6的IP地址和端口
 * sockfd：套接字句柄
 * ipv6addr：待绑定的IPv6地址，格式如：x:x:x:x:x:x:x:x/x:x:x:x:x:x:d.d.d.d
 * port：待绑定的端口
 * return：0 on success，-1 on fail
 */
int BindSocket6(int sockfd, const char *ipv6addr, unsigned short port);

/*
 * 在套接字上开启监听
 * sockfd：套接字句柄
 * backlog：套接字的未完成连接队列的最大长度
 * return：0 on success，-1 on fail
 */
int ListenSocket(int sockfd, int backlog);

/*
 * 接收客户端连接
 * sockfd：套接字句柄
 * sa：保存客户端地址信息
 * len：作为输入时表示sa大小，作为输出时表示客户端地址实际大小
 * return：client fd on success，-1 on fail
 */
int AcceptSocket(int sockfd, struct sockaddr_storage *sa, socklen_t *len);

/*
 * 非阻塞连接指定的服务地址
 * sockfd：套接字句柄
 * saptr：待连接的服务地址
 * salen：saptr大小
 * ms：超时时间
 * return：0 on success，-1 on fail
 */
int ConnectSocket(int sockfd, const struct sockaddr *saptr, socklen_t salen, unsigned int ms);

/*
 * TCP连接指定的主机
 * host：主机名、域名或者点分十进制IP地址、或者IPv6的16进制串
 * service：端口或者服务名如ftp、ntp等
 * timeout：超时时间，单位ms
 * return：sockfd on success，-1 on failed
 */
int TcpConnectSocket(const char *host, const char *service, unsigned int timeout);

/*
 * 开启TCP监听
 * host：主机名、域名或者点分十进制IP地址、或者IPv6的16进制串
 * service：端口或者服务名如ftp、ntp等
 * backlo：套接字的未完成连接队列的最大长度
 * return：sockfd on success，-1 on failed
 */
int TcpListenSocket(const char *host, const char *service, int backlog);

/*
 * TCP读取数据
 * sockfd：套接字描述符
 * msg：保存数据的缓存
 * length：msg缓存大小，单位字节
 * timeout：超时时间(ms)
 * return：num of read bytes on success，-1 on failed
 */
int TcpRecvSocket(int sockfd, void *msg, size_t length, int timeout);

/*
 * TCP发送数据
 * sockfd：套接字描述符
 * msg：待发送的数据
 * length：msg数据大小，单位字节
 * timeout：超时时间(ms)
 * return：num of send on success，-1 on failed
 */
int TcpSendSocket(int sockfd, const void *msg, size_t length, int timeout);

/*
 * 开启UDP监听，返回监听套接字
 * host：主机名、域名或者点分十进制IP地址、或者IPv6的16进制串
 * servic：端口或者服务名如ftp、ntp等
 * return：sockfd on success，-1 on failed
 */
int UdpListenSocket(const char *host, const char *service);

/*
 * UDP读取数据
 * sockfd：套接字描述符
 * msg：保存数据的缓存
 * length：msg缓存大小，单位字节
 * timeout：超时时间(ms)
 * peer_addr：对端IP信息，可选
 * return：num of read bytes on success，-1 on failed
 */
int UdpRecvSocket(int sockfd, void *msg, size_t length, int timeout, struct sockaddr_storage *peer_addr);

/*
 * UDP发送数据
 * sockfd：套接字描述符
 * msg：待发送的数据
 * length：msg数据大小，单位字节
 * dest_addr：目的IP地址
 * addrlen：dest_addr大小
 * return：num of send on success，-1 on failed
 */
int UdpSendSocket(int sockfd, const struct sockaddr *dest_addr, int addrlen, const void *msg, size_t length);

/*
 * UDP发送数据
 * sockfd：套接字描述符
 * msg：待发送的数据
 * length：msg数据大小，单位字节
 * dest_addr：目的IPv4地址
 * port：目的端口
 * return：num of send on success，-1 on failed
 */
int UdpSendSocket4(int sockfd, const char *dest_addr, unsigned short port, const void *msg, size_t length);

/*
 * 加入组播
 * grp：要加入的多播组
 * netcardName：加入多播组的本机接口，如eth0
 * ifindex：本机接口索引，应大于0，为0则根据接口名获取本机IP地址
 * return：0 on success，-1 on fail
 */
int UdpJoinMcast(int sockfd, const struct sockaddr *grp, socklen_t grplen, const char *netcardName, unsigned int ifindex);

/*
 * 退出组播
 * grp：要退出的多播组
 * return：0 on success，-1 on fail
 */
int UdpLeaveMcast(int sockfd, const struct sockaddr *grp, socklen_t grplen);

/*
 * 设置多播TTL
 * ttl: 1~255
 * return:  0 on success，-1 on fail
 */
int UdpSetMcastTTL(int sockfd, int ttl);

/*
 * 设置多播数据包本地回环是否开启
 * flag：0 or 1
 * return：0 on success，-1 on fail
 */
int UdpSetMcastLoop(int sockfd, int flag);

/*
 * 设置多播数据包外出接口
 * ifname：网卡名
 * ifindex：接口索引
 * return：0 on success，-1 on fail
 */
int UdpSetMcastIf(int sockfd, const char *ifname, unsigned int ifindex);

/*
 * 获取套接字当前文件标志
 * sockfd：套接字句柄
 * flag：保存标志
 * return：0 on success，-1 on fail
 */
int GetSocketFlag(int sockfd, int *flag);

/*
 * 设置套接字标志
 * sockfd：套接字句柄
 * flag：待设置的标志
 * return：0 on success，-1 on fail
 */
int SetSocketFlag(int sockfd, int flag);

/*
 * 获取套接字当前未读数据大小
 * sockfd：套接字句柄
 * size：保存数据大小
 * return：0 on success，-1 on fail
 */
int GetSocketUnread(int sockfd, int *size);

/*
 * 获取对端套接字的端口
 * sockfd：套接字句柄
 * return：peer port（主机字节序）on success，-1 on fail
 */
int GetSocketPeerPort(int sockfd);

/*
 * 获取对端套接字的IP地址
 * sockfd：套接字句柄
 * dst：保存IP地址（网络字节序）
 * size：dst大小，单位字节
 * return：0 on success，-1 on fail
 */
int GetSocketPeerAddr(int sockfd, void *dst, int size);

/*
 * 获取对端套接字的IP地址
 * sockfd：套接字句柄
 * buff：保存对端IP地址缓冲区
 * size：buff长度，单位字节
 * return：0 on success，-1 on fail
 */
int GetSocketPeerAddr2(int sockfd, char *buff, int size);

/*
 * 获取本地套接字的端口
 * sockfd：套接字句柄
 * return：port（主机字节序）on success，-1 on fail
 */
int GetSocketPort(int sockfd);

/*
 * 获取本地套接字的IP地址
 * sockfd：套接字句柄
 * dst：保存IP地址（网络字节序）
 * size：dst大小，单位字节
 * return：0 on success，-1 on fail
 */
int GetSocketAddr(int sockfd, void *dst, int size);

/*
 * 获取本地套接字的IP地址
 * sockfd：套接字句柄
 * buff：保存本地IP地址缓冲区
 * size：buff长度，单位字节
 * return：0 on success，-1 on fail
 */
int GetSocketAddr2(int sockfd, char *buff, int size);

/*
 * 设置套接字阻塞与否
 * sockfd：套接字句柄
 * block：0：非阻塞，1：阻塞
 * return：0 on success，-1 on fail
 */
int SetSocketBlock(int sockfd, int block);

/*
 * 设置套接字发送超时时间
 * sockfd：套接字句柄
 * ms：超时时间
 * return：0 on success，-1 on fail
 */
int SetSocketSndTimeout(int sockfd, int ms);

/*
 * 设置套接字接收超时时间
 * sockfd：套接字句柄
 * ms：超时时间
 * return：0 on success，-1 on fail
 */
int SetSocketRcvTimeout(int sockfd, int ms);

/*
 * 设置套接字地址复用与否
 * sockfd：套接字句柄
 * on：0：不复用，1：复用
 * return：0 on success，-1 on fail
 */
int SetSocketReuseAddr(int sockfd, int on);

/*
 * 设置套接字端口复用与否
 * sockfd：套接字句柄
 * on：0：不复用，1：复用
 * return：0 on success，-1 on fail
 */
int SetSocketReusePort(int sockfd, int on);

/*
 * 设置套接字发送接收缓冲区大小
 * sockfd：套接字句柄
 * snd_size：待设置的发送缓冲大小，单位字节，为0表示不设置
 * rcv_size：待设置的接收缓冲大小，单位字节，为0表示不设置
 * return：0 on success，-1 on fail
 */
int SetSocketBufSize(int sockfd, int snd_size, int rcv_size);

/*
 * 设置套接字忽略管道错误
 * sockfd：套接字句柄
 * return：0 on success，-1 on fail
 */
int SetSocketIgnPipe(int sockfd);

/*
 * 设置套接字禁止Nagle算法与否
 * sockfd：套接字句柄
 * on：0：不禁止，1：禁止
 * return：0 on success，-1 on fail
 */
int SetSocketNoDelay(int sockfd, int on);

/*
 * 设置套接字启用保活与否
 * sockfd：套接字句柄
 * on：0：不启用，1：启用
 * return：0 on success，-1 on fail
 */
int SetSocketKeepalive(int sockfd, int on);

/*
 * 设置套接字启用保活与否
 * sockfd：套接字句柄
 * on：0：不启用，1：启用
 * interval：保活间隔，单位秒
 * retry_interval：重试间隔，单位秒
 * retry_count：重试次数
 * return：0 on success，-1 on fail
 */
int SetSocketKeepalive2(int sockfd, int on, int interval, int retry_interval, int retry_count);

/*
 * 连接建立成功后且收到第一组数据时accept函数才返回
 * TCP_DEFER_ACCEPT选项可以让服务器在完成TCP三次握手后不立即将连接从SYN_RECV状态
 * 转换到ESTABLISHED状态，而是等待客户端发送数据
 * 如果在指定的时间内没有收到数据，连接将被丢弃；如果收到了数据，连接才会被接受
 * return: 0 on success, -1 on fail
 */
int SetSocketDeferAccept(int sock);




#ifdef __cplusplus
}
#endif

#endif
