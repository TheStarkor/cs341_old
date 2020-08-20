/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>


#include <E/E_TimerModule.hpp>
#include <E/E_TimeUtil.hpp>


#define IDLE 0
#define BOUND 1
#define SYN_SENT 2
#define ESTAB 3
#define LISTENING 4
#define SYNRCVD 5
#define FIN_WAIT_1 6
#define FIN_WAIT_2 7
#define CLOSE_WAIT 8
#define LAST_ACK 9
#define TIMED_WAIT 10
#define CLOSED 11

namespace E
{

class Socket
{
public:
	UUID syscallUUID;
	int pid;
	int fd;
	int state;
	struct sockaddr *sa; // src_addr, arc_port
	in_addr_t dest_addr;
	in_port_t dest_port;
	int dest_seq;
	int src_seq;
	int ack_num;
	int backlog;
	Socket *clone;

	std::list<Socket*> backlog_list;
	std::list<struct accept_elem*> accept_list;

	Socket(int _pid, int _fd)
	{
		pid = _pid;
		fd = _fd;
		state = IDLE;
		sa = NULL;
		dest_addr = -1;
		dest_port = -1;
		dest_seq = -1;
		src_seq = -1;
		ack_num = -1;
		backlog = -1;
		clone = NULL;
	};
};

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

class Header
{
public:
	in_addr_t src_addr;
	in_port_t src_port;
	in_addr_t dest_addr;
	in_port_t dest_port;
	uint32_t seq_num;
	uint32_t ack_num;
	bool urg;
	bool ack;
	bool psh;
	bool rst;
	bool syn;
	bool fin;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgent_pointer;

	Header()
	{
		seq_num = rand() % sizeof(int);
		ack_num = 0;
		urg = 0;
		ack = 0;
		psh = 0;
		rst = 0;
		syn = 0;
		fin = 0;
		window = 0;
		checksum = 0;
		urgent_pointer = 0;
	}
};

struct accept_elem
{
	UUID syscallUUID;
	int pid;
	sockaddr *addr;
	socklen_t *addrlen;
};

struct timer_elem
{
	UUID timerUUID;
	int state;
	Socket *socket;
};

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:

private:
	virtual void timerCallback(void* payload) final;

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
protected:
	virtual Socket* find_socket(int pid, int fd);
	virtual in_addr_t get_addr(struct sockaddr_in *sa);
	virtual in_port_t get_port(struct sockaddr_in *sa);
	virtual int check_addr(struct sockaddr *addr);
	virtual int count_backlog(Socket *socket);
	virtual void syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol);
	virtual void remove_socket(int pid, int sockfd);
	virtual void syscall_close(UUID syscallUUID, int pid, int sockfd);
	virtual void syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *my_addr, socklen_t addrlen);
	virtual void syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	virtual void allocate_header(Packet *packet, Header *header);
	virtual void read_header(Packet *packet, Header *header);
	virtual void syscall_connect(UUID syscallUUID, int pid, int sockfd, const struct sockaddr *addr, socklen_t addrlen);
	virtual void syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr* addr, socklen_t* addrlen);
	virtual void syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog);
	virtual Socket* find_established(Socket *socket);
	virtual void syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual Socket* find_socket_addr(Header *header);
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
	virtual struct timer_elem* allocate_timer(int time, Socket *socket) final;
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
