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

#define IDLE 0
#define BOUND 1

namespace E
{

class Socket
{
public:
	UUID syscallUUID;
	int pid;
	int fd;
	int state;
	struct sockaddr *sa;

	Socket(int _pid, int _fd)
	{
		pid = _pid;
		fd = _fd;
		state = IDLE;
		sa = NULL;
	};
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
	virtual void syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol);
	virtual void syscall_close(UUID syscallUUID, int pid, int sockfd);
	virtual void syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *my_addr, socklen_t addrlen);
	virtual void syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;

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
