/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"

namespace E
{
std::list<Socket*> socket_list;

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{
}

void TCPAssignment::finalize()
{

}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int, param.param3_int);
		break;
	case CLOSE:
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		//this->syscall_connect(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		//this->syscall_getsockname(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

Socket* TCPAssignment::find_socket(int pid, int fd)
{
	Socket* socket = NULL;

	for (std::list<Socket*>::iterator i = socket_list.begin(); i != socket_list.end(); ++i){
		if (pid == (*i)->pid && fd == (*i)->fd) {
			socket = *i;
		}
	}

	return socket;
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol)
{
	int fd = createFileDescriptor(pid);
	Socket* socket = new Socket(pid, fd);
	socket_list.push_back(socket);
	returnSystemCall(syscallUUID, fd);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int sockfd)
{
	for (std::list<Socket*>::iterator it = socket_list.begin(); it != socket_list.end(); ++it) {
		if (pid == (*it)->pid && sockfd == (*it)->fd) 
		{
			free((*it)->sa);
			socket_list.erase(it);
			removeFileDescriptor(pid, sockfd);
			returnSystemCall(syscallUUID, 0);
			return;
		}
	}

	returnSystemCall(syscallUUID, -1);
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *my_addr, socklen_t addrlen)
{
	Socket* socket = find_socket(pid, sockfd);

	if (socket == NULL || socket->state != IDLE) {
		returnSystemCall(syscallUUID, -1);
		return;
	}

	struct sockaddr_in* new_sa = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
	new_sa->sin_family = ((struct sockaddr_in *) my_addr)->sin_family;
	new_sa->sin_addr = ((struct sockaddr_in *) my_addr)->sin_addr;
	new_sa->sin_port = ((struct sockaddr_in *) my_addr)->sin_port;
	socket->sa = (struct sockaddr *) new_sa;
	socket->state = BOUND;

	returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{

}

void TCPAssignment::timerCallback(void* payload)
{

}


}
