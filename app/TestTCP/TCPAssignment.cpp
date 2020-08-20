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
std::list<Socket*> wait_list;
std::list<timer_elem*> timer_list;

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
	socket_list.clear();
	wait_list.clear();
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
		this->syscall_connect(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		this->syscall_accept(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		this->syscall_getpeername(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

Socket* TCPAssignment::find_socket(int pid, int fd)
{
	Socket* socket = NULL;

	for (std::list<Socket*>::iterator it = socket_list.begin(); it != socket_list.end(); ++it){
		if (pid == (*it)->pid && fd == (*it)->fd) {
			socket = *it;
		}
	}

	return socket;
}

in_addr_t TCPAssignment::get_addr(struct sockaddr_in *sa)
{
	return sa->sin_addr.s_addr;
}

in_port_t TCPAssignment::get_port(struct sockaddr_in *sa)
{
	return sa->sin_port;
}

int TCPAssignment::check_addr(struct sockaddr *addr)
{
	in_addr_t my_addr = get_addr((struct sockaddr_in *) addr);
	in_port_t my_port = get_port((struct sockaddr_in *) addr);

	in_addr_t tmp_addr;
	in_port_t tmp_port;

	for (std::list<Socket*>::iterator it = socket_list.begin(); it != socket_list.end(); ++it)
	{
		if ((*it)->state == IDLE)
		{
			continue;
		}

		
		tmp_addr = get_addr((struct sockaddr_in *) ((*it)->sa));
		tmp_port = get_port((struct sockaddr_in *) ((*it)->sa));
		if ((tmp_addr == my_addr || my_addr == INADDR_ANY || tmp_addr == INADDR_ANY) && (tmp_port == my_port))
		{
			return 1;
		}
	}
	
	return 0;
}

uint16_t calc_checksum(Packet *packet)
{
	in_addr_t src_addr, dest_addr;

	packet->readData(14 + 12, &src_addr, 4);
	packet->readData(14 + 16, &dest_addr, 4);

	size_t len = packet->getSize();
	len -= 14 + 20;

	uint8_t *seg = (uint8_t *) malloc(len);
	packet->readData(14 + 20, seg, len);
	uint16_t checksum = NetworkUtil::tcp_sum(src_addr, dest_addr, seg, len);
	free(seg);

	return checksum ^ 0xffff;
}

int TCPAssignment::count_backlog(Socket *socket)
{
	int cnt = 0;

	for (std::list<Socket*>::iterator it = socket->backlog_list.begin(); it != socket->backlog_list.end(); ++it)
	{
		if ((*it)->state == SYNRCVD)
			cnt++;
	}

	return cnt;
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol)
{
	int fd = createFileDescriptor(pid);

	while (find_socket(pid, fd) != NULL) {
		fd = createFileDescriptor(pid);
	}

	Socket* socket = new Socket(pid, fd);
	socket_list.push_back(socket);
	returnSystemCall(syscallUUID, fd);
}

void TCPAssignment::remove_socket(int pid, int sockfd)
{
	for (std::list<Socket*>::iterator it = socket_list.begin(); it != socket_list.end(); ++it) {
		if (pid == (*it)->pid && sockfd == (*it)->fd) 
		{
			free((*it)->sa);
			socket_list.erase(it);
			removeFileDescriptor(pid, sockfd);
			return;
		}
	}
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int sockfd)
{
	Socket *socket = find_socket(pid, sockfd);
	if (socket == NULL)
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

	if (socket->state <= SYN_SENT)
	{
		remove_socket(pid, sockfd);
		returnSystemCall(syscallUUID, 0);
		return;
	}

	// ??? SYNRCVD
	if (socket->state == ESTAB)
		socket->state = FIN_WAIT_1;
	else if (socket->state == CLOSE_WAIT)
		socket->state = LAST_ACK;

	Header *header = new Header();
	header->dest_addr = socket->dest_addr;
	header->dest_port = socket->dest_port;
	header->src_addr = ((struct sockaddr_in *) socket->sa)->sin_addr.s_addr;
	header->src_port = ((struct sockaddr_in *) socket->sa)->sin_port;
	header->seq_num = socket->src_seq;
	header->fin = 1;

	Packet *new_packet = allocatePacket(14 + 20 + 20);
	allocate_header(new_packet, header);

	sendPacket("IPv4", new_packet);

	returnSystemCall(syscallUUID, 0);

	delete header;
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *my_addr, socklen_t addrlen)
{
	Socket* socket = find_socket(pid, sockfd);

	if (socket == NULL || socket->state != IDLE) 
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

	if (check_addr(my_addr))
	{
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

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	Socket *socket = find_socket(pid, sockfd);

	if (socket == NULL)
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

	struct sockaddr_in *my_sa = (struct sockaddr_in *) socket->sa;
	((struct sockaddr_in *) addr)->sin_family = my_sa->sin_family;
	((struct sockaddr_in *) addr)->sin_addr = my_sa->sin_addr;
	((struct sockaddr_in *) addr)->sin_port = my_sa->sin_port;
	*addrlen = sizeof(struct sockaddr_in);

	returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::allocate_header(Packet *packet, Header *header)
{
	uint16_t flags = 0;
	flags |= header->fin << 0;
	flags |= header->syn << 1;
	flags |= header->rst << 2;
	flags |= header->psh << 3;
	flags |= header->ack << 4;
	flags |= header->urg << 5;

	flags = htons(flags);
	uint32_t seq_num = htonl(header->seq_num);
	uint32_t ack_num = htonl(header->ack_num);
	uint16_t window = htons(header->window);
	uint16_t checksum = htons(header->checksum);
	uint16_t urgent = htons(header->urgent_pointer);

	packet->writeData(14 + 12, &(header->src_addr), 4);
	packet->writeData(14 + 16, &(header->dest_addr), 4);
	packet->writeData(14 + 20, &(header->src_port), 2);
	packet->writeData(14 + 20 + 2, &(header->dest_port), 2);
	packet->writeData(14 + 20 + 4, &seq_num, 4);
	packet->writeData(14 + 20 + 8, &ack_num, 4);
	packet->writeData(14 + 20 + 12, &flags, 2);
	packet->writeData(14 + 20 + 14, &window, 2);
	packet->writeData(14 + 20 + 16, &checksum, 2);
	packet->writeData(14 + 20 + 18, &urgent, 2);

	checksum = htons(calc_checksum(packet));
	packet->writeData(14 + 20 + 16, &checksum, 2);
}

void TCPAssignment::read_header(Packet *packet, Header *header)
{
	uint16_t flags, window, checksum, urgent;
	uint32_t seq_num, ack_num;

	packet->readData(14 + 12, &(header->src_addr), 4);
	packet->readData(14 + 16, &(header->dest_addr), 4);
	packet->readData(14 + 20, &(header->src_port), 2);
	packet->readData(14 + 20 + 2, &(header->dest_port), 2);
	packet->readData(14 + 20 + 4, &seq_num, 4);
	packet->readData(14 + 20 + 8, &ack_num, 4);
	packet->readData(14 + 20 + 12, &flags, 2);
	packet->readData(14 + 20 + 14, &window, 2);
	packet->readData(14 + 20 + 16, &checksum, 2);
	packet->readData(14 + 20 + 18, &urgent, 2);

	header->seq_num = ntohl(seq_num);
	header->ack_num = ntohl(ack_num);

	flags = ntohs(flags);
	header->fin = flags & (1 << 0);
	header->syn = flags & (1 << 1);
	header->rst = flags & (1 << 2);
	header->psh = flags & (1 << 3);
	header->ack = flags & (1 << 4);
	header->urg = flags & (1 << 5);

	header->window = ntohs(window);
	header->checksum = ntohs(checksum);
	header->urgent_pointer = ntohs(urgent);
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	Socket *socket = find_socket(pid, sockfd);

	if (socket == NULL || socket->state != IDLE)
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

	Packet* packet = allocatePacket(14 + 20 + 20);

	Header* header = new Header();
	header->dest_addr = ((struct sockaddr_in *) addr)->sin_addr.s_addr;
	header->dest_port = ((struct sockaddr_in *) addr)->sin_port;
	int port = getHost()->getRoutingTable((uint8_t *) &(header->dest_addr));
	getHost()->getIPAddr((uint8_t *) &(header->src_addr), port);
	header->src_port = (rand() % sizeof(in_port_t));
	header->syn = 1;

	allocate_header(packet, header);

	in_addr_t test_addr;
	in_port_t test_port;

	packet->readData(14 + 16, &test_addr, 4);
	packet->readData(14 + 20 + 2, &test_port, 2);

	sendPacket("IPv4", packet);

	struct sockaddr_in* new_sa = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
	new_sa->sin_family = AF_INET;
	new_sa->sin_addr.s_addr = header->src_addr;
	new_sa->sin_port = header->src_port;
	socket->sa = (struct sockaddr *) new_sa;
	socket->dest_addr = header->dest_addr;
	socket->dest_port = header->dest_port;
	socket->state = SYN_SENT;
	socket->syscallUUID = syscallUUID;
	socket->src_seq = header->seq_num;

	delete header;
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr* addr, socklen_t* addrlen) {
	Socket* socket = find_socket(pid, sockfd);

	if (socket == NULL || socket->state <= SYN_SENT) {
		returnSystemCall(syscallUUID, -1);
		return;
	}

	((struct sockaddr_in *) addr)->sin_family = AF_INET;
	((struct sockaddr_in *) addr)->sin_addr.s_addr = socket->dest_addr;
	((struct sockaddr_in *) addr)->sin_port = socket->dest_port;
	*addrlen = sizeof(struct sockaddr_in);

	returnSystemCall(syscallUUID, 0);	
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog)
{
	Socket *socket = find_socket(pid, sockfd);

	if (socket == NULL || socket->state != BOUND)
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

	socket->state = LISTENING;
	socket->backlog = backlog;

	returnSystemCall(syscallUUID, 0);
}

Socket* TCPAssignment::find_established(Socket* socket)
{
	Socket *res_socket = NULL;

	for (std::list<Socket*>::iterator it = socket->backlog_list.begin(); it != socket->backlog_list.end(); ++it)
	{
		if((*it)->state >= ESTAB)
		{
			res_socket = &(**it);
			socket->backlog_list.erase(it);
			return res_socket;
		}
	}

	return res_socket;
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	Socket *socket = find_socket(pid, sockfd);

	if (socket == NULL || socket->state != LISTENING)
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

	Socket *backlog_elem = find_established(socket);

	if (backlog_elem != NULL)
	{
		int fd = createFileDescriptor(pid);
		backlog_elem->fd = fd;
		backlog_elem->pid = pid;

		((struct sockaddr_in *) addr)->sin_family = AF_INET;
		((struct sockaddr_in *) addr)->sin_addr.s_addr = ((struct sockaddr_in *) socket->sa)->sin_addr.s_addr;
		((struct sockaddr_in *) addr)->sin_port = ((struct sockaddr_in *) socket->sa)->sin_port;

		returnSystemCall(syscallUUID, fd);
		return;
	}
	else
	{
		struct accept_elem *ae = (struct accept_elem *) malloc(sizeof(struct accept_elem));
		ae->syscallUUID = syscallUUID;
		ae->pid = pid;
		ae->addr = addr;
		ae->addrlen = addrlen;

		socket->accept_list.push_back(ae);
	}
}

Socket* TCPAssignment::find_socket_addr(Header *header)
{
	Socket *socket = NULL;

	in_addr_t src_addr = header->src_addr;
	in_addr_t src_port = header->src_addr;
	in_addr_t dest_addr = header->dest_addr;
	in_port_t dest_port = header->dest_port;

	bool listening = header->syn == 1;
	
	for (std::list<Socket*>::iterator it = socket_list.begin(); it != socket_list.end(); ++it)
	{
		if ((struct sockaddr_in *) ((*it)->sa) == NULL)
			continue;

		in_addr_t my_addr = ((struct sockaddr_in *) ((*it)->sa))->sin_addr.s_addr;
		in_port_t my_port = ((struct sockaddr_in *) ((*it)->sa))->sin_port;

		if ((my_addr == INADDR_ANY || dest_addr == INADDR_ANY || my_addr == dest_addr) && (my_port == dest_port))
		{
			socket = *it;

			if (header->syn == 1 && socket->state == LISTENING)
				break;

			if (header->ack == 1 && socket->state == SYNRCVD)
				break;
		}
	}

	return socket;
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
	Header *header = new Header();
	read_header(packet, header);

	Socket *socket = find_socket_addr(header);

	if (socket == NULL)
	{
		freePacket(packet);
		delete header;
		return;
	}

	uint16_t checksum = calc_checksum(packet);
	if (checksum != 0)
	{
		freePacket(packet);
		delete header;
		return;
	}


	switch (socket->state)
	{
		case SYN_SENT:
		{
			if (header->syn != 1 || header->ack != 1)
				break;

			if (header->ack_num != socket->src_seq + 1)
				break;

			returnSystemCall(socket->syscallUUID, 0);

			Header *new_header = new Header();
			new_header->src_addr = header->dest_addr;
			new_header->src_port = header->dest_port;
			new_header->dest_addr = header->src_addr;
			new_header->dest_port = header->src_port;
			new_header->seq_num = header->ack_num;
			new_header->ack_num = header->seq_num + 1;
			new_header->ack = 1;

			Packet *new_packet = allocatePacket(14 + 20 + 20);
			allocate_header(new_packet, new_header);
			sendPacket("IPv4", new_packet);

			socket->state = ESTAB;
			socket->src_seq = new_header->seq_num;
			socket->ack_num = new_header->ack_num;
			socket->syscallUUID = NULL;

			delete new_header;
			break;
		}

		case LISTENING:
		{
			if (header->syn != 1)
				break;

			if (socket->backlog > count_backlog(socket))
			{
				Header *new_header = new Header();
				new_header->src_addr = header->dest_addr;
				new_header->src_port = header->dest_port;
				new_header->dest_addr = header->src_addr;
				new_header->dest_port = header->src_port;
				new_header->ack_num = header->seq_num + 1;
				new_header->syn = 1;
				new_header->ack = 1;

				Packet *new_packet = allocatePacket(14 + 20 + 20);
				allocate_header(new_packet, new_header);
				sendPacket("IPv4", new_packet);

				Socket *clone = new Socket(-1, -1);
				clone->clone = socket;
				clone->state = SYNRCVD;
				clone->dest_addr = new_header->dest_addr;
				clone->dest_port = new_header->dest_port;
				clone->src_seq = new_header->seq_num;
				clone->ack_num = new_header->ack_num;

				struct sockaddr_in *new_sa = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
				new_sa->sin_family = AF_INET;
				new_sa->sin_addr.s_addr = new_header->src_addr;
				new_sa->sin_port = new_header->src_port;

				clone->sa = (struct sockaddr *)new_sa;

				socket_list.push_back(clone);
				socket->backlog_list.push_back(clone);

				delete new_header;
			}

			break;
		}

		case SYNRCVD:
		{
			if (header->ack != 1)
				break;
			
			if (header->ack_num != socket->src_seq + 1) // ack 계산???
				break;

			socket->state = ESTAB;
			socket->src_seq = header->ack_num;

			if (socket->clone->accept_list.size() > 0)
			{
				struct accept_elem *ae = socket->clone->accept_list.front();
				socket->clone->accept_list.pop_front();

				int new_fd = createFileDescriptor(ae->pid);
				socket->fd = new_fd;
				socket->pid = ae->pid;
				
				// ??? dest or src
				((struct sockaddr_in *) ae->addr)->sin_family = AF_INET;
				((struct sockaddr_in *) ae->addr)->sin_addr.s_addr = ((struct sockaddr_in *)socket->sa)->sin_addr.s_addr;
				((struct sockaddr_in *) ae->addr)->sin_port = ((struct sockaddr_in *)socket->sa)->sin_port;

				find_established(socket->clone);
				returnSystemCall(ae->syscallUUID, socket->fd);
				free(ae);
			}

			break;
		}

		case ESTAB:
		{
			if (header->fin != 1)
				break;
			
			Header *new_header = new Header();
			new_header->dest_addr = header->src_addr;
			new_header->dest_port = header->src_port;
			new_header->src_addr = header->dest_addr;
			new_header->src_port = header->src_port;
			new_header->seq_num = socket->src_seq;
			new_header->ack_num = header->seq_num + 1;
			new_header->ack = 1;

			Packet *my_packet = allocatePacket(14 + 20 + 20);
			allocate_header(my_packet, new_header);

			sendPacket("IPv4", my_packet);

			socket->state = CLOSE_WAIT;
			socket->ack_num = new_header->ack_num;

			delete new_header;

			break;
		}

		case FIN_WAIT_1:
		{
			if (header->ack != 1)
				break;

			if (header->ack_num == socket->src_seq + 1)
			{
				socket->src_seq = header->ack_num;
				socket->state = FIN_WAIT_2;
			}

			break;
		}

		case FIN_WAIT_2:
		{
			if (header->fin != 1)
				break;

			Header *new_header = new Header();
			new_header->dest_addr = header->src_addr;
			new_header->dest_port = header->src_port;
			new_header->src_addr = header->dest_addr;
			new_header->src_port = header->dest_port;
			new_header->seq_num = socket->src_seq;
			new_header->ack_num = header->seq_num + 1;
			new_header->ack = 1;

			Packet *new_packet = allocatePacket(14 + 20 + 20);
			allocate_header(new_packet, new_header);
			
			sendPacket("IPv4", new_packet);

			socket->state = TIMED_WAIT;

			wait_list.push_back(socket);

			for (std::list<Socket*>::iterator it = socket_list.begin(); it != socket_list.end(); ++it)
			{
				if ((*it) == socket)
				{
					socket_list.erase(it);
					break;
				}
			}

			allocate_timer(2 * 100, socket);

			delete new_header;

			break;
		}

		case LAST_ACK:
		{
			if (header->ack != 1 || header->ack_num != socket->src_seq + 1)
				break;

			remove_socket(socket->pid, socket->fd);

			break;
		}
	}	

	freePacket(packet);
	delete header;
}

struct timer_elem* TCPAssignment::allocate_timer(int time, Socket *socket)
{
	struct timer_elem *te = (struct timer_elem *) malloc(sizeof(struct timer_elem));
	te->socket = socket;

	UUID timerUUID = addTimer(te, TimeUtil::makeTime(time, TimeUtil::MSEC));

	te->timerUUID = timerUUID;

	timer_list.push_back(te);
	return te;
}


void TCPAssignment::timerCallback(void* payload)
{
	struct timer_elem *te = (struct timer_elem *) payload;

	cancelTimer(te->timerUUID);
	free(te->socket->sa);
	removeFileDescriptor(te->socket->pid, te->socket->fd);

	for (std::list<Socket*>::iterator it = wait_list.begin(); it != wait_list.end(); ++it)
	{
		if ((*it) == te->socket)
		{
			wait_list.erase(it);
			delete te->socket;
			free(te);
			return;
		}
	}
}


}
