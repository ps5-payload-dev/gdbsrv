/* Copyright (C) 2024 John Törnblom

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include <sys/socket.h>

#include "gdb_resp.h"


/**
 * Accept TCP connections.
 **/
static int
gdb_conn_accept(uint16_t port) {
  struct sockaddr_in sock_addr;
  socklen_t len;
  int optval;
  int srvfd;
  int fd;

  if((srvfd=socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
    perror("socket");
    return -1;
  }

  optval = 1;
  setsockopt(srvfd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval,
	     sizeof (optval));

  sock_addr.sin_family = PF_INET;
  sock_addr.sin_port = htons(port);
  sock_addr.sin_addr.s_addr = INADDR_ANY;
  if(bind(srvfd, (struct sockaddr *) &sock_addr, sizeof (sock_addr))) {
    perror("bind");
    close(srvfd);
    return -1;
  }

  if(listen(srvfd, 1)) {
    perror("listen");
    close(srvfd);
    return -1;
  }

  len = sizeof(socklen_t);
  if((fd=accept(srvfd, (struct sockaddr *)&sock_addr, &len)) < 0) {
    perror("accept");
    close(srvfd);
    return -1;
  }

  optval = 1;
  setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&optval,
	     sizeof (optval));

  optval = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&optval,
	     sizeof (optval));

  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | FASYNC);
  fcntl(fd, F_SETOWN, getpid());

  close(srvfd);

  return fd;
}


int
gdb_serve(uint16_t port) {
  int fd;

  printf("serving gdb on port %d\n", port);
  signal(SIGPIPE, SIG_IGN);

  while(1) {
    if((fd=gdb_conn_accept(port)) < 0) {
      sleep(3);
      continue;
    }

    printf("Starting session for fd %d\n", fd);
    gdb_response_session(fd);
    close(fd);
  }

  return 0;
}

