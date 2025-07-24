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

#include <sys/types.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include <sys/socket.h>

#include "gdb_resp.h"


static void*
gdb_thread(void *args) {
  int fd = (int)(long)args;
  int optval = 1;

  if(setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&optval,
		sizeof (optval))) {
    perror("setsockopt");
    close(fd);
    return NULL;
  }

  optval = 1;
  if(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&optval,
		sizeof (optval))) {
    perror("setsockopt");
    close(fd);
    return NULL;
  }

  gdb_response_session(fd);
  close(fd);
  pthread_exit(NULL);

  return NULL;
}


int
gdb_serve(uint16_t port) {
  struct sockaddr_in server_addr;
  struct sockaddr_in client_addr;
  char ip[INET_ADDRSTRLEN];
  struct ifaddrs *ifaddr;
  int ifaddr_wait = 1;
  socklen_t addr_len;
  pthread_t trd;
  int connfd;
  int srvfd;

  if(getifaddrs(&ifaddr) == -1) {
    perror("getifaddrs");
    exit(EXIT_FAILURE);
  }

  signal(SIGPIPE, SIG_IGN);

  // Enumerate all AF_INET IPs
  for(struct ifaddrs *ifa=ifaddr; ifa!=NULL; ifa=ifa->ifa_next) {
    if(ifa->ifa_addr == NULL) {
      continue;
    }

    if(ifa->ifa_addr->sa_family != AF_INET) {
      continue;
    }

    // skip localhost
    if(!strncmp("lo", ifa->ifa_name, 2)) {
      continue;
    }

    struct sockaddr_in *in = (struct sockaddr_in*)ifa->ifa_addr;
    inet_ntop(AF_INET, &(in->sin_addr), ip, sizeof(ip));

    // skip interfaces without an ip
    if(!strncmp("0.", ip, 2)) {
      continue;
    }

    printf("Serving GDB on %s:%d (%s)\n", ip, port, ifa->ifa_name);
    ifaddr_wait = 0;
  }

  freeifaddrs(ifaddr);

  if(ifaddr_wait) {
    return 0;
  }

  if((srvfd=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket");
    return -1;
  }

  if(setsockopt(srvfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
    perror("setsockopt");
    return -1;
  }

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  server_addr.sin_port = htons(port);

  if(bind(srvfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
    perror("bind");
    return -1;
  }

  if(listen(srvfd, 5) != 0) {
    perror("listen");
    return -1;
  }

  addr_len = sizeof(client_addr);

  while(1) {
    if((connfd=accept(srvfd, (struct sockaddr*)&client_addr, &addr_len)) < 0) {
      perror("accept");
      break;
    }

    pthread_create(&trd, NULL, gdb_thread, (void*)(long)connfd);
  }

  return close(srvfd);
}

