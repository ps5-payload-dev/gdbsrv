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

#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/syscall.h>
#include <sys/sysctl.h>

#include <ps5/kernel.h>
#include <ps5/klog.h>

#include "gdb_serve.h"


typedef struct notify_request {
  char useless1[45];
  char message[3075];
} notify_request_t;


int sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);


/**
 * Fint the pid of a process with the given name.
 **/
static pid_t
find_pid(const char* name) {
  int mib[4] = {1, 14, 8, 0};
  pid_t mypid = getpid();
  pid_t pid = -1;
  size_t buf_size;
  uint8_t *buf;

  if(sysctl(mib, 4, 0, &buf_size, 0, 0)) {
    perror("sysctl");
    return -1;
  }

  if(!(buf=malloc(buf_size))) {
    perror("malloc");
    return -1;
  }

  if(sysctl(mib, 4, buf, &buf_size, 0, 0)) {
    perror("sysctl");
    free(buf);
    return -1;
  }

  for(uint8_t *ptr=buf; ptr<(buf+buf_size);) {
    int ki_structsize = *(int*)ptr;
    pid_t ki_pid = *(pid_t*)&ptr[72];
    char *ki_tdname = (char*)&ptr[447];

    ptr += ki_structsize;
    if(!strcmp(name, ki_tdname) && ki_pid != mypid) {
      pid = ki_pid;
    }
  }

  free(buf);

  return pid;
}


int main(int argc, char** argv, char** envp) {
  notify_request_t req;
  uint16_t port = 2159;
  pid_t pid;

  syscall(SYS_thr_set_name, -1, "gdbsrv.elf");

  printf("Socket server was compiled at %s %s\n", __DATE__, __TIME__);
  klog_printf("Socket server was compiled at %s %s\n", __DATE__, __TIME__);

  while((pid=find_pid("gdbsrv.elf")) > 0) {
    if(kill(pid, SIGKILL)) {
      perror("kill");
      exit(-1);
    }
    sleep(1);
  }

  bzero(&req, sizeof req);
  strncpy(req.message, "Serving GDB on port 2159", sizeof req.message);
  sceKernelSendNotificationRequest(0, &req, sizeof req, 0);

  while(1) {
    gdb_serve(port);
    sleep(3);
  }

  return 0;
}
