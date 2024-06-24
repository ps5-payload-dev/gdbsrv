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

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/user.h>

#include "gdb_arch.h"


int
gdb_traceme(void) {
  return ptrace(PTRACE_TRACEME, 0, 0, 0);
}


int
gdb_attach(pid_t pid) {
  return ptrace(PTRACE_ATTACH, pid, 0, 0);
}


int
gdb_detach(pid_t pid) {
  if(ptrace(PTRACE_DETACH, pid, 0, 0) == -1) {
    return -1;
  }

  return 0;
}


int
gdb_step(int pid, intptr_t addr, int sig) {
  if(ptrace(PTRACE_SINGLESTEP, pid, addr, (void*)(long)sig) == -1) {
    return -1;
  }

  return 0;
}


int
gdb_continue(pid_t pid, intptr_t addr, int sig) {
  if(ptrace(PTRACE_CONT, pid, addr, (void*)(long)sig) == -1) {
    return -1;
  }

  return 0;
}


int
gdb_getregs(pid_t pid, uint64_t gprmap[GDB_GPR_MAX]) {
  struct user_regs_struct r;

  if(ptrace(PTRACE_GETREGS, pid, NULL, &r) == -1) {
    return -1;
  }

  gprmap[GDB_GPR_RAX] = r.rax;
  gprmap[GDB_GPR_RAX] = r.rax;
  gprmap[GDB_GPR_RBX] = r.rbx;
  gprmap[GDB_GPR_RCX] = r.rcx;
  gprmap[GDB_GPR_RDX] = r.rdx;
  gprmap[GDB_GPR_RSI] = r.rsi;
  gprmap[GDB_GPR_RDI] = r.rdi;
  gprmap[GDB_GPR_RBP] = r.rbp;
  gprmap[GDB_GPR_RSP] = r.rsp;
  gprmap[GDB_GPR_R8] = r.r8;
  gprmap[GDB_GPR_R9] = r.r9;
  gprmap[GDB_GPR_R10] = r.r10;
  gprmap[GDB_GPR_R11] = r.r11;
  gprmap[GDB_GPR_R12] = r.r12;
  gprmap[GDB_GPR_R13] = r.r13;
  gprmap[GDB_GPR_R14] = r.r14;
  gprmap[GDB_GPR_R15] = r.r15;
  gprmap[GDB_GPR_RIP] = r.rip;
  gprmap[GDB_GPR_EFLAGS] = r.eflags;
  gprmap[GDB_GPR_CS] = r.cs;
  gprmap[GDB_GPR_SS] = r.ss;
  gprmap[GDB_GPR_DS] = r.ds;
  gprmap[GDB_GPR_ES] = r.es;
  gprmap[GDB_GPR_FS] = r.fs;
  gprmap[GDB_GPR_GS] = r.gs;

  return 0;
}


int
gdb_setregs(pid_t pid, const uint64_t gprmap[GDB_GPR_MAX]) {
  struct user_regs_struct r;

  if(ptrace(PTRACE_GETREGS, pid, NULL, &r) == -1) {
    return -1;
  }

  r.rax = gprmap[GDB_GPR_RAX];
  r.rbx = gprmap[GDB_GPR_RBX];
  r.rcx = gprmap[GDB_GPR_RCX];
  r.rdx = gprmap[GDB_GPR_RDX];
  r.rsi = gprmap[GDB_GPR_RSI];
  r.rdi = gprmap[GDB_GPR_RDI];
  r.rbp = gprmap[GDB_GPR_RBP];
  r.rsp = gprmap[GDB_GPR_RSP];
  r.r8 = gprmap[GDB_GPR_R8];
  r.r9 = gprmap[GDB_GPR_R9];
  r.r10 = gprmap[GDB_GPR_R10];
  r.r11 = gprmap[GDB_GPR_R11];
  r.r12 = gprmap[GDB_GPR_R12];
  r.r13 = gprmap[GDB_GPR_R13];
  r.r14 = gprmap[GDB_GPR_R14];
  r.r15 = gprmap[GDB_GPR_R15];
  r.rip = gprmap[GDB_GPR_RIP];
  r.eflags = gprmap[GDB_GPR_EFLAGS];
  r.cs = gprmap[GDB_GPR_CS];
  r.ss = gprmap[GDB_GPR_SS];
  r.ds = gprmap[GDB_GPR_DS];
  r.es = gprmap[GDB_GPR_ES];
  r.fs = gprmap[GDB_GPR_FS];
  r.gs = gprmap[GDB_GPR_GS];

  if(ptrace(PTRACE_SETREGS, pid, NULL, &r) == -1) {
    return -1;
  }

  return 0;
}


int
gdb_setreg(pid_t pid, enum gdb_gpr reg, uint64_t val) {
  uint64_t gprmap[GDB_GPR_MAX];

  if(gdb_getregs(pid, gprmap)) {
    return -1;
  }

  gprmap[reg] = val;

  return gdb_setregs(pid, gprmap);
}


int
gdb_getreg(pid_t pid, enum gdb_gpr reg, uint64_t* val) {
  uint64_t gprmap[GDB_GPR_MAX];

  if(gdb_getregs(pid, gprmap)) {
    return -1;
  }

  *val = gprmap[reg];

  return 0;
}


static int
gdb_getlong(pid_t pid, intptr_t addr, long* val) {
  errno = 0;
  *val = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
  if(errno != 0) {
    return -1;
  }
  return 0;
}


static int
gdb_setlong(pid_t pid, intptr_t addr, long val) {
  return ptrace(PTRACE_POKEDATA, pid, addr, val);
}


int
gdb_copyout(pid_t pid, intptr_t addr, void* buf, size_t len) {
  long val;

  for(off_t i=0; i<len; i+=8) {
    if(gdb_getlong(pid, addr+i, &val)) {
      return -1;
    }
    if(len-i < 8) {
      memcpy(((char*)buf)+i, &val, len-i);
    } else {
      memcpy(((char*)buf)+i, &val, 8);
    }
  }

  return 0;
}


int gdb_copyin(pid_t pid, const void* buf, intptr_t addr, size_t len) {
  long val;

  for(off_t i=0; i<len; i+=8) {
    if(gdb_getlong(pid, addr+i, &val)) {
      return -1;
    }
    if(len-i < 8) {
      memcpy(&val, ((char*)buf)+i, len-i);
    } else {
      memcpy(&val, ((char*)buf)+i, 8);
    }
    if(gdb_setlong(pid, addr+i, val)) {
      return -1;
    }
  }

  return 0;
}


pid_t
gdb_spawn(char* argv[], int stdio, intptr_t* baseaddr) {
  pid_t pid;

  if(!(pid=fork())) {
    if(gdb_traceme()) {
      perror("gdb_traceme");
      _exit(-1);
    }

    for(int i=1; i<1000; i++) {
      if(i != stdio) {
	close(i);
      }
    }

    dup2(stdio, STDOUT_FILENO);
    dup2(stdio, STDERR_FILENO);

    return execve(argv[0], argv, 0);
  }

  if(waitpid(pid, 0, 0) == -1) {
    perror("waitpid");
    kill(pid, SIGKILL);
    gdb_detach(pid);
  }

  if(baseaddr) {
    *baseaddr = 0;
  }

  return pid;
}
