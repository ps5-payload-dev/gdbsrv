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

#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include <ps5/kernel.h>

#include "pt.h"


static int
sys_ptrace(int request, pid_t pid, caddr_t addr, int data) {
  uint8_t privcaps[16] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                          0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
  pid_t mypid = getpid();
  uint8_t caps[16];
  uint64_t authid;
  int ret;

  if(!(authid=kernel_get_ucred_authid(mypid))) {
    return -1;
  }
  if(kernel_get_ucred_caps(mypid, caps)) {
    return -1;
  }

  if(kernel_set_ucred_authid(mypid, 0x4800000000010003l)) {
    return -1;
  }
  if(kernel_set_ucred_caps(mypid, privcaps)) {
    return -1;
  }

  ret = (int)__syscall(SYS_ptrace, request, pid, addr, data);

  if(kernel_set_ucred_authid(mypid, authid)) {
    return -1;
  }
  if(kernel_set_ucred_caps(mypid, caps)) {
    return -1;
  }

  return ret;
}


intptr_t
pt_resolve(pid_t pid, const char* nid) {
  intptr_t addr;

  if((addr=kernel_dynlib_resolve(pid, 0x1, nid))) {
    return addr;
  }

  return kernel_dynlib_resolve(pid, 0x2001, nid);
}


int
pt_trace_me(void) {
  return sys_ptrace(PT_TRACE_ME, 0, 0, 0);
}


int
pt_attach(pid_t pid) {
  if(sys_ptrace(PT_ATTACH, pid, 0, 0)) {
    return -1;
  }

  return 0;
}


int
pt_detach(pid_t pid) {
  if(sys_ptrace(PT_DETACH, pid, 0, 0)) {
    return -1;
  }

  return 0;
}


int
pt_step(int pid) {
  if(sys_ptrace(PT_STEP, pid, (caddr_t)1, 0)) {
    return -1;
  }

  if(waitpid(pid, 0, 0) < 0) {
    return -1;
  }

  return 0;
}


int
pt_continue(pid_t pid, int sig) {
  if(sys_ptrace(PT_CONTINUE, pid, (caddr_t)1, sig)) {
    return -1;
  }

  return 0;
}


int
pt_getregs(pid_t pid, struct reg *r) {
  return sys_ptrace(PT_GETREGS, pid, (caddr_t)r, 0);
}


int
pt_setregs(pid_t pid, const struct reg *r) {
  return sys_ptrace(PT_SETREGS, pid, (caddr_t)r, 0);
}


int
pt_copyout(pid_t pid, intptr_t addr, void* buf, size_t len) {
  int prot = kernel_get_vmem_protection(pid, addr, len);
  struct ptrace_io_desc iod = {
    .piod_op = PIOD_READ_D,
    .piod_offs = (void*)addr,
    .piod_addr = buf,
    .piod_len = len};
  int ret;

  kernel_set_vmem_protection(pid, addr, len, prot | PROT_READ);
  ret = sys_ptrace(PT_IO, pid, (caddr_t)&iod, 0);
  kernel_set_vmem_protection(pid, addr, len, prot);

  return ret;
}


int
pt_copyin(pid_t pid, const void* buf, intptr_t addr, size_t len) {
  int prot = kernel_get_vmem_protection(pid, addr, len);
  struct ptrace_io_desc iod = {
    .piod_op = PIOD_WRITE_D,
    .piod_offs = (void*)addr,
    .piod_addr = (void*)buf,
    .piod_len = len};
  int ret;

  kernel_set_vmem_protection(pid, addr, len, prot | PROT_READ | PROT_WRITE);
  ret = sys_ptrace(PT_IO, pid, (caddr_t)&iod, 0);
  kernel_set_vmem_protection(pid, addr, len, prot);

  return ret;
}


int
pt_setchar(pid_t pid, intptr_t addr, char val) {
  return pt_copyin(pid, &val, addr, sizeof(val));
}


int
pt_setshort(pid_t pid, intptr_t addr, short val) {
  return pt_copyin(pid, &val, addr, sizeof(val));
}


int
pt_setint(pid_t pid, intptr_t addr, int val) {
  return pt_copyin(pid, &val, addr, sizeof(val));
}


int
pt_setlong(pid_t pid, intptr_t addr, long val) {
  return pt_copyin(pid, &val, addr, sizeof(val));
}



char
pt_getchar(pid_t pid, intptr_t addr) {
  char val = 0;

  pt_copyout(pid, addr, &val, sizeof(val));

  return val;
}


short
pt_getshort(pid_t pid, intptr_t addr) {
  short val = 0;

  pt_copyout(pid, addr, &val, sizeof(val));

  return val;
}


int
pt_getint(pid_t pid, intptr_t addr) {
  int val = 0;

  pt_copyout(pid, addr, &val, sizeof(val));

  return val;
}


long
pt_getlong(pid_t pid, intptr_t addr) {
  long val = 0;

  pt_copyout(pid, addr, &val, sizeof(val));

  return val;
}


long
pt_call(pid_t pid, intptr_t addr, ...) {
  struct reg jmp_reg;
  struct reg bak_reg;
  va_list ap;

  if(pt_getregs(pid, &bak_reg)) {
    return -1;
  }

  memcpy(&jmp_reg, &bak_reg, sizeof(jmp_reg));
  jmp_reg.r_rip = addr;

  va_start(ap, addr);
  jmp_reg.r_rdi = va_arg(ap, uint64_t);
  jmp_reg.r_rsi = va_arg(ap, uint64_t);
  jmp_reg.r_rdx = va_arg(ap, uint64_t);
  jmp_reg.r_rcx = va_arg(ap, uint64_t);
  jmp_reg.r_r8  = va_arg(ap, uint64_t);
  jmp_reg.r_r9  = va_arg(ap, uint64_t);
  va_end(ap);

  if(pt_setregs(pid, &jmp_reg)) {
    return -1;
  }

  // single step until the function returns
  while(jmp_reg.r_rsp <= bak_reg.r_rsp) {
    if(pt_step(pid)) {
      return -1;
    }
    if(pt_getregs(pid, &jmp_reg)) {
      return -1;
    }
  }

  // restore registers
  if(pt_setregs(pid, &bak_reg)) {
    return -1;
  }

  return jmp_reg.r_rax;
}


long
pt_syscall(pid_t pid, int sysno, ...) {
  intptr_t addr = pt_resolve(pid, "HoLVWNanBBc");
  struct reg jmp_reg;
  struct reg bak_reg;
  va_list ap;

  if(!addr) {
    return -1;
  } else {
    addr += 0xa;
  }

  if(pt_getregs(pid, &bak_reg)) {
    return -1;
  }

  memcpy(&jmp_reg, &bak_reg, sizeof(jmp_reg));
  jmp_reg.r_rip = addr;
  jmp_reg.r_rax = sysno;

  va_start(ap, sysno);
  jmp_reg.r_rdi = va_arg(ap, uint64_t);
  jmp_reg.r_rsi = va_arg(ap, uint64_t);
  jmp_reg.r_rdx = va_arg(ap, uint64_t);
  jmp_reg.r_r10 = va_arg(ap, uint64_t);
  jmp_reg.r_r8  = va_arg(ap, uint64_t);
  jmp_reg.r_r9  = va_arg(ap, uint64_t);
  va_end(ap);

  if(pt_setregs(pid, &jmp_reg)) {
    return -1;
  }

  // single step until the function returns
  while(jmp_reg.r_rsp <= bak_reg.r_rsp) {
    if(pt_step(pid)) {
      return -1;
    }
    if(pt_getregs(pid, &jmp_reg)) {
      return -1;
    }
  }

  // restore registers
  if(pt_setregs(pid, &bak_reg)) {
    return -1;
  }

  return jmp_reg.r_rax;
}


intptr_t
pt_mmap(pid_t pid, intptr_t addr, size_t len, int prot, int flags,
	int fd, off_t off) {
  return pt_syscall(pid, SYS_mmap, addr, len, prot, flags, fd, off);
}


int
pt_msync(pid_t pid, intptr_t addr, size_t len, int flags) {
  return pt_syscall(pid, SYS_msync, addr, len, flags);
}


int
pt_munmap(pid_t pid, intptr_t addr, size_t len) {
  return pt_syscall(pid, SYS_munmap, addr, len);
}


int
pt_mprotect(pid_t pid, intptr_t addr, size_t len, int prot) {
  return pt_syscall(pid, SYS_mprotect, addr, len, prot);
}


int
pt_socket(pid_t pid, int domain, int type, int protocol) {
  return (int)pt_syscall(pid, SYS_socket, domain, type, protocol);
}


int
pt_setsockopt(pid_t pid, int fd, int level, int optname, intptr_t optval,
	      socklen_t optlen) {
  return (int)pt_syscall(pid, SYS_setsockopt, fd, level, optname, optval,
			 optlen, 0);
}

int
pt_bind(pid_t pid, int sockfd, intptr_t addr, socklen_t addrlen) {
  return (int)pt_syscall(pid, SYS_bind, sockfd, addr, addrlen);
}


ssize_t
pt_recvmsg(pid_t pid, int fd, intptr_t msg, int flags) {
  return (int)pt_syscall(pid, SYS_recvmsg, fd, msg, flags);
}


int
pt_close(pid_t pid, int fd) {
  return (int)pt_syscall(pid, SYS_close, fd);
}


int
pt_dup2(pid_t pid, int oldfd, int newfd) {
  return (int)pt_syscall(pid, SYS_dup2, oldfd, newfd);
}


int
pt_rdup(pid_t pid, pid_t other_pid, int fd) {
  return (int)pt_syscall(pid, 0x25b, other_pid, fd);
}


int
pt_pipe(pid_t pid, intptr_t pipefd) {
  intptr_t faddr = pt_resolve(pid, "-Jp7F+pXxNg");
  return (int)pt_call(pid, faddr, pipefd);
}


void
pt_perror(pid_t pid, const char *s) {
  intptr_t faddr = pt_resolve(pid, "9BcDykPmo1I");
  intptr_t addr = pt_call(pid, faddr);
  int err = pt_getint(pid, addr);
  char buf[255];

  strcpy(buf, s);
  strcat(buf, ": ");
  strcat(buf, strerror(err));
  puts(buf);
}


intptr_t
pt_sceKernelGetProcParam(pid_t pid) {
  intptr_t faddr = pt_resolve(pid, "959qrazPIrg");

  return pt_call(pid, faddr);
}

intptr_t
pt_getargv(pid_t pid) {
  intptr_t faddr = pt_resolve(pid, "FJmglmTMdr4");

  return pt_call(pid, faddr);
}
