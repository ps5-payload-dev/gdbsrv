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
#include <sys/syscall.h>
#include <sys/wait.h>

#include <ps5/kernel.h>
#include <ps5/mdbg.h>

#include "gdb_arch.h"


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

  ret = (int)syscall(SYS_ptrace, request, pid, addr, data);

  if(kernel_set_ucred_authid(mypid, authid)) {
    return -1;
  }
  if(kernel_set_ucred_caps(mypid, caps)) {
    return -1;
  }

  return ret;
}


int
gdb_traceme(void) {
  return sys_ptrace(PT_TRACE_ME, 0, 0, 0);
}


int
gdb_attach(pid_t pid) {
  if(sys_ptrace(PT_ATTACH, pid, 0, 0) == -1) {
    return -1;
  }

  if(waitpid(pid, 0, 0) == -1) {
    return -1;
  }

  return 0;
}


int
gdb_detach(pid_t pid) {
  if(sys_ptrace(PT_DETACH, pid, 0, 0) == -1) {
    return -1;
  }

  return 0;
}


int
gdb_step(int pid, intptr_t addr, int sig) {
  if(!addr) {
    addr = 1;
  }

  if(sys_ptrace(PT_STEP, pid, (caddr_t)addr, 0)) {
    return -1;
  }

  return 0;
}


int
gdb_continue(pid_t pid, intptr_t addr, int sig) {
  if(!addr) {
    addr = 1;
  }

  if(sys_ptrace(PT_CONTINUE, pid, (caddr_t)addr, sig) == -1) {
    return -1;
  }

  return 0;
}


int
gdb_getregs(pid_t pid, uint64_t gprmap[GDB_GPR_MAX]) {
  struct reg r;

  if(ptrace(PT_GETREGS, pid, (caddr_t)&r, 0) == -1) {
    return -1;
  }

  gprmap[GDB_GPR_RAX] = r.r_rax;
  gprmap[GDB_GPR_RAX] = r.r_rax;
  gprmap[GDB_GPR_RBX] = r.r_rbx;
  gprmap[GDB_GPR_RCX] = r.r_rcx;
  gprmap[GDB_GPR_RDX] = r.r_rdx;
  gprmap[GDB_GPR_RSI] = r.r_rsi;
  gprmap[GDB_GPR_RDI] = r.r_rdi;
  gprmap[GDB_GPR_RBP] = r.r_rbp;
  gprmap[GDB_GPR_RSP] = r.r_rsp;
  gprmap[GDB_GPR_R8] = r.r_r8;
  gprmap[GDB_GPR_R9] = r.r_r9;
  gprmap[GDB_GPR_R10] = r.r_r10;
  gprmap[GDB_GPR_R11] = r.r_r11;
  gprmap[GDB_GPR_R12] = r.r_r12;
  gprmap[GDB_GPR_R13] = r.r_r13;
  gprmap[GDB_GPR_R14] = r.r_r14;
  gprmap[GDB_GPR_R15] = r.r_r15;
  gprmap[GDB_GPR_RIP] = r.r_rip;
  gprmap[GDB_GPR_EFLAGS] = r.r_rflags;
  gprmap[GDB_GPR_CS] = r.r_cs;
  gprmap[GDB_GPR_SS] = r.r_ss;
  gprmap[GDB_GPR_DS] = r.r_ds;
  gprmap[GDB_GPR_ES] = r.r_es;
  gprmap[GDB_GPR_FS] = r.r_fs;
  gprmap[GDB_GPR_GS] = r.r_gs;

  return 0;
}

int
gdb_setregs(pid_t pid, const uint64_t gprmap[GDB_GPR_MAX]) {
  struct reg r;

  if(ptrace(PT_GETREGS, pid, (caddr_t)&r, 0) == -1) {
    return -1;
  }

  r.r_rax = gprmap[GDB_GPR_RAX];
  r.r_rbx = gprmap[GDB_GPR_RBX];
  r.r_rcx = gprmap[GDB_GPR_RCX];
  r.r_rdx = gprmap[GDB_GPR_RDX];
  r.r_rsi = gprmap[GDB_GPR_RSI];
  r.r_rdi = gprmap[GDB_GPR_RDI];
  r.r_rbp = gprmap[GDB_GPR_RBP];
  r.r_rsp = gprmap[GDB_GPR_RSP];
  r.r_r8 = gprmap[GDB_GPR_R8];
  r.r_r9 = gprmap[GDB_GPR_R9];
  r.r_r10 = gprmap[GDB_GPR_R10];
  r.r_r11 = gprmap[GDB_GPR_R11];
  r.r_r12 = gprmap[GDB_GPR_R12];
  r.r_r13 = gprmap[GDB_GPR_R13];
  r.r_r14 = gprmap[GDB_GPR_R14];
  r.r_r15 = gprmap[GDB_GPR_R15];
  r.r_rip = gprmap[GDB_GPR_RIP];
  r.r_rflags = gprmap[GDB_GPR_EFLAGS];
  r.r_cs = gprmap[GDB_GPR_CS];
  r.r_ss = gprmap[GDB_GPR_SS];
  r.r_ds = gprmap[GDB_GPR_DS];
  r.r_es = gprmap[GDB_GPR_ES];
  r.r_fs = gprmap[GDB_GPR_FS];
  r.r_gs = gprmap[GDB_GPR_GS];

  if(ptrace(PT_SETREGS, pid, (caddr_t)&r, 0) == -1) {
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


int
gdb_copyin(pid_t pid, const void* buf, intptr_t addr, size_t len) {
  return mdbg_copyin(pid, buf, addr, len);
}


int
gdb_copyout(pid_t pid, intptr_t addr, void* buf, size_t len) {
  return mdbg_copyout(pid, addr, buf, len);
}


int
gdb_spawn(char* filename) {
  char* argv[] = {filename, 0};
  pid_t pid = fork();

  if(!pid) {
    if(gdb_traceme()) {
      _exit(-1);
    }

    return execve(filename, argv, 0);
  }

  return pid;
}

