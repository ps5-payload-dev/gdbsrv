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

#define GDB_SIGNAL_HUP    1
#define GDB_SIGNAL_INT    2
#define GDB_SIGNAL_QUIT   3
#define GDB_SIGNAL_ILL    4
#define GDB_SIGNAL_TRAP   5
#define GDB_SIGNAL_ABRT   6
#define GDB_SIGNAL_EMT    7
#define GDB_SIGNAL_FPE    8
#define GDB_SIGNAL_KILL   9
#define GDB_SIGNAL_BUS    10
#define GDB_SIGNAL_SEGV   11
#define GDB_SIGNAL_SYS    12
#define GDB_SIGNAL_PIPE   13
#define GDB_SIGNAL_ALRM   14
#define GDB_SIGNAL_TERM   15
#define GDB_SIGNAL_URG    16
#define GDB_SIGNAL_STOP   17
#define GDB_SIGNAL_TSTP   18
#define GDB_SIGNAL_CONT   19
#define GDB_SIGNAL_CHLD   20
#define GDB_SIGNAL_TTIN   21
#define GDB_SIGNAL_TTOU   22
#define GDB_SIGNAL_IO     23
#define GDB_SIGNAL_XCPU   24
#define GDB_SIGNAL_XFSZ   25
#define GDB_SIGNAL_VTALRM 26
#define GDB_SIGNAL_PROF   27
#define GDB_SIGNAL_WINCH  28
#define GDB_SIGNAL_LOST   29
#define GDB_SIGNAL_USR1   30
#define GDB_SIGNAL_USR2   31


int gdb_sig_toposix(int gdb_sig) {
  switch(gdb_sig) {
  case GDB_SIGNAL_HUP:    return SIGHUP;
  case GDB_SIGNAL_INT:    return SIGINT;
  case GDB_SIGNAL_QUIT:   return SIGQUIT;
  case GDB_SIGNAL_ILL:    return SIGILL;
  case GDB_SIGNAL_TRAP:   return SIGTRAP;
  case GDB_SIGNAL_ABRT:   return SIGABRT;
  case GDB_SIGNAL_FPE:    return SIGFPE;
  case GDB_SIGNAL_KILL:   return SIGKILL;
  case GDB_SIGNAL_BUS:    return SIGBUS;
  case GDB_SIGNAL_SEGV:   return SIGSEGV;
  case GDB_SIGNAL_SYS:    return SIGSYS;
  case GDB_SIGNAL_PIPE:   return SIGPIPE;
  case GDB_SIGNAL_ALRM:   return SIGALRM;
  case GDB_SIGNAL_TERM:   return SIGTERM;
  case GDB_SIGNAL_URG:    return SIGURG;
  case GDB_SIGNAL_STOP:   return SIGSTOP;
  case GDB_SIGNAL_TSTP:   return SIGTSTP;
  case GDB_SIGNAL_CONT:   return SIGCONT;
  case GDB_SIGNAL_CHLD:   return SIGCHLD;
  case GDB_SIGNAL_TTIN:   return SIGTTIN;
  case GDB_SIGNAL_TTOU:   return SIGTTOU;
  case GDB_SIGNAL_IO:     return SIGIO;
  case GDB_SIGNAL_XCPU:   return SIGXCPU;
  case GDB_SIGNAL_XFSZ:   return SIGXFSZ;
  case GDB_SIGNAL_VTALRM: return SIGVTALRM;
  case GDB_SIGNAL_PROF:   return SIGPROF;
  case GDB_SIGNAL_WINCH:  return SIGWINCH;
  case GDB_SIGNAL_USR1:   return SIGUSR1;
  case GDB_SIGNAL_USR2:   return SIGUSR2;
  default:                return 0;
  }
}


int gdb_sig_fromposix(int posix_sig) {
  switch(posix_sig) {
  case SIGHUP:    return GDB_SIGNAL_HUP;
  case SIGINT:    return GDB_SIGNAL_INT;
  case SIGQUIT:   return GDB_SIGNAL_QUIT;
  case SIGILL:    return GDB_SIGNAL_ILL;
  case SIGTRAP:   return GDB_SIGNAL_TRAP;
  case SIGABRT:   return GDB_SIGNAL_ABRT;
  case SIGFPE:    return GDB_SIGNAL_FPE;
  case SIGKILL:   return GDB_SIGNAL_KILL;
  case SIGBUS:    return GDB_SIGNAL_BUS;
  case SIGSEGV:   return GDB_SIGNAL_SEGV;
  case SIGSYS:    return GDB_SIGNAL_SYS;
  case SIGPIPE:   return GDB_SIGNAL_PIPE;
  case SIGALRM:   return GDB_SIGNAL_ALRM;
  case SIGTERM:   return GDB_SIGNAL_TERM;
  case SIGURG:    return GDB_SIGNAL_URG;
  case SIGSTOP:   return GDB_SIGNAL_STOP;
  case SIGTSTP:   return GDB_SIGNAL_TSTP;
  case SIGCONT:   return GDB_SIGNAL_CONT;
  case SIGCHLD:   return GDB_SIGNAL_CHLD;
  case SIGTTIN:   return GDB_SIGNAL_TTIN;
  case SIGTTOU:   return GDB_SIGNAL_TTOU;
  case SIGIO:     return GDB_SIGNAL_IO;
  case SIGXCPU:   return GDB_SIGNAL_XCPU;
  case SIGXFSZ:   return GDB_SIGNAL_XFSZ;
  case SIGVTALRM: return GDB_SIGNAL_VTALRM;
  case SIGPROF:   return GDB_SIGNAL_PROF;
  case SIGWINCH:  return GDB_SIGNAL_WINCH;
  case SIGUSR1:   return GDB_SIGNAL_USR1;
  case SIGUSR2:   return GDB_SIGNAL_USR2;
  default:        return 0;
  }
}
