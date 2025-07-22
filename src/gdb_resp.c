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
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>

#include <sys/wait.h>

#include "gdb_arch.h"
#include "gdb_pkt.h"
#include "gdb_resp.h"
#include "gdb_sig.h"


#define STR_START_WITH(str, prefix) (!memcmp(str, prefix, strlen(prefix)))


/**
 * Keep track of the session state.
 **/
typedef struct gdb_session {
  pid_t pid;
  int fd;
  int sig;
  int stdio;
  intptr_t baseaddr;
} gdb_session_t;


/**
 * Help the client identify the target architecture.
 **/
static char target_xml[] = "<?xml version=\"1.0\"?>\n" \
  "<!DOCTYPE target SYSTEM \"gdb-target.dtd\">\n"
  "<target>\n"
  "<architecture>i386:x86-64</architecture>\n"
  "<osabi>none</osabi>\n"
  "</target>\n";


/**
 * Unescape binary data trasnmitted from gdb.
 **/
static int
gdb_bin_unescape(char *data, int len) {
  char *w = data;
  char *r = data;

  while(r-data < len) {
    char v = *r++;
    if(v != '}') {
      *w++ = v;
      continue;
    }
    *w++ = *r++ ^ 0x20;
  }

  return w - data;
}


/**
 * Convert a hexstring into its binary representation.
 **/
static int
gdb_hex2bin(const char* str, void* bin, size_t size) {
  int len = strlen(str);
  uint8_t* ptr = bin;
  int ch;

  if(len > size*2 || len%2) {
    return -1;
  }

  memset(bin, 0, size);
  for(int i=0; i<len; i+=2, ptr++) {
    if(sscanf(str+i, "%02x", &ch) != 1) {
      return -1;
    }
    *ptr = ch;
  }

  return 0;
}


/**
 * Flush stdout of the interior to the connecting client,
 * and look for Ctrl-c sequence from the client.
 **/
static int
gdb_response_stdio(gdb_session_t* sess) {
  struct pollfd fds[2];
  char buf[0x100];
  ssize_t len;
  int cnt = 1;

  memset(fds, 0, sizeof(fds));

  fds[0].fd = sess->fd;
  fds[0].events = POLLIN;

  fds[1].fd = sess->stdio;
  fds[1].events = POLLIN;

  if(fds[1].fd > 0) {
    cnt++;
  }

  switch(poll(fds, cnt, 1)) {
  case -1:
    if(gdb_pkt_notify_perror(sess->fd, "poll")) {
      perror("gdb_pkt_notify_perror");
    }
    return SIGSTOP;

  case 0:
    return 0;

  default:
    if(fds[0].revents & POLLIN) {
      if((len=read(sess->fd, buf, 1)) < 0) {
	perror("read");
	return SIGSTOP;
      }

      if(buf[0] == 3) {
	return SIGSTOP;
      }
    }

    if(fds[1].revents & POLLIN) {
      if((len=read(sess->stdio, buf, sizeof(buf))) < 0) {
	if(gdb_pkt_notify_perror(sess->fd, "read")) {
	  perror("gdb_pkt_notify_perror");
	}
	return SIGSTOP;
      }

      if(gdb_pkt_notify(sess->fd, buf, len) < 0) {
	if(errno == EINTR) {
	  return SIGSTOP;
	}

	perror("gdb_pkt_notify");
	return SIGSTOP;
      }
    }
  }

  return 0;
}



/**
 * Wait for a signal, and copy a gdb packet response to *data*.
 **/
static int
gdb_waitpid(gdb_session_t* sess, char* data, size_t size) {
  int status = 0;
  int res;

  while(1) {
    if((res=waitpid(sess->pid, &status, WNOHANG | WUNTRACED)) < 0) {
      return -1;
    }

    if(!res) {
      if((res=gdb_response_stdio(sess))) {
	kill(sess->pid, res);
      }
      continue;
    }

    if(WIFEXITED(status)) {
      snprintf(data, size, "W%02x", WEXITSTATUS(status));
      return 0;

    } else if(WIFSIGNALED(status)) {
      sess->sig = WTERMSIG(status);
      snprintf(data, size, "X%02x", gdb_sig_fromposix(sess->sig));
      return 0;

    } else if(WIFSTOPPED(status)) {
      sess->sig = WSTOPSIG(status);
      snprintf(data, size, "S%02x", gdb_sig_fromposix(sess->sig));
      return 0;
    }
  }

  return 0;
}


/**
 * Input pattern: '!'
 *
 * Enable extended mode. In extended mode, the remote server is made persistent.
 * The 'R' packet is used to restart the program being debugged.
 *
 * Reply:
 *   'OK' - The remote target both supports and has enabled extended mode.
 **/
static int
gdb_response_extended_mode(gdb_session_t* sess, const char* data, size_t size) {
  return gdb_pkt_puts(sess->fd, "OK");
}


/**
 * Input pattern: '?'
 *
 * This is sent when connection is first established to query the reason the
 * target halted. The reply is the same as for step and continue. This packet
 * has a special interpretation when the target is in non-stop mode; see Remote
 * Non-Stop.
 *
 * Reply:
 *   See Stop Reply Packets, for the reply specifications.
 **/
static int
gdb_response_getsig(gdb_session_t* sess, const char* data, size_t size) {
  int exit_code = 0;

  if(sess->pid > 0) {
    return gdb_pkt_printf(sess->fd, "S%02X", gdb_sig_fromposix(sess->sig));
  } else {
    return gdb_pkt_printf(sess->fd, "W%02X", exit_code);
  }
}


/**
 * Input pattern: 'c [addr]'
 *
 * Continue at addr, which is the address to resume. If addr is omitted, resume
 * at current address.
 *
 *  This packet is deprecated for multi-threading support. See vCont packet.
 *
 * Reply:
 *   See Stop Reply Packets, for the reply specifications.
 *
 * -----------------------------------------------------------------------------
 *
 * Input pattern: 'C sig[;addr]'
 *
 * Continue with signal sig (hex signal number). If ‘;addr’ is omitted, resume
 * at same address.
 *
 * This packet is deprecated for multi-threading support. See vCont packet.
 *
 * Reply:
 *   See Stop Reply Packets, for the reply specifications.
 **/
static int
gdb_response_continue(gdb_session_t* sess, const char* data, size_t size) {
  intptr_t addr = 0;
  char buf[32];
  int sig = 0;

  if(sscanf(data, "S%x;%lx", &sig, &addr) != 2) {
    if(sscanf(data, "S%x", &sig) != 1) {
      sscanf(data, "s%lx", &addr);
    }
  }

  sig = gdb_sig_toposix(sig);

  if(gdb_continue(sess->pid, addr, sig)) {
    return gdb_pkt_perror(sess->fd, "gdb_continue");
  }

  if(gdb_waitpid(sess, buf, sizeof(buf))) {
    return gdb_pkt_perror(sess->fd, "gdb_waitpid");
  }

  return gdb_pkt_puts(sess->fd, buf);
}


/**
 * Input pattern: 'D[;pid]'
 *
 * The first form of the packet is used to detach GDB from the remote system.
 * It is sent to the remote target before GDB disconnects via the detach
 * command.
 *
 * The second form, including a process ID, is used when multiprocess protocol
 * extensions are enabled (see multiprocess extensions), to detach only a
 * specific process. The pid is specified as a big-endian hex string.
 *
 * Reply:
    ‘OK’ for success
 **/
static int
gdb_response_detach(gdb_session_t* sess, const char* data, size_t size) {
  pid_t pid = sess->pid;

  if(sscanf(data, "D;%x", &pid) != 2){
    if(strcmp(data, "D")){
      return -1;
    }
  }

  if(gdb_detach(pid)) {
    return gdb_pkt_perror(sess->fd, "gdb_detach");
  }

  sess->pid = -1;

  return gdb_pkt_puts(sess->fd, "OK");
}


/**
 * Input pattern: 'g'
 *
 * Read general registers.
 *
 * Reply:
 *   XX...
 *
 * Each byte of register data is described by two hex digits. The bytes with
 * the register are transmitted in target byte order. The size of each register
 * and their position within the 'g' packet are determined by the target
 * description (see Target Descriptions); in the absence of a target
 * description, this is done using code internal to GDB; typically this is some
 * customary register layout for the architecture in question.
 *
 * When reading registers, the stub may also return a string of literal x's
 * in place of the register data digits, to indicate that the corresponding
 * register’s value is unavailable. For example, when reading registers from a
 * trace frame (see Using the Collected Data), this means that the register has
 * not been collected in the trace frame. When reading registers from a live
 * program, this indicates that the stub has no means to access the register
 * contents, even though the corresponding register is known to exist. Note
 * that if a register truly does not exist on the target, then it is better to
 * not include it in the target description in the first place.
 *
 * For example, for an architecture with 4 registers of 4 bytes each, the
 * following reply indicates to GDB that registers 0 and 2 are unavailable,
 * while registers 1 and 3 are available, and both have zero value:
 *
 *      -> g
 *      <- xxxxxxxx00000000xxxxxxxx00000000
 **/
static int
gdb_response_getregs(gdb_session_t* sess, const char* data, size_t size) {
  uint64_t gprmap[GDB_GPR_MAX];
  char buf[GDB_PKT_MAX_SIZE];
  char hex[17];

  if(gdb_getregs(sess->pid, gprmap)) {
    return gdb_pkt_perror(sess->fd, "gdb_getregs");
  }

  buf[0] = 0;
  for(int i=GDB_GPR_RAX; i<=GDB_GPR_RIP; i++) {
    sprintf(hex, "%016lx", __builtin_bswap64(gprmap[i]));
    strcat(buf, hex);
  }

  for(int i=GDB_GPR_EFLAGS; i<=GDB_GPR_GS; i++) {
    sprintf(hex, "%08x", __builtin_bswap32(gprmap[i]));
    strcat(buf, hex);
  }

  return gdb_pkt_puts(sess->fd, buf);
}


/**
 * Input pattern: 'G XX...'
 *
 * Write general registers. See read registers packet, for a description of
 * the XX... data.
 *
 * Reply:
 *   ‘OK’ for success
 **/
static int
gdb_response_setregs(gdb_session_t* sess, const char* data, size_t size) {
  uint64_t gprmap[GDB_GPR_MAX];

  data++;
  for(int i=GDB_GPR_RAX; i<=GDB_GPR_RIP; i++) {
    long val;
    if(sscanf(data, "%016lx", &val) != 1) {
      return -1;
    }
    data += 16;
    gprmap[i] = __builtin_bswap64(val);
  }

  for(int i=GDB_GPR_EFLAGS; i<=GDB_GPR_GS; i++) {
    int val;
    if(sscanf(data, "%08x", &val) != 1) {
      return -1;
    }
    data += 8;
    gprmap[i] = __builtin_bswap32(val);
  }

  if(gdb_setregs(sess->pid, gprmap)) {
    return gdb_pkt_perror(sess->fd, "gdb_setregs");
  }

  return gdb_pkt_puts(sess->fd, "OK");
}


/**
 * Input pattern: 'k'
 *
 * Kill request.
 *
 * The exact effect of this packet is not specified.
 *
 * For a bare-metal target, it may power cycle or reset the target system.
 * For that reason, the ‘k’ packet has no reply.
 *
 * For a single-process target, it may kill that process if possible.
 *
 * A multiple-process target may choose to kill just one process, or all that
 * are under GDB's control. For more precise control, use the vKill packet (see
 * vKill packet).
 *
 * If the target system immediately closes the connection in response to ‘k’,
 * GDB does not consider the lack of packet acknowledgment to be an error, and
 * assumes the kill was successful.
 *
 * If connected using target extended-remote, and the target does not close the
 * connection in response to a kill request, GDB probes the target state as if
 * a new connection was opened (see ? packet).
 **/
static int
gdb_response_kill(gdb_session_t* sess, const char* data, size_t size) {
  if(sess->pid < 0) {
    return gdb_pkt_puts(sess->fd, "");
  }

  if(kill(sess->pid, SIGTERM)) {
    return gdb_pkt_perror(sess->fd, "kill");
  }

  return -1;
}


/**
 * Input pattern: 'm addr,length'
 *
 * Read length addressable memory units starting at address addr (see
 * addressable memory unit). Note that addr may not be aligned to any particular
 * boundary.
 *
 * The stub need not use any particular size or alignment when gathering data
 * from memory for the response; even if addr is word-aligned and length is a
 * multiple of the word size, the stub is free to use byte accesses, or not.
 * For this reason, this packet may not be suitable for accessing memory-mapped
 * I/O devices.
 *
 * Reply:
 *   XX...
 *
 * Memory contents; each byte is transmitted as a two-digit hexadecimal number.
 * The reply may contain fewer addressable memory units than requested if the
 * server was able to read only part of the region of memory.
 *
 * Unlike most packets, this packet does not support ‘E.errtext’-style textual
 *error replies (see textual error reply).
 **/
static int
gdb_response_getmem(gdb_session_t* sess, const char* data, size_t size) {
  char dbuf[GDB_PKT_MAX_SIZE / 2];
  char sbuf[GDB_PKT_MAX_SIZE];
  intptr_t addr;
  char hex[17];
  size_t len;

  if(sscanf(data, "m%lx,%lx:", &addr, &len) != 2) {
    return -1;
  }

  if(sizeof(dbuf) <= len) {
    return -1;
  }

  if(gdb_copyout(sess->pid, addr, dbuf, len)) {
    return gdb_pkt_printf(sess->fd, "E%02X", errno);
  }

  sbuf[0] = 0;
  for(size_t i=0; i<len; i+=8) {
    long *word = (long*)&dbuf[i];
    sprintf(hex, "%016lx", __builtin_bswap64(*word));
    strcat(sbuf, hex);
  }
  sbuf[len*2] = 0;

  return gdb_pkt_puts(sess->fd, sbuf);
}


/**
 * Input pattern: 'M addr,length:XX...'
 *
 * Write length addressable memory units starting at address addr (see
 * addressable memory unit). The data is given by XX...; each byte is
 * transmitted as a two-digit hexadecimal number.
 *
 * Reply:
    'OK' - All the data was written successfully. (If only part of the
           data was written, this command returns an error.)
 **/
static int
gdb_response_setmem(gdb_session_t* sess, const char* data, size_t size) {
  char buf[GDB_PKT_MAX_SIZE / 2];
  intptr_t addr;
  size_t len;

  if(sscanf(data, "M%lx,%lx:", &addr, &len) != 2) {
    return gdb_pkt_printf(sess->fd, "E00");
  }

  if(!(data=strstr(data, ":"))) {
    return -1;
  }
  if(gdb_hex2bin(data+1, buf, sizeof(buf))) {
    return -1;
  }
  if(gdb_copyin(sess->pid, buf, addr, len)) {
    return gdb_pkt_printf(sess->fd, "E%02X", errno);
  }

  return gdb_pkt_puts(sess->fd, "OK");}


/**
 * Input pattern: 'p n'
 *
 * Read the value of register n; n is in hex. See read registers packet, for a
 * description of how the returned register value is encoded.
 *
 * Reply:
 *   XX... the register’s value
 **/
static int
gdb_response_getreg(gdb_session_t* sess, const char* data, size_t size) {
  enum gdb_gpr reg;
  uint64_t val;

  if(sscanf(data, "p%x", &reg) != 1){
    return -1;
  }

  if(gdb_getreg(sess->pid, reg, &val)) {
    return gdb_pkt_perror(sess->fd, "gdb_getreg");
  }

  if(reg <= GDB_GPR_RIP) {
    return gdb_pkt_printf(sess->fd, "%016lx", __builtin_bswap64(val));
  } else {
    return gdb_pkt_printf(sess->fd, "%08lx", __builtin_bswap32(val));
  }
}


/**
 * Input pattern: 'P n...=r...'
 *
 * Write register n... with value r..., where the register number n is in
 * hexadecimal and r... contains two hex digits for each byte in the
 * register (target byte order).
 *
 * Reply:
     'OK' for success
 **/
static int
gdb_response_setreg(gdb_session_t* sess, const char* data, size_t size) {
  enum gdb_gpr reg;
  uint64_t val;

  if(sscanf(data, "P%x=%lx", &reg, &val) != 2) {
    return -1;
  }

  if(reg <= GDB_GPR_RIP) {
    val = __builtin_bswap64(val);
  } else {
    val = __builtin_bswap32(val);
  }

  if(gdb_setreg(sess->pid, reg, val)) {
    return gdb_pkt_perror(sess->fd, "gdb_getreg");
  }

  return gdb_pkt_puts(sess->fd, "OK");
}




/**
 * Input pattern: 'qAttached:pid'
 *
 * Return an indication of whether the remote server attached to an existing
 * process or created a new process. When the multiprocess protocol extensions
 * are supported (see multiprocess extensions), pid is an integer in hexadecimal
 * format identifying the target process. Otherwise, GDB will omit the pid field
 * and the query packet will be simplified as 'qAttached'.
 *
 * This query is used, for example, to know whether the remote process should be
 * detached or killed when a GDB session is ended with the quit command.
 *
 * Reply:
    '1' - The remote server attached to an existing process.
    '0' - The remote server created a new process.
**/
static int
gdb_response_attached(gdb_session_t* sess, const char* data, size_t size) {
  return gdb_pkt_printf(sess->fd, "%d", sess->pid > 0);
}


/**
 * Input pattern: 'qOffsets'
 *
 * Get section offsets that the target used when relocating the downloaded image.
 *
 * Reply:
 *   'Text=xxx;Data=yyy;Bss=zzz'
 *
 * Relocate the Text section by xxx from its original address. Relocate the Data
 * section by yyy from its original address. If the object file format provides
 * segment information (e.g. ELF ‘PT_LOAD’ program headers), GDB will relocate
 * entire segments by the supplied offsets.
 *
 * Note: while a Bss offset may be included in the response, GDB ignores this
 * and instead applies the Data offset to the Bss section.
 *
 *   'TextSeg=xxx;DataSeg=yyy'
 *
 * Relocate the first segment of the object file, which conventionally contains
 * program code, to a starting address of xxx. If ‘DataSeg’ is specified,
 * relocate the second segment, which conventionally contains modifiable data,
 * to a starting address of yyy. GDB will report an error if the object file
 * does not contain segment information, or does not contain at least as many
 * segments as mentioned in the reply. Extra segments are kept at fixed offsets
 * relative to the last relocated segment.
 **/
static int
gdb_response_offsets(gdb_session_t* sess, const char* data, size_t size) {
  return gdb_pkt_printf(sess->fd, "Text=%lx;Data=%lx;Bss=%lx",
			sess->baseaddr, sess->baseaddr, sess->baseaddr);
}


/**
 * Input pattern 'qSupported:feature1;feeature2;...'
 *
 * Tell the remote stub about features supported by GDB, and query the stub for
 * features it supports. This packet allows GDB and the remote stub to take
 * advantage of each others’ features. ‘qSupported’ also consolidates multiple
 * feature probes at startup, to improve GDB performance—a single larger packet
 * performs better than multiple smaller probe packets on high-latency links.
 * Some features may enable behavior which must not be on by default, e.g.
 * because it would confuse older clients or stubs. Other features may describe
 * packets which could be automatically probed for, but are not. These features
 * must be reported before GDB will use them. This "default unsupported"
 * behavior is not appropriate for all packets, but it helps to keep the
 * initial connection time under control with new versions of GDB which support
 * increasing numbers of packets.
 *
 * Reply:
 *   feature1;feeature2;...;featureN
 *
 * The stub supports or does not support each returned stubfeature, depending
 * on the form of each stubfeature (see manual for the possible forms).
 **/
static int
gdb_response_supported(gdb_session_t* sess, const char* data, size_t size) {
  char s[GDB_PKT_MAX_SIZE];

  sprintf(s, "PacketSize=%x", GDB_PKT_MAX_SIZE-0x100);
  strcat(s, ";qXfer:features:read+");

  return gdb_pkt_puts(sess->fd, s);
}


/**
 * Input pattern: 'qXfer:features:read:annex:offset,length'
 *
 * Access the target description. See Target Descriptions. The annex specifies
 * which XML document to access. The main description is always loaded from the
 * 'target.xml' annex.
 *
 * This packet is not probed by default; the remote stub must request it,
 * by supplying an appropriate ‘qSupported’ response (see qSupported).
 **/
static int
gdb_response_transfer(gdb_session_t* sess, const char* data, size_t size) {
  if(STR_START_WITH(data, "qXfer:features:read:target.xml:")) {
    return gdb_pkt_printf(sess->fd, "l%s", target_xml);
  }

  return gdb_pkt_printf(sess->fd, "");
}


/**
 * Input pattern: 's [addr]'
 *
 * Single step, resuming at addr. If addr is omitted, resume at same address.
 *
 * This packet is deprecated for multi-threading support. See vCont packet.
 *
 * Reply:
 *   See Stop Reply Packets, for the reply specifications.
 *
 * -----------------------------------------------------------------------------
 *
 * Input pattern: 'S sig[;addr]'
 *
 * Step with signal. This is analogous to the 'C' packet, but requests a
 * single-step, rather than a normal resumption of execution.
 *
 * This packet is deprecated for multi-threading support. See vCont packet.
 *
 * Reply:
 *   See Stop Reply Packets, for the reply specifications.
 **/
static int
gdb_response_step(gdb_session_t* sess, const char* data, size_t size) {
  intptr_t addr = 0;
  char buf[32];
  int sig = 0;

  if(sscanf(data, "S%x;%lx", &sig, &addr) != 2) {
    if(sscanf(data, "S%x", &sig) != 1) {
      sscanf(data, "s%lx", &addr);
    }
  }

  sig = gdb_sig_toposix(sig);

  if(gdb_step(sess->pid, addr, sig)) {
    return gdb_pkt_perror(sess->fd, "gdb_step");
  }

  if(gdb_waitpid(sess, buf, sizeof(buf))) {
    return gdb_pkt_perror(sess->fd, "gdb_waitpid");
  }

  return gdb_pkt_puts(sess->fd, buf);
}


/**
 * Input pattern: 'vAttach;pid'
 *
 * Attach to a new process with the specified process ID pid. The process ID
 * is a hexadecimal integer identifying the process. In all-stop mode, all
 * threads in the attached process are stopped; in non-stop mode, it may be
 * attached without being stopped if that is supported by the target.
 *
 * This packet is only available in extended mode (see extended mode).
 *
 * Reply:
 *   'Any stop packet' - for success in all-stop mode (see Stop Reply Packets)
 *   ‘OK’ - for success in non-stop mode (see Remote Non-Stop) 
 **/
static int
gdb_response_attach(gdb_session_t* sess, const char* data, size_t size) {
  char buf[32];
  pid_t pid;

  if(sscanf(data, "vAttach;%x", &pid) != 1) {
    return -1;
  }

  if(gdb_attach(pid)) {
    return gdb_pkt_perror(sess->fd, "gdb_attach");
  }
  if(kill(pid, SIGSTOP)) {
    return gdb_pkt_perror(sess->fd, "kill");
  }

  sess->pid = pid;
  sess->stdio = -1;

  if(gdb_waitpid(sess, buf, sizeof(buf))) {
    return gdb_pkt_perror(sess->fd, "gdb_waitpid");
  }

  return gdb_pkt_puts(sess->fd, buf);
}


/**
 * Input pattern: 'vFile:setfs:pid'
 *
 * Select the filesystem on which vFile operations with filename arguments will
 * operate. This is required for GDB to be able to access files on remote
 * targets where the remote stub does not share a common filesystem with the
 * inferior(s).
 *
 * If pid is nonzero, select the filesystem as seen by process pid. If pid is
 * zero, select the filesystem as seen by the remote stub. Return 0 on success,
 * or -1 if an error occurs. If vFile:setfs: indicates success, the selected
 * filesystem remains selected until the next successful vFile:setfs: operation.
 **/
static int
gdb_response_setfs(gdb_session_t* sess, const char* data, size_t size) {
  return gdb_pkt_puts(sess->fd, "F0");
}


/**
 * Input pattern: 'vFile:open: filename, flags, mode'
 *
 * Open a file at filename and return a file descriptor for it, or return -1
 * if an error occurs. The filename is a string, flags is an integer indicating
 * a mask of open flags (see Open Flags), and mode is an integer indicating a
 * mask of mode bits to use if the file is created (see mode_t Values).
 * See open, for details of the open flags and mode values.
 **/
static int
gdb_response_fsopen(gdb_session_t* sess, const char* data, size_t size) {
  char buf[GDB_PKT_MAX_SIZE];
  char filename[PATH_MAX];
  char *tok;
  int flags;
  int mode;
  int fd;

  data += 11;
  strcpy(buf, data);
  if(!(tok=strstr(buf, ","))) {
    return -1;
  }
  *tok = 0;

  if(gdb_hex2bin(buf, filename, sizeof(filename))) {
    return -1;
  }
  if(sscanf(tok+1, "%x,%x", &flags, &mode) != 2) {
    return -1;
  }

  if((fd=open(filename, flags | O_CREAT, mode)) < 0) {
    return gdb_pkt_printf(sess->fd, "F-1,%x", errno);
  }

  return gdb_pkt_printf(sess->fd, "F%x", fd);
}


/**
 * Input pattern: 'vFile:close: fd'
 *
 * Close the open file corresponding to fd and return 0, or -1 if an
 * error occurs.
 **/
static int
gdb_response_fsclose(gdb_session_t* sess, const char* data, size_t size) {
  int fd;

  if(sscanf(data, "vFile:close:%x", &fd) != 1) {
    return -1;
  }

  if(close(fd)) {
    return gdb_pkt_printf(sess->fd, "F-1,%x", errno);
  } else {
    return gdb_pkt_puts(sess->fd, "F0");
  }
}


/**
 * Input pattern: 'vFile:pwrite: fd, offset, data'
 *
 * Write data (a binary buffer) to the open file corresponding to fd. Start the
 * write at offset from the start of the file. Unlike many write system calls,
 * there is no separate count argument; the length of data in the packet is
 * used. 'vFile:pwrite' returns the number of bytes written, which may be
 * shorter than the length of data, or -1 if an error occurred.
 **/
static int
gdb_response_fswrite(gdb_session_t* sess, const char* data, size_t size) {
  const char* tok;
  ssize_t len;
  off_t off = 0;
  void* buf;
  int fd;
  int r;

  if(sscanf(data, "vFile:pwrite:%x,%lx", &fd, &off) != 2) {
    return -1;
  }
  if(lseek(fd, off, SEEK_SET) == -1) {
    return gdb_pkt_printf(sess->fd, "F-1,%x", errno);
  }

  if(!(tok=strstr(data, ","))) {
    return -1;
  }
  if(!(tok=strstr(tok+1, ","))) {
    return -1;
  }

  tok += 1;
  if((len=(size-(size_t)(tok-data))) < 0) {
    return -1;
  }
  if(!(buf=malloc(len))) {
    return -1;
  }

  memcpy(buf, tok, len);
  len = gdb_bin_unescape(buf, len);

  if((len=write(fd, buf, len)) == -1) {
    r = gdb_pkt_printf(sess->fd, "F-1,%x", errno);
  } else {
    r = gdb_pkt_printf(sess->fd, "F%x", len);
  }

  free(buf);

  return r;
}


/**
 * Input pattern: 'vRun;filename[;argument]...'
 *
 * Run the program filename, passing it each argument on its command line.
 * The file and arguments are hex-encoded strings. If filename is an empty
 * string, the stub may use a default program (e.g. the last program run).
 * The program is created in the stopped state.
 *
 * This packet is only available in extended mode (see extended mode).
 *
 * Reply:
     Any stop packet for success (see Stop Reply Packets).
 **/
static int
gdb_response_run(gdb_session_t* sess, const char* data, size_t size) {
  char filename[PATH_MAX];
  char* argv[] = {filename, 0};
  int fds[2];

  data += 5;
  if(gdb_hex2bin(data, filename, sizeof(filename))) {
    return -1;
  }

  if(pipe(fds) == -1) {
    return gdb_pkt_perror(sess->fd, "pipe");
  }

  if(fcntl(fds[0], F_SETFL, O_NONBLOCK) == -1){
    close(fds[0]);
    close(fds[1]);
    return gdb_pkt_perror(sess->fd, "fcntl");
  }

  if((sess->pid=gdb_spawn(argv, fds[1], &sess->baseaddr)) < 0) {
    close(fds[0]);
    close(fds[1]);
    return gdb_pkt_printf(sess->fd, "X-1,%d", errno);
  }

  close(fds[1]);
  sess->sig = SIGSTOP;
  sess->stdio = fds[0];

  printf("Attached to PID: %d, ELF: %s\n", sess->pid, filename);

  return gdb_pkt_printf(sess->fd, "S%02X", gdb_sig_fromposix(sess->sig));
}


static int
gdb_response(void* ctx, const char* data, size_t size) {
  gdb_session_t* sess = (gdb_session_t*)ctx;

  switch(data[0]) {
  case '!':
    return gdb_response_extended_mode(sess, data, size);

  case '?':
    return gdb_response_getsig(sess, data, size);

  case 'c':
  case 'C':
    return gdb_response_continue(sess, data, size);

  case 'D':
    return gdb_response_detach(sess, data, size);

  case 'g':
    return gdb_response_getregs(sess, data, size);

  case 'G':
    return gdb_response_setregs(sess, data, size);

  case 'k':
    return gdb_response_kill(sess, data, size);

  case 'm':
    return gdb_response_getmem(sess, data, size);

  case 'M':
    return gdb_response_setmem(sess, data, size);

  case 'p':
    return gdb_response_getreg(sess, data, size);

  case 'P':
    return gdb_response_setreg(sess, data, size);

  case 'q':
    if(STR_START_WITH(data, "qAttached")) {
      return gdb_response_attached(sess, data, size);
    }
    if(!strcmp(data, "qOffsets")) {
      return gdb_response_offsets(sess, data, size);
    }
    if(STR_START_WITH(data, "qSupported")) {
      return gdb_response_supported(sess, data, size);
    }
    if(STR_START_WITH(data, "qXfer")) {
      return gdb_response_transfer(sess, data, size);
    }
    return gdb_pkt_puts(sess->fd, "");

  case 's':
  case 'S':
    return gdb_response_step(sess, data, size);

  case 'v':
    if(STR_START_WITH(data, "vAttach")) {
      return gdb_response_attach(sess, data, size);
    }
    if(STR_START_WITH(data, "vFile:setfs")) {
      return gdb_response_setfs(sess, data, size);
    }
    if(STR_START_WITH(data, "vFile:open")) {
      return gdb_response_fsopen(sess, data, size);
    }
    if(STR_START_WITH(data, "vFile:close")) {
      return gdb_response_fsclose(sess, data, size);
    }
    if(STR_START_WITH(data, "vFile:pwrite")) {
      return gdb_response_fswrite(sess, data, size);
    }
    if(STR_START_WITH(data, "vRun")) {
      return gdb_response_run(sess, data, size);
    }

  default:
    return gdb_pkt_puts(sess->fd, "");
  }

  return -1;
}


void
gdb_response_session(int fd) {
  gdb_session_t sess = {
    .fd = fd,
    .pid = -1,
    .sig = 0,
    .stdio = -1,
    .baseaddr = 0
  };

  while(1) {
    if(gdb_pkt_get(fd, gdb_response, &sess)) {
      break;
    }
  }

  if(sess.fd > 0) {
    close(sess.fd);
  }
  if(sess.stdio > 0) {
    close(sess.stdio);
  }
  if(sess.pid > 0) {
    kill(sess.pid, SIGKILL);
  }
}
