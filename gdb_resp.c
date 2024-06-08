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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/wait.h>

#include "pt.h"
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
} gdb_session_t;


/**
 * Help the client identify the target architecture.
 **/
static char target_xml[] = "<?xml version=\"1.0\"?>\n" \
  "<!DOCTYPE target SYSTEM \"gdb-target.dtd\">\n"
  "<target>\n"
  "<architecture>i386:x86-64</architecture>\n"
  "<osabi>GNU/Linux</osabi>\n" // TODO: remove osabi?
  "</target>\n";


/**
 * Wait for a signal and report it to the client.
 **/
static int
gdb_waitpid(gdb_session_t* sess, char* data, size_t size) {
  int status;

  if(waitpid(sess->pid, &status, WUNTRACED) < 0) {
    return -1;
  }

  if(WIFEXITED(status)) {
    snprintf(data, size, "W%02x", WEXITSTATUS(status));

  } else if(WIFSIGNALED(status)) {
    sess->sig = WTERMSIG(status);
    snprintf(data, size, "X%02x", gdb_sig_fromposix(sess->sig));

  } else if(WIFSTOPPED(status)) {
    sess->sig = WSTOPSIG(status);
    snprintf(data, size, "S%02x", gdb_sig_fromposix(sess->sig));
  }

  return 0;
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
  return gdb_pkt_printf(sess->fd, "S%02X", gdb_sig_fromposix(sess->sig));
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

  if(pt_continue(sess->pid, addr, sig)) {
    return gdb_pkt_perror(sess->fd, "pt_continue");
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

  if(pt_detach(pid)) {
    return gdb_pkt_perror(sess->fd, "pt_detach");
  }

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

  if(pt_getregs(sess->pid, gprmap)) {
    return gdb_pkt_perror(sess->fd, "pt_getregs");
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

  if(pt_setregs(sess->pid, gprmap)) {
    return gdb_pkt_perror(sess->fd, "pt_setregs");
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
  if(kill(sess->pid, SIGTERM)) {
    return gdb_pkt_perror(sess->fd, "kill");
  }

  close(sess->fd);
  exit(0);
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

  if(pt_copyout(sess->pid, addr, dbuf, len)) {
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

  data = strstr(data, ":") + 1;
  for(int i=0; i<len; i++) {
    int val;
    if(sscanf(data, "%02x", &val) != 1) {
      return -1;
    }
    data += 2;
    buf[i] = val;
  }

  if(pt_copyin(sess->pid, buf, addr, len)) {
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

  if(pt_getreg(sess->pid, reg, &val)) {
    return gdb_pkt_perror(sess->fd, "pt_getreg");
  }

  if(reg <= GDB_GPR_RIP) {
    return gdb_pkt_printf(sess->fd, "%016lx", __builtin_bswap64(val));
  } else {
    return gdb_pkt_printf(sess->fd, "%04lx", __builtin_bswap32(val));
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

  if(pt_setreg(sess->pid, reg, val)) {
    return gdb_pkt_perror(sess->fd, "pt_getreg");
  }

  return gdb_pkt_puts(sess->fd, "OK");
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
  intptr_t text_addr = 0;
  intptr_t data_addr = 0;
  intptr_t bss_addr = 0;

  // TODO: add needed parameters for implementing 'qOffsets'
  return gdb_pkt_printf(sess->fd, "");

  return gdb_pkt_printf(sess->fd, "Text=%lx;Data=%lx;Bss=%lx",
			text_addr, data_addr, bss_addr);
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

  sprintf(s, "PacketSize=%d", GDB_PKT_MAX_SIZE);
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

  if(pt_step(sess->pid, addr, sig)) {
    return gdb_pkt_perror(sess->fd, "pt_step");
  }

  if(gdb_waitpid(sess, buf, sizeof(buf))) {
    return gdb_pkt_perror(sess->fd, "gdb_waitpid");
  }

  return gdb_pkt_puts(sess->fd, buf);
}


/**
 *
 **/
static int
gdb_response(void* ctx, const char* data, size_t size) {
  gdb_session_t* sess = (gdb_session_t*)ctx;

  switch(data[0]) {
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

  default:
    return gdb_pkt_puts(sess->fd, "");
  }

  return -1;
}


void
gdb_response_session(int fd, pid_t pid) {
  gdb_session_t sess = {
    .fd = fd,
    .pid = pid,
    .sig = 0
  };

  while(1) {
    if(gdb_pkt_get(fd, gdb_response, &sess)) {
      break;
    }
  }

  kill(pid, SIGSTOP);
}
