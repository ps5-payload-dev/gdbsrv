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
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "gdb_pkt.h"


/**
 * Lookup table with the hex charset.
 **/
static const char hexchars[] = "0123456789abcdef";


/**
 *
 **/
static int
gdb_hex(int c) {
  return
    ((c >= 'a') && (c <= 'f')) ? c - 'a' + 10 :
    ((c >= '0') && (c <= '9')) ? c - '0' :
    ((c >= 'A') && (c <= 'F')) ? c - 'A' + 10 : -1;
}


/**
 * Write a character to the given file descriptor.
 **/
static int
gdb_putchar(int fd, char c) {
  while(1) {
    switch(write(fd, &c, sizeof(c))) {
    case -1:
      if(EAGAIN != errno && EINTR != errno) return -1;
    case 0:
      continue;
    default:
      return 0;
    }
  }
}


/**
 * Read a character form the given file descriptor.
 **/
static int
gdb_getchar(int fd) {
  char c;

  while(1) {
    switch(read(fd, &c, sizeof(c))) {
    case -1:
      if(EAGAIN != errno && EINTR != errno) return -1;
    case 0:
      continue;
    default:
      return (c & 0xff);
    }
  }
}


/**
 * Wait for the start symbol of a gdb packet.
 **/
static int
gdb_pkt_sync(int fd) {
  int c;
  while(1) {
    c = gdb_getchar(fd);
    switch(c) {
    case '$':
      return 0;
    case -1:
      printf("sync: ignoring %02x\n", c);
      return -1;
    default:
      printf("sync: ignoring %02x\n", c);
      continue;
    }
  }
}


int
gdb_pkt_put(int fd, const char* data, size_t size) {
  uint8_t checksum = 0;
  int ch;

#if GDB_PKT_TRACE
  printf("rsp-out '%s'\n", data);
#endif

  if(gdb_putchar(fd, '$')) {
    return -1;
  }

  for(size_t i=0; i<size; i++) {
    ch = data[i];
    if(('$' == ch) || ('#' == ch) || ('*' == ch) || ('}' == ch)) {
      ch ^= 0x20;
      checksum += (uint8_t)'}';
      if(gdb_putchar(fd, '}')) {
	return -1;
      }
    }
    checksum += ch;

    if(gdb_putchar(fd, ch)) {
      return -1;
    }
  }

  if(gdb_putchar(fd, '#')) {
    return -1;
  }
  if(gdb_putchar(fd, hexchars[checksum >> 4])) {
    return -1;
  }
  if(gdb_putchar(fd, hexchars[checksum % 16])) {
    return -1;
  }
  if(gdb_getchar(fd) != '+') {
    return -1;
  }

  return 0;
}


int
gdb_pkt_puts(int fd, const char* str) {
  return gdb_pkt_put(fd, str, strlen(str));
}


int
gdb_pkt_printf(int fd, const char *fmt, ...) {
  char s[GDB_PKT_MAX_SIZE];
  va_list args;
  int res;

  va_start(args, fmt);
  res = vsnprintf(s, sizeof(s), fmt, args);
  va_end(args);

  if(res == sizeof(s)) {
    return -1;
  }

  return gdb_pkt_puts(fd, s);
}


int
gdb_pkt_perror(int fd, const char *str) {
  return gdb_pkt_printf(fd, "E.%s: %s", str, strerror(errno));
}


int
gdb_pkt_get(int fd, gdb_pkt_cb_t* cb, void* ctx) {
  char buf[GDB_PKT_MAX_SIZE];
  uint8_t checksum = 0;
  uint8_t xmitcsum = 0;
  off_t offset = 0;
  int ch = 0;

  if(gdb_pkt_sync(fd)) {
    return -1;
  }

  while(1) {
    if((ch=gdb_getchar(fd)) == -1) {
      return -1;
    }

    if('#' == ch) {
      break;
    }

    if(offset >= sizeof(buf)-1) {
      return -1;
    }

    checksum += (uint8_t)ch;
    buf[offset] = (char)ch;
    offset += 1;
  }
  buf[offset] = 0;
  if((ch=gdb_getchar(fd)) == -1) {
    return 0;
  }
  xmitcsum = gdb_hex(ch) << 4;

  if((ch=gdb_getchar(fd)) == -1) {
    return 0;
  }
  xmitcsum += gdb_hex(ch);

  if(checksum != xmitcsum) {
    gdb_putchar(fd, '-');
    return -1;
  }

#if GDB_PKT_TRACE
  printf("rsp-in '%s'\n", buf);
#endif

  gdb_putchar(fd, '+');
  return cb(ctx, buf, offset);
}
