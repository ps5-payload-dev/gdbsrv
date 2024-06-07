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

#pragma once

#include <stddef.h>


/**
 * Maximum size of packets.
 **/
#define GDB_PKT_MAX_SIZE 0x4000


/**
 * Callback prototype for gdb packet responses.
 **/
typedef int (gdb_pkt_cb_t)(void* ctx, const char* data, size_t size);


/**
 * Read a gdb packet from the given file descriptor, and pass it along
 * to the response callback function.
 **/
int gdb_pkt_get(int fd, gdb_pkt_cb_t* cb, void* ctx);


/**
 * Respond with a gdb packet containg data of the given size.
 **/
int gdb_pkt_put(int fd, const char* data, size_t size);


/**
 * Respond with a gdb packet containg the given string.
 **/
int gdb_pkt_puts(int fd, const char* str);


/**
 * Respond with a gdb packet as a string with the given format.
 **/
int gdb_pkt_printf(int fd, const char* fmt, ...);


/**
 * Respond with a gdb packet as a strerror() string.
 **/
int gdb_pkt_perror(int fd, const char* str);
