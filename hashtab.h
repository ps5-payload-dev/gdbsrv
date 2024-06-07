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

#include <stdint.h>


struct hashtab_member;
typedef struct hashtab_member* hashtab_t;


/**
 * Create a new hash table.
 **/
hashtab_t* hashtab_new(void);


/**
 * Delete a hash table
 **/
void hashtab_del(hashtab_t* htab);


/**
 * Add a member to the given hash table.
 **/
int hashtab_member_add(hashtab_t* htab, uint64_t key, uint64_t val);


/**
 * Delete a member from the given hash table-
 **/
int hashtab_member_del(hashtab_t* htab, uint64_t key);


/**
 * Check if a hash table contains a given member.
 **/
int hashtab_member_exists(const hashtab_t* htab, uint64_t key);


/**
 * Get the value of a member from the given hash table.
 **/
uint64_t hashtab_member_value(const hashtab_t* htab, uint64_t key);
