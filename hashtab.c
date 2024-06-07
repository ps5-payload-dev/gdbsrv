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

#include <stdint.h>
#include <stdlib.h>

/**
 * NUmber of buckets
 **/
#define NB_BUCKETS  1021


/**
 * Linked list of hash table members.
 **/
typedef struct hashtab_member {
  uint64_t key;
  uint64_t val;
  struct hashtab_member *next;
} hashtab_member_t;


/**
 * A hash table is an array of linked lists.
 **/
typedef struct hashtab_member* hashtab_t;


hashtab_t*
hashtab_new(void) {
  return calloc(NB_BUCKETS, sizeof(hashtab_member_t*));
}


void
hashtab_del(hashtab_t* htab) {
  //TODO
}


int
hashtab_member_add(hashtab_t* htab, uint64_t key, uint64_t val) {
  int hash = key % NB_BUCKETS;
  hashtab_member_t *m;

  for(m=htab[hash]; m!=0; m=m->next) {
    if(m->key == key) {
      return -1;
    }
  }

  m = malloc(sizeof(hashtab_member_t));
  m->key = key;
  m->val = val;
  m->next  = htab[hash];
  htab[hash] = m;

  return 0;
}


int
hashtab_member_del(hashtab_t* htab, uint64_t key) {
  int hash = key % NB_BUCKETS;
  hashtab_member_t *prev = 0;
  hashtab_member_t *curr = 0;

  for(prev=0, curr=htab[hash]; curr!=0; prev=curr, curr=curr->next) {
    if(curr->key == key) {
      if(prev) {
	prev->next = curr->next;
      } else {
	htab[hash] = curr->next;
      }
      free(curr);
      return 0;
    }
  }

  return -1;
}


int
hashtab_member_exists(const hashtab_t* htab, uint64_t key) {
  int hash = key % NB_BUCKETS;

  for(hashtab_member_t* m=htab[hash]; m!=0; m=m->next) {
    if(m->key == key) {
      return 1;
    }
  }

  return 0;
}


uint64_t
hashtab_member_value(const hashtab_t* htab, uint64_t key) {
  int hash = key % NB_BUCKETS;

  for(hashtab_member_t* m=htab[hash]; m!=0; m=m->next) {
    if(m->key == key) {
      return m->val;
    }
  }

  return -1;
}
