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

#include <stdio.h>
#include <unistd.h>


int main() {
  int x = 0;
  int y = 0;

  while(1) {
    x += 1;
    y += 2;
    printf("x=%d, y=%d, main=%p, pid=%d\n",
	   x, y, main, getpid());
    sleep(1);
  }

  return 0;
}
