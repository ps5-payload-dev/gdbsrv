/* Copyright (C) 2025 John Törnblom

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

#include <elf.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <ps4/kernel.h>
#include <ps4/klog.h>
#include <ps4/mdbg.h>

#include "elfldr.h"
#include "pt.h"


/**
 * Convenient macros.
 **/
#define ROUND_PG(x) (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#define TRUNC_PG(x) ((x) & ~(PAGE_SIZE - 1))
#define PFLAGS(x)   ((((x) & PF_R) ? PROT_READ  : 0) | \
		     (((x) & PF_W) ? PROT_WRITE : 0) | \
		     (((x) & PF_X) ? PROT_EXEC  : 0))


/**
 * Context structure for the ELF loader.
 **/
typedef struct elfldr_ctx {
  uint8_t *elf;
  pid_t pid;

  intptr_t base_addr;
  size_t base_size;
  void *base_mirror;
} elfldr_ctx_t;


/**
 * Parse a R_X86_64_RELATIVE relocatable.
 **/
static int
r_relative(elfldr_ctx_t *ctx, Elf64_Rela *rela) {
  intptr_t *loc = ctx->base_mirror + rela->r_offset;
  intptr_t val = ctx->base_addr + rela->r_addend;

  *loc = val;

  return 0;
}


/**
 * Parse a PT_LOAD program header.
 **/
static int
data_load(elfldr_ctx_t *ctx, Elf64_Phdr *phdr) {
  void *data = ctx->base_mirror + phdr->p_vaddr;

  if(!phdr->p_memsz) {
    return 0;
  }

  if(!phdr->p_filesz) {
    return 0;
  }

  memcpy(data, ctx->elf + phdr->p_offset, phdr->p_filesz);

  return 0;
}


/**
 *
 **/
int
elfldr_sanity_check(uint8_t *elf, size_t elf_size) {
  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf;
  Elf64_Phdr *phdr;

  if(elf_size < sizeof(Elf64_Ehdr) ||
     elf_size < sizeof(Elf64_Phdr) + ehdr->e_phoff ||
     elf_size < sizeof(Elf64_Shdr) + ehdr->e_shoff) {
    return -1;
  }

  if(ehdr->e_ident[0] != 0x7f || ehdr->e_ident[1] != 'E'
     || ehdr->e_ident[2] != 'L' || ehdr->e_ident[3] != 'F') {
    return -1;
  }

  phdr = (Elf64_Phdr *)(elf + ehdr->e_phoff);
  for(int i = 0; i < ehdr->e_phnum; i++) {
    if(phdr[i].p_offset + phdr[i].p_filesz > elf_size) {
      return -1;
    }
  }

  return 0;
}


/**
 * Load an ELF into the address space of a process with the given pid.
 **/
static intptr_t
elfldr_load(pid_t pid, uint8_t *elf, intptr_t* baseaddr) {
  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf;
  Elf64_Phdr *phdr = (Elf64_Phdr *)(elf + ehdr->e_phoff);
  Elf64_Shdr *shdr = (Elf64_Shdr *)(elf + ehdr->e_shoff);

  elfldr_ctx_t ctx = {.elf = elf, .pid = pid};

  size_t min_vaddr = -1;
  size_t max_vaddr = 0;

  int error = 0;

  // Compute size of virtual memory region.
  for(int i = 0; i < ehdr->e_phnum; i++) {
    if(phdr[i].p_vaddr < min_vaddr) {
      min_vaddr = phdr[i].p_vaddr;
    }

    if(max_vaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
      max_vaddr = phdr[i].p_vaddr + phdr[i].p_memsz;
    }
  }

  min_vaddr = TRUNC_PG(min_vaddr);
  max_vaddr = ROUND_PG(max_vaddr);
  ctx.base_size = max_vaddr - min_vaddr;

  int flags = MAP_PRIVATE | MAP_ANONYMOUS;
  int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
  if(ehdr->e_type == ET_DYN) {
    ctx.base_addr = 0;
  } else if(ehdr->e_type == ET_EXEC) {
    ctx.base_addr = min_vaddr;
    flags |= MAP_FIXED;
  } else {
    puts("elfldr_load: ELF type not supported");
    return 0;
  }

  if(!(ctx.base_mirror=malloc(ctx.base_size))) {
    perror("malloc");
    return 0;
  }

  // Reserve an address space of sufficient size.
  if((ctx.base_addr=pt_mmap(pid, ctx.base_addr, ctx.base_size, prot,
			    flags, -1, 0)) == -1) {
    puts("pt_mmap failed");
    free(ctx.base_mirror);
    return 0;
  }

  // Parse program headers.
  for(int i = 0; i < ehdr->e_phnum && !error; i++) {
    switch(phdr[i].p_type) {
      case PT_LOAD:
        error = data_load(&ctx, &phdr[i]);
        break;
    }
  }

  // Apply relocations.
  for(int i = 0; i < ehdr->e_shnum && !error; i++) {
    if(shdr[i].sh_type != SHT_RELA) {
      continue;
    }

    Elf64_Rela *rela = (Elf64_Rela *)(elf + shdr[i].sh_offset);
    for(int j = 0; j < shdr[i].sh_size / sizeof(Elf64_Rela); j++) {
      switch(rela[j].r_info & 0xffffffffl) {
        case R_X86_64_RELATIVE:
          error = r_relative(&ctx, &rela[j]);
          break;
      }
    }
  }

  if(mdbg_copyin(ctx.pid, ctx.base_mirror, ctx.base_addr, ctx.base_size)) {
    perror("mdbg_copyin");
    error = 1;
  }

  // Set protection bits on mapped segments.
  for(int i = 0; i < ehdr->e_phnum && !error; i++) {
    if(phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) {
      continue;
    }
    if(pt_mprotect(pid, ctx.base_addr + phdr[i].p_vaddr,
                   ROUND_PG(phdr[i].p_memsz), PFLAGS(phdr[i].p_flags))) {
      puts("pt_mprotect failed");
      error = 1;
    }
  }

  if(pt_msync(pid, ctx.base_addr, ctx.base_size, MS_SYNC)) {
    puts("pt_msync failed");
    error = 1;
  }

  free(ctx.base_mirror);

  if(error) {
    pt_munmap(pid, ctx.base_addr, ctx.base_size);
    return 0;
  }

  *baseaddr = ctx.base_addr;

  return ctx.base_addr + ehdr->e_entry;
}


/**
 * Prepare registers of a process for execution of an ELF.
 **/
static int
elfldr_prepare_exec(pid_t pid, uint8_t *elf, intptr_t* baseaddr) {
  intptr_t entry;
  struct reg r;

  if(pt_getregs(pid, &r)) {
    perror("pt_getregs");
    return -1;
  }

  if(!(entry=elfldr_load(pid, elf, baseaddr))) {
    puts("elfldr_load failed");
    return -1;
  }

  mdbg_setlong(pid, r.r_rsp - 8, r.r_rip);
  r.r_rsp -= 8;
  r.r_rip = entry;

  if(pt_setregs(pid, &r)) {
    perror("pt_setregs");
    pt_detach(pid, SIGKILL);
    return -1;
  }

  return 0;
}


/**
 *
 **/
static int
elfldr_raise_privileges(pid_t pid) {
  unsigned char caps[16] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

  if(kernel_set_proc_rootdir(pid, KERNEL_ADDRESS_ROOTVNODE)) {
    klog_puts("kernel_set_proc_rootdir failed");
    return -1;
  }
  if(kernel_set_proc_jaildir(pid, KERNEL_ADDRESS_ROOTVNODE)) {
    klog_puts("kernel_set_proc_jaildir failed");
    return -1;
  }
  if(kernel_set_ucred_prison(pid, KERNEL_ADDRESS_PRISON0)) {
    klog_puts("kernel_set_proc_rootdir failed");
    return -1;
  }

  if(kernel_set_ucred_uid(pid, 0)) {
    klog_puts("kernel_set_ucred_uid failed");
    return -1;
  }
  if(kernel_set_ucred_caps(pid, caps)) {
    return -1;
  }
  if(kernel_set_ucred_authid(pid, 0x3801000000000013l)) {
    klog_puts("kernel_set_ucred_authid failed");
    return -1;
  }

  return 0;
}


/**
 * Execute an ELF inside the process with the given pid.
 **/
int
elfldr_exec(pid_t pid, int stdio, uint8_t *elf, intptr_t* baseaddr) {
  int error = 0;

  if(elfldr_raise_privileges(pid)) {
    puts("Unable to raise privileges");
    pt_detach(pid, SIGKILL);
    return -1;
  }

  if(stdio > 0) {
    stdio = pt_rdup(pid, getpid(), stdio);

    pt_close(pid, STDERR_FILENO);
    pt_close(pid, STDOUT_FILENO);
    pt_close(pid, STDIN_FILENO);

    pt_dup2(pid, stdio, STDIN_FILENO);
    pt_dup2(pid, stdio, STDOUT_FILENO);
    pt_dup2(pid, stdio, STDERR_FILENO);

    pt_close(pid, stdio);
  }

  if(elfldr_prepare_exec(pid, elf, baseaddr)) {
    error = -1;
  }

  return error;
}


/**
 * Set the heap size for libc.
 **/
static int
elfldr_set_heap_size(pid_t pid, uint32_t size) {
  intptr_t sceLibcHeapExtendedAlloc;
  intptr_t sceLibcHeapSize;
  intptr_t sceLibcParam;
  intptr_t sceProcParam;
  intptr_t buf;

  if((buf=pt_mmap(pid, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
		  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)) == -1) {
    puts("pt_mmap failed");
    return -1;
  }
  if(pt_dynlib_get_proc_param(pid, buf, buf + 0x100)) {
    puts("pt_dynlib_process_needed_and_relocate failed");
    pt_munmap(pid, buf, PAGE_SIZE);
    return -1;
  }
  if(!(sceProcParam = mdbg_getlong(pid, buf))) {
    perror("mdbg_getlong");
    pt_munmap(pid, buf, PAGE_SIZE);
    return -1;
  }

  if(mdbg_copyout(pid, sceProcParam + 56, &sceLibcParam,
                  sizeof(sceLibcParam))) {
    perror("mdbg_copyout");
    pt_munmap(pid, buf, PAGE_SIZE);
    return -1;
  }

  if(mdbg_copyout(pid, sceLibcParam + 16, &sceLibcHeapSize,
                  sizeof(sceLibcHeapSize))) {
    perror("mdbg_copyout");
    pt_munmap(pid, buf, PAGE_SIZE);
    return -1;
  }

  if(mdbg_setint(pid, sceLibcHeapSize, size)) {
    perror("mdbg_setint");
    pt_munmap(pid, buf, PAGE_SIZE);
    return -1;
  }

  if(size != -1) {
    pt_munmap(pid, buf, PAGE_SIZE);
    return 0;
  }

  // sceLibcHeapExtendedAlloc is not allocated when using SceSpZeroConf
  sceLibcHeapExtendedAlloc = buf;
  if(mdbg_setlong(pid, sceLibcParam + 32, sceLibcHeapExtendedAlloc)) {
    perror("mdbg_setlong");
    pt_munmap(pid, buf, PAGE_SIZE);
    return -1;
  }

  if(mdbg_setint(pid, sceLibcHeapExtendedAlloc, 1)) {
    perror("mdbg_setint");
    pt_munmap(pid, buf, PAGE_SIZE);
    return -1;
  }

  return 0;
}


/**
 * Read a file from disk at the given path.
 **/
static uint8_t*
elfldr_readfile(const char* path) {
  uint8_t* buf;
  ssize_t len;
  FILE* file;

  if(!(file=fopen(path, "rb"))) {
    perror("fopen");
    return 0;
  }

  if(fseek(file, 0, SEEK_END)) {
    perror("fseek");
    return 0;
  }

  if((len=ftell(file)) < 0) {
    perror("ftell");
    return 0;
  }

  if(fseek(file, 0, SEEK_SET)) {
    perror("fseek");
    return 0;
  }

  if(!(buf=malloc(len))) {
    return 0;
  }

  if(fread(buf, 1, len, file) != len) {
    perror("fread");
    free(buf);
    return 0;
  }

  if(fclose(file)) {
    perror("fclose");
    free(buf);
    return 0;
  }

  return buf;
}


/**
 *
 **/
static int
elfldr_rfork_entry(void *progname) {
  const char *SceSpZeroConf = "/system/vsh/app/NPXS21016/eboot.bin";
  char *const argv[] = {"eboot.bin", 0};

  if(syscall(0x23b, 0)) {
    klog_perror("sys_budget_set");
    return 0;
  }

  if(open("/dev/deci_stdin", O_RDONLY) < 0) {
    klog_perror("open");
    return 0;
  }
  if(open("/dev/deci_stdout", O_WRONLY) < 0) {
    klog_perror("open");
    return 0;
  }
  if(open("/dev/deci_stderr", O_WRONLY) < 0) {
    klog_perror("open");
    return 0;
  }

  if(ptrace(PT_TRACE_ME, 0, 0, 0)) {
    klog_perror("ptrace");
    return 0;
  }

  execve(SceSpZeroConf, argv, 0);

  klog_perror("execve");
  return 0;
}


/**
 * Execute an ELF inside a new process.
 **/
pid_t
elfldr_spawn(char* argv[], int stdio, intptr_t* baseaddr) {
  uint8_t int3instr = 0xcc;
  struct kevent evt;
  intptr_t brkpoint;
  uint8_t orginstr;
  uint8_t* elf;
  void *stack;
  pid_t pid;
  int kq;

  if((kq=kqueue()) < 0) {
    perror("kqueue");
    return -1;
  }

  if(!(stack=malloc(PAGE_SIZE))) {
    perror("malloc");
    close(kq);
    return -1;
  }

  if((pid=rfork_thread(RFPROC | RFCFDG | RFMEM, stack + PAGE_SIZE - 8,
		       elfldr_rfork_entry, 0)) < 0) {
    perror("rfork_thread");
    free(stack);
    close(kq);
    return -1;
  }

  EV_SET(&evt, pid, EVFILT_PROC, EV_ADD, NOTE_EXEC | NOTE_EXIT, 0, 0);
  if(kevent(kq, &evt, 1, &evt, 1, 0) < 0) {
    perror("kevent");
    free(stack);
    close(kq);
    return -1;
  }

  free(stack);
  close(kq);

  while(pt_attach(pid) == -1) {
    if(errno == EBUSY) {
      continue;
    }
    perror("pt_attach");
    kill(pid, SIGKILL);
    return -1;
  }

  if(pt_dynlib_process_needed_and_relocate(pid)) {
    puts("pt_dynlib_process_needed_and_relocate");
    pt_detach(pid, SIGKILL);
    return -1;
  }

  // Allow libc to allocate arbitrary amount of memory.
  if(elfldr_set_heap_size(pid, -1)) {
    puts("pt_dynlib_process_needed_and_relocate failed");
    pt_detach(pid, SIGKILL);
    return -1;
  }

  // Insert a breakpoint at the eboot entry.
  if(!(brkpoint = kernel_dynlib_entry_addr(pid, 0))) {
    puts("kernel_dynlib_entry_addr failed");
    pt_detach(pid, SIGKILL);
    return -1;
  }
  brkpoint += 58; // offset to invocation of main()

  if(mdbg_copyout(pid, brkpoint, &orginstr, sizeof(orginstr))) {
    perror("mdbg_copyout");
    pt_detach(pid, SIGKILL);
    return -1;
  }
  if(mdbg_copyin(pid, &int3instr, brkpoint, sizeof(int3instr))) {
    perror("mdbg_copyin");
    pt_detach(pid, SIGKILL);
    return -1;
  }

  // Continue execution until we hit the breakpoint, then remove it.
  if(pt_continue(pid, SIGCONT)) {
    perror("pt_continue");
    pt_detach(pid, SIGKILL);
    return -1;
  }
  if(waitpid(pid, 0, 0) == -1) {
    perror("waitpid");
    pt_detach(pid, SIGKILL);
    return -1;
  }
  if(mdbg_copyin(pid, &orginstr, brkpoint, sizeof(orginstr))) {
    perror("mdbg_copyin");
    pt_detach(pid, SIGKILL);
    return -1;
  }

  // Execute the ELF
  if(!(elf=elfldr_readfile(argv[0]))) {
    pt_detach(pid, SIGKILL);
    return -1;
  }

  if(elfldr_exec(pid, stdio, elf, baseaddr)) {
    kill(pid, SIGKILL);
    return -1;
  }

  return pid;
}

