#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <linux/version.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <sys/mount.h>

#include "libbpf.h"

#define LOG_BUF_SIZE (1024*1024)

#ifndef __NR_bpf
# if defined(__i386__)
#  define __NR_bpf 357
# elif defined(__x86_64__)
#  define __NR_bpf 321
# elif defined(__aarch64__)
#  define __NR_bpf 280
# elif defined(__sparc__)
#  define __NR_bpf 349
# elif defined(__s390__)
#  define __NR_bpf 351
# else
#  error __NR_bpf not defined. libbpf does not support your arch.
# endif
#endif

static inline __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr,
			unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

char bpf_log_buf[LOG_BUF_SIZE];
char GPL_LICENSE[] = "GPL";

struct lbm_program {
  char name[256];
  unsigned int subsystem;
  unsigned int direction;

  struct bpf_insn * insns;
  unsigned int insn_count;
};


#define LBM_SYS_PATH "/sys/kernel/security/lbm"
#define LBM_BPF_PATH "/sys/fs/bpf"

#define MAX_BPF_INSTRUCTIONS 4096

ssize_t lbm_read_sys(const char * path, char * buf, size_t sz)
{
  char fullpath[PATH_MAX];
  snprintf(fullpath, sizeof(fullpath)-1, "%s/%s", LBM_SYS_PATH, path);

  int fd = open(fullpath, O_RDONLY);

  if (fd < 0) {
    perror("lbm_read_sys");
    return -1;
  }

  size_t total = 0;

  while(total < sz) {
    ssize_t readcnt = read(fd, buf+total, sz-total);

    if (readcnt == 0) {
      buf[total] = '\0';
      break;
    } else if (readcnt < 0) {
      if (errno == EAGAIN) {
        continue;
      } else {
        buf[total] = '\0';

        perror("lbm_read_sys");

        close(fd);
        return -1;
      }
    } else {
      total += readcnt;
    }
  }

  close(fd);

  return total;
}

void lbm_alloc_program(struct lbm_program * program)
{
    memset(program, 0, sizeof(*program));
}

void lbm_free_program(struct lbm_program * program)
{
  if(program->insns) {
    free(program->insns);
    program->insns = NULL;
  }

  memset(program, 0, sizeof(*program));
}

int lbm_extract_program(char * program_path, struct lbm_program * program)
{
        assert(program != NULL);

        // Technically this will run initializers / finalizers
        // We dont want this as this is essentially arbitrary code execution
        // But considering that we have no business loading untrusted filters
        // We'll let it slide...for now
        void * bpf_program = dlopen(program_path, RTLD_NOW);

        if (!bpf_program) {
          printf("Failed to open compiled BPF program: %s\n", dlerror());
          return -1;
        }

        struct bpf_insn * prog = dlsym(bpf_program, "prog");

        if (!prog) {
          printf("Unable to load BPF program: %s\n", dlerror());
          dlclose(bpf_program);
          return -1;
        }

        unsigned int * prog_size = dlsym(bpf_program, "prog_size");

        if (!prog_size) {
          printf("Unable to load BPF program instruction count: %s\n", dlerror());
          dlclose(bpf_program);
          return -1;
        }

        unsigned int program_size = *prog_size;

        if (program_size > MAX_BPF_INSTRUCTIONS) {
          printf("Program (%s) size (%u) exceeds maximum instruction count of %u\n",
              program_path, program_size, MAX_BPF_INSTRUCTIONS);
          dlclose(bpf_program);
          return -1;
        }

        if (program_size == 0) {
          printf("Program is of zero size\n");
          dlclose(bpf_program);
          return -1;
        }

        struct bpf_insn * insns = malloc(sizeof(struct bpf_insn)*program_size);

        if (!insns) {
          printf("Unable to alloc memory for LBM instructions\n");
          return -1;
        }

        memcpy(insns, prog, sizeof(struct bpf_insn)*program_size);
        dlclose(bpf_program);

        program->insns = insns;
        program->insn_count = program_size;


        return 0;
}

int lbm_load_program(struct lbm_program * program, const char * lbm_pin_path)
{
  int prog_fd;
  union bpf_attr attr;

  memset(&attr, 0, sizeof(attr));

  attr.lbm.prog_type = BPF_PROG_TYPE_LBM,
  attr.lbm.insn_cnt = program->insn_count,
  attr.lbm.insns = ptr_to_u64(program->insns),
  attr.lbm.license = ptr_to_u64(GPL_LICENSE),
  attr.lbm.log_level = 1,	/* debug mode */
  attr.lbm.log_size = LOG_BUF_SIZE,
  attr.lbm.log_buf = ptr_to_u64(bpf_log_buf),
  attr.lbm.kern_version = LINUX_VERSION_CODE;	/* needs to match the current kernel */
  attr.lbm.subsys_idx = 0,	/* USB */
  //attr.lbm.subsys_idx = 1,	/* BT hci */
  //attr.lbm.subsys_idx = 1,	/* BT l2cap */
  attr.lbm.call_dir = 0,	/* Ingress */
  attr.lbm.pathname = ptr_to_u64(lbm_pin_path),
  attr.lbm.bpf_name = ptr_to_u64(program->name),

  prog_fd = sys_bpf(BPF_PROG_LOAD_LBM, &attr, sizeof(attr));

  if (strlen(bpf_log_buf) > 0) {
    printf("Logs:\n%s\n", bpf_log_buf);
  }

  if (prog_fd < 0) {
    if (errno == ENOENT) {
      perror("Failed to load LBM program (are you use the BPF filesystem is mounted?)");
    } else {
      perror("Failed to load LBM program");
    }
    return -1;
  } else {
    printf("Loaded %s with %u instructions\n", program->name, program->insn_count);
  }
  return 0;
}

int main(int argc, char * argv[])
{
        char sysread[256];
        char * bpf_path = argv[2];
        char pathname[256];
        struct lbm_program program;

        if(argc < 3) {
          printf("%s: bpf_name bpf_path\n", argv[0]);
          return 1;
        }

        if (getuid() != 0) {
          printf("You must be root to load LBM programs\n");
          return 1;
        }

        //mount("none", LBM_BPF_PATH, "bpf", MS_MGC_VAL, NULL);

        if (lbm_read_sys("enable", sysread, sizeof(sysread)-1) < 0) {
          printf("Unable to read LBM enabled flag. Are you using an LBM kernel?\n");
          return 1;
        }

        if (strcmp(sysread, "1\n") != 0) {
          printf("LBM must be enabled before loading programs\n");
          return 1;
        }

        lbm_alloc_program(&program);

        strncpy(program.name, argv[1], sizeof(program.name)-1);
        snprintf(pathname, sizeof(pathname)-1, "%s/%s", LBM_BPF_PATH, program.name);

        if (lbm_extract_program(bpf_path, &program) < 0) {
          return -1;
        }

        if (lbm_load_program(&program, pathname) < 0) {
          return -1;
        }

        lbm_free_program(&program);

	return 0;
}
