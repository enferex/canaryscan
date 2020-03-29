#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

// *-- CanaryScan -------------------------------------------------------------*
// |                                                                           |
// | Scan this processes' memory map looking for its canary.                   |
// | The canary might be generated via the kernel upon binary load, and passed |
// | to the userland runtime loader (glibc's rtld.c aka ld) via an elf aux     |
// | field.                                                                    |
// | Use cases:                                                                |
// |   (1) Identify if some memory mapped regions are caching the canary value.|   
// |   (2) Run this multiple times to collect numerous canary values.          |
// |       For science!                                                        |
// |                                                                           |
// | This is similar to https://github.com/enferex/homingcanary                |
// | HomingCanary scans other processes but requires root access.              |
// |                                                                           |
// *---------------------------------------------------------------------------*


_Static_assert(sizeof(uintptr_t) == 8, "This is designed for 64bit binaries.");

// This is set in main() and used when scanning /proc/self/maps
static uintptr_t canary;

// Specify a memory range (this is populated from /proc/self/maps entries).
typedef struct _range_t {
  uintptr_t begin;    // Start address (first item in /proc/self/maps)
  const char *perms;  // Permission string (second column in /proc/self/maps)
  size_t offset;      // Offset (third column in /proc/self/maps)
  size_t size;        // End - Begin: first column /proc/self/maps range.
  struct _range_t *next;
} range_t;

static void print_range(const range_t *range, _Bool newline) {
  assert(range);
  printf("%p (%zu size) (perms: %s)%c", range->begin, range->size, range->perms,
         newline ? '\n' : ' ');
}

// Parse the memory map for this process.
static range_t *get_ranges(void) {
  FILE *fp = fopen("/proc/self/maps", "r");
  assert(fp);

  char *line = NULL;
  range_t *head = NULL;
  size_t n_read = 0;
  while (getline(&line, &n_read, fp) > 0) {
#ifndef NDEBUG
    printf("[d] Found /proc/self/map entry: %s", line);
#endif
    range_t *node = calloc(1, sizeof(range_t));
    char *range_str = strdup(strtok(line, " "));

    // The upper bit is 1 for kernel space memory, which we cannot touch.
    // Since we extracted this value from an ascii string, just check the
    // most significant nybble is F, which is not entirely correct, but should
    // suffice.
    if (range_str[0] == 'F' || range_str[0] == 'f') {
      printf("[+] Skipping potential kernel space memory: %s\n", range_str);
      continue;
    }

    node->perms = strdup(strtok(NULL, " "));
    node->offset = strtoll(strtok(NULL, " "), NULL, 16);
    const uintptr_t begin = strtoll(strtok(range_str, "-"), NULL, 16);
    const uintptr_t end = strtoll(strtok(NULL, " "), NULL, 16);
    assert(end >= begin);
    node->begin = begin;
    node->size = end - begin;
    node->next = head;
    head = node;
    free(range_str);
#ifndef NDEBUG
    printf("[d] Scanned range: ");
    print_range(node, true);
#endif
  }
  if (errno)
    fprintf(stderr, "[-] Error reading /proc/self/maps: %s [%s]\n",
            strerror(errno), line);
  return head;
}

static _Bool is_read(const range_t *range) {
  assert(range && range->perms);
  return range->perms[0] == 'r' &&
         ((range->begin & 0x7ff0000000000000) != 0x7ff0000000000000);
}

// Scan the range looking for the canary.
static void scan_range(int fd, const range_t *range) {
  assert(range);
  if (!is_read(range)) {
    printf("[+] Ignoring (not-readable range): ");
    print_range(range, true);
  } else {
    printf("[+] Scanning: ");
    print_range(range, false);
    printf("...\n");
    for (size_t itr = 0; itr < range->size; itr += sizeof(uintptr_t)) {
      const uintptr_t *addr =
          (uintptr_t *)range->begin + (itr * sizeof(uintptr_t)) + range->offset;
      uintptr_t data = 0;
      if ((pread(fd, &data, sizeof(data), 0) > 0) && (data == canary))
        printf("[*] Found canary at: %p\n", addr);
    }
  }
}

static _Noreturn void usage(const char *execname) {
  printf(
      "Usage: %s [-h] [-q] \n"
      "  -q: Quiet mode, print this process' canary and exit.\n"
      "  -h: Display this help message.\n", execname);
  exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {
  _Bool quiet_mode = false;

  // Args
  if (argc > 2) usage(argv[0]);
  for (int i = 1; i < argc; ++i) {
    if (argv[i][0] != '-') {
      fprintf(stderr, "Unexpected flag.  See usage: '-h'\n");
      exit(EXIT_FAILURE);
    }
    switch (argv[i][1]) {
      case 'h':
        usage(argv[0]);
        break;
      case 'q':
        quiet_mode = true;
        break;
      default:
        fprintf(stderr, "Unexpected flag.  See usage: '-h'\n");
        exit(EXIT_FAILURE);
        break;
    }
  }

  // Copy the canary in an easier place to access.
  asm volatile("mov %%fs:0x28, %0\n\t" : "=r"(canary));

  // Quiet mode. (Avoid printing the [+] status ascii icon.)
  if (quiet_mode) {
    printf("Canary: 0x%016lx\n", canary);
    exit(EXIT_SUCCESS);
  }

  // Scan mode.
  printf("[+] Canary: 0x%016lx\n", canary);
  const int fd = open("/proc/self/mem", O_RDONLY | __O_LARGEFILE);
  if (fd < 0) {
    fprintf(stderr, "[-] Error opening memory map: %s\n", strerror(errno));
    exit(errno);
  }

  range_t *ranges = get_ranges();
  for (const range_t *rr = ranges; rr; rr = rr->next) scan_range(fd, rr);

  return 0;
}
