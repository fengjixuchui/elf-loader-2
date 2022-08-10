#ifndef ELF_LOADER_LOADER_H
#define ELF_LOADER_LOADER_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uintptr_t base;
    uintptr_t entry;
    uintptr_t header;
    size_t header_num;
    size_t header_size;
} elf_context_t;

typedef struct {
    uintptr_t base;
    uintptr_t minVA;
    uintptr_t maxVA;
} elf_image_t;

int load_elf(const char *path, elf_context_t ctx[2]);
int jump_elf(elf_context_t ctx[2], int argc, char **argv, char **envp);

#endif //ELF_LOADER_LOADER_H
