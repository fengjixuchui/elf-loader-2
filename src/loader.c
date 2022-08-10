#include <elf/loader.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <limits.h>
#include <sys/mman.h>
#include <string.h>

#define STACK_ALIGN     16

#define PROGRAM         0
#define INTERPRETER     1

#define AV_PATH         "/proc/self/auxv"

#ifndef PAGE_SIZE
#define PAGE_SIZE       0x1000
#endif

#define ROUND_PG(x)     (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#define TRUNC_PG(x)     ((x) & ~(PAGE_SIZE - 1))

#if __i386__ || __arm__

#define BUFFER_SIZE     512

#define Elf_Ehdr        Elf32_Ehdr
#define Elf_Phdr        Elf32_Phdr
#define Elf_auxv_t      Elf32_auxv_t
#define ELF_CLASS       ELFCLASS32

#elif __x86_64__ || __aarch64__

#define BUFFER_SIZE     832

#define Elf_Ehdr        Elf64_Ehdr
#define Elf_Phdr        Elf64_Phdr
#define Elf_auxv_t      Elf64_auxv_t
#define ELF_CLASS       ELFCLASS64

#endif

int is_elf(Elf_Ehdr *ehdr) {
    if (
            ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
            ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
            ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
            ehdr->e_ident[EI_MAG3] != ELFMAG3)
        return -1;


    if (ehdr->e_ident[EI_CLASS] != ELF_CLASS || ehdr->e_ident[EI_VERSION] != EV_CURRENT)
        return -1;

    if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN)
        return -1;

    return 0;
}

int load_segments(char *buffer, int fd, elf_image_t *image) {
    Elf_Ehdr *ehdr = (Elf_Ehdr *) buffer;
    Elf_Phdr *phdr = (Elf_Phdr *) (buffer + ehdr->e_phoff);

    uintptr_t minVA = -1;
    uintptr_t maxVA = 0;

    for (Elf_Phdr *i = phdr; i < &phdr[ehdr->e_phnum]; i++) {
        if (i->p_type != PT_LOAD)
            continue;

        if (i->p_vaddr < minVA)
            minVA = i->p_vaddr;

        if (i->p_vaddr + i->p_memsz > maxVA)
            maxVA = i->p_vaddr + i->p_memsz;
    }

    minVA = TRUNC_PG(minVA);
    maxVA = ROUND_PG(maxVA);

    int dyn = ehdr->e_type == ET_DYN;

    void *base = mmap(
            dyn ? NULL : (void *) minVA,
            maxVA - minVA,
            PROT_NONE,
            (dyn ? 0 : MAP_FIXED) | MAP_PRIVATE | MAP_DENYWRITE,
            fd,
            0);

    if (base == MAP_FAILED)
        return -1;

    for (Elf_Phdr *i = phdr; i < &phdr[ehdr->e_phnum]; i++) {
        if (i->p_type != PT_LOAD)
            continue;

        if ((i->p_align & (PAGE_SIZE - 1)) != 0) {
            munmap(base, maxVA - minVA);
            return -1;
        }

        if (((i->p_vaddr - i->p_offset) & (i->p_align - 1)) != 0) {
            munmap(base, maxVA - minVA);
            return -1;
        }

        size_t offset = i->p_vaddr & (PAGE_SIZE - 1);
        size_t size = ROUND_PG(i->p_memsz + offset);
        size_t filesize = ROUND_PG(i->p_filesz + offset);
        uintptr_t start = (uintptr_t) base + TRUNC_PG(i->p_vaddr) - minVA;

        int protection = (i->p_flags & PF_R ? PROT_READ : 0) | (i->p_flags & PF_W ? PROT_WRITE : 0) |
                         (i->p_flags & PF_X ? PROT_EXEC : 0);

        if (mmap(
                (void *) start,
                size,
                protection,
                MAP_FIXED | MAP_PRIVATE | MAP_DENYWRITE,
                fd,
                (off_t) (i->p_offset - offset)) == MAP_FAILED) {
            munmap(base, maxVA - minVA);
            return -1;
        }

        if (i->p_memsz == i->p_filesz)
            continue;

        memset((char *) start + offset + i->p_filesz, 0, filesize - i->p_filesz - offset);

        if (size == filesize)
            continue;

        if (mmap(
                (char *) start + filesize,
                size - filesize,
                protection,
                MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0) == MAP_FAILED) {
            munmap(base, maxVA - minVA);
            return -1;
        }
    }

    image->base = (uintptr_t) base;
    image->minVA = minVA;
    image->maxVA = maxVA;

    return 0;
}

int load_elf(const char *path, elf_context_t ctx[2]) {
    struct stat sb;

    if (stat(path, &sb) < 0)
        return -1;

    if ((sb.st_mode & S_IFREG) == 0)
        return -1;

    int fd = open(path, O_RDONLY, 0);

    if (fd < 0)
        return -1;

    char buffer[BUFFER_SIZE] = {};

    if (read(fd, buffer, BUFFER_SIZE) < 0) {
        close(fd);
        return -1;
    }

    if (is_elf((Elf_Ehdr *) buffer) < 0) {
        close(fd);
        return -1;
    }

    Elf_Ehdr *ehdr = (Elf_Ehdr *) buffer;
    Elf_Phdr *phdr = (Elf_Phdr *) (buffer + ehdr->e_phoff);

    for (Elf_Phdr *i = phdr; i < &phdr[ehdr->e_phnum]; i++) {
        if (i->p_type == PT_INTERP) {
            char interpreter[PATH_MAX] = {};

            if (lseek(fd, (off_t) i->p_offset, SEEK_SET) < 0) {
                close(fd);
                return -1;
            }

            if (read(fd, interpreter, i->p_filesz) != i->p_filesz) {
                close(fd);
                return -1;
            }

            if (load_elf(interpreter, ctx + 1) < 0) {
                close(fd);
                return -1;
            }

            break;
        }
    }

    elf_image_t image = {};

    if (load_segments(buffer, fd, &image) < 0) {
        close(fd);
        return -1;
    }

    ctx->base = image.base;
    ctx->entry = image.base + ehdr->e_entry - image.minVA;
    ctx->header = image.base + ehdr->e_phoff;
    ctx->header_num = ehdr->e_phnum;
    ctx->header_size = ehdr->e_phentsize;

    close(fd);

    return 0;
}

int jump_elf(elf_context_t ctx[2], int argc, char **argv, char **envp) {
    int fd = open(AV_PATH, O_RDONLY, 0);

    if (fd < 0)
        return -1;

    char av[1024] = {};

    ssize_t length = read(fd, av, sizeof(av));

    if (length == -1) {
        close(fd);
        return -1;
    }

    close(fd);

    for (Elf_auxv_t *i = (Elf_auxv_t *) av; i->a_type != AT_NULL; i++) {
        switch (i->a_type) {
            case AT_PHDR:
                i->a_un.a_val = ctx[PROGRAM].header;
                break;

            case AT_PHENT:
                i->a_un.a_val = ctx[PROGRAM].header_size;
                break;

            case AT_PHNUM:
                i->a_un.a_val = ctx[PROGRAM].header_num;
                break;

            case AT_BASE:
                i->a_un.a_val = ctx[INTERPRETER].base ? ctx[INTERPRETER].base : 0;
                break;

            case AT_ENTRY:
                i->a_un.a_val = ctx[PROGRAM].entry;
                break;

            case AT_EXECFN:
                i->a_un.a_val = (unsigned long) argv[0];
                break;
        }
    }

    char buffer[4096] = {};
    char *stack = (char *) (((uintptr_t) buffer + STACK_ALIGN - 1) & ~(STACK_ALIGN - 1));

    size_t *p = (size_t *) stack;

    *(int *) p++ = argc;

    for (int i = 0; i < argc; i++)
        *(char **) p++ = argv[i];

    *(char **) p++ = NULL;

    for (char **i = envp; *i; i++)
        *(char **) p++ = *i;

    *(char **) p++ = NULL;

    memcpy(p, av, length);

    uintptr_t entry = ctx[INTERPRETER].entry ? ctx[INTERPRETER].entry : ctx[PROGRAM].entry;

#ifdef __i386__
    asm volatile("mov %0, %%esp; xor %%edx, %%edx; jmp *%1;" :: "r"(stack), "a"(entry));
#elif __x86_64__
    asm volatile("mov %0, %%rsp; xor %%rdx, %%rdx; jmp *%1;"::"r"(stack), "a"(entry));
#elif __arm__
    asm volatile("mov %%sp, %0; mov %%r0, #0; bx %[func];" :: "r"(stack), [func] "r"(entry));
#elif __aarch64__
    asm volatile("mov sp, %[stack]; mov w0, #0; br %[func];" :: [stack] "r"(stack), [func] "r"(entry));
#endif

    return 0;
}
