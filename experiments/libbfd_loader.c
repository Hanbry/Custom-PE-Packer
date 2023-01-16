#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#define PACKAGE
#define PACKAGE_VERSION 

#include <bfd.h>

int main(int argc, char **argv) {
    bfd *abfd;
    asection *section;
    char **matching;
    void (*entry_point)();
    bfd_init();

    if (argc < 2) {
        printf("Usage: %s <elf-file>\n", argv[0]);
        return 1;
    }

    // Öffnen Sie die ELF-Datei
    abfd = bfd_openr(argv[1], NULL);
    if (abfd == NULL) {
        bfd_perror("bfd_openr");
        return 1;
    }

    // Überprüfen Sie, ob es sich um eine ELF-Datei handelt
    if (!bfd_check_format(abfd, bfd_object)) {
        printf("Not an ELF file\n");
        return 1;
    }

    // Iterieren Sie über die Abschnitte und laden Sie sie in den Speicher
    for (section = abfd->sections; section != NULL; section = section->next) {
        if (!(bfd_get_section_flags(abfd, section) & SEC_ALLOC))
            continue;

        bfd_size_type size = bfd_get_section_size(section);
        bfd_vma vma = bfd_get_section_vma(abfd, section);
        bfd_byte *buffer = malloc(size);

        bfd_get_section_contents(abfd, section, buffer, 0, size);
        memcpy((void *) vma, buffer, size);

        // Relocations verarbeiten
        if (bfd_get_section_flags(abfd, section) & SEC_RELOC) {
            if (!bfd_check_relocs(abfd, section, buffer)) {
                bfd_perror("bfd_check_relocs");
                return 1;
            }
            bfd_simple_relocate_section(abfd, section, buffer);
        }
        free(buffer);
    }

    // Suchen Sie nach dem Einstiegspunkt des Programms (die "main"-Funktion)
    bfd_scan_library(abfd,matching);
    entry_point = bfd_get_start_address(abfd);

    // Rufen Sie die main()-Funktion des Programms auf
    (*entry_point)();

    // Schließen Sie die ELF-Datei
    bfd_close(abfd);

    return 0;
}
