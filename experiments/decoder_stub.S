section .data
    key db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ; Platzhalter für XOR Schlüssel

section .text
    global _start

_start:
    ; Laden des ersten 64-Bit-Teils des Schlüssels in rax
    mov rax, key
    mov rdx, key + 8
    xor rax, rdx

    ; Laden der Startadressen des Programmheaders in rbx
    mov rbx, [elf_header + 0x28] ; elf_header ist hier die Startadresse des ELF-Headers
    add rbx, elf_header

    ; Laden der Anzahl der Programmheader in rcx
    mov rcx, [elf_header + 0x38]
    xor rcx, rcx
    mov cl, [elf_header + 0x3a]

decode:
    ; Laden der Startadresse des aktuellen Programmheaders
    mov rdx, [rbx + 0x10]
    add rdx, elf_header

    ; Laden der Größe des aktuellen Programmheaders
    mov r8, [rbx + 0x20]
    xor r8, r8
    mov r8b, [rbx + 0x22]
    mov r8w, [rbx + 0x24]

    ; Entschlüsseln des Programmheaders
    xor_decode:
        xor byte [rdx], al
        inc rdx
        dec r8
    jne xor_decode

    ; Weiter mit dem nächsten Programmheader
    add rbx, 0x38
    dec rcx
    jne decode

    ; Springen zur eigentlichen Programmstartadresse
    mov rax, [elf_header + 0x18]
    jmp rax

section .text
    elf_header: