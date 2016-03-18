pushf
push rax
push rdi
push rsi
push rdx

mov rax, 29
mov rdi, FTOK_KEY
mov rsi, 1024
mov rdx, 932
syscall
mov rdi, rax
mov rax, 30
xor rsi, rsi
xor rdx, rdx
syscall

mov rdi, rax
mov rax, [rsp + 0x28]
mov rsi, [rdi + 0x8]
mov rdx, [rdi]
mov [rdi], rax
shl rdx, 0x20
xor rax, rdx
mov [rdi], rax
imul rsi, rsi, 0x8
lea rdx, [rdi + 0x10]
add rdx, rsi
mov [rdx], rax
mov rsi, [rdi + 0x8]
inc rsi
mov [rdi + 0x8], rsi

pop rdx
pop rsi
pop rdi
pop rax
popf
ret
