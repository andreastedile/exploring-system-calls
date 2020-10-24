# Esplorando le system call

In questo documento vediamo come si effettua una semplice system call in un computer con architettura Intel 64-bit e sistema operativo Linux-Ubuntu 18.04.1. Questa breve ricerca si fonda sull'analisi del file eseguibile prodotto dalla compilazione. Dapprima analizziamo il contenuto che si ottiene disassemblando un file eseguibile, e successivamente ci concentriamo su un programma Assembly.

Fonti interessanti:

https://youtu.be/mB79rNrpOhg  
https://youtu.be/VQAKkuLL31g  
https://youtu.be/BWRR3Hecjao

## Concetti preliminari

### System call

Un calcolatore consiste di numerosi dispositivi hardware che lavorano in armonia sotto la gestione del kernel del sistema operativo. Il kernel implementa un'interfaccia fra il livello dell'hardware e il livello del software, che comporta una serie di benefici:

- Libera i programmatori dallo studio dei dettagli della programmazione a basso livello dei dispositivi.
- Il kernel può controllare l'accuratezza delle richieste fatte al livello dell'interfaccia prima di soddisfarle.
- I programmi diventano più portabili, in quanto possono eseguire correttamente su ogni kernel che espone lo stesso insieme di interfacce.

Il kernel realizza questa interfaccia esponendo ai programmi delle **system call** con cui può essere richiamato.

In altre parole, una system call è un entry point controllato nel kernel del sistema operativo. I programmi fanno uso delle system call per richiedere i servizi del kernel, che quest'ultimo svolge orchestrando i dispositivi hardware.

In Linux, la libreria **glibc** dà modo di effettuare le system call.

### C standard library

Questa libreria, cui ci si riferisce spesso con l'abbreviazione **libc**, contiene le funzioni standard che possono essere usate dai programmi C. La sua implementazione più usata su Linux è la GNU C Library, o **[glibc](https://www.gnu.org/software/libc/)**. La glibc arriva in due versioni, statica o dinamica, a seconda del tipo di compilazione che intendiamo conseguire.

La glibc contiene inoltre varie librerie di fondamentale importanza. In particolare, essa fornisce la API dello standard POSIX, che vediamo qui di seguito.

### POSIX

Lo standard POSIX è nato per mantenere compatibilità fra sistemi operativi ed incrementare la portabilità dei programmi a livello di codice sorgente. Esso specifica una API uniforme che i programmatori possano usare sui sistemi operativi conformi allo standard. La API di POSIX comprende le funzioni fondamentali che un sistema operativo mette tipicamente a disposizione: `open`, `read`, `close`, `write`, `fork`...

Lo standard non prescrive una particolare implementazione della API, ma si occupa esclusivamente della specificarne le funzioni e il servizio che devono realizzare.

Valgono le seguenti considerazioni:

- POSIX si riferisce ad una API e non ad un'implementazione.
- In virtù di questo fatto, i servizi descritta dalla specifica POSIX si possono implementare sia in User mode che in Kernel mode (nel secondo caso, viene fatto uso di system call).
- La distinzione fra API e system call è irrilevante per il programmatore, che fa unicamente fede al comportamento atteso della funzione (nome, tipo dei parametri, significato del valore di ritorno), mentre è rilevante per il designer di un kernel, che deve poter riconoscere se la funzione lavora in Kernel mode (è una system call) o in User mode.
- Un sistema può fregiarsi della certificazione POSIX se espone al programmatore una API che è conforme allo standard POSIX.

### Chiamare il kernel Linux

La API dello standard POSIX è implementata in Linux dalla glibc, e il suo accesso è consentito dall'header `unistd.h`.

Alla luce di questo fatto, una chiamata ad una funzione della API è in realtà una chiamata ad una funzione wrapper, che si occupa di inserire i valori corretti nei registri per poi effettuare una trap che restituisce il controllo al kernel.

Le system call *vere e proprie*, infatti, sono implementate da routine scritte nel linguaggio Assembly per una specifica architettura hardware; mentre le system call fornite dalla C standard library sono in realtà dei comodi wrapper che nascondono l'implementazione della system call vera e propria. Questo ulteriore livello di indirizzamento incrementa la modularità e portabilità.

![](https://qph.fs.quoracdn.net/main-qimg-28627e0d73ba1753783422fd0cf70751)

È tuttavia uso comune e corretto riferirsi a queste funzioni wrapper come *system call*, in quanto il loro effetto ultimo è di fatto quello di invocare una system call.

In Linux, volendo, si può invocare una system call per cui glibc non fornisce un wrapper dedicato attraverso la funzione [`syscall`](http://man7.org/linux/man-pages/man2/syscall.2.html), che vedremo successivamente.

Sinteticamente, le funzioni wrapper della glibc seguono questi [tre passaggi](http://man7.org/linux/man-pages/man2/intro.2.html#DESCRIPTION) chiave:

- Copiano il numero univoco della system call e i parametri nei registri laddove il kernel li aspetta.
- Effettuano una trap in Kernel mode: ora il kernel svolge il vero lavoro della system call.
- Quando il kernel fa tornare la CPU in User mode, settano `errno` se la system call ha ritornato un numero di errore.

### Architetture e kernel

Ogni architettura ha i propri requisiti per invocare il kernel e passargli parametri.

Vediamo per qualche architettura l' istruzione che consegue la transizione in Kernel mode:

| arch/ABI |   istr    | #syscall | retval |
| :------: | :-------: | :------: | :----: |
|   i386   | int $0x80 |   eax    |  eax   |
|  x86-64  |  syscall  |   rax    |  rax   |
|  arm64   |  svc #0   |    x8    |   x0   |

Vediamo anche i registri usati per passare gli argomenti delle system call:

| arch/ABI | arg1 | arg2 | arg3 | arg4 | arg5 | arg6 |
| :------: | :--: | :--: | :--: | :--: | :--: | :--: |
|   i386   | ebx  | ecx  | edx  | esi  | edi  | ebp  |
|  x86-64  | rdi  | rsi  | rdx  | r10  |  r8  |  r9  |
|  arm64   |  x0  |  x1  |  x2  |  x3  |  x4  |  x5  |

### Le system call di Linux

Abbiamo visto che l'accesso alla API del kernel Linux, che è conforme allo standard POSIX, è consentito da `unistd.h`, un header che contiene oltretutto le definizioni di [alcune system call](https://stackoverflow.com/questions/30155858/are-unix-linux-system-calls-part-of-posix-library-functions) non previste da POSIX.

## Un primo programma

Iniziamo, scrivendo nel file *hello.c* il seguente programma C:

```c
#include <stdio.h>
int main()
{
	printf("Hello, World!\n");
	return 0;
}
```

L'header `stdio.h` contiene la definizione della funzione `printf`, implementata dalla C standard library.

Compiliamo *hello.c* in *hello.out* con `gcc -o hello.out hello.c`.

Eseguendo *hello.out* otteniamo l'output:

```
Hello, World!
```

Con `ls -l` verifichiamo che *hello.c* ha una dimensione di 8.10 kilobyte ed *hello.out* di 8.3 kilobyte.

Con `file hello.out` verifichiamo che le librerie per *hello.out* sono state linkate dinamicamente:

> andreastedile@ubuntu:~/Desktop/Syscalls$ file hello.out 
> hello.out: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=88cd59f387301bdc8abe58360ea55b641135b5c7, not stripped

Elenchiamo queste librerie con `ldd hello.out`:

> andreastedile@ubuntu:~/Desktop/Syscalls$ ldd hello.out 
> ​	linux-vdso.so.1 =>  (0x00007ffef037f000)
> ​	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f617ecb7000)
> ​	/lib64/ld-linux-x86-64.so.2 (0x000055d764da7000)

[`linux-vdso.so.1`](http://man7.org/linux/man-pages/man7/vdso.7.html) è una shared library che aumenta la performance di alcune system call.

[`libc.so.6`](http://man7.org/linux/man-pages/man7/libc.7.html) è la C standard library di Linux che è stata linkata dinamicamente.

## Prima esplorazione

Con `objdump -d hello.out` disassembliamo il file binario `hello.out`. Analizziamo solo alcune parti dell'output, che è molto grande:

```assembly
000000000000063a <main>:
 63a:	55                   	push   %rbp
 63b:	48 89 e5             	mov    %rsp,%rbp
 63e:	48 8d 3d 9f 00 00 00 	lea    0x9f(%rip),%rdi
 645:	e8 c6 fe ff ff       	callq  510 <puts@plt>
 64a:	b8 00 00 00 00       	mov    $0x0,%eax
 64f:	5d                   	pop    %rbp
 650:	c3                   	retq   
 651:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
 658:	00 00 00 
 65b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
```

`push %rbp` e `pop %rbp` sono usate rispettivamente nel prologo e nell'epilogo delle subroutine, per salvare sullo stack il contenuto di un registro o prelevare dallo stack il contenuto della memoria.

`%rbp` e `%rsp` sono due registri special purpose, rispettivamente usati come *base pointer* (puntatore alla base del record di attivazione della subroutine corrente) e *stack pointer* (puntatore alla cima del record di attivazione della subroutine corrente). In realtà, in questo programma, questi due registri non sono strettamente necessari, in quanto nella funzione `main` non vi sono variabili locali cui bisogni riferirsi.

`lea 0x9f(%rip),%rdi` carica in `%rdi` l'indirizzo di memoria dato dalla somma di `%rip` (un registro special purpose puntatore all'istruzione corrente) e 0x9f, cioè 6e4 (645 - 9f). All'indirizzo 6e4 si trova la stringa `Hello, World!\n`. Più precisamente, la stringa è contenuta nella sezione `.rodata`, che possiamo analizzare con `objdump -s hello.out -j .rodata`:

```assembly
hello.out:     file format elf64-x86-64

Contents of section .rodata:
 06e0 01000200 48656c6c 6f2c2057 6f726c64 ....Hello, World
 06f0 2100                              	!.                   
```

`callq 510` è un'invocazione della subroutine all'indirizzo di memoria 510:

```assembly
0000000000000510 <puts@plt>:
 510:	ff 25 ba 0a 20 00    	jmpq   *0x200aba(%rip)        # 200fd0 <puts@GLIBC_2.2.5>
 516:	68 00 00 00 00       	pushq  $0x0
 51b:	e9 e0 ff ff ff       	jmpq   500 <.plt>
```

Il compilatore, accorgendosi che `Hello, World!\n` è una *string literal*, ha effettuato un'ottimizzazione traducendo `printf` in `puts`.

Infine, `mov $0x0,%eax` corrisponde a `return 0;` del codice in C.

Siamo arrivati fin qua, ma c'è un "problema": l'istruzione `jmpq` (all'indirizzo di memoria 510), che salta alla subroutine all'indirizzo 200fd0, non è che una reference alla C standard library (in altre parole, è la funzione wrapper di cui parlavamo, che si occupa di gestire per noi la system call per `puts`).

Pertanto, rintracciare la parte di codice che rappresenta la system call è abbastanza problematico: ci serve un "escamotage".

## Un tentativo

Proviamo a cambiare il programma C invocando la funzione `write`:

```c
#include <unistd.h>
int main()
{
	write(1, "Hello, World!\n", 14);	//1: file descriptor, 14: byte
	return 0;
}
```

L'header `unistd.h` contiene la definizione della funzione `write`.

Questa funzione fa parte della API che i sistemi operativi conformi allo standard POSIX devono mandatoriamente implementare. Nonostante non sia funzione richiesta dallo standard del linguaggio C, è la C standard library a fornirne un'implementazione.

È possibile scrivere qualcosa di ancor più basso livello? Sì: come abbiamo accennato prima, `unistd.h` mette a disposizione la funzione `syscall`, che permette di invocare una qualsiasi system call e si rivela particolarmente utile quando la glibc non fornisce un wrapper per quest'ultima.

L'header `sys/syscall.h` contiene le costanti simboliche delle system calls.

Modifichiamo nuovamente il programma C nella maniera seguente:

```c
#include <unistd.h>
#include <sys/syscall.h>
int main()
{
	syscall(SYS_write, 1, "Hello, World!\n", 14);
    	return 0;
}
```

Il programma si può ancora compilare ed eseguire correttamente.

Disassembliamo nuovamente l'eseguibile con `objdump -d hello.out`:

```assembly
000000000000064a <main>:
 64a:	55                   	push   %rbp
 64b:	48 89 e5             	mov    %rsp,%rbp
 64e:	b9 0e 00 00 00       	mov    $0xe,%ecx
 653:	48 8d 15 aa 00 00 00 	lea    0xaa(%rip),%rdx
 65a:	be 01 00 00 00       	mov    $0x1,%esi
 65f:	bf 01 00 00 00       	mov    $0x1,%edi
 664:	b8 00 00 00 00       	mov    $0x0,%eax
 669:	e8 b2 fe ff ff       	callq  520 <syscall@plt>
 66e:	b8 00 00 00 00       	mov    $0x0,%eax
 673:	5d                   	pop    %rbp
 674:	c3                   	retq   
 675:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
 67c:	00 00 00 
 67f:	90                   	nop
```

Notiamo quattro istruzioni:

- `mov $0xe,%ecx` mette il valore 14 nel registro `%ecx`,
- `lea 0xaa(%rip),%rdx` mette l'indirizzo della stringa `Hello, World!\n` in `%rdx`,
- `mov $0x1,%esi` e `mov $0x1,%edi` mettono il valore 1 nei registri `%esi` e `%edi`. Questi argomenti rappresentano il numero della system call che vogliamo effettuare e il file descriptor per lo standard output.

Queste istruzioni realizzano il passaggio degli argomenti alla subroutine invocata successivamente con l'istruzione `callq 520`.

All'indirizzo di memoria 520 troviamo nuovamente una reference alla C standard library.

```assembly
 0000000000000520 <syscall@plt>:
 520:	ff 25 aa 0a 20 00    	jmpq   *0x200aaa(%rip)        # 200fd0 <syscall@GLIBC_2.2.5>
 526:	68 00 00 00 00       	pushq  $0x0
 52b:	e9 e0 ff ff ff       	jmpq   510 <.plt>
```

Non abbiamo ancora avuto modo di vedere una vera e propria invocazione della system call...

## Static linking

Per andare avanti nella nostra missione esplorativa, linkiamo staticamente le librerie. Questo si consegue con l'opzione **static** per il linker: `gcc -static -o hello.out hello.c`. Sostanzialmente, il linker estrae il codice necessario dalla versione statica della C standard library, `libc.a`, che verrà iniettato nel file eseguibile. In questo modo, nel file eseguibile saranno incluse le istruzioni che realizzano la system call.

Dal momento che le librerie sono state linkate staticamente, la dimensione di *hello.out* cresce a 895 kilobyte, ed è ben maggiore rispetto agli 8.3 kilobyte precedenti.

`ldd hello.out` indica, giustamente,

> not a dynamic executable

Analizziamo alcune parti di `hello.out`.

Nella sezione `main` vi sono le usuali istruzioni che realizzano lo scambio dei parametri per l'imminente invocazione di procedura, e l'unico cambiamento interessante è dato dall'istruzione:

```assembly
  400b6c:	e8 ef 93 04 00       	callq  449f60 <syscall>
```

All'indirizzo di memoria 449f60 abbiamo:

```assembly
0000000000449f60 <syscall>:
  449f60:	48 89 f8             	mov    %rdi,%rax
  449f63:	48 89 f7             	mov    %rsi,%rdi
  449f66:	48 89 d6             	mov    %rdx,%rsi
  449f69:	48 89 ca             	mov    %rcx,%rdx
  449f6c:	4d 89 c2             	mov    %r8,%r10
  449f6f:	4d 89 c8             	mov    %r9,%r8
  449f72:	4c 8b 4c 24 08       	mov    0x8(%rsp),%r9
  449f77:	0f 05                	syscall 
  449f79:	48 3d 01 f0 ff ff    	cmp    $0xfffffffffffff001,%rax
  449f7f:	73 01                	jae    449f82 <syscall+0x22>
  449f81:	c3                   	retq   
  449f82:	48 c7 c1 c0 ff ff ff 	mov    $0xffffffffffffffc0,%rcx
  449f89:	f7 d8                	neg    %eax
  449f8b:	64 89 01             	mov    %eax,%fs:(%rcx)
  449f8e:	48 83 c8 ff          	or     $0xffffffffffffffff,%rax
  449f92:	c3                   	retq   
  449f93:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  449f9a:	00 00 00 
  449f9d:	0f 1f 00             	nopl   (%rax)
```

Si tratta dell'implementazione vera e propria della system call `write`, che, come vediamo, effettua una trap nel kernel mediante l'istruzione `syscall`.

## Osservazioni finali

Ora che abbiamo potuto apprezzare la natura di basso livello di una system call, concludiamo con un'ultima osservazione.

Compiliamo il file *hello.c* nel file assembly *hello.S* con il comando `gcc -S hello.c -o hello.S`. 

Esaminiamo *hello.s*:

```assembly
	.file	"hello.c"
	.text
	.section	.rodata
.LC0:
	.string	"Hello, World!\n"
	.text
	.globl	main
	.type	main, @function
main:
.LFB0:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	$14, %ecx
	leaq	.LC0(%rip), %rdx
	movl	$1, %esi
	movl	$1, %edi
	movl	$0, %eax
	call	syscall@PLT
	movl	$0, %eax
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE0:
	.size	main, .-main
	.ident	"GCC: (Ubuntu 7.3.0-27ubuntu1~18.04) 7.3.0"
	.section	.note.GNU-stack,"",@progbits
```

Anche qui, in linea con le nostre aspettative, notiamo le istruzioni per il passaggio dei parametri, con i valori corretti.

### Vi sono margini di miglioramento?

Sì, in quanto gcc ha più volte inserito molti elementi non necessari alla stampa della stringa `Hello, World!\n.` Un giorno mostreremo come ridurre al minimo il codice Assembly :-)
