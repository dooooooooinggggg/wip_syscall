
# ptraceで実行中のプロセスを書き換える。

>Linux などの多くの Unix 的なOS には ptrace というシステムコールがあります。
>ptrace を使うと実行中のプロセスに対して、レジスタの書き換えやメモリ上のデータの書き換えといったさまざまな操作を行うことができます。

>ptrace はデバッガ用に作られた API のようですが、使い方によっては他にもおもしろい用途があるかもしれません。

ようは、ptraceというシステムコールを使って、他のプロセスを書き換えるプログラムを作成する。

```c

#include <stdio.h>

int main(){
    while(1){
        printf("hello, world!");
    }

    return 0;
}

```

このようなプロセスに対して、

```shell

$ objdump -s helloworld_mac | grep -C1 hello

# helloworld_mac: file format Mach-O 64-bit x86-64

# --
# --
# Contents of section __cstring:
#  100000fa6 68656c6c 6f2c2077 6f726c64 2100      hello, world!.
# Contents of section __unwind_info:

```

ここで、hellの16進数での表現は、
`68656c6c`である。

上から順に、hellである。
0x68
0x65
0x6c
0x6c

ここで、これを書き換えるプログラムを書く。

`ptrace.c`にて。

## つまり

>ptrace の操作はカーネル内で行われるため、ユーザスペースではできないことも平気でできてしまいます。

ここで実行してみる。
ある端末で、hello worldがひたすら表示されるものを実行、
その前に、objdumpで、hello worldが始まる部分をメモっておく。
今回の場合は、`0750`だったので、`0x0750`を第2引数にする。
第1引数は、`3273`(pid)
第3引数は、書き込みたい文字列(今回は、hipp(厳密には違う、ppihになってしまう)なので、`0x68697070`)


```shell

\# ps a | grep helloworld

# 3273 pts/0 S+ 0.01 ./helloworld

\# ./sampleptrace 3273 0x750 0x68697070
# Segmentation fault

```

```c

int main( int argc, char *argv ){
    // assert が実行されたとき,expression が 0 (偽) であれば,
    // プログラムの実行を停止し,assert が呼び出された箇所を表示します.
    assert( argc == 4 );
    // 文字列で表現された数値をint型の数値に変換する。
    // 変換不能なアルファベットなどの文字列の場合は0を返すが、数値が先頭にあればその値を返す。
    pid_t pid = atoi(argv[1]); // pid_t = UNIXおよびPOSIX準拠システム(Linuxなど)のC/C++で使われる、プロセスIDを表わす型。
    void *addr = (void *)strtol(argv[2], NULL, 0);
    void *word = (void *)strtol(argv[3], NULL, 0);
    assert( ptrace(PTRACE_ATTACH, pid, NULL, NULL) == 0 );// ptrace(PTRACE_ATTACH, pid, NULL, NULL) = 0でなければならない。
    wait(NULL);
    assert( ptrace(PTRACE_POKEDATA, pid, addr, word) == 0 );
    assert( ptrace(PTRACE_DETACH, pid, NULL, NULL) == 0 );
    return 0;
}


```

落ちた。

## gucchanさんにアドバイスを求めた結果

基本的に、OSはカーネル空間とユーザー空間の二つがあってプロセスごとに仮想メモリっていう仕組みを使って

めちゃくちゃ広いメモリを使えるかのように見せてくれるんだけど、まずカーネル空間上で動くカーネルのプログラムがユーザー空間で動いてるプロセスを管理してるので

Ptraceはカーネル空間上で実装されているものであることからカーネルにこのpidのユーザープロセスを制御したいっていうことを伝えて、
そのユーザー空間のメモリ空間（.textとかヒープとか)をいじることができるという解釈でいい。

システムコール自体はOSの持っている機能にユーザープログラム側からアクセスするための手段として提供されている。
なので、空間が別々に分かれているということがイメージできていたらOKだと思う。

あとたぶんエラーに関してだけど配置アドレスを指定するところが32bitで指定してSegmentation faultになっているので64bitだからだと思うなー。


ちょっとヒント。でも32bitLinux持ってないからデバッグ一回もしてないからたぶん動かないとは思うけどだいたいこんな感じじゃないのかな？ptraceのドキュメント見たりしてあとは自分で動くようにやってみてほしい

システムコールは呼び出される時にこういう操作をアセンブリでやるんだけど、
実行プロセスのシステムコールをとるんだったら該当プロセスのeaxだけをとりあえず取得してどういうシステムコールが呼ばれてるのかどうかをチェックしてる。



## ptraceシステムコール一覧

```c

long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);

```


## PTRACE_TRACEME

このプロセスが親プロセスによってトレースされることを表す。

## PTRACE\_PEEKTEXT, PTRACE_PEEKDATA

子プロセスのメモリの addr の位置から 1 ワードを読み出す。
引数 data は無視される。

## PTRACE_PEEKUSR

子プロセスの USER 領域のオフセット addr の位置から 1 ワードを読み込む。
引数 data は無視される。

## PTRACE\_POKETEXT, PTRACE_POKEDATA

ワード data を子プロセスのメモリの addr の位置へコピーする。

## PTRACE_POKEUSR

ワード data を子プロセスの USER 領域のオフセット addr の位置にコピーする。

## PTRACE\_GETREGS, PTRACE_GETFPREGS

それぞれ、子プロセスの汎用レジスタ、浮動小数点レジスタを親プロセスの data の位置にコピーする。
この data の書式に関しては <linux/user.h> を参照すること。(addr は無視される。)

## PTRACE\_SETREGS, PTRACE_SETFPREGS

それぞれ、子プロセスの汎用レジスタ、浮動小数点レジスタに 親プロセスの date の位置からコピーする。
addr は無視される。

## PTRACE\_SYSCALL, PTRACE_SINGLESTEP

PTRACE\_CONT と同様に停止した子プロセスを再開する。 ただし、PTRACE\_SYSCALL の場合は子プロセスが 次にシステムコールに入るかシステムコールから抜けるかする時に、 PTRACE\_SINGLESTEP の場合は 1 命令 (instruction) 実行した後に停止させる (通常どおり、子プロセスはシグナルを受け取った場合にも停止する)。 親プロセスから見ると、子プロセスは SIGTRAP を受信して 停止したように見える。そのため、例えば PTRACE\_SYSCALL を使うと、 1回目の停止で引き数を調べて PTRACE_SYSCALL を実行し、 2回目の停止でシステムコールの返り値を調べる、 というようなことができる。(addr は無視される。)

##


##





# 参考文献

[http://0xcc.net/blog/archives/000077.html](http://0xcc.net/blog/archives/000077.html)

















