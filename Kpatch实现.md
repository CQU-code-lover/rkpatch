# 结构

>  kpatch-build：用于将源码patch生成ko热补丁
>
>  patch module：指生成的ko热补丁，包括需要新的函数和被替换函数的记录信息
>
>  kpatch core module: kpatch核心代码模块，为新旧函数热替换提供接口， 使用kpatch时候是kpatch.ko模块，使用livepatch的时候不存在，因为内核已经支持livepatch
>
>  kpatch utility: kpatch管理工具，主要是kpatch命令(kpatch list/load/unload 查询／加载／卸载)
>   kpatch-build作为生成热补丁的用户态工具，同时支持kpatch和livepatch的生成，具体哪个取决于CONFIG_LIVEPATCH，centos 4.18内核开始支持livepatch。

# Examle　

0001-xfs-debug-xfs-log.patch：

```
From e63f82904ace5c35aab5af05b17f00b949c28e6b Mon Sep 17 00:00:00 2001
From: hanjinke <didiglobal.com>
Date: Thu, 8 Apr 2021 15:18:04 +0800
Subject: [PATCH] xfs: debug xfs log

Signed-off-by: hanjinke <didiglobal.com>
---

 fs/xfs/xfs_log.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/fs/xfs/xfs_log.c b/fs/xfs/xfs_log.c
index 2466b0f5b..b2f8e0568 100644
--- a/fs/xfs/xfs_log.c
+++ b/fs/xfs/xfs_log.c
@@ -3331,6 +3331,8 @@ xfs_log_force(
 	XFS_STATS_INC(mp, xs_log_force);
 	trace_xfs_log_force(mp, 0, _RET_IP_);

+	dump_stack();
  +

 	xlog_cil_force(log);
 	 
 	spin_lock(&log->l_icloglock);

-- 
```

　0001-xfs-debug-xfs-log.patch这个patch很简单，就是在xfs_log_force函数里添加了一行dump_stack()，用于打印同步xfs log的调用流程。

   生成livepatch的命令：　

```shell
kpatch-build -v /usr/lib/debug/lib/modules/4.18.0-193.6.3.el8_2.x86_64/vmlinux -c /boot/config-4.18.0-193.6.3.el8_2.x86_64 -s kernel-4.18.0-193.6.3.el8_2/ 0001-xfs-debug-xfs-log.patch
```

　最终生成livepatch-0001-xfs-debug-xfs-log.ko，kpatch load livepatch-0001-xfs-debug-xfs-log.ko完成加载，kpatch list查询是否安装成功。

# kpatch build

## 找到更改的xfs_log.o

  kpatch-build首先编译一遍orig内核，在打入0001-xfs-debug-xfs-log.patch，再编译一遍patched 内核。那么如何找到patch涉及到哪些.o文件的更改。

  看下kpatch-buiild的编译内核的CC工具：

```
　888 echo "Building original source"
 889 [[ -n "$OOT_MODULE" ]] || ./scripts/setlocalversion --save-scmversion || die
 890 unset KPATCH_GCC_TEMPDIR
 891 
 892 KPATCH_CC_PREFIX="$TOOLSDIR/kpatch-cc "
 893 declare -a MAKEVARS
 894 if [ "$CONFIG_CC_IS_CLANG" -eq 1 ]; then
 895     MAKEVARS+=("CC=${KPATCH_CC_PREFIX}clang")
 896     MAKEVARS+=("HOSTCC=clang")
 897 else
 898     MAKEVARS+=("CC=${KPATCH_CC_PREFIX}gcc")
 899 fi
 900 
 901 if [ "$CONFIG_LD_IS_LLD" -eq 1 ]; then
 902     MAKEVARS+=("LD=${KPATCH_CC_PREFIX}ld.lld")
 903     MAKEVARS+=("HOSTLD=ld.lld")
 904 else
 905     MAKEVARS+=("LD=${KPATCH_CC_PREFIX}ld")
 906 fi
 907 
```

892行，CC的前缀是"$TOOLSDIR/kpatch-cc "，而898行CC=${KPATCH_CC_PREFIX}gcc") 也就是CC＝"$TOOLSDIR/kpatch-cc 　gcc"。相当于每次执行CC的时候都会执行kpatch-cc脚本，相当于对CC进行了一次hook。 看下kpatch-cc脚本：



```
 1 #!/bin/bash
  2 
  3 if [[ ${KPATCH_GCC_DEBUG:-0} -ne 0 ]]; then
  4     set -o xtrace
  5 fi
  6 TOOLCHAINCMD="$1"
  7 shift
  8 
  9 if [[ -z "$KPATCH_GCC_TEMPDIR" ]]; then
 10     exec "$TOOLCHAINCMD" "$@"
 11 fi
 12 
 13 declare -a args=("$@")
 14 
 15 if [[ "$TOOLCHAINCMD" =~ ^(.*-)?gcc$ || "$TOOLCHAINCMD" =~ ^(.*-)?clang$ ]] ; then
 16     while [ "$#" -gt 0 ]; do
 17         if [ "$1" = "-o" ]; then
 18             obj="$2"
 19 
 20             # skip copying the temporary .o files created by
 21             # recordmcount.pl
 22             [[ "$obj" = */.tmp_mc_*.o ]] && break;
 23 
 24             [[ "$obj" = */.tmp_*.o ]] && obj="${obj/.tmp_/}"
 25             relobj=${obj//$KPATCH_GCC_SRCDIR\//}
 26             case "$relobj" in
 27                 *.mod.o|\
 28                 *built-in.o|\
 29                 *built-in.a|\
 30                 vmlinux.o|\
 31                 .tmp_kallsyms1.o|\
 32                 .tmp_kallsyms2.o|\
 33                 init/version.o|\
 34                 arch/x86/boot/version.o|\
 35                 arch/x86/boot/compressed/eboot.o|\
 36                 arch/x86/boot/header.o|\
 37                 arch/x86/boot/compressed/efi_stub_64.o|\
 38                 arch/x86/boot/compressed/piggy.o|\
 39                 kernel/system_certificates.o|\
 40                 arch/x86/vdso/*|\
 41                 arch/x86/entry/vdso/*|\
 42                 drivers/firmware/efi/libstub/*|\
 43                 arch/powerpc/kernel/prom_init.o|\
 44                 arch/powerpc/kernel/vdso64/*|\
 45                 lib/*|\
 46                 .*.o|\
 47                 */.lib_exports.o)
  48                     break
 49                     ;;
 50                 *.o)
 51                     echo "$relobj changed!!!!" >> /mnt/outlog
 52                     mkdir -p "$KPATCH_GCC_TEMPDIR/orig/$(dirname "$relobj")"
 53                     [[ -e "$obj" ]] && cp -f "$obj" "$KPATCH_GCC_TEMPDIR/orig/$relobj"
 54                     echo "$relobj" >> "$KPATCH_GCC_TEMPDIR/changed_objs"
 55                     break
 56                     ;;
 57                 *)
 58                     break
 59                     ;;
 60             esac
 61         fi
 62         shift
 63     done
 64 elif [[ "$TOOLCHAINCMD" =~ ^(.*-)?ld || "$TOOLCHAINCMD" =~ ^(.*-)?ld.lld ]] ; then
 65     while [ "$#" -gt 0 ]; do
 66         if [ "$1" = "-o" ]; then
 67             obj="$2"
 68             relobj=${obj//$KPATCH_GCC_SRCDIR\//}
 69             case "$obj" in
 70                 *.ko)
 71                     mkdir -p "$KPATCH_GCC_TEMPDIR/module/$(dirname "$relobj")"
 72                     cp -f "$obj" "$KPATCH_GCC_TEMPDIR/module/$relobj"
 73                     break
 74                     ;;
 75                 .tmp_vmlinux*|vmlinux)
 76                     args+=(--warn-unresolved-symbols)
 77                     break
 78                     ;;
 79                 *)
 80                     break
 81                     ;;
 82             esac
 83         fi
 84         shift
 85     done
 86 fi
 87 
 88 exec "$TOOLCHAINCMD" "${args[@]}"
```


　在编译orig 内核的时候，第９行，$KPATCH_GCC_TEMPDIR没有设置，脚本会在第10行返回，在编译patched kernel的时候，kpatch-build会设置$KPATCH_GCC_TEMPDIR，同时由于kennel是增量编译，我们修改了xfs_log.c文件，只会重新编译xfs_log.o文件，最终会进入case 2也就是50行，会把xfs_log.o文件拷贝到$KPATCH_GCC_TEMPDIR/orig/目录下，并把xfs_log.o这个名字写入$KPATCH_GCC_TEMPDIR/changed_objs，我们就拿到了被修改的.o文件xfs_log.o。

## 拿到xfs_log.o之后，如何知道xfs_log.o里的那些函数被修改了

　　　create-diff-object工具负责完成以上工作，主要实现位于kpatch/kpatch-build/create-diff-object.c。

　前面提到kptatch-build会编译origin kernel和patched kernel，这和普通的编译内核不太一样，主要区别kpatch-build编译时候使用gcc的”-ffunction-sections “和”-fdata-sections“

　-ffunction-sections “会把每个函数单独编译成一个elf的代码section，”-fdata-sections“把每个数据变量单独编译成一个elf的数据section。

　ex：

```
[root@localhost xfs]# readelf -S xfs_log.o | grep text.*PROGBITS
  [ 1] .text             PROGBITS         0000000000000000  00000040
  [ 4] .text.xlog_grant_ PROGBITS         0000000000000000  00000040
  [ 8] .text.xlog_get_ic PROGBITS         0000000000000000  000007e0
  [11] .text.xlog_space_ PROGBITS         0000000000000000  00000960
  [13] .text.xlog_grant_ PROGBITS         0000000000000000  00000ad0
  [15] .text.xlog_grant_ PROGBITS         0000000000000000  00000bd0
  [19] .text.xlog_state_ PROGBITS         0000000000000000  00001460
  [21] .text.xlog_bdstra PROGBITS         0000000000000000  00001570
  [25] .text.xlog_alloc_ PROGBITS         0000000000000000  00001770
  [27] .text.xlog_deallo PROGBITS         0000000000000000  00002010
  [30] .text.xlog_state_ PROGBITS         0000000000000000  00002210
  [36] .text.xlog_grant_ PROGBITS         0000000000000000  00002310
  [40] .text.xlog_regran PROGBITS         0000000000000000  00002500
  [42] .text.xlog_pack_d PROGBITS         0000000000000000  00002850
  [44] .text.xlog_state_ PROGBITS         0000000000000000  000029b0
  [46] .text.xlog_iclogs PROGBITS         0000000000000000  00002a00
  [48] .text.xlog_get_lo PROGBITS         0000000000000000  00002a50
  [50] .text.xlog_state_ PROGBITS         0000000000000000  00002ad0
  [52] .text.xlog_grant_ PROGBITS         0000000000000000  00002c00
  [58] .text.xlog_grant_ PROGBITS         0000000000000000  00003c30
  [61] .text.xlog_state_ PROGBITS         0000000000000000  00003d00
  [63] .text.xlog_state_ PROGBITS         0000000000000000  00004140
  [65] .text.xlog_iodone PROGBITS         0000000000000000  00004260
  [67] .text.xlog_grant_ PROGBITS         0000000000000000  000043c0
  [69] .text.xfs_log_reg PROGBITS         0000000000000000  00004580
  [72] .text.xfs_log_not PROGBITS         0000000000000000  00004940
  [76] .text.xfs_log_mou PROGBITS         0000000000000000  00004cd0
  [78] .text.xfs_log_ite PROGBITS         0000000000000000  00005320
  [80] .text.xfs_log_spa PROGBITS         0000000000000000  00005390
  [82] .text.xlog_ungran PROGBITS         0000000000000000  00005590
  [84] .text.xlog_assign PROGBITS         0000000000000000  000058b0
  [86] .text.xlog_assign PROGBITS         0000000000000000  000059d0
  [88] .text.xfs_log_wor PROGBITS         0000000000000000  00005a70
  [90] .text.xlog_cksum  PROGBITS         0000000000000000  00005b10
  [93] .text.xlog_sync   PROGBITS         0000000000000000  00005c50
  [95] .text.xlog_state_ PROGBITS         0000000000000000  00006260
```

　每个函数都是单独的代码段，而正常的编译内核一个.o目标文件只有一个text section，包含本文件内所有函数汇编。

　总体来说，create-diff-object工具完成以下几种工作：

- 1.**create-diff-object**

  工具使用有七个参数：

　　参数1：origin_obj，原始xfs_log.o的路径

　　参数2： patched_obj，patch之后xfs_log.o的路径

  		参数3： parent_name，一般是patch所在的模块名字，如果不是模块则是vmlinux。本文中是xfs

   		参数4：parent_symtab，patch之后，xfs_ko.symtab，包含xfs模块符号表（由readelf -s xfs.ko > xfs_ko.symtab，此xfs.ko是patched后的）

　　参数5: mod_symvers，patch之后内核的Module.symvers，包含内核的所有导出符号的校验信息

　　参数6：patch_name，要生成的livapatch的名字，本文是livepatch_0001_debug_xfs

　　参数7：output_name，输出文件的路径，输出文件依然是xfs_log.o

- 2.elf解析工作

　　create_diff_object中一个elf用kpatch_elf表示：

```
struct kpatch_elf {
    Elf *elf;　　　　　　　　　　　// 标准ELF描述符
    struct list_head sections;　// section的链表
    struct list_head symbols;　　//　符号链表
    struct list_head strings;　　// 字符串链表
    int fd;　　　　　　　　　　　　　// elf文件的打开描述符　　　　　　　
};
```

 kpatch_elf_open主要负责解析elf文件，分别对origin和patched xfs_log.o进行解析。

根据elf文件格式解析出所有的section放入kpatch_elf的section链表。

从.symtab解析出所有symbol放入kpatch-elf的symbols链表。

对于重定位的section，解析出每个rela挂入相应sec->relas链表。

扫描每个func类型的symblol所在的section的所有rela，如果有fentry_的重定位项，设置sym->has_func_profiling＝１，表明此函数可以被ftrace跟踪，也就可以被patch，因为kpatch/livepatch是基于ftrace机制。fentry重定位项位于函数首部，内核初始化或者模块加载的时候fentry__类型的重定位项会被替换为nop指令。

- 3.**符号解析工作**

lookup_open负责符号解析工作，解析结果放入struct lookup_table:

```
 struct lookup_table {
     int obj_nr, exp_nr;
     struct object_symbol *obj_syms;
     struct export_symbol *exp_syms;
     struct object_symbol *local_syms;
     char *objname;
 };
```

首先解析内核的Module.symvers文件，Module.symvers文件存放vmlinux的所有导出符号的名字和对应函数的crc校验，解析结果放入lookup_table->exp_syms，相当于内核导出符号表。

接下来解析patch后的xfs.ko的符号表，结果存在在loopup_table->obj_syms。

最后，找到xfs_log.c所对应的symbol给lookup_table->local_sym，这也是xfs_log.c文件内local的起始位置。以后查找xfs_log.c内的local symbol是从这里开始查找。

- 4.**找出改变的函数**

 找出改变的函数，也就是找出具体需要patch的函数，这是是create-diff-object的关键。

主要分两步完成：

　　第一步，通过kpatch_correlate_elfs函数完成原始的xfs_log.o和patched的xfs_log.o的section的配对。

　　前面提过，由于gcc编译选项”-ffunction-sections“，每个函数对应一个单独的text section，例如函数xlog_sync对应的text section的名字为.text.xlog_sync。

  kpatch_correlate_elfs遍历oriigin xfs_log.o和patched　xfs_log.o的所有func类型的section，如果section的名字相同，说明就是相同函数的section，original和patched xfs_log.o的同一函数的section被成为twin。

　　function类型的section如果没有找到相应的twin，说明是patch的的新函数，sec->status设置为NEW。

  第二步，通过kpatch_compare_correlated_elements函数比较每个twin中的两个section是否相同来确定函数是否改变。

　　快速比较sec->sh.sh_size 和sec->data->d_size，即比较sec的hdr的长度和内容长度，如果不相等设置sec->status = CHANGED，如果相等再进行sec->data->d_buf的sec的内容的全比较。

　　最后根据sec的status来设置相应的symbol的status。

- 5**.构建 livepatch symbol和livepatch relocation** 

   最终生成livepatch的本质是ko文件，ko文件是在模块加载时候进行重定位操作，类似动态库加载。

　　不同的是，普通内核模块除了使用内部local 符号外，对于外部符号，只能引用内核导出符号，模块的加载机制也只能解析内核导出符号，并进行重定位操作。

　　对于livepatch，patched的函数不可避免的要使用大量本地符号和内核未导出符号，这样原有的模块加载机制就无法工作。

　　为此，livepatch给自己开了后门，定义了自己的 livepatch symbol和livepatch relocation。

   livepatch symbol指livepatch引用的普通模块加载机制无法解析的符号集，livepatch relocation 是引用livapatch symbols的重定位项。

　　kpatch_create_intermediate_sections函数负责构建.kpatch.relocations和.kpatch.symbol两个section。

```
static void kpatch_create_intermediate_sections(struct kpatch_elf *kelf,
                        struct lookup_table *table,
                        char *objname,
                        char *pmod_name)
{
    int nr, index;
    struct section *sec, *ksym_sec, *krela_sec;
    struct rela *rela, *rela2, *safe;
    struct symbol *strsym, *ksym_sec_sym;
    struct kpatch_symbol *ksyms;
    struct kpatch_relocation *krelas;
    struct lookup_result symbol;
    bool special;
    bool vmlinux = !strcmp(objname, "vmlinux");
    struct special_section *s;

    /* count rela entries that need to be dynamic */
    nr = 0;
    list_for_each_entry(sec, &kelf->sections, list) {
        if (!is_rela_section(sec))
            continue;
        if (!strcmp(sec->name, ".rela.kpatch.funcs")) {
            continue;
        }
     
        list_for_each_entry(rela, &sec->relas, list) {
     
            /* upper bound on number of kpatch relas and symbols */
            nr++;
     
            /*
             * We set 'need_dynrela' here in the first pass because
             * the .toc section's 'need_dynrela' values are
             * dependent on all the other sections.  Otherwise, if
             * we did this analysis in the second pass, we'd have
             * to convert .toc dynrelas at the very end.
             *
             * Specifically, this is needed for the powerpc
             * internal symbol function pointer check which is done
             * via .toc indirection in need_dynrela().
             */
            if (need_dynrela(table, rela))
                toc_rela(rela)->need_dynrela = 1;
        }

   }

    /* create .kpatch.relocations text/rela section pair */
    krela_sec = create_section_pair(kelf, ".kpatch.relocations", sizeof(*krelas), nr);
    krelas = krela_sec->data->d_buf;
     
    /* create .kpatch.symbols text/rela section pair */
    ksym_sec = create_section_pair(kelf, ".kpatch.symbols", sizeof(*ksyms), nr);
    ksyms = ksym_sec->data->d_buf;
     
    /* create .kpatch.symbols section symbol (to set rela->sym later) */
    ALLOC_LINK(ksym_sec_sym, &kelf->symbols);
    ksym_sec_sym->sec = ksym_sec;
    ksym_sec_sym->sym.st_info = GELF_ST_INFO(STB_LOCAL, STT_SECTION);
    ksym_sec_sym->type = STT_SECTION;
    ksym_sec_sym->bind = STB_LOCAL;
    ksym_sec_sym->name = ".kpatch.symbols";
     
    /* lookup strings symbol */
    strsym = find_symbol_by_name(&kelf->symbols, ".kpatch.strings");
    if (!strsym)
        ERROR("can't find .kpatch.strings symbol");
     
    /* populate sections */
    index = 0;
    list_for_each_entry(sec, &kelf->sections, list) {
        if (!is_rela_section(sec))
            continue;
        if (!strcmp(sec->name, ".rela.kpatch.funcs") ||
            !strcmp(sec->name, ".rela.kpatch.relocations") ||
            !strcmp(sec->name, ".rela.kpatch.symbols"))
            continue;
     
        special = false;
        for (s = special_sections; s->name; s++)
            if (!strcmp(sec->base->name, s->name))
                special = true;
     
        list_for_each_entry_safe(rela, safe, &sec->relas, list) {
            if (!rela->need_dynrela)
                continue;
     
            /*
             * Starting with Linux 5.8, .klp.arch sections are no
             * longer supported: now that vmlinux relocations are
             * written early, before paravirt and alternative
             * module init, .klp.arch is technically not needed.
             *
             * For sanity we just need to make sure that there are
             * no .klp.rela.{module}.{section} sections for special
             * sections.  Otherwise there might be ordering issues,
             * if the .klp.relas are applied after the module
             * special section init code (e.g., apply_paravirt)
             * runs due to late module patching.
             */
            if (!KLP_ARCH && !vmlinux && special)
                ERROR("unsupported dynrela reference to symbol '%s' in module-specific special section '%s'",
                      rela->sym->name, sec->base->name);
     
            if (!lookup_symbol(table, rela->sym->name, &symbol))
                ERROR("can't find symbol '%s' in symbol table",
                      rela->sym->name);
     
            log_debug("lookup for %s: obj=%s sympos=%lu",
                      rela->sym->name, symbol.objname,
                  symbol.sympos);
     
            /* Fill in ksyms[index] */
            if (vmlinux)
                ksyms[index].src = symbol.addr;
            else
                /* for modules, src is discovered at runtime */
                ksyms[index].src = 0;
            ksyms[index].sympos = symbol.sympos;
            ksyms[index].type = rela->sym->type;
            ksyms[index].bind = rela->sym->bind;
     
            /* add rela to fill in ksyms[index].name field */
            ALLOC_LINK(rela2, &ksym_sec->rela->relas);
            rela2->sym = strsym;
            rela2->type = ABSOLUTE_RELA_TYPE;
            rela2->addend = offset_of_string(&kelf->strings, rela->sym->name);
            rela2->offset = (unsigned int)(index * sizeof(*ksyms) + \
                    offsetof(struct kpatch_symbol, name));
     
            /* add rela to fill in ksyms[index].objname field */
            ALLOC_LINK(rela2, &ksym_sec->rela->relas);
            rela2->sym = strsym;
            rela2->type = ABSOLUTE_RELA_TYPE;
            rela2->addend = offset_of_string(&kelf->strings, symbol.objname);
            rela2->offset = (unsigned int)(index * sizeof(*ksyms) + \
                    offsetof(struct kpatch_symbol, objname));
     
            /* Fill in krelas[index] */
            if (is_gcc6_localentry_bundled_sym(rela->sym) &&
                rela->addend == (int)rela->sym->sym.st_value)
                rela->addend -= rela->sym->sym.st_value;
            krelas[index].addend = rela->addend;
            krelas[index].type = rela->type;
            krelas[index].external = !vmlinux && symbol.exported;
     
            /* add rela to fill in krelas[index].dest field */
            ALLOC_LINK(rela2, &krela_sec->rela->relas);
            if (sec->base->secsym)
                rela2->sym = sec->base->secsym;
            else
                ERROR("can't create dynrela for section %s (symbol %s): no bundled or section symbol",
                      sec->name, rela->sym->name);
     
            rela2->type = ABSOLUTE_RELA_TYPE;
            rela2->addend = rela->offset;
            rela2->offset = (unsigned int)(index * sizeof(*krelas) + \
                    offsetof(struct kpatch_relocation, dest));
     
            /* add rela to fill in krelas[index].objname field */
            ALLOC_LINK(rela2, &krela_sec->rela->relas);
            rela2->sym = strsym;
            rela2->type = ABSOLUTE_RELA_TYPE;
            rela2->addend = offset_of_string(&kelf->strings, objname);
            rela2->offset = (unsigned int)(index * sizeof(*krelas) + \
                offsetof(struct kpatch_relocation, objname));
     
            /* add rela to fill in krelas[index].ksym field */
            ALLOC_LINK(rela2, &krela_sec->rela->relas);
            rela2->sym = ksym_sec_sym;
            rela2->type = ABSOLUTE_RELA_TYPE;
            rela2->addend = (unsigned int)(index * sizeof(*ksyms));
            rela2->offset = (unsigned int)(index * sizeof(*krelas) + \
                offsetof(struct kpatch_relocation, ksym));
     
            /*
             * Mark the referred to symbol for removal but
             * only if it is not from this object file.
             * The symbols from this object file may be needed
             * later (for example, they may have relocations
             * of their own which should be processed).
             */
            if (!rela->sym->sec)
                rela->sym->strip = 1;
            list_del(&rela->list);
            free(rela);
     
            index++;
        }
    }
     
    /* set size to actual number of ksyms/krelas */
    ksym_sec->data->d_size = index * sizeof(struct kpatch_symbol);
    ksym_sec->sh.sh_size = ksym_sec->data->d_size;
     
    krela_sec->data->d_size = index * sizeof(struct kpatch_relocation);
    krela_sec->sh.sh_size = krela_sec->data->d_size;

}
```

   函数主要流程：

　<1>.19-45行，遍历所有rela的section中的所有重定位项，找出需要livepatch自己重定位的重定位项，设置rela->need_dynrela=1筛选函数是need_dynrela函数。

　need_dynrela函数不做展开，主要有以下标准：

　patch中引入的新函数，不需要dynrela，普通的rela就可以。

　patch的object(xfs_log.o)中的本地函数和全局但未导出的函数，需要dynrela。

　位于vmlinux中的导出符号不需要dynrela，但其他模块中的导出符号需要dynrela，主要防止在加载livepatch的时候，这个函数所在的模块还没加载，那样是无法找到它，也就无法进行重定位。

  <2>.创建.kpatch.symbol段和.kpatch.reloctions段

需要说明的是kpatch.symbol是指上文中的livapatch symbol，.kpatch.relocations是指livepatch relocation。这些符号和引用他们的重定位项普通的内核模块加载机制无法处理，需要特殊处理所以需要单独成段，以区别普通的符号表和重定位段。

   遍历xfs_log.o的所有的section，对每个section的重定位段，只处理need_dynrela的重定位项（livepatch relocation)。

   针对每个rela和它引用的symbol，rela加入.kpatch.relacation段，symbol加入.kpatch.symbol段。

   之后针对每个rela和symbol创建若干个相关联的重定位段，比如：

   针对rela的dest成员创建一个rela，用于修正rela的offset成员。

   针对rela的object_name创建一个rela，用于修正rela的object的object_name。

   针对rela的sym创建一个rela创建一个rela，用于修正rela的sym成员。

   同样针对每个symbol的object_name和name成员分别创建两个rela，用于修正symbol的object_name和name成员。

   这些新创建的rela由create-klp-module工具来进行重定位操作，用来还原真实的livepatch rela。rela的生成和重定位也是create-diff-object和create-klp-module约定的操作，并不是elf标准。

   之所以rela和symbol本身需要自己的重定位项，是因为create-diff-object最后会生成output.o的时候，symtab表、shstrtab和strtab表都会发生变化(比如strip掉无用的symbol)，这样原有的rela和symbol就不准确了。

<3>.生成.kpatch.function段

   .kpatch.function段包含的是changged的function，前面第5步说明了找到changed function的过程，每个changed function对应一个struct kpatch_patch_func：

```
 struct kpatch_patch_func {
     unsigned long new_addr; //新函数的地址
     unsigned long new_size; //新函数的大小
     unsigned long old_addr; //旧函数地址
     unsigned long old_size; //旧函数大小
     unsigned long sympos;   //在.kpatch.symbol中的index
     char *name;             //函数名字
     char *objname;          //函数所在的文件的.o的名字
 };
```

 根据changed func的个数创建.kpatch.function段，然后为每个changed func生成一个struct kpatch_patch_func，放入.kpatch.function段中即可。

6.生成xfs_log.o

  create-diff-object工具比较origined xfs_log.o和patched xfs_log.o最终生成xfs_log.o。

 最终生成的xfs_log.o elf文件主要组件具体包括：

<1>.shstrtab、strtab、rodata等这些来自xfs_log.o的段。

<2>.changed func对应的text section、rela section和对应的symbol要包含。orgined和patched xfs_log.o中相同的section及其对应的rela section和symbol，则不需要包含。

因此最终xfs_log.o的shrstrtab(段名字符串表)和strtab(字符串表)相对于patched xfs_log.o也会做相应的瘦身。

<3>.livepatch特有的.kpatch.function段，.kpatch.relocation段和.kpatch.symbol段，分别是changed function列表段，引用livepatch symbol的重定位项组成的段和livepatch symbol段。

(三).生成livepatch的ko文件（livepatch-0001-debug-xfs.ko）

　　kpatch-build里面把cearte-diff-object所有的输出.o文件拷贝到kpatch/kmod/patch目录下，本文的例子只有xfs_log.o，实际上可能很多。patch目录树：

```
patch
├── kpatch.h -> ../core/kpatch.h
├── kpatch.lds.S
├── kpatch-macros.h
├── kpatch-patch.h
├── kpatch-patch-hook.c
├── livepatch-patch-hook.c
├── Makefile
└── patch-hook.c
```

livepatch-patch-hook.c和kpatch-patch-hook.c主要包含ko的初始化函数和卸载函数，livepatch机制使用livepatch-patch-hook.c文件。

kpatch-build首先把所有的create-diff-object的输出.o文件使用ld命令链接为一个ouput.o文件。patch目录下make，livepatch-patch-hook.c生成patch-hook.o，最终依赖output.o和patch-hook.o生成livepatch-0001-debug-xfs.ko文件。

(四).create-klp-module生成最终的livepatch的ko文件

create-klp-module负责生成符合livepatch module elf规范的liveptach ko，livepatch module elf规范参照内核文档Documentation/livepatch/module-elf-format.txt。

具体来说，create-klp-module工作如下：

1.完成.kpatch.symbol和.kpatch.relocation的重定位工作

前面说过，create-diff-object工具针对每个livepatch symbol和livepatch relocation的都生成多个重定位项。这里create-klp-module根据.rela.kpatch.symbol和.rela.kpatch.relocation完成对.kpatch.symbol和.kpatch.relocation的重定位工作，还原出真实的.kpatch.symbol和.kpatch.relocation。

2..kpatch.symbol段和.kpatch.relocation段的最终归属

.kpatch.symbol全部归入符号表.symtab，.kpatch.relocation用来生成.klp.rela段，以本文为例生成.klp.rela.xfs.text段。

对于.kpatch.symbol，全部加入.symtab，由于.kpatch.symbol会存在多个重复的livepatch symbol，所以加入的时候要完成去重。并且对于每个livepatch symbol需要在完成重命名之后再加入.symtab，重命名规则：name命名之后，.klp.sym.name.objname,pos。

.klp.sym：表明这是个livepatch symbol

name:      符号名字

objname: 符号所在的object的名字，内核里符号是vmlinux，内核模块是模块名字

pos:         对于local符号，表示在object中的index，否则是0

对于.kpatch.relocation，用来生成.klp.rela.xfs.text段，这是livepatch ko的elf的专有的段。

3.重新布局livepatch ko的elf，生成最终的livepatch ko文件

.kpatch.symbol/.rela.kpatch.symbol/.kpatch.relocation/.rela.kpatch.relocation这些section不再需要，无需在写入新的elf文件。同时又产生了新的段.klp.rela.xfs.text，所以需要重建节头名字字符串表.shstrtab。

在第2步中，把所有的livepatch symbol全部加入到了.symtab中，这改变了.symtab的布局，需要调用kpatch_reindex_elements对symtab中的symbol重新进行编号，使symbol->index正确反应其在.symtab中的位置。symbol在symtab中的index变了之后，需要调用kpatch_rebuild_rela_section_data函数对每一个重定位段进行修正，具体来说修改其中每个重定位项的r_info字段，使其指向其引用符号的在symtab中的新位置。

同时由于symtab的改变，相应的symbol的字符串表.strtab也需要扩容，把新加入的livepatch symbol的名字全部加进去。

比较重要的一点，在新的符号表.symtab中，对于未定义符号（sym->sec为空），如果是livepatch symbol，symbol的st_shndx 为SHN_LIVEPATCH，对于正常的未定义符号，symbol的st_shndx为SHN_UNDEF。在livepatch ko加载的时候，前者由livepatch的专有机制去解析，后者由内核模块的加载机制去解析。

最后生成新的.shstrtab、.symtab和.strtab，重新布局老的elf后，写入新的livepatch ko文件，生成最终的livepatch ko文件。

(五)．livepatch ko的动态链接

本文为例livepatch ko文件是livepatch-0001-debug-xfs.ko。从elf文件格式的角度来看，livepatch ko文件本质是内核ko文件，但同时又具有livepatch的血统，因此加载又与普通的内核模块加载流程有所不同。本章节主要从动态加载的角度来看下livepatch ko文件在加载的时候的链接过程。

总体来说，livepatch ko的链接主要是包括livepatch相关的链接和正常内核ko的链接两部分。

1.livepatch相关的链接

livepatch的链接包括livepatch symbol的符号解析和livepatch relocation的重定位。符号解析和重定位都是在在klp_write_object_relocations函数里完成。

调用栈：

```
klp_enable_patch
    klp_init_patch
        klp_init_object
            klp_init_object_loaded
                klp_write_object_relocations
```

klp_write_object_relocations函数：

```c
static int klp_write_object_relocations(struct module *pmod,
                    struct klp_object *obj)
{
    int i, cnt, ret = 0;
    const char *objname, *secname;
    char sec_objname[MODULE_NAME_LEN];
    Elf_Shdr *sec;

    if (WARN_ON(!klp_is_object_loaded(obj)))
        return -EINVAL;
     
    objname = klp_is_module(obj) ? obj->name : "vmlinux";
     
    /* For each klp relocation section */
    for (i = 1; i < pmod->klp_info->hdr.e_shnum; i++) {
        sec = pmod->klp_info->sechdrs + i;
        secname = pmod->klp_info->secstrings + sec->sh_name;
        if (!(sec->sh_flags & SHF_RELA_LIVEPATCH))
            continue;
     
        /*
         * Format: .klp.rela.sec_objname.section_name
         * See comment in klp_resolve_symbols() for an explanation
         * of the selected field width value.
         */
        cnt = sscanf(secname, ".klp.rela.%55[^.]", sec_objname);
        if (cnt != 1) {
            pr_err("section %s has an incorrectly formatted name\n",
                   secname);
            ret = -EINVAL;
            break;
        }
     
        if (strcmp(objname, sec_objname))
            continue;
     
        ret = klp_resolve_symbols(sec, pmod);
        if (ret)
            break;
     
        ret = apply_relocate_add(pmod->klp_info->sechdrs,
     
                     pmod->core_kallsyms.strtab,
                     pmod->klp_info->symndx, i, pmod);
        if (ret)
            break;
    }
     
    return ret;

}
```

只处理sh_flags有SHF_RELA_LIVEPATCH标志的节，前面说过这些节是livepatch的特有的重定位节，名字格式为.rela.klp.objname。

调用klp_resolve_symbols函数进行符号解析，apply_relocate_add函数完成重定位工作。

klp_resolve_symbols函数：

```c
static int klp_resolve_symbols(Elf_Shdr *relasec, struct module *pmod)
{
    int i, cnt, vmlinux, ret;
    char objname[MODULE_NAME_LEN];
    char symname[KSYM_NAME_LEN];
    char *strtab = pmod->core_kallsyms.strtab;
    Elf_Rela *relas;
    Elf_Sym *sym;
    unsigned long sympos, addr;

    BUILD_BUG_ON(MODULE_NAME_LEN < 56 || KSYM_NAME_LEN != 128);
     
    relas = (Elf_Rela *) relasec->sh_addr;
    /* For each rela in this klp relocation section */
    for (i = 0; i < relasec->sh_size / sizeof(Elf_Rela); i++) {
        sym = pmod->core_kallsyms.symtab + ELF_R_SYM(relas[i].r_info);
        if (sym->st_shndx != SHN_LIVEPATCH) {
            pr_err("symbol %s is not marked as a livepatch symbol\n",
                   strtab + sym->st_name);
            return -EINVAL; 
        } 
     
        /* Format: .klp.sym.objname.symname,sympos */
        cnt = sscanf(strtab + sym->st_name,
                 ".klp.sym.%55[^.].%127[^,],%lu",
                 objname, symname, &sympos);
        if (cnt != 3) {
            pr_err("symbol %s has an incorrectly formatted name\n",
                   strtab + sym->st_name);
            return -EINVAL;
        }
        /* klp_find_object_symbol() treats a NULL objname as vmlinux */
        vmlinux = !strcmp(objname, "vmlinux");
        ret = klp_find_object_symbol(vmlinux ? NULL : objname,
                         symname, sympos, &addr);
        if (ret)
            return ret;
     
        sym->st_value = addr;
    }
     
    return 0;

}
```


遍历重定位节的每个rela项，找到每个rela引用的symbol，每个symbol的st_shndx必须为SHN_LIVEPATCH，代表这是个livepatch symbol，否则出错。

每个livepatch symbol的名字格式为: .klp.sym.objname,name.pos，根据symbol的nam解析出符号的objname，name和pos。

调用klp_find_object_symbol进行符号查找，如果内核符号，调用kallsyms_on_each_symbol进行查找，如果是模块内部符号调用module_kallsyms_on_each_symbol在相应的模块里进查找。

无论那种查找，都会进行objname(内核符号不用)，name和pos的全匹配，livepatch symbol都不是导出符号，仅仅根据名字进行查找，不一定全局唯一，[objname、name、pos]全匹配确保精准查找。

找到之后符号地址赋值给sym->st_value。

重定位工作由apply_relocate_add函数完成。重定位是对引用的函数和变量根据实际的地址进行修正。函数代码比较简单，还是通过本文的livepatch-0001-debug-xfs.ko例子进行说明。

查看livepatch-0001-debug-xfs.ko中的livepatch relocation项:

```
readelf -r livepatch-0001-debug-xfs.ko | grep klp.sym
000000000032  007400000002 R_X86_64_PC32     0000000000000000 .klp.sym.xfs.xfsstats, - 4
00000000008f  007500000002 R_X86_64_PC32     0000000000000000 .klp.sym.xfs.xlog_cil_ - 4
0000000000e8  007400000002 R_X86_64_PC32     0000000000000000 .klp.sym.xfs.xfsstats, - 4
000000000238  004b00000002 R_X86_64_PC32     0000000000000000 .klp.sym.xfs.xlog_stat - 4
000000000250  004c00000002 R_X86_64_PC32     0000000000000000 .klp.sym.xfs.xlog_stat - 4
00000000029d  007600000002 R_X86_64_PC32     0000000000000000 .klp.sym.xfs.__tracepo + 24
0000000002d7  004b00000002 R_X86_64_PC32     0000000000000000 .klp.sym.xfs.xlog_stat - 4
```

​       上图有7个livepatch relocation，其中6个是对函数引用的重定位，1个是对tracepoint的重定位，重定位类型都是R_X86_64_PC32。R_X86_64_PC32是x86_64平台上的对一个使用PC相对地址的引用，这个offset是32位的。X86_64是指x86_64平台，PC32表示这是个pc相对地址引用且offset范围是32位。

  R_X86_64_PC32类型的重定位公式为：S+A-P

   S：符号的实际地址

　　A：加数（addend，也称修正值）

　　P：重定位项所在的地址

　　PC相对寻址是目标符号到本指令下一条指令的地址，S+A-P = S-(P-A)，在上图中，最后一列的数字为addend，Ｓ+A -P = S-(P-A) = S -(P+4)。

   套用公式在函数中apply_relocate_add中修正如下：

　　*(u32 *)loc ＝　sym->st_value + rel[i].r_addend

2.正常的模块动态链接

　　livepatch本质是内核模块，除了livepatch relocation的链接，还有属于正常模块的动态链接。

　　正常模块动态链接在load_module函数里处理，调用栈：

```
do_syscall_64
　　__do_sys_finit_module
　　　　　load_module
```

　　其中，simplify_symbols函数负责符号解析，apply_relocations函数负责重定位。

　　simplify_symbols主要处理st_shndx为SHN_UNDEF的符号，SHN_LIVEPATCH的符号上一步已经处理了。

　　simplify_symbol函数最终调用find_symbol进行symbol的查找工作。因为正常模块的未定义符号只能是导出符号，symbol的名字是全局唯一的，故仅根据符号本身的名字就可以找到。

 simplify_symbol函数首先在内核导出符号表ksymtab里查找，没找到的话遍历系统已加载的模块，在模块的导出符号表里查找。

　　apply_relocations函数负责重定位，最终调用apply_relocate_add进行重定位。

　　举例来说，livepatch-0001-debug-xfs.ko调用了内核函数dump_stack函数：

```
readelf -r livepatch-0001-debug-xfs.ko | grep dump_stack
0000000000a7  005e00000002 R_X86_64_PC32     0000000000000000 dump_stack - 4
```

　　重定位类型为R_X86_64_PC32，具体的重定位方法前面说过。

  (六)．livepatch的函数的热替换

　　网上有关的介绍比较多，这里只简要写下流程。livepatch使用了ftrace机制来实现函数热替换，所以这里以ftarce的框架来说明。

　　1.ftrace一级hook构造

　　一级hook就是ftrace的通用trampoline，用于在ftrace使能之后，使用callq指令跳转到的位置。

　　livepatch中trampoline的创建流程如下:

```
entry_SYSCALL_64_after_hwframe
     do_syscall_64
       load_module
           do_init_module
              do_one_initcall
                 patch_init
                      klp_enable_patch
                         klp_patch_object
                            register_ftrace_function
                                    ftrace_startup
                                          __register_ftrace_function
                                                   arch_ftrace_update_trampoline
                                                         create_trampoline
```

　　trampoline的构造在create_trampoline函数，这个函数以内核里ftrace_regs_caller函数的汇编为蓝本来制作trampoline。ftrace_regs_caller函数的定义如下:

```
ENTRY(ftrace_regs_caller)
    /* Save the current flags before any operations that can change them */
    pushfq

    /* added 8 bytes to save flags */
    save_mcount_regs 8
    /* save_mcount_regs fills in first two parameters */

GLOBAL(ftrace_regs_caller_op_ptr)
    /* Load the ftrace_ops into the 3rd parameter */
    movq function_trace_op(%rip), %rdx
    /* Save the rest of pt_regs */
    movq %r15, R15(%rsp)
    movq %r14, R14(%rsp)
    movq %r13, R13(%rsp)
    movq %r12, R12(%rsp)
    movq %r11, R11(%rsp)
    movq %r10, R10(%rsp)
    movq %rbx, RBX(%rsp)
    /* Copy saved flags */
    movq MCOUNT_REG_SIZE(%rsp), %rcx
    movq %rcx, EFLAGS(%rsp)
    /* Kernel segments */
    movq $__KERNEL_DS, %rcx
    movq %rcx, SS(%rsp)
    movq $__KERNEL_CS, %rcx
    movq %rcx, CS(%rsp)
    /* Stack - skipping return address and flags */
    leaq MCOUNT_REG_SIZE+8*2(%rsp), %rcx
    movq %rcx, RSP(%rsp)
    /* regs go into 4th parameter */
    leaq (%rsp), %rcx
GLOBAL(ftrace_regs_call)
    call ftrace_stub
    /* Copy flags back to SS, to restore them */
    movq EFLAGS(%rsp), %rax
    movq %rax, MCOUNT_REG_SIZE(%rsp)
    /* Handlers can change the RIP */
    movq RIP(%rsp), %rax
    movq %rax, MCOUNT_REG_SIZE+8(%rsp)
    /* restore the rest of pt_regs */
    movq R15(%rsp), %r15
    movq R14(%rsp), %r14
    movq R13(%rsp), %r13
    movq R12(%rsp), %r12
    movq R10(%rsp), %r10
    movq RBX(%rsp), %rbx
    restore_mcount_regs
    /* Restore flags */
    popfq
    /*
     * As this jmp to ftrace_epilogue can be a short jump
     * it must not be copied into the trampoline.
     * The trampoline will add the code to jump
     * to the return.
     */
GLOBAL(ftrace_regs_caller_end)
    jmp ftrace_epilogue
ENDPROC(ftrace_regs_caller)
```

​       首先调用alloc_tramp函数申请size+MCOUNT_INSN_SIZE+sizeof(void *)大小的vmalloc内存。size为ftrace_regs_caller_end - ftrace_regs_caller的大小，可以认为是ftrace_regs_caller函数的大小，MCOUNT_INSN_SIZE为5字节，用来构造跳转指令，在ftrace_regs_caller结束之后跳转到函数ftrace_epilogue(trampoline收尾工作)，在跳转指令之后还需要一个指针的位置用来存放livepatch的struct ftrace_ops的地址。

　　申请过trampoline内存之后，将ftrace_regs_caller的代码全部拷贝到申请的内存里面。

　　在紧挨着新内存ftrace_regs_caller函数的位置构造一个相对jmp指令，跳转到ftrace_epilogue的label处。看下这个label的代码：

```
181 GLOBAL(ftrace_epilogue)
182 
183 #ifdef CONFIG_FUNCTION_GRAPH_TRACER
184 GLOBAL(ftrace_graph_call)
185     jmp ftrace_stub
186 #endif
      ftrace_epilogue处的处理是jmp ftrace_stub，看下 ftrace_stub的处理:

280 GLOBAL(ftrace_stub)
281     retq
```

　 ftrace_strub处就是retq指令。总结来说，ftrace_epilogue其实就是个retq指令，用于ftrace_regs_caller函数的收尾工作。

　在这条跳转指令之后的8个字节，用来存放livepatch的struct ftrace_ops的地址。

构造movq指令，位于ftrace_regs_caller_op_ptr这个label处，这个lable在ftrace_regs_caller内部，是为ftrace二级hook准备第三个参数，后面会提到这个第三个参数就是livepatch的ftrace_ops的地址。这个movq指令采用pc相对寻址，指令格式movq <offset>(%rip)，%rdx，占位7个字节。

　在原有的movq指令里只有offset是不对的，所以这里仅仅需要修正offset即可。offset就是struct ftrace_ops指针的位置到这条movq下一条指令的位置。ftrace_ops指针存储的位置，在trampoline紧挨者ftrace_regs_caller函数体和jmp ftrace_epilogue指令之后。注意这里不是struct ftrace_ops内存和movq下一条指令的距离，而是struct ftrace_ops的指针存放的位置，因为xxx(rip)这里有个取值动作。

2.ftrace二级hook的使能

　ftrace二级hook开启在arch_ftrace_update_trampoline函数里完成，调用栈：

```
entry_SYSCALL_64_after_hwframe
     do_syscall_64
       load_module
           do_init_module
              do_one_initcall
                 patch_init
                      klp_enable_patch
                         klp_patch_object
                            register_ftrace_function
                                    ftrace_startup
                                          __register_ftrace_function
                                                    arch_ftrace_update_trampoline
```

   4.18的ftrace的二级hook函数是ftrace_ops_assist_func函数。

   arch_ftrace_update_trampoline在构造好ftrace_ops的trampoline之后，接下来使能ftrace的二级hook。

   二级hook的位置位于trampoline的ftrace_regs_caller函数中的ftrace_regs_call的label的位置。如下：

```
GLOBAL(ftrace_regs_call)
    call ftrace_stub
```

　下面要做的就是把这个call ftrace_stub指令，替换成对 ftrace_ops_assist_func的调用即可。需要构造一条调用指令，call+offset即可，offset是ftrace_ops_assist_func函数地址到call ftrace_stub下一条指令的距离，然后用这个调用指令替换call ftrace_stub这条指令。

　调用指令是５个字节，复制替换的时候不能保证是原子的，多核的情况下，在拷贝的过程中，如果cpu取到部分指令会导致指令非法异常或者跑飞。

   x64采用int3指令过渡来解决这个问题，在ftrace_modify_code函数里实现。

```
ftrace_modify_code(unsigned long ip, unsigned const char *old_code,
            unsigned const char *new_code)
 {
     int ret;

     ret = add_break(ip, old_code);
     if (ret)
         goto out;
     
     run_sync();
     
     ret = add_update_code(ip, new_code);
     if (ret)
         goto fail_update;
     
     run_sync();
     
     ret = ftrace_write(ip, new_code, 1);
     /*
      * The breakpoint is handled only when this function is in progress.
      * The system could not work if we could not remove it.
      */
     BUG_ON(ret);

  out:
     run_sync();
     return ret;

  fail_update:
     /* Also here the system could not work with the breakpoint */
     if (ftrace_write(ip, old_code, 1))
         BUG();
     goto out;
 }
```

　　先通过add_break函数修改第一个字节位int3指令，run_sync作废指令cache和指令预取，重新来，然后调用add_update_code更新后4个字节，在调用run_sync，最后调用ftrace_write把int3指令替换为call指令的opcode最后再调用run_sync。

　　在第一步中，其他cpu要么看到int3，要么完全看不到，没有问题。第二步中，拷贝后4个字节的过程中，因为有了int3，触发int3异常，在do_int3中发现这是ftrace在用int3做代码修改过渡，那么修改保存的ip返回地址，跳过包括in3指令在内的5个字节。在第三步中，cpu要么看到完正的5字节call指令，要么看到in3+4字节的offset，处理和第二步一样。

　　总之，通过in3指令的过渡，使得整个5字节的指令拷贝，都处在int3异常的保护中，不会发生cpu去执行不完整的5字节的call指令。

　　二级hook使能，trampoline里会调用ftrace_ops_assist_func函数，并且前面在构造trampoline的过程中，为它准备好了第三个入参ftrace_ops。

3.ftrace三级hook

 看下二级hook函数ftrace_ops_assist_func：

```
static void ftrace_ops_assist_func(unsigned long ip, unsigned long parent_ip,
                   struct ftrace_ops *op, struct pt_regs *regs)
{
    int bit;

    if ((op->flags & FTRACE_OPS_FL_RCU) && !rcu_is_watching())
        return;
     
    bit = trace_test_and_set_recursion(TRACE_LIST_START, TRACE_LIST_MAX);
    if (bit < 0)
        return;
     
    preempt_disable_notrace();
     
    op->func(ip, parent_ip, op, regs);
     
    preempt_enable_notrace();
    trace_clear_recursion(bit);

}
```

   最终调用了ftrace_ops的func的钩子，在livepatch中这个钩子是klp_ftrace_handler，这是实现livepatch函数热替换的关键函数。

```
static void notrace klp_ftrace_handler(unsigned long ip,
                       unsigned long parent_ip,
                       struct ftrace_ops *fops,
                       struct pt_regs *regs)
{
    struct klp_ops *ops;
    struct klp_func *func;
    int patch_state;

    ops = container_of(fops, struct klp_ops, fops);
     
    preempt_disable_notrace();
     
    func = list_first_or_null_rcu(&ops->func_stack, struct klp_func,
                      stack_node);
     
    if (WARN_ON_ONCE(!func))
        goto unlock;
    smp_rmb();
     
    if (unlikely(func->transition)) {
     
        smp_rmb();
     
        patch_state = current->patch_state;
     
        WARN_ON_ONCE(patch_state == KLP_UNDEFINED);
     
        if (patch_state == KLP_UNPATCHED) {
     
            func = list_entry_rcu(func->stack_node.next,
                          struct klp_func, stack_node);
     
            if (&func->stack_node == &ops->func_stack)
                goto unlock;
        }
    }
     
    if (func->nop)
        goto unlock;
     
    klp_arch_set_pc(regs, (unsigned long)func->new_func);

unlock:
    preempt_enable_notrace();
}
```

　　这个函数里涉及到函数热替换的是klp_arch_set_pc函数，这是个体系相关函数，x64下实现如下：

```
 static inline void klp_arch_set_pc(struct pt_regs *regs, unsigned long ip)
 {   
     regs->ip = ip;
 }
```

　　这里将regs->ip赋值为新函数的地址。

　　看下ftrcae_regs_caller函数的汇编，重点关注下函数的恢复现场的流程：

```
ENTRY(ftrace_regs_caller)
    /* Save the current flags before any operations that can change them */
    pushfq

    /* added 8 bytes to save flags */
    save_mcount_regs 8
    /* save_mcount_regs fills in first two parameters */

GLOBAL(ftrace_regs_caller_op_ptr)
    /* Load the ftrace_ops into the 3rd parameter */
    movq function_trace_op(%rip), %rdx

    /* Save the rest of pt_regs */
    movq %r15, R15(%rsp)
    movq %r14, R14(%rsp)
    movq %r13, R13(%rsp)
    movq %r12, R12(%rsp)
    movq %r11, R11(%rsp)
    movq %r10, R10(%rsp)
    movq %rbx, RBX(%rsp)
    /* Copy saved flags */
    movq MCOUNT_REG_SIZE(%rsp), %rcx
    movq %rcx, EFLAGS(%rsp)
    /* Kernel segments */
    movq $__KERNEL_DS, %rcx
    movq %rcx, SS(%rsp)
    movq $__KERNEL_CS, %rcx
    movq %rcx, CS(%rsp)
    /* Stack - skipping return address and flags */
    leaq MCOUNT_REG_SIZE+8*2(%rsp), %rcx
    movq %rcx, RSP(%rsp)
     
    /* regs go into 4th parameter */
    leaq (%rsp), %rcx

GLOBAL(ftrace_regs_call)
    call ftrace_stub　　//替换为 call ftrace_ops_assist_func
    /* Copy flags back to SS, to restore them */
    movq EFLAGS(%rsp), %rax
    movq %rax, MCOUNT_REG_SIZE(%rsp)

    /* Handlers can change the RIP */
    movq RIP(%rsp), %rax
    movq %rax, MCOUNT_REG_SIZE+8(%rsp)
     
    /* restore the rest of pt_regs */
    movq R15(%rsp), %r15
    movq R14(%rsp), %r14
    movq R13(%rsp), %r13
    movq R12(%rsp), %r12
    movq R10(%rsp), %r10
    movq RBX(%rsp), %rbx
     
    restore_mcount_regs
     
    /* Restore flags */
    popfq
     
    /*
     * As this jmp to ftrace_epilogue can be a short jump
     * it must not be copied into the trampoline.
     * The trampoline will add the code to jump
     * to the return.
     */

GLOBAL(ftrace_regs_caller_end)

    jmp ftrace_epilogue

ENDPROC(ftrace_regs_caller)
```

　在36行的ftrace_ops_assist_func函数返回后，regs->ip地址已经是新函数的地址。

　42行新函数地址给rax。

　43行新函数地址rax赋值给MCOUNT_REG_SIZE+8(%rsp)。

　3行，MCOUNT_REG_SIZE(%rsp)地址保存的是rflags的值。

    MCOUNT_REG_SIZE+8(%rsp)地址是栈中保存调用ftrace_regs_caller的旧函数的返回值位置，原来这个位置的值应该是old_func_addr+5，现在被替换为新函数的地址首地址。

　ftrace_regs_caller函数执行完之后，jmp_ftrace_epilogue，前面说过这本质是个retq指令。

　retq指令将当前的rsp位置的值，也就是新函数的地址装载到rip，执行新函数，完成新旧函数替换。

4.ftrace一级hook使能

　　一、二、三级hook倶备，最后需要使能一级hook来开启livepatch。　　　

　　使能一级hook就是构造call指令，调用ftrace_ops的trampoline，并用这条指令替换patch函数的前5个字节。替换流程：

```
entry_SYSCALL_64_after_hwframe
　　　do_syscall_64
　　　　__do_sys_finit_module
　　　　　　load_module
　　　　　　　　do_init_module
　　　　　　　　　do_one_initcall
　　　　　　　　　　patch_init
　　　　　　　　　　　　klp_enable_patch
　　　　　　　　　　　　　klp_patch_object
　　　　　　　　　　　　　　register_ftrace_function
　　　　　　　　　　　　　　　　ftrace_startup
　　　　　　　　　　　　　　　　　ftrace_run_update_code
　　　　　　　　　　　　　　　　　　arch_ftrace_update_code
　　　　　　　　　　　　　　　　　　　ftrace_modify_all_code
　　　　　　　　　　　　　　　　　　　　 ftrace_replace_code
```

​     指令更新在ftrace_replace_code函数里面，依然使用int3指令过渡，不再展开。

 (七)．livepatch的一致性

 livepatch的一致性主要解决安全性问题，在新函数生效前，确保旧的含有没有在使用。

　 新函数在整个系统中完全替换旧函数这个过程称为"transition"，过渡的意思。

　1.livepatch 加载

　kpatch load livepatch-0001-debug-xfs.ko完成livepatch的加载。

　这个过程主要要是两步：

　首先insmod livepatch-0001-debug-xfs.ko

最后循环读取/sys/kernel/livepatch/livepatch_0001_debug_xfs/transition，直到不为1，超时时间15s。

   2.初始化transition流程

　主要在__klp_enable_patch函数开启transition流程。

　初始化全部变量klp_transition_patch=KLP_PATCHED，这是我们的目标。

　初始化全局变量klp_transition_patch=patch，这是本次要打的patch。

初始化每个task的patch_state为KLP_UNPATCHED，这是我们的现状。

　整个transition的流程就是让系统中每个task的patch_state都追赶上klp_transition_patch的状态(KLP_PATCHED)。

   3.开启transition的流程

　设置系统中每个task->thread_info->flags的TIF_PATCH_PENDING标志位。

   4.进行trasition

   由klp_try_complete_transition函数完成。 

　<1>.遍历系统所有的task，如果本task没有完成transition(task的patch_state!=klp_transition_patch)，进行task级的transition。

　　对current和系统中其他非running的进程检查，如果task的本身内核栈中不包含旧函数，本task完成trasition，task的patch_state更新为klp_transition_patch，并清除TIF_PATCH_PENDING标志，该进程完成本次transition的kpi。

　<2>.经过<1>步的检查之后，发现还有task没有完成transition的kpi，启动klp_transition_work这个定时work，1s后在来次检查。

　　如果多次klp_try_complete_transition依然有进程没有完成本身的transition，那就需要主动push一下。

　　对于内核线程，调用wake_up_state直接唤醒s状态的进程。

　　对于用户进程，调用signal_wake_up发送fake signal信号。对于处于s状态的用户进程，进行唤醒，如果进程处于running状态并且在运行，调用kick_process函数向进程所在的cpu发送reschedule的ipi中断，迫使进程让出cpu，这样进程才能接受stack check。

<3>进程自动的transition通过点

　　处于以下两种状态的话。进程自动通过进程级的transition：

　　对于用户进程，当返回用户态的时候调用klp_update_patch_state完成transition。

　　对于swapper线程，当进入ild loop的时候调用klp_update_patch_state完成transition。

   5.整个transition完成

　　系统中所有的task都通过自己的trasition之后，调用klp_complete_transition函数结束这个transition。

   klp_complete_transition工作如下：

　　设置本patch的每个obj的每个func的transition为false。每个obj代表是livepatch中修改了的.o文件。

   设置系统中所有task的patch_state为KLP_UNDEFINED。

　　设置全局klp_target_state状态为KLP_UNPATCHED。

　　设置全局klp_transition_patch为NULL，表示当前无在进行transition的patch。这样/sys/kernel/livepatch/livepatch_0001_debug_xfs/transition读到0，kpatch load流程结束。

   

(八)．新旧函数替换时机

　　看下klp_ftrace_handler函数:

```
static void notrace klp_ftrace_handler(unsigned long ip,
                       unsigned long parent_ip,
                       struct ftrace_ops *fops,
                       struct pt_regs *regs)
{
    struct klp_ops *ops;
    struct klp_func *func;
    int patch_state;

    ops = container_of(fops, struct klp_ops, fops);
     
    /*
      * A variant of synchronize_rcu() is used to allow patching functions
      * where RCU is not watching, see klp_synchronize_transition().
      */
     preempt_disable_notrace();
     
    func = list_first_or_null_rcu(&ops->func_stack, struct klp_func,
                      stack_node);
     
    /*
     * func should never be NULL because preemption should be disabled here
     * and unregister_ftrace_function() does the equivalent of a
     * synchronize_rcu() before the func_stack removal.
     */
    if (WARN_ON_ONCE(!func))
        goto unlock;
     
    smp_rmb();
     
    if (unlikely(func->transition)) {
     
        smp_rmb();
     
        patch_state = current->patch_state;
     
        WARN_ON_ONCE(patch_state == KLP_UNDEFINED);
     
        if (patch_state == KLP_UNPATCHED) {
            /*
             * Use the previously patched version of the function.
             * If no previous patches exist, continue with the
             * original function.
             */
            func = list_entry_rcu(func->stack_node.next,
                          struct klp_func, stack_node);
     
            if (&func->stack_node == &ops->func_stack)
                goto unlock;
        }
    }
     
    /*
     * NOPs are used to replace existing patches with original code.
     * Do nothing! Setting pc would cause an infinite loop.
     */
    if (func->nop)
        goto unlock;
     
    klp_arch_set_pc(regs, (unsigned long)func->new_func);

unlock:
    preempt_enable_notrace();
}
```

​                                                                                                                                                   

 这个函数主要根据transiton的状态来决定使用新函数还是旧函数。

　分两种情况：

　　　<1>.整体transition在进行中(func->transition== true)，如果进程本身通过的进程级的transition(task->patch_state== KLP_PATCHED)，那么调用klp_arch_set_pc函数，本进程使用新函数。如果没有通过进程级的transition，那么使用旧函数。

　　　<2>.整体trasition已经完成，所有进程使用新函数。

​       有一种情况，如果整体transition在进行中，本进程还没有进程级的transition，但这个被patched函数已经有一个livepatch在运行，这种情况需要替换为原来livepatch的新函数。