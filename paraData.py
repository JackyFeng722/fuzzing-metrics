import os
# 针对research2
root_dir = os.getcwd()
# 模糊测试默认被测程序路径
programs_dir = os.path.join(os.path.dirname(root_dir),'research2', 'program')
# asan编译被测程序路径
AsanProgram_dir = os.path.join(os.path.dirname(root_dir),'research2', 'programAsan')
# GDB编译被测程序路径
GDBProgram_dir = os.path.join(os.path.dirname(root_dir),'research2', 'programGDB')
# 种子集
corpus_dir = os.path.join(root_dir, 'seed/')


# TODO: DATASET=[id,programName,para,type,exe_path, asan_exe_path ,GDB_exe_path ,input_corpus]
dataset = [
    # TODO: GUN工具集
    [1, "cxxfilt", "-t", "elf", os.path.join(programs_dir, 'binutils-2.34/binutils', 'cxxfilt'),
     os.path.join(AsanProgram_dir, 'binutils-2.34/binutils', 'cxxfilt'),
     os.path.join(GDBProgram_dir, 'binutils-2.34/binutils', 'cxxfilt'),
     os.path.join(corpus_dir, 'elf'), ['-t']],
    [2, "objdump", "-d @@", "elf", os.path.join(programs_dir, 'binutils-2.34/binutils', 'objdump'),
     os.path.join(AsanProgram_dir, 'binutils-2.34/binutils', 'objdump'),
     os.path.join(GDBProgram_dir, 'binutils-2.34/binutils', 'objdump'),
     os.path.join(corpus_dir, 'elf'), ['-d', '@@']],
    [3, "objcopy", "–dump-section text=/dev/null @@ /dev/null", "elf",
     os.path.join(programs_dir, 'binutils-2.34/binutils', 'objcopy'),
     os.path.join(AsanProgram_dir, 'binutils-2.34/binutils', 'objcopy'),
     os.path.join(GDBProgram_dir, 'binutils-2.34/binutils', 'objcopy'),
     os.path.join(corpus_dir, 'elf'), ['--dump-section', 'text=/dev/null', '@@', '/dev/null']],
    [4, "readelf", "-a @@", "elf", os.path.join(programs_dir, 'binutils-2.34/binutils', 'readelf'),
     os.path.join(AsanProgram_dir, 'binutils-2.34/binutils', 'readelf'),
     os.path.join(GDBProgram_dir, 'binutils-2.34/binutils', 'readelf'),
     os.path.join(corpus_dir, 'elf'), ['-a', '@@']],
    [5, "size", "@@", "elf", os.path.join(programs_dir, 'binutils-2.34/binutils', 'size'),
     os.path.join(AsanProgram_dir, 'binutils-2.34/binutils', 'size'),
     os.path.join(GDBProgram_dir, 'binutils-2.34/binutils', 'size'),
     os.path.join(corpus_dir, 'elf'),
     ['@@']],
    [6, "strip", "-o /dev/null @@", "elf", os.path.join(programs_dir, 'binutils-2.34/binutils', 'strip-new'),
     os.path.join(AsanProgram_dir, 'binutils-2.34/binutils', 'strip-new'),
     os.path.join(GDBProgram_dir, 'binutils-2.34/binutils', 'strip-new'),
     os.path.join(corpus_dir, 'elf'), ['-o', '/dev/null', '@@']],
    # TODO: 常用被测程序
    [7, "jhead", "@@", "jpeg", os.path.join(programs_dir, 'jhead-3.00/jhead'),
     os.path.join(AsanProgram_dir, 'jhead-3.00/jhead'),
     os.path.join(GDBProgram_dir, 'jhead-3.00/jhead'),
     os.path.join(corpus_dir, 'jpeg'),
     ['@@']],
    [8, "djpeg", "@@", "jpeg", os.path.join(programs_dir, 'jpegsrc.v6b/jpeg-6b/djpeg'),
     os.path.join(AsanProgram_dir, 'jpegsrc.v6b/jpeg-6b/djpeg'),
     os.path.join(GDBProgram_dir, 'jpegsrc.v6b/jpeg-6b/djpeg'),
     os.path.join(corpus_dir, 'jpeg'),
     ['@@']],
    [9, "tcpdump", "-nr @@", "pacp", os.path.join(programs_dir, 'tcpdump-4.99.1/tcpdump'),
     os.path.join(AsanProgram_dir, 'tcpdump-4.99.1/tcpdump'),
     os.path.join(GDBProgram_dir, 'tcpdump-4.99.1/tcpdump'),
     os.path.join(corpus_dir, 'pcap'), ['-nr', '@@']],
    [10, "bsdtar", "-xf @@ /dev/null", "tar", os.path.join(programs_dir, 'libarchive-3.6.0/bsdtar'),
     os.path.join(AsanProgram_dir, 'libarchive-3.6.0/bsdtar'),
     os.path.join(GDBProgram_dir, 'libarchive-3.6.0/bsdtar'),
     os.path.join(corpus_dir, 'tar'), ['-xf', '@@', '/dev/null']],
    [101, "mp3gain", "@@", "mp3", os.path.join(programs_dir, 'mp3gain-1.5.2/mp3gain'),
     os.path.join(AsanProgram_dir, 'mp3gain-1.5.2/mp3gain'),
     os.path.join(GDBProgram_dir, 'mp3gain-1.5.2/mp3gain'),
     os.path.join(corpus_dir, 'mp3'),
     ['@@']],
    [102, "cflow", "@@", "txt", os.path.join(programs_dir ,'cflow-1.6/src/cflow'),
     os.path.join(AsanProgram_dir ,'cflow-1.6/src/cflow'),
     os.path.join(GDBProgram_dir, 'cflow-1.6/src/cflow'),
     os.path.join(corpus_dir, 'text'),
     ['@@']],
    [103, "pdfimages", "@@ /dev/null", "pdf", os.path.join(programs_dir, 'xpdf-4.00/xpdf/pdfimages'),
     os.path.join(AsanProgram_dir, 'xpdf-4.00/xpdf/pdfimages'),
     os.path.join(GDBProgram_dir, 'xpdf-4.00/xpdf/pdfimages'),
     os.path.join(corpus_dir, 'pdf'),
     ['@@','/dev/null']],
    # TODO: LAVA-M被测程序
    [11, "base64", "-d @@", "txt",
     os.path.join(programs_dir, 'lava_corpus/LAVA-M', 'base64/coreutils-8.24-lava-safe/lava-install/bin/base64'),
     os.path.join(AsanProgram_dir, 'lava_corpus/LAVA-M', 'base64/coreutils-8.24-lava-safe/lava-install/bin/base64'),
     os.path.join(GDBProgram_dir, 'lava_corpus/LAVA-M', 'base64/coreutils-8.24-lava-safe/lava-install/bin/base64'),
     os.path.join(corpus_dir, 'lavam/base64'), ['-d', '@@']],
    [12, "md5sum", "-c @@", "txt",
     os.path.join(programs_dir, 'lava_corpus/LAVA-M', 'md5sum/coreutils-8.24-lava-safe/lava-install/bin/md5sum'),
     os.path.join(AsanProgram_dir, 'lava_corpus/LAVA-M', 'md5sum/coreutils-8.24-lava-safe/lava-install/bin/md5sum'),
     os.path.join(GDBProgram_dir, 'lava_corpus/LAVA-M', 'md5sum/coreutils-8.24-lava-safe/lava-install/bin/md5sum'),
     os.path.join(corpus_dir, 'lavam/md5sum'), ['-c', '@@']],
    [13, "uniq", "@@", "txt",
     os.path.join(programs_dir, 'lava_corpus/LAVA-M', 'uniq/coreutils-8.24-lava-safe/lava-install/bin/uniq'),
     os.path.join(AsanProgram_dir, 'lava_corpus/LAVA-M', 'uniq/coreutils-8.24-lava-safe/lava-install/bin/uniq'),
     os.path.join(GDBProgram_dir, 'lava_corpus/LAVA-M', 'uniq/coreutils-8.24-lava-safe/lava-install/bin/uniq'),
     os.path.join(corpus_dir, 'lavam/uniq'), ['@@']],
    [14, "who", "@@", "binary",
     os.path.join(programs_dir, 'lava_corpus/LAVA-M', 'who/coreutils-8.24-lava-safe/lava-install/bin/who'),
     os.path.join(AsanProgram_dir, 'lava_corpus/LAVA-M', 'who/coreutils-8.24-lava-safe/lava-install/bin/who'),
     os.path.join(GDBProgram_dir, 'lava_corpus/LAVA-M', 'who/coreutils-8.24-lava-safe/lava-install/bin/who'),
     os.path.join(corpus_dir, 'lavam/who'), ['@@']],
]