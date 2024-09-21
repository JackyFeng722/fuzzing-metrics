    # 欢迎进入 JackyFeng 的README
# Fuzzing-Metrics（扩展版）操作指南
## 1、安装mysql数据库
<details open>
<summary>安装mysql数据库</summary>
 
数据库用于记录crash崩溃文件信息、记录ASAN和gdb-exploitable发现的漏洞情况、展示CVE_ASAN和CVE_GDB的所有CVE漏洞类型，方便后面进行CVE漏洞类型匹配。
#### 1.1、确保你的linux系统已经安装好msyql数据库、pycharm可使用Database工具
#### 1.2、建立数据库用户：
在[common.py](./metrics-extend/code/common.py)文件开头确保你的数据库用户以及数据库名称已经创建并拥有全部权限，其中数据库连接名称为`secret_mysql`。
> 注意：请确保你的user、password、数据库名称对应连接`secret_mysql`，否则无法访问数据库。
```
secret_mysql = {"user":"unifuzz", "passwd":"你的密码", "host":"localhost", "port": 3306, "db":"unifuzz"}
```
#### 1.3、数据库文件为：[unifuzz.sql](./metrics-extend/code/unifuzz.sql),打开它并执行生成三个大表：bugid、crash 和 dockers
</details>


## 2、ASAN漏洞分析：使用crashrunner.py
 
该文件:[crashrunner.py](./metrics-extend/code/crashrunner.py)涉及内存错误分析工具AddressSanitizer。
ASAN（AddressSanitizer）是一种内存错误检测工具，可帮助开发人员快速发现和调试程序中的内存错误和漏洞。其工作原理是在程序运行时对内存访问进行检测，通过插入代码来对内存进行标记和检测，并在检测到错误时生成详细的报告。
#### 2.1、生成崩溃列表文件crasheslist.txt
```shell
find -type f|grep crashes/|grep -v README.txt > crasheslist.txt
```
##### 命令解释：
- 在指定crashes目录下，查找所有关于崩溃信息的日志文件，并排除了一个名为README.txt的文件，最终将它们的文件名输出到crasheslist.txt的文本文件中。
#### 2.2、指定编译目标被测可执行程序启动AddressSanitizer
官方被测程序地址：https://github.com/unifuzz/unibench.git
> 注意：有些linux上运行的程序，可能需要自动化脚本工具Configure来生成makefile文件，那么就需要在./configure后面添加启动ASAN命令，有些提供了makefile文件的需要在该文件内添加启动ASAN命令（可能需要多次添加）。
 
##### 2.2.1 对于cflow：未提供makefile文件，其配置如下：
```shell
make clean
export CC="clang-12"
./configure CFLAGS="-g -O2 -fsanitize=address"
CC="clang-12" make
```
##### 2.2.2 对于mp3gain：已提供makefile文件，其配置如下（makefile中两处修改）：
```shell
 CFLAGS = -Wall -Wextra -fsanitize=address 
 $(CC) -o mp3gain $(OBJS) $(RC_OBJ) $(LIBS)  -fsanitize=address
```
修改后提通过clang-12编译：
```shell
CC="clang-12" make
```
#### 2.3、运行crashrunner.py
在crasheslist.txt文件目录下，输入以下命令：
```shell
cat crasheslist.txt |CMD="/home/jacky/Desktop/cflow-1.6_02/src/cflow @@"  OUT="/home/jacky/Desktop/output/ASAN_OUTPUT" /home/jacky/Desktop/metrics/code/crashrunner.py
```
##### 参数说明：
> cat crasheslist.txt |CMD= `参数1`  OUT=`参数2` `参数3`
- 参数1： 指定编译目标可执行程序及替换参数
- 参数2： 指定ASAN_OUTPUT文件夹输出的绝对路径
- 参数3： crashrunner.py所在的绝对路径

#### 2.4、运行成功后将会生成输出文件
ASAN_OUTPUT输出文件夹下生成tmp文件（临时文件）,`.stderr`、`.stdout`、`.returncode`文本文件，其中`.stderr`文件中必须包含`AddressSanitizer`字段，
`.returncode`文件中记录的返回值必须为1
 

## 3、gdb-exploitable漏洞分析：使用exploitablerunner.py
该文件:[exploitablerunner.py](./metrics-extend/code/exploitablerunner.py)涉及相关gdb命令。其中，exploitable 是一个gdb插件，可以帮助分析程序中的漏洞，其主要功能是在gdb中检测和报告易受攻击的漏洞类型和级别。
该插件依赖于程序的符号表和调试信息，并使用各种漏洞检测技术（例如，内存溢出、空指针解引用、格式化字符串漏洞等）来确定程序中的潜在漏洞。它会分析崩溃的栈跟踪、异常信号、异常退出、内存破坏等信息，并根据漏洞类型和严重性进行分类和报告。

 
 
#### 3.1、安装GDB 'exploitable'插件：<https://github.com/jfoote/exploitable>
##### 要求：
- Compatible x86/x86_64/ARM/MIPS Linux
- Compatible GDB 7.2 or later
- Python 2.7 or later (for triage.py)
##### 全局安装及使用：
```shell
python setup.py install
```
- 若出现下面提示则继续：
```
**********************************************
 Install complete! Source exploitable.py from
 your .gdbinit to make it available in GDB:
 echo "source /usr/lib/python3.8/site-packages/exploitable-1.32-py3.8.egg/exploitable/exploitable.py" >> ~/.gdbinit
 **********************************************
```
- 复制提示的第三行命令启动全局配置：
```shell
echo "source /usr/lib/python3.8/site-packages/exploitable-1.32-py3.8.egg/exploitable/exploitable.py" >> ~/.gdbinit
```

##### 运行exploitable命令：
```shell
(gdb) exploitable
```

#### 3.2、指定编译目标可执行程序
官方被测程序地址：https://github.com/unifuzz/unibench.git
>注意：复制一份未编译的目标程序，直接clang-12编译即可：
- 3.2.1、对于cflow终端进行配置：
```shell
 make clean
 export CC="clang-12"
 ./configure
 CC="clang-12" make
```
- 3.2.2、对于mp3gain中的makefile文件修改为：
```shell
CC=clang-12
CFLAGS= -Wall -O2 -DHAVE_MEMCPY -g
```
（注: -g可以确保在GDB中查看具体的调试信息，包括源代码行号、变量值等）
#### 3.3、终端窗口命令
在exploitablerunner.py 所在目录层，终端执行下面命令：
```shell
python3 exploitablerunner.py  /home/jacky/Desktop/cflow-1.6_12/src/cflow   /home/jacky/Desktop/hp_ubuntu_desktop/output/fuzz_cflow/crasheslist.txt  /home/jacky/Desktop/output/GDB_OUTPUT
```
##### 参数说明：
> python3  exploitablerunner.py  `参数1`  `参数2` `参数3` 
- 参数1：目标可执行程序所在的绝对路径
- 参数2：crasheslist.txt的绝对路径，必须与crashes/文件同层
- 参数3：GDB_OUTPUT输出目录
#### 3.4、运行成功后将会生成输出文件
GDB_OUTPUT的子文件夹下生成tmp文件（临时文件）,`.stderr`、`.stdout`、`.returncode`文本文件，其中`.stderr`文件中必须包含`AddressSanitizer`字段，
`.returncode`文件中记录的返回值必须为1
 
    
    
## 4、写入数据库

对生成的三个数据表bugid、crashe和dockers进行实验数据的写入操作。
### 4.1、写入数据表bugid
第3步执行[crashrunner.py](./metrics-extend/code/crashrunner.py)文件时就已经写入数据库，系统自动将ASAN漏洞分析的数据写入到表bugid中，其结构如下：（以cflow为例）

 | id  |    progname |                                                                                      stacktrace                                                                                      |      vulntype       | CVE | extra |
|-----|------------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|:-------------------:|:---:|:-----:|
| 1   |       cflow |                                                                       ['reference', 'expression', 'func_body']                                                                       | heap-use-after-free |     |
| 2   |       cflow |                                                              ['reference', 'expression', 'parse_variable_declaration']                                                               | heap-use-after-free |     |
| 3   |       cflow |                                                                         ['call', 'expression', 'func_body']                                                                          | heap-use-after-free |     |
| 4   |       cflow |                                                                   ['reference', 'expression', 'initializer_list']                                                                    | heap-use-after-free |     |
| 5   |       cflow |                                                                 ['call', 'expression', 'parse_variable_declaration']                                                                 | heap-use-after-free |     |
| ... |         ... |                                                                                         ...                                                                                          |         ...         |     |

### 4.2、写入数据表crash
读取ASAN_OUTPUT中的所有stderr文件内容（ASAN检测到的漏洞信息）、GDB_OUTPUT中的所有stdout文件内容（gdb-exploitable检测到的漏洞信息）并写入到数据库表crash中。
> 注意：确保你的ASAN_OUTPUT和GDB_OUTPUT在同一输出目录下
- 在[db_crash_init.py](./metrics-extend/code/db_crash_init.py)所在文件目录层，输入执行命令如下：

```shell
python3  db_crash_init.py   /home/jacky/Desktop/hp_ubuntu_desktop/output/fuzz_cflow/crasheslist.txt   /home/jacky/Desktop/output/ASAN_OUTPUT   cflow
```

##### 参数说明：
> python3    db_crash_init.py    `参数1`    `参数2`    `参数3`  
- 参数1：crasheslist.txt文件绝对路径
- 参数2：ASAN_OUTPUT路径
- 参数3：目标可执行程序名称
系统自动将实验对象和相关路径写入到表bugid中，其结构如下：（以cflow为例）

  
|                                                filepath                                                | fuzzer | progname |                        experiment                        | duN | filesize | createtime | timeouted | asanvalidated | gccasan_vulntype | gccasan_full | gccasan_fullraw | gccasan_uniq | gccasan_1 | gccasan_2 | gccasan_3 | gccasan_4 | gccasan_5 | gdbvalidated | exploitable | exploitable_class | exploitable_hash1 | exploitable_hash2 | bugid | cve | cvss_v2 | cvss_v3 | queuetocrash |
|:------------------------------------------------------------------------------------------------------:|:------:|:--------:|:--------------------------------------------------------:|:---:|:--------:|:----------:|:---------:|:-------------:|:----------------:|:------------:|:---------------:|:------------:|:---------:|:---------:|:---------:|:---------:|:---------:|:------------:|:-----------:|:-----------------:|:-----------------:|:-----------------:|:-----:|:---:|:-------:|:-------:|:------------:|
|   /home/jacky/Desktop/output/fuzz_cflow/crashes/id:000222,sig:11,src:001394,op:MOpt-core-havoc,rep:4   | slime  |  cflow   |   id:000222,sig:11,src:001394,op:MOpt-core-havoc,rep:4   | 222 |  12415   |     -1     |     1     |       0       |                  |              |                 |              |           |           |           |           |           |      -1      |             |                   |                   |                   |  -1   |     |   -1    |   -1    |      -1      |
| /home/jacky/Desktop/output/fuzz_cflow/crashes/id:000232,sig:11,src:000681+000628,op:MOpt-splice,rep:64 | slime  |  cflow   | id:000232,sig:11,src:000681+000628,op:MOpt-splice,rep:64 | 232 |  136928  |     -1     |     1     |       0       |                  |              |                 |              |           |           |           |           |           |      -1      |             |                   |                   |                   |  -1   |     |   -1    |   -1    |      -1      |
|                                                  ...                                                   | slime  |  cflow   |                           ...                            |     |          |            |           |               |                  |              |                 |              |           |           |           |           |           |              |             |                   |                   |                   |       |     |         |         |              |
|                                                  ...                                                   | slime  |  cflow   |                           ...                            |     |          |            |           |               |                  |              |                 |              |           |           |           |           |           |              |             |                   |                   |                   |       |     |         |         |              |
|                                                  ...                                                   | slime  |  cflow   |                           ...                            |     |          |            |           |               |                  |              |                 |              |           |           |           |           |           |              |             |                   |                   |                   |       |     |         |         |              |
|                                                  ...                                                   |  ...   |   ...    |                           ...                            | ... |   ...    |            |           |               |                  |              |                 |              |           |           |           |           |           |              |             |                   |                   |                   |       |     |         |         |              |

 
    
## 5、CVE漏洞分析
 
这里用到的是[cvematch.py](./metrics-extend/code/cvematch.py)文件，ASAN和gbd-exploitable匹配到的CVE漏洞编号将直接写入到数据库表crash中。
### 5.1、执行分析
在[cvematch.py](./metrics-extend/code/cvematch.py)文件终端下，输入：（以mp3gain为例）
```shell
python3  ./cvematch.py  mp3gain  /home/jacky/Desktop/mp3gain-1.5.2_02/mp3gain   /home/jacky/Desktop/output
```
##### 参数说明：
> python3  ./cvematch.py   `参数1`   `参数2`    `参数3` 
- 参数1：目标可执行程序名称
- 参数2：目标可执行程序绝对路径
- 参数3：输出目录绝对路径（ASAN_OUT和GDB_OUTPUT的上级目录）
### 5.2、结果导出
在pycharm中，找到数据库Database中的crash表，点击 `Export Data`即可查看详细的漏洞匹配结果。 


### 5.3、CVE漏洞数据官网
MITRE CVE数据库：MITRE是负责分配CVE标识符的机构，其网站提供CVE漏洞的搜索和浏览功能。您可以通过关键字、CVE标识符、目标程序名称来查找特定漏洞的详细信息。
网址：[https://cve.mitre.org/](https://cve.mitre.org/cve/search_cve_list.html)，直接输入project名称即可查看该程序下的所有CVE漏洞信息。

---
    
## 6、文件结构
 
```
exeFile_path -- 可执行文件路径
│
crasheslist_path -- crasheslist.txt文件路径（与crashe文件同层）
│
Output_Path -- 输出目录
    │
    │     
    └───ASAN_OUTPUT -- 输出目录：ASAN_OUTPUT分析输出目录
    │   │        
    │   └───subfolder
    │       │ 
    │       └───tmp -- 临时文件目录 
    │       │    │
    │       │    └───tmp_file
    │       │   id:000000,sig:11,src:000063,op:MOpt-havoc,rep:16.returncode -- returncode中返回代码代表执行成功与否    
    │       │   id:000000,sig:11,src:000063,op:MOpt-havoc,rep:16.stderr     -- stderr文件存放AddressSanitizer漏洞分析结果 
    │       │   id:000000,sig:11,src:000063,op:MOpt-havoc,rep:16.stdout     
    │       │   ...
    │
    └───GDB_OUTPUT -- 输出目录：GDB_OUTPUT分析输出目录
    │   │        
    │   └───subfolder
    │       │ 
    │       └───tmp -- 临时文件目录  
    │       │    │
    │       │    └───tmp_file
    │       │   id:000000,sig:11,src:000063,op:MOpt-havoc,rep:16.stderr    
    │       │   id:000000,sig:11,src:000063,op:MOpt-havoc,rep:16.stdout    -- stderr文件存放GDB分析结果  
    │       │   id:000000,sig:11,src:000063,op:MOpt-havoc,rep:16.timeouted -- timeouted超时文件，超时才存在   
    │       │   ...   
```
 

