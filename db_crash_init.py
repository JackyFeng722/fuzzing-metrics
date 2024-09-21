# general experiment load to database
# 功能：创建crash，并将ASAN的详细检测结果信息写入
import re
import sys,os,functools
from common import runsql
from bugid import getbugid
from pprint import pprint
cwd = os.getcwd()  # 获取当前文件路径 : /home/jacky/Desktop/metrics/code
# UniBench提供的种子文件项目
data = [
    [1, "exiv2", "@@", "jpg"],
    [2,"tiffsplit","@@","tiff"],  # slime 8
    [3,"mp3gain","@@","mp3"],  # slime 6
    [4,"wav2swf","-o /dev/null @@","wav"],
    [5,"pdftotext","@@ /dev/null","pdf"], # slime 9 over
    [6,"infotocap","-o /dev/null @@","text"],
    [7,"mp42aac","@@ /dev/null","mp4"],
    [8,"flvmeta","@@","flv"],
    [9,"objdump","-S @@","obj"],   # slime 7
    [10,"uniq","@@","uniq"],
    [11,"base64","-d @@","base64"],
    [12,"md5sum","-c @@","md5sum"],
    [13,"who","@@","who"],
    [14, "tcpdump", "-e -vv -nr @@", "tcpdump100"],
    [15, "ffmpeg", "-y -i @@ -c:v mpeg4 -c:a copy -f mp4 /dev/null", "ffmpeg100"],  # slime 2
    [16, "gdk-pixbuf-pixdata", "@@ /dev/null", "pixbuf"],   # slime 3
    [17, "cflow", "@@", "cflow"],  # slime 1
    [18, "nm-new", "-A -a -l -S -s --special-syms --synthetic --with-symbol-versions -D @@", "nm"], #, name2="binutils-latest", folder="binutils-latest/")
    [19, "sqlite3", " < @@", "sql"],
    [20, "lame3.99.5", "@@ /dev/null", "lame3.99.5"],
    [21, "jhead", "@@", "jhead"],   # slime 5
    [22, "imginfo", "-f @@", "imginfo"],   # slime 4
    [23, "jq", ". @@", "json"],
    [24, "mujs", "@@", "mujs"], #mujs 1.0.2
    [None, "pngimage", "@@", "pngimage"],
]

@functools.lru_cache(maxsize=8888) # 暂时用不到，不管
def getstarttime_real(fuzzer, line0, line1):
    # base = "/c/ori/"+fuzzer+"/"+line0+"/"+line1+"/"

    base ="/home/jacky/Desktop/hp_ubuntu_desktop/output/"+"fuzz_"+fuzzer+"/"+line0+"/"+line1+"/"
    if "qsym" in line1:
        if os.path.exists(base+"afl-master/crashes/README.txt"):
            base += "afl-master/"
        else:
            assert os.path.exists(base+"afl-slave/crashes/README.txt")
            base += "afl-slave/"
    fuzzerstats = open(base+"fuzzer_stats").readlines()
    record_starttime = int([i.split()[2] for i in fuzzerstats if i.startswith("start_time")][0])
    record_lasttime = int([i.split()[2] for i in fuzzerstats if i.startswith("last_crash")][0])
    try:
        real_lasttime = os.path.getmtime(base+"crashes/"+[i for i in os.listdir(base+"crashes") if i!="README.txt"][-1])
    except:
        print(base)
        exit()
    #if  (fuzzer, line0, line1) == ('afl_dockervsvm', '2.tiffsplit_d2', 'dockervsvm_afl2_11'):
    #    print(record_starttime, record_lasttime, real_lasttime, os.listdir(base+"crashes"))
    return record_starttime - record_lasttime + real_lasttime

# 获取崩溃类型
def get_vulntype(err):
    res = "???"
    for line in err.split("\n"):
        if "AddressSanitizer" in line:
            #print(line)
            if " leaked in" in line:
                res = "memory_leak"
            elif "unknown-crash on address" in line:
                res = "unknown-crash"
            elif "failed to allocate" in line:
                res = "excessive_memory_allocation"
            elif "attempting free on address which was not malloc" in line:
                res = "free_error"
            else:
                for item in ["SEGV", "heap-buffer-overflow", "heap-use-after-free","stack-buffer-overflow","global-buffer-overflow","stack-use-after-return","stack-use-after-scope","initialization-order-fiasco", "stack-overflow","memcpy-param-overlap", "alloc-dealloc-mismatch", "use-after-poison", "stack-buffer-underflow", "odr-violation", "new-delete-type-mismatch", "negative-size-param", "invalid-pointer-pair", "intra-object-overflow", "illegal-instruction", "dynamic-stack-buffer-overflow", "container-overflow", "calloc-overflow", "double-free", "alloc-dealloc-mismatch", "allocation-size-too-big", "access-violation"]:
                    if item+" " in line:
                        res = item
    return res

# 获取asan独特崩溃
def get_asanuniq(err):
    keywords = set()
    for part in err.split("FUNCTIONSTARTFUNCTIONSTARTFUNCTIONSTART"):
        if "FUNCTIONENDFUNCTIONENDFUNCTIONEND" in part:
            keywords.add(part.split("FUNCTIONENDFUNCTIONENDFUNCTIONEND")[0])
    return str(tuple(sorted(keywords)))

cvedb = {}# cveid: [cveid, function name, file name, vuln type]
funcname2cve = {} # {funcname: [cve1, cve2]

def addtodict(dict, name, value):
    if name not in dict:
        dict[name] = []
    dict[name].append(value)

CVE_translate = {
    "NULL_pointer_dereference" :"SEGV",
    "heap-based_buffer_over-read": "heap-buffer-overflow",
    "heap-based_buffer_overflow": "heap-buffer-overflow",
}

# 文件内未被用到： 初始化 CVE 数据库，并将其中的数据存储在全局变量中，以方便后续的查询和分析。
def init_cve():
    global funcname2cve, cvedb
    for f in os.listdir("/d/_cvedb"):
        prog = f.replace("cvedb_","").replace(".txt", "")
        for line in open("/d/_cvedb/"+f,"r"):
            l = line[:-1].split("\t")
            funcname = l[1].replace("()","")
            if funcname.endswith("."):
                funcname = funcname[:-1]
            funcname = funcname.split("->")[-1]
            l[1] = funcname
            if l[3] in CVE_translate:
                l[3] = CVE_translate[l[3]]
            cvedb[l[0]] = l

            funcname = l[1]
            addtodict(funcname2cve.setdefault(prog, {}), funcname, l)
            if "::" in funcname:
                addtodict(funcname2cve.setdefault(prog, {}), funcname.split("::")[1], l)
# 文件内未被用到
def choose_match_cve(filepath, funcname, vulntype, cve_candidate, crashfilename):
    res = []
    notequal = []
    for c in cve_candidate: #[cveid, function name, file name, vuln type]
        if c[2] and filepath.endswith(c[2]):
            if vulntype == c[3]:
                res.append(c)
            else:
                notequal.append(c)
    if not res:
        print(crashfilename)
        print(filepath, funcname, vulntype)
        if notequal:
            print("notequal:", notequal)
        else:
            print("cve_candidate", cve_candidate)
        print()
    return res

# 重要
# 包括获取gccasan_full，对读取的文件.stderr内容的读取：errtext
# 从 ASan 错误信息中解析出漏洞类型、完整的调用栈信息和相关信息，如漏洞编号、程序名称等，并返回这些信息的元组
# 提取ASAN的stderr文件中的信息
def parse_asan(err, progname,filename):
    vulntype = get_vulntype(err)
    uniq = get_asanuniq(err)
    started = False
    full = []
    fullraw = []
    cve_candidate = None
    for line in err.split("\n"):
        if "FUNCTIONSTARTFUNCTIONSTARTFUNCTIONSTART" in line:
            started = True
            location = line.split("LOCATIONSTARTLOCATIONSTARTLOCATIONSTART")[1].split("LOCATIONENDLOCATIONENDLOCATIONEND_")[0]
            function = line.split("FUNCTIONSTARTFUNCTIONSTARTFUNCTIONSTART")[1].split("FUNCTIONENDFUNCTIONENDFUNCTIONEND_")[0]
            funcname = function.split("(")[0]
            #fullraw.append(function)
            fullraw.append(funcname)
            if not (location.startswith("/usr") or location.startswith("/lib") or location.startswith("/lib32") or location.startswith("/lib64") or location.startswith("/var") or location.startswith("/bin") or location=="<null>"):
                #full.append(function)
                full.append(funcname)
                filepath = location.split(":")[0]
                #if not cve_candidate:
                #    if funcname in funcname2cve[progname]:
                #        cve_candidate = funcname2cve[progname][funcname]
                #    elif funcname.split("::")[-1] in funcname2cve[progname]:
                #        cve_candidate = funcname2cve[progname][funcname.split("::")[-1]]
        elif line=="" and started:
            break # the first stack trace has ended
    bugid = getbugid(progname, str(full[:3]), vulntype ,filename)
    #if cve_candidate:
    #    print(progname, bugid, cve_candidate)
    return vulntype,str(full),str(fullraw),uniq,full[0] if len(full) else "",str(full[:2]),str(full[:3]),str(full[:4]),str(full[:5]), bugid

# 补充：gdb提取
def parse_agb(err, progname):
    started = False
    # 初始化匹配项
    problem_fun = set()
    for line in err.split("\n"):
        # 正则表达式匹配函数名称
        pattern = re.compile(r'0x[0-9a-fA-F]+ in (\w+)\s*\(')

        # 查找所有匹配项
        matches = pattern.findall(line)
        if matches:  # 如果匹配结果非空
            problem_fun.update(matches)

        # 将 problem_fun 列表转换为字符串
        problem_fun_str = ', '.join(problem_fun)


        if "Exploitability Classification" in line:
            started = True
            exploitability_class = line.split(":")[1].strip()
            exploitability_class= exploitability_class.strip()  # 去两端空格
        if "Hash" in line:
            started = True
            exploitability_hash = line.split(":")[1].strip()
            exploitability_hash= exploitability_hash.split('.')[0].strip()  # 去两端空格，去重复
        if "Description" in line:
            started = True
            exploitability_description = line.split(":")[1].strip()
            exploitability_description= exploitability_description.strip()  # 去两端空格

        elif line == "" and started:
            break
    return exploitability_class,exploitability_hash,exploitability_description ,problem_fun_str

#init_cve()

sqlpending = []
t = 0

def run(fuzzer,progname,crashes_list_path,OUTPUT,flag):  # 这里的fuzzer就是program
    # crashes_list_path:  ../project/RE2_output/fuzzerName/program/program_X_Y/crashlist.txt
    # ASAN_OUTPUT:        ../project/AnalysisOutput/ASAN_OUTPUT/fuzzerName/program/program_X_Y
    # progname:   programPrefix       jhead
    fuzzer_tool= fuzzer
    # fuzzer = progname
    global sql, sqlbase, t, sqlpending

    # ASAN漏洞分析
    if flag == 'ASAN':
        ASAN_OUTPUT = OUTPUT
        # print('crashes_list_path:',crashes_list_path)
        # print('ASAN_OUTPUT:', ASAN_OUTPUT)
        for _line in open(crashes_list_path).readlines():
            if not _line:
                continue

            line1 = _line
            filepath_n  = _line.split("\n")[0]   # 崩溃文件路径  /home..../crashes/id:.....
            filepath  = filepath_n.split("/")[-1]  #    id:000063,sig:11,src:000063,op:MOpt-havoc,rep:32
            experiment = line1                                       # 直接保留

            #starttime = getstarttime_real(fuzzer, line0, line1)
            #filetime = os.path.getmtime(filepath.replace("/c/work/general","/c/ori"))
            #assert filetime <= starttime+86400, str([fuzzer, line0, line1, starttime, starttime+86400, filetime, filepath.replace("/c/work/general","/c/ori"), ])
            #createtime = filetime-starttime
            createtime = "-1"

            stderrfile =  os.path.join(ASAN_OUTPUT,filepath+ ".stderr") # ASAN_OUTPUT文件中的 stderr文件
            # str(line) + ".stderr"  # ASAN_OUTPUT文件中的 stderr文件
            print('stderrfile:',stderrfile)
            # dupN = line1.split("_")[-1]    #类型有误，应该是整数， 仍然为line1：  id:000093,sig:11,src:000678,op:MOpt-havoc,rep:8   功能：保留最后一个“_”后的内容
            dupN = 0
            filesize = os.path.getsize(stderrfile)

            (gccasan_vulntype,gccasan_full,gccasan_fullraw,gccasan_uniq,gccasan_1,gccasan_2,gccasan_3,gccasan_4,
             gccasan_5, bugid) = "","","","","","","","","","-1"
            gdbvalidated,exploitable = "-1", "" #TODO
            cve,cvss_impact,cvss_exploitability = "", "-1", "-1"

            if os.path.exists(stderrfile):
                # print('stderrfile存在')
                timeouted = "0"
                stderrtext = open(stderrfile, "rb").read().decode(errors="ignore")

                if "Sanitizer" in stderrtext:
                    # print('Sanitizer存在')
                    asanvalidated = "1"
                    (gccasan_vulntype,gccasan_full,gccasan_fullraw,gccasan_uniq,gccasan_1,gccasan_2,gccasan_3,gccasan_4,
                     gccasan_5, bugid) = parse_asan(stderrtext, progname,filename = filepath )
                else:
                    print('找不到 Sanitizer')
                    asanvalidated = "0"
            else:
                timeouted = "1"
                asanvalidated = "0"

            sql += "(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s),"  # +3个
            sqlpending.extend(
                [filepath, fuzzer_tool, progname, experiment, dupN, filesize, createtime, timeouted, asanvalidated,
                 gccasan_vulntype, gccasan_full, gccasan_fullraw, gccasan_uniq, gccasan_1, gccasan_2, gccasan_3, gccasan_4,
                 gccasan_5, gdbvalidated, 'null', 'null' , 'null', 'null', bugid, cve,
                 cvss_impact, cvss_exploitability])  # 数据库 ASAN
            if len(sqlpending) == 24 * 100:
                t += 1
                print('t:', t)
                runsql(sql[:-1], *sqlpending)  # 数据库replace写入：crash
                sqlpending = []
                sql = sqlbase
            print('ASAN漏洞分析完成，已经写入数据库crash !!!')

        # GDB漏洞分析
    elif flag == 'GDB':
        GDB_OUTPUT = OUTPUT
        for _line in open(crashes_list_path).readlines():
            if not _line:
                continue
            experiment = _line
            dupN= 1
            gdbvalidated = '1'
            createtime = "-1"
            exploitable = 'gdb exploitable'
            asanvalidated ='0'
            gccasan_vulntype= gccasan_full = gccasan_fullraw = gccasan_uniq = gccasan_1= gccasan_2= gccasan_3\
                = gccasan_4 = gccasan_5 =''
            cve, cvss_impact, cvss_exploitability = "", "-1", "-1"
            bugid = 0

            # 补充：gdb检测结果写入数据库
            # GDB_OUTPUT = '/'.join(OUTPUT.split('/')[:-1]) + '/GDB_OUTPUT'  # /home/jacky/Desktop/output/GDB_OUTPUT
            filepath_n = _line.split("\n")[0]
            filepath = filepath_n.split("/")[-1]
            gdb_stdoutfile = os.path.join(GDB_OUTPUT, filepath + ".stdout")
            filesize = os.path.getsize(gdb_stdoutfile) #
            if os.path.exists(gdb_stdoutfile):
                stdout = open(gdb_stdoutfile, "rb").read().decode(errors="ignore")
                if "Short description" in stdout:
                    # print('gdb_stdout存在')
                    gdbvalidated = "1"
                    timeouted = "0"
                    exploitable_class, exploitable_hash1, gdb_stacktrace3,problem_fun = parse_agb(stdout, progname) # gdb exploitable分析结果
                    print('exploitable_class, exploitable_hash1, gdb_stacktrace3,problem_fun:', exploitable_class, exploitable_hash1, gdb_stacktrace3,problem_fun )
                else:
                    timeouted = "-1"
                    print('gdb_stdout不存在:',gdb_stdoutfile)

            sql += "(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s),"  # asan -10个 == 18字段
            sqlpending.extend([filepath,fuzzer_tool,progname,experiment,dupN,filesize,createtime,timeouted,
                               # asanvalidated,gccasan_vulntype,gccasan_full,gccasan_fullraw,gccasan_uniq,
                               # gccasan_1,gccasan_2,gccasan_3,gccasan_4,gccasan_5,
                               gdbvalidated, exploitable , exploitable_class, exploitable_hash1,problem_fun, gdb_stacktrace3 ,
                               bugid,cve,cvss_impact,cvss_exploitability])
            if len(sqlpending) == 24*100:
                t += 1
                print('t:',t)
                runsql(sql[:-1], *sqlpending)  # 数据库replace写入：crash
                sqlpending = []
                sql = sqlbase
    else:
        print('未知分析')
        return -1


def AsanMain(TABLENAME,fuzzers,crashes_list_path,crashAnalysPath,program,flag):  # 添加  program,crashes_list_path
    global sqlbase, sql
    # 表crash，添加了三个字段：exploitable_class,exploitable_hash1,gdb_stacktrace3
    sqlbase = "replace into "+TABLENAME+"(filepath,fuzzer,progname,experiment,dupN,filesize,createtime,timeouted,asanvalidated,gccasan_vulntype,gccasan_full,gccasan_fullraw,gccasan_uniq,gccasan_1,gccasan_2,gccasan_3,gccasan_4,gccasan_5,gdbvalidated,exploitable,exploitable_class,exploitable_hash1,gdb_stacktrace3,bugid,cve,cvss_v2,cvss_v3) values "
    sql = sqlbase
    for fuzzer in fuzzers:
        # run(fuzzer)
        run(fuzzer,program,crashes_list_path,crashAnalysPath,flag)

    if sqlpending:
        runsql(sql[:-1], *sqlpending)  # 数据库replace写入：crash

def GDBMain(TABLENAME,fuzzers,crashes_list_path,crashAnalysPath,program,flag):  # 添加  program,crashes_list_path
    global sqlbase, sql
    # 表crash，添加了三个字段：exploitable_class,exploitable_hash1,gdb_stacktrace3
    sqlbase = "replace into "+TABLENAME+"(filepath,fuzzer,progname,experiment,dupN,filesize,createtime,timeouted,gdbvalidated,exploitable,exploitable_class,exploitable_hash1,problem_fun,gdb_stacktrace3,bugid,cve,cvss_v2,cvss_v3) values "
    sql = sqlbase
    for fuzzer in fuzzers:
        # run(fuzzer)
        run(fuzzer,program,crashes_list_path,crashAnalysPath,flag)

    if sqlpending:
        runsql(sql[:-1], *sqlpending)  # 数据库replace写入：crash

if __name__ == "__main__":
    #main("crash", ["afl_dockervsvm", "aflfast_dockervsvm", "honggfuzz", "angora", "tfuzz", "vuzzer", "qsym"])
    # main("crash_new", ["afl", "aflfast", "qsym", "angora", "vuzzer", "mopt", "honggfuzz", "tfuzz"])

    crashes_list_path = sys.argv[1]  # crasheslist.text文件输出路径
    ASAN_OUTPUT = sys.argv[2]  # ASAN_OUTPUT输出路径
    target_exe_file = sys.argv[3]  # 被测程序名称
    # print('被测程序: ',target_exe_file)
    # print('crashes_list_path: ', crashes_list_path)
    # print('ASAN_OUTPUT: ', ASAN_OUTPUT)
    if not target_exe_file:
        print("[Error] target_exe_file  not given")
        exit(1)
    if not crashes_list_path:
        print("[Error] crashes_list_path  not given")
        exit(1)
    if not ASAN_OUTPUT:
        print("[Error] ASAN_OUTPUT  not given")
        exit(1)

    AsanMain("crash", ["slime"],crashes_list_path,ASAN_OUTPUT,target_exe_file) # 参数 fuzzers 先暂定为slime