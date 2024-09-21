import sys, os, shutil, subprocess, glob, shlex
from db_crash_init import parse_asan

os.environ[
    "ASAN_OPTIONS"] = 'stack_trace_format="FUNCTIONSTARTFUNCTIONSTARTFUNCTIONSTART%fFUNCTIONENDFUNCTIONENDFUNCTIONEND_LOCATIONSTARTLOCATIONSTARTLOCATIONSTART%SLOCATIONENDLOCATIONENDLOCATIONEND_FRAMESTARTFRAMESTARTFRAMESTART%nFRAMEENDFRAMEENDFRAMEEND"'
# UniBench提供的种子文件项目
FULLDATA = [[0, None, None, None], [1, "exiv2", "@@", "jpg"], [2, "tiffsplit", "@@", "tiff"],
            [3, "mp3gain", "@@", "mp3"], [4, "wav2swf", "-o output @@", "wav"], [5, "pdftotext", "@@", "pdf"],
            [6, "infotocap", "-o /dev/null @@", "text"], [7, "mp42aac", "@@ /dev/null", "mp4"],
            [8, "flvmeta", "@@", "flv"], [9, "objdump", "-S @@", "obj"], [10, "uniq", "@@", "uniq"],
            [11, "base64", "-d @@", "base64"], [12, "md5sum", "-c @@", "md5sum"], [13, "who", "@@", "who"],
            [14, "tcpdump", "-e -vv -nr @@", "pcap"],
            [15, "ffmpeg", "-y -i @@ -c:v mpeg4 -c:a copy -f mp4 /dev/null", "avi"],
            [16, "gdk-pixbuf-pixdata", "@@ /dev/null", "pixbuf"],
            [17, "cflow", "@@", "cflow"],
            [18, "nm-new", "-A -a -l -S -s --special-syms --synthetic --with-symbol-versions -D @@", "nm"],
            [19, "sqlite3", " < @@", "sql"],
            [20, "lame3.99.5", "@@ /dev/null", "lame3.99.5"],
            [21, "jhead", "@@", "jhead"],
            [22, "imginfo", "-f @@", "imginfo"],
            [23, "jq", ". @@", "json"],
            [24, "mujs", "@@", "mujs"]
            ]

# PROGNAME = "ffmpeg"
# PROGNAME = "cflow"
# PROGNAME = "mp3gain"
PROGNAME = sys.argv[1] # project name : mp3gain
exe_flie = sys.argv[2] # cflow 目标可执行程序绝对路径 : /home/.../mp3gain
output_path = sys.argv[3] # 文件输出路径，ASAN_OUTPUT 和 GDB_OUTPUT的上级目录
# output = sys.argv[2] # output path:
print('PROGNAME:', PROGNAME)
print('exe_flie_path:', exe_flie)
print('output_path:', output_path)
ID, _, DEFAULT_PARAM, _ = [i for i in FULLDATA if i[1] == PROGNAME][0]

# CMD = "/d/p/aflasan/{ID}.{PROGNAME} PARAM".format(**globals())
CMD = (exe_flie+" PARAM").format(**globals())

# GDBCMD = "gdb -ex 'r PARAM' -ex 'exploitable' -ex 'bt' -ex 'quit' /d/p/justafl/{ID}.{PROGNAME}".format(**globals())
GDBCMD = ("gdb -ex 'r PARAM' -ex 'exploitable' -ex 'bt' -ex 'quit' "+exe_flie).format(**globals())

# if PROGNAME=="infotocap":
#     CMD = "/d/p/aflasan/{PROGNAME} PARAM".format(**globals())
#     GDBCMD = "gdb -ex 'r PARAM' -ex 'exploitable' -ex 'bt' -ex 'quit' /d/p/justafl/{PROGNAME}".format(**globals())
DATA = []
TRACEDATA = []

# 缺少原始数据集
def step0_loaddata():
    global DATA
    title = None
    for line in open("cvematch_" + PROGNAME + ".txt"):  # 没有这个文件？？？？cvematch_
        l = line[:-1].split("\t")
        if title is None:
            title = l
        else:
            d = {}
            for i, v in enumerate(l):
                d[title[i]] = v.strip()
            # print(d)
            d['pocvalidated'] = int(d['pocvalidated'])
            if d['type'] == 'infinit-loop':
                d['type'] == "infinite loop"
            DATA.append(d)


# os.makedirs("/c/ASAN_OUTPUT/cve",exist_ok=True)
# os.makedirs("/c/GDB_OUTPUT/cve",exist_ok=True)

# 处理原始数据集采用到
# os.makedirs("/home/jacky/Desktop/output/ASAN_OUTPUT/cve", exist_ok=True)
# os.makedirs("home/jacky/Desktop/output/GDB_OUTPUT/cve", exist_ok=True)

# 栈去重
def uniq_trace(stack):
    res = []
    for item in stack:
        if not len(res):
            res.append(item)
        elif item != res[-1]:
            res.append(item)
    return res


def extract_asan(cvefile, command, stderrfile, stdoutfile):
    assert (os.path.exists(cvefile)), cvefile
    id = os.path.basename(cvefile)

    tmpfile = "/home/jacky/Desktop/output/ASAN_OUTPUT/tmp/cvematch_running_" + PROGNAME
    if not os.path.exists(tmpfile):  # tmp文件夹不存在则创建
        os.makedirs(tmpfile, exist_ok=True)

    shutil.copy(cvefile, tmpfile)

    command = command.strip()
    if command:
        assert command.startswith(PROGNAME)
        thiscommand = command.replace(PROGNAME, "").strip()
        thisCMD = CMD.replace("PARAM", thiscommand)
    else:
        thisCMD = CMD.replace("PARAM", DEFAULT_PARAM)
    cmd = shlex.split(thisCMD.replace("@@", tmpfile))

    if not os.path.exists(stderrfile):
        try:
            x = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        except subprocess.TimeoutExpired:
            print("[timeout]", id)
            return False
        with open(stdoutfile, "wb") as errfp:
            errfp.write(x.stdout)
        with open(stderrfile, "wb") as errfp:
            errfp.write(x.stderr)
        err = x.stderr.decode(errors="ignore")
    else:
        with open(stderrfile, "rb") as errfp:
            err = errfp.read().decode(errors="ignore")
    # print(err)
    assert "AddressSanitizer" in err, (err, cvefile, cmd)
    gccasan_vulntype, gccasan_full, gccasan_fullraw, gccasan_uniq, gccasan_1, gccasan_2, gccasan_3, gccasan_4, gccasan_5, bugid = parse_asan(
        err, PROGNAME)
    stack = [i for i in eval(gccasan_full) if i != "main"]
    if len(stack) > 100:
        result = set()
        for item in set(stack):
            if stack.count(item) > 10:
                result.add(item)
        stack = list(result)
    return gccasan_vulntype, uniq_trace(stack)


def cveid2what(id, func, command, prefix):
    cvefiles = glob.glob("/d1/cvepoc/" + PROGNAME + "/" + id + "*")
    assert len(cvefiles), "cvefile not exist:" + id
    result = []
    for f in cvefiles:
        stderrfile = prefix + os.path.basename(f) + ".stderr"
        stdoutfile = prefix + os.path.basename(f) + ".stdout"
        result.append(func(f, command, stderrfile, stdoutfile))
    return result

# 处理原始数据集采用到  asan
def cveid2asan(id, command):
    # return cveid2what(id, extract_asan, command, "/c/ASAN_OUTPUT/cve/" )
    return cveid2what(id, extract_asan, command, "/home/jacky/Desktop/output/ASAN_OUTPUT/cve/")


import re


def _in_blacklist(name, filepos):
    if name in ("__kernel_vsyscall", "abort", "raise",
                "malloc", "free", "__GI_abort",
                "__GI_raise", "malloc_printerr",
                "__libc_message", "_int_malloc",
                "_int_free", "main", "___vsnprintf_chk",
                "___asprintf", "malloc_consolidate", "___sprintf_chk"):
        return True
    for word in ["std::", "__GI_", "_IO_", "__memcpy_", "__assert_", "___printf", "___vsprintf_chk"]:
        if name.startswith(word):
            return True
    if filepos.startswith("/usr") or "/libc" in filepos or "/libm" in filepos:
        return True
    return False


def extract_gdb(cvefile, command, stderrfile, stdoutfile):  #  return type, uniq_trace(gdb_stack)
    assert (os.path.exists(cvefile)), cvefile             # cvefile即测试用例  ， stderrfile就GDBOUT_PUT中的filepath
    id = os.path.basename(cvefile)
    # tmpfile = "/tmp/cvematch_runninggdb_" + PROGNAME
    tmpfile = "/home/jacky/Desktop/output/GDB_OUTPUT/tmp/cvematch_running_" + PROGNAME
    if not os.path.exists(tmpfile):  # tmp文件夹不存在则创建
        os.makedirs(tmpfile, exist_ok=True)

    # print('tempfile:',tmpfile)
    # print('cvefile:', cvefile)
    print('command:', command)     # empty
    # print('stderrfile:',stderrfile)
    # print('stdoutfile:',stdoutfile)

    shutil.copy(cvefile, tmpfile)

    command = command.strip()
    if command:
        assert command.startswith(PROGNAME)
        thiscommand = command.replace(PROGNAME, "").strip()
        thisCMD = GDBCMD.replace("PARAM", thiscommand)
    else:
        thisCMD = GDBCMD.replace("PARAM", DEFAULT_PARAM)
    cmd = shlex.split(thisCMD.replace("@@", tmpfile))
    if not os.path.exists(stderrfile):               # cmd：不存在stderrfile文件时才用到
        # print('stderrfile不存在')
        print(" ".join(["'" + i + "'" for i in cmd]))
        try:
            x = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        except subprocess.TimeoutExpired:
            print("[timeout]", id)
            raise
        with open(stdoutfile, "wb") as errfp:
            errfp.write(x.stdout)
        with open(stderrfile, "wb") as errfp:
            errfp.write(x.stderr)
        err = x.stderr.decode(errors="ignore")
        stdout = x.stdout.decode(errors="ignore")                 #  /home/jacky/Desktop/output/GDB_OUTPUT/mp3gain/id:000173,sig:11,src:001544,op:MOpt-core-havoc,rep:128.stderr
    else:                                                                   #stderrfile文件存在：执行读取操作
        # print('stderrfile文件存在')
        with open(stderrfile, "rb") as errfp:
            err = errfp.read().decode(errors="ignore")
            # print('err:',err)
        with open(stdoutfile, "rb") as fp:
            stdout = fp.read().decode(errors="ignore")
    assert "\n#0  " in stdout, cvefile
   # print('stdout:',stdout)   # GNU gdb (Ubuntu 12.1-0ubuntu1) 12.1 ........ 即读取GDB_OUTPUT中的stdout文件内容
    gdb_stack = []
    for line in stdout.split("\n#0 ")[1].split("\n"):  # 针对stdout(有gdb分析的信息)
        if not " (" in line:
            break
        func = line.split(" (")[0].split(" in ")[-1].strip()
        if func.startswith("#"):
            func = " ".join(func.split(" ")[1:])
        func = func.strip()
        if line.split(" ")[-2] in ["at", "from"]:
            filepos = line.split(" ")[-1].strip()

        else:
            filepos = ""
        print('func, filepos, line:',func, filepos, line)
        if _in_blacklist(func, filepos):
            continue
        if "(" in func:
            func = func.split("(")[0]
        gdb_stack.append(func)
    print('gdb_stack：',gdb_stack ) #  ['WriteMP3GainAPETag']
    gdb_stacktrace3 = str(gdb_stack[:3])
    assert " received signal " in stdout
    type = stdout.split(" received signal ")[1].split(",")[0].strip()    # Program received signal SIGSEGV, Segmentation fault.
    print('type,gdb_stack,uniq_trace(gdb_stack):',type,gdb_stack, uniq_trace(gdb_stack))
    return type, uniq_trace(gdb_stack)

# 处理原始数据集采用到 gdb
def cveid2gdb(id, command):
    print('id, extract_gdb, command:',id, extract_gdb, command)
    print('cveid2what(id, extract_gdb, command, "/home/jacky/Desktop/output/GDB_OUTPUT/cve/"):', cveid2what(id, extract_gdb, command, "/home/jacky/Desktop/output/GDB_OUTPUT/cve/"))
    return cveid2what(id, extract_gdb, command, "/home/jacky/Desktop/output/GDB_OUTPUT/cve/")


def translate_asan2gdb(type):
    t = {
        "excessive_memory_allocation": "SIGABRT",
        "FPE": "SIGFPE"
    }
    return t.get(type, "")


def step1_pocrun():
    global DATA, TRACEDATA
    for cve in DATA:
        filepos = [i.strip() for i in cve["file"].split(",")] if cve["file"].strip() else []

        if cve["pocvalidated"] == 1:
            for type, trace in cveid2asan(cve["id"], cve["command"]):
                TRACEDATA.append([cve["id"], cve["pocvalidated"], type, translate_asan2gdb(type), trace, filepos])
            continue
        elif cve["pocvalidated"] == 2:
            for type, trace in cveid2gdb(cve["id"], cve["command"]):
                TRACEDATA.append(
                    [cve["id"], cve["pocvalidated"], ("" if type != "SIGSEGV" else "SEGV"), type, trace, filepos])
            continue
        else:
            trace = cve["keywords"]
            if "，" in trace:
                trace = trace.split("，")
            else:
                trace = trace.split(",")
            trace = [t.strip() for t in trace]
            type, gdbtype = cve["type"], cve["gdbtype"]
            if type and not gdbtype:
                gdbtype = translate_asan2gdb(type)
            # print(cve["id"], type, trace)
            # trace = trace[:3] # TODO: delete me!!!
            TRACEDATA.append([cve["id"], cve["pocvalidated"], type, gdbtype, trace, filepos])
    _TRACEDATA = []
    for i in TRACEDATA:
        if len(i[4]) > 10:
            i[4] = i[4][:10]
        if i not in _TRACEDATA:
            _TRACEDATA.append(i)
    TRACEDATA = _TRACEDATA
    TRACEDATA.sort(key=lambda i: len(i[4]), reverse=True)


def ismatch(t1, t2, first=False): # trace  t
    """
    return if t1 contains t2
    """
    len_t1, len_t2 = len(t1), len(t2)
    for i in range(0, len_t1 - len_t2 + 1):
        if t1[i:i + len_t2] == t2:
            return True
        if first:
            break
    return False


def ismatchtype(cvetype, thistype):
    print('ismatchtype函数：',cvetype, thistype)
    # return: 
    #    1 equal
    #    2 possible equal
    #    0 not equal
    if cvetype == thistype:
        return 1
    if "SEGV" in [cvetype, thistype] and "stack-overflow" not in [cvetype, thistype]:
        return 0
    return 0


def dprint(*args):
    sys.stderr.write(" ".join([str(i) for i in args]) + "\n")


SAMECVES = []
LINENUMBERS = []
if os.path.exists("extrarules_" + PROGNAME + ".txt"):
    for _line in open("extrarules_" + PROGNAME + ".txt"):
        l = _line[:-1].split()
        if l[1] == "=":
            SAMECVES.append(set([l[0], l[2]]))
        elif l[1] == "linenumber":
            LINENUMBERS.append([l[0], l[2]])


def choose_matches(thistype, thistrace, cvematches, prefer):
    if set(cvematches) in SAMECVES:
        return cvematches
    myprint("choose_matches:", thistype, thistrace, cvematches, prefer)
    cves = sorted([i for i in TRACEDATA if i[0] in cvematches], key=lambda i: len(i[4]), reverse=True)

    thelen = len(cves[0][4])
    result = [i[0] for i in cves if len(i[4]) == thelen]

    if len(result) > 1:
        # after sorting by priority, we still have multiple choices
        # then we choose the equal one
        cves2 = [i for i in TRACEDATA if i[0] in result and i[4][0] == thistrace[0]]
        result = [i[0] for i in cves2]

    myprint([i[0] for i in cves], result, "\n")
    return result


def void(*args):
    pass


myprint = dprint


# 将crash表中的filepath作为输入
def match_asan(filename,output_path):  #  filenane==filepath: /home/jacky/Desktop/hp_ubuntu_desktop/output/fuzz_mp3gain/crashes/id:000169,sig:11,src:001512+001353,op:MOpt-splice,rep:128
    global BPRINT_SHOULDPRINT
    # stderrfile = filename.replace("/hp_ubuntu_desktop/output/fuzz_mp3gain/crashes",
    #                               "/output/ASAN_OUTPUT/" +PROGNAME) + ".stderr"  # 切换到之前生成的ASAN_OUTPUT输出的stderr文件
    stderrfile = output_path +'/ASAN_OUTPUT/'  + PROGNAME + '/' + filename.split('/')[-1] +'.stderr'

    # stdoutfile = filename.replace("/hp_ubuntu_desktop/output/fuzz_mp3gain/crashes", "/output/ASAN_OUTPUT/"+PROGNAME) + ".stdout"  # 用不到
    if not os.path.exists(stderrfile) or "AddressSanitizer" not in open(stderrfile,
                                                                        errors="ignore").read():  # stderr文件：路径不存在 or 无AddressSanitizer信息 ，则报错
        myprint("[error] maybe no asan:", stderrfile)
        return []
    # print('stderrfile:',stderrfile)
    errtext = open(stderrfile, "r", errors="ignore").read()
    if "p" in sys.argv:  # 用户在运行程序时指定了参数p，则打印
        print(errtext)
    # print('errtext:',errtext)
    gccasan_vulntype, gccasan_full, gccasan_fullraw, gccasan_uniq, gccasan_1, gccasan_2, gccasan_3, gccasan_4, gccasan_5, bugid = parse_asan(
        errtext, PROGNAME)
    # print('parse_asan（errtext, PROGNAME）返回直：',parse_asan(errtext, PROGNAME))
    #   返回值： vulntype,str(full),str(fullraw),uniq,full[0] if len(full) else "",str(full[:2]),str(full[:3]),str(full[:4]),str(full[:5]), bugid

    trace = [i for i in eval(gccasan_full) if i != "main"]  # 过滤掉了调用栈中的 "main" 函数，因为主函数很少是漏洞的根源。
    # print('trace:',trace)
    if len(trace) > 100:  # 判断调用栈的长度是否超过了 100，如果是，则将调用栈中出现次数超过 10 次的函数保留下来，其余函数剔除
        result = set()
        for item in set(trace):
            if trace.count(item) > 10:
                result.add(item)
        trace = list(result)
    trace = uniq_trace(trace)  # uniq_trace函数去重和压缩，即将连续出现的相同函数名只记录一次。
    myprint('gccasan_vulntype、trace:',gccasan_vulntype, trace)
    flag = True
    matches = []
    matches3 = []
    if gccasan_vulntype == "stack-overflow":
        for id, src, type, gdbtype, t, filepos in TRACEDATA:
            if type != "stack-overflow":  # 如果不是'stack-overflow'类型则跳过该元素
                continue
            # print("is stack-overflow?", trace, t)
            if set(trace) == set(t):
                matches.append(id)  # matches中记录 该元素t的调用栈与变量trace相同时
    else:
        for id, src, type, gdbtype, t, filepos in TRACEDATA:
            # print('TRACEDATA:',TRACEDATA)
            if type in ["infinite loop", "stack-overflow"]:  # 如果type为"infinite loop"或者"stack-overflow"则直接跳过，不进行匹配
                continue
            print('trace 、 t 、匹配情况：',trace, t,ismatch(trace, t, first=True))

            if ismatch(trace, t, first=True):  # we require first match, no sliding match
                typematched = ismatchtype(gccasan_vulntype, type)  # 如果也匹配则将此元素的id添加到matches列表中
                # print('typematched:',typematched)  # 未执行
                if typematched:
                    if typematched == 2:
                        myprint("this is a possible match", gccasan_vulntype, type)
                    # print("match: ", id)
                    matches.append(id)
            if ismatch(trace, t[:3], first=True) and ismatchtype(gccasan_vulntype,
                                                                 type):  # 再使用ismatch函数判断trace和t的前3个元素是否匹配，如果匹配则同样判断
                matches3.append(id)  # gccasan_vulntype和type是否匹配，如果也匹配则将此元素的id添加到matches3列表中
    if len(matches) > 1:
        matches = choose_matches(gccasan_vulntype, trace, matches, prefer="asan")
    if matches:
        myprint("asan match:", matches[0] if len(matches) == 1 else matches)
    else:
        myprint("asan no match!")
    myprint("asan matches3:", matches3)
    if not matches:
        BPRINT_SHOULDPRINT = True

    if 1:  # delete me!
        if not matches and len(matches3) == 1:
            return matches3
    return matches

# 以print输出的形式，无数据库读写
def match_gdb(filename,output_path):
    global BPRINT_SHOULDPRINT
    # stderrfile = filename.replace("/hp_ubuntu_desktop/output/fuzz_mp3gain/crashes", "/output/GDB_OUTPUT/"+PROGNAME) + ".stderr"
    # stdoutfile = filename.replace("/hp_ubuntu_desktop/output/fuzz_mp3gain/crashes", "/output/GDB_OUTPUT/"+PROGNAME) + ".stdout"
    stderrfile = output_path +"/GDB_OUTPUT/"+PROGNAME+'/'+ filename.split('/')[-1] +'.stderr'
    stdoutfile = output_path +"/GDB_OUTPUT/"+PROGNAME+'/'+ filename.split('/')[-1] +'.stdout'
    if not os.path.exists(stdoutfile) or "\n#0 " not in open(stdoutfile, errors="ignore").read():
        myprint("[error] maybe timeout gdb:", stdoutfile)
        return []
    thistype, trace = extract_gdb(filename, "", stderrfile, stdoutfile)  # 输入cvefile, command, stderrfile, stdoutfile，输出type, uniq_trace(gdb_stack): SIGSEGV ['III_dequantize_sample']
    # print('thistype, trace:',thistype, trace)
    myprint('thistype, trace:',thistype, trace)
    matches = []
    matches3 = []
    for id, src, type, gdbtype, t, filepos in TRACEDATA:
        print('当前id , type, gdbtype,trace, t',id , type, gdbtype,trace, t)
        if type == "infinite loop":
            continue
        if ismatch(trace, t, first=True) and thistype == gdbtype:
            myprint("gdb is comparing: ", id, type, t)
            matches.append(id)
        if ismatch(trace, t[:3], first=True):  #   matches3 中只保存 t 字符串的前三个字符与 trace 匹配成功的 id 值--即CVE编号
            matches3.append(id)
    if len(matches) > 1:
        matches = choose_matches(thistype, trace, matches, prefer="gdb")
    if matches:
        myprint("gdb match:", matches[0] if len(matches) == 1 else matches)
    else:
        myprint("gdb no match!")
    myprint("gdb matches3:", matches3)
    if not matches:
        BPRINT_SHOULDPRINT = True
    if not matches and len(matches3) == 1:
        return matches3
    return matches


from bugid import runsql
from pprint import pprint

ENABLE_WRITE = False
if "writedb" in sys.argv:
    ENABLE_WRITE = True


# 将asan_cve写入到数据库表crash中
def write_asan_cve(gccasan_full, gccasan_vulntype, cves):
    if not ENABLE_WRITE:
        return
    cve = ",".join(cves)
    cvssv2 = max([CVSSV2.get(i, 0) for i in cves])
    cvssv3 = max([CVSSV3.get(i, 0) for i in cves])
    # sql = "update crash set cve=%s, cvss_v2=%s, cvss_v3=%s where progname='" + PROGNAME + "' and cve is null and gccasan_full=%s and gccasan_vulntype=%s"
    sql = "update crash set cve=%s, cvss_v2=%s, cvss_v3=%s where progname='" + PROGNAME + "' and gccasan_full=%s and gccasan_vulntype=%s"

    return runsql(sql, cve, cvssv2, cvssv3, gccasan_full, gccasan_vulntype)  # 执行更新数据库表crash-----asan


# 涉及gdb写入数据库操作
def write_gdb_cve(exploitable_hash2, exploitable_class, cves,filename):
    # print('write_gdb_cve开始:ENABLE_WRITE:',exploitable_hash2, exploitable_class, cves)
    # if not ENABLE_WRITE:
    #     return
    cve = ",".join(cves)
    # print('cve')
    cvssv2 = max([CVSSV2.get(i, 0) for i in cves])
    cvssv3 = max([CVSSV3.get(i, 0) for i in cves])
    print('执行sql前:cvssv2、cvssv3：',cvssv2,cvssv2)
    print("")
    # sql = "update crash set cve=%s, cvss_v2=%s, cvss_v3=%s where progname='"+PROGNAME+"' and cve is null and exploitable_hash2=%s and exploitable_class=%s"
    sql = "update crash set cve=%s, cvss_v2=%s, cvss_v3=%s where progname='" + PROGNAME + "' and experiment=%s"

    print('gdb-sql完成：', cve, cvssv2, cvssv3, exploitable_hash2, exploitable_class,filename)
    # print('gdb-runsql:',runsql(sql, cve, cvssv2, cvssv3, exploitable_hash2, exploitable_class))  # 全?空
    return runsql(sql, cve, cvssv2, cvssv3, filename)   # 执行更新数据库表crash-----gdb

CVSSV2={}
CVSSV3={}
# CVSSV2 = {_line.split("\t")[0]: _line[:-1].split("\t")[1] for _line in open("cvssv2.txt")}
# CVSSV3 = {_line.split("\t")[0]: _line[:-1].split("\t")[1] for _line in open("cvssv3.txt")}

BPRINT_BUFFER = []
BPRINT_SHOULDPRINT = False


def bprint(*args):
    global BPRINT_SHOULDPRINT, BPRINT_BUFFER
    BPRINT_BUFFER.append(" ".join([str(i) for i in args]))


def bprint_clear():
    global BPRINT_SHOULDPRINT, BPRINT_BUFFER
    if BPRINT_SHOULDPRINT and BPRINT_BUFFER:
        print("\n".join(BPRINT_BUFFER))
    BPRINT_SHOULDPRINT = False
    BPRINT_BUFFER = []


# myprint=bprint

# 生成追踪文件trace_data_{progname}.txt
def generate_tracefile():
    step0_loaddata()
    step1_pocrun()
    with open("tracedata_" + PROGNAME + ".txt", "w") as fp:
        for item in TRACEDATA:
            fp.write("\t".join([str(i) for i in item]) + "\n")  # 数组写入文件，换行、缩进
    exit()

if __name__ == "__main__":
    #PROGNAME = sys.argv[1]  # 可执行文件
    # PROGNAME = sys.argv[1]
    if not os.path.exists("tracedata_" + PROGNAME + ".txt"):  # 生成trace_data_{progname}.txt： 位置：当前目录code/下
        generate_tracefile()
    # if len(sys.argv) == 2:
    #     if sys.argv[1] == "showtrace":
    #         for item in TRACEDATA:
    #             print("\t".join([str(i) for i in item]))
    #         exit()
    #     elif sys.argv[1] == "exit":
    #         exit()
    #     elif sys.argv[1] == "save":
    #         generate_tracefile()
    # load the dataset from our modified txt
    TRACEDATA = []
    for _line in open("tracedata_" + PROGNAME + ".txt"):  # 读取数据集trace_data.txt中的内容
        l = _line[:-1].split("\t")  # 和cvematch_data.txt中的内容格式一致
        TRACEDATA.append([l[0], l[1], l[2], l[3], uniq_trace(eval(l[4])), eval(l[5])])  # 直接选取前四、堆栈信息中筛选出唯一的函数调用信息、[]、
    print(TRACEDATA)
    # asan_cve匹配
    for item in runsql(
            "SELECT crash.gccasan_full,count(*)as cnt, filepath, gccasan_3, gccasan_vulntype FROM crash where crash.progname='%(P)s' and crash.asanvalidated>0 and crash.cve='' group by gccasan_vulntype,gccasan_full,filepath" % (
            {'P': PROGNAME})):
        filepath = item[2]  # 取crash表中filepath：
        # print('filepath:',filepath)  #  /home/jacky/Desktop/hp_ubuntu_desktop/output/fuzz_mp3gain/crashes/id:000173,sig:11,src:001544,op:MOpt-core-havoc,rep:128
        myprint("\n>>>", filepath)     #  对 SQL 查询结果进行遍历，并将每条记录的 filepath 字段值取出，赋值给变量 filepath。
        myprint("bugcnt:", item[1], item[0], item[3], item[4])
        print('filepaths:',filepath)
        result = match_asan(filepath,output_path)
        print('result:',result)
        if result:
            if len(result) > 1:
                if set(result) not in SAMECVES:
                    # multiple match, should reconsider!
                    myprint("should reconsider:", result)
                else:
                    # matched same cve, nice match
                    myprint('matched same cve:',result)
            else:
                # only one match, good!
                myprint('only one match, good:',result)
            write_asan_cve(item[0], item[4], result)
        else:
            print("No results found for the query.")
        bprint_clear()

    print('--------------------- gdb_asan匹配结束--------------------')
    print('--------------------- gdb_cve匹配开始---------------------')
    # gdb_cve匹配
    for item in runsql(
            "SELECT exploitable_hash2,count(*)as cnt, filepath, gdb_stacktrace3, exploitable_class,experiment FROM crash where crash.progname='%(P)s' and crash.gdbvalidated>0  group by exploitable_hash2, exploitable_class,filepath" % (
            {'P': PROGNAME})):
        filepath = item[2]

        print('file_name:', item[5])
        myprint("\nfilepath>>>", filepath)
        myprint("gdbbugcnt:", item[1], item[0], item[3], item[4],item[5])
        # result = match_asan(filepath)
        # if not result:
        result = match_gdb(filepath,output_path)  # print形式打印，无数据库读写
        print('match result:',result)
        # print('result.len:', len(result))
        if result:
            if len(result) > 1:
                if set(result) not in SAMECVES:
                    # multiple match, should reconsider!
                    myprint("should reconsider:", result)
                else:
                    # matched same cve, nice match
                    myprint('matched same cve:',result)
            else:
                # only one match, good!
                myprint('only one match, good:',result)
            # print('item[0], item[4], result,item[5]:',item[0], item[4], result,item[5])
            write_gdb_cve(item[0], item[4], result,item[5])                # (exploitable_hash2, exploitable_class, cves)   problems?????
            print(' write_gdb_cve写入完成！！！',(item[0], item[4], result) )
        bprint_clear()
