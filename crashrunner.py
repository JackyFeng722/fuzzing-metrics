#!/usr/bin/python3

"""
Assume that we have conducted experiments with 30 repetitions and the folder is like:
/c/work/general/afl/exiv2/1/crashes
/c/work/general/afl/exiv2/2/crashes
...
/c/work/general/afl/exiv2/30/crashes

We can run the crash to obtain ASAN output to folder /c/ASAN_OUTPUT/c_work_general/{fuzzername}/{progname}/{repetition}/
# cd /c/work/general/afl
# find -type f|grep crashes/|grep -v README.txt > crasheslist.txt
# cat crasheslist.txt|CMD="/d/p/aflasan/exiv2 @@" /nfs/scripts/crashrunner.py
"""

import sys
import subprocess
import re
import os
import time
import glob
import shlex
import shutil
import threading
from time import sleep
from paraData import dataset
from db_crash_init import AsanMain,GDBMain
from exploitablerunner import gdbAnalysis
MAX_THREADS = 10
os.environ["ASAN_OPTIONS"]='stack_trace_format="FUNCTIONSTARTFUNCTIONSTARTFUNCTIONSTART%fFUNCTIONENDFUNCTIONENDFUNCTIONEND_LOCATIONSTARTLOCATIONSTARTLOCATIONSTART%SLOCATIONENDLOCATIONENDLOCATIONEND_FRAMESTARTFRAMESTARTFRAMESTART%nFRAMEENDFRAMEENDFRAMEEND"'

root_dir = os.getcwd()  # 根目录
programNamePath = os.path.dirname(root_dir)  # cmd :   /home/jacky/Desktop/cflow-1.6_tmp_2/src/cflow @@
crashlist_file = []  # crashlist files
lock = threading.Lock()

def dprint(*args):
    sys.stderr.write(" ".join([str(i) for i in args])+"\n")


def run_one_file(file, cmd, tmpfile, stdoutfile, stderrfile, timeoutfile, timeout=10):
    """
    Run certain file to get stdoutfile and stderrfile
    First, the file will be copied to tmpfile,
    then @@ in cmd will be replaced to tmpfile,
    output will be saved to stdoutfile and stderrfile
    if timedout, timeoutfile will be created
    
    Return: (nottimeout, runtime, outputtext)
    
    The caller should keep tmpfile only operated by current thread,
    stdoutfile folder should be present
    """
    shutil.copy(file, tmpfile)
    
    if "@@" in cmd:
        cmds = shlex.split(cmd.replace("@@", tmpfile))
        stdin = None
    else:
        cmds = shlex.split(cmd)
        stdin = open(tmpfile, "rb")
        
    nottimeout = True
    if os.path.exists(timeoutfile):
        os.unlink(timeoutfile)
    starttime = time.time()
    
    #dprint(cmds)
    try:
        x = subprocess.run(cmds, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        exitcode = x.returncode
    except subprocess.TimeoutExpired as e:
        x = e
        nottimeout = False
        with open(timeoutfile, "w") as tmp:
            tmp.write(file+"\n")
        exitcode = -15 #SIGTERM
    
    endtime = time.time()
    runtime = endtime - starttime
    outputtext = x.stdout.decode(errors="ignore")+"\n"+x.stderr.decode(errors="ignore")
    
    with open(stdoutfile, "wb") as fp:
        fp.write(x.stdout)
    with open(stderrfile, "wb") as fp:
        fp.write(x.stderr)
    with open(stdoutfile.replace(".stdout", ".returncode"), "w") as fp:
        fp.write(str(exitcode))
    
    return (nottimeout, exitcode, runtime, outputtext)

FINISHED = 0
RESULT = {}

from db_crash_init import parse_asan
def getbugid(text, progname,filename):
    gccasan_vulntype,gccasan_full,gccasan_fullraw,gccasan_uniq,gccasan_1,gccasan_2,gccasan_3,gccasan_4,gccasan_5, bugid = parse_asan(text, progname,filename)
    return bugid

def thread_main(files, cmd,out,progname, threadid, myname):
    # in each thread, iteratively call run_one_file:
    #     run_one_file(file, cmd, tmpfile, stdoutfile, stderrfile, timeoutfile, timeout=10)
    # tmpfile is calculated using myname and threadid
    # pathname of other output files are generated using file pathname, 
    # appending ".stdout", ".stderr", ".timeout" suffix respectively
    
    global FINISHED, RESULT
    usecache = not os.environ.get("NOCACHE", False)

    for file in files:
        # we will place output files to a folder under /c/ASAN_OUTPUT/
        # this folder is generated solely from file pathname
        # used as a cache folder, to speed up further analysis
        # we ignore certain keywords to shorten output_folder name
        
        # print("current:",file)
        f = file.split("/")
        fname = f[-1]     # fname即   id:000195,sig:11,src:001320,op:MOpt-core-havoc,rep:16
        prefix = progname    # prefix是文件夹名称:jhead,mpa3gain...

        # 分析输出路径
        out = os.path.join(os.path.dirname(root_dir),'AnalysisOutput','ASAN_OUTPUT') # /home/jacky/Desktop/output/ASAN_OUTPUT
        output_folder =os.path.join(out,fuzzer,prefix)  # ../project/AnalysisOutput/ASAN_OUTPUT/fuzzerName/program
        #print("output_folder:",output_folder)

        
        if not os.path.exists(output_folder):  # 输出文件夹不存在则创建
            os.makedirs(output_folder, exist_ok=True)
        # 临时文件所在路径
        tmpfile = out+"/" +fuzzer+"/"  +prefix +"/tmp/{myname}_{threadid}".format(**locals())    # modify
        tmp =os.path.join(out,fuzzer,prefix,'tmp')  # 临时文件所在路径: ../project/AnalysisOutput/ASAN_OUTPUT/fuzzerName/program/tmp
        if not os.path.exists(tmp):  # tmp文件夹不存在则创建
            os.makedirs(tmp, exist_ok=True)
        program_x_y = os.path.join(output_folder, proname)
        if not os.path.exists(os.path.join( output_folder,proname) ):  # 创建文件目录,存放三个输出文件: ../project/AnalysisOutput/ASAN_OUTPUT/fuzzerName/program/program_x_y/
            os.makedirs(program_x_y, exist_ok=True)
            
        stdoutfile = os.path.join( output_folder,proname,fname+".stdout")  # ../project/AnalysisOutput/ASAN_OUTPUT/fuzzerName/program/program_x_y/xxxxxxxxxxxx.stdout
        stderrfile = os.path.join( output_folder,proname,fname+".stderr")
        timeoutfile =os.path.join( output_folder,proname,fname+".timeout")
        
        with lock:
            if not os.path.exists(stdoutfile) or not usecache:       # 生成stdoutfile 文件
                # do not read cache, run it!
                res = run_one_file(file, cmd, tmpfile, stdoutfile, stderrfile, timeoutfile, timeout=10)
            else:
                nottimeout = not os.path.exists(timeoutfile)
                exitcode = int(open(stdoutfile.replace(".stdout", ".returncode")).read())
                runtime = -1
                outputtext = open(stdoutfile, "r", errors="ignore").read()+"\n"+open(stderrfile, "r", errors="ignore").read()
                res = (nottimeout, exitcode, runtime, outputtext)

            RESULT[file] = res
            if "AddressSanitizer" in res[3]:
               print("find AddressSanitizer:",file)
        with lock:
            FINISHED += 1

# paraData.py中查找元素
def find_program(dataset, progname):
    for data in dataset:
        if data[1] == progname:
            return data[1]
    return None

def find_para(dataset, progname):
    for data in dataset:
        if data[1] == progname:
            return data[2]
    return None

def find_asan_program(dataset, progname):
    for data in dataset:
        if data[1] == progname:
            return data[5]
    return None
def find_GDB_program(dataset, progname):
    for data in dataset:
        if data[1] == progname:
            return data[6]
    return None

# /home/jacky/Desktop/research/RE2_output/AFL/mp3gain/mp3gain_1_0
def find_crasheslist_files(base_dir, crash_dir_name, readme, output_file):
    if(os.path.join(base_dir,crash_dir_name)):
        print(base_dir.split('/')[-1],'crash文件不存在')

    crash_dir = os.path.join(base_dir,crash_dir_name)
    print('crash_dir:',crash_dir)
    # 遍历 crash/ 目录下的所有文件和子目录
    for root, dirs, files in os.walk(crash_dir):
        files.sort()
        print('files:',files)  #  ['id:000035,sig:11,src:000008,op:havoc,rep:16', 'id:000182,sig:06,src:001031+001461,op:splice,rep:128', ...]

    # 使用列表推导式过滤掉 'README.txt'
    global  crashlist_file
    crashlist_file = [ os.path.join(base_dir,'crashes',file) for file in files if file != readme] # 检查文件路径是否不包含 readme.txt
    print('crashlist_file:',crashlist_file)
    # 将结果写入到 output_file 文件中
    with open(output_file, "w") as f:
        for file in crashlist_file:
            f.write(file + "\n")


if __name__ == "__main__":

    fuzzer = input("模糊器名称:")
    proname = input("被测程序名称:")  # jhead_1_1
    mode = input("选择漏洞分析：1.ASAN  2.GDB :")
    # 被测程序简称: jhead
    programPrefix = find_program(dataset,proname.split('_')[0])
    print('program:',programPrefix)
    # 启动asan的被测程序: asan jhead
    programAsanPath = find_asan_program(dataset,proname.split('_')[0])
    print('programAsanPath:',programAsanPath)
    # 启动GDB的被测程序: GDB jhead
    programGDBPath = find_GDB_program(dataset,proname.split('_')[0])
    # fuzzing结果文件(crashes):   ../project/RE2_output/fuzzerName/program/program_X_Y
    pronamePath = os.path.join(os.path.dirname(root_dir),"RE2_output",fuzzer,programPrefix,proname)
    print('pronamePath',pronamePath)
    # ASAN结果保存路径:           ../project/AnalysisOutput/ASAN_OUTPUT/fuzzerName/program/program_X_Y
    pronamePathOutput = os.path.join(os.path.dirname(root_dir),'AnalysisOutput','ASAN_OUTPUT',fuzzer,programPrefix,proname)
    print('ASANoutput:',pronamePathOutput)
    # GDB结果保存路径:           ../project/AnalysisOutput/GDB_OUTPUT/fuzzerName/program/program_X_Y
    pronamePathOutputGDB = os.path.join(os.path.dirname(root_dir),'AnalysisOutput','GDB_OUTPUT',fuzzer,programPrefix,proname)
    print('GDBoutput:',pronamePathOutputGDB)

    # 生成文件crasheslist.txt,保存在当前被测程序crash统计目录下
    find_crasheslist_files(pronamePath, 'crashes/', 'README.txt', os.path.join(pronamePath,'crasheslist.txt'))
    dprint("Total crashlist files:", len(crashlist_file))

    # ASAN漏洞分析
    if mode == "1":
        if programPrefix is None and programAsanPath is None:
            print('输入模糊器或被测程序不存在:')
            sys.exit(1)  # 退出程序，状态码 1 表示程序异常终止

        # 被测程序输入指令
        cmdPrefix = find_para(dataset, proname.split('_')[0])
        cmd = programAsanPath + " "+ cmdPrefix  # cmd :   /home/jacky/Desktop/cflow-1.6_tmp_2/src/cflow @@

        if not cmd:
            print("[Error] env CMD not given")
            exit(1)
        print('cmd:',cmd)

        # assert programPrefix in programName
        assert os.access(programAsanPath, os.X_OK), "CMD program not executable?"

        myname = "tmp_crashrunner_"+str(os.getpid())

        len_FILES=len(crashlist_file)
        # 线程数=min(10,全部文件数)
        threadN = min(MAX_THREADS, len_FILES)
        print('threadN:',threadN)

        out = os.path.join(os.path.dirname(root_dir),'AnalysisOutput','ASAN_OUTPUT',fuzzer)
        for i in range(threadN):
            t = threading.Thread(target=thread_main, args=[crashlist_file[i::threadN], cmd,out, programPrefix,i, myname])
            t.start()


        while FINISHED < len_FILES:
            #print("finished:", FINISHED, "/", len_FILES)
            sleep(1)

        foundbugids = set()
        for name, value in RESULT.items():
            # print("value[3]:  ",value[3])
            text = value[3]
            if "AddressSanitizer" in text:
                # print('test:',text) # 查看.stderr结果内容
                foundbugids.add(getbugid(text, programPrefix,filename=name.split('/')[-1]))
        print("bugids:", sorted(list(foundbugids)))

        for f in glob.glob("/tmp/"+myname+"*"):
            os.unlink(f)

        # 写入数据库
        AsanMain("crash", [fuzzer], os.path.join(pronamePath,'crasheslist.txt'), pronamePathOutput,
             programPrefix,flag='ASAN')


    # GDB漏洞分析
    elif mode=="2":
        gdbAnalysis(programGDBPath,os.path.join(pronamePath,'crasheslist.txt'),pronamePathOutputGDB)
        # 写入数据库
        GDBMain("crash_gdb", [fuzzer], os.path.join(pronamePath,'crasheslist.txt'), pronamePathOutputGDB,
             programPrefix,flag='GDB')

    else:
        print('无效指令')