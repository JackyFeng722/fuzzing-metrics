import os
import requests
from bs4 import BeautifulSoup

# 初始化存储无法访问的 URL 字典
cve_not_reach = []

def search_cve(program,cve_file):
    CVEID_count = 0   # CVE计数器
    # 构建URL
    url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={program}"

    # 发送请求获取网页内容
    response = requests.get(url)

    # 检查请求是否成功
    if response.status_code != 200:
        print(f"Failed to retrieve data: {response.status_code}")
        return

    # 解析HTML内容
    soup = BeautifulSoup(response.text, 'html.parser')

    # 查找所有CVE链接
    cve_links = soup.find_all('a', href=True)

    # 筛选并访问每个CVE链接
    for link in cve_links:
        href = link['href']
        if href.startswith('/cgi-bin/cvename.cgi?name='):
            cve_url = f"https://cve.mitre.org{href}"
            CVEID = href.split('name=')[-1]
            CVEID_count +=1

            print(f"Visiting {CVEID_count}: {CVEID}: {cve_url}")
            find_misc_links(cve_url,CVEID,cve_file)
            print('-------------------------------------------------------------------------------------------')



def find_misc_links(cve_url,CVEID,cve_file):
    # 发送请求获取CVE页面内容
    response = requests.get(cve_url)

    # 检查请求是否成功
    if response.status_code != 200:
        print(f"Failed to retrieve data: {response.status_code}")
        return

    # 解析HTML内容
    soup = BeautifulSoup(response.text, 'html.parser')

    # 查找所有以MISC开头的链接
    misc_links = soup.find_all('a', href=True)

    for link in misc_links:
        href = link['href']
        # 读取每个CVE漏洞网页信息:   发送请求获取MISC页面内容
        if href.startswith('https://') and 'MISC' in link.text:
            try:
                response = requests.get(href, timeout=20)  # 你可以在此处添加 proxies=proxies 参数
                response.raise_for_status()  # 检查请求是否成功
            except requests.exceptions.ConnectionError as conn_err:
                if 'Network is unreachable' in str(conn_err):

                    cve_not_reach.append({'cve_id': CVEID, 'url': href})
                    # print(f"Network is unreachable. Added {href} to cve_not_reach list and continuing.")
                    print(f"\033[91mNetwork is unreachable. Added {href} with CVE ID {CVEID}.\033[0m")
                    continue
                else:
                    print(f"\033[91mConnection error occurred: {conn_err}\033[0m")
            except requests.exceptions.HTTPError as http_err:
                print(f"\033[91mHTTP error occurred: {http_err}\033[0m")
            except requests.exceptions.Timeout as timeout_err:
                print(f"\033[91mTimeout error occurred: {timeout_err}\033[0m")
            except requests.exceptions.RequestException as req_err:
                print(f"\033[91mAn error occurred: {req_err}\033[0m")
            else:
                # 访问网页
                response = requests.get(href)
                # 解析网页内容
                soup = BeautifulSoup(response.content, 'html.parser')
                # 获取页面的文本内容
                data = soup.get_text()

                type, funname ,funpoc  = get_vulnInfo(data)
                print(' type, funname, funpoc:', type,  funname ,funpoc )
                # 将数据写入目标文件
                with open(cve_file, "a") as file:
                    file.write(f"{CVEID}\t")
                    file.write(f"{type}\t")
                    file.write(f"{funname}\t")
                    file.write(f"{funpoc}\t\n")



    print('cve not reach id:',cve_not_reach)



def get_vulnInfo(err):
    res = "???"
    count = 0
    # 问题函数位置
    funpoc = []
    # 问题函数名
    fullraw = []

    for line in err.split("\n"):
        if "AddressSanitizer" in line:
            count += 1
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

        # 类型1: 0x423ec1 in ReadMP3APETag (/d/prog/mp3gain-code/mp3gain/apetag.c:243)
        if '(' in line and 0< count < 2 and  line.strip().startswith('#') :
            # 类型3: 0 0x4473f9  (/home/.../analysis/mp3gain-1_6_2-src/mp3gain+0x4473f9)
            if ' in ' not in line:
                # 提取函数名称（在 '(' 前的部分）
                funcname = line.split("(")[0].strip().split(" ")[
                    -1].strip()  # in ReadMP3APETag  /x/xx  -----> ReadMP3APETag
                fileLib = line.split("(")[-1]  # lib/x86_64-linux-gnu/libc.so.6+0x2082f -----> lib
                filePos = line.split("/")[-1].split(":")[
                    0].strip()  # (/lib/x86_64-linux-gnu/libc.so.6+0x2082f  --->  ibc.so.6+0x2082f

                if len(funcname):
                    fullraw.append(funcname)

                if not (fileLib.startswith("/usr") or fileLib.startswith("/lib") or fileLib.startswith(
                        "/lib32") or fileLib.startswith("/lib64") or fileLib.startswith("/var") or fileLib.startswith(
                    "/bin") or fileLib == "<null>"):
                    funpoc.append(filePos)
            else:
                # 提取函数名称（在 '(' 前的部分）
                funcname = line.split("(")[0].split("in")[-1].strip() # in ReadMP3APETag  (xxx)  -----> ReadMP3APETag
                fileLib = line.split("(")[-1]   # (/lib/x86_64-linux-gnu/libc.so.6+0x2082f) -----> /lib
                filePos = line.split(")")[0].split("/")[-1].split(":")[0].strip()  # (/lib/x86_64-linux-gnu/libc.so.6+0x2082f  --->  ibc.so.6+0x2082f

                if len(funcname):
                    fullraw.append(funcname)

                if not (fileLib.startswith("/usr") or fileLib.startswith("/lib") or fileLib.startswith(
                        "/lib32") or fileLib.startswith("/lib64") or fileLib.startswith("/var") or fileLib.startswith(
                    "/bin") or fileLib == "<null>"):

                    funpoc.append(filePos)


        # 类型2: 0x423ec1 in ReadMP3APETag /d/prog/mp3gain-code/mp3gain/apetag.c:243
        elif '(' not in line and 0< count < 2 and  line.strip().startswith('#'):
            # 提取函数名称（在 '(' 前的部分）
            funcname = line.split("/")[0].split("in")[-1].strip() # in ReadMP3APETag  /x/xx  -----> ReadMP3APETag
            fileLib = line.split("/")[-1]   # lib/x86_64-linux-gnu/libc.so.6+0x2082f -----> lib
            filePos = line.split("/")[-1].split(":")[0].strip()  # (/lib/x86_64-linux-gnu/libc.so.6+0x2082f  --->  ibc.so.6+0x2082f

            if len(funcname):
                fullraw.append(funcname)

            if not (fileLib.startswith("usr") or fileLib.startswith("lib") or fileLib.startswith(
                    "lib32") or fileLib.startswith("lib64") or fileLib.startswith("var") or fileLib.startswith(
                "bin") or fileLib == "<null>"):

                funpoc.append(filePos)




        if count > 2:
            print('many poc')
            break

    return res,fullraw,funpoc


if __name__ == "__main__":

    program = input("Enter the program name: ")

    # 当前文件根目录
    CVE_ANALYSIS = os.path.dirname(os.path.abspath(__file__))

    # 目标文件夹和文件路径
    root_cve_dir = os.path.join(CVE_ANALYSIS, "CveDataset")
    if not os.path.exists(root_cve_dir):
        os.makedirs(root_cve_dir)

    # 确保目标文件夹存在，如果不存在，则创建它
    if not os.path.exists(root_cve_dir):
        os.makedirs(root_cve_dir)

    # 目标文件路径
    cve_file = os.path.join(root_cve_dir,  program+ ".txt")
    search_cve(program,cve_file)





