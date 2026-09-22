"""
Curl工具模块
作用：给大模型LLM提供可调用的HTTP请求工具
底层调用系统自带curl程序发送网页请求，用于扫描网站目录、访问页面、提交登录表单等渗透资产收集操作
包含两个工具：
1. local_curl：结构化参数请求，安全规范，推荐AI优先使用
2. local_curl_raw：原始curl字符串，灵活但有命令注入风险，仅复杂请求使用
get_curl_tools：统一导出工具给Executor加载，让AI识别这两个可执行函数
"""
# json库：解析JSON格式请求头字符串，转Python字典
import json
# shlex：安全分割命令字符串，自动处理引号、空格、特殊符号，防止命令错乱
import shlex
# subprocess：Python调用本机系统命令（核心，用来运行curl程序）
import subprocess
# typing 类型注解：仅给人/IDE看，标注变量、函数的数据类型，不运行代码
from typing import Optional, List, Dict, Any
# langchain工具装饰器：@tool标记函数为AI可调用工具，LLM能读取函数名、注释、参数
from langchain_core.tools import tool


def _parse_headers(headers: Optional[str]) -> Dict[str, str]:
    """
    私有工具函数：解析JSON格式的请求头
    入参headers：可选JSON字符串，格式如 {"Cookie":"session=xxx","User-Agent":"xxx"}
    返回：键值对字典 {请求头名: 请求头值}
    逻辑：
    1. 如果headers为空，直接返回空字典
    2. 尝试把JSON文本转为Python字典
    3. 转换失败/不是字典，返回空头
    """
    # 判断没有传入headers，直接返回空请求头
    if not headers:
        return {}

    try:
        # 将JSON字符串转为Python字典对象
        obj = json.loads(headers)
        # 确保解析出来是字典，统一转字符串避免类型报错
        if isinstance(obj, dict):
            return {str(k): str(v) for k, v in obj}
        # 解析结果不是字典，丢弃，返回空
        return {}
    # JSON格式错误、解析异常，捕获后返回空头
    except Exception:
        return {}


@tool("local_curl")
def local_curl(
    url: str,
    method: str = "GET",
    headers: Optional[str] = None,
    data: Optional[str] = None,
    timeout_sec: int = 20,
    insecure: bool = False,
) -> Dict[str, Any]:
    """
    【AI可用标准curl工具】结构化发送HTTP请求，用于网站扫描、页面访问、登录提交
    适用场景：资产扫描、页面探测、接口GET/POST请求，安全可控，优先让AI调用

    参数说明：
    :param url: 目标网站地址（必填，要扫描/访问的网页链接）
    :param method: HTTP请求方式，默认GET；登录提交表单用POST
    :param headers: 请求头，JSON字符串格式，例如 {"Cookie":"session=123"}，携带登录凭证
    :param data: POST请求的表单/JSON请求体，登录账号密码填在这里
    :param timeout_sec: 请求超时时间，超过20秒判定网站无响应
    :param insecure: 是否忽略HTTPS证书报错（False=正常校验，True=跳过证书，扫描内网网站用）

    返回字典：
    exit_code: curl程序退出码 0=请求成功 非0=访问失败
    stdout: 网站返回的页面源代码（扫描到的页面内容，资产信息）
    stderr: 报错信息（网站打不开、超时、证书错误等）
    cmd: 本次执行的完整curl命令列表，用于打印调试
    """
    # 初始化curl基础参数：-sS 静默模式，不打印进度；--max-time 设置超时
    cmd: List[str] = ["curl", "-sS", "-X", method, "--max-time", str(timeout_sec)]

    # 如果开启忽略HTTPS证书，追加-k参数
    if insecure:
        cmd.append("-k")

    # 调用上面的函数，把JSON请求头转成字典
    hdrs = _parse_headers(headers)
    # 循环拼接每个请求头到curl命令，格式 -H "key: value"
    for k, v in hdrs.items():
        cmd += ["-H", f"{k}: {v}"]

    # 如果有POST表单数据，添加--data-binary携带请求体
    if data is not None:
        cmd += ["--data-binary", data]

    # 网址放在curl命令最后一位（curl标准传参规范）
    cmd.append(url)

    try:
        # 执行系统curl命令
        # capture_output=True 捕获页面输出+报错
        # text=True 输出转为字符串，不用二进制
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )
        # 执行成功，返回结果
        return {
            "exit_code": proc.returncode,
            "stdout": proc.stdout,  # 扫描获取到的网页内容（核心资产数据）
            "stderr": proc.stderr,
            "cmd": cmd,
        }
    # 执行curl出现异常（命令不存在、权限不足等）
    except Exception as e:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": str(e),
            "cmd": cmd,
        }


@tool("local_curl_raw")
def local_curl_raw(args: str = None, **kwargs) -> Dict[str, Any]:
    """
    【AI原始curl工具】直接传入完整curl参数字符串，高度灵活
    适用场景：复杂特殊请求、多层引号、特殊Header，风险更高，仅标准工具无法满足时使用
    入参args：curl后面所有参数字符串，不要写curl本身
    示例传参："-X POST https://test.com -H 'Cookie: abc' --data 'user=admin'"

    返回字典：和local_curl结构完全一致
    """
    # 兼容LangChain框架自动封装的参数别名v__args
    if args is None:
        args = kwargs.get('v__args', kwargs.get('args', ''))

    # 如果AI传的是列表，拼接成完整字符串
    if isinstance(args, list):
        args = ' '.join(str(a) for a in args)

    # curl命令固定前缀
    base = ["curl"]
    try:
        # shlex安全拆分参数字符串，自动处理单双引号、空格
        parts = shlex.split(args)
    except Exception:
        # 分词失败，直接原样放入列表兜底执行
        parts = [args]

    # 拼接完整curl命令数组
    cmd = base + parts

    try:
        # 调用系统curl执行命令
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )
        return {
            "exit_code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "cmd": cmd,
        }
    # 执行异常捕获
    except Exception as e:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": str(e),
            "cmd": cmd,
        }


def get_curl_tools() -> List:
    """
    工具导出函数
    作用：给Executor执行Agent调用，一次性获取所有curl工具
    Executor拿到这个列表后，传给LLM，AI就知道可以使用local_curl、local_curl_raw扫描网站
    返回：包含两个工具函数的列表
    """
    return [local_curl, local_curl_raw]