#!/usr/bin/env python3

import http.server
import socketserver
import base64
import subprocess
import os
import json
import socket # For hostname
import shlex # For safer command splitting

# --- Configuration ---
HOST = '0.0.0.0' # Listen on all interfaces
PORT = 5000     # Changed to a common HTTP port
# WARNING: Hardcoding credentials is not recommended for production.
USERNAME = "admin"
PASSWORD = "supersecretpassword" # Change this!

# !!! WARNING: SSL/HTTPS HAS BEEN REMOVED !!!
# Credentials will be sent in PLAINTEXT over the network.
# Only use this version if you understand and accept the security risks.
# For any sensitive use, SSL is highly recommended.
# !!! WARNING END !!!

# --- Global State (for CWD) ---
current_working_directory = os.getcwd()

# Define the threaded HTTP server class
class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Handle requests in a separate thread."""
    allow_reuse_address = True

class WebShellHandler(http.server.BaseHTTPRequestHandler):

    def _send_auth_required(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Web Shell (INSECURE HTTP)"') # Updated realm
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"<h1>401 Unauthorized</h1><p>Authentication required.</p>")

    def _check_auth(self):
        auth_header = self.headers.get('Authorization')
        if auth_header is None:
            self._send_auth_required()
            return False

        if not auth_header.startswith('Basic '):
            self.send_error(400, "Bad Authorization header")
            return False

        try:
            encoded_credentials = auth_header.split(' ')[1]
            decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
            username, password = decoded_credentials.split(':', 1)

            if username == USERNAME and password == PASSWORD:
                return True
            else:
                self._send_auth_required()
                return False
        except Exception as e:
            print(f"Authentication error: {e}")
            self.send_error(400, "Error processing credentials")
            return False

    def _get_prompt(self):
        global current_working_directory
        user = USERNAME
        host = socket.gethostname()
        home_dir = os.path.expanduser(f"~{user}") if user == os.getlogin() else os.path.expanduser("~")
        norm_cwd = os.path.normpath(current_working_directory)
        norm_home = os.path.normpath(home_dir)

        if norm_cwd == norm_home or norm_cwd.startswith(norm_home + os.sep):
            display_cwd = "~" + norm_cwd[len(norm_home):]
        else:
            display_cwd = norm_cwd
        
        return f"{user}@{host}:{display_cwd}$ "

    def do_GET(self):
        if not self._check_auth():
            return

        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()

            initial_prompt = self._get_prompt()
            # The JavaScript needs to be aware of the Authorization header for POST
            # Storing it in a JS variable is one way, though ideally,
            # for truly stateless requests, it might be better to re-prompt if 401.
            # For simplicity here, we'll continue to pass it.
            auth_header_value = self.headers.get("Authorization", "")

            html_content = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Python Web Shell (HTTP - Insecure)</title>
                <style>
                    body {{ font-family: monospace; background-color: #1e1e1e; color: #d4d4d4; margin: 0; padding: 10px; }}
                    #terminal {{ height: calc(100vh - 70px); overflow-y: auto; border: 1px solid #333; padding: 10px; margin-bottom:10px; white-space: pre-wrap; word-wrap: break-word;}}
                    .output-line {{ margin-bottom: 5px; }}
                    .command-line {{ color: #569cd6; }}
                    .stdout {{ color: #d4d4d4; }}
                    .stderr {{ color: #f44747; }}
                    #prompt-container {{ display: flex; align-items: center; }}
                    #prompt {{ color: #6a9955; white-space: nowrap; }}
                    #command-input {{
                        flex-grow: 1; background-color: transparent; color: #d4d4d4;
                        border: none; outline: none; font-family: monospace; font-size: 1em;
                        padding-left: 5px;
                    }}
                </style>
            </head>
            <body>
                <div id="terminal"></div>
                <div id="prompt-container">
                    <span id="prompt">{initial_prompt}</span>
                    <input type="text" id="command-input" autofocus>
                </div>

                <script>
                    const terminal = document.getElementById('terminal');
                    const commandInput = document.getElementById('command-input');
                    const promptSpan = document.getElementById('prompt');
                    let commandHistory = [];
                    let historyIndex = -1;
                    const storedAuthHeader = "{auth_header_value}"; // Store auth header from GET

                    function appendToTerminal(htmlContent, type = 'stdout') {{
                        const line = document.createElement('div');
                        line.classList.add('output-line');
                        if (type === 'command') {{
                            line.classList.add('command-line');
                        }} else if (type === 'stderr') {{
                            line.classList.add('stderr');
                        }} else {{
                            line.classList.add('stdout');
                        }}
                        line.innerHTML = htmlContent;
                        terminal.appendChild(line);
                        terminal.scrollTop = terminal.scrollHeight;
                    }}

                    commandInput.addEventListener('keydown', async (event) => {{
                        if (event.key === 'Enter') {{
                            event.preventDefault();
                            const command = commandInput.value.trim();
                            if (command === '') return;

                            commandHistory.push(command);
                            historyIndex = commandHistory.length;

                            appendToTerminal(promptSpan.textContent + escapeHtml(command), 'command');
                            commandInput.value = '';

                            try {{
                                const headers = {{
                                    'Content-Type': 'application/json'
                                }};
                                if (storedAuthHeader) {{ // Add auth header if available
                                    headers['Authorization'] = storedAuthHeader;
                                }}

                                const response = await fetch('/', {{ // URL will be http://...
                                    method: 'POST',
                                    headers: headers,
                                    body: JSON.stringify({{ command: command }})
                                }});

                                if (response.status === 401) {{
                                    appendToTerminal("Authentication failed or session expired. Please refresh the page to re-authenticate.", 'stderr');
                                    commandInput.disabled = true;
                                    return;
                                }}
                                if (!response.ok) {{
                                    throw new Error(`HTTP error! status: ${{response.status}}`);
                                }}

                                const result = await response.json();
                                if (result.output) {{
                                    result.output.split('\\n').forEach(line => {{
                                        appendToTerminal(escapeHtml(line), result.is_error ? 'stderr' : 'stdout');
                                    }});
                                }}
                                promptSpan.textContent = result.prompt;

                            }} catch (error) {{
                                console.error('Error:', error);
                                appendToTerminal(`Client-side error: ${{escapeHtml(error.message)}}`, 'stderr');
                            }}
                        }} else if (event.key === 'ArrowUp') {{
                            if (commandHistory.length > 0 && historyIndex > 0) {{
                                event.preventDefault();
                                historyIndex--;
                                commandInput.value = commandHistory[historyIndex];
                                commandInput.setSelectionRange(commandInput.value.length, commandInput.value.length);
                            }}
                        }} else if (event.key === 'ArrowDown') {{
                            if (commandHistory.length > 0 && historyIndex < commandHistory.length -1 ) {{
                                event.preventDefault();
                                historyIndex++;
                                commandInput.value = commandHistory[historyIndex];
                                commandInput.setSelectionRange(commandInput.value.length, commandInput.value.length);
                            }} else if (historyIndex === commandHistory.length -1) {{
                                event.preventDefault();
                                historyIndex++;
                                commandInput.value = "";
                            }}
                        }}
                    }});

                    function escapeHtml(unsafe) {{
                        return unsafe
                             .replace(/&/g, "&")
                             .replace(/</g, "<")
                             .replace(/>/g, ">")
                             .replace(/'/g, "'")
                             .replace(/'/g, "'");
                    }}
                    commandInput.focus();
                </script>
            </body>
            </html>
            """
            self.wfile.write(html_content.encode('utf-8'))
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        global current_working_directory
        if not self._check_auth(): # Authentication still happens
            return

        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        try:
            data = json.loads(post_data.decode('utf-8'))
            command_str = data.get('command')

            if not command_str:
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'output': 'No command provided', 'prompt': self._get_prompt(), 'is_error': True}).encode('utf-8'))
                return

            output = ""
            is_error = False

            if command_str.strip().startswith('cd'):
                parts = shlex.split(command_str)
                if len(parts) > 1:
                    target_dir = parts[1]
                    target_dir_expanded = os.path.expanduser(os.path.expandvars(target_dir))
                    try:
                        if not os.path.isabs(target_dir_expanded):
                            target_dir_expanded = os.path.join(current_working_directory, target_dir_expanded)
                        
                        os.chdir(target_dir_expanded)
                        current_working_directory = os.getcwd()
                        output = f"Changed directory to {current_working_directory}"
                    except FileNotFoundError:
                        output = f"cd: no such file or directory: {target_dir}"
                        is_error = True
                    except Exception as e:
                        output = f"cd: error changing directory: {e}"
                        is_error = True
                else:
                    try:
                        home_dir = os.path.expanduser("~")
                        os.chdir(home_dir)
                        current_working_directory = os.getcwd()
                        output = f"Changed directory to {current_working_directory}"
                    except Exception as e:
                        output = f"cd: error changing to home directory: {e}"
                        is_error = True
            elif command_str.strip().lower() == 'exit' or command_str.strip().lower() == 'logout':
                output = "Session will be 'closed' by client (refresh to reconnect)."
            else:
                try:
                    process = subprocess.run(
                        command_str,
                        shell=True,
                        capture_output=True,
                        text=True,
                        cwd=current_working_directory,
                        env=dict(os.environ, PATH=os.environ.get("PATH","") + ":/usr/local/bin")
                    )
                    stdout = process.stdout.strip()
                    stderr = process.stderr.strip()
                    if stdout: output += stdout
                    if stderr:
                        if output: output += "\n"
                        output += stderr
                        if process.returncode != 0:
                            is_error = True

                except Exception as e:
                    output = f"Error executing command: {str(e)}"
                    is_error = True

            response_data = {
                'output': output,
                'prompt': self._get_prompt(),
                'is_error': is_error
            }
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode('utf-8'))

        except json.JSONDecodeError:
            self.send_response(400)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'output': 'Invalid JSON payload', 'prompt': self._get_prompt(), 'is_error': True}).encode('utf-8'))
        except Exception as e:
            print(f"POST handling error: {e}")
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'output': f'Server error: {str(e)}', 'prompt': self._get_prompt(), 'is_error': True}).encode('utf-8'))


def run_server():
    # Use ThreadedHTTPServer directly, no SSL
    httpd = ThreadedHTTPServer((HOST, PORT), WebShellHandler)
    
    print(f"Serving HTTP (INSECURE) on {HOST}:{PORT}...") # Updated print
    print(f"!!! WARNING: Credentials (Username: {USERNAME}, Password: {PASSWORD}) will be sent in PLAINTEXT !!!")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer shutting down.")
    finally:
        httpd.server_close()

if __name__ == '__main__':
    # No need to check for CERTFILE anymore
    run_server()