<?php

//dados de ligação à BD
$host = 'localhost:3306';
$db = 'db_tarefa4';
$user = 'root';
$pass = 'fm1003+-FM';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$db", $user, $pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    die("Erro de ligação à base de dados: " . $e->getMessage());
}

session_start();




if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}




// Classe TOTP simples
class SimpleTOTP {
    
    public static function generateSecret($length = 32) {
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $secret = '';
        for ($i = 0; $i < $length; $i++) {
            $secret .= $chars[random_int(0, 31)];
        }
        return $secret;
    }
    
    public static function base32Decode($secret) {
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $secret = strtoupper($secret);
        $decoded = '';
        
        for ($i = 0; $i < strlen($secret); $i += 8) {
            $chunk = substr($secret, $i, 8);
            $chunk = str_pad($chunk, 8, '=');
            
            $binaryString = '';
            for ($j = 0; $j < 8; $j++) {
                if ($chunk[$j] != '=') {
                    $val = strpos($chars, $chunk[$j]);
                    $binaryString .= str_pad(decbin($val), 5, '0', STR_PAD_LEFT);
                }
            }
            
            for ($j = 0; $j < strlen($binaryString); $j += 8) {
                $byte = substr($binaryString, $j, 8);
                if (strlen($byte) == 8) {
                    $decoded .= chr(bindec($byte));
                }
            }
        }
        
        return $decoded;
    }
    
    public static function generateTOTP($secret, $timeSlice = null) {
        if ($timeSlice === null) {
            $timeSlice = floor(time() / 30);
        }
        
        $secretkey = self::base32Decode($secret);
        $time = pack('N*', 0) . pack('N*', $timeSlice);
        $hm = hash_hmac('SHA1', $time, $secretkey, true);
        $offset = ord(substr($hm, -1)) & 0x0F;
        $hashpart = substr($hm, $offset, 4);
        $value = unpack('N', $hashpart);
        $value = $value[1];
        $value = $value & 0x7FFFFFFF;
        $modulo = pow(10, 6);
        return str_pad($value % $modulo, 6, '0', STR_PAD_LEFT);
    }
    
    public static function verifyTOTP($secret, $code, $discrepancy = 1) {
        $currentTimeSlice = floor(time() / 30);
        
        for ($i = -$discrepancy; $i <= $discrepancy; $i++) {
            $calculatedCode = self::generateTOTP($secret, $currentTimeSlice + $i);
            if ($calculatedCode === $code) {
                return true;
            }
        }
        return false;
    }
    
    public static function getQRCodeUrl($user, $secret, $issuer = 'MeuSite') {
        $url = 'otpauth://totp/' . urlencode($issuer . ':' . $user) . '?secret=' . $secret . '&issuer=' . urlencode($issuer);
        return 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' . urlencode($url);
    }
}

// Função para registar utilizador com MFA
function registarUtilizador($email, $password) {
    global $pdo;
    
    // Verificar se o email já existe
    $sql = "SELECT id FROM users WHERE email = ?";
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$email]);
    if ($stmt->fetch()) {
        return ['success' => false, 'message' => 'Email já existe!'];
    }
    
    $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    $segredo_mfa = SimpleTOTP::generateSecret();
    
    $sql = "INSERT INTO users (email, password, mfa_secret, mfa_enabled) VALUES (?, ?, ?, 0)";
    $stmt = $pdo->prepare($sql);
    
    if ($stmt->execute([$email, $hash, $segredo_mfa])) {
        $user_id = $pdo->lastInsertId();
        return ['success' => true, 'user_id' => $user_id, 'mfa_secret' => $segredo_mfa];
    }
    
    return ['success' => false, 'message' => 'Erro ao registar utilizador.'];
}

// Função de login
function fazerLogin($email, $password) {
    global $pdo;
    
    $sql = "SELECT * FROM users WHERE email = ?";
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$email]);
    $user = $stmt->fetch();
    
    if ($user && password_verify($password, $user['password'])) {
        return $user;
    }
    return false;
}

// Função para ativar MFA
function ativarMFA($user_id, $codigo) {
    global $pdo;
    
    $sql = "SELECT mfa_secret FROM users WHERE id = ?";
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$user_id]);
    $user = $stmt->fetch();
    
    if ($user && SimpleTOTP::verifyTOTP($user['mfa_secret'], $codigo)) {
        $sql = "UPDATE users SET mfa_enabled = 1 WHERE id = ?";
        $stmt = $pdo->prepare($sql);
        return $stmt->execute([$user_id]);
    }
    
    return false;
}


$message = '';
$qr_code_url = '';
$show_mfa_setup = false;
$show_mfa_login = false;



$password_valid = false;
$errors = [];
$email_valid = false;



if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['registar']))

{
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'] ?? '')) {
        $errors[]  = "Token de segurança inválido.";
    } else {

     
        $email = $_POST['email'];
        $password = $_POST['password'];
        $confirm_password = $_POST['confirm_password'];
        


        // Validar EMAIL
           $email = filter_var(trim($email), FILTER_SANITIZE_EMAIL);
        
        if (empty($email)) {
            $errors[] = "O email é obrigatório.";
            echo  "O email é obrigatório.";
          echo '<br>';
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = "Formato de email inválido.";
            echo "Formato de email inválido.";
            echo '<br>';
        } elseif (strlen($email) > 254) {
            $errors[] = "O email é muito longo (máximo 254 caracteres).";
            echo "O email é muito longo (máximo 254 caracteres).";
             echo '<br>';
        } elseif (strlen($email) < 5) {
            $errors[] = "O email é muito curto (mínimo 5 caracteres).";
            echo "O email é muito curto (mínimo 5 caracteres).";
                  echo '<br>';
        } else {
            // Validações adicionais de email
            $email_parts = explode('@', $email);
            if (count($email_parts) !== 2) {
                $errors[] = "Email deve conter exatamente um @.";
                echo  "Email deve conter exatamente um @.";
                 echo '<br>';
            } else {
                $local_part = $email_parts[0];
                $domain_part = $email_parts[1];
                
                // Validar parte local (antes do @)
                if (strlen($local_part) > 64) {
                    $errors[] = "A parte local do email é muito longa (máximo 64 caracteres).";
                    echo "A parte local do email é muito longa (máximo 64 caracteres).";
                      echo '<br>';
                } elseif (empty($local_part)) {
                    $errors[] = "A parte local do email não pode estar vazia.";
                    echo "A parte local do email não pode estar vazia.";
                     echo '<br>';
                } elseif (preg_match('/^\.|\.$|\.\./', $local_part)) {
                    $errors[] = "A parte local do email tem pontos consecutivos ou nas extremidades.";
                    echo "A parte local do email tem pontos consecutivos ou nas extremidades.";
                  
                         echo '<br>';
                }
                
                // Validar domínio
                if (strlen($domain_part) > 253) {
                    $errors[] = "O domínio do email é muito longo.";
                         echo "O domínio do email é muito longo.";
                      echo '<br>';
                } elseif (empty($domain_part)) {
                    $errors[] = "O domínio do email não pode estar vazio.";
                    echo "O domínio do email não pode estar vazio.";
                      echo '<br>';
                } elseif (!preg_match('/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/', $domain_part)) {
                    $errors[] = "Formato de domínio inválido.";
                    echo "Formato de domínio inválido.";
                    echo '<br>';
                } elseif (substr_count($domain_part, '.') < 1) {
                    $errors[] = "O domínio deve conter pelo menos um ponto.";
                    echo  "O domínio deve conter pelo menos um ponto.";
                    echo '<br>';
                }
                
                // Lista de domínios temporários/suspeitos (opcional)
                $temp_domains = ['10minutemail.com', 'guerrillamail.com', 'mailinator.com', 'tempmail.org'];
                if (in_array(strtolower($domain_part), $temp_domains)) {
                    $errors[] = "Emails temporários não são permitidos.";
                    echo "Emails temporários não são permitidos.";
                       echo '<br>';
                }
            }
            
            if (empty(array_filter($errors, fn($e) => strpos($e, 'email') !== false || strpos($e, 'Email') !== false))) {
                $email_valid = true;
            }
        }
        
          echo '<br>';


        // Validar SENHAS
        // Validar se as senhas coincidem
        if ($password !== $confirm_password) {
            $errors[] = "As senhas não coincidem.";
            echo "As senhas não coincidem.";
            echo '<br>';
        }


     
        
        // Validações da senha
        if (strlen($password) < 8) {
            $errors[] = "A senha deve ter pelo menos 8 caracteres.";
             echo "A senha deve ter pelo menos 8 caracteres.";
               echo '<br>';
        }
        if (strlen($password) > 128) {
            $errors[] = "A senha não pode ter mais de 128 caracteres.";
            echo "A senha não pode ter mais de 128 caracteres.";
              echo '<br>';
        }
        if (!preg_match('/[a-z]/', $password)) {
       $errors[] = "A senha deve conter pelo menos uma letra minúscula.";
            echo "A senha deve conter pelo menos uma letra minúscula.";
            echo '<br>';
           
        }
        if (!preg_match('/[A-Z]/', $password)) {
              echo  "A senha deve conter pelo menos uma letra maiúscula.";
               echo '<br>';
            $errors[] = "A senha deve conter pelo menos uma letra maiúscula.";
        }
        if (!preg_match('/[0-9]/', $password)) {
            $errors[] = "A senha deve conter pelo menos um número.";
              echo "A senha deve conter pelo menos um número.";
              echo '<br>';
        }
        if (!preg_match('/[^A-Za-z0-9]/', $password)) {
            $errors[] = "A senha deve conter pelo menos um caractere especial.";
            echo "A senha deve conter pelo menos um carater especial.";
                echo '<br>';
        }
        
      
        
        if (empty(array_filter($errors, fn($e) => strpos($e, 'senha') !== false))) {
            $password_valid = true;
        }
        
        // Se tudo OK, fazer registo do utilizador
        if (empty($errors)) {

          
          
            
            echo "<div style='color: green; padding: 10px; background: #e8f5e8; border-radius: 4px; margin: 10px 0;'>✅ Utilizador registado com sucesso! Email e senhas válidos.</div>";
        
    
    //echo 'ok';
    $resultado = registarUtilizador($email, $password);
    
    
    if ($resultado['success']) {
        $_SESSION['temp_user_id'] = $resultado['user_id'];
        $_SESSION['temp_email'] = $email;
        $_SESSION['temp_mfa_secret'] = $resultado['mfa_secret'];
        $qr_code_url = SimpleTOTP::getQRCodeUrl($email, $resultado['mfa_secret']);
        $show_mfa_setup = true;
        $message = "Utilizador registado! Configure o MFA digitalizando o QR-Code.";
    } else {
        $message = $resultado['message'];
    }
        
}
    }
}



if (isset($_POST['ativar_mfa'])) {
    $codigo = $_POST['codigo_mfa'];
    $user_id = $_SESSION['temp_user_id'];
    
    if (ativarMFA($user_id, $codigo)) {
        $message = "MFA ativado com sucesso! Pode fazer login.";
        unset($_SESSION['temp_user_id'], $_SESSION['temp_email'], $_SESSION['temp_mfa_secret']);
        $show_mfa_setup = false;
    } else {
        $message = "Código MFA inválido. Tente novamente.";
        $qr_code_url = SimpleTOTP::getQRCodeUrl($_SESSION['temp_email'], $_SESSION['temp_mfa_secret']);
        $show_mfa_setup = true;
    }
}

if (isset($_POST['login'])) {
    $email = $_POST['email'];
    $password = $_POST['password'];
    
    $user = fazerLogin($email, $password);
    
    if ($user) {
        if ($user['mfa_enabled']) {
            $_SESSION['temp_login_user'] = $user;
            $show_mfa_login = true;
            $message = "Insira o código MFA da app de autenticação.";
        } else {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['user_email'] = $user['email'];
            $message = "Login realizado! Bem-vindo! (MFA não configurado)";
        }
    } else {
        $message = "Email ou password incorretos.";
    }
}

if (isset($_POST['verificar_mfa'])) {
    $codigo = $_POST['codigo_mfa_login'];
    $user = $_SESSION['temp_login_user'];
    
    if (SimpleTOTP::verifyTOTP($user['mfa_secret'], $codigo)) {
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['user_email'] = $user['email'];
        unset($_SESSION['temp_login_user']);
        $message = "Login realizado com sucesso!";
        $show_mfa_login = false;
    } else {
        $message = "Código MFA inválido. Tente novamente.";
        $show_mfa_login = true;
    }
}

if (isset($_POST['logout'])) {
    session_destroy();
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}


if (isset($_POST['testar_codigo']) && isset($_SESSION['temp_mfa_secret'])) {
    $codigo_atual = SimpleTOTP::generateTOTP($_SESSION['temp_mfa_secret']);
    $message = "Código atual para teste: " . $codigo_atual;
    $qr_code_url = SimpleTOTP::getQRCodeUrl($_SESSION['temp_email'], $_SESSION['temp_mfa_secret']);
    $show_mfa_setup = true;
}
?>






<!DOCTYPE html>
<html lang="pt">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LOGIN</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
        }
        .form {
            background: #f8f9ff;
            padding: 25px;
            margin: 20px 0;
            border-radius: 12px;
            border-left: 5px solid #667eea;
        }
        input {
            padding: 15px;
            margin: 10px 0;
            width: 100%;
            max-width: 350px;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            box-sizing: border-box;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        button {
            padding: 15px 30px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            margin-top: 15px;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
        }
        .btn-secondary {
            background: #6c757d;
            margin-left: 10px;
        }
        .btn-secondary:hover {
            background: #5a6268;
            box-shadow: 0 4px 15px rgba(108, 117, 125, 0.4);
        }
        .message {
            padding: 18px;
            margin: 20px 0;
            border-radius: 8px;
            font-weight: 500;
        }
        .error {
            background: #ffe6e6;
            border: 2px solid #ff9999;
            color: #cc0000;
        }
        .success {
            background: #e6ffe6;
            border: 2px solid #99ff99;
            color: #008000;
        }
        .info {
            background: #e6f3ff;
            border: 2px solid #99ccff;
            color: #0066cc;
        }
        .qr-container {
            text-align: center;
            margin: 25px 0;
            padding: 25px;
            background: white;
            border-radius: 12px;
            border: 3px dashed #667eea;
        }
        .qr-container img {
            border-radius: 8px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        .user-info {
            background: linear-gradient(135deg, #d4edda, #c3e6cb);
            padding: 25px;
            border-radius: 12px;
            margin-bottom: 25px;
            border-left: 5px solid #28a745;
        }
        .instructions {
            background: #fff8e1;
            border: 2px solid #ffcc02;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }
        .instructions ol li {
            margin: 8px 0;
            font-weight: 500;
        }
        h1 {
            color: #333;
            text-align: center;
            font-size: 2.5em;
            margin-bottom: 30px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        h3 {
            color: #667eea;
            margin-top: 0;
            font-size: 1.4em;
        }
        .secret-display {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            word-break: break-all;
            color: #666;
            margin-top: 10px;
        }
        .code-input {
            text-align: center;
            font-size: 24px;
            letter-spacing: 8px;
            font-weight: bold;
        }








.password-field {
            position: relative;
            margin: 20px 0;
        }
        .password-input {
            width: 100%;
            padding: 12px 45px 12px 12px;
            border: 2px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
            transition: border-color 0.3s;
            box-sizing: border-box;
            font-family: 'Courier New', monospace;
        }
        .password-input:focus {
            outline: none;
            border-color: #4CAF50;
        }
        .password-input.invalid {
            border-color: #f44336;
        }
        .password-input.valid {
            border-color: #4CAF50;
        }
        .password-input.match {
            border-color: #4CAF50;
        }
        .password-input.no-match {
            border-color: #f44336;
        }
        .toggle-password {
            position: absolute;
            right: 12px;
            top: 50%;
            transform: translateY(-50%);
            cursor: pointer;
            font-size: 18px;
            color: #666;
            user-select: none;
        }
        .toggle-password:hover {
            color: #333;
        }
        .password-strength {
            height: 6px;
            background-color: #eee;
            border-radius: 3px;
            margin-top: 8px;
            overflow: hidden;
        }
        .strength-bar {
            height: 100%;
            width: 0%;
            transition: all 0.3s ease;
            border-radius: 3px;
        }
        .strength-very-weak { background-color: #f44336; width: 20%; }
        .strength-weak { background-color: #ff5722; width: 40%; }
        .strength-medium { background-color: #ff9800; width: 60%; }
        .strength-strong { background-color: #8bc34a; width: 80%; }
        .strength-very-strong { background-color: #4caf50; width: 100%; }
        .password-requirements {
            margin-top: 10px;
            font-size: 12px;
            color: #666;
        }
        .requirement {
            margin: 2px 0;
            padding: 2px 0;
        }
        .requirement.valid {
            color: #4caf50;
        }
        .requirement.invalid {
            color: #f44336;
        }
        .requirement::before {
            content: "• ";
            font-weight: bold;
        }
        .match-indicator {
            margin-top: 8px;
            font-size: 12px;
            padding: 8px;
            border-radius: 4px;
            text-align: center;
            font-weight: bold;
        }
        .match-indicator.match {
            background-color: #e8f5e8;
            color: #4caf50;
        }
        .match-indicator.no-match {
            background-color: #ffebee;
            color: #f44336;
        }
        .match-indicator.empty {
            background-color: #f5f5f5;
            color: #999;
        }
        .field-label {
            display: block;
            margin-bottom: 8px;
            font-weight: bold;
            color: #333;
        }
        .error-messages {
            color: #f44336;
            margin-top: 10px;
            padding: 10px;
            background-color: #ffebee;
            border-radius: 4px;
            font-size: 14px;
        }
        .other-fields {
            margin: 20px 0;
        }
        .other-fields input {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
            margin-bottom: 10px;
            box-sizing: border-box;
        }

    </style>
</head>
<body>
    <div class="container">
        <h1>LOGIN</h1>
        
        <?php if ($message): ?>
            <div class="message <?php echo (strpos($message, 'sucesso') !== false || strpos($message, 'realizado') !== false) ? 'success' : (strpos($message, 'Erro') !== false || strpos($message, 'inválido') !== false ? 'error' : 'info'); ?>">
                <?php echo htmlspecialchars($message); ?>
            </div>
        <?php endif; ?>

        <?php if (isset($_SESSION['user_id'])): ?>
            <div class="user-info">
                <h3>👋 Bem-vindo!</h3>
                <p><strong>📧 Email:</strong> <?php echo htmlspecialchars($_SESSION['user_email']); ?></p>
                <p><strong>🆔 ID:</strong> <?php echo $_SESSION['user_id']; ?></p>
                <p><strong>🔒 Status:</strong> Autenticado com segurança</p>
                <form method="POST" style="display: inline;">
                    <button type="submit" name="logout">🚪 Logout</button>
                </form>
            </div>
        
        <?php elseif ($show_mfa_setup): ?>
            <div class="form">
                <h3>📱 Configurar MFA</h3>
                <div class="instructions">
                    <p><strong>📋 Passos para configurar:</strong></p>
                    <ol>
                        <li>📲 Instale uma app autenticadora (Google Authenticator, Authy, etc.)</li>
                        <li>📷 Digitaliza o QR-Code abaixo com a app</li>
                        <li>🔢 Insira o código de 6 dígitos gerado pela app</li>
                        <li>✅ Confirme para ativar o MFA</li>
                    </ol>
                </div>
                
                <?php if ($qr_code_url): ?>
                    <div class="qr-container">
                        <p><strong>📱 QR-Code para MFA:</strong></p>
                        <img src="<?php echo $qr_code_url; ?>" alt="QR Code MFA" width="200" height="200" />
                        <div class="secret-display">
                            <strong>🔑 Segredo manual:</strong><br>
                            <?php echo $_SESSION['temp_mfa_secret']; ?>
                        </div>
                    </div>
                <?php endif; ?>
                
                <form method="POST">
                    <input type="text" name="codigo_mfa" placeholder="000000" required maxlength="6" pattern="[0-9]{6}" class="code-input">
                    <br>
                    <button type="submit" name="ativar_mfa">✅ Ativar MFA</button>
                    
                </form>
                
                <p><small>💡 <strong>Dica:</strong> Caso não consiga digitalizar o QR-Code, pode inserir manualmente o código na app de autenticação.</small></p>
            </div>
            
        <?php elseif ($show_mfa_login): ?>
            <div class="form">
                <h3>🔐 Verificação MFA</h3>
                <p>🔢 Insira o código de 6 dígitos da app de autenticação:</p>
                <form method="POST">
                    <input type="text" name="codigo_mfa_login" placeholder="000000" required maxlength="6" pattern="[0-9]{6}" class="code-input" autofocus>
                    <br>
                    <button type="submit" name="verificar_mfa">🔓 Verificar</button>
                </form>
                <p><small>⏰ O código é válido por 30 segundos e muda automaticamente.</small></p>
            </div>
            
        <?php else: ?>
            <div class="form">
                <h3>📝 Registar Nova Conta</h3>
                <form method="POST" autocomplete="on">
    


<input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
           
         <div class="other-fields">
                <label for="email" class="field-label">📧 Email</label>
                <input type="email"
                       id="email"
                       name="email"
                       class="email-input"
                       placeholder="exemplo@dominio.com"
                       required
                       maxlength="254"
                       autocomplete="email"
                       autocapitalize="none"
                       spellcheck="false"
                       oninput="validateEmail(this.value)"
                       value="<?php echo htmlspecialchars($_POST['email'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">
                <div class="email-validation" id="emailValidation">
                    Digite um endereço de email válido
                </div>
            </div>



 <!-- Campo de Senha Principal -->
            <div class="password-field">
                <label for="password" class="field-label">🔒 Senha</label>
                <input type="password"
                       id="password"
                       name="password"
                       class="password-input"
                       placeholder="Digite sua senha segura"
                       required
                       minlength="8"
                       maxlength="128"
                       autocomplete="new-password"
                       autocapitalize="none"
                       spellcheck="false"
                       data-lpignore="true"
                       oninput="validatePassword(this.value)"
                       onpaste="setTimeout(() => validatePassword(this.value), 10)">
                <span class="toggle-password" onclick="togglePasswordVisibility('password')" id="toggleIcon1">👁️</span>
                
                <div class="password-strength">
                    <div class="strength-bar" id="strengthBar"></div>
                </div>
                
                <div class="password-requirements">
                    <div class="requirement" id="req-length">Pelo menos 8 caracteres</div>
                    <div class="requirement" id="req-lower">Uma letra minúscula (a-z)</div>
                    <div class="requirement" id="req-upper">Uma letra maiúscula (A-Z)</div>
                    <div class="requirement" id="req-number">Um número (0-9)</div>
                    <div class="requirement" id="req-special">Um caractere especial (!@#$%^&*)</div>
                    <div class="requirement" id="req-common">Não ser uma senha comum</div>
                </div>
            </div>
            
            <!-- Campo de Confirmação de Senha -->
            <div class="password-field">
                <label for="confirm_password" class="field-label">🔒 Confirmar Senha</label>
                                <input type="password"
                       id="confirm_password"
                       name="confirm_password"
                       class="password-input"
                       placeholder="Digite novamente sua senha"
                       required
                       minlength="8"
                       maxlength="128"
                       autocomplete="new-password"
                       autocapitalize="none"
                       spellcheck="false"
                       data-lpignore="true"
                       oninput="checkPasswordMatch()"
                       onpaste="setTimeout(() => checkPasswordMatch(), 10)">
                <span class="toggle-password" onclick="togglePasswordVisibility('confirm_password')" id="toggleIcon2">👁️</span>
                  
                <div class="match-indicator" id="matchIndicator">
                    Digite a confirmação da senha
                </div>
             
            </div>
            
            <?php if (!empty($password_errors)): ?>
                <div class="error-messages">
                    <?php foreach ($password_errors as $error): ?>
                        <div><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>



      
                    <br>
                    <button type="submit" name="registar" id="submitBtn">📝 Registar</button>
                </form>
                <p><small>⚠️ <strong>Nota:</strong> Após o registro, será necessário configurar o MFA para maior segurança.</small></p>
            </div>
            

  <script>

// Lista de domínios temporários para verificação
        const tempDomains = ['10minutemail.com', 'guerrillamail.com', 'mailinator.com', 'tempmail.org', 'yopmail.com', 'throwaway.email'];
        
        function validateEmail(email) {
            const emailInput = document.getElementById('email');
            const emailValidation = document.getElementById('emailValidation');
            
            if (email.length === 0) {
                emailValidation.textContent = 'Digite um endereço de email válido';
                emailValidation.className = 'email-validation empty';
                emailInput.classList.remove('valid', 'invalid');
                return false;
            }
            
            // Validações básicas
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            const isValidFormat = emailRegex.test(email);
            const isValidLength = email.length >= 5 && email.length <= 254;
            
            // Validações avançadas
            let errors = [];
            
            if (!isValidFormat) {
                errors.push('Formato inválido');
            }
            
            if (!isValidLength) {
                if (email.length < 5) errors.push('Muito curto (mín. 5 caracteres)');
                if (email.length > 254) errors.push('Muito longo (máx. 254 caracteres)');
            }
            
            if (isValidFormat) {
                const parts = email.split('@');
                const localPart = parts[0];
                const domainPart = parts[1];
                
                // Validar parte local
                if (localPart.length > 64) {
                    errors.push('Parte local muito longa');
                }
                if (/^\.|\.$|\.\./.test(localPart)) {
                    errors.push('Pontos inválidos na parte local');
                }
                
                // Validar domínio
                if (!/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domainPart)) {
                    errors.push('Domínio inválido');
                }
                
                // Verificar domínios temporários
                if (tempDomains.includes(domainPart.toLowerCase())) {
                    errors.push('Emails temporários não permitidos');
                }
                
                // Verificar se domínio tem pelo menos um ponto
                if (domainPart.indexOf('.') === -1) {
                    errors.push('Domínio deve conter pelo menos um ponto');
                }
            }
            
            // Atualizar interface
            if (errors.length === 0) {
                emailValidation.textContent = '✅ Email válido';
                emailValidation.className = 'email-validation valid';
                emailInput.classList.add('valid');
                emailInput.classList.remove('invalid');
                return true;
            } else {
                emailValidation.textContent = '❌ ' + errors[0];
                emailValidation.className = 'email-validation invalid';
                emailInput.classList.add('invalid');
                emailInput.classList.remove('valid');
                return false;
            }
        }



        // Lista de senhas comuns para verificação
        const commonPasswords = ['123456', 'password', '123456789', '12345678', '12345', '1234567', 'qwerty', 'abc123', 'password123', 'admin', 'letmein', 'welcome', 'monkey', 'dragon'];
        
        function togglePasswordVisibility(fieldId) {
            const passwordInput = document.getElementById(fieldId);
            const toggleIcon = document.getElementById(fieldId === 'password' ? 'toggleIcon1' : 'toggleIcon2');
            
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                toggleIcon.textContent = '🙈';
            } else {
                passwordInput.type = 'password';
                toggleIcon.textContent = '👁️';
            }
        }
        
        function validatePassword(password) {
            const requirements = {
                'req-length': password.length >= 8,
                'req-lower': /[a-z]/.test(password),
                'req-upper': /[A-Z]/.test(password),
                'req-number': /[0-9]/.test(password),
                'req-special': /[^A-Za-z0-9]/.test(password),
                'req-common': !commonPasswords.includes(password.toLowerCase())
            };
            
            let score = 0;
            let allValid = true;
            
        
            Object.keys(requirements).forEach(reqId => {
                const element = document.getElementById(reqId);
                if (requirements[reqId]) {
                    element.classList.add('valid');
                    element.classList.remove('invalid');
                    score++;
                } else {
                    element.classList.add('invalid');
                    element.classList.remove('valid');
                    allValid = false;
                }
            });
            
         
            updateStrengthBar(score);
            
           
            const passwordInput = document.getElementById('password');
            
            if (password.length === 0) {
                passwordInput.classList.remove('valid', 'invalid');
            } else if (allValid) {
                passwordInput.classList.add('valid');
                passwordInput.classList.remove('invalid');
            } else {
                passwordInput.classList.add('invalid');
                passwordInput.classList.remove('valid');
            }
            
            // Verificar correspondência após validação
            checkPasswordMatch();
        }
        
        function checkPasswordMatch() {
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirm_password').value;

            const matchIndicator = document.getElementById('matchIndicator');
            const confirmInput = document.getElementById('confirm_password');
            
            if (confirmPassword.length === 0) {
                matchIndicator.textContent = 'Digite a confirmação da senha';
                matchIndicator.className = 'match-indicator empty';
                confirmInput.classList.remove('match', 'no-match');
            } else if (password === confirmPassword) {
                matchIndicator.textContent = '✅ As senhas coincidem';
                matchIndicator.className = 'match-indicator match';
                confirmInput.classList.add('match');
                confirmInput.classList.remove('no-match');
            } else {
                matchIndicator.textContent = '❌ As senhas não coincidem';
                matchIndicator.className = 'match-indicator no-match';
                confirmInput.classList.add('no-match');
                confirmInput.classList.remove('match');
            }
        }
        
        function updateStrengthBar(score) {
            const strengthBar = document.getElementById('strengthBar');
            const classes = ['strength-very-weak', 'strength-weak', 'strength-medium', 'strength-strong', 'strength-very-strong'];
            

            classes.forEach(cls => strengthBar.classList.remove(cls));
            
      
            if (score <= 1) {
                strengthBar.classList.add('strength-very-weak');
            } else if (score <= 2) {
                strengthBar.classList.add('strength-weak');
            } else if (score <= 3) {
                strengthBar.classList.add('strength-medium');
            } else if (score <= 4) {
                strengthBar.classList.add('strength-strong');
            } else {
                strengthBar.classList.add('strength-very-strong');
            }
        }
        
        // Prevenir colagem de senhas fracas em ambos os campos
        ['password', 'confirm_password'].forEach(fieldId => {
            document.getElementById(fieldId).addEventListener('paste', function(e) {
                setTimeout(() => {
                    const password = e.target.value;
                    if (commonPasswords.includes(password.toLowerCase())) {
                        alert('⚠️ Esta senha é muito comum e insegura. Por favor, escolha uma senha mais forte.');
                        e.target.value = '';
                        if (fieldId === 'password') {
                            validatePassword('');
                        } else {
                            checkPasswordMatch();
                        }
                    }
                }, 10);
            });
        });
        
        // Sincronizar validação quando houver mudanças
        document.getElementById('password').addEventListener('input', function() {
            checkPasswordMatch();
        });
        
        // Proteção contra auto-preenchimento inseguro
        document.addEventListener('DOMContentLoaded', function() {
            const passwordField = document.getElementById('password');
            const confirmField = document.getElementById('confirm_password');
            
          
            setTimeout(() => {
                if (passwordField.value) {
                    validatePassword(passwordField.value);
                }
                if (confirmField.value) {
                    checkPasswordMatch();
                }
            }, 1000);
        });
    </script>




 <script>
         function myFunction() {
           var x = document.getElementById("mypass");
           if (x.type === "password") {
             x.type = "text";
           } else {
             x.type = "password";
           }
         }
         </script>


<script>
function email_validation(){
'use strict';

var mailformat = /^\w+([\.\-]?\w+)*@\w+([\.\-]?\w+)*(\.\w{2,3})+$/;
var email_name = document.getElementById("email");
var email_value = document.getElementById("email").value;
var email_length = email_value.length;
if(!email_value.match(mailformat) || email_length === 0)
{

document.getElementById('email_err').innerHTML = '<br>'+'Email inválido.';
email_name.focus();
document.getElementById('email_err').style.color = "#FF0000";
}
else
{
   document.getElementById('email_err').innerHTML = '<br>'+'Email válido';
document.getElementById('email_err').style.color = "#00AF33";
}
}
</script>







            <div class="form">
                <h3>🚪 Fazer Login</h3>
                <form method="POST">
                    <input type="email" name="email" placeholder="📧 Email" required>
                    <br>
                    <input type="password" name="password" placeholder="🔒 Password" required>
                    <br>
                    <button type="submit" name="login">🚪 Login</button>
                </form>
            </div>
            
        
        <?php endif; ?>
    </div>

    <script>
    
        document.querySelectorAll('.code-input').forEach(input => {
            input.addEventListener('input', function(e) {
                // Remove caracteres não numéricos
                this.value = this.value.replace(/[^0-9]/g, '');
            });
        });
    </script>
</body>
</html>