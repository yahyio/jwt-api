<?php

require __DIR__ . '/jwt.php';

const JWT_TTL = 3600;
const RATE_LIMIT = 30;
const RATE_WINDOW = 60;

$secret = getenv('JWT_SECRET') ?: 'change-me-in-production';

header('Content-Type: application/json; charset=utf-8');

function respond(int $status, array $payload): never
{
    http_response_code($status);
    echo json_encode($payload, JSON_UNESCAPED_UNICODE);
    exit;
}

function fail(int $status, string $message): never
{
    respond($status, ['success' => false, 'error' => $message, 'data' => null]);
}

function ok(array $data, int $status = 200): never
{
    respond($status, ['success' => true, 'error' => null, 'data' => $data]);
}

function db(): PDO
{
    static $pdo = null;
    if ($pdo === null) {
        $pdo = new PDO('sqlite:' . __DIR__ . '/api.db');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        $pdo->exec('
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT "user",
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS rate_hits (
                ip TEXT NOT NULL,
                hit_at INTEGER NOT NULL
            );
        ');
    }
    return $pdo;
}

function rate_limit(): void
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $now = time();
    $pdo = db();

    $pdo->prepare('DELETE FROM rate_hits WHERE hit_at < ?')->execute([$now - RATE_WINDOW]);
    $stmt = $pdo->prepare('SELECT COUNT(*) FROM rate_hits WHERE ip = ?');
    $stmt->execute([$ip]);

    if ((int) $stmt->fetchColumn() >= RATE_LIMIT) {
        header('Retry-After: ' . RATE_WINDOW);
        fail(429, 'Rate limit exceeded, slow down.');
    }
    $pdo->prepare('INSERT INTO rate_hits (ip, hit_at) VALUES (?, ?)')->execute([$ip, $now]);
}

function body(): array
{
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);
    if (!is_array($data)) {
        fail(400, 'Body must be valid JSON.');
    }
    return $data;
}

function current_user(string $secret): array
{
    $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\s+(\S+)$/', $auth, $m)) {
        fail(401, 'Missing bearer token.');
    }
    $claims = jwt_verify($m[1], $secret);
    if ($claims === null) {
        fail(401, 'Token is invalid or expired.');
    }
    return $claims;
}

rate_limit();

$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$path = '/' . trim(str_replace('index.php', '', $path), '/');

if ($method === 'GET' && $path === '/') {
    ok([
        'name'      => 'jwt-api',
        'version'   => '1.0.0',
        'endpoints' => [
            'POST /register'    => 'Create a new account',
            'POST /login'       => 'Get a JWT token',
            'GET /me'           => 'Get current user (auth required)',
            'GET /admin/users'  => 'List all users (admin only)',
        ],
    ]);
}

if ($method === 'POST' && $path === '/register') {
    $input = body();
    $email = filter_var(trim($input['email'] ?? ''), FILTER_VALIDATE_EMAIL);
    $password = $input['password'] ?? '';

    if (!$email) {
        fail(422, 'A valid email is required.');
    }
    if (strlen($password) < 8) {
        fail(422, 'Password must be at least 8 characters.');
    }

    try {
        $stmt = db()->prepare('INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)');
        $stmt->execute([$email, password_hash($password, PASSWORD_DEFAULT), date('c')]);
    } catch (PDOException) {
        fail(409, 'That email is already registered.');
    }

    ok(['id' => (int) db()->lastInsertId(), 'email' => $email], 201);
}

if ($method === 'POST' && $path === '/login') {
    $input = body();
    $stmt = db()->prepare('SELECT id, email, password_hash, role FROM users WHERE email = ?');
    $stmt->execute([trim($input['email'] ?? '')]);
    $user = $stmt->fetch();

    if (!$user || !password_verify($input['password'] ?? '', $user['password_hash'])) {
        fail(401, 'Wrong email or password.');
    }

    $token = jwt_sign(['sub' => $user['id'], 'email' => $user['email'], 'role' => $user['role']], $secret, JWT_TTL);
    ok(['token' => $token, 'expires_in' => JWT_TTL]);
}

if ($method === 'GET' && $path === '/me') {
    $claims = current_user($secret);
    ok(['id' => $claims['sub'], 'email' => $claims['email'], 'role' => $claims['role']]);
}

if ($method === 'GET' && $path === '/admin/users') {
    $claims = current_user($secret);
    if (($claims['role'] ?? '') !== 'admin') {
        fail(403, 'Admin role required.');
    }
    $users = db()->query('SELECT id, email, role, created_at FROM users ORDER BY id')->fetchAll();
    ok(['users' => $users, 'total' => count($users)]);
}

fail(404, "No route for $method $path");
