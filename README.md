# JWT API

REST API with hand-rolled HS256 JWTs — no libraries. Signing, verification, expiry check and constant-time compare implemented from scratch.

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/` | — | API info |
| POST | `/register` | — | Create account |
| POST | `/login` | — | Get JWT token |
| GET | `/me` | Bearer | Current user |
| GET | `/admin/users` | Bearer (admin) | List all users |

## Features

- HS256 JWT sign & verify from scratch
- bcrypt password hashing
- Per-IP rate limiting (30 req/min)
- Role-based access control
- Consistent JSON envelope on every response

## Tech Stack

PHP 8 · SQLite · PDO · Zero dependencies

## Run

```bash
php -S localhost:8001
```
