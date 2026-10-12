# API de Autenticação

API REST em Express, TypeScript, Prisma e SQLite para cadastro, autenticação e perfil de usuários.

## Executar localmente

```bash
npm install
Copy-Item .env.example .env
npx prisma migrate dev --name init
npm run dev
```

A API inicia em `http://localhost:3000`. A especificação OpenAPI está disponível em `GET /openapi.json`.

## Endpoints

- `POST /auth/register` — corpo: `name`, `email`, `password` (mínimo 8 caracteres).
- `POST /auth/login` — corpo: `email`, `password`.
- `POST /auth/refresh` — corpo: `refreshToken`; rotaciona o token de refresh.
- `POST /auth/logout` — corpo: `refreshToken`; revoga a sessão correspondente.
- `GET /users/me` — requer `Authorization: Bearer <accessToken>`.
- `GET /health` — verificação de disponibilidade.

O login e o cadastro retornam `user`, `accessToken` e `refreshToken`. Não envie refresh tokens em URLs ou logs. Configure `JWT_ACCESS_SECRET` com um segredo aleatório forte fora do desenvolvimento.

## Testes e Docker

```bash
npm test
docker compose up --build
```
