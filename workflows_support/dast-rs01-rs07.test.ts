#!/usr/bin/env node
'use strict';

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

// Configuração
const BASE_URL = (process.env.DAST_BASE_URL || 'http://localhost:3000').replace(/\/+$/, '');
const REPORT_PATH = process.env.DAST_REPORT_PATH || path.join(process.cwd(), 'rs01-rs07-report.json');
const RATE_LIMIT_ATTEMPTS = Number.parseInt(process.env.DAST_RATE_LIMIT_ATTEMPTS || '30', 10);
const RUN_ID = `${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
const results = [];

function newAccount(label) {
  return {
    label,
    email: `dast-${label}-${RUN_ID}@example.invalid`,
    password: `Dast-${crypto.randomBytes(12).toString('hex')}!`,
    created: false,
    registerResponse: null,
    loginResponse: null,
    accessToken: null,
    refreshToken: null
  };
}

const accountA = newAccount('a');
const accountB = newAccount('b');

// Registro de resultados e estados de avaliação.
const outcome = (status, details) => ({ status, details });
const notEvaluated = details => outcome('NOT_EVALUATED', details);
const notApplicable = details => outcome('NOT_APPLICABLE', details);
const ESSENTIAL_TESTS = [
  /Token válido permite acessar \/auth\/me/,
  /Refresh token é rejeitado após logout/,
  /Limitação de tentativas de login/,
  /Login não revela se a conta existe/
];
function isEssentialTest(id, test) {
  return (id === 'RS01' || id === 'RS06' || id === 'PREP') &&
    (ESSENTIAL_TESTS.some(pattern => pattern.test(test)) ||
     (id === 'PREP' && /Criar conta temporária|Autenticar conta temporária/.test(test)));
}
function addResult(id, test, status, details) {
  results.push({ id, test, status, details, essential: isEssentialTest(id, test) });
}
function addNotEvaluated(id, test, details) { addResult(id, test, 'NOT_EVALUATED', details); }
function addNotApplicable(id, test, details) { addResult(id, test, 'NOT_APPLICABLE', details); }

// Executa um teste sem confundir erro de execução com vulnerabilidade confirmada.
async function runTest(id, test, fn) {
  try {
    const result = await fn();
    addResult(id, test, result.status, result.details);
  } catch (error) {
    addResult(id, test, 'INFRA_ERROR', error.message || String(error));
  }
}

async function request(method, route, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  try {
    const headers = { ...(options.headers || {}) };
    let body;
    if (options.rawBody !== undefined) {
      body = options.rawBody;
      headers['Content-Type'] = options.contentType || 'application/json';
    } else if (options.body !== undefined) {
      body = JSON.stringify(options.body);
      headers['Content-Type'] = 'application/json';
    }
    if (options.token) headers.Authorization = `Bearer ${options.token}`;
    if (options.authorization) headers.Authorization = options.authorization;

    const response = await fetch(`${BASE_URL}${route}`, {
      method, headers, body, signal: controller.signal
    });
    const text = await response.text();
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch { /* Resposta não JSON também pode ser analisada. */ }
    return { status: response.status, text, json, headers: response.headers };
  } finally {
    clearTimeout(timer);
  }
}

function tokenFrom(data, names) {
  if (!data || typeof data !== 'object') return null;
  for (const name of names) if (typeof data[name] === 'string' && data[name]) return data[name];
  return tokenFrom(data.data, names) || tokenFrom(data.tokens, names);
}

async function loginWith(email, password) {
  const response = await request('POST', '/auth/login', { body: { email, password } });
  const tokens = isSuccess(response.status) ? {
    accessToken: tokenFrom(response.json, ['accessToken', 'access_token', 'token']),
    refreshToken: tokenFrom(response.json, ['refreshToken', 'refresh_token'])
  } : {};
  return { response, accessToken: tokens.accessToken || null, refreshToken: tokens.refreshToken || null };
}
const loginAs = account => loginWith(account.email, account.password);
const isSuccess = status => status >= 200 && status < 300;
const isRejected = status => [400, 401, 403, 404, 405, 409, 413, 415, 422].includes(status);
const isAuthDenied = status => [401, 403].includes(status);

// A entrada inválida deve receber uma rejeição esperada, não apenas qualquer erro.
function rejectionResult(status, expected = [400, 413, 415, 422]) {
  if (expected.includes(status)) return 'PASS';
  if (isSuccess(status) || status >= 500 || [401, 403, 409].includes(status)) return 'FAIL';
  return isRejected(status) ? 'NOT_EVALUATED' : 'FAIL';
}
function accessResult(status) {
  return isAuthDenied(status) ? 'PASS' : isSuccess(status) || status >= 500 ? 'FAIL' : 'NOT_EVALUATED';
}
function combineResults(statuses) {
  if (statuses.includes('FAIL')) return 'FAIL';
  return statuses.every(status => status === 'PASS') ? 'PASS' : 'NOT_EVALUATED';
}

function registerBody(overrides = {}) {
  return {
    name: 'DAST Test User',
    email: `dast-${crypto.randomBytes(6).toString('hex')}-${RUN_ID}@example.invalid`,
    password: `Dast-${crypto.randomBytes(12).toString('hex')}!`,
    ...overrides
  };
}

function leaksInternalDetails(text) {
  return /stack trace|node_modules|\/app\/|\/home\/|prisma\.|SQLITE_ERROR|SQLITE_[A-Z_]+|DATABASE_URL|JWT_(ACCESS|REFRESH)_SECRET|PrismaClient\w*Error|\bP20\d\d\b|Unique constraint failed|SyntaxError|JsonWebTokenError|TokenExpiredError|jwt malformed|\bat\s+(?:async\s+)?[\w.<>$]+\s+\([^)]*:\d+:\d+\)|\.(?:ts|js):\d+:\d+/i.test(text || '');
}
function exposesFrameworkDefaults(text) {
  return /Cannot (GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) \//.test(text || '');
}

// Considera nomes específicos de credenciais e hashes conhecidos, não chaves genéricas hash/salt.
function hasCredentialKey(value) {
  if (!value || typeof value !== 'object') return false;
  return Object.entries(value).some(([key, item]) =>
    /^(password|passwordHash|password_hash|credential|credentials|refreshTokenHash|refresh_token_hash)$/i.test(key) ||
    hasCredentialKey(item));
}
function exposesCredentials(response, sentPasswords = []) {
  const text = response?.text || '';
  return /\$2[abxy]\$\d{2}\$|\$argon2(id|i|d)\$|\$scrypt\$/i.test(text) ||
    sentPasswords.some(password => password && text.includes(password)) || hasCredentialKey(response?.json);
}
function reflectsPrivilege(value) {
  if (!value || typeof value !== 'object') return false;
  return Object.entries(value).some(([key, item]) => {
    if (/^(role|roles|isAdmin|admin)$/i.test(key) && (item === true || /admin/i.test(JSON.stringify(item)))) return true;
    return reflectsPrivilege(item);
  });
}

// JWT helpers: usados somente para tokens JWT com assinatura HMAC.
function base64Url(value) { return Buffer.from(JSON.stringify(value)).toString('base64url'); }
function readJwtHeader(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return null;
  try { return JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')); } catch { return null; }
}
function tamperSignature(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3 || !parts[2]) return null;
  parts[2] = (parts[2][0] === 'A' ? 'B' : 'A') + parts[2].slice(1);
  return parts.join('.');
}
function forgeUnsignedToken(token) {
  if (!readJwtHeader(token)) return null;
  const parts = token.split('.');
  return `${base64Url({ alg: 'none', typ: 'JWT' })}.${parts[1]}.`;
}
function signWithSecret(token, secret) {
  const header = readJwtHeader(token);
  if (!header || !/^HS(256|384|512)$/.test(header.alg)) return null;
  const parts = token.split('.');
  const signature = crypto.createHmac(`sha${header.alg.slice(2)}`, secret)
    .update(`${parts[0]}.${parts[1]}`).digest('base64url');
  return `${parts[0]}.${parts[1]}.${signature}`;
}
function sendOversizedBody() {
  return request('POST', '/auth/login', {
    rawBody: JSON.stringify({ email: 'a@example.invalid', password: 'A'.repeat(1100000) })
  });
}

const INVALID_PAYLOADS = [
  { route: '/auth/register', label: 'Cadastro sem campos', body: {} },
  { route: '/auth/register', label: 'Cadastro com tipos inválidos', body: { name: { invalid: true }, email: 123, password: ['invalid'] } },
  { route: '/auth/login', label: 'Login sem campos', body: {} },
  { route: '/auth/login', label: 'Login com tipos inválidos', body: { email: null, password: { invalid: true } } },
  { route: '/auth/login', label: 'Login com objeto de filtro no e-mail', body: { email: { contains: '@' }, password: 'Senha-Incorreta-123!' } },
  { route: '/auth/refresh', label: 'Refresh sem campos', body: {} },
  { route: '/auth/refresh', label: 'Refresh com tipo inválido', body: { refreshToken: { invalid: true } } }
];

// Preparação — pré-condições ausentes não são classificadas como falhas de segurança.
async function createTemporaryAccount(account) {
  try {
    account.registerResponse = await request('POST', '/auth/register', {
      body: { name: 'DAST Test User', email: account.email, password: account.password }
    });
    account.created = [200, 201, 202].includes(account.registerResponse.status);
    if (!account.created) addNotEvaluated('PREP', `Criar conta temporária ${account.label.toUpperCase()}`, `Cadastro HTTP ${account.registerResponse.status}.`);
  } catch (error) {
    addResult('PREP', `Criar conta temporária ${account.label.toUpperCase()}`, 'INFRA_ERROR', error.message);
  }
}
async function authenticate(account) {
  if (!account.created) return;
  try {
    const session = await loginAs(account);
    Object.assign(account, { loginResponse: session.response, accessToken: session.accessToken, refreshToken: session.refreshToken });
    if (!account.accessToken || !account.refreshToken) {
      addNotEvaluated('PREP', `Autenticar conta temporária ${account.label.toUpperCase()}`, `Tokens ausentes na resposta de login HTTP ${session.response.status}.`);
    }
  } catch (error) {
    addResult('PREP', `Autenticar conta temporária ${account.label.toUpperCase()}`, 'INFRA_ERROR', error.message);
  }
}

// RS01 — Controle de acesso e autorização
async function testRs01() {
  for (const [label, options] of [
    ['sem token', {}], ['com esquema Basic', { authorization: 'Basic ZGFzdDpkYXN0' }]
  ]) {
    await runTest('RS01', `GET /auth/me ${label} é rejeitado`, async () => {
      const response = await request('GET', '/auth/me', options);
      return outcome(accessResult(response.status), `HTTP ${response.status}; esperado 401 ou 403.`);
    });
  }

  await runTest('RS01', 'Token válido permite acessar /auth/me', async () => {
    if (!accountA.accessToken) return notEvaluated('Conta A não foi autenticada.');
    const response = await request('GET', '/auth/me', { token: accountA.accessToken });
    return outcome(response.status === 200 ? 'PASS' : isAuthDenied(response.status) ? 'FAIL' : 'NOT_EVALUATED',
      `Login HTTP ${accountA.loginResponse.status}; /auth/me HTTP ${response.status}.`);
  });

  await runTest('RS01', 'Cada token retorna apenas os dados do próprio usuário', async () => {
    if (!accountA.accessToken || !accountB.accessToken) return notEvaluated('As contas A e B não foram ambas autenticadas.');
    const [a, b] = await Promise.all([
      request('GET', '/auth/me', { token: accountA.accessToken }),
      request('GET', '/auth/me', { token: accountB.accessToken })
    ]);
    if (a.text.includes(accountB.email) || b.text.includes(accountA.email)) return outcome('FAIL', 'Dados de outra conta apareceram na resposta.');
    if (!a.text.includes(accountA.email) || !b.text.includes(accountB.email)) return notEvaluated('As respostas não permitem confirmar o isolamento entre contas.');
    return outcome('PASS', 'Cada token retornou o e-mail da própria conta, sem o e-mail da outra.');
  });

  for (const test of [
    { name: 'Refresh token não é aceito como token de acesso', token: () => accountA.refreshToken, method: 'GET', route: '/auth/me', body: undefined },
    { name: 'Token de acesso não é aceito como refresh token', token: () => accountA.accessToken, method: 'POST', route: '/auth/refresh', body: token => ({ refreshToken: token }) }
  ]) {
    await runTest('RS01', test.name, async () => {
      const token = test.token();
      if (!token) return notEvaluated('Token necessário não está disponível.');
      const response = await request(test.method, test.route, test.method === 'GET' ? { token } : { body: test.body(token) });
      return outcome(test.method === 'GET' ? accessResult(response.status) : rejectionResult(response.status, [400, 401, 403, 422]), `HTTP ${response.status}.`);
    });
  }

  await runTest('RS01', 'Métodos não previstos em /auth/me são rejeitados', async () => {
    if (!accountA.accessToken) return notEvaluated('Conta A não foi autenticada.');
    const statuses = await Promise.all(['PUT', 'PATCH', 'DELETE'].map(async method => ({ method, status: (await request(method, '/auth/me', { token: accountA.accessToken, body: {} })).status })));
    return outcome(
      combineResults(statuses.map(item => rejectionResult(item.status, [400, 401, 403, 404, 405, 415, 422]))),
      statuses.map(item => `${item.method} HTTP ${item.status}`).join('; ')
    );
  });

  await runTest('RS01', 'Cadastro não concede privilégios enviados pelo cliente', async () => {
    const body = registerBody({ role: 'admin', roles: ['admin'], isAdmin: true, admin: true });
    const register = await request('POST', '/auth/register', { body });
    if (!isSuccess(register.status)) return outcome(rejectionResult(register.status), `Cadastro com campos de privilégio HTTP ${register.status}.`);
    const session = await loginWith(body.email, body.password);
    if (!session.accessToken) return notEvaluated(`Não foi possível autenticar a conta de teste (HTTP ${session.response.status}).`);
    const profile = await request('GET', '/auth/me', { token: session.accessToken });
    if (reflectsPrivilege(register.json) || reflectsPrivilege(profile.json)) return outcome('FAIL', 'Campo de privilégio elevado apareceu nas respostas.');
    return outcome('PASS', `Cadastro HTTP ${register.status}; privilégio elevado não foi refletido em /auth/me (HTTP ${profile.status}). A atribuição silenciosa não é observável via HTTP se a API não expõe papéis.`);
  });

  addNotApplicable('RS01', 'IDOR em recursos de outros usuários', 'A API não possui recurso de negócio pertencente a usuários; o isolamento é verificado em /auth/me. Confirmar a especificação OpenAPI.');
}

// RS02 — Configuração segura da aplicação
async function testRs02() {
  await runTest('RS02', 'Health check não expõe detalhes internos', async () => {
    const response = await request('GET', '/health');
    if (response.status === 404) return notEvaluated('A rota /health não existe.');
    const leaked = leaksInternalDetails(response.text);
    return outcome(leaked ? 'FAIL' : 'PASS', `HTTP ${response.status}; detalhes internos ${leaked ? 'detectados' : 'não detectados'}.`);
  });

  await runTest('RS02', 'Cabeçalhos de segurança e divulgação de tecnologia', async () => {
    const routes = ['/health', '/auth/me', `/rota-inexistente-${RUN_ID}`];
    const issues = [];
    for (const route of routes) {
      const response = await request('GET', route);
      const poweredBy = response.headers.get('x-powered-by');
      const server = response.headers.get('server');
      if (poweredBy) issues.push(`${route}: X-Powered-By=${poweredBy}`);
      if (server && /\d+\.\d+/.test(server)) issues.push(`${route}: Server=${server}`);
      if (response.headers.get('x-content-type-options')?.toLowerCase() !== 'nosniff') issues.push(`${route}: X-Content-Type-Options ausente/incorreto`);
    }
    // CORS * é registrado apenas como contexto; não é falha automática sem avaliar credenciais e uso.
    const cors = await request('OPTIONS', '/auth/login', { headers: { Origin: 'https://dast.example.invalid', 'Access-Control-Request-Method': 'POST' } });
    const origin = cors.headers.get('access-control-allow-origin');
    const credentials = cors.headers.get('access-control-allow-credentials');
    if (origin === '*' && credentials?.toLowerCase() === 'true') issues.push('CORS combina origem * com credenciais');
    return outcome(issues.length ? 'FAIL' : 'PASS', issues.length ? issues.join('; ') : `Cabeçalhos avaliados; CORS allow-origin=${origin || 'ausente'}, allow-credentials=${credentials || 'ausente'}. Origem * isolada não foi considerada vulnerabilidade.`);
  });

  await runTest('RS02', 'Arquivos sensíveis e rotas de depuração não são servidos', async () => {
    const paths = ['/.env', '/.git/config', '/package.json', '/prisma/schema.prisma', '/prisma/dev.db', '/dev.db', '/debug', '/console'];
    const served = [];
    for (const target of paths) {
      const response = await request('GET', target);
      if (isSuccess(response.status)) served.push(`${target} (HTTP ${response.status})`);
    }
    return outcome(served.length ? 'FAIL' : 'PASS', served.length ? `Respostas de sucesso: ${served.join(', ')}.` : `Nenhum dos ${paths.length} caminhos retornou sucesso.`);
  });

  await runTest('RS02', 'Token assinado com segredos comuns não é aceito', async () => {
    if (!accountA.accessToken) return notEvaluated('Conta A não foi autenticada.');
    const candidates = ['secret', 'changeme', 'change-me', 'jwt_secret', 'jwt-secret', 'your-secret-key', 'supersecret', 'dev-secret', 'default', 'password', '123456'];
    let signable = false;
    const accepted = [];
    for (const secret of candidates) {
      const forged = signWithSecret(accountA.accessToken, secret);
      if (!forged) break;
      signable = true;
      if ((await request('GET', '/auth/me', { token: forged })).status === 200) accepted.push(secret);
    }
    if (!signable) return notApplicable('Token não é JWT assinado com HMAC HS256, HS384 ou HS512.');
    return outcome(accepted.length ? 'FAIL' : 'PASS', accepted.length ? `Segredo previsível aceito: ${accepted.join(', ')}.` : `Nenhum dos ${candidates.length} segredos foi aceito; isso não prova que o segredo é forte.`);
  });

  addNotEvaluated('RS02', 'Segredos fixos no código-fonte', 'Não observável via HTTP; depende de SAST e inspeção do código/configuração.');
}

// RS04 — Gerenciamento seguro de credenciais
async function testRs04() {
  const marker = () => `Secret-${crypto.randomBytes(8).toString('hex')}`;
  for (const test of [
    { name: 'Resposta de cadastro inválido não ecoa senha', run: async secret => request('POST', '/auth/register', { body: { name: { invalid: true }, email: 'email-invalido', password: secret } }) },
    { name: 'Resposta de login inválido não ecoa senha', run: async secret => request('POST', '/auth/login', { body: { email: accountA.created ? accountA.email : `ausente-${RUN_ID}@example.invalid`, password: secret } }) }
  ]) {
    await runTest('RS04', test.name, async () => {
      const secret = marker();
      const response = await test.run(secret);
      const leaked = response.text.includes(secret);
      return outcome(leaked ? 'FAIL' : 'PASS', `HTTP ${response.status}; senha sentinela ${leaked ? 'exposta' : 'não encontrada'}.`);
    });
  }

  for (const test of [
    { name: 'Resposta de cadastro válido não expõe credenciais', response: () => accountA.registerResponse },
    { name: 'Resposta de login válido não expõe credenciais', response: () => accountA.loginResponse }
  ]) {
    await runTest('RS04', test.name, async () => {
      const response = test.response();
      if (!response) return notEvaluated('Resposta de preparação não disponível.');
      const exposed = exposesCredentials(response, [accountA.password]);
      return outcome(exposed ? 'FAIL' : 'PASS', `HTTP ${response.status}; campos/padrões específicos de credenciais ${exposed ? 'detectados' : 'não detectados'}.`);
    });
  }

  await runTest('RS04', 'Resposta de /auth/me não expõe credenciais', async () => {
    if (!accountA.accessToken) return notEvaluated('Conta A não foi autenticada.');
    const response = await request('GET', '/auth/me', { token: accountA.accessToken });
    const exposed = exposesCredentials(response, [accountA.password]);
    return outcome(exposed ? 'FAIL' : 'PASS', `HTTP ${response.status}; credenciais ${exposed ? 'detectadas' : 'não detectadas'}.`);
  });

  addNotEvaluated('RS04', 'Senha armazenada com hashing apropriado', 'Não observável via HTTP; exige inspeção do código e do banco SQLite.');
}

// RS05 — Validação de entrada
async function testRs05() {
  const cases = [
    ...INVALID_PAYLOADS.map(test => ({ ...test, expected: [400, 415, 422] })),
    { route: '/auth/register', label: 'Cadastro com senha vazia', body: registerBody({ password: '' }), expected: [400, 422] },
    { route: '/auth/register', label: 'Cadastro com senha de 1 caractere', body: registerBody({ password: '1' }), expected: [400, 422] },
    { route: '/auth/register', label: 'Cadastro com senha de 10.000 caracteres', body: registerBody({ password: 'A'.repeat(10000) }), expected: [400, 413, 422] },
    { route: '/auth/register', label: 'Cadastro com e-mail de 10.000 caracteres', body: registerBody({ email: `${'a'.repeat(10000)}@example.invalid` }), expected: [400, 413, 422] },
    { route: '/auth/register', label: 'Cadastro com nome de 10.000 caracteres', body: registerBody({ name: 'A'.repeat(10000) }), expected: [400, 413, 422] }
  ];
  for (const test of cases) {
    await runTest('RS05', `${test.label} é rejeitado`, async () => {
      const response = await request('POST', test.route, { body: test.body });
      return outcome(rejectionResult(response.status, test.expected), `HTTP ${response.status}; esperados: ${test.expected.join(', ')}.`);
    });
  }

  await runTest('RS05', 'Login com Content-Type text/plain não é aceito', async () => {
    if (!accountA.created) return notEvaluated('Conta A não foi criada.');
    const response = await request('POST', '/auth/login', { rawBody: JSON.stringify({ email: accountA.email, password: accountA.password }), contentType: 'text/plain' });
    return outcome(rejectionResult(response.status, [400, 415, 422]), `HTTP ${response.status}; esperado 400, 415 ou 422.`);
  });
  await runTest('RS05', 'JSON malformado é rejeitado', async () => {
    const response = await request('POST', '/auth/login', { rawBody: '{"email": "x", "password":' });
    return outcome(rejectionResult(response.status, [400, 415, 422]), `HTTP ${response.status}; esperado 400, 415 ou 422.`);
  });
  await runTest('RS05', 'Corpo acima do limite é rejeitado', async () => {
    const response = await sendOversizedBody();
    return outcome(rejectionResult(response.status, [400, 413, 422]), `HTTP ${response.status}; corpo de aproximadamente 1,1 MB; esperado rejeição por tamanho.`);
  });
}

// RS06 — Autenticação, sessão, enumeração e limitação de tentativas
async function testRs06() {
  const tokenCases = [
    { name: 'Token inválido é rejeitado', token: () => 'token.invalido' },
    { name: 'Token com assinatura adulterada é rejeitado', token: () => accountA.accessToken ? tamperSignature(accountA.accessToken) : null },
    { name: 'Token sem assinatura (alg none) é rejeitado', token: () => accountA.accessToken ? forgeUnsignedToken(accountA.accessToken) : null }
  ];
  for (const test of tokenCases) {
    await runTest('RS06', test.name, async () => {
      const token = test.token();
      if (!token) return accountA.accessToken ? notApplicable('Token não possui formato JWT esperado.') : notEvaluated('Conta A não foi autenticada.');
      const response = await request('GET', '/auth/me', { token });
      return outcome(accessResult(response.status), `HTTP ${response.status}; esperado 401 ou 403.`);
    });
  }

  for (const test of [
    { name: 'Login com conta inexistente é rejeitado', get: () => ({ email: `ausente-${RUN_ID}@example.invalid`, password: 'Senha-Incorreta-123!' }) },
    { name: 'Login com senha incorreta é rejeitado', get: () => ({ email: accountA.email, password: `Errada-${crypto.randomBytes(6).toString('hex')}!` }), needsAccount: true }
  ]) {
    await runTest('RS06', test.name, async () => {
      if (test.needsAccount && !accountA.created) return notEvaluated('Conta A não foi criada.');
      const response = await request('POST', '/auth/login', { body: test.get() });
      return outcome(rejectionResult(response.status, [400, 401, 403, 422]), `HTTP ${response.status}; esperado rejeição de autenticação.`);
    });
  }

  await runTest('RS06', 'Login não revela se a conta existe', async () => {
    if (!accountA.created) return notEvaluated('Conta A não foi criada.');
    const [known, unknown] = await Promise.all([
      request('POST', '/auth/login', { body: { email: accountA.email, password: `Errada-${crypto.randomBytes(6).toString('hex')}!` } }),
      request('POST', '/auth/login', { body: { email: `outra-${RUN_ID}@example.invalid`, password: `Errada-${crypto.randomBytes(6).toString('hex')}!` } })
    ]);
    if (known.status === 429 || unknown.status === 429) return notEvaluated('Rate limit HTTP 429 interferiu na comparação.');
    const normalize = (text, email) => String(text || '').replaceAll(email, '<email>');
    const equal = known.status === unknown.status && normalize(known.text, accountA.email) === normalize(unknown.text, `outra-${RUN_ID}@example.invalid`);
    return outcome(equal ? 'PASS' : 'FAIL', `Conta existente HTTP ${known.status}; inexistente HTTP ${unknown.status}; respostas ${equal ? 'iguais' : 'diferentes'}. Tempo de resposta não avaliado.`);
  });

  await runTest('RS06', 'Refresh token inválido é rejeitado', async () => {
    const response = await request('POST', '/auth/refresh', { body: { refreshToken: `invalido-${RUN_ID}` } });
    return outcome(rejectionResult(response.status, [400, 401, 403, 422]), `HTTP ${response.status}.`);
  });

  await runTest('RS06', 'Refresh token anterior é rejeitado após renovação', async () => {
    if (!accountA.created) return notEvaluated('Conta A não foi criada.');
    const session = await loginAs(accountA);
    if (!session.refreshToken) return notEvaluated(`Refresh token ausente; login HTTP ${session.response.status}.`);
    const first = await request('POST', '/auth/refresh', { body: { refreshToken: session.refreshToken } });
    if (!isSuccess(first.status)) return notEvaluated(`Renovação inicial HTTP ${first.status}; fluxo esperado não observado.`);
    const reuse = await request('POST', '/auth/refresh', { body: { refreshToken: session.refreshToken } });
    return outcome(rejectionResult(reuse.status, [400, 401, 403, 422]), `Renovação HTTP ${first.status}; reutilização HTTP ${reuse.status}. Interpretar conforme o design da API.`);
  });

  await runTest('RS06', 'Refresh token é rejeitado após logout', async () => {
    if (!accountA.created) return notEvaluated('Conta A não foi criada.');
    const session = await loginAs(accountA);
    if (!session.accessToken || !session.refreshToken) return notEvaluated(`Tokens ausentes; login HTTP ${session.response.status}.`);
    const logout = await request('POST', '/auth/logout', { token: session.accessToken, body: { refreshToken: session.refreshToken } });
    if (!isSuccess(logout.status)) return notEvaluated(`Logout não concluído: HTTP ${logout.status}.`);
    const refresh = await request('POST', '/auth/refresh', { body: { refreshToken: session.refreshToken } });
    return outcome(rejectionResult(refresh.status, [400, 401, 403, 422]), `Logout HTTP ${logout.status}; refresh posterior HTTP ${refresh.status}.`);
  });
}

// RS06 — Executado por último porque o bloqueio pode afetar os demais testes.
async function testRateLimiting() {
  await runTest('RS06', 'Limitação de tentativas de login', async () => {
    const email = accountA.created ? accountA.email : `ausente-${RUN_ID}@example.invalid`;
    const counts = {};
    let blockedAt = null;
    for (let attempt = 1; attempt <= RATE_LIMIT_ATTEMPTS; attempt++) {
      const response = await request('POST', '/auth/login', { body: { email, password: `Errada-${attempt}-${crypto.randomBytes(4).toString('hex')}!` } });
      counts[response.status] = (counts[response.status] || 0) + 1;
      if ([423, 429].includes(response.status)) { blockedAt = attempt; break; }
    }
    const summary = Object.entries(counts).map(([status, count]) => `HTTP ${status}: ${count}`).join('; ');
    return outcome(blockedAt ? 'PASS' : 'FAIL', blockedAt
      ? `Bloqueio observado na tentativa ${blockedAt}; ${summary}.`
      : `Nenhum bloqueio HTTP 423/429 em ${RATE_LIMIT_ATTEMPTS} tentativas; ${summary}. Não distingue limite acima do configurado de ausência de limite.`);
  });
}

// RS07 — Tratamento seguro de erros
async function testRs07() {
  const scenarios = [
    { name: 'Erro de login', run: () => request('POST', '/auth/login', { body: { email: `ausente-${RUN_ID}@example.invalid`, password: 'Senha-Incorreta-123!' } }) },
    ...INVALID_PAYLOADS.map(test => ({ name: test.label, run: () => request('POST', test.route, { body: test.body }) })),
    { name: 'JSON malformado', run: () => request('POST', '/auth/login', { rawBody: '{"email": "x", "password":' }) },
    { name: 'Corpo acima do limite', run: sendOversizedBody },
    { name: 'Rota inexistente', run: () => request('GET', `/rota-inexistente-${RUN_ID}`), framework: true }
  ];
  for (const test of scenarios) {
    await runTest('RS07', `${test.name} não revela detalhes internos`, async () => {
      const response = await test.run();
      const leaked = leaksInternalDetails(response.text) || (test.framework && exposesFrameworkDefaults(response.text));
      const unexpectedServerError = response.status >= 500;
      return outcome(leaked || unexpectedServerError ? 'FAIL' : 'PASS', `HTTP ${response.status}; detalhes internos ${leaked ? 'detectados' : 'não detectados'}${unexpectedServerError ? '; erro HTTP 5xx inesperado' : ''}.`);
    });
  }

  await runTest('RS07', 'Cadastro duplicado não revela detalhes internos nem retorna 5xx', async () => {
    if (!accountA.created) return notEvaluated('Conta A não foi criada.');
    const response = await request('POST', '/auth/register', { body: { name: 'DAST Test User', email: accountA.email, password: accountA.password } });
    if (response.status === 429) return notEvaluated('Rate limit HTTP 429 interferiu no teste.');
    const leaked = leaksInternalDetails(response.text);
    return outcome(leaked || response.status >= 500 ? 'FAIL' : 'PASS', `HTTP ${response.status}; detalhes internos ${leaked ? 'detectados' : 'não detectados'}.`);
  });

  await runTest('RS07', 'Token inválido não revela detalhes internos nem retorna 5xx', async () => {
    const tokens = ['token.invalido', 'a.b.c'];
    const forged = accountA.accessToken && tamperSignature(accountA.accessToken);
    if (forged) tokens.push(forged);
    const problems = [];
    for (const token of tokens) {
      const response = await request('GET', '/auth/me', { token });
      if (leaksInternalDetails(response.text) || response.status >= 500) problems.push(`HTTP ${response.status}`);
    }
    return outcome(problems.length ? 'FAIL' : 'PASS', problems.length ? `Respostas problemáticas: ${problems.join(', ')}.` : `Sem detalhes internos/5xx em ${tokens.length} respostas.`);
  });
}

// RS03 é avaliada por SCA (npm audit), não por estes testes DAST.
async function main() {
  await createTemporaryAccount(accountA);
  await createTemporaryAccount(accountB);
  await authenticate(accountA);
  await authenticate(accountB);
  await testRs01();
  await testRs02();
  await testRs04();
  await testRs05();
  await testRs06();
  await testRs07();
  await testRateLimiting();
  writeReport();
}

function buildSummary() {
  const count = status => results.filter(result => result.status === status).length;
  const essentialNotEvaluated = results.filter(result =>
    result.essential && result.status === 'NOT_EVALUATED'
  ).length;
  return {
    passed: count('PASS'), failed: count('FAIL'),
    notEvaluated: count('NOT_EVALUATED'), notApplicable: count('NOT_APPLICABLE'),
    infrastructureErrors: count('INFRA_ERROR'), essentialNotEvaluated
  };
}
function sortedResults() { return [...results].sort((a, b) => a.id.localeCompare(b.id)); }
function writeReport() {
  const summary = buildSummary();
  const report = { generatedAt: new Date().toISOString(), baseUrl: BASE_URL, summary, results: sortedResults() };
  fs.mkdirSync(path.dirname(REPORT_PATH), { recursive: true });
  fs.writeFileSync(REPORT_PATH, JSON.stringify(report, null, 2));
  console.log(JSON.stringify(summary, null, 2));
  console.log(`Relatório salvo: ${REPORT_PATH}`);
  // Testes essenciais não avaliados impedem um resultado aparentemente aprovado.
  process.exitCode = summary.failed || summary.infrastructureErrors || summary.essentialNotEvaluated ? 1 : 0;
}

main().catch(error => {
  const report = {
    generatedAt: new Date().toISOString(), baseUrl: BASE_URL,
    summary: { ...buildSummary(), fatalErrors: 1 }, error: error.message,
    results: sortedResults()
  };
  try {
    fs.mkdirSync(path.dirname(REPORT_PATH), { recursive: true });
    fs.writeFileSync(REPORT_PATH, JSON.stringify(report, null, 2));
  } catch (writeError) {
    console.error(`Não foi possível salvar o relatório: ${writeError.message}`);
  }
  console.error(error);
  process.exitCode = 2;
});
