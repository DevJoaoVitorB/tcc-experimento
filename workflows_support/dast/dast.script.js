/*
 * Testes DAST complementares específicos da API de autenticação.
 *
 * FINALIDADE
 * Executa somente verificações comportamentais que a varredura padrão do
 * OWASP ZAP não garante cobrir, principalmente falhas lógicas de autorização,
 * confusão entre tipos de token, ciclo de vida de refresh token e exposição
 * de credenciais nas respostas.
 *
 * O ZAP padrão continua responsável por suas regras de análise passiva e ativa
 * (por exemplo, injeções, parâmetros, cabeçalhos e erros conhecidos). Este
 * script NÃO tenta reproduzir essas verificações genéricas.
 *
 * JUSTIFICATIVA OFICIAL
 * A documentação do ZAP afirma que a análise ativa encontra apenas certos tipos
 * de vulnerabilidade e não detecta falhas lógicas como broken access control:
 * https://www.zaproxy.org/docs/desktop/start/features/ascan/
 * https://www.zaproxy.org/docs/desktop/start/features/scanpolicy/
 *
 * A especificação OpenAPI deve ser importada pelo plano de automação antes do
 * Active Scan. O script é um Active Scan Script e usa o ciclo scan(helper,msg,
 * param,value) documentado pelo ZAP:
 * https://www.zaproxy.org/docs/desktop/addons/script-console/scanrules/
 *
 * ESCOPO / LIMITAÇÕES
 * - Pressupõe POST /auth/register, POST /auth/login, POST /auth/refresh,
 *   POST /auth/logout e GET /users/me.
 * - Cria contas temporárias com e-mails @example.invalid. Use apenas no ambiente
 *   de teste isolado e autorizado.
 * - Não tenta adivinhar endpoints de recursos de negócio. IDOR em recursos
 *   específicos só pode ser testado quando seus endpoints/IDs estiverem
 *   definidos; não é correto inferi-los.
 * - Não testa rate limiting para evitar bloqueio/ruído na varredura padrão.
 * - PASS e NOT_EVALUATED são registrados no log; somente falhas explícitas
 *   levantam alertas ZAP. Ausência de pré-condições resulta em NOT_EVALUATED.
 * - O script roda uma vez por instância do ZAP, no primeiro request que aciona
 *   o Active Scan, para evitar repetir a suíte em cada payload da varredura.
 */

const URI = Java.type('org.apache.commons.httpclient.URI');
const UUID = Java.type('java.util.UUID');
const System = Java.type('java.lang.System');
const ScanRuleMetadata = Java.type(
    'org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata'
);

var suiteExecuted = false;

function getMetadata() {
    return ScanRuleMetadata.fromYaml(`
id: 110900
name: Testes comportamentais extras - API de autenticação
description: Verifica falhas lógicas de autorização, confusão de tokens, invalidação de refresh token e exposição de credenciais que não são garantidas pela varredura padrão.
solution: Aplique autorização no servidor, separe access e refresh tokens, invalide sessões quando necessário e nunca exponha senhas, hashes ou tokens internos em respostas.
reference: https://www.zaproxy.org/docs/desktop/start/features/ascan/
risk: MEDIUM
confidence: MEDIUM
cweId: 862
wascId: 0
    `);
}

function scan(helper, msg, param, value) {
    if (suiteExecuted) return;
    suiteExecuted = true;

    try {
        runSuite(helper, msg, getBaseUrl(msg));
    } catch (e) {
        print('[DAST-EXTRA] INFRA_ERROR: ' + String(e));
    }
}

function getBaseUrl(msg) {
    var configured = String(System.getenv('DAST_BASE_URL') || '').replace(/\/+$/, '');
    if (configured) return configured;

    var u = msg.getRequestHeader().getURI();
    var scheme = String(u.getScheme());
    var port = Number(u.getPort());
    return scheme + '://' + String(u.getHost()) +
        (port > 0 && port !== (scheme === 'https' ? 443 : 80) ? ':' + port : '');
}

function rand() {
    return String(UUID.randomUUID()).replace(/-/g, '');
}

function parseJson(text) {
    try { return text ? JSON.parse(text) : null; } catch (_) { return null; }
}

function tokenFrom(data, names) {
    if (!data || typeof data !== 'object') return null;
    for (var i = 0; i < names.length; i++) {
        if (typeof data[names[i]] === 'string' && data[names[i]]) return data[names[i]];
    }
    return tokenFrom(data.data, names) || tokenFrom(data.tokens, names);
}

function send(helper, original, base, method, route, options) {
    options = options || {};
    var message = original.cloneRequest();
    var target = new URI(base + route, false);

    message.getRequestHeader().setMethod(method);
    message.getRequestHeader().setURI(target);
    message.getRequestHeader().setHeader('Host',
        target.getHost() + (target.getPort() > 0 ? ':' + target.getPort() : ''));
    message.getRequestHeader().setHeader('Authorization', '');

    if (options.token) {
        message.getRequestHeader().setHeader('Authorization', 'Bearer ' + options.token);
    } else if (options.authorization) {
        message.getRequestHeader().setHeader('Authorization', options.authorization);
    }

    var body = options.rawBody !== undefined ? options.rawBody :
        (options.body !== undefined ? JSON.stringify(options.body) : '');
    message.setRequestBody(body);
    message.getRequestHeader().setHeader('Content-Length', String(body.length));

    if (options.body !== undefined || options.rawBody !== undefined) {
        message.getRequestHeader().setHeader('Content-Type',
            options.contentType || 'application/json');
    }

    helper.sendAndReceive(message, false, false);
    var text = String(message.getResponseBody().toString());
    return {
        status: Number(message.getResponseHeader().getStatusCode()),
        text: text,
        json: parseJson(text),
        message: message
    };
}

function is2xx(status) { return status >= 200 && status < 300; }
function isRejected(status) {
    return [400, 401, 403, 404, 405, 409, 415, 422].indexOf(status) >= 0;
}

function finding(helper, response, testName, detail, risk, evidence) {
    print('[DAST-EXTRA] ' + testName + ' => FAIL; ' + detail);
    helper.newAlert()
        .setRisk(risk || 2)
        .setConfidence(2)
        .setName('DAST extra - ' + testName)
        .setDescription(detail)
        .setUri(String(response.message.getRequestHeader().getURI().toString()))
        .setParam(testName)
        .setEvidence(evidence || ('HTTP ' + response.status))
        .setOtherInfo('Teste complementar comportamental. Revise a evidência e confirme o impacto antes de classificar como vulnerabilidade confirmada.')
        .setSolution('Valide autenticação e autorização no servidor; diferencie access tokens de refresh tokens; invalide refresh tokens após logout/rotação; remova credenciais e hashes das respostas.')
        .setReference('https://www.zaproxy.org/docs/desktop/start/features/ascan/')
        .setCweId(862)
        .setMessage(response.message)
        .raise();
}

function result(name, status, passed, detail) {
    print('[DAST-EXTRA] ' + name + ' => ' +
        (passed ? 'PASS' : 'NOT_EVALUATED') + '; HTTP ' + status + '; ' + detail);
}

function checkRejected(helper, response, name, detail) {
    if (isRejected(response.status)) {
        result(name, response.status, true, detail);
    } else if (is2xx(response.status)) {
        finding(helper, response, name,
            detail + ' A API aceitou a requisição que deveria ser recusada.',
            2, 'HTTP ' + response.status);
    } else {
        result(name, response.status, false,
            detail + ' Resposta inconclusiva; não classificada automaticamente como vulnerabilidade.');
    }
}

function registerAccount(helper, original, base, label) {
    var a = {
        email: 'dast-extra-' + label + '-' + rand() + '@example.invalid',
        password: 'Dast-' + rand() + '!',
        created: false,
        access: null,
        refresh: null
    };
    var reg = send(helper, original, base, 'POST', '/auth/register', {
        body: { name: 'DAST Extra User ' + label, email: a.email, password: a.password }
    });
    a.created = [200, 201, 202].indexOf(reg.status) >= 0;
    print('[DAST-EXTRA][PREP] cadastro ' + label + ': HTTP ' + reg.status);
    if (!a.created) return a;

    var login = send(helper, original, base, 'POST', '/auth/login', {
        body: { email: a.email, password: a.password }
    });
    if (is2xx(login.status)) {
        a.access = tokenFrom(login.json, ['accessToken', 'access_token', 'token']);
        a.refresh = tokenFrom(login.json, ['refreshToken', 'refresh_token']);
    }
    print('[DAST-EXTRA][PREP] login ' + label + ': HTTP ' + login.status +
        '; access=' + Boolean(a.access) + '; refresh=' + Boolean(a.refresh));
    return a;
}

function containsCredentialLeak(response, password) {
    var text = response.text || '';
    if (password && text.indexOf(password) >= 0) return 'senha sentinela refletida';
    var data = response.json;
    if (!data || typeof data !== 'object') return null;

    function walk(obj, path) {
        if (!obj || typeof obj !== 'object') return null;
        for (var k in obj) {
            if (!Object.prototype.hasOwnProperty.call(obj, k)) continue;
            var key = String(k).toLowerCase();
            var val = obj[k];
            // A presença de accessToken/refreshToken pode ser parte legítima do
            // contrato de login. Não sinalizamos tokens de sessão genericamente.
            if (/^(password|passwd|passwordhash|password_hash|hashedpassword|password_digest|credentialhash|credential_hash)$/.test(key)) {
                if (val !== null && val !== '' && val !== false) return path + k;
            }
            if (val && typeof val === 'object') {
                var nested = walk(val, path + k + '.');
                if (nested) return nested;
            }
        }
        return null;
    }
    return walk(data, '');
}

function checkNoCredentialLeak(helper, response, name, password) {
    var leak = containsCredentialLeak(response, password);
    if (leak) {
        finding(helper, response, name,
            'A resposta contém a senha enviada ou um campo de senha/hash não vazio (' + leak + ').',
            3, leak);
    } else {
        result(name, response.status, true,
            'Nenhuma senha sentinela ou campo explícito de senha/hash foi detectado; isso não prova segurança do armazenamento.');
    }
}

function runSuite(helper, original, base) {
    print('[DAST-EXTRA] Início da suíte complementar em ' + base);

    /*
     * EXTRA 1 — Acesso sem autenticação.
     * O scanner padrão não garante detectar falhas lógicas de controle de
     * acesso; esta checagem confirma o comportamento esperado da rota conhecida.
     */
    var anonymous = send(helper, original, base, 'GET', '/users/me', {});
    checkRejected(helper, anonymous, 'GET /users/me sem autenticação',
        'O perfil deve exigir autenticação.');

    var a = registerAccount(helper, original, base, 'a');
    var b = registerAccount(helper, original, base, 'b');

    /*
     * EXTRA 2 — Isolamento entre identidades.
     * /users/me é uma rota própria, portanto não substitui testes IDOR de
     * recursos de negócio. Para testar IDOR, o projeto precisa declarar um
     * endpoint/identificador de recurso pertencente a outro usuário.
     */
    if (a.access && b.access) {
        var pa = send(helper, original, base, 'GET', '/users/me', { token: a.access });
        var pb = send(helper, original, base, 'GET', '/users/me', { token: b.access });
        var identityA = pa.text.indexOf(a.email) >= 0 && pa.text.indexOf(b.email) < 0;
        var identityB = pb.text.indexOf(b.email) >= 0 && pb.text.indexOf(a.email) < 0;

        if (identityA && identityB) {
            result('Isolamento dos perfis A/B', 200, true,
                'Cada resposta contém o próprio e-mail e não o e-mail da outra conta.');
        } else if (is2xx(pa.status) && is2xx(pb.status) &&
                   (pa.text.indexOf(b.email) >= 0 || pb.text.indexOf(a.email) >= 0)) {
            finding(helper, pb, 'Isolamento dos perfis A/B',
                'Uma resposta de perfil parece conter a identidade da outra conta.',
                3, 'Possível exposição cruzada de e-mail entre contas');
        } else {
            result('Isolamento dos perfis A/B', pa.status, false,
                'Não foi possível confirmar o formato de identidade nas respostas; revisão manual necessária.');
        }
    } else {
        print('[DAST-EXTRA] Isolamento dos perfis A/B => NOT_EVALUATED; duas contas/tokens não disponíveis.');
    }

    /*
     * EXTRA 3 — Confusão entre access token e refresh token.
     * O ZAP testa tokens e autenticação em vários casos, mas a separação entre
     * finalidades de tokens é uma regra de negócio específica da API.
     */
    if (a.refresh) {
        var refreshAsAccess = send(helper, original, base, 'GET', '/users/me', { token: a.refresh });
        checkRejected(helper, refreshAsAccess, 'Refresh token usado como access token',
            'Um refresh token não deve autorizar acesso a recursos protegidos.');
    } else {
        print('[DAST-EXTRA] Refresh token usado como access token => NOT_EVALUATED; refresh token ausente.');
    }

    if (a.access) {
        var accessAsRefresh = send(helper, original, base, 'POST', '/auth/refresh', {
            body: { refreshToken: a.access }
        });
        checkRejected(helper, accessAsRefresh, 'Access token usado como refresh token',
            'Um access token não deve ser aceito como credencial de renovação.');
    } else {
        print('[DAST-EXTRA] Access token usado como refresh token => NOT_EVALUATED; access token ausente.');
    }

    /*
     * EXTRA 4 — Rotação e logout de refresh token.
     * A reutilização após rotação e o uso após logout verificam o ciclo de vida
     * da sessão; não são garantidos por uma varredura genérica de payloads.
     */
    if (a.created) {
        var session = send(helper, original, base, 'POST', '/auth/login', {
            body: { email: a.email, password: a.password }
        });
        var refresh = tokenFrom(session.json, ['refreshToken', 'refresh_token']);
        var access = tokenFrom(session.json, ['accessToken', 'access_token', 'token']);

        if (refresh) {
            var rotated = send(helper, original, base, 'POST', '/auth/refresh', {
                body: { refreshToken: refresh }
            });
            if (is2xx(rotated.status)) {
                var reused = send(helper, original, base, 'POST', '/auth/refresh', {
                    body: { refreshToken: refresh }
                });
                checkRejected(helper, reused, 'Reutilização de refresh token após rotação',
                    'Se a API implementa rotação, o token anterior deve ser invalidado.');
            } else {
                result('Reutilização de refresh token após rotação', rotated.status, false,
                    'A renovação inicial não funcionou; teste de rotação não avaliado.');
            }

            // Usa uma sessão nova e separada para que o teste de logout não
            // seja contaminado pelo teste anterior de rotação.
            var logoutSession = send(helper, original, base, 'POST', '/auth/login', {
                body: { email: a.email, password: a.password }
            });
            var logoutAccess = tokenFrom(logoutSession.json, ['accessToken', 'access_token', 'token']);
            var logoutRefresh = tokenFrom(logoutSession.json, ['refreshToken', 'refresh_token']);

            if (logoutAccess && logoutRefresh) {
                var logout = send(helper, original, base, 'POST', '/auth/logout', {
                    token: logoutAccess, body: { refreshToken: logoutRefresh }
                });
                if (is2xx(logout.status)) {
                    var afterLogout = send(helper, original, base, 'POST', '/auth/refresh', {
                        body: { refreshToken: logoutRefresh }
                    });
                    checkRejected(helper, afterLogout, 'Refresh token após logout',
                        'Após logout bem-sucedido, o refresh token revogado não deve renovar a sessão.');
                } else {
                    result('Refresh token após logout', logout.status, false,
                        'Logout não confirmou sucesso; invalidação não avaliada. Verifique o contrato da API.');
                }
            } else {
                print('[DAST-EXTRA] Refresh token após logout => NOT_EVALUATED; tokens da sessão de logout ausentes.');
            }
        } else {
            print('[DAST-EXTRA] Rotação/logout de refresh token => NOT_EVALUATED; refresh token ausente.');
        }
    }

    /*
     * EXTRA 5 — Exposição de credenciais nas respostas.
     * O ZAP tem regras genéricas de exposição de informação, mas não conhece
     * necessariamente o contrato de resposta e os campos de senha/hash desta
     * API. Tokens de sessão são permitidos no login quando fazem parte do contrato.
     */
    var credentialSentinel = 'Sentinel-' + rand() + '!';
    var regCheck = send(helper, original, base, 'POST', '/auth/register', {
        body: { name: 'DAST Credential Check', email: 'dast-cred-' + rand() + '@example.invalid',
                password: credentialSentinel }
    });
    // A senha sentinela é comparada literalmente para detectar reflexão indevida.
    var loginInvalid = send(helper, original, base, 'POST', '/auth/login', {
        body: { email: 'missing-' + rand() + '@example.invalid', password: 'Sentinel-' + rand() + '!' }
    });
    checkNoCredentialLeak(helper, regCheck, 'Cadastro não expõe senha/hash', credentialSentinel);
    checkNoCredentialLeak(helper, loginInvalid, 'Login inválido não expõe senha/hash', null);

    if (a.access) {
        var profile = send(helper, original, base, 'GET', '/users/me', { token: a.access });
        checkNoCredentialLeak(helper, profile, 'Perfil não expõe senha/hash', a.password);
    }

    print('[DAST-EXTRA] Fim da suíte complementar.');
}
