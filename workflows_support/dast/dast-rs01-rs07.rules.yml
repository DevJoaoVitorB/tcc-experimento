/*
 * RS06 — Autenticação e gerenciamento de sessão
 * OWASP ZAP Active Scan Script
 *
 * Base: testRs06() de dast-rs01-rs07.test.ts
 *
 * Requer:
 *   DAST_BASE_URL=http://localhost:3000
 *
 * Observação:
 *   O script é disparado quando o Active Scan alcança /auth/login.
 *   Os cenários de rate limiting devem ser executados separadamente
 *   e por último, conforme o experimento original.
 */

const URI = Java.type('org.apache.commons.httpclient.URI');
const UUID = Java.type('java.util.UUID');
const System = Java.type('java.lang.System');
const ScanRuleMetadata = Java.type(
    'org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata',
);

var executed = false;

function getMetadata() {
    return ScanRuleMetadata.fromYaml(`
id: 110601
name: RS06 - Autenticação e gerenciamento de sessão
description: Verifica rejeição de tokens inválidos, autenticação, enumeração de contas e invalidação de refresh tokens.
solution: Valide assinatura, algoritmo, validade e finalidade dos tokens. Aplique mensagens de autenticação consistentes e invalide sessões e refresh tokens após logout ou rotação.
reference: https://owasp.org/Top10/
risk: HIGH
confidence: MEDIUM
cweId: 287
wascId: 0
    `);
}

function scan(helper, msg, param, value) {
    if (executed) return;

    // Inicia na primeira requisição do contexto, sem depender da ordem do spider.
    executed = true;

    try {
        runRs06(helper, msg, getBaseUrl(msg));
    } catch (e) {
        print('[RS06] INFRA_ERROR: ' + String(e));
    }
}

function getBaseUrl(msg) {
    var configured = String(System.getenv('DAST_BASE_URL') || '');
    if (configured) return configured.replace(/\/+$/, '');

    var u = msg.getRequestHeader().getURI();
    var scheme = String(u.getScheme());
    var host = String(u.getHost());
    var port = Number(u.getPort());

    return (
        scheme +
        '://' +
        host +
        (port > 0 && port !== (scheme === 'https' ? 443 : 80) ? ':' + port : '')
    );
}

function randomHex() {
    return String(UUID.randomUUID()).replace(/-/g, '');
}

function send(helper, original, base, method, route, options) {
    options = options || {};

    var message = original.cloneRequest();
    var target = new URI(base + route, false);

    message.getRequestHeader().setMethod(method);
    message.getRequestHeader().setURI(target);
    message
        .getRequestHeader()
        .setHeader(
            'Host',
            target.getHost() +
                (target.getPort() > 0 ? ':' + target.getPort() : ''),
        );

    message.getRequestHeader().setHeader('Authorization', '');

    if (options.token) {
        message
            .getRequestHeader()
            .setHeader('Authorization', 'Bearer ' + options.token);
    }

    var body = '';

    if (options.rawBody !== undefined) {
        body = options.rawBody;
    } else if (options.body !== undefined) {
        body = JSON.stringify(options.body);
    }

    message.setRequestBody(body);

    if (options.body !== undefined || options.rawBody !== undefined) {
        message
            .getRequestHeader()
            .setHeader(
                'Content-Type',
                options.contentType || 'application/json',
            );
    }

    message.getRequestHeader().setHeader('Content-Length', String(body.length));

    helper.sendAndReceive(message, false, false);

    var text = String(message.getResponseBody().toString());
    var json = null;

    try {
        json = text ? JSON.parse(text) : null;
    } catch (_) {}

    return {
        status: Number(message.getResponseHeader().getStatusCode()),
        text: text,
        json: json,
        message: message,
    };
}

function isSuccess(status) {
    return status >= 200 && status < 300;
}

function isRejected(status) {
    return [400, 401, 403, 404, 405, 409, 413, 415, 422].indexOf(status) >= 0;
}

function rejectionResult(status, expected) {
    if (expected.indexOf(status) >= 0) return 'PASS';

    if (
        isSuccess(status) ||
        status >= 500 ||
        status === 401 ||
        status === 403 ||
        status === 409
    ) {
        return 'FAIL';
    }

    return isRejected(status) ? 'NOT_EVALUATED' : 'FAIL';
}

function accessResult(status) {
    if (status === 401 || status === 403) return 'PASS';
    if (isSuccess(status) || status >= 500) return 'FAIL';
    return 'NOT_EVALUATED';
}

function tokenFrom(data, names) {
    if (!data || typeof data !== 'object') return null;

    for (var i = 0; i < names.length; i++) {
        if (typeof data[names[i]] === 'string' && data[names[i]]) {
            return data[names[i]];
        }
    }

    return tokenFrom(data.data, names) || tokenFrom(data.tokens, names);
}

function registerAccount(helper, original, base, label) {
    var account = {
        email: 'dast-rs06-' + label + '-' + randomHex() + '@example.invalid',
        password: 'Dast-' + randomHex() + '!',
        accessToken: null,
        refreshToken: null,
        created: false,
    };

    var reg = send(helper, original, base, 'POST', '/auth/register', {
        body: {
            name: 'DAST RS06 User',
            email: account.email,
            password: account.password,
        },
    });

    account.created = [200, 201, 202].indexOf(reg.status) >= 0;

    if (!account.created) {
        print(
            '[RS06] PREP: cadastro da conta ' +
                label +
                ' não concluído; HTTP ' +
                reg.status,
        );
        return account;
    }

    var login = send(helper, original, base, 'POST', '/auth/login', {
        body: {
            email: account.email,
            password: account.password,
        },
    });

    if (isSuccess(login.status)) {
        account.accessToken = tokenFrom(login.json, [
            'accessToken',
            'access_token',
            'token',
        ]);

        account.refreshToken = tokenFrom(login.json, [
            'refreshToken',
            'refresh_token',
        ]);
    }

    if (!account.accessToken || !account.refreshToken) {
        print(
            '[RS06] PREP: tokens ausentes para conta ' +
                label +
                '; HTTP ' +
                login.status,
        );
    }

    return account;
}

function record(helper, original, base, test, result, detail, evidence) {
    print('[RS06] ' + test + ' => ' + result + '; ' + detail);

    if (result !== 'FAIL') return;

    var msg = evidence && evidence.message ? evidence.message : original;

    helper
        .newAlert()
        .setRisk(2)
        .setConfidence(2)
        .setName('RS06 - ' + test)
        .setDescription(
            'O cenário de segurança RS06 não foi satisfeito. ' + detail,
        )
        .setUri(base)
        .setParam(test)
        .setEvidence('HTTP ' + (evidence ? evidence.status : 'N/A'))
        .setOtherInfo(detail)
        .setSolution(
            'Valide tokens e sessões no servidor, use respostas consistentes ' +
                'para falhas de autenticação e invalide refresh tokens após logout.',
        )
        .setReference('https://owasp.org/Top10/')
        .setCweId(287)
        .setMessage(msg)
        .raise();
}

function runRs06(helper, original, base) {
    var account = registerAccount(helper, original, base, 'a');

    // 1. Tokens inválidos, assinatura adulterada e alg=none.
    var tokenCases = [
        {
            name: 'Token inválido é rejeitado',
            token: function () {
                return 'token.invalido';
            },
        },
        {
            name: 'Token com assinatura adulterada é rejeitado',
            token: function () {
                if (!account.accessToken) return null;
                var p = account.accessToken.split('.');
                if (p.length !== 3 || !p[2]) return null;
                p[2] = (p[2][0] === 'A' ? 'B' : 'A') + p[2].slice(1);
                return p.join('.');
            },
        },
        {
            name: 'Token sem assinatura alg none é rejeitado',
            token: function () {
                if (!account.accessToken) return null;

                var p = account.accessToken.split('.');
                if (p.length !== 3) return null;

                var header = javaBase64Url(
                    JSON.stringify({ alg: 'none', typ: 'JWT' }),
                );

                return header + '.' + p[1] + '.';
            },
        },
    ];

    tokenCases.forEach(function (test) {
        var token = test.token();

        if (!token) {
            print(
                '[RS06] ' +
                    test.name +
                    ' => NOT_EVALUATED; token JWT compatível não disponível.',
            );
            return;
        }

        var response = send(helper, original, base, 'GET', '/users/me', {
            token: token,
        });

        record(
            helper,
            original,
            base,
            test.name,
            accessResult(response.status),
            'HTTP ' + response.status + '; esperado 401 ou 403.',
            response,
        );
    });

    // 2. Login com conta inexistente e senha incorreta.
    var invalidLoginCases = [
        {
            name: 'Login com conta inexistente é rejeitado',
            body: {
                email: 'ausente-' + randomHex() + '@example.invalid',
                password: 'Senha-Incorreta-123!',
            },
        },
        {
            name: 'Login com senha incorreta é rejeitado',
            body: {
                email: account.email,
                password: 'Errada-' + randomHex() + '!',
            },
            needsAccount: true,
        },
    ];

    invalidLoginCases.forEach(function (test) {
        if (test.needsAccount && !account.created) {
            print(
                '[RS06] ' +
                    test.name +
                    ' => NOT_EVALUATED; conta de teste não criada.',
            );
            return;
        }

        var response = send(helper, original, base, 'POST', '/auth/login', {
            body: test.body,
        });

        record(
            helper,
            original,
            base,
            test.name,
            rejectionResult(response.status, [400, 401, 403, 422]),
            'HTTP ' + response.status + '; esperada rejeição de autenticação.',
            response,
        );
    });

    // 3. Enumeração de contas por diferença no conteúdo/status.
    if (!account.created) {
        print(
            '[RS06] Login não revela se a conta existe => ' +
                'NOT_EVALUATED; conta de teste não criada.',
        );
    } else {
        var known = send(helper, original, base, 'POST', '/auth/login', {
            body: {
                email: account.email,
                password: 'Errada-' + randomHex() + '!',
            },
        });

        var unknownEmail = 'outra-' + randomHex() + '@example.invalid';

        var unknown = send(helper, original, base, 'POST', '/auth/login', {
            body: {
                email: unknownEmail,
                password: 'Errada-' + randomHex() + '!',
            },
        });

        if (known.status === 429 || unknown.status === 429) {
            print(
                '[RS06] Login não revela se a conta existe => ' +
                    'NOT_EVALUATED; rate limit HTTP 429 interferiu.',
            );
        } else {
            var knownText = known.text.split(account.email).join('<email>');
            var unknownText = unknown.text.split(unknownEmail).join('<email>');
            var equal =
                known.status === unknown.status && knownText === unknownText;

            record(
                helper,
                original,
                base,
                'Login não revela se a conta existe',
                equal ? 'PASS' : 'FAIL',
                'Conta existente HTTP ' +
                    known.status +
                    '; inexistente HTTP ' +
                    unknown.status +
                    '; respostas ' +
                    (equal ? 'iguais' : 'diferentes') +
                    '. Tempo de resposta não avaliado.',
                known,
            );
        }
    }

    // 4. Refresh token inválido.
    var invalidRefresh = send(helper, original, base, 'POST', '/auth/refresh', {
        body: { refreshToken: 'invalido-' + randomHex() },
    });

    record(
        helper,
        original,
        base,
        'Refresh token inválido é rejeitado',
        rejectionResult(invalidRefresh.status, [400, 401, 403, 422]),
        'HTTP ' + invalidRefresh.status + '.',
        invalidRefresh,
    );

    // 5. Rotação: token anterior deve ser rejeitado após renovação.
    if (!account.created) {
        print(
            '[RS06] Refresh token anterior é rejeitado após renovação => ' +
                'NOT_EVALUATED; conta não criada.',
        );
    } else {
        var session = send(helper, original, base, 'POST', '/auth/login', {
            body: { email: account.email, password: account.password },
        });

        var refreshToken = tokenFrom(session.json, [
            'refreshToken',
            'refresh_token',
        ]);

        if (!refreshToken) {
            print(
                '[RS06] Refresh token anterior é rejeitado após renovação => ' +
                    'NOT_EVALUATED; refresh token ausente.',
            );
        } else {
            var first = send(helper, original, base, 'POST', '/auth/refresh', {
                body: { refreshToken: refreshToken },
            });

            if (!isSuccess(first.status)) {
                print(
                    '[RS06] Refresh token anterior é rejeitado após renovação => ' +
                        'NOT_EVALUATED; renovação inicial HTTP ' +
                        first.status +
                        '.',
                );
            } else {
                var reuse = send(
                    helper,
                    original,
                    base,
                    'POST',
                    '/auth/refresh',
                    { body: { refreshToken: refreshToken } },
                );

                record(
                    helper,
                    original,
                    base,
                    'Refresh token anterior é rejeitado após renovação',
                    rejectionResult(reuse.status, [400, 401, 403, 422]),
                    'Renovação HTTP ' +
                        first.status +
                        '; reutilização HTTP ' +
                        reuse.status +
                        '. Interpretar conforme o design da API.',
                    reuse,
                );
            }
        }
    }

    // 6. Refresh token deve ser rejeitado após logout.
    if (!account.created) {
        print(
            '[RS06] Refresh token é rejeitado após logout => ' +
                'NOT_EVALUATED; conta não criada.',
        );
    } else {
        var logoutSession = send(
            helper,
            original,
            base,
            'POST',
            '/auth/login',
            { body: { email: account.email, password: account.password } },
        );

        var accessToken = tokenFrom(logoutSession.json, [
            'accessToken',
            'access_token',
            'token',
        ]);

        var refresh = tokenFrom(logoutSession.json, [
            'refreshToken',
            'refresh_token',
        ]);

        if (!accessToken || !refresh) {
            print(
                '[RS06] Refresh token é rejeitado após logout => ' +
                    'NOT_EVALUATED; tokens ausentes.',
            );
        } else {
            var logout = send(helper, original, base, 'POST', '/auth/logout', {
                token: accessToken,
                body: { refreshToken: refresh },
            });

            if (!isSuccess(logout.status)) {
                print(
                    '[RS06] Refresh token é rejeitado após logout => ' +
                        'NOT_EVALUATED; logout HTTP ' +
                        logout.status +
                        '.',
                );
            } else {
                var afterLogout = send(
                    helper,
                    original,
                    base,
                    'POST',
                    '/auth/refresh',
                    { body: { refreshToken: refresh } },
                );

                record(
                    helper,
                    original,
                    base,
                    'Refresh token é rejeitado após logout',
                    rejectionResult(afterLogout.status, [400, 401, 403, 422]),
                    'Logout HTTP ' +
                        logout.status +
                        '; refresh posterior HTTP ' +
                        afterLogout.status +
                        '.',
                    afterLogout,
                );
            }
        }
    }

    print(
        '[RS06] Limitação de tentativas de login: execute separadamente, ' +
            'por último, com a quantidade de tentativas configurada no TypeScript.',
    );
}

function javaBase64Url(text) {
    var Base64 = Java.type('java.util.Base64');
    var bytes = new java.lang.String(text).getBytes('UTF-8');

    return String(
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes),
    );
}
