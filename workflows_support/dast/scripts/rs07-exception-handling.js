/*
 * RS07 — Tratamento seguro de erros
 * OWASP ZAP Active Scan Script
 *
 * Base: testRs07() de dast-rs01-rs07.test.ts
 *
 * Executa os cenários quando o Active Scan alcançar /auth/login.
 * Confirme a compatibilidade com a versão do ZAP do pipeline.
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
id: 110701
name: RS07 - Tratamento seguro de erros
description: Verifica exposição de detalhes internos e erros HTTP 5xx em respostas da API.
solution: Implemente tratamento centralizado de exceções. Retorne mensagens genéricas ao cliente e registre detalhes técnicos apenas nos logs internos.
reference: https://owasp.org/Top10/
risk: MEDIUM
confidence: MEDIUM
cweId: 209
wascId: 0
    `);
}

function scan(helper, msg, param, value) {
    if (executed) return;

    var route = String(msg.getRequestHeader().getURI().getPath() || '');

    if (route !== '/auth/login') return;

    executed = true;

    try {
        runRs07(helper, msg, getBaseUrl(msg));
    } catch (e) {
        print('[RS07] INFRA_ERROR: ' + String(e));
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

function registerBody(overrides) {
    var body = {
        name: 'DAST RS07 User',
        email: 'dast-rs07-' + randomHex() + '@example.invalid',
        password: 'Dast-' + randomHex() + '!',
    };

    if (overrides) {
        Object.keys(overrides).forEach(function (key) {
            body[key] = overrides[key];
        });
    }

    return body;
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
    message.getRequestHeader().setHeader('Content-Length', String(body.length));

    if (options.rawBody !== undefined || options.body !== undefined) {
        message
            .getRequestHeader()
            .setHeader(
                'Content-Type',
                options.contentType || 'application/json',
            );
    }

    helper.sendAndReceive(message, false, false);

    return {
        status: Number(message.getResponseHeader().getStatusCode()),
        text: String(message.getResponseBody().toString()),
        message: message,
    };
}

function leaksInternalDetails(text) {
    return /stack trace|node_modules|\/app\/|\/home\/|prisma\.|SQLITE_ERROR|SQLITE_[A-Z_]+|DATABASE_URL|JWT_(ACCESS|REFRESH)_SECRET|PrismaClient\w*Error|\bP20\d\d\b|Unique constraint failed|SyntaxError|JsonWebTokenError|TokenExpiredError|jwt malformed|\bat\s+(?:async\s+)?[\w.<>$]+\s+\([^)]*:\d+:\d+\)|\.(?:ts|js):\d+:\d+/i.test(
        text || '',
    );
}

function exposesFrameworkDefaults(text) {
    return /Cannot (GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) \//.test(
        text || '',
    );
}

function createAlert(helper, response, test, evidence) {
    helper
        .newAlert()
        .setRisk(2)
        .setConfidence(2)
        .setName('RS07 - ' + test)
        .setDescription(
            'A resposta da API revelou detalhes internos ou retornou um erro 5xx inesperado.',
        )
        .setUri(String(response.message.getRequestHeader().getURI().toString()))
        .setParam(test)
        .setEvidence(evidence)
        .setOtherInfo(
            'HTTP ' +
                response.status +
                '. Verifique o corpo da resposta e os logs do servidor.',
        )
        .setSolution(
            'Trate exceções de forma centralizada, retorne mensagens genéricas ' +
                'e evite expor stack traces, caminhos locais, detalhes do banco de ' +
                'dados ou informações internas do framework.',
        )
        .setReference('https://owasp.org/Top10/')
        .setCweId(209)
        .setMessage(response.message)
        .raise();
}

function check(helper, response, test, framework) {
    var leaked =
        leaksInternalDetails(response.text) ||
        (framework && exposesFrameworkDefaults(response.text));

    var serverError = response.status >= 500;
    var failed = leaked || serverError;

    var result = failed ? 'FAIL' : 'PASS';
    var detail =
        'HTTP ' +
        response.status +
        '; detalhes internos ' +
        (leaked ? 'detectados' : 'não detectados') +
        (serverError ? '; erro HTTP 5xx inesperado' : '');

    print('[RS07] ' + test + ' => ' + result + '; ' + detail);

    if (failed) {
        createAlert(
            helper,
            response,
            test,
            'HTTP ' +
                response.status +
                (leaked ? '; possível vazamento de detalhes internos' : '') +
                (serverError ? '; erro 5xx' : ''),
        );
    }
}

function runRs07(helper, original, base) {
    var invalidPayloads = [
        {
            route: '/auth/register',
            label: 'Cadastro sem campos',
            body: {},
        },
        {
            route: '/auth/register',
            label: 'Cadastro com tipos inválidos',
            body: {
                name: { invalid: true },
                email: 123,
                password: ['invalid'],
            },
        },
        {
            route: '/auth/login',
            label: 'Login sem campos',
            body: {},
        },
        {
            route: '/auth/login',
            label: 'Login com tipos inválidos',
            body: {
                email: null,
                password: { invalid: true },
            },
        },
        {
            route: '/auth/login',
            label: 'Login com objeto de filtro no e-mail',
            body: {
                email: { contains: '@' },
                password: 'Senha-Incorreta-123!',
            },
        },
        {
            route: '/auth/refresh',
            label: 'Refresh sem campos',
            body: {},
        },
        {
            route: '/auth/refresh',
            label: 'Refresh com tipo inválido',
            body: {
                refreshToken: { invalid: true },
            },
        },
    ];

    var scenarios = [
        {
            name: 'Erro de login',
            run: function () {
                return send(helper, original, base, 'POST', '/auth/login', {
                    body: {
                        email: 'ausente-' + randomHex() + '@example.invalid',
                        password: 'Senha-Incorreta-123!',
                    },
                });
            },
        },
    ];

    invalidPayloads.forEach(function (test) {
        scenarios.push({
            name: test.label,
            run: function () {
                return send(helper, original, base, 'POST', test.route, {
                    body: test.body,
                });
            },
        });
    });

    scenarios.push({
        name: 'JSON malformado',
        run: function () {
            return send(helper, original, base, 'POST', '/auth/login', {
                rawBody: '{"email": "x", "password":',
                contentType: 'application/json',
            });
        },
    });

    scenarios.push({
        name: 'Corpo acima do limite',
        run: function () {
            return send(helper, original, base, 'POST', '/auth/login', {
                body: {
                    email: 'a@example.invalid',
                    password: new Array(1100001).join('A'),
                },
            });
        },
    });

    scenarios.push({
        name: 'Rota inexistente',
        framework: true,
        run: function () {
            return send(
                helper,
                original,
                base,
                'GET',
                '/rota-inexistente-' + randomHex(),
                {},
            );
        },
    });

    scenarios.forEach(function (test) {
        try {
            var response = test.run();
            check(
                helper,
                response,
                test.name + ' não revela detalhes internos',
                !!test.framework,
            );
        } catch (e) {
            print('[RS07] INFRA_ERROR - ' + test.name + ': ' + String(e));
        }
    });

    // Cadastro duplicado: usa a mesma conta temporária criada aqui.
    var account = registerBody();

    var registration = send(helper, original, base, 'POST', '/auth/register', {
        body: account,
    });

    if ([200, 201, 202].indexOf(registration.status) < 0) {
        print(
            '[RS07] Cadastro duplicado => NOT_EVALUATED; ' +
                'preparação HTTP ' +
                registration.status,
        );
    } else {
        var duplicate = send(helper, original, base, 'POST', '/auth/register', {
            body: account,
        });

        if (duplicate.status === 429) {
            print(
                '[RS07] Cadastro duplicado => NOT_EVALUATED; rate limit HTTP 429.',
            );
        } else {
            check(
                helper,
                duplicate,
                'Cadastro duplicado não revela detalhes internos nem retorna 5xx',
                false,
            );
        }
    }

    // Tokens inválidos: verifica vazamento e erros 5xx.
    var tokens = ['token.invalido', 'a.b.c'];

    tokens.forEach(function (token) {
        var response = send(helper, original, base, 'GET', '/users/me', {
            token: token,
        });

        check(
            helper,
            response,
            'Token inválido não revela detalhes internos nem retorna 5xx',
            false,
        );
    });
}
