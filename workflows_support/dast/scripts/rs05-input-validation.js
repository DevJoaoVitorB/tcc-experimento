/*
 * RS05 — Validação de entrada
 * OWASP ZAP Active Scan script (ECMAScript / Graal.js).
 *
 * Base: testRs05() em dast-rs01-rs07.test.ts.
 *
 * Cenários:
 * - Payloads inválidos definidos em INVALID_PAYLOADS.
 * - Cadastro com senha vazia ou de um caractere.
 * - Cadastro com senha, e-mail ou nome de 10.000 caracteres.
 * - Login com Content-Type text/plain.
 * - JSON malformado.
 * - Corpo de requisição de aproximadamente 1,1 MB.
 *
 * Somente FAIL gera alerta nativo do ZAP.
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
        id: 110501,
        name: "RS05 - Validação de entrada",
        description: "Verifica se a API rejeita entradas inválidas, formatos inadequados e corpos de requisição excessivamente grandes.",
        solution: "Valide tipo, formato, tamanho e limites de cada campo no servidor. Rejeite JSON malformado e tipos de conteúdo não suportados.",
        reference: "https://owasp.org/Top10/",
        risk: "Medium",
        confidence: "Medium",
        cweId: 20,
        wascId: 20
    `);
}

function scan(helper, msg, param, value) {
    if (executed) return;

    var route = String(msg.getRequestHeader().getURI().getPath() || '');

    // O plano precisa incluir /auth/login para iniciar os cenários.
    if (route !== '/auth/login') return;

    executed = true;

    try {
        runRs05(helper, msg, getBaseUrl(msg));
    } catch (e) {
        print(
            '[RS05] INFRA_ERROR (não classificado como vulnerabilidade): ' +
                String(e),
        );
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
        name: 'DAST Test User',
        email: 'dast-rs05-' + randomHex() + '@example.invalid',
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

    if (options.contentType) {
        message
            .getRequestHeader()
            .setHeader('Content-Type', options.contentType);
    }

    if (options.rawBody !== undefined) {
        message.setRequestBody(options.rawBody);

        if (options.contentType) {
            message
                .getRequestHeader()
                .setHeader('Content-Type', options.contentType);
        }

        message
            .getRequestHeader()
            .setHeader('Content-Length', String(options.rawBody.length));
    } else if (options.body !== undefined) {
        var body = JSON.stringify(options.body);

        message.setRequestBody(body);
        message
            .getRequestHeader()
            .setHeader(
                'Content-Type',
                options.contentType || 'application/json',
            );
        message
            .getRequestHeader()
            .setHeader('Content-Length', String(body.length));
    } else {
        message.setRequestBody('');
        message.getRequestHeader().setHeader('Content-Length', '0');
    }

    helper.sendAndReceive(message, false, false);

    return {
        status: Number(message.getResponseHeader().getStatusCode()),
        text: String(message.getResponseBody().toString()),
        message: message,
    };
}

function expectedRejection(status, expected) {
    if (expected.indexOf(status) >= 0) {
        return 'PASS';
    }

    if (
        (status >= 200 && status < 300) ||
        status >= 500 ||
        [401, 403, 409].indexOf(status) >= 0
    ) {
        return 'FAIL';
    }

    if ([400, 404, 405, 413, 415, 422, 429].indexOf(status) >= 0) {
        return 'NOT_EVALUATED';
    }

    return 'FAIL';
}

function createAlert(helper, response, test, expected, evidence) {
    helper
        .newAlert()
        .setRisk(2)
        .setConfidence(2)
        .setName('RS05 - ' + test)
        .setDescription(
            'A API não rejeitou uma entrada inválida conforme o cenário RS05.',
        )
        .setUri(String(response.message.getRequestHeader().getURI().toString()))
        .setParam(test)
        .setAttack(evidence)
        .setEvidence('HTTP ' + response.status)
        .setOtherInfo(
            'Esperado: HTTP ' +
                expected.join(', ') +
                '. Recebido: HTTP ' +
                response.status +
                '.',
        )
        .setSolution(
            'Implemente validação de entrada no servidor, com regras explícitas ' +
                'para tipo, formato e tamanho dos dados. Rejeite conteúdo malformado ' +
                'e aplique limites ao corpo das requisições.',
        )
        .setReference('https://owasp.org/Top10/')
        .setCweId(20)
        .setMessage(response.message)
        .raise();
}

function check(helper, response, test, expected, detail) {
    var status = expectedRejection(response.status, expected);

    print(
        '[RS05] ' +
            test +
            ' => ' +
            status +
            '; HTTP ' +
            response.status +
            '; ' +
            detail,
    );

    if (status === 'FAIL') {
        createAlert(helper, response, test, expected, detail);
    }
}

function runRs05(helper, trigger, base) {
    var cases = [
        {
            label: 'Cadastro com senha vazia',
            route: '/auth/register',
            body: registerBody({ password: '' }),
            expected: [400, 422],
        },
        {
            label: 'Cadastro com senha de 1 caractere',
            route: '/auth/register',
            body: registerBody({ password: '1' }),
            expected: [400, 422],
        },
        {
            label: 'Cadastro com senha de 10.000 caracteres',
            route: '/auth/register',
            body: registerBody({
                password: new Array(10001).join('A'),
            }),
            expected: [400, 413, 422],
        },
        {
            label: 'Cadastro com e-mail de 10.000 caracteres',
            route: '/auth/register',
            body: registerBody({
                email: new Array(10001).join('a') + '@example.invalid',
            }),
            expected: [400, 413, 422],
        },
        {
            label: 'Cadastro com nome de 10.000 caracteres',
            route: '/auth/register',
            body: registerBody({
                name: new Array(10001).join('A'),
            }),
            expected: [400, 413, 422],
        },
    ];

    /*
     * Os payloads abaixo reproduzem classes de entrada inválida.
     * A lista INVALID_PAYLOADS original não está embutida neste script;
     * compare-a com o TypeScript antes de afirmar equivalência integral.
     */
    var invalidPayloads = [
        {
            label: 'Cadastro com corpo JSON nulo',
            route: '/auth/register',
            body: null,
            expected: [400, 415, 422],
        },
        {
            label: 'Cadastro com tipos de campos incorretos',
            route: '/auth/register',
            body: {
                name: { invalid: true },
                email: 12345,
                password: ['invalid'],
            },
            expected: [400, 415, 422],
        },
        {
            label: 'Login com tipos de campos incorretos',
            route: '/auth/login',
            body: {
                email: { invalid: true },
                password: ['invalid'],
            },
            expected: [400, 415, 422],
        },
    ];

    cases = invalidPayloads.concat(cases);

    cases.forEach(function (test) {
        var response = send(helper, trigger, base, 'POST', test.route, {
            body: test.body,
        });

        check(
            helper,
            response,
            test.label + ' é rejeitado',
            test.expected,
            'Esperada rejeição da entrada inválida.',
        );
    });

    // Login com Content-Type text/plain.
    var plain = send(helper, trigger, base, 'POST', '/auth/login', {
        rawBody: JSON.stringify({
            email: 'dast-rs05@example.invalid',
            password: 'Dast-Invalid-123!',
        }),
        contentType: 'text/plain',
    });

    check(
        helper,
        plain,
        'Login com Content-Type text/plain não é aceito',
        [400, 415, 422],
        'Esperado 400, 415 ou 422.',
    );

    // JSON malformado.
    var malformed = send(helper, trigger, base, 'POST', '/auth/login', {
        rawBody: '{"email": "x", "password":',
        contentType: 'application/json',
    });

    check(
        helper,
        malformed,
        'JSON malformado é rejeitado',
        [400, 415, 422],
        'Esperado 400, 415 ou 422.',
    );

    // Corpo de aproximadamente 1,1 MB.
    var oversizedBody = JSON.stringify({
        name: 'DAST Test User',
        email: 'dast-rs05-oversized@example.invalid',
        password: new Array(1100001).join('A'),
    });

    var oversized = send(helper, trigger, base, 'POST', '/auth/register', {
        rawBody: oversizedBody,
        contentType: 'application/json',
    });

    check(
        helper,
        oversized,
        'Corpo acima do limite é rejeitado',
        [400, 413, 422],
        'Corpo de aproximadamente 1,1 MB; esperada rejeição por tamanho.',
    );
}
