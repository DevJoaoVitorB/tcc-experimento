/*
 * RS01 — Controle de acesso e autorização
 * OWASP ZAP Active Scan script (ECMAScript / Graal.js).
 * Base: cenários RS01 de dast-rs01-rs07.test.ts.
 *
 * Execute somente contra ambiente autorizado: cria contas temporárias.
 * PASS/NOT_EVALUATED/NOT_APPLICABLE ficam no log; somente FAIL cria alerta.
 */

const URI = Java.type("org.apache.commons.httpclient.URI");
const UUID = Java.type("java.util.UUID");
const System = Java.type("java.lang.System");
var executed = false;

function getMetadata() {
    return {
        id: 110101,
        name: "RS01 - Controle de acesso e autorização",
        description: "Verifica autenticação, separação de tokens, isolamento entre contas, métodos HTTP e tentativa de elevação de privilégios.",
        solution: "Aplique autorização no servidor, negue acesso por padrão, valide a finalidade dos tokens e não confie em privilégios enviados pelo cliente.",
        reference: "https://owasp.org/Top10/",
        risk: "Medium",
        confidence: "Medium",
        cweId: 862,
        wascId: 0
    };
}

function scan(helper, msg, param, value) {
    if (
        executed ||
        String(msg.getRequestHeader().getURI().getPath()) !== "/users/me"
    ) {
        return;
    }

    executed = true;

    try {
        runRs01(helper, msg, baseUrl(msg));
    } catch (e) {
        print(
            "[RS01] INFRA_ERROR (não classificado como vulnerabilidade): " +
            String(e)
        );
    }
}

function baseUrl(msg) {
    var env = String(System.getenv("DAST_BASE_URL") || "");

    if (env) {
        return env.replace(/\/+$/, "");
    }

    var u = msg.getRequestHeader().getURI();
    var scheme = String(u.getScheme());
    var host = String(u.getHost());
    var port = Number(u.getPort());

    return scheme + "://" + host +
        (port > 0 && port !== (scheme === "https" ? 443 : 80)
            ? ":" + port
            : "");
}

function rand() {
    return String(UUID.randomUUID()).replace(/-/g, "");
}

function account(label, run) {
    return {
        label: label,
        email: "dast-" + label + "-" + run + "@example.invalid",
        password: "Dast-" + rand() + "!",
        created: false,
        loginStatus: null,
        accessToken: null,
        refreshToken: null
    };
}

function json(text) {
    try {
        return text ? JSON.parse(String(text)) : null;
    } catch (e) {
        return null;
    }
}

function tokenFrom(data, names) {
    if (!data || typeof data !== "object") {
        return null;
    }

    for (var i = 0; i < names.length; i++) {
        if (
            typeof data[names[i]] === "string" &&
            data[names[i]]
        ) {
            return data[names[i]];
        }
    }

    return tokenFrom(data.data, names) ||
        tokenFrom(data.tokens, names);
}

function send(helper, original, base, method, route, options) {
    options = options || {};

    var m = original.cloneRequest();
    var target = new URI(base + route, false);

    m.getRequestHeader().setMethod(method);
    m.getRequestHeader().setURI(target);

    m.getRequestHeader().setHeader(
        "Host",
        target.getHost() +
            (target.getPort() > 0 ? ":" + target.getPort() : "")
    );

    m.getRequestHeader().setHeader("Authorization", "");

    if (options.authorization) {
        m.getRequestHeader().setHeader(
            "Authorization",
            options.authorization
        );
    } else if (options.token) {
        m.getRequestHeader().setHeader(
            "Authorization",
            "Bearer " + options.token
        );
    }

    if (options.body !== undefined) {
        var body = JSON.stringify(options.body);

        m.setRequestBody(body);

        m.getRequestHeader().setHeader(
            "Content-Type",
            "application/json"
        );

        m.getRequestHeader().setHeader(
            "Content-Length",
            String(body.length)
        );
    } else {
        m.setRequestBody("");

        m.getRequestHeader().setHeader(
            "Content-Length",
            "0"
        );
    }

    helper.sendAndReceive(m, false, false);

    var status = Number(
        m.getResponseHeader().getStatusCode()
    );

    var text = String(
        m.getResponseBody().toString()
    );

    return {
        status: status,
        text: text,
        json: json(text),
        message: m
    };
}

function success(s) {
    return s >= 200 && s < 300;
}

function denied(s) {
    return s === 401 || s === 403;
}

function rejected(s) {
    return [
        400, 401, 403, 404, 405,
        409, 413, 415, 422
    ].indexOf(s) >= 0;
}

function accessResult(s) {
    return denied(s)
        ? "PASS"
        : (success(s) || s >= 500
            ? "FAIL"
            : "NOT_EVALUATED");
}

function rejectionResult(s, expected) {
    if (expected.indexOf(s) >= 0) {
        return "PASS";
    }

    if (
        success(s) ||
        s >= 500 ||
        [401, 403, 409].indexOf(s) >= 0
    ) {
        return "FAIL";
    }

    return rejected(s)
        ? "NOT_EVALUATED"
        : "FAIL";
}

function combine(statuses) {
    if (statuses.indexOf("FAIL") >= 0) {
        return "FAIL";
    }

    for (var i = 0; i < statuses.length; i++) {
        if (statuses[i] !== "PASS") {
            return "NOT_EVALUATED";
        }
    }

    return "PASS";
}

function privilegeReflected(value) {
    if (!value || typeof value !== "object") {
        return false;
    }

    var keys = Object.keys(value);

    for (var i = 0; i < keys.length; i++) {
        var k = keys[i];
        var v = value[k];

        if (
            /^(role|roles|isAdmin|admin)$/i.test(k) &&
            (v === true || /admin/i.test(JSON.stringify(v)))
        ) {
            return true;
        }

        if (privilegeReflected(v)) {
            return true;
        }
    }

    return false;
}

function finding(
    helper,
    response,
    test,
    expected,
    detail
) {
    helper.newAlert()
        .setRisk(2)
        .setConfidence(2)
        .setName("RS01 - " + test)
        .setDescription(
            "Falha no cenário RS01 definido em dast-rs01-rs07.test.ts."
        )
        .setUri(
            String(
                response.message
                    .getRequestHeader()
                    .getURI()
                    .toString()
            )
        )
        .setParam(test)
        .setAttack("HTTP " + response.status)
        .setEvidence(detail)
        .setOtherInfo(
            "Esperado: " + expected +
            ". Observado: " + detail
        )
        .setSolution(
            "Aplique autorização no servidor, negue acesso por padrão, " +
            "valide a finalidade dos tokens e ignore privilégios " +
            "administrativos enviados pelo cliente."
        )
        .setReference("https://owasp.org/Top10/")
        .setCweId(862)
        .setMessage(response.message)
        .raise();
}

function check(
    helper,
    response,
    test,
    status,
    expected,
    detail
) {
    print(
        "[RS01] " + test +
        " => " + status +
        "; " + detail
    );

    if (status === "FAIL") {
        finding(
            helper,
            response,
            test,
            expected,
            detail
        );
    }
}

function registerBody(run, extra) {
    var b = {
        name: "DAST Test User",
        email: "dast-" +
            rand().substring(0, 12) +
            "-" + run + "@example.invalid",
        password: "Dast-" + rand() + "!"
    };

    if (extra) {
        Object.keys(extra).forEach(function (k) {
            b[k] = extra[k];
        });
    }

    return b;
}

function runRs01(helper, trigger, base) {
    var run = String(new java.util.Date().getTime()) +
        "-" + rand().substring(0, 8);

    var a = account("a", run);
    var b = account("b", run);

    // Pré-condições: criar duas contas e obter tokens.
    [a, b].forEach(function (x) {
        var r = send(
            helper,
            trigger,
            base,
            "POST",
            "/auth/register",
            {
                body: {
                    name: "DAST Test User",
                    email: x.email,
                    password: x.password
                }
            }
        );

        x.created = [200, 201, 202].indexOf(r.status) >= 0;

        print(
            "[RS01][PREP] criar conta " +
            x.label + ": HTTP " + r.status
        );
    });

    [a, b].forEach(function (x) {
        if (!x.created) {
            return;
        }

        var r = send(
            helper,
            trigger,
            base,
            "POST",
            "/auth/login",
            {
                body: {
                    email: x.email,
                    password: x.password
                }
            }
        );

        x.loginStatus = r.status;

        if (success(r.status)) {
            x.accessToken = tokenFrom(
                r.json,
                ["accessToken", "access_token", "token"]
            );

            x.refreshToken = tokenFrom(
                r.json,
                ["refreshToken", "refresh_token"]
            );
        }

        print(
            "[RS01][PREP] autenticar " + x.label +
            ": HTTP " + r.status +
            "; access=" + Boolean(x.accessToken) +
            "; refresh=" + Boolean(x.refreshToken)
        );
    });

    // 1. GET /users/me sem token e com Basic.
    [
        {
            name: "GET /users/me sem token é rejeitado",
            options: {},
            expected: "401 ou 403"
        },
        {
            name: "GET /users/me com esquema Basic é rejeitado",
            options: {
                authorization: "Basic ZGFzdDpkYXN0"
            },
            expected: "401 ou 403"
        }
    ].forEach(function (t) {
        var r = send(
            helper,
            trigger,
            base,
            "GET",
            "/users/me",
            t.options
        );

        check(
            helper,
            r,
            t.name,
            accessResult(r.status),
            t.expected,
            "HTTP " + r.status
        );
    });

    // 2. Token válido deve acessar o perfil.
    if (a.accessToken) {
        var own = send(
            helper,
            trigger,
            base,
            "GET",
            "/users/me",
            { token: a.accessToken }
        );

        check(
            helper,
            own,
            "Token válido permite acessar /users/me",
            own.status === 200
                ? "PASS"
                : denied(own.status)
                    ? "FAIL"
                    : "NOT_EVALUATED",
            "HTTP 200",
            "login HTTP " + a.loginStatus +
                "; perfil HTTP " + own.status
        );
    } else {
        print(
            "[RS01] Token válido permite acessar /users/me " +
            "=> NOT_EVALUATED: access token A ausente."
        );
    }

    // 3. Isolamento entre contas A e B.
    if (a.accessToken && b.accessToken) {
        var pa = send(
            helper, trigger, base,
            "GET", "/users/me",
            { token: a.accessToken }
        );

        var pb = send(
            helper, trigger, base,
            "GET", "/users/me",
            { token: b.accessToken }
        );

        var s = "NOT_EVALUATED";
        var d = "Respostas não confirmam isolamento.";

        if (
            pa.text.indexOf(b.email) >= 0 ||
            pb.text.indexOf(a.email) >= 0
        ) {
            s = "FAIL";
            d = "A resposta de uma conta contém o e-mail da outra.";
        } else if (
            pa.text.indexOf(a.email) >= 0 &&
            pb.text.indexOf(b.email) >= 0
        ) {
            s = "PASS";
            d = "Cada resposta contém o e-mail próprio e não o da outra conta.";
        }

        check(
            helper,
            pa,
            "Cada token retorna apenas os dados do próprio usuário",
            s,
            "perfil A apenas A e perfil B apenas B",
            d
        );
    } else {
        print(
            "[RS01] Isolamento entre usuários " +
            "=> NOT_EVALUATED: não foi possível autenticar as duas contas."
        );
    }

    // 4. Refresh token como access token.
    if (a.refreshToken) {
        var rta = send(
            helper, trigger, base,
            "GET", "/users/me",
            { token: a.refreshToken }
        );

        check(
            helper,
            rta,
            "Refresh token não é aceito como token de acesso",
            accessResult(rta.status),
            "401 ou 403",
            "HTTP " + rta.status
        );
    } else {
        print(
            "[RS01] Refresh token como access token " +
            "=> NOT_EVALUATED: refresh token ausente."
        );
    }

    // 5. Access token como refresh token.
    if (a.accessToken) {
        var atr = send(
            helper, trigger, base,
            "POST", "/auth/refresh",
            { body: { refreshToken: a.accessToken } }
        );

        check(
            helper,
            atr,
            "Token de acesso não é aceito como refresh token",
            rejectionResult(atr.status, [400, 401, 403, 422]),
            "400, 401, 403 ou 422",
            "HTTP " + atr.status
        );
    } else {
        print(
            "[RS01] Access token como refresh token " +
            "=> NOT_EVALUATED: access token ausente."
        );
    }

    // 6. PUT/PATCH/DELETE em /users/me.
    if (a.accessToken) {
        var statuses = [];

        ["PUT", "PATCH", "DELETE"].forEach(function (method) {
            var r = send(
                helper, trigger, base,
                method, "/users/me",
                { token: a.accessToken, body: {} }
            );

            var s = rejectionResult(
                r.status,
                [400, 401, 403, 404, 405, 415, 422]
            );

            statuses.push(s);

            check(
                helper,
                r,
                method + " /users/me é rejeitado",
                s,
                "400, 401, 403, 404, 405, 415 ou 422",
                "HTTP " + r.status
            );
        });

        print(
            "[RS01] Resultado combinado dos métodos: " +
            combine(statuses)
        );
    } else {
        print(
            "[RS01] Métodos HTTP não previstos " +
            "=> NOT_EVALUATED: access token A ausente."
        );
    }

    // 7. Tentativa de atribuir privilégios no cadastro.
    var elevated = registerBody(run, {
        role: "admin",
        roles: ["admin"],
        isAdmin: true,
        admin: true
    });

    var er = send(
        helper, trigger, base,
        "POST", "/auth/register",
        { body: elevated }
    );

    if (!success(er.status)) {
        check(
            helper,
            er,
            "Cadastro não concede privilégios enviados pelo cliente",
            rejectionResult(er.status, [400, 413, 415, 422]),
            "rejeitar o cadastro ou ignorar campos sem conceder privilégio",
            "Cadastro HTTP " + er.status
        );
    } else {
        var el = send(
            helper, trigger, base,
            "POST", "/auth/login",
            {
                body: {
                    email: elevated.email,
                    password: elevated.password
                }
            }
        );

        var et = success(el.status)
            ? tokenFrom(
                el.json,
                ["accessToken", "access_token", "token"]
            )
            : null;

        if (!et) {
            print(
                "[RS01] Elevação de privilégio " +
                "=> NOT_EVALUATED: cadastro aceito, mas login/token indisponível."
            );
        } else {
            var ep = send(
                helper, trigger, base,
                "GET", "/users/me",
                { token: et }
            );

            if (
                privilegeReflected(er.json) ||
                privilegeReflected(ep.json)
            ) {
                check(
                    helper,
                    ep,
                    "Cadastro não concede privilégios enviados pelo cliente",
                    "FAIL",
                    "nenhum privilégio administrativo atribuído pelo cliente",
                    "Campo de privilégio elevado apareceu na resposta de cadastro ou perfil."
                );
            } else {
                print(
                    "[RS01] Cadastro não concede privilégios enviados " +
                    "pelo cliente => PASS observável; a atribuição silenciosa " +
                    "não é verificável via HTTP se a API não expõe papéis."
                );
            }
        }
    }

    // 8. Conforme o teste original, IDOR é não aplicável.
    print(
        "[RS01] IDOR em recursos de outros usuários => NOT_APPLICABLE: " +
        "não há recurso de negócio de usuário no escopo; " +
        "isolamento é verificado em /users/me."
    );
}