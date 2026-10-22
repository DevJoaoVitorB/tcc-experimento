/*
 * RS02 — Security Misconfiguration
 * OWASP ZAP Active Scan script (ECMAScript / Graal.js).
 * Baseado nos cenários RS02 de dast-rs01-rs07.test.ts.
 *
 * Cenários:
 * 1. /health não revela detalhes internos.
 * 2. Cabeçalhos de segurança e CORS.
 * 3. Caminhos/arquivos sensíveis não ficam acessíveis.
 * 4. JWT HS256/HS384/HS512 não aceitam segredos comuns.
 * 5. Segredos fixos no código: NOT_EVALUATED (responsabilidade do SAST).
 *
 * Execute apenas contra ambiente de teste autorizado.
 * PASS/NOT_EVALUATED/NOT_APPLICABLE ficam no log; FAIL gera alerta ZAP.
 */

const URI = Java.type("org.apache.commons.httpclient.URI");
const UUID = Java.type("java.util.UUID");
const System = Java.type("java.lang.System");
const Mac = Java.type("javax.crypto.Mac");
const SecretKeySpec = Java.type("javax.crypto.spec.SecretKeySpec");

var executed = false;

function getMetadata() {
    return {
        id: 110201,
        name: "RS02 - Security misconfiguration",
        description: "Verifica vazamento de detalhes internos, cabeçalhos HTTP, CORS, exposição de caminhos sensíveis e aceitação de JWT assinado com segredos comuns.",
        solution: "Remova detalhes internos das respostas, configure cabeçalhos HTTP e CORS de forma segura, impeça acesso a arquivos internos e use segredos JWT fortes e externos ao código-fonte.",
        reference: "https://owasp.org/Top10/",
        risk: "Medium",
        confidence: "Medium",
        cweId: 16,
        wascId: 0
    };
}

function scan(helper, msg, param, value) {
    if (executed) return;

    var path = String(msg.getRequestHeader().getURI().getPath() || "");

    // O plano precisa incluir /health para disparar o conjunto de testes RS02.
    if (path !== "/health") return;

    executed = true;

    try {
        runRs02(helper, msg, getBaseUrl(msg));
    } catch (e) {
        print("[RS02] INFRA_ERROR (não classificado como vulnerabilidade): " + String(e));
    }
}

function getBaseUrl(msg) {
    var configured = String(System.getenv("DAST_BASE_URL") || "");

    if (configured) return configured.replace(/\/+$/, "");

    var u = msg.getRequestHeader().getURI();
    var scheme = String(u.getScheme());
    var host = String(u.getHost());
    var port = Number(u.getPort());

    return scheme + "://" + host +
        (port > 0 && port !== (scheme === "https" ? 443 : 80)
            ? ":" + port
            : "");
}

function parseJson(text) {
    try {
        return text ? JSON.parse(String(text)) : null;
    } catch (e) {
        return null;
    }
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
    }

    if (options.origin) {
        m.getRequestHeader().setHeader("Origin", options.origin);
    }

    if (options.headers) {
        Object.keys(options.headers).forEach(function (k) {
            m.getRequestHeader().setHeader(k, options.headers[k]);
        });
    }

    if (options.body !== undefined) {
        var body = typeof options.body === "string"
            ? options.body
            : JSON.stringify(options.body);

        m.setRequestBody(body);

        if (!options.rawBody) {
            m.getRequestHeader().setHeader(
                "Content-Type",
                "application/json"
            );
        }

        m.getRequestHeader().setHeader(
            "Content-Length",
            String(body.length)
        );
    } else {
        m.setRequestBody("");
        m.getRequestHeader().setHeader("Content-Length", "0");
    }

    helper.sendAndReceive(m, false, false);

    return {
        status: Number(m.getResponseHeader().getStatusCode()),
        text: String(m.getResponseBody().toString()),
        message: m
    };
}

function header(response, name) {
    try {
        var value = response.message
            .getResponseHeader()
            .getHeader(name);

        return value === null || value === undefined
            ? ""
            : String(value);
    } catch (e) {
        return "";
    }
}

function internalDetails(text) {
    var patterns = [
        /\bat\s+\S+\s+\([^)]*:\d+:\d+\)/i,
        /\bnode_modules\b/i,
        /(?:\/app\/|\/home\/|\/var\/www\/|[A-Z]:\\[^ ]+)/i,
        /\bprisma\b/i,
        /\bSQLite\b/i,
        /\bDATABASE_URL\b/i,
        /\bJWT_(?:ACCESS|REFRESH)_SECRET\b/i,
        /\bPrismaClient(?:KnownRequestError|UnknownRequestError|ValidationError)?\b/i,
        /\bP20\d{2}\b/i,
        /\bUnique constraint failed\b/i,
        /\bSyntaxError\b/i,
        /\bJsonWebTokenError\b|\bTokenExpiredError\b/i,
        /\b\w+\.(?:ts|js|json):\d+:\d+\b/i
    ];

    for (var i = 0; i < patterns.length; i++) {
        if (patterns[i].test(String(text || ""))) {
            return true;
        }
    }

    return false;
}

function finding(
    helper,
    response,
    test,
    risk,
    cwe,
    expected,
    evidence,
    solution
) {
    helper.newAlert()
        .setRisk(risk)
        .setConfidence(2)
        .setName("RS02 - " + test)
        .setDescription(
            "Falha no cenário RS02 definido em dast-rs01-rs07.test.ts."
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
        .setEvidence(String(evidence))
        .setOtherInfo(
            "Esperado: " + expected +
            ". Evidência: " + String(evidence)
        )
        .setSolution(solution)
        .setReference("https://owasp.org/Top10/")
        .setCweId(cwe)
        .setMessage(response.message)
        .raise();
}

function check(
    helper,
    response,
    test,
    status,
    expected,
    evidence,
    risk,
    cwe,
    solution
) {
    print(
        "[RS02] " + test +
        " => " + status +
        "; HTTP " + response.status +
        "; " + evidence
    );

    if (status === "FAIL") {
        finding(
            helper,
            response,
            test,
            risk || 2,
            cwe || 16,
            expected,
            evidence,
            solution ||
                "Revise a configuração da aplicação e remova a exposição identificada."
        );
    }
}

function b64url(bytes) {
    var Base64 = Java.type("java.util.Base64");

    return String(
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(bytes)
    );
}

function hmacJwt(secret, algorithm, payload) {
    var algMap = {
        HS256: "HmacSHA256",
        HS384: "HmacSHA384",
        HS512: "HmacSHA512"
    };

    var headerPart = b64url(
        new java.lang.String(
            JSON.stringify({ alg: algorithm, typ: "JWT" })
        ).getBytes("UTF-8")
    );

    var payloadPart = b64url(
        new java.lang.String(
            JSON.stringify(payload)
        ).getBytes("UTF-8")
    );

    var signingInput = headerPart + "." + payloadPart;
    var mac = Mac.getInstance(algMap[algorithm]);

    mac.init(
        new SecretKeySpec(
            new java.lang.String(secret).getBytes("UTF-8"),
            algMap[algorithm]
        )
    );

    var signature = mac.doFinal(
        new java.lang.String(signingInput).getBytes("UTF-8")
    );

    return signingInput + "." + b64url(signature);
}

function tokenPayload() {
    var now = Math.floor(new Date().getTime() / 1000);

    return {
        sub: "dast-rs02-user",
        id: "dast-rs02-user",
        email: "dast-rs02@example.invalid",
        iat: now,
        exp: now + 300
    };
}

function runRs02(helper, trigger, base) {
    var solution =
        "Não exponha detalhes de implementação em respostas HTTP; registre detalhes apenas nos logs internos.";

    // 1. /health não deve revelar detalhes internos.
    var health = send(
        helper, trigger, base,
        "GET", "/health"
    );

    if (health.status === 404) {
        print(
            "[RS02] /health sem endpoint => NOT_EVALUATED (endpoint ausente)."
        );
    } else {
        var leaks = internalDetails(health.text);

        check(
            helper,
            health,
            "/health não revela detalhes internos",
            leaks ? "FAIL" : "PASS",
            "resposta sem stack trace, caminhos internos, detalhes de Prisma/SQLite ou segredos",
            leaks
                ? "A resposta contém padrão compatível com detalhe interno."
                : "Nenhum padrão interno detectado.",
            2,
            209,
            solution
        );
    }

    // 2. Cabeçalhos de segurança HTTP.
    var paths = [
        "/health",
        "/users/me",
        "/dast-rs02-route-" + String(UUID.randomUUID())
    ];

    paths.forEach(function (route) {
        var r = send(helper, trigger, base, "GET", route);
        var issues = [];

        var powered = header(r, "X-Powered-By");
        var server = header(r, "Server");
        var nosniff = header(r, "X-Content-Type-Options");

        if (powered) {
            issues.push("X-Powered-By=" + powered);
        }

        if (/\b(?:Apache|nginx|Express|PHP|Node\.js)\/?\d+(?:\.\d+)*/i.test(server)) {
            issues.push("Server=" + server);
        }

        if (nosniff.toLowerCase() !== "nosniff") {
            issues.push(
                "X-Content-Type-Options ausente ou diferente de nosniff"
            );
        }

        check(
            helper,
            r,
            "Cabeçalhos de segurança HTTP em " + route,
            issues.length ? "FAIL" : "PASS",
            "sem X-Powered-By, sem versão explícita no Server e X-Content-Type-Options: nosniff",
            issues.length
                ? issues.join("; ")
                : "Cabeçalhos avaliados conforme critérios RS02.",
            1,
            693,
            "Remova X-Powered-By e versões de servidor; configure X-Content-Type-Options: nosniff."
        );
    });

    // 3. CORS: falha apenas com wildcard e credenciais juntos.
    var cors = send(
        helper,
        trigger,
        base,
        "OPTIONS",
        "/auth/login",
        {
            origin: "https://dast-origin.example.invalid",
            headers: {
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type,authorization"
            }
        }
    );

    var allowOrigin = header(cors, "Access-Control-Allow-Origin");
    var allowCredentials = header(cors, "Access-Control-Allow-Credentials");

    var unsafeCors =
        allowOrigin.trim() === "*" &&
        allowCredentials.toLowerCase() === "true";

    check(
        helper,
        cors,
        "CORS não combina origem wildcard com credenciais",
        unsafeCors ? "FAIL" : "PASS",
        "não usar Access-Control-Allow-Origin: * junto com Access-Control-Allow-Credentials: true",
        "Access-Control-Allow-Origin=" + (allowOrigin || "(ausente)") +
            "; Access-Control-Allow-Credentials=" +
            (allowCredentials || "(ausente)"),
        2,
        942,
        "Restrinja CORS a origens confiáveis. Não combine origem wildcard com credenciais."
    );

    // 4. Caminhos sensíveis não devem retornar HTTP 2xx.
    [
        "/.env",
        "/.git/config",
        "/package.json",
        "/prisma/schema.prisma",
        "/prisma/dev.db",
        "/dev.db",
        "/debug",
        "/console"
    ].forEach(function (route) {
        var r = send(helper, trigger, base, "GET", route);

        var status =
            r.status >= 200 && r.status < 300
                ? "FAIL"
                : "PASS";

        check(
            helper,
            r,
            "Caminho sensível não está exposto: " + route,
            status,
            "status HTTP fora de 2xx",
            "HTTP " + r.status +
                (r.status >= 200 && r.status < 300
                    ? "; caminho retornou sucesso."
                    : "; caminho não retornou sucesso."),
            3,
            538,
            "Bloqueie o acesso público a arquivos de configuração, repositórios, bancos e rotas de depuração."
        );
    });

    // 5. JWT assinado com segredos comuns.
    var commonSecrets = [
        "secret",
        "changeme",
        "change-me",
        "jwt_secret",
        "jwt-secret",
        "your-secret-key",
        "supersecret",
        "dev-secret",
        "default",
        "password",
        "123456"
    ];

    var algorithms = ["HS256", "HS384", "HS512"];
    var acceptedWeakSecret = null;
    var jwtProbe = null;
    var jwtPayload = tokenPayload();

    for (
        var a = 0;
        a < algorithms.length && !acceptedWeakSecret;
        a++
    ) {
        for (
            var s = 0;
            s < commonSecrets.length && !acceptedWeakSecret;
            s++
        ) {
            var token = hmacJwt(
                commonSecrets[s],
                algorithms[a],
                jwtPayload
            );

            var response = send(
                helper,
                trigger,
                base,
                "GET",
                "/users/me",
                { authorization: "Bearer " + token }
            );

            jwtProbe = response;

            if (response.status >= 200 && response.status < 300) {
                acceptedWeakSecret = {
                    secret: commonSecrets[s],
                    algorithm: algorithms[a]
                };
            }
        }
    }

    if (acceptedWeakSecret) {
        check(
            helper,
            jwtProbe,
            "JWT aceita segredo de assinatura comum",
            "FAIL",
            "JWT assinado com segredo forte e não previsível",
            "Token " + acceptedWeakSecret.algorithm +
                " assinado com segredo comum foi aceito; segredo=" +
                acceptedWeakSecret.secret,
            3,
            347,
            "Use segredo JWT forte, aleatório e gerenciado fora do código-fonte; valide também issuer, audience e claims."
        );
    } else {
        print(
            "[RS02] JWT com segredos comuns => PASS para a lista testada; " +
            "isso não prova que o segredo configurado seja forte."
        );
    }

    // 6. O teste de segredos fixos no código pertence ao SAST.
    print(
        "[RS02] Segredos fixos no código-fonte => NOT_EVALUATED: cenário destinado ao SAST."
    );
}