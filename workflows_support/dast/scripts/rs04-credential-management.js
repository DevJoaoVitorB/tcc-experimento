/*
 * RS04 — Gerenciamento seguro de credenciais
 * OWASP ZAP Active Scan script (ECMAScript / Graal.js).
 *
 * Base: testRs04() em dast-rs01-rs07.test.ts.
 *
 * Cenários:
 * 1. Resposta de cadastro inválido não ecoa senha.
 * 2. Resposta de login inválido não ecoa senha.
 * 3. Resposta de cadastro válido não expõe credenciais.
 * 4. Resposta de login válido não expõe credenciais.
 * 5. Resposta de /users/me não expõe credenciais.
 * 6. Hashing de senha: NOT_EVALUATED (exige inspeção do código e SQLite).
 *
 * Somente FAIL gera alerta nativo do ZAP.
 */

const URI = Java.type("org.apache.commons.httpclient.URI");
const UUID = Java.type("java.util.UUID");
const System = Java.type("java.lang.System");

var executed = false;

function getMetadata() {
    return {
        id: 110401,
        name: "RS04 - Gerenciamento seguro de credenciais",
        description: "Verifica se respostas HTTP expõem senhas, hashes de senha ou campos específicos de credenciais.",
        solution: "Nunca retorne senhas, hashes ou tokens internos de credenciais nas respostas. Armazene senhas com algoritmos de hashing apropriados, como Argon2id, bcrypt ou scrypt.",
        reference: "https://owasp.org/Top10/",
        risk: "High",
        confidence: "Medium",
        cweId: 522,
        wascId: 0
    };
}

function scan(helper, msg, param, value) {
    if (executed) return;

    var route = String(
        msg.getRequestHeader().getURI().getPath() || ""
    );

    // O plano deve disparar o script ao acessar /users/me.
    if (route !== "/users/me") return;

    executed = true;

    try {
        runRs04(helper, msg, getBaseUrl(msg));
    } catch (e) {
        print(
            "[RS04] INFRA_ERROR (não classificado como vulnerabilidade): " +
            String(e)
        );
    }
}

function getBaseUrl(msg) {
    var configured = String(
        System.getenv("DAST_BASE_URL") || ""
    );

    if (configured) {
        return configured.replace(/\/+$/, "");
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

function send(helper, original, base, method, route, options) {
    options = options || {};

    var message = original.cloneRequest();
    var target = new URI(base + route, false);

    message.getRequestHeader().setMethod(method);
    message.getRequestHeader().setURI(target);

    message.getRequestHeader().setHeader(
        "Host",
        target.getHost() +
            (target.getPort() > 0
                ? ":" + target.getPort()
                : "")
    );

    message.getRequestHeader().setHeader("Authorization", "");

    if (options.token) {
        message.getRequestHeader().setHeader(
            "Authorization",
            "Bearer " + options.token
        );
    }

    if (options.body !== undefined) {
        var body = JSON.stringify(options.body);

        message.setRequestBody(body);
        message.getRequestHeader().setHeader(
            "Content-Type",
            "application/json"
        );
        message.getRequestHeader().setHeader(
            "Content-Length",
            String(body.length)
        );
    } else {
        message.setRequestBody("");
        message.getRequestHeader().setHeader(
            "Content-Length",
            "0"
        );
    }

    helper.sendAndReceive(message, false, false);

    return {
        status: Number(
            message.getResponseHeader().getStatusCode()
        ),
        text: String(message.getResponseBody().toString()),
        json: parseJson(
            String(message.getResponseBody().toString())
        ),
        message: message
    };
}

function parseJson(text) {
    try {
        return text ? JSON.parse(text) : null;
    } catch (e) {
        return null;
    }
}

function isSuccess(status) {
    return status >= 200 && status < 300;
}

function randomHex() {
    return String(UUID.randomUUID()).replace(/-/g, "");
}

function newAccount(label, runId) {
    return {
        label: label,
        email: "dast-" + label + "-" + runId + "@example.invalid",
        password: "Dast-" + randomHex() + "!",
        created: false,
        registerResponse: null,
        loginResponse: null,
        accessToken: null,
        refreshToken: null
    };
}

function tokenFrom(data, names) {
    if (!data || typeof data !== "object") return null;

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

function exposesCredentialKey(value) {
    if (!value || typeof value !== "object") {
        return false;
    }

    var keys = Object.keys(value);

    for (var i = 0; i < keys.length; i++) {
        var key = keys[i];

        if (
            /^(password|passwordHash|password_hash|credential|credentials|refreshTokenHash|refresh_token_hash)$/i.test(key)
        ) {
            return true;
        }

        if (exposesCredentialKey(value[key])) {
            return true;
        }
    }

    return false;
}

function exposesCredentials(response, passwords) {
    var text = response.text || "";

    // Hashes conhecidos: bcrypt, Argon2 e scrypt.
    var containsHash =
        /\$2[abxy]\$\d{2}\$|\$argon2(id|i|d)\$|\$scrypt\$/i.test(text);

    var containsPassword = passwords.some(function (password) {
        return password && text.indexOf(password) >= 0;
    });

    return containsHash ||
        containsPassword ||
        exposesCredentialKey(response.json);
}

function createAlert(helper, response, test, evidence) {
    helper.newAlert()
        .setRisk(3)
        .setConfidence(2)
        .setName("RS04 - " + test)
        .setDescription(
            "A resposta HTTP expôs uma senha, hash ou campo específico de credenciais."
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
        .setEvidence(evidence)
        .setOtherInfo(
            "Cenário RS04; resposta HTTP " + response.status +
            ". A evidência deve ser revisada para confirmar a exposição."
        )
        .setSolution(
            "Remova senhas, hashes e campos internos de credenciais das respostas. " +
            "Armazene senhas usando hashing apropriado e nunca as registre ou devolva ao cliente."
        )
        .setReference("https://owasp.org/Top10/")
        .setCweId(522)
        .setMessage(response.message)
        .raise();
}

function check(
    helper,
    response,
    test,
    failed,
    evidence
) {
    var status = failed ? "FAIL" : "PASS";

    print(
        "[RS04] " + test +
        " => " + status +
        "; HTTP " + response.status +
        "; " + evidence
    );

    if (failed) {
        createAlert(helper, response, test, evidence);
    }
}

function runRs04(helper, trigger, base) {
    var runId = String(new java.util.Date().getTime()) +
        "-" + randomHex().substring(0, 8);

    var account = newAccount("rs04", runId);

    /*
     * Preparação:
     * cria a conta para permitir comparar as respostas de cadastro
     * e login válidos.
     */
    var register = send(
        helper,
        trigger,
        base,
        "POST",
        "/auth/register",
        {
            body: {
                name: "DAST Test User",
                email: account.email,
                password: account.password
            }
        }
    );

    account.registerResponse = register;
    account.created = [200, 201, 202].indexOf(register.status) >= 0;

    print(
        "[RS04][PREP] Cadastro da conta temporária: HTTP " +
        register.status
    );

    if (account.created) {
        var login = send(
            helper,
            trigger,
            base,
            "POST",
            "/auth/login",
            {
                body: {
                    email: account.email,
                    password: account.password
                }
            }
        );

        account.loginResponse = login;

        if (isSuccess(login.status)) {
            account.accessToken = tokenFrom(
                login.json,
                ["accessToken", "access_token", "token"]
            );

            account.refreshToken = tokenFrom(
                login.json,
                ["refreshToken", "refresh_token"]
            );
        }

        print(
            "[RS04][PREP] Login da conta temporária: HTTP " +
            login.status
        );
    }

    /*
     * 1. Resposta de cadastro inválido não ecoa senha.
     */
    var invalidRegisterPassword = "Secret-" + randomHex();

    var invalidRegister = send(
        helper,
        trigger,
        base,
        "POST",
        "/auth/register",
        {
            body: {
                name: { invalid: true },
                email: "email-invalido",
                password: invalidRegisterPassword
            }
        }
    );

    var registerEcho =
        invalidRegister.text.indexOf(invalidRegisterPassword) >= 0;

    check(
        helper,
        invalidRegister,
        "Resposta de cadastro inválido não ecoa senha",
        registerEcho,
        registerEcho
            ? "Senha sentinela encontrada na resposta."
            : "Senha sentinela não encontrada na resposta."
    );

    /*
     * 2. Resposta de login inválido não ecoa senha.
     */
    var invalidLoginPassword = "Secret-" + randomHex();

    var invalidLogin = send(
        helper,
        trigger,
        base,
        "POST",
        "/auth/login",
        {
            body: {
                email: account.created
                    ? account.email
                    : "ausente-" + runId + "@example.invalid",
                password: invalidLoginPassword
            }
        }
    );

    var loginEcho =
        invalidLogin.text.indexOf(invalidLoginPassword) >= 0;

    check(
        helper,
        invalidLogin,
        "Resposta de login inválido não ecoa senha",
        loginEcho,
        loginEcho
            ? "Senha sentinela encontrada na resposta."
            : "Senha sentinela não encontrada na resposta."
    );

    /*
     * 3. Resposta de cadastro válido não expõe credenciais.
     */
    var registerExposes = exposesCredentials(
        register,
        [account.password]
    );

    check(
        helper,
        register,
        "Resposta de cadastro válido não expõe credenciais",
        registerExposes,
        registerExposes
            ? "Campos específicos de credenciais, hash ou senha detectados."
            : "Nenhum campo específico de credenciais, hash ou senha detectado."
    );

    /*
     * 4. Resposta de login válido não expõe credenciais.
     */
    if (!account.loginResponse) {
        print(
            "[RS04] Resposta de login válido não expõe credenciais " +
            "=> NOT_EVALUATED: conta não foi criada."
        );
    } else {
        var loginExposes = exposesCredentials(
            account.loginResponse,
            [account.password]
        );

        check(
            helper,
            account.loginResponse,
            "Resposta de login válido não expõe credenciais",
            loginExposes,
            loginExposes
                ? "Campos específicos de credenciais, hash ou senha detectados."
                : "Nenhum campo específico de credenciais, hash ou senha detectado."
        );
    }

    /*
     * 5. Resposta de /users/me não expõe credenciais.
     */
    if (!account.accessToken) {
        print(
            "[RS04] Resposta de /users/me não expõe credenciais " +
            "=> NOT_EVALUATED: access token não disponível."
        );
    } else {
        var profile = send(
            helper,
            trigger,
            base,
            "GET",
            "/users/me",
            { token: account.accessToken }
        );

        var profileExposes = exposesCredentials(
            profile,
            [account.password]
        );

        check(
            helper,
            profile,
            "Resposta de /users/me não expõe credenciais",
            profileExposes,
            profileExposes
                ? "Campos específicos de credenciais, hash ou senha detectados."
                : "Nenhum campo específico de credenciais, hash ou senha detectado."
        );
    }

    /*
     * 6. Hashing apropriado da senha não pode ser confirmado via HTTP.
     */
    print(
        "[RS04] Senha armazenada com hashing apropriado " +
        "=> NOT_EVALUATED: exige inspeção do código e do banco SQLite."
    );
}