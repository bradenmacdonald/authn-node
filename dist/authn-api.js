"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __classPrivateFieldSet = (this && this.__classPrivateFieldSet) || function (receiver, privateMap, value) {
    if (!privateMap.has(receiver)) {
        throw new TypeError("attempted to set private field on non-instance");
    }
    privateMap.set(receiver, value);
    return value;
};
var __classPrivateFieldGet = (this && this.__classPrivateFieldGet) || function (receiver, privateMap) {
    if (!privateMap.has(receiver)) {
        throw new TypeError("attempted to get private field on non-instance");
    }
    return privateMap.get(receiver);
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
var _authnUrl, _authnPrivateUrl, _appDomain, _username, _password, _keystore, _log;
Object.defineProperty(exports, "__esModule", { value: true });
exports.KeratinAuthNClient = void 0;
/**
 * API client for the Keratin-AuthN server.
 * This is meant to be used in a Node.js-based server.
 */
const querystring_1 = __importDefault(require("querystring"));
const url_1 = require("url");
const crypto_1 = require("crypto");
const node_fetch_1 = __importStar(require("node-fetch"));
const jose_1 = require("jose");
class KeratinAuthNError extends Error {
    constructor(statusCode, statusText, errors) {
        super(`AuthN API Call Failed: ${statusCode} ${statusText}`);
        this.errors = errors;
        // This clips the constructor invocation to make the stack trace a little nicer.
        Error.captureStackTrace(this, this.constructor);
    }
}
/** Compare URLs, ignoring minor changes like misisng trailing slash or port number */
function urlsEqual(url1, url2) {
    if (url1 === url2) {
        return true;
    }
    let u1, u2;
    try {
        u1 = new url_1.URL(url1);
        u2 = new url_1.URL(url2);
    }
    catch (_a) {
        return false;
    }
    return ((u1.protocol === u2.protocol) &&
        (u1.hostname === u2.hostname) &&
        ((u1.port || "80") === (u2.port || "80")) &&
        (u1.pathname === u2.pathname));
}
class KeratinAuthNClient {
    constructor(options) {
        _authnUrl.set(this, void 0);
        _authnPrivateUrl.set(this, void 0);
        _appDomain.set(this, void 0);
        _username.set(this, void 0);
        _password.set(this, void 0);
        _keystore.set(this, void 0);
        _log.set(this, void 0);
        __classPrivateFieldSet(this, _authnUrl, options.authnUrl);
        __classPrivateFieldSet(this, _authnUrl, __classPrivateFieldGet(this, _authnUrl).replace(/\/+$/g, "")); // Strip trailing slash
        __classPrivateFieldSet(// Strip trailing slash
        this, _authnPrivateUrl, options.authnPrivateUrl || options.authnUrl);
        __classPrivateFieldSet(this, _authnPrivateUrl, __classPrivateFieldGet(this, _authnPrivateUrl).replace(/\/+$/g, "")); // Strip trailing slash
        __classPrivateFieldSet(// Strip trailing slash
        this, _appDomain, options.appDomain);
        __classPrivateFieldSet(this, _username, options.username);
        __classPrivateFieldSet(this, _password, options.password);
        __classPrivateFieldSet(this, _keystore, new jose_1.JWKS.KeyStore());
        __classPrivateFieldSet(this, _log, options.debugLogger || ((msg) => { }));
    }
    get authnUrl() { return __classPrivateFieldGet(this, _authnUrl); }
    get authnPrivateUrl() { return __classPrivateFieldGet(this, _authnPrivateUrl); }
    /**
     * Validate a session token (would usually be passed as a JWT in the "Authorization" HTTP header).
     * Returns an object with the account ID if the token is valid, or undefined if the token is invalid.
     */
    async validateSessionToken(token) {
        // The token must be a (non-empty) string:
        if (!token || typeof token !== "string") {
            __classPrivateFieldGet(this, _log).call(this, `AuthN: Session token ${token} is empty or not a string.`);
            return undefined;
        }
        // Parse token
        let data;
        try {
            data = jose_1.JWT.decode(token);
        }
        catch (err) {
            __classPrivateFieldGet(this, _log).call(this, `AuthN: Invalid JWT: ${err}`);
            return undefined;
        }
        // Check issuer
        if (!urlsEqual(data.iss, __classPrivateFieldGet(this, _authnUrl))) {
            __classPrivateFieldGet(this, _log).call(this, `AuthN: Invalid JWT issuer: ${data.iss} (expected ${__classPrivateFieldGet(this, _authnUrl)})`);
            return undefined;
        }
        // Check audience
        const audience = Array.isArray(data.aud) ? data.aud : [data.aud];
        if (!audience.includes(__classPrivateFieldGet(this, _appDomain))) {
            __classPrivateFieldGet(this, _log).call(this, `AuthN: Invalid JWT audience: ${data.aud} (expected ${__classPrivateFieldGet(this, _appDomain)})`);
            return undefined;
        }
        // Verify signature
        try {
            jose_1.JWT.verify(token, __classPrivateFieldGet(this, _keystore));
        }
        catch (err) {
            if (err.code === "ERR_JWKS_NO_MATCHING_KEY") {
                // Fetch new key and retry
                try {
                    await this.refreshKeys();
                    jose_1.JWT.verify(token, __classPrivateFieldGet(this, _keystore));
                }
                catch (err) {
                    __classPrivateFieldGet(this, _log).call(this, `AuthN: JWT Signature validation failed: ${err}`);
                    return undefined;
                }
            }
            else {
                __classPrivateFieldGet(this, _log).call(this, `AuthN: JWT Signature validation failed: ${err}`);
                return undefined;
            }
        }
        // Return data
        const accountId = parseInt(data.sub, 10);
        return { accountId, };
    }
    /**
     * Register a new account. Normally the frontend should call this directly, but sometimes you need to create
     * accounts on the backend, e.g. for importing a user or dev/test accounts.
     *
     * Password may be either an existing BCrypt hash or a plaintext (raw) string. The password will not be validated
     * for complexity. If a password is not specified, a random one will be securely generated.
     */
    async createUser(args) {
        if (!args.password) {
            // Generate a secure password automatically
            args = { ...args, password: crypto_1.randomBytes(64).toString("hex") };
        }
        const result = await this.callApi("post", "/accounts/import", args);
        __classPrivateFieldGet(this, _log).call(this, `AuthN: Created user ${args.username}`);
        return { accountId: result.id };
    }
    /** Check if a user with the given username exists. */
    async isUsernameRegistered(args) {
        const result = await this.callApiRaw("get", "/accounts/available", args);
        if (result.status === 200) {
            return false;
        }
        else if (result.status === 422) {
            return true;
        }
        throw new Error(`Unable to check username status: response was ${result.status} ${result.statusText}`);
    }
    /** Get a user via their account ID (get account ID from validateSessionToken()) */
    async getAccount(args) {
        return this.callApi("get", `/accounts/${args.accountId}`);
    }
    /**
     * Change a user's username (or email) or locked status
     * May throw a KeratinAuthNError with error.errors[0].message as either NOT_FOUND or FORMAT_INVALID
     */
    async update(args) {
        if (args.username !== undefined) {
            await this.callApi("patch", `/accounts/${args.accountId}`, { username: args.username });
        }
        if (args.locked === true) {
            await this.callApi("patch", `/accounts/${args.accountId}/lock`);
        }
        else if (args.locked === false) {
            await this.callApi("patch", `/accounts/${args.accountId}/unlock`);
        }
    }
    /** Wipe all personal information, including username and password. Intended for user deletion routine. */
    async archive(args) {
        return this.callApi("delete", `/accounts/${args.accountId}`);
    }
    /** Flags the account for a required password change on their next login */
    async expirePassword(args) {
        return this.callApi("patch", `/accounts/${args.accountId}/expire_password`);
    }
    /**
     * Request passwordless login for user with specified username.
     * This is useful in cases where your backend needs to look up the user (e.g. by email) to get their username,
     * if you are not using email as authn username.
     *
     * Always claims to succeed - use isUsernameRegistered() if you need to know if this will succeed or not.
     */
    async requestPasswordlessLogin(args) {
        const result = await this.callApiRaw("get", `/session/token`, { username: args.username });
        if (result.status !== 200) {
            const msg = await result.text();
            __classPrivateFieldGet(this, _log).call(this, `AuthN: passwordless login request failed with ${result.status} ${result.statusText} (${msg})`);
            throw new KeratinAuthNError(result.status, result.statusText);
        }
    }
    async callApi(method, url, data) {
        const result = await this.callApiRaw(method, url, data);
        if (result.status >= 200 && result.status <= 300) {
            return (await result.json()).result;
        }
        else {
            const msg = await result.text();
            let errors = undefined;
            try {
                errors = (await result.json()).errors;
            }
            catch (_a) { }
            __classPrivateFieldGet(this, _log).call(this, `AuthN: ${method} to ${url} failed with ${result.status} ${result.statusText} (${msg})`);
            throw new KeratinAuthNError(result.status, result.statusText, errors);
        }
    }
    async callApiRaw(method, url, data) {
        const headers = new node_fetch_1.Headers();
        const authToken = Buffer.from(`${__classPrivateFieldGet(this, _username)}:${__classPrivateFieldGet(this, _password)}`).toString("base64");
        headers.set("Authorization", `Basic ${authToken}`); // Required for private endpoints
        headers.set("Origin", `http://${__classPrivateFieldGet(this, _appDomain)}`); // Required for public endpoints
        const opts = { method: method };
        if (method === "get") {
            if (data) {
                url = url + "?" + querystring_1.default.stringify(data);
            }
        }
        else {
            opts.body = JSON.stringify(data || {});
            headers.set("Content-Type", "application/json");
        }
        opts.headers = headers;
        return node_fetch_1.default(`${__classPrivateFieldGet(this, _authnPrivateUrl)}${url}`, opts);
    }
    async refreshKeys() {
        const response = await this.callApiRaw("get", "/jwks");
        if (response.status !== 200) {
            throw new Error("Unable to fetch new key from AuthN microservice.");
        }
        const keydata = await response.json();
        __classPrivateFieldGet(this, _log).call(this, `AuthN: Refreshed keys (current keys are ${keydata.keys.map((k) => k.kid).join(", ")})`);
        __classPrivateFieldSet(this, _keystore, jose_1.JWKS.asKeyStore(keydata));
    }
}
exports.KeratinAuthNClient = KeratinAuthNClient;
_authnUrl = new WeakMap(), _authnPrivateUrl = new WeakMap(), _appDomain = new WeakMap(), _username = new WeakMap(), _password = new WeakMap(), _keystore = new WeakMap(), _log = new WeakMap();
//# sourceMappingURL=authn-api.js.map