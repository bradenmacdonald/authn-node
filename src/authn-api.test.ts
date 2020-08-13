/**
 * Tests for the API client for the Keratin-AuthN server.
 */
import intern from "intern";
import { JWT, JWK } from "jose";
import { KeratinAuthNClient } from "./authn-api";

const { registerSuite } = intern.getPlugin("interface.object");
const { assert } = intern.getPlugin("chai");

registerSuite("Keratin AuthN API Client", () => {
    const defaultClientOptions = Object.freeze({
        authnPrivateUrl: "http://test-authn-server:3000",
        authnUrl: "https://authn.example.com",
        appDomain: "app.example.com",
        username: "testuser",
        password: "password",
        debugLogger: console.log,
    });
    const defaultClaims = Object.freeze({
        sub: "12345",  // The only value in the payload is the account ID, 12345
    });
    const defaultOptions: JWT.SignOptions = Object.freeze({
        issuer: defaultClientOptions.authnUrl,
        audience: defaultClientOptions.appDomain,
    });
    /** Mock that simulates the AuthN service returning its current key(s) */
    const mockGetKey = (client: KeratinAuthNClient, key: JWK.RSAKey): void => {
        (client as any)["callApiRaw"] = async (method: string, url: string) => {
            if (url === "/jwks") {
                return {
                    status: 200,
                    json: async () => ({keys: [key.toJWK(false)]}),
                };
            }
        }
    }
    return {
        tests: {
            async "parses and validates a valid session token"() {
                const key = await JWK.generate("RSA", 512, {use: "sig"});
                const validToken = JWT.sign(defaultClaims, key, defaultOptions);
                const client = new KeratinAuthNClient(defaultClientOptions);
                mockGetKey(client, key);

                const result = await client.validateSessionToken(validToken);
                assert.isDefined(result);
                assert.equal(result?.accountId, 12345);
            },
            async "rejects a session token signed by another key"() {
                const realKey = await JWK.generate("RSA", 512, {use: "sig"});
                const badKey = await JWK.generate("RSA", 512, {use: "sig"});
                const invalidToken = JWT.sign(defaultClaims, badKey, defaultOptions);
                const client = new KeratinAuthNClient(defaultClientOptions);
                mockGetKey(client, realKey);

                const result = await client.validateSessionToken(invalidToken);
                assert.isUndefined(result);
            },
            async "Ignores minor differences in issuer URL"() {
                // "https://authn.example.com" vs. "https://authn.example.com:80/"
                const key = await JWK.generate("RSA", 512, {use: "sig"});
                const validToken = JWT.sign(defaultClaims, key, {...defaultOptions, issuer: "https://authn.example.com:80/"});
                const client = new KeratinAuthNClient(defaultClientOptions);
                mockGetKey(client, key);

                const result = await client.validateSessionToken(validToken);
                assert.isDefined(result);
                assert.equal(result?.accountId, 12345);
            },
            async "rejects a session token signed by another issuer"() {
                const key = await JWK.generate("RSA", 512, {use: "sig"});
                const invalidToken = JWT.sign(defaultClaims, key, {...defaultOptions, issuer: "https://other.example.com"});
                const client = new KeratinAuthNClient(defaultClientOptions);
                mockGetKey(client, key);

                const result = await client.validateSessionToken(invalidToken);
                assert.isUndefined(result);
            },
            async "rejects a session token issued to another app"() {
                const key = await JWK.generate("RSA", 512, {use: "sig"});
                const invalidToken = JWT.sign(defaultClaims, key, {...defaultOptions, audience: "other-app.example.com"});
                const client = new KeratinAuthNClient(defaultClientOptions);
                mockGetKey(client, key);

                const result = await client.validateSessionToken(invalidToken);
                assert.isUndefined(result);
            },
        },
    };
});
