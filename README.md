# Node.js API Client for Keratin AuthN

This Node.js package allows you to integrate the [Keratin AuthN authentication microservice](https://github.com/keratin/authn-server) with a Node.js web application backend. You will still need to use [a separate API client on the frontend](https://github.com/keratin/authn-js).

Has only two dependencies and is fully compatible with TypeScript.

## Usage Example: integrating with Hapi

```typescript
import * as Hapi from "@hapi/hapi";
import * as Boom from "@hapi/boom";
import { KeratinAuthNClient } from "authn-node";
import { config, log, User } from "my-app/blah";

export const authClient = new KeratinAuthNClient({
    appDomain: config.appDomain,
    authnUrl: config.authnUrl,
    authnPrivateUrl: config.authnPrivateUrl,
    username: config.authnApiUsername,
    password: config.authnApiPassword,
    debugLogger: log.debug,
});

/** Authentication scheme that integrates the Keratin AuthN Microservice into the hapi web server framework */
export const authnScheme: Hapi.ServerAuthScheme = function (server, options) {

    const authenticate: Hapi.ServerAuthSchemeObject["authenticate"] = async (request, h) => {
        // Note: we return HTTP 401 if the authentication is invalid, because despite the name, it's about
        // Authentication and HTTP 403 is about authorization.
        const authHeader = request.headers.authorization;
        if (authHeader === undefined) {
            throw Boom.unauthorized("Authorization header (and JWT token) is required.")
        }
        if (!authHeader.startsWith("Bearer ")) {
            throw Boom.unauthorized("Authorization header is not a bearer token.")
        }
        const authToken = authHeader.substr(7);
        const authInfo = await authClient.validateSessionToken(authToken);
        if (authInfo === undefined) {
            throw Boom.unauthorized("Authorization token is invalid or expired.")
        }

        const user = await User.getOne({authnId: authInfo.accountId});

        const credentials = {
            user: {
                id: user.id,
                authnId: authInfo.accountId,
                username: user.username,
                email: user.email,
                realname: user.realname,
            },
        }
        return h.authenticated({ credentials, artifacts: {} });
    };

    return { authenticate, };
}
```
