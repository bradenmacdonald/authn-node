interface Options {
    /** The URL to the authn server from your app's server; not necessarily the public URL. e.g. "http://authn:3000" */
    authnPrivateUrl?: string;
    /** The domain of your application (no protocol). Must be one of the APP_DOMAINS of the Keratin AuthN server. */
    appDomain: string;
    /** The AUTHN_URL of your Keratin AuthN server (its public URL).e.g. "https://authn.myapp.com" */
    authnUrl: string;
    /** Username for API requests to private Keratin AuthN endpoints. */
    username: string;
    /** Password for API requests to private Keratin AuthN endpoints. */
    password: string;
    /** Optional method this class can call to log a string for debugging */
    debugLogger?: (msg: string) => void;
}
export interface KeratinAuthNSession {
    accountId: number;
}
export interface KeratinAuthNAccount {
    id: number;
    username: string;
    locked: boolean;
    deleted: boolean;
}
export declare class KeratinAuthNClient {
    #private;
    constructor(options: Options);
    get authnUrl(): string;
    get authnPrivateUrl(): string;
    /**
     * Validate a session token (would usually be passed as a JWT in the "Authorization" HTTP header).
     * Returns an object with the account ID if the token is valid, or undefined if the token is invalid.
     */
    validateSessionToken(token: string): Promise<KeratinAuthNSession | undefined>;
    /**
     * Register a new account. Normally the frontend should call this directly, but sometimes you need to create
     * accounts on the backend, e.g. for importing a user or dev/test accounts.
     *
     * Password may be either an existing BCrypt hash or a plaintext (raw) string. The password will not be validated
     * for complexity. If a password is not specified, a random one will be securely generated.
     */
    createUser(args: {
        username: string;
        password?: string;
        locked?: boolean;
    }): Promise<{
        accountId: number;
    }>;
    /** Check if a user with the given username exists. */
    isUsernameRegistered(args: {
        username: string;
    }): Promise<boolean>;
    /** Get a user via their account ID (get account ID from validateSessionToken()) */
    getAccount(args: {
        accountId: number;
    }): Promise<KeratinAuthNAccount>;
    /**
     * Change a user's username (or email) or locked status
     * May throw a KeratinAuthNError with error.errors[0].message as either NOT_FOUND or FORMAT_INVALID
     */
    update(args: {
        accountId: number;
        username?: string;
        locked?: boolean;
    }): Promise<void>;
    /** Wipe all personal information, including username and password. Intended for user deletion routine. */
    archive(args: {
        accountId: number;
    }): Promise<void>;
    /** Flags the account for a required password change on their next login */
    expirePassword(args: {
        accountId: number;
    }): Promise<void>;
    /**
     * Request passwordless login for user with specified username.
     * This is useful in cases where your backend needs to look up the user (e.g. by email) to get their username,
     * if you are not using email as authn username.
     *
     * Always claims to succeed - use isUsernameRegistered() if you need to know if this will succeed or not.
     */
    requestPasswordlessLogin(args: {
        username: string;
    }): Promise<void>;
    private callApi;
    private callApiRaw;
    private refreshKeys;
}
export {};
