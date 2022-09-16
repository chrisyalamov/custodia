import { AccessToken, AuthorizationGrant, Client, IdPHandlers, RefreshToken } from "./types";
import crypto from "crypto"
import bcrypt from "bcrypt"
import jsonwebtoken, { JwtPayload } from "jsonwebtoken"

export class IdP {
    handlers: IdPHandlers;
    secret: string;

    /**
     * Iniitialises a new instance of the IdP (Identity Provider) class.
     * 
     * @param options Options for configuring the Identity Provider
     * @param {IdPHandlers} options.handlers Handler functions for interacting with the database
     * @param {string} options.secret A secret used for signing and verifying JWTs (min 256 bits).
     */

    constructor({ handlers, secret }: { handlers: IdPHandlers, secret: string }) {
        this.handlers = handlers;
        this.secret = secret;
    }

    /**
     * This function creates a new access token for the specified user and scope.
     * @internal
     * @param __namedParameters.user         The ID of the user
     * @param __namedParameters.scope        The scope of the access token
     *  
     * @returns {string} The signed JWT containing the access token
     */
    async generateAndStoreAccessTokenJWT({ user, scope }: {
        user: string,
        scope: string
    }): Promise<string> {
        // Create a new access token and store it in the database
        const token = crypto.randomBytes(32).toString("hex");
        const hashedToken = await bcrypt.hash(token, 10);
        const storedToken = await this.handlers.storeAccessToken({
            user: user,
            scope: scope,
            token: hashedToken,
        })

        // Construct JWT access token
        let tokenJWT = jsonwebtoken.sign({
            id: storedToken.id,
            token: token,
        }, this.secret, {
            expiresIn: "1h",
        });

        return tokenJWT;
    }

    /**
     * This function creates a new access token for the specified user and scope.
     * @internal
     * @param __namedParameters.user         The ID of the user
     * @param __namedParameters.scope        The scope of the access token
     *  
     * @returns {string} The signed JWT containing the access token
     */
     async generateAndStoreRefreshTokenJWT({ user, scope, client }: {
        user: string,
        scope: string,
        client: string,
    }): Promise<string> {
        // Create a new refresh token and store it in the database
        const refreshToken = crypto.randomBytes(32).toString("hex");
        const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
        const storedRefreshToken = await this.handlers.storeRefreshToken({
            client: client,
            user: user,
            scope: scope,
            token: hashedRefreshToken,
        })

        // Construct JWT refresh token
        let refreshTokenJWT = jsonwebtoken.sign({
            id: storedRefreshToken.id,
            token: refreshToken,
        }, this.secret, {
            expiresIn: "90d",
        });

        return refreshTokenJWT;
    }

    /**
     * When the client initially sends the user-agent to the authorization endpoint,
     * the developer will authenticate the user. Upon successful authentication, the
     * developer will call this method to generate an authorization code.
     * 
     * The user-agent will then be redirected to the client's redirect URI with the
     * authorization code as a query parameter.
     * 
     * @param __namedParameters.user          The ID of the user which has been successfully authenticated
     * @param __namedParameters.scope         The scope of the authorization request
     * @param __namedParameters.client        The ID of the client which is requesting authorization
     * @param __namedParameters.redirectUri   The redirect URI to which the user-agent will be redirected
     * @returns 
     */
    async generateAuthorizationCode({ user, scope, client, redirectUri }: {
        user: string,
        scope: string,
        client: string,
        redirectUri: string
    }): Promise<string> {
        // Retrieve the client from the database
        let clientObject = await this.handlers.getClient(client);
        if (!clientObject) throw new Error("Client not found");

        // Ensure the redirect URI is valid for the specified client
        if (!(clientObject as Client).redirectUris.includes(redirectUri)) {
            throw new Error("Invalid redirect URI");
        }

        // Generate a random authorization code
        const code = crypto.randomBytes(32).toString("hex");

        // Hash and store the authorization code in the database
        const hashedCode = await bcrypt.hash(code, 10);

        const storedGrant = await this.handlers.storeAuthorizationGrant({
            user: user,
            scope: scope,
            client: client,
            redirectUri: redirectUri,
            code: hashedCode,
        });

        // Return the JWT containing the unhashed authorization code
        return jsonwebtoken.sign({
            id: storedGrant.id,
            code: code,
        }, this.secret, {
            expiresIn: "10m",
        });
    }

    /**
     * Once the client has obtained an authorization code, they will attempt to exchange it for an access token.
     * 
     * This function takes an authorization code (grant) and returns an access token.
     * It revokes the authorization code (so it can only be used once) and stores the access token in the database.
     * 
     * @param __namedParameters.code          The authorization code to exchange for an access token
     * @param __namedParameters.client        The ID of the client which is requesting authorization
     * @param __namedParameters.clientSecret  The client's secret
     * @param __namedParameters.redirectUri   The redirect URI to which the user-agent was redirected (should match the one in the authorization request)
     * @returns {Promise<{accessToken: string, refreshToken: string }>} An object containing the access token and refresh tokens
     */
    async exchangeCode({ code, client, clientSecret, redirectUri }: {
        code: string,
        client: string,
        clientSecret: string,
        redirectUri: string
    }): Promise<{
        accessToken: string,
        refreshToken: string,
    }> {
        // Verify the JWT
        const grant = jsonwebtoken.verify(code, this.secret) as {id: string, code: string};

        // Retrieve the authorization grant from the database by ID
        const storedGrant = await this.handlers.getAuthorizationGrant(grant.id);

        // Check that the redirect URI matches the one in the authorization grant
        if (storedGrant.redirectUri !== redirectUri) {
            throw new Error("Invalid redirect URI");
        }

        // Retrieve the client from the database
        const clientObject = await this.handlers.getClient(client);

        // Check that the client secret is valid
        let match = this.handlers.validateClientSecret(clientSecret, clientObject.secret);

        // Create a new access token and store it in the database
        const tokenJWT = await this.generateAndStoreAccessTokenJWT({
            user: storedGrant.user,
            scope: (storedGrant.scope as string)
        });

        // Create a refresh token and store it in the database
        const refreshTokenJWT = await this.generateAndStoreRefreshTokenJWT({
            user: storedGrant.user,
            scope: (storedGrant.scope as string),
            client: client,
        });

        // Revoke the authorization grant
        await this.handlers.revokeGrant(grant.id);

        return {
            accessToken: tokenJWT,
            refreshToken: refreshTokenJWT,
        }
    }

    /**
     * The access token which the client would have obtained will eventually expire.
     * 
     * Upon exchange, the client will have also received a refresh token, which they can use to obtain
     * a subsequent access token.
     * 
     * This function takes a refresh token and returns an access token.
     * 
     * In the process, it also revokes the refresh token and provides a new one.
     * 
     * @param __namedParameters.refreshToken  The refresh token to exchange for a new pair of tokens
     * @param __namedParameters.client        The ID of the client which is requesting authorization
     * @param __namedParameters.clientSecret  The secret supplied in the request (IdP will check if it matches using the verifyClientSecret handler)
     * @returns {Promise<{accessToken: string, refreshToken: string }>} An object containing the access token and refresh tokens
     */
    async exchangeRefreshToken({ refreshToken, client, clientSecret }: {
        refreshToken: string,
        client: string,
        clientSecret: string,
    }): Promise<{
        accessToken: string,
        refreshToken: string,
    }> {
        // Verify the JWT
        const refresh = jsonwebtoken.verify(refreshToken, this.secret) as {id: string, token: string};

        // Retrieve the refresh token from the database
        const storedRefreshToken = await this.handlers.getRefreshToken(refresh.id);

        // Retrieve the client from the database
        const clientObject = await this.handlers.getClient(client);

        // Check that the client secret is valid
        let match = this.handlers.validateClientSecret(clientSecret, clientObject.secret);

        // Check that the refresh token is valid
        let valid = await bcrypt.compare(refresh.token, storedRefreshToken.token);

        // Create a new access token and store it in the database
        const tokenJWT = await this.generateAndStoreAccessTokenJWT({
            user: storedRefreshToken.user,
            scope: storedRefreshToken.scope as string,
        });

        const refreshTokenJWT = await this.generateAndStoreRefreshTokenJWT({
            user: storedRefreshToken.user,
            scope: storedRefreshToken.scope as string,
            client: client,
        });

        // Revoke the refresh token
        await this.handlers.revokeRefreshToken(refresh.id);

        return {
            accessToken: tokenJWT,
            refreshToken: refreshTokenJWT,
        };
    }

    /**
     * When the API is queried, requests will include an access token (e.g. in an Auhorization header with a value of "Bearer ...")
     * 
     * This function checks that the access token is valid for the provided user and scope.
     * 
     * The scope is optional, and if not provided, the function will check that the access token is valid for any scope.
     * If provided, scope is verified by checking that the access token's scope .includes() the provided scope.
     * 
     * @param token The token to check
     * @param user  The ID of the user which is making the request
     * @param scope The scope of the request
     * @returns The Access token, if valid
     */
    async verifyAccessToken({token, user, scope}: {
        token: string,
        user: string,
        scope?: string,
    }): Promise<AccessToken> {
        // Check JWT valid
        let decodedJWT
        try {
            const jwt = jsonwebtoken.verify(token, this.secret) as JwtPayload;
            decodedJWT = {
                id: (jwt.id as string),
                token: (jwt.token as string),
            } as AccessToken;
        } catch {
            throw new Error("Invalid token");
        }

        // Retrieve the access token from the database
        let storedToken = await this.handlers.getAccessToken(decodedJWT.id as string);

        // If scopes are set, check that the access token's scope includes the requested scope
        if (scope && !(storedToken.scope as string).includes(scope)) {
            throw new Error("Invalid scope");
        }

        // Return a response
        return storedToken;
    }
}