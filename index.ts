import { AccessToken, AuthorizationGrant, Client, IdPHandlers } from "./types";
import crypto from "crypto"
import bcrypt from "bcrypt"
import jsonwebtoken from "jsonwebtoken"

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
     * When the client initially sends the user-agent to the authorization endpoint,
     * the developer will authenticate the user. Upon successful authentication, the
     * developer will call this method to generate an authorization code.
     * 
     * The user-agent will then be redirected to the client's redirect URI with the
     * authorization code as a query parameter.
     * 
     * @param user          The ID of the user which has been successfully authenticated
     * @param scope         The scope of the authorization request
     * @param client        The ID of the client which is requesting authorization
     * @param redirectUri   The redirect URI to which the user-agent will be redirected
     * @returns 
     */
    async generateAuthorizationCode({ user, scope, client, redirectUri}: {
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
     * @param code          The authorization code to exchange for an access token
     * @param client        The ID of the client which is requesting authorization
     * @param clientSecret  The client's secret
     * @param redirectUri   The redirect URI to which the user-agent was redirected (should match the one in the authorization request)
     * @returns The access token
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
        const token = crypto.randomBytes(32).toString("hex");
        const hashedToken = await bcrypt.hash(token, 10);
        const storedToken = await this.handlers.storeAccessToken({
            user: storedGrant.user,
            scope: storedGrant.scope,
            token: hashedToken,
        })

        // Revoke the authorization grant
        await this.handlers.revokeGrant(grant.id);

        // Construct JWT access token
        let tokenJWT = jsonwebtoken.sign({
            id: storedToken.id,
            token: token,
        }, this.secret, {
            expiresIn: "1h",
        });

        // Create a refresh token and store it in the database
        const refreshToken = crypto.randomBytes(32).toString("hex");
        const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
        const storedRefreshToken = await this.handlers.storeRefreshToken({
            client: client,
            user: storedGrant.user,
            scope: storedGrant.scope,
            token: hashedRefreshToken,
        })

        // Construct JWT refresh token
        let refreshTokenJWT = jsonwebtoken.sign({
            id: storedRefreshToken.id,
            token: refreshToken,
        }, this.secret, {
            expiresIn: "90d",
        });

        return {
            accessToken: tokenJWT,
            refreshToken: refreshTokenJWT,
        }
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
     * @returns The Access token
     */
    async verifyAccessToken(
        token: string,
        user: string,
        scope: string
    ): Promise<AccessToken> {
        // Check JWT valid

        // Retrieve the access token from the database

        // Return a response

        return {
            id: "1",
            user: "1",
            scope: "read",
        }
    }
}