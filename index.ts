import { AccessToken, AuthorizationGrant, IdPHandlers } from "./types";

export class IdP {
    handlers: IdPHandlers;

    /**
     * Iniitialises a new instance of the IdP (Identity Provider) class.
     * 
     * @param options Options for configuring the Identity Provider
     * @param {IdPHandlers} options.handlers Handlers for interacting with the database
     */

    constructor({ handlers }: { handlers: IdPHandlers }) {
        this.handlers = handlers;
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
    async generateAuthorizationCode(
        user: string,
        scope: string,
        client: string,
        redirectUri: string
    ): Promise<AuthorizationGrant> {
        // Retrieve the client from the database

        // Ensure the redirect URI is valid for the specified client

        // Generate a random authorization code

        // Hash and store the authorization code in the database

        // Return the UNHASHED authorization code, to be returned to the client
        return {
            id: "1",
            user: "1",
            scope: "read",
            client: "1",
            code: "123",
            redirectUri: "https://example.com",
        }
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
    async exchangeCode(
        code: string,
        client: string,
        clientSecret: string,
        redirectUri: string
    ): Promise<AccessToken> {
        // Retrieve the authorization grant from the database

        return {
            id: "1",
            user: "1",
            scope: "read",
            token: "123",
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
            token: "123",
        }
    }
}