export interface AuthorizationGrant {
    id?: string;
    user: string;
    scope: string;
    client: string;
    code: string;
    redirectUri: string;
}

export interface AccessToken {
    id?: string;
    user: string;
    scope: string;
    token: string;
}

/**
 * 
 * Handlers are functions which define how the IdP interacts with the database.
 * 
 * Developers can implement their own handlers to use their own database. Some plugins are available for common databases.
 * 
 */
export interface IdPHandlers {
    /**
     * The storeAuthorizationGrant handler is called by the IdP to store an authorization grant in the database, in a way defined by the developer. Returns the AuthorizationGrant object with the generated ID.
     * 
     * @param grant The authorization grant to store
     * @returns {Promise<AuthorizationGrant>}
     */
    storeAuthorizationGrant: (grant: AuthorizationGrant) => Promise<AuthorizationGrant>;

    /**
     * The getGrant handler is called by the IdP to retrieve an authorization grant from the database, in a way defined by the developer. Returns the AuthorizationGrant object with the generated ID.
     * 
     * @param id The ID of the authorization grant to retrieve
     * @returns {Promise<AuthorizationGrant>}
     */
    getGrant: (id: string) => Promise<AuthorizationGrant>;

    /**
     * The revokeGrant handler is called by the IdP to revoke an authorization grant which exists in the database, in a way defined by the developer.
     * 
     * @param id The ID of the authorization grant to be revoked
     */
    revokeGrant: (id: string) => Promise<void>;

    /**
     * The storeAccessToken handler is called by the IdP to store an access token in the database, in a way defined by the developer. Returns the AccessToken object with the generated ID.
     * 
     * @param token The access token to store
     * @returns {Promise<AccessToken>}
     */
    storeAccessToken: (token: AccessToken) => Promise<string>;

    /**
     * The getAccessToken handler is called by the IdP to retrieve an access token from the database, in a way defined by the developer. Returns the AccessToken object with the generated ID.
     * 
     * @param id The ID of the access token to retrieve
     * @returns {Promise<AccessToken>}
     */
    getAccessToken: (id: string) => Promise<AccessToken>;

    /**
     * The revokeAccessToken handler is called by the IdP to revoke an access token which exists in the database, in a way defined by the developer.
     * 
     * @param id The ID of the access token to be revoked
     * @returns {Promise<void>}
     */
    revokeAccessToken: (id: string) => Promise<void>;
}