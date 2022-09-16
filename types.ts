export interface AuthorizationGrant {
  id?: string
  user: string
  scope?: string
  client: string
  code: string
  redirectUri: string
}

export interface RefreshToken {
  id?: string
  client: string
  user: string
  scope?: string
  token: string
}

/**
 * An access token is a string provided when making a request to an API.
 *
 * It confirms access to the API for a given user and scope.
 */
export interface AccessToken {
  // The ID of the access token in the database
  id?: string
  // The ID of the user which the access token is for
  user: string
  // The scope of the access token
  scope?: string
  // The access token itself
  token?: string
}

export interface Client {
  id?: string
  name: string
  secret: string
  redirectUris: string[]
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
     * @example ```typescript
     * async (grant) => {
     *   let storedGrant = await db.collection("authorization_grants").insertOne(grant);
     *   return storedGrant._id;
     * }
     * ```
     */
  storeAuthorizationGrant: (grant: AuthorizationGrant) => Promise<AuthorizationGrant>

  /**
     * The getAuthorizationGrant handler is called by the IdP to retrieve an authorization grant from the database, in a way defined by the developer. Returns the AuthorizationGrant object with the generated ID.
     *
     * @param id The ID of the authorization grant to retrieve
     * @returns {Promise<AuthorizationGrant>}
     * @example ```typescript
     * async (id) => {
     *   return await db.collection("authorization_grants").findOne({ _id: ObjectId(id) });
     * }
     * ```
     */
  getAuthorizationGrant: (id: string) => Promise<AuthorizationGrant>

  /**
     * The revokeGrant handler is called by the IdP to revoke an authorization grant which exists in the database, in a way defined by the developer.
     *
     * @param id The ID of the authorization grant to be revoked
     * @example ```typescript
     * async (id) => {
     *   return await db.collection("authorization_grants").deleteOne({ _id: ObjectId(id) });
     * }
     * ```
     */
  revokeGrant: (id: string) => Promise<void>

  /**
     * The storeRefreshToken handler is called by the IdP to store a refresh token in the database, in a way defined by the developer. Returns the RefreshToken object with the generated ID.
     *
     * @param token The refresh token to store
     * @returns {Promise<RefreshToken>} The refresh token with the generated ID
     */
  storeRefreshToken: (refreshToken: RefreshToken) => Promise<RefreshToken>

  /**
     * The getRefreshToken handler is called by the IdP to retrieve a refresh token from the database, in a way defined by the developer. Returns the RefreshToken object with the generated ID.
     *
     * @param id The ID of the refresh token to retrieve
     * @returns {Promise<RefreshToken>} The refresh token
     */
  getRefreshToken: (id: string) => Promise<RefreshToken>

  /**
     * The revokeRefreshToken handler is called by the IdP to revoke a refresh token which exists in the database, in a way defined by the developer.
     *
     * A refresh token is revoked after it has been redeemed, as refresh tokens are single use under RFC 6749.
     */
  revokeRefreshToken: (id: string) => Promise<void>

  /**
     * The storeAccessToken handler is called by the IdP to store an access token in the database, in a way defined by the developer. Returns the AccessToken object with the generated ID.
     *
     * @param token The access token to store
     * @returns {Promise<AccessToken>}
     * @example ```typescript
     * async (token) => {
     *   let storedToken = await db.collection("access_tokens").insertOne(token);
     *   return storedToken._id;
     * }
     * ```
     */
  storeAccessToken: (token: AccessToken) => Promise<AccessToken>

  /**
     * The getAccessToken handler is called by the IdP to retrieve an access token from the database, in a way defined by the developer. Returns the AccessToken object with the generated ID.
     *
     * @param id The ID of the access token to retrieve
     * @returns {Promise<AccessToken>}
     * @example ```typescript
     * async (id) => {
     *  return await db.collection("access_tokens").findOne({ _id: ObjectId(id) });
     * }
     * ```
     */
  getAccessToken: (id: string) => Promise<AccessToken>

  /**
     * The revokeAccessToken handler is called by the IdP to revoke an access token which exists in the database, in a way defined by the developer.
     *
     * @param id The ID of the access token to be revoked
     * @returns {Promise<void>}
     * @example ```typescript
     * async (id) => {
     *  return await db.collection("access_tokens").deleteOne({ _id: ObjectId(id) });
     * }
     * ```
     */
  revokeAccessToken: (id: string) => Promise<void>

  /**
     * The getClient handler is called by the IdP to retrieve a client from the database, in a way defined by the developer. Returns the Client object.
     *
     * @param id The ID of the client to retrieve
     * @returns {Promise<Client>}
     */
  getClient: (id: string) => Promise<Client> | Promise<undefined> | Client | undefined

  /**
     * This function is called by the IdP to check whether a provided secret matches the stored secret for a client. Returns true if the secret matches, false otherwise.
     *
     * @param attempt The secret to check
     * @param stored The secret stored for the client
     *
     * @returns {Promise<boolean>}
     * @example ```typescript
     * async (attempt, stored) => {
     *  return bcrypt.compare(attempt, stored);
     * }
     * ```
     */
  validateClientSecret: (attempt: string, storedSecret: string) => Promise<boolean>
}
