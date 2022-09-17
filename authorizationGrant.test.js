import {
  IdP
} from './dist/index'
import bcrypt from 'bcrypt'
import jsonwebtoken from 'jsonwebtoken'

const stores = {
  clients: [{
    id: '1',
    name: 'test',
    secret: 'test',
    redirectUris: ['http://localhost:3000']
  }],
  users: [{
    id: '1',
    name: 'chris'
  }],
  resources: [{
    id: '1',
    name: 'resource1',
    owner: '1'
  }],
  authorizationCodes: [],
  accessTokens: [],
  refreshTokens: []
}

const options = {
  handlers: {
    storeAuthorizationGrant: async (grant) => {
      const id = stores.authorizationCodes.length + 1
      stores.authorizationCodes.push({
        id: id.toString(),
        ...grant
      })
      return {
        id: id.toString(),
        ...grant
      }
    },
    getAuthorizationGrant: (id) => {
      return stores.authorizationCodes.find((grant) => grant.id === id)
    },
    revokeGrant: (id) => {
      stores.authorizationCodes = stores.authorizationCodes.filter((grant) => grant.id !== id)
    },
    storeAccessToken: (token) => {
      const id = stores.accessTokens.length + 1
      stores.accessTokens.push({
        id: id.toString(),
        ...token
      })
      return {
        id: id.toString(),
        ...token
      }
    },
    getAccessToken: (id) => {
      return stores.accessTokens.find((token) => token.id === id)
    },
    revokeAccessToken: (id) => {
      stores.accessTokens = stores.accessTokens.filter((token) => token.id !== id)
    },
    getClient: (id) => {
      return stores.clients.find((client) => client.id === id)
    },
    validateClientSecret: (attempt, storedSecret) => {
      return attempt === storedSecret
    },
    storeRefreshToken: (token) => {
      const id = stores.refreshTokens.length + 1
      stores.refreshTokens.push({
        id: id.toString(),
        ...token
      })
      return {
        id: id.toString(),
        ...token
      }
    },
    getRefreshToken: (id) => {
      return stores.refreshTokens.find((token) => token.id === id)
    },
    revokeRefreshToken: (id) => {
      stores.refreshTokens = stores.refreshTokens.filter((token) => token.id !== id)
    }
  },
  secret: '70337336763979244226452948404D635166546A576E5A7234743777217A2543'
}

describe('Authorization code flow', () => {
  it('should initialise an IdP object', () => {
    const idp = new IdP(options)
    expect(idp).toBeDefined()
  })

  it('should generate an authorization code', async () => {
    const idp = new IdP(options)
    const grant = await idp.generateAuthorizationCode({
      user: '1',
      scope: 'write',
      client: '1',
      redirectUri: 'http://localhost:3000'
    })

    // Decode the JWT
    const decodedJWT = jsonwebtoken.verify(grant, options.secret)
    // Retrieve the grant which was stored by the IdP
    const storedCode = stores.authorizationCodes.find((code) => code.id === decodedJWT.id)

    const match = await bcrypt.compare(decodedJWT.code, storedCode.code)
    expect(match).toBeTruthy()
  })

  it('should exchange an authorization code for an access token', async () => {
    const idp = new IdP(options)

    // Obtain an authorization code
    const grant = await idp.generateAuthorizationCode({
      user: '1',
      scope: 'write',
      client: '1',
      redirectUri: 'http://localhost:3000'
    })

    // Exchange the token
    const token = await idp.exchangeCode({
      code: grant,
      client: '1',
      redirectUri: 'http://localhost:3000',
      clientSecret: 'test'
    })

    // Decode the JWT
    const decodedAccessToken = jsonwebtoken.verify(token.accessToken, options.secret)

    // Make sure the decoded data from the JWT matches the data stored in the database by the IdP
    const storedToken = stores.accessTokens.find((token) => token.id === decodedAccessToken.id)
    expect(storedToken).toBeDefined()

    const match = await bcrypt.compare(decodedAccessToken.token, storedToken.token)
    expect(match).toBeTruthy()

    // Check that the authorization code has been revoked
    const storedCode = stores.authorizationCodes.find((code) => code.id === grant.id)
    expect(storedCode).toBeUndefined()
  })

  it('should exchange a refresh token for a new access token', async () => {
    const idp = new IdP(options)

    // Obtain an authorization code
    const grant = await idp.generateAuthorizationCode({
      user: '1',
      scope: 'write',
      client: '1',
      redirectUri: 'http://localhost:3000'
    })

    // Exchange the token
    const token = await idp.exchangeCode({
      code: grant,
      client: '1',
      redirectUri: 'http://localhost:3000',
      clientSecret: 'test'
    })

    // Decode the refresh token JWT
    const decodedRefreshToken = jsonwebtoken.verify(token.refreshToken, options.secret)

    // Check that the refresh token has been stored
    const storedRefreshToken = stores.refreshTokens.find((token) => token.id === decodedRefreshToken.id)
    expect(storedRefreshToken).toBeDefined()

    // Check that the refresh token matches the one stored in the database
    const refreshTokenMatch = await bcrypt.compare(decodedRefreshToken.token, storedRefreshToken.token)
    expect(refreshTokenMatch).toBeTruthy()

    // Exchange the refresh token for a new access token
    const newToken = await idp.exchangeRefreshToken({
      refreshToken: token.refreshToken,
      client: '1',
      clientSecret: 'test'
    })

    // Decode the new access token
    const decodedNewAccessToken = jsonwebtoken.verify(newToken.accessToken, options.secret)

    // Check that the new access token has been stored
    const storedNewAccessToken = stores.accessTokens.find((token) => token.id === decodedNewAccessToken.id)

    // Check that the new access token matches the one stored in the database
    const newAccessTokenMatch = await bcrypt.compare(decodedNewAccessToken.token, storedNewAccessToken.token)

    expect(newAccessTokenMatch).toBeTruthy()
  })

  it('should verify an access token', async () => {
    const idp = new IdP(options)

    // Obtain an authorization code
    const grant = await idp.generateAuthorizationCode({
      user: '1',
      scope: 'write',
      client: '1',
      redirectUri: 'http://localhost:3000'
    })

    // Exchange the token
    const token = await idp.exchangeCode({
      code: grant,
      client: '1',
      redirectUri: 'http://localhost:3000',
      clientSecret: 'test'
    })

    const verification = await idp.verifyAccessToken({
      token: token.accessToken,
      user: '1',
      scope: 'write'
    })

    expect(verification).toBeDefined()
  })

  it('should return error on invalid client', async () => {
    const idp = new IdP(options)

    const t = async () => {
      // Obtain an authorization code
      await idp.generateAuthorizationCode({
        user: '1',
        scope: 'write',
        // Invalid client ID
        client: '2',
        redirectUri: 'http://localhost:3000'
      })
    }

    await expect(t).rejects.toThrow('Invalid client')
  })

  it('should return error on invalid redirectUri', async () => {
    const idp = new IdP(options)

    const t = async () => {
      // Obtain an authorization code
      await idp.generateAuthorizationCode({
        user: '1',
        scope: 'write',
        client: '1',
        // Invalid redirect URI
        redirectUri: 'http://localhost:3001'
      })
    }

    await expect(t).rejects.toThrow('Invalid redirect URI')
  })

  it('should return error on invalid client secret (exchange)', async () => {
    const idp = new IdP(options)

    const grant = await idp.generateAuthorizationCode({
      user: '1',
      scope: 'write',
      client: '1',
      redirectUri: 'http://localhost:3000'
    })

    const t = async () => {
      // Exchange the token
      await idp.exchangeCode({
        code: grant,
        client: '1',
        redirectUri: 'http://localhost:3000',
        // Invalid client secret
        clientSecret: 'test2'
      })
    }

    await expect(t).rejects.toThrow('Invalid client secret')
  })
})
