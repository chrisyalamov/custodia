import { IdP } from './index.js'

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

const idp = new IdP(options)

idp.generateAuthorizationCode({
  user: '1',
  scope: 'read',
  client: '1',
  redirectUri: 'http://localhost:3000'
}).then(authCode => {
  console.log('Generated an authorization code', authCode)
  console.log('current db state', stores)
  console.log('\n\n\n\n\n\n')

  idp.exchangeCode({
    code: authCode,
    client: '1',
    clientSecret: 'test',
    redirectUri: 'http://localhost:3000'
  }).then(accessToken => {
    console.log('Generated an access token and refresh token', accessToken)
    console.log('current db state', stores)
    console.log('\n\n\n\n\n\n')

    idp.exchangeRefreshToken({
      refreshToken: accessToken.refreshToken,
      client: '1',
      clientSecret: 'test'
    }).then(accessToken => {
      console.log('Generated a new access token and refresh token', accessToken)
      console.log('current db state', stores)
    })
  })
})
