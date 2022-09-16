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
  accessTokens: []
}

const options = {
  storeAuthorizationGrant: async (grant) => {
    const id = stores.authorizationCodes.length + 1
    stores.authorizationCodes.push({ id, ...grant })
    return id
  },
  getGrant: (id) => {
    return stores.authorizationCodes.find((grant) => grant.id === id)
  },
  revokeGrant: (id) => {
    stores.authorizationCodes = stores.authorizationCodes.filter((grant) => grant.id !== id)
  },
  storeAccessToken: (token) => {
    const id = stores.accessTokens.length + 1
    stores.accessTokens.push({ id, ...token })
    return id
  },
  getAccessToken: (id) => {
    return stores.accessTokens.find((token) => token.id === id)
  },
  revokeAccessToken: (id) => {
    stores.accessTokens = stores.accessTokens.filter((token) => token.id !== id)
  },
  getClient: (id) => {
    return stores.clients.find((client) => client.id === id)
  }
}

const idp = new IdP({ handlers: options, secret: '1234567890' })

idp.generateAuthorizationCode({
  user: '1',
  scope: 'read',
  client: '1',
  redirectUri: 'http://localhost:3000'
}).then(r => {
  console.log(r)
})
