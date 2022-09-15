import { IdP } from './index'

const stores = {
  clients: [{
    id: '1',
    name: 'test'
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
  }
}

describe('Authorization code flow', () => {
  it('should initialise an IdP object', () => {
    const idp = new IdP(options)
    expect(idp).toBeDefined()
  })
})
