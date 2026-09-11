export const sessions = {
  tokenMap: {},
  put: function (token: string, user: object) {
    this.tokenMap[token] = user
  },
  get: function (token: string) {
    return this.tokenMap[token]
  }
}
