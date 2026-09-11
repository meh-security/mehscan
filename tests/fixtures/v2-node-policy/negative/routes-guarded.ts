app.use('/downloads', security.isAuthorized(), serveIndex('downloads', { icons: true }))
app.get('/metrics', security.isAccounting(), metricsHandler)

declare const app: any
declare const security: any
declare const serveIndex: any
declare const metricsHandler: any
