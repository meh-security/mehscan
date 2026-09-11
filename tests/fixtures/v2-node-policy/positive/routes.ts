app.use('/downloads', middleware, serveIndex('downloads', { icons: true }))
app.get('/metrics', metricsHandler)
finale.resource({ model: UserModel, excludeAttributes: ['password'] })

declare const app: any
declare const middleware: any
declare const serveIndex: any
declare const metricsHandler: any
declare const finale: any
declare const UserModel: any
