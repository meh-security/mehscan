import * as invoice from './authenticated-route'

declare const app: any
declare const security: any
declare const utils: any

app.get('/invoices/:id', security.isAuthorized(), utils.asyncHandler(invoice.getInvoice()))
