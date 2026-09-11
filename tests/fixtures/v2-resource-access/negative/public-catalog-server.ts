import * as delivery from './public-catalog'

declare const app: any
declare const utils: any

app.get('/api/delivery-methods', utils.asyncHandler(delivery.listDeliveryMethods()))
app.get('/api/delivery-methods/:id', utils.asyncHandler(delivery.getDeliveryMethod()))
