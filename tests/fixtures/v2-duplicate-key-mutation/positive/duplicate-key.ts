declare const BasketItemModel: any
declare const parsePairs: (raw: string) => Array<{ key: string, value: string }>

interface RequestWithRawBody {
  rawBody: string
}

export async function addBasketItem (req: RequestWithRawBody, res: any) {
  const result = parsePairs(req.rawBody)
  const basketIds = []
  for (let i = 0; i < result.length; i++) {
    if (result[i].key === 'BasketId') {
      basketIds.push(result[i].value)
    }
  }
  if (req.user.id !== basketIds[0]) {
    res.status(401).send('invalid basket')
  } else {
    const basketItem = { BasketId: basketIds[basketIds.length - 1] }
    const instance = BasketItemModel.build(basketItem)
    await instance.save()
  }
}
