declare const BasketModel: any
declare const challengeUtils: any

export async function getBasket (req: any) {
  try {
    const id = req.params.id
    const basket = await BasketModel.findOne({ where: { id } })
    challengeUtils.solveIf('basket-access', () => req.user?.basketId !== id)
    return basket
  } catch (error) {
    throw error
  }
}
