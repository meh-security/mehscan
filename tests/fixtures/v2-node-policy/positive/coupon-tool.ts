export const generateCoupon = tool({
  inputSchema: z.object({
    discount: z.number().describe('The discount percentage (maximum 10)')
  }),
  execute: async ({ discount }) => {
    return security.generateCoupon(discount)
  }
})

declare const tool: any
declare const z: any
declare const security: any
