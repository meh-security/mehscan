import { DataTypes } from 'sequelize'

export const UserModel: any = {}
UserModel.init({
  email: { type: DataTypes.STRING },
  role: { type: DataTypes.STRING },
  isActive: { type: DataTypes.BOOLEAN }
})

export const ProductModel: any = {}
ProductModel.init({
  name: { type: DataTypes.STRING },
  description: { type: DataTypes.STRING }
})
