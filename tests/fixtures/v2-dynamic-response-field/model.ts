declare const User: any
declare const DataTypes: any

User.init({
  id: { type: DataTypes.INTEGER },
  email: { type: DataTypes.STRING },
  password: { type: DataTypes.STRING },
  totpSecret: { type: DataTypes.STRING }
})
