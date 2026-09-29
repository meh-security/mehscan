package app

import (
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type User struct {
	Email string
}

func structuredValue(db *gorm.DB, email string) {
	db.Where(User{Email: email}).First(&User{})
}

func structuredPointer(db *gorm.DB, email string) {
	db.Where(&User{Email: email}).First(&User{})
}

func structuredMap(db *gorm.DB, email string) {
	db.Where(map[string]any{"email": email}).First(&User{})
}

func structuredParameter(db *gorm.DB, condition *User) {
	db.Where(condition).First(&User{})
}

func structuredMapParameter(db *gorm.DB, condition map[string]any) {
	db.Where(condition).First(&User{})
}

func unknownCondition(db *gorm.DB, condition interface{}) {
	db.Where(condition).First(&User{})
}

func stringCondition(db *gorm.DB, condition string) {
	db.Where(condition).First(&User{})
}

func rawExpression(db *gorm.DB, name string) {
	db.Where(clause.Expr{SQL: "name = '" + name + "'"}).First(&User{})
}

func composedCondition(db *gorm.DB, name string) {
	db.Where("name = '" + name + "'").First(&User{})
}

func boundCondition(db *gorm.DB, email string) {
	db.Where("email = ?", email).First(&User{})
}
