package fixture

import (
	"database/sql"
	"fmt"
)

var DB *sql.DB

func UnsafeQuery(uid string) error {
	query := fmt.Sprintf("SELECT * FROM users WHERE id=%s", uid)
	_, err := DB.Query(query)
	return err
}

func SafeQuery(uid string) error {
	statement, err := DB.Prepare("SELECT * FROM users WHERE id=?")
	if err != nil {
		return err
	}
	_, err = statement.Query(uid)
	return err
}

func SafeDynamicPrepare(uid string) error {
	query := "SELECT * FROM users WHERE id=?"
	statement, err := DB.Prepare(query)
	if err != nil {
		return err
	}
	return statement.QueryRow(uid).Err()
}
