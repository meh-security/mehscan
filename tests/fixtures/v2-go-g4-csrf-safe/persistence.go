package fixture

import "database/sql"

var DB *sql.DB
var profile Profile

type Profile struct{}

func (Profile) UpdateProfile(name, uid string) error {
	statement, err := DB.Prepare("UPDATE profiles SET name=? WHERE user_id=?")
	if err != nil {
		return err
	}
	_, err = statement.Exec(name, uid)
	return err
}

