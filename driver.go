package encrypted

import (
	"database/sql/driver"
	"errors"
)

// Encrypted will be encrypted before data is inserted
type Encrypted string

// Value - Implementation of valuer for database/sql
func (e Encrypted) Value() (driver.Value, error) {
	// value needs to be a base driver.Value type.
	return Encrypt(string(e)), nil
}

// Scan - Implement the database/sql scanner interface
func (e *Encrypted) Scan(value interface{}) error {
	// if value is nil return empty string
	if value == nil {
		*e = Encrypted("")
		return nil
	}
	if s, err := driver.String.ConvertValue(value); err == nil {
		// if this is a string type
		if v, ok := s.([]byte); ok {
			// decrypt
			str := string(v)
			*e = Encrypted(Decrypt(str))
			return nil
		}
	}
	// otherwise, return an error
	return errors.New("failed to scan Encrypted type")
}
