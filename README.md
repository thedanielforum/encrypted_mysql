# encrypted_mysql
Encrypted type for mysql golang

You will need to set the secret with a env variable `ENCRYPTED_MYSQL_SECRET`.
This secret needs to be 32 bytes long, this will encrypt you data with AES 256.

Just use the encrypted type and it will encrypt and decrypt the data on read/write.
```go
import encrypted "github.com/thedanielforum/encrypted_mysql"

type User struct {
    ID      int64
    Name    string
	Address encrypted.Encrypted
}

// new user
u := &User{
    Name: "Kim Bob Kim",
	Address: encrypted.Encrypted("123 very secret address"),
}
// insert user!
_, err = db.Exec(
	`INSERT INTO users (name, address) VALUES (?, ?)`,
    u.Name,
    u.Address,
)

// The inserted data would be something like
// name: Kim Bob Kim
// address: 056694843abc07a1f371be05db37be33b1

// get the customer record
rows, _ := db.Query(`SELECT id, name, address FROM test ORDER BY id DESC LIMIT 1`)

// close the rows at the end of the function
defer rows.Close()
for rows.Next() {
	foundUser := new(User)
	if err := rows.Scan(
		&foundUser.ID,
        &foundUser.Name,
        &foundUser.Address,
	);
	// time to print our customers!!
	fmt.Printf("%+v", foundUser)
}
```
