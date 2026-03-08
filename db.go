package main

import (
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"time"

	_ "modernc.org/sqlite"
)

// Database wraps a SQLite connection for key storage.
type Database struct {
	db *sql.DB
}

// NewDatabase opens (or creates) a SQLite database at filepath and ensures the
// keys table exists.
func NewDatabase(filepath string) (*Database, error) {
	db, err := sql.Open("sqlite", filepath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS keys(
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	)`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("create table: %w", err)
	}
	return &Database{db: db}, nil
}

// Close closes the underlying database connection.
func (d *Database) Close() error {
	return d.db.Close()
}

// StoreKey serializes privKey as PKCS1 PEM and inserts it into the database.
// Returns the auto-incremented kid.
func (d *Database) StoreKey(privKey *rsa.PrivateKey, exp int64) (int64, error) {
	pemBytes := SerializePrivateKey(privKey)
	result, err := d.db.Exec("INSERT INTO keys (key, exp) VALUES (?, ?)", pemBytes, exp)
	if err != nil {
		return 0, fmt.Errorf("insert key: %w", err)
	}
	return result.LastInsertId()
}

// GetValidKey returns a non-expired private key from the database, or nil if
// none exist.
func (d *Database) GetValidKey() (*KeyEntry, error) {
	row := d.db.QueryRow(
		"SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid DESC LIMIT 1",
		time.Now().Unix(),
	)
	return scanKeyEntry(row)
}

// GetExpiredKey returns an expired private key from the database, or nil if
// none exist.
func (d *Database) GetExpiredKey() (*KeyEntry, error) {
	row := d.db.QueryRow(
		"SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY kid DESC LIMIT 1",
		time.Now().Unix(),
	)
	return scanKeyEntry(row)
}

// GetAllValidKeys returns all non-expired keys from the database.
func (d *Database) GetAllValidKeys() ([]KeyEntry, error) {
	rows, err := d.db.Query(
		"SELECT kid, key, exp FROM keys WHERE exp > ?",
		time.Now().Unix(),
	)
	if err != nil {
		return nil, fmt.Errorf("query valid keys: %w", err)
	}
	defer rows.Close()

	var entries []KeyEntry
	for rows.Next() {
		var kid int64
		var pemBytes []byte
		var exp int64
		if err := rows.Scan(&kid, &pemBytes, &exp); err != nil {
			return nil, fmt.Errorf("scan key row: %w", err)
		}
		privKey, err := DeserializePrivateKey(pemBytes)
		if err != nil {
			return nil, err
		}
		entries = append(entries, KeyEntry{
			PrivateKey: privKey,
			PublicKey:  &privKey.PublicKey,
			Kid:        strconv.FormatInt(kid, 10),
			Expiry:     exp,
		})
	}
	return entries, rows.Err()
}

// scanKeyEntry scans a single row into a KeyEntry. Returns nil, nil when no
// row is found (sql.ErrNoRows).
func scanKeyEntry(row *sql.Row) (*KeyEntry, error) {
	var kid int64
	var pemBytes []byte
	var exp int64
	if err := row.Scan(&kid, &pemBytes, &exp); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan key: %w", err)
	}
	privKey, err := DeserializePrivateKey(pemBytes)
	if err != nil {
		return nil, err
	}
	return &KeyEntry{
		PrivateKey: privKey,
		PublicKey:  &privKey.PublicKey,
		Kid:        strconv.FormatInt(kid, 10),
		Expiry:     exp,
	}, nil
}

// SerializePrivateKey encodes an RSA private key as PKCS1 PEM bytes.
func SerializePrivateKey(key *rsa.PrivateKey) []byte {
	derBytes := x509.MarshalPKCS1PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derBytes,
	})
}

// DeserializePrivateKey decodes PKCS1 PEM bytes into an RSA private key.
func DeserializePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
