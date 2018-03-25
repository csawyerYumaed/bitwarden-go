package sqlite

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"path"
	"strconv"
	"time"

	bw "github.com/Odysseus16/bitwarden-go/internal/common"
	_ "github.com/mattn/go-sqlite3"
	uuid "github.com/satori/go.uuid"
)

type DB struct {
	db  *sql.DB
	dir string
}

const acctTbl = `
CREATE TABLE IF NOT EXISTS "accounts" (
  id                  INTEGER,
  name                TEXT,
  email               TEXT UNIQUE,
  masterPasswordHash  NUMERIC,
  masterPasswordHint  TEXT,
  key                 TEXT,
  refreshtoken        TEXT,
  privatekey          TEXT NOT NULL,
  pubkey              TEXT NOT NULL,
  tfasecret           TEXT NOT NULL,
	organization				REAL,
PRIMARY KEY(id)
)`

const orgUsersTbl = `
CREATE TABLE IF NOT EXISTS "organizations" (
	id             TEXT,
	orgId					 Text,
	userId				 Text,
	name           TEXT,
	email          TEXT,
	status				 INTEGER,
	type					 INTEGER,
PRIMARY KEY(id)
)`

const cipherMiniTbl = `
CREATE TABLE IF NOT EXISTS "ciphermini" (
	collectionids	 			REAL,
	folderId Text,
	favorite INTEGER,
	edit INTEGER,
	id             			TEXT,
	organizationid			TEXT,
	type 								INT,
	data 								REAL,
	name								TEXT,
	notes TEXT,
	login 							REAL,
	card 								REAL,
	identity 						REAL,
	securenote 					TEXT,
	fields 							REAL,
	attachments 				REAL,
	organizationusetotp INT,
	revisionDate        INT,
	object              string,
	owner string,
PRIMARY KEY(id)
)`

const ciphersTbl = `
CREATE TABLE IF NOT EXISTS "ciphers" (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  type         INT,
  revisiondate INT,
  data         REAL,
  owner        INT,
  folderid     TEXT,
  attachments  REAL,
  favorite     INT NOT NULL
)
`
const foldersTbl = `
CREATE TABLE IF NOT EXISTS "folders" (
  id           TEXT,
  name         TEXT,
  revisiondate INTEGER,
  owner        INTEGER,
PRIMARY KEY(id)
)
`
const collectionTable = `
CREATE TABLE IF NOT EXISTS "collection" (
	id TEXT,
	organizationid TEXT,
	name TEXT,
	object TEXT,
PRIMARY KEY(id)
)
`

func (db *DB) Init() error {
	for _, sql := range []string{acctTbl, ciphersTbl, orgUsersTbl, foldersTbl, collectionTable, cipherMiniTbl} {
		if _, err := db.db.Exec(sql); err != nil {
			return errors.New(fmt.Sprintf("SQL error with %s\n%s", sql, err.Error()))
		}
	}
	return nil
}

func (db *DB) SetDir(d string) {
	db.dir = d
}

func (db *DB) Open() error {
	var err error
	if db.dir != "" {
		db.db, err = sql.Open("sqlite3", path.Join(db.dir, "db"))
	} else {
		db.db, err = sql.Open("sqlite3", "db")
	}
	return err
}

func (db *DB) Close() {
	db.db.Close()
}

func (db *DB) AddAccount(acc bw.Account) error {
	stmt, err := db.db.Prepare("INSERT INTO accounts(name, email, masterPasswordHash, masterPasswordHint, key, refreshtoken, privatekey, pubkey, tfasecret, organization) values(?,?,?,?,?,?,?,?,?,?)")
	if err != nil {
		return err
	}
	organization, err := acc.Organizations.Bytes()
	if err != nil {
		return err
	}
	_, err = stmt.Exec(acc.Name, acc.Email, acc.MasterPasswordHash, acc.MasterPasswordHint, acc.Key, "", "", "", "", organization)
	if err != nil {
		return err
	}

	return nil
}

func (db *DB) UpdateAccountInfo(acc bw.Account) error {
	id, err := strconv.ParseInt(acc.Id, 10, 64)
	if err != nil {
		return err
	}

	stmt, err := db.db.Prepare("UPDATE accounts SET refreshtoken=$1, privatekey=$2, pubkey=$3, organization =$4 WHERE id=$5")
	if err != nil {
		return err
	}
	organization, err := acc.Organizations.Bytes()
	if err != nil {
		return err
	}
	_, err = stmt.Exec(acc.RefreshToken, acc.KeyPair.EncryptedPrivateKey, acc.KeyPair.PublicKey, organization, id)
	if err != nil {
		return err
	}

	return nil
}

func (db *DB) GetAccount(username string, refreshtoken string) (bw.Account, error) {
	var row *sql.Row
	acc := bw.Account{}
	acc.KeyPair = bw.KeyPair{}
	if username != "" {
		query := "SELECT * FROM accounts WHERE email = $1"
		row = db.db.QueryRow(query, username)
	}

	if refreshtoken != "" {
		query := "SELECT * FROM accounts WHERE refreshtoken = $1"
		row = db.db.QueryRow(query, refreshtoken)
	}
	var blob []byte
	var iid int
	err := row.Scan(&iid, &acc.Name, &acc.Email, &acc.MasterPasswordHash, &acc.MasterPasswordHint, &acc.Key, &acc.RefreshToken, &acc.KeyPair.EncryptedPrivateKey, &acc.KeyPair.PublicKey, &acc.TwoFactorSecret, &blob)
	if err != nil {
		return acc, err
	}

	if len(blob) > 0 {
		err = json.Unmarshal(blob, &acc.Organizations)
		if err != nil {
			log.Println(err)
			return acc, err
		}
	} else {
		acc.Organizations = bw.OrganizationsData{}
	}
	acc.Id = strconv.Itoa(iid)

	return acc, nil
}

func (db *DB) GetID(id string) (bw.Account, error) {
	var row *sql.Row
	acc := bw.Account{}
	acc.KeyPair = bw.KeyPair{}
	if id != "" {
		query := "SELECT * FROM accounts WHERE id = $1"
		row = db.db.QueryRow(query, id)
	}
	var blob []byte
	var iid int
	err := row.Scan(&iid, &acc.Name, &acc.Email, &acc.MasterPasswordHash, &acc.MasterPasswordHint, &acc.Key, &acc.RefreshToken, &acc.KeyPair.EncryptedPrivateKey, &acc.KeyPair.PublicKey, &acc.TwoFactorSecret, &blob)
	if err != nil {
		return acc, err
	}
	if len(blob) > 0 {
		err = json.Unmarshal(blob, &acc.Organizations)
		if err != nil {
			return acc, err
		}
	} else {
		acc.Organizations = bw.OrganizationsData{}
	}
	acc.Id = strconv.Itoa(iid)

	return acc, nil
}

func (db *DB) AddFolder(name string, owner string) (bw.Folder, error) {
	iowner, err := strconv.ParseInt(owner, 10, 64)
	if err != nil {
		return bw.Folder{}, err
	}

	newFolderID, err := uuid.NewV4()
	if err != nil {
		return bw.Folder{}, err
	}

	folder := bw.Folder{
		Id:           newFolderID.String(),
		Name:         name,
		Object:       "folder",
		RevisionDate: time.Now(),
	}

	stmt, err := db.db.Prepare("INSERT INTO folders(id, name, revisiondate, owner) values(?,?,?, ?)")
	if err != nil {
		return bw.Folder{}, err
	}

	_, err = stmt.Exec(folder.Id, folder.Name, folder.RevisionDate.Unix(), iowner)
	if err != nil {
		return bw.Folder{}, err
	}

	return folder, nil
}

func (db *DB) UpdateFolder(newFolder bw.Folder, owner string) error {
	iowner, err := strconv.ParseInt(owner, 10, 64)
	if err != nil {
		return err
	}

	stmt, err := db.db.Prepare("UPDATE folders SET name=$1, revisiondate=$2 WHERE id=$3 AND owner=$4")
	if err != nil {
		return err
	}

	_, err = stmt.Exec(newFolder.Name, newFolder.RevisionDate.Unix(), newFolder.Id, iowner)
	if err != nil {
		return err
	}

	return nil
}

func (db *DB) GetFolders(owner string) ([]bw.Folder, error) {
	iowner, err := strconv.ParseInt(owner, 10, 64)
	if err != nil {
		return nil, err
	}

	var folders []bw.Folder
	query := "SELECT id, name, revisiondate FROM folders WHERE owner = $1"
	rows, err := db.db.Query(query, iowner)
	if err != nil {
		return nil, err
	}

	var revDate int64
	for rows.Next() {
		f := bw.Folder{}
		err := rows.Scan(&f.Id, &f.Name, &revDate)
		if err != nil {
			return nil, err
		}
		f.RevisionDate = time.Unix(revDate, 0)

		folders = append(folders, f)
	}

	if len(folders) < 1 {
		folders = make([]bw.Folder, 0) // Make an empty slice if there are none or android app will crash
	}
	return folders, err
}

func (db *DB) Update2FAsecret(secret string, email string) error {
	stmt, err := db.db.Prepare("UPDATE accounts SET tfasecret=$1 WHERE email=$2")
	if err != nil {
		return err
	}

	_, err = stmt.Exec(secret, email)
	if err != nil {
		return err
	}

	return nil
}

func (db *DB) AddOrgUser(user bw.OrgUserwId) error {
	stmt, err := db.db.Prepare("INSERT INTO organizations(id, orgId, userId, name, email, status, type ) values(?,?,?,?,?,?, ?)")
	if err != nil {
		log.Println(err)
		return err
	}
	_, err = stmt.Exec(user.Id, user.OrgId, user.UserId, user.Name, user.Email, user.Status, user.Type)
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}

func (db *DB) UpdateOrgUser(user bw.OrgUserwId) error {
	stmt, err := db.db.Prepare("UPDATE organizations SET id=$1, orgId=$2, userId=$3, name=$4, status=$5, type=$6 WHERE email=$7")
	if err != nil {
		return err
	}
	_, err = stmt.Exec(user.Id, user.OrgId, user.UserId, user.Name, user.Status, user.Type, user.Email)
	if err != nil {
		return err
	}

	return nil
}
func (db *DB) GetOrgUsers(orgId string) (bw.OrgUserswId, error) {
	var users bw.OrgUserswId
	query := "SELECT id, orgId, userId, name, email, status, type FROM organizations WHERE orgId = $1"
	rows, err := db.db.Query(query, orgId)

	for rows.Next() {
		user, err := sqlRowToUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	if len(users) < 1 {
		users = make([]bw.OrgUserwId, 0) // Make an empty slice if there are none or android app will crash
	}
	return users, err
}

func sqlRowToUser(row interface {
	Scan(dest ...interface{}) error
}) (bw.OrgUserwId, error) {
	user := bw.OrgUserwId{
		AccessAll: true,
		Object:    "organizationUserUserDetails",
	}
	var status, type1 int
	var orgId, userId, name, email, id string
	err := row.Scan(&id, &orgId, &userId, &name, &email, &status, &type1)
	if err != nil {
		return bw.OrgUserwId{}, err
	}
	user.Id = id
	user.OrgId = orgId
	user.UserId = userId
	user.Name = name
	user.Email = email
	user.Status = status
	user.Type = type1
	return user, nil
}

func (db *DB) GetOrgUser(orgUserId string) (bw.OrgUserwId, error) {
	query := "SELECT id, orgId, userId, name, email, status, type FROM organizations WHERE userId = $1"
	row := db.db.QueryRow(query, orgUserId)
	return sqlRowToUser(row)
}
func (db *DB) GetOrgUserbyId(Id string) (bw.OrgUserwId, error) {
	query := "SELECT id, orgId, userId, name, email, status, type FROM organizations WHERE id = $1"
	row := db.db.QueryRow(query, Id)
	return sqlRowToUser(row)
}

func (db *DB) GetOrgUserbyEmail(email string) (bw.OrgUserwId, error) {
	query := "SELECT id, orgId, userId, name, email, status, type FROM organizations WHERE email = $1"
	row := db.db.QueryRow(query, email)
	return sqlRowToUser(row)
}

func (db *DB) AddCollection(collection bw.CollectionData) error {
	stmt, err := db.db.Prepare("INSERT INTO collection(id, organizationid, name, object) values(?,?,?, ?)")
	if err != nil {
		return err
	}
	_, err = stmt.Exec(collection.Id, collection.OrganizationId, collection.Name, collection.Object)
	if err != nil {
		return err
	}
	return nil
}
func sqlRowToCollection(row interface {
	Scan(dest ...interface{}) error
}) (bw.CollectionData, error) {
	collection := bw.CollectionData{}
	var id, organizationId, name, object string
	err := row.Scan(&id, &organizationId, &name, &object)
	if err != nil {
		return collection, err
	}
	collection.Id = id
	collection.OrganizationId = organizationId
	collection.Name = name
	collection.Object = object
	return collection, nil
}

func (db *DB) GetCollection(id string) (bw.CollectionData, error) {
	query := "SELECT id, organizationid, name, object FROM collection WHERE id = $1"
	row := db.db.QueryRow(query, id)
	return sqlRowToCollection(row)
}

func (db *DB) GetCollections(organizationid string) ([]bw.CollectionData, error) {
	var collections []bw.CollectionData
	query := "SELECT id, organizationid, name, object type FROM collection WHERE organizationid = $1"
	rows, err := db.db.Query(query, organizationid)
	if err != nil {
		return []bw.CollectionData{}, err
	}

	for rows.Next() {
		collection, err := sqlRowToCollection(rows)
		if err != nil {
			return nil, err
		}
		collections = append(collections, collection)
	}

	if len(collections) < 1 {
		collections = make([]bw.CollectionData, 0) // Make an empty slice if there are none or android app will crash
	}
	return collections, err
}

//AddCipher adds a cipher to the database
func (db *DB) AddCipher(cipher bw.Cipher, owner string) error {
	var login, card, identity, secureNote *[]byte
	var data []byte
	a := 1
	c := 3
	stmt, err := db.db.Prepare("INSERT INTO ciphermini(collectionids, folderId, favorite, edit, id, organizationid, type, data, name, notes, login, card, identity, securenote, fields, attachments, organizationusetotp, revisiondate, object, owner) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, ?)")
	if err != nil {
		return err
	}
	collectionids, err := cipher.CollectionIds.Bytes()
	if err != nil {
		return err
	}
	switch cipher.Type {
	case a: //Login
		{
			var err0, err1 error
			data, err0 = cipher.DataL.Bytes()
			if err0 != nil {
				return err
			}
			login, err1 = cipher.Login.Bytes()
			if err1 != nil {
				return err
			}
			card = nil
			identity = nil
			secureNote = nil
		}
	case c:
		{
			var err0, err1 error
			data, err0 = cipher.DataC.Bytes()
			if err0 != nil {
				return err
			}
			card, err1 = cipher.Card.Bytes()
			if err1 != nil {
				return err
			}
			login = nil
			identity = nil
			secureNote = nil
		}
	default:
		log.Fatal("Error")
	}
	fields, err := cipher.Fields.Bytes()
	if err != nil {
		return err
	}
	attachmetns, err := cipher.Attachments.Bytes()
	if err != nil {
		return err
	}
	//convert boolean to integer
	favorite := boolToInt(cipher.Favorite)
	edit := boolToInt(cipher.Edit)
	organizationUseTotp := boolToInt(cipher.OrganizationUseTotp)
	_, err = stmt.Exec(collectionids, cipher.FolderId, favorite, edit, cipher.Id, cipher.OrganizationId, cipher.Type, data, cipher.Name, cipher.Notes, login, card, identity, secureNote, fields, attachmetns, organizationUseTotp, cipher.RevisionDate.Unix(), cipher.Object, owner)
	if err != nil {
		return err
	}
	return nil
}

func boolToInt(b bool) int {
	switch b {
	case true:
		{
			return 1
		}
	case false:
		{
			return 0
		}
	}
	return 0
}
func intToBool(i int) bool {

	switch i {
	case 1:
		{
			return true
		}
	case 0:
		{
			return false
		}
	}
	return false
}

func sqlRowToCipher(row interface {
	Scan(dest ...interface{}) error
}) (bw.Cipher, error) {
	cipher := bw.Cipher{}
	var folderId, id, organizationId, name, notes, object *string
	var favorite, edit, type1, organizationUseTotp int
	var revDate int64
	var collectionids, data, login, card, identity, secureNote, fields, attachments []byte
	err := row.Scan(&collectionids, &folderId, &favorite, &edit, &id, &organizationId, &type1, &data, &name, &notes, &login, &card, &identity, &secureNote, &fields, &attachments, &organizationUseTotp, &revDate, &object)
	if err != nil {
		return bw.Cipher{}, err
	}
	if len(collectionids) > 0 {
		err = json.Unmarshal(collectionids, &cipher.CollectionIds)
		if err != nil {
			return cipher, err
		}
	} else {
		cipher.CollectionIds = nil
	}
	switch type1 {
	case 1:
		{
			if len(data) > 0 {
				err = json.Unmarshal(data, &cipher.DataL)
				if err != nil {
					return cipher, err
				}
			} else {
				cipher.DataL = nil
			}
			if len(login) > 0 {
				err = json.Unmarshal(login, &cipher.Login)
				cipher.Card = nil
				cipher.Identity = nil
				cipher.SecureNote = nil
				if err != nil {
					return cipher, err
				}
			} else {
				cipher.Login = nil
			}
		}
	case 3:
		{
			if len(data) > 0 {
				err = json.Unmarshal(data, &cipher.DataC)
				if err != nil {
					return cipher, err
				}
			} else {
				cipher.DataC = nil
			}
			if len(card) > 0 {
				err = json.Unmarshal(card, &cipher.Card)
				cipher.Login = nil
				cipher.Identity = nil
				cipher.SecureNote = nil
				if err != nil {
					return cipher, err
				}
			} else {
				cipher.Card = nil
			}
		}
	default:
		log.Fatal("err")
	}
	if len(fields) > 0 {
		err = json.Unmarshal(fields, &cipher.Fields)
		if err != nil {
			return cipher, err
		}
	} else {
		cipher.Fields = nil
	}
	if len(attachments) > 0 {
		err = json.Unmarshal(attachments, &cipher.Attachments)
		if err != nil {
			return cipher, err
		}
	} else {
		cipher.Attachments = nil
	}
	cipher.FolderId = folderId
	cipher.Id = id
	cipher.OrganizationId = organizationId
	cipher.Name = name
	cipher.Notes = notes
	cipher.Object = object
	cipher.Favorite = intToBool(favorite)
	cipher.Edit = intToBool(edit)
	cipher.Type = type1
	cipher.OrganizationUseTotp = intToBool(organizationUseTotp)
	cipher.RevisionDate = time.Unix(revDate, 0)
	return cipher, nil
}
func (db *DB) GetCiphers(owner string) ([]bw.Cipher, error) {
	var ciphers []bw.Cipher
	query := "SELECT collectionids, folderId, favorite, edit, id, organizationid, type, data, name, notes, login, card, identity, securenote, fields, attachments, organizationusetotp, revisiondate, object FROM ciphermini WHERE owner = $1"
	rows, err := db.db.Query(query, owner)
	if err != nil {
		return []bw.Cipher{}, err
	}
	for rows.Next() {
		cipher, err := sqlRowToCipher(rows)
		if err != nil {
			return nil, err
		}
		ciphers = append(ciphers, cipher)
	}
	if len(ciphers) < 1 {
		ciphers = make([]bw.Cipher, 0) // Make an empty slice if there are none or android app will crash
	}
	return ciphers, err
}

func (db *DB) GetCipher(id string) (bw.Cipher, error) {
	query := "SELECT collectionids, folderId, favorite, edit, id, organizationid, type, data, name, notes, login, card, identity, securenote, fields, attachments, organizationusetotp, revisiondate, object FROM ciphermini WHERE id = $1"
	row := db.db.QueryRow(query, id)
	return sqlRowToCipher(row)
}
func (db *DB) GetCiphersOrg(organization string) ([]bw.Cipher, error) {
	var ciphers []bw.Cipher
	query := "SELECT collectionids, folderId, favorite, edit, id, organizationid, type, data, name, notes, login, card, identity, securenote, fields, attachments, organizationusetotp, revisiondate, object FROM ciphermini WHERE organizationid = $1"
	rows, err := db.db.Query(query, organization)
	if err != nil {
		return []bw.Cipher{}, err
	}
	for rows.Next() {
		cipher, err := sqlRowToCipher(rows)
		if err != nil {
			return nil, err
		}
		ciphers = append(ciphers, cipher)
	}
	if len(ciphers) < 1 {
		ciphers = make([]bw.Cipher, 0) // Make an empty slice if there are none or android app will crash
	}
	return ciphers, err
}

func (db *DB) UpdateCipher(id string, cipher bw.Cipher, owner string) error {
	var login, card, identity, secureNote *[]byte
	var data []byte
	a := 1
	c := 3
	stmt, err := db.db.Prepare("UPDATE ciphermini SET collectionids=$1, folderId=$2, favorite=$3, edit=$4, organizationid=$5, type=$6, data=$7, name=$8, notes=$9, login=$10, card=$11, identity=$12, securenote=$13, fields=$14, attachments=$15, organizationusetotp=$16, revisiondate=$17, object=$18, owner=$19 WHERE id=$20")
	if err != nil {
		return err
	}
	collectionids, err := cipher.CollectionIds.Bytes()
	if err != nil {
		return err
	}
	switch cipher.Type {
	case a: //Login
		{
			var err0, err1 error
			data, err0 = cipher.DataL.Bytes()
			if err0 != nil {
				return err
			}
			login, err1 = cipher.Login.Bytes()
			if err1 != nil {
				return err
			}
			card = nil
			identity = nil
			secureNote = nil
		}
	case c:
		{
			var err0, err1 error
			data, err0 = cipher.DataC.Bytes()
			if err0 != nil {
				return err
			}
			card, err1 = cipher.Card.Bytes()
			if err1 != nil {
				return err
			}
			login = nil
			identity = nil
			secureNote = nil
		}
	default:
		log.Fatal("Error")
	}
	fields, err := cipher.Fields.Bytes()
	if err != nil {
		return err
	}
	attachmetns, err := cipher.Attachments.Bytes()
	if err != nil {
		return err
	}
	//convert boolean to integer
	favorite := boolToInt(cipher.Favorite)
	edit := boolToInt(cipher.Edit)
	organizationUseTotp := boolToInt(cipher.OrganizationUseTotp)
	_, err = stmt.Exec(collectionids, cipher.FolderId, favorite, edit, cipher.OrganizationId, cipher.Type, data, cipher.Name, cipher.Notes, login, card, identity, secureNote, fields, attachmetns, organizationUseTotp, cipher.RevisionDate.Unix(), cipher.Object, owner, cipher.Id)
	if err != nil {
		return err
	}
	return nil
}
func (db *DB) DeleteCipher(id string) error {
	stmt, err := db.db.Prepare("DELETE from ciphermini WHERE id=$1")
	if err != nil {
		return err
	}

	_, err = stmt.Exec(id)
	if err != nil {
		return err
	}
	return nil
}
