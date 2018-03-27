package common

import (
	"encoding/json"
	"time"
)

var Cfg struct {
	InitDB              bool
	Location            string
	SigningKey          string
	JwtExpire           int
	HostAddr            string
	HostPort            string
	DisableRegistration bool
	VaultURL            string
	Email               string
	EmailPassword       string
	EmailPort           int
	SmptServer          string
	PrintInvite         bool
	UseHTTPS            bool
	Key                 string
	Crt                 string
}

type KeyPair struct {
	EncryptedPrivateKey string `json:"encryptedPrivateKey"`
	PublicKey           string `json:"publicKey"`
}

type Attachments []AttachmentData
type OrgUsers []OrgUser
type OrgUserswId []OrgUserwId
type OrganizationsData []OrgData
type CollectionIds []string
type Fields []Field
type Ciphers []Cipher
type CiphersPost []CipherPost
type Uriss []Uris

type Account struct {
	Id                 string            `json:"id"`
	Name               string            `json:"name"`
	Email              string            `json:"email"`
	MasterPasswordHash string            `json:"masterPasswordHash"`
	MasterPasswordHint string            `json:"masterPasswordHint"`
	Key                string            `json:"key"`
	Organizations      OrganizationsData `json:"Organizations"`
	KeyPair            KeyPair           `json:"keys"`
	RefreshToken       string            `json:"-"`
	TwoFactorSecret    string            `json:"-"`
}

type Publickey struct {
	UserId    string
	PublicKey string
	Object    string
}

func (acc Account) GetProfile() Profile {
	p := Profile{
		Id:                 acc.Id,
		Name:               nil,
		Email:              acc.Email,
		EmailVerified:      true,
		Premium:            true,
		Culture:            "en-US",
		Key:                acc.Key,
		SecurityStamp:      nil,
		Organizations:      acc.Organizations,
		MasterPasswordHint: nil,
		PrivateKey:         acc.KeyPair.EncryptedPrivateKey,
		Object:             "profile",
	}

	if len(acc.TwoFactorSecret) > 0 {
		p.TwoFactorEnabled = true
	}

	return p
}

type AttachmentData struct {
	Id       string
	Url      string
	FileName string
	Size     int64
	SizeName string
	Object   string
}

func (attachments *Attachments) Bytes() ([]byte, error) {
	b, err := json.Marshal(attachments)
	return b, err
}
func (organizationsData *OrganizationsData) Bytes() ([]byte, error) {
	b, err := json.Marshal(organizationsData)
	return b, err
}

type Profile struct {
	Id                 string
	Name               *string
	Email              string
	EmailVerified      bool
	Premium            bool
	MasterPasswordHint *string
	Culture            string
	TwoFactorEnabled   bool
	Key                string
	PrivateKey         string
	SecurityStamp      *string
	Organizations      OrganizationsData
	Object             string
}

type SyncData struct {
	Profile Profile
	Folders []Folder
	Ciphers interface{}
	Domains Domains
	Object  string
}

type CollectionId struct {
	CollectionId string
}

type Domains struct {
	EquivalentDomains       []string
	GlobalEquivalentDomains []GlobalEquivalentDomains
	Object                  string
}

type GlobalEquivalentDomains struct {
	Type     int
	Domains  []string
	Excluded bool
}

type Folder struct {
	Id           string
	Name         string
	Object       string
	RevisionDate time.Time
}

type Data struct {
	Object string
	Data   interface{}
}
type PostCiphers struct { //used
	Data              CiphersPost
	ContinuationToken *string
	Object            string
}

type Cipher struct {
	CollectionIds       *CollectionIds
	FolderId            *string
	Favorite            bool
	Edit                bool
	Id                  *string
	OrganizationId      *string
	Type                int
	Data                interface{}
	DataL               *CipherDataLogin
	DataC               *CipherDataCard
	DataI               *CipherDataIdentity
	Name                *string
	Notes               *string
	Login               *Login
	Card                *Card
	Identity            *Identity
	SecureNote          *SecureNote
	Fields              *Fields
	Attachments         *Attachments
	OrganizationUseTotp bool
	RevisionDate        time.Time
	Object              *string
}
type CipherPost struct {
	CollectionIds       *CollectionIds
	FolderId            *string
	Favorite            bool
	Edit                bool
	Id                  *string
	OrganizationId      *string
	Type                int
	Data                interface{}
	Name                *string
	Notes               *string
	Login               *Login
	Card                *Card
	Identity            *string
	SecureNote          *string
	Fields              *Fields
	Attachments         *Attachments
	OrganizationUseTotp bool
	RevisionDate        time.Time
	Object              string //cipher
}

type CipherMiniLogin struct {
	CollectionIds  *CollectionIds
	FolderId       *string
	Favorite       bool
	Edit           bool
	Id             string
	OrganizationId *string
	Type           int
	Data           *CipherDataLogin
	Name           *string
	//Notes 						*string
	Login               *Login
	Card                *string
	Identity            *string
	SecureNote          *string
	Fields              *Fields
	Attachments         *Attachments
	OrganizationUseTotp bool
	RevisionDate        time.Time
	Object              string //cipherMiniDetails
}

type CipherPostLogin struct {
	FolderId            *string
	Favorite            bool
	Edit                bool
	Id                  *string
	OrganizationId      *string
	Type                int
	Data                *CipherDataLogin
	Name                *string
	Notes               *string
	Login               *Login
	Card                *string
	Identity            *string
	SecureNote          *string
	Fields              *Fields
	Attachments         *Attachments
	OrganizationUseTotp bool
	RevisionDate        time.Time
	Object              string //cipher
}
type Login struct {
	Uri      *string
	Uris     *Uriss
	Username *string
	Password *string
	Totp     *string
}

func (Login *Login) Bytes() (*[]byte, error) {
	b, err := json.Marshal(Login)
	return &b, err
}

type CipherDataLogin struct {
	Uri      *string
	Uris     Uriss
	Username *string
	Password *string
	Totp     *string // Must be pointer to output null in json. Android app will crash if not null
	Name     *string
	Notes    *string
	Fields   *Fields
}

func (CipherDataLogin *CipherDataLogin) Bytes() ([]byte, error) {
	b, err := json.Marshal(CipherDataLogin)
	return b, err
}

type CipherMiniCard struct {
	CollectionIds       CollectionIds
	Id                  string
	OrganizationId      string
	Type                int
	Data                CipherDataCard
	Name                string
	Login               string
	Card                Card
	Identity            string
	SecureNote          string
	Fields              string
	Attachments         Attachments
	OrganizationUseTotp bool
	RevisionDate        time.Time
	Object              string //cipherMiniDetails
}

type Card struct {
	CardholderName *string
	Brand          *string
	Number         *string
	ExpMonth       *string
	ExpYear        *string
}

func (Card *Card) Bytes() (*[]byte, error) {
	b, err := json.Marshal(Card)
	return &b, err
}

type CipherDataCard struct {
	CardholderName *string
	Brand          *string
	Number         *string
	ExpMonth       *string
	ExpYear        *string
	Code           *string
	Name           *string
	Notes          *string
	Fields         *Fields
}

func (CipherDataCard *CipherDataCard) Bytes() ([]byte, error) {
	b, err := json.Marshal(CipherDataCard)
	return b, err
}

type ChipherMiniIdentity struct {
	CollectionIds       CollectionIds
	Id                  string
	OrganizationId      string
	Type                int
	Data                CipherDataIdentity
	Name                string
	Login               string
	Card                string
	Identity            Identity
	SecureNote          string
	Fields              string
	Attachments         Attachments
	OrganizationUseTotp bool
	RevisionDate        time.Time
	Object              string //cipherMiniDetails
}
type Identity struct {
	Tilte          string
	FirstName      string
	MiddleName     string
	LastName       string
	Address1       string
	Address2       string
	City           string
	State          string
	PostalCode     string
	Country        string
	Company        string
	Email          string
	Phone          string
	SSN            string
	Username       string
	PassportNumber string
	LicenseNumber  string
}

func (Identity *Identity) Bytes() ([]byte, error) {
	b, err := json.Marshal(Identity)
	return b, err
}

type CipherDataIdentity struct {
	Tilte          string
	FirstName      string
	MiddleName     string
	LastName       string
	Address1       string
	Address2       string
	City           string
	State          string
	PostalCode     string
	Country        string
	Company        string
	Email          string
	Phone          string
	SSN            string
	Username       string
	PassportNumber string
	LicenseNumber  string
	Name           string
	Notes          string
	Fields         []Fields
}

func (CipherDataIdentity *CipherDataIdentity) Bytes() ([]byte, error) {
	b, err := json.Marshal(CipherDataIdentity)
	return b, err
}

type SecureNote struct {
}

type Uris struct {
	Uri   *string
	Match *int
}
type Field struct {
	Type  int
	Name  string
	Value string
}

func (Fields *Fields) Bytes() ([]byte, error) {
	b, err := json.Marshal(Fields)
	return b, err
}

func (CollectionIds *CollectionIds) Bytes() ([]byte, error) {
	b, err := json.Marshal(CollectionIds)
	return b, err
}

type OrgData struct {
	Id             string
	Name           string
	UseGroups      bool
	UseEvents      bool
	UseDirectory   bool
	UseTotp        bool
	Seats          int
	MaxCollections int
	MaxStorageGb   int
	Key            string
	Status         int
	Type           int
	Enabled        bool
	Object         string
}

type OrgUser struct {
	Id        string
	UserId    string
	Name      string
	Email     string
	Status    int
	Type      int
	AccessAll bool
	Object    string
}
type OrgUserwId struct {
	Id        string // Organization User Id
	OrgId     string
	UserId    string //User
	Name      string
	Email     string
	Status    int
	Type      int
	AccessAll bool
	Object    string
}
type Organizationusers struct {
	Data              OrgUsers
	ContinuationToken *string
	Object            string
}
type OrganizationUserswId struct {
	Data              OrgUserswId
	ContinuationToken *string
	Object            string
}

type Collection struct {
	Data              []CollectionData
	ContinuationToken *string
	Object            string
}

type CollectionData struct {
	Id             string
	OrganizationId string
	Name           string
	Object         string
}
