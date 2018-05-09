package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Odysseus16/bitwarden-go/internal/auth"
	bw "github.com/Odysseus16/bitwarden-go/internal/common"
	"github.com/antonholmquist/jason"
	"github.com/gorilla/mux"
	"github.com/satori/go.uuid"
	"gopkg.in/gomail.v2"
)

var norg neworgData

type APIHandler struct {
	db database
}

func New(db database) APIHandler {
	h := APIHandler{
		db: db,
	}

	return h
}

// Interface to make testing easier
type database interface {
	GetAccount(username string, refreshtoken string) (bw.Account, error)
	UpdateAccountInfo(acc bw.Account) error
	AddFolder(name string, owner string) (bw.Folder, error)
	UpdateFolder(newFolder bw.Folder, owner string) error
	GetFolders(owner string) ([]bw.Folder, error)
	GetID(id string) (bw.Account, error)
	GetOrgUsers(orgId string) (bw.OrgUserswId, error)
	AddOrgUser(user bw.OrgUserwId) error
	GetOrgUser(orgUserId string) (bw.OrgUserwId, error)
	GetOrgUserbyId(Id string) (bw.OrgUserwId, error)
	UpdateOrgUser(user bw.OrgUserwId) error
	AddCollection(collection bw.CollectionData) error
	GetCollection(id string) (bw.CollectionData, error)
	GetCollections(organizationid string) ([]bw.CollectionData, error)
	AddCipher(cipher bw.Cipher, owner string) error
	GetCiphers(owner string) ([]bw.Cipher, error)
	GetCipher(id string) (bw.Cipher, error)
	UpdateCipher(id string, cipher bw.Cipher, owner string) error
	GetCiphersOrg(organization string) ([]bw.Cipher, error)
	DeleteCipher(id string) error
	GetOrgUserbyEmail(email string) (bw.OrgUserwId, error)
}

func (h *APIHandler) HandleKeysUpdate(w http.ResponseWriter, req *http.Request) {
	email := auth.GetEmail(req)

	acc, err := h.db.GetAccount(email, "")
	if err != nil {
		log.Fatal(err)
	}
	decoder := json.NewDecoder(req.Body)
	var kp bw.KeyPair
	err = decoder.Decode(&kp)
	if err != nil {
		log.Fatal(err)
	}
	defer req.Body.Close()

	acc.KeyPair = kp

	h.db.UpdateAccountInfo(acc)
}

func (h *APIHandler) HandleKey(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	userId := vars["userId"]
	acc, err := h.db.GetID(userId)
	if err != nil {
		log.Fatal(err)
	}
	publickey := bw.Publickey{
		UserId:    acc.Id,
		PublicKey: acc.KeyPair.PublicKey,
		Object:    "userKey",
	}
	data, err := json.Marshal(publickey)
	if err != nil {
		log.Fatal(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (h *APIHandler) HandleKeyOrg(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	orgUserId := vars["orgUserId"]
	decoder := json.NewDecoder(req.Body)
	var keyOrg keyOrg
	err := decoder.Decode(&keyOrg)
	if err != nil {
		log.Fatal(err)
	}
	id, err := h.db.GetOrgUserbyId(orgUserId)
	if err != nil {
		log.Fatal(err)
	}
	acc, err := h.db.GetID(id.UserId)
	if err != nil {
		log.Fatal(err)
	}
	acc.Organizations[0].Key = keyOrg.Key
	acc.Organizations[0].Status = 2
	data, err1 := json.Marshal(nil)
	if err != nil {
		log.Fatal(err1)
	}
	err2 := h.db.UpdateAccountInfo(acc)
	if err2 != nil {
		log.Fatal(err2)
	}
	id.Status = 2
	h.db.UpdateOrgUser(id)
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (h *APIHandler) HandleProfile(w http.ResponseWriter, req *http.Request) {
	email := auth.GetEmail(req)

	acc, err := h.db.GetAccount(email, "")
	if err != nil {
		log.Fatal(err)
	}

	prof := acc.GetProfile()

	data, err := json.Marshal(&prof)
	if err != nil {
		log.Fatal(err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (h *APIHandler) HandleCollections(w http.ResponseWriter, req *http.Request) {

	collections := bw.Data{Object: "list", Data: []string{}}
	data, err := json.Marshal(collections)
	if err != nil {
		log.Fatal(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}
func (h *APIHandler) HandleAttachments(w http.ResponseWriter, req *http.Request) {
	email := auth.GetEmail(req)
	vars := mux.Vars(req)
	cipherID := vars["cipherId"]
	file, header, err := req.FormFile("data")
	if err != nil {
		log.Println("[-] Error in req.FormFile ", err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "{'error': %s}", err)
		return
	}
	defer file.Close()
	token, err := uuid.NewV1()
	os.MkdirAll("./attachments/"+cipherID, os.ModePerm)
	f, err := os.OpenFile("./attachments/"+cipherID+"/"+token.String(), os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		log.Println(err)
	}
	defer f.Close()
	io.Copy(f, file)
	cipher, err := h.db.GetCipher(cipherID)
	if err != nil {
		log.Println(err)
	}
	attach := bw.AttachmentData{
		Id:       token.String(),
		Url:      "http://localhost:8000/attachments/" + cipherID + "/" + token.String(), //http or https shouldn´t matter
		FileName: header.Filename,
		Size:     header.Size,
		SizeName: strconv.FormatInt(header.Size, 10) + " Bytes",
		Object:   "attachment",
	}
	*cipher.Attachments = append(*cipher.Attachments, attach)
	h.db.UpdateCipher(*cipher.Id, cipher, email)
	cipherPost := transformCipherToPost(cipher)
	data, err := json.Marshal(cipherPost)
	if err != nil {
		log.Fatal(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func HandleAttachmentGet(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	cipherID := vars["cipherId"]
	attachmetnID := vars["attachmentId"]
	path := "./attachments/" + cipherID + "/" + attachmetnID
	openfile, err := os.Open(path)
	defer openfile.Close()
	if err != nil {
		log.Println(err)
	}
	openfile.Seek(0, 0)
	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, openfile)
}

func (h *APIHandler) HandleCipherPost(w http.ResponseWriter, req *http.Request) {
	email := auth.GetEmail(req)
	v, err := jason.NewObjectFromReader(req.Body)
	if err != nil {
		log.Fatal(err)
	}
	cipherType, err := v.GetInt64("type")
	if err == nil {
		switch cipherType {
		case 1:
			{
				cipher1, err := unmarshalCipher(v, false, "")
				if err != nil {
					log.Fatal(err)
				}
				err1 := h.db.AddCipher(cipher1, email)
				if err1 != nil {
					log.Fatal(err1)
				}
				cipherpost := transformCipherToPost(cipher1)
				data, err := json.Marshal(cipherpost)
				if err != nil {
					log.Fatal(err)
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write(data)
			}
		case 3:
			{
				cipher1, err := unmarshalCard(v, false, "")
				if err != nil {
					log.Fatal(err)
				}
				err1 := h.db.AddCipher(cipher1, email)
				if err1 != nil {
					log.Fatal(err1)
				}
				cipherpost := transformCipherToPost(cipher1)

				data, err := json.Marshal(cipherpost)
				if err != nil {
					log.Fatal(err)
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write(data)
			}
		}
	} else {
		cipherType, err := v.GetInt64("Type")
		if err != nil {
			log.Fatal("Can´t get josn")
		} else {
			switch cipherType {
			case 1:
				{
					cipher1, err := unmarshalCipheriOS(v, false, "")
					if err != nil {
						log.Fatal(err)
					}
					err1 := h.db.AddCipher(cipher1, email)
					if err1 != nil {
						log.Fatal(err1)
					}
					cipherpost := transformCipherToPost(cipher1)
					data, err := json.Marshal(cipherpost)
					if err != nil {
						log.Fatal(err)
					}
					w.Header().Set("Content-Type", "application/json")
					w.Write(data)
				}
			case 3:
				{
					cipher1, err := unmarshalCardiOS(v, false, "")
					if err != nil {
						log.Fatal(err)
					}
					err1 := h.db.AddCipher(cipher1, email)
					if err1 != nil {
						log.Fatal(err1)
					}
					cipherpost := transformCipherToPost(cipher1)

					data, err := json.Marshal(cipherpost)
					if err != nil {
						log.Fatal(err)
					}
					w.Header().Set("Content-Type", "application/json")
					w.Write(data)
				}
			default:
				{
					log.Fatal("Can´t decode Cipher1")
				}
			}
		}
	}
}
func (h *APIHandler) HandleCipherGet(w http.ResponseWriter, req *http.Request) {
	email := auth.GetEmail(req)
	ciphers, err := h.db.GetCiphers(email)
	if err != nil {
		log.Fatal(err)
	}
	cipherspost := bw.CiphersPost{}
	for _, cipher := range ciphers {
		cipherspost = append(cipherspost, transformCipherToPost(cipher))
	}
	orgUser, _ := h.db.GetOrgUserbyEmail(email)
	if orgUser.Email != "" {
		orgCiphers, _ := h.db.GetCiphersOrg(orgUser.OrgId)
		for _, cipher := range orgCiphers {
			if containsCipher(cipherspost, cipher) == false {
				cipherspost = append(cipherspost, transformCipherToPost(cipher))
			} else {
				continue
			}
		}
	}
	post := bw.PostCiphers{
		Data:              cipherspost,
		ContinuationToken: nil,
		Object:            "list",
	}
	data, err := json.Marshal(post)
	if err != nil {
		log.Fatal(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}
func (h *APIHandler) HandleCipherUpdateGet(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	Id := vars["cipherId"]
	cipher, err := h.db.GetCipher(Id)
	if err != nil {
		log.Fatal(err)
	}
	postCipher := transformCipherToPost(cipher)
	data, err := json.Marshal(postCipher)
	if err != nil {
		log.Fatal(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}
func (h *APIHandler) HandleCipherUpdatePost(w http.ResponseWriter, req *http.Request) {
	email := auth.GetEmail(req)
	vars := mux.Vars(req)
	Id := vars["cipherId"]
	v, err := jason.NewObjectFromReader(req.Body)
	if err != nil {
		log.Fatal(err)
	}
	cipherType, err := v.GetInt64("type")
	if err == nil {
		switch cipherType {
		case 1:
			{
				cipher1, err := unmarshalCipher(v, true, Id)
				if err != nil {
					log.Fatal(err)
				}
				err1 := h.db.UpdateCipher(Id, cipher1, email)
				if err1 != nil {
					log.Fatal(err1)
				}
				cipherpost := transformCipherToPost(cipher1)
				data, err := json.Marshal(cipherpost)
				if err != nil {
					log.Fatal(err)
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write(data)
			}
		case 3:
			{
				cipher1, err := unmarshalCard(v, true, Id)
				if err != nil {
					log.Fatal(err)
				}
				err1 := h.db.UpdateCipher(Id, cipher1, email)
				if err1 != nil {
					log.Fatal(err1)
				}
				cipherpost := transformCipherToPost(cipher1)

				data, err := json.Marshal(cipherpost)
				if err != nil {
					log.Fatal(err)
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write(data)
			}
		}
	} else {
		cipherType, err := v.GetInt64("Type")
		if err != nil {
			log.Fatal("Can´t get Josn")
		} else {
			switch cipherType {
			case 1:
				{
					cipher1, err := unmarshalCipheriOS(v, true, Id)
					if err != nil {
						log.Fatal(err)
					}
					err1 := h.db.UpdateCipher(Id, cipher1, email)
					if err1 != nil {
						log.Fatal(err1)
					}
					cipherpost := transformCipherToPost(cipher1)
					data, err := json.Marshal(cipherpost)
					if err != nil {
						log.Fatal(err)
					}
					w.Header().Set("Content-Type", "application/json")
					w.Write(data)
				}
			case 3:
				{
					cipher1, err := unmarshalCardiOS(v, true, Id)
					if err != nil {
						log.Fatal(err)
					}
					err1 := h.db.UpdateCipher(Id, cipher1, email)
					if err1 != nil {
						log.Fatal(err1)
					}
					cipherpost := transformCipherToPost(cipher1)

					data, err := json.Marshal(cipherpost)
					if err != nil {
						log.Fatal(err)
					}
					w.Header().Set("Content-Type", "application/json")
					w.Write(data)
				}
			default:
				{
					log.Fatal("Can´t decode Cipher3")
				}
			}
		}
	}

}
func (h *APIHandler) HandleSync(w http.ResponseWriter, req *http.Request) {
	email := auth.GetEmail(req)

	acc, err := h.db.GetAccount(email, "")
	prof := acc.GetProfile()
	ciphers, err := h.db.GetCiphers(email)
	if err != nil {
		log.Println(err)
	}
	cipherspost := bw.CiphersPost{}
	for _, cipher := range ciphers {
		cipherspost = append(cipherspost, transformCipherToPost(cipher))

	}
	orgUser, _ := h.db.GetOrgUserbyEmail(email)
	if orgUser.Email != "" {
		orgCiphers, _ := h.db.GetCiphersOrg(orgUser.OrgId)
		for _, cipher := range orgCiphers {
			if containsCipher(cipherspost, cipher) == false {
				cipherspost = append(cipherspost, transformCipherToPost(cipher))
			} else {
				continue
			}
		}
	}
	folders, err := h.db.GetFolders(acc.Id)
	if err != nil {
		log.Println(err)
	}

	Domains := bw.Domains{
		Object:            "domains",
		EquivalentDomains: nil,
		GlobalEquivalentDomains: []bw.GlobalEquivalentDomains{
			bw.GlobalEquivalentDomains{Type: 1, Domains: []string{"youtube.com", "google.com", "gmail.com"}, Excluded: false},
		},
	}

	data := bw.SyncData{
		Profile: prof,
		Folders: folders,
		Domains: Domains,
		Object:  "sync",
		Ciphers: cipherspost,
	}

	jdata, err := json.Marshal(&data)
	if err != nil {
		log.Fatal(err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jdata)
}

func (h *APIHandler) HandleFolder(w http.ResponseWriter, req *http.Request) {
	email := auth.GetEmail(req)

	acc, err := h.db.GetAccount(email, "")
	if err != nil {
		log.Fatal("Account lookup " + err.Error())
	}

	var data []byte
	if req.Method == "POST" {
		decoder := json.NewDecoder(req.Body)

		var folderData struct {
			Name string `json:"name"`
		}

		err = decoder.Decode(&folderData)
		if err != nil {
			log.Fatal(err)
		}
		defer req.Body.Close()

		folder, err := h.db.AddFolder(folderData.Name, acc.Id)
		if err != nil {
			log.Fatal("newFolder error" + err.Error())
		}

		data, err = json.Marshal(&folder)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		folders, err := h.db.GetFolders(acc.Id)
		if err != nil {
			log.Println(err)
		}
		list := bw.Data{Object: "list", Data: folders}
		data, err = json.Marshal(list)
		if err != nil {
			log.Fatal(err)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (h *APIHandler) HandleFolderUpdate(w http.ResponseWriter, req *http.Request) {
	email := auth.GetEmail(req)
	acc, err := h.db.GetAccount(email, "")
	if err != nil {
		log.Fatal("Account lookup " + err.Error())
	}

	switch req.Method {
	case "POST":
		fallthrough // Do same as PUT. Web Vault wants to post
	case "PUT":
		// Get the folder id
		folderID := strings.TrimPrefix(req.URL.Path, "/api/folders/")

		decoder := json.NewDecoder(req.Body)

		var folderData struct {
			Name string `json:"name"`
		}

		err := decoder.Decode(&folderData)
		if err != nil {
			log.Fatal(err)
		}
		defer req.Body.Close()

		newFolder := bw.Folder{
			Id:           folderID,
			Name:         folderData.Name,
			RevisionDate: time.Now().UTC(),
			Object:       "folder",
		}

		err = h.db.UpdateFolder(newFolder, acc.Id)
		if err != nil {
			w.Write([]byte("0"))
			log.Println(err)
			return
		}

		// Send response
		data, err := json.Marshal(&newFolder)
		if err != nil {
			log.Fatal(err)
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		return
	}
	w.Header().Set("Content-Type", "application/json")
}

func (h *APIHandler) HandleOrg(w http.ResponseWriter, req *http.Request) {
	bConfirm := false
	bConfirm = strings.Contains(req.URL.Path, "confirm")
	id, error1 := uuid.NewV1()
	if error1 != nil {
		log.Println("Error with the ID", error1)
	}
	switch bConfirm {
	case false:
		{
			email := auth.GetEmail(req)
			acc, err := h.db.GetAccount(email, "")
			decoder := json.NewDecoder(req.Body)
			err = decoder.Decode(&norg)
			if err != nil {
				log.Fatal(err)
			}
			defer req.Body.Close()
			org := bw.OrgData{
				Id:             id.String(),
				Name:           norg.Name,
				Key:            norg.Key,
				Status:         2,
				Type:           0,
				Enabled:        true,
				MaxCollections: 2,
				MaxStorageGb:   1,
				Seats:          2,
				UseGroups:      true,
				UseEvents:      true,
				UseDirectory:   true,
				UseTotp:        true,
				Object:         "profileOrganization",
			}
			organization := bw.OrganizationsData{
				org,
			}
			b, err := uuid.NewV1()
			if error1 != nil {
				log.Println("Error with the ID", error1)
			}
			acc.Organizations = organization
			h.db.UpdateAccountInfo(acc)

			orgUser := bw.OrgUserwId{
				Id:        b.String(),
				OrgId:     org.Id,
				UserId:    acc.Id,
				Name:      acc.Name,
				Email:     acc.Email,
				Status:    2,
				Type:      0,
				AccessAll: true,
				Object:    "organizationUserUserDetails",
			}
			err1 := h.db.AddOrgUser(orgUser)
			if err1 != nil {
				log.Fatal(err)
			}
			data, err := json.Marshal(&org)
			if err != nil {
				log.Fatal(err)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(data)
		}
	case true:
		{
			decoder := json.NewDecoder(req.Body)
			var keyOrg keyOrg
			err := decoder.Decode(&keyOrg)
			if err != nil {
				log.Fatal(err)
			}
			acc, err := h.db.GetID("2")
			if err != nil {
				log.Fatal(err)
			}
			for _, value := range acc.Organizations {
				value.Key = keyOrg.Key
			}
			h.db.UpdateAccountInfo(acc)
		}
	}
}
func (h *APIHandler) HandleOrgDetailsGet(w http.ResponseWriter, req *http.Request) {
	m, _ := url.ParseQuery(req.URL.RawQuery)
	orgId := (m["organizationId"][0])
	ciphers, err := h.db.GetCiphersOrg(orgId)
	if err != nil {
		log.Println(err)
	}
	cipherspost := bw.CiphersPost{}
	for _, cipher := range ciphers {
		cipherspost = append(cipherspost, transformCipherToPost(cipher))

	}
	post := bw.PostCiphers{
		Data:              cipherspost,
		ContinuationToken: nil,
		Object:            "list",
	}
	data, err := json.Marshal(post)
	if err != nil {
		log.Fatal(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)

}
func (h *APIHandler) HandleOrgCipherAdminPost(w http.ResponseWriter, req *http.Request) {
	email := auth.GetEmail(req)
	v, err := jason.NewObjectFromReader(req.Body)
	if err != nil {
		log.Fatal(err)
	}
	cipher, err := unmarshalCipherLoginOrg(v, false, "")
	if err != nil {
		log.Fatal(err)
	}
	err1 := h.db.AddCipher(cipher, email)
	if err1 != nil {
		log.Fatal(err1)
	}
	postCipher := transformCipherToPost(cipher)
	data, err := json.Marshal(postCipher)
	if err != nil {
		log.Fatal(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)

}

func (h *APIHandler) HandleOrgCipherUpdateAdminPost(w http.ResponseWriter, req *http.Request) {
	email := auth.GetEmail(req)
	vars := mux.Vars(req)
	Id := vars["Id"]
	v, err := jason.NewObjectFromReader(req.Body)
	if err != nil {
		log.Fatal(err)
	}
	cipher, err := unmarshalCipherLoginOrg(v, true, Id)
	if err != nil {
		log.Fatal(err)
	}
	err1 := h.db.UpdateCipher(Id, cipher, email)
	if err1 != nil {
		log.Fatal(err1)
	}
	postCipher := transformCipherToPost(cipher)
	data, err := json.Marshal(postCipher)
	if err != nil {
		log.Fatal(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)

}
func (h *APIHandler) HandleOrgEditCipherGet(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	Id := vars["Id"]
	cipher1, _ := h.db.GetCipher(Id)
	postCipher := transformCipherToPost(cipher1)
	data, err := json.Marshal(postCipher)
	if err != nil {
		log.Fatal(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}
func (h *APIHandler) HandleCipherDelete(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	Id := vars["cipherId"]
	err := h.db.DeleteCipher(Id)
	if err != nil {
		log.Println(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(""))
}

//Only invite one user every time
func (h *APIHandler) HandleOrgInvite(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	orgId1 := vars["orgId"]
	id, error1 := uuid.NewV1()
	if error1 != nil {
		log.Println("Error with the Id", error1)
	}
	id2, error2 := uuid.NewV1()
	if error2 != nil {
		log.Println("Error with the Id", error1)
	}
	decoder := json.NewDecoder(req.Body)
	holder := struct {
		Collections []string `json:"collections"`
		Emails      []string `json:"emails"`
		Type        string   `json:"Type"`
	}{}
	err := decoder.Decode(&holder)
	if err != nil {
		log.Fatal(err)
	}
	defer req.Body.Close()
	user := bw.OrgUserwId{
		Id:        id2.String(),
		OrgId:     orgId1,
		UserId:    id.String(), //we don´t know the User Id yet
		Name:      "",
		Email:     "",
		Status:    0,
		Type:      0,
		AccessAll: true,
		Object:    "organizationUserUserDetails",
	}
	for _, email := range holder.Emails {
		user.Email = email
	}
	email := auth.GetEmail(req)
	acc, err := h.db.GetAccount(email, "")
	if err != nil {
		log.Fatal(err)
	}
	var orgName string
	for _, value := range acc.Organizations {
		orgName = value.Name
	}
	user.Name = orgName
	sendInvite(user.OrgId, user.UserId, user.Email, orgName, "CDF") //token solution

	err2 := h.db.AddOrgUser(user)
	if err2 != nil {
		log.Println(err2)
	}
	orgUserswId, err := h.db.GetOrgUsers(orgId1)
	if err != nil {
		log.Println(err)
	}
	orgUsers := bw.OrgUsers{}
	for _, value := range orgUserswId {
		orgUsers = append(orgUsers, transformUser(value))
	}
	organization := bw.Organizationusers{
		Data:              orgUsers,
		ContinuationToken: nil,
		Object:            "list"}

	data, err := json.Marshal(organization)
	if err != nil {
		log.Fatal(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (h *APIHandler) HandleOrgUsers(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	orgId1 := vars["orgId"]
	orgUserswId, err := h.db.GetOrgUsers(orgId1)
	if err != nil {
		log.Println(err)
	}
	orgUsers := bw.OrgUsers{}
	for _, value := range orgUserswId {
		orgUsers = append(orgUsers, transformUser(value))
	}
	organization := bw.Organizationusers{
		Data:              orgUsers,
		ContinuationToken: nil,
		Object:            "list"}

	data, err := json.Marshal(organization)
	if err != nil {
		log.Fatal(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (h *APIHandler) HandleOrgAcception(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	orgUserId := vars["orgUserId"]
	user, err := h.db.GetOrgUser(orgUserId)
	if err != nil {
		log.Fatal(err)
	}
	email := auth.GetEmail(req)
	acc, err := h.db.GetAccount(email, "")
	profile := acc.GetProfile()
	if err != nil {
		log.Fatal("Account lookup " + err.Error())
	}
	user.UserId = acc.Id
	user.Name = acc.Name
	user.Status = 1
	org := bw.OrgData{
		Id:             user.OrgId,
		Name:           user.Name, //problem is the user name not the organization name
		Key:            "",
		Status:         user.Status,
		Type:           user.Type,
		Enabled:        true,
		MaxCollections: 2,
		MaxStorageGb:   1,
		Seats:          2,
		UseGroups:      true,
		UseEvents:      true,
		UseDirectory:   true,
		UseTotp:        true,
		Object:         "profileOrganization",
	}
	profile1 := bw.OrganizationsData{}
	profile1 = append(profile1, org)
	acc.Organizations = profile1
	h.db.UpdateAccountInfo(acc)
	if err != nil {
		log.Fatal(err.Error())
	}
	err2 := h.db.UpdateOrgUser(user)
	if err2 != nil {
		log.Fatal(err.Error())
	}
	profile.Organizations = profile1
	data, err := json.Marshal(acc)
	if err != nil {
		log.Fatal(err)
	}
	data, err1 := json.Marshal(nil)
	if err != nil {
		log.Fatal(err1)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func sendInvite(organizationId string, organizationUserId string, email string, organizationName, token string) {
	if bw.Cfg.PrintInvite == false {
		m := gomail.NewMessage()
		m.SetHeader("From", bw.Cfg.Email)
		m.SetHeader("To", email)
		m.SetHeader("Subject", "Bitwarden Invitation")
		m.SetBody("text/html", "<p><a href="+bw.Cfg.VaultURL+":"+bw.Cfg.HostPort+"/#/accept-organization?organizationId="+organizationId+"&amp;organizationUserId="+organizationUserId+"&amp;email="+email+"&amp;organizationName="+organizationName+"&amp;token="+token+">"+bw.Cfg.VaultURL+":"+bw.Cfg.HostPort+"/#/accept-organization?organizationId="+organizationId+"&amp;organizationUserId="+organizationUserId+"&amp;email="+email+"&amp;organizationName="+organizationName+"&amp;token="+token+"</a></p>")

		d := gomail.NewDialer(bw.Cfg.SmtpServer, bw.Cfg.EmailPort, bw.Cfg.Email, bw.Cfg.Email)

		if err := d.DialAndSend(m); err != nil {
			panic(err)
		}
	} else {
		log.Println("InvationLink: " + "http://localhost" + ":" + bw.Cfg.HostPort + "/#/accept-organization?organizationId=" + organizationId + "&organizationUserId=" + organizationUserId + "&email=" + email + "&organizationName=" + organizationName + "&token=" + token)
	}

}

func (h *APIHandler) HandleOrgCollectionGet(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	orgId := vars["orgId"]
	collectionsData, err := h.db.GetCollections(orgId)
	if err != nil {
		log.Println(err)
	}
	collections := bw.Collection{
		Data:              collectionsData,
		ContinuationToken: nil,
		Object:            "list",
	}
	data, err := json.Marshal(collections)
	if err != nil {
		log.Fatal(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}
func (h *APIHandler) HandleOrgCollectionPost(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	orgId := vars["orgId"]
	decoder := json.NewDecoder(req.Body)
	var collectionname collectionName
	err := decoder.Decode(&collectionname)
	if err != nil {
		log.Fatal(err)
	}
	id, err := uuid.NewV1()
	if err != nil {
		log.Fatal(err)
	}
	collection := bw.CollectionData{
		Id:             id.String(),
		OrganizationId: orgId,
		Name:           collectionname.Name,
		Object:         "collection",
	}
	err1 := h.db.AddCollection(collection)
	if err1 != nil {
		log.Fatal(err1)
	}
	data, err := json.Marshal(collection)
	if err != nil {
		log.Fatal(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)

}

type neworgData struct {
	Name           string `json:"name"`
	PlanType       string `json:"planType"`
	Key            string `json:"key"`
	BillingEmail   string `json:"billingEmail"`
	CollectionName string `json:"collectionName"`
}
type keyOrg struct {
	Key string `json:"key"`
}
type collectionName struct {
	Name string `json:"name"`
}

func unmarshalCipherLoginOrg(v *jason.Object, update bool, Id string) (bw.Cipher, error) {
	idv1, err1 := uuid.NewV1()
	id := Id
	if err1 != nil {
		return bw.Cipher{}, err1
	}
	cM := bw.Cipher{}
	cDL := bw.CipherDataLogin{}
	fs := bw.Fields{}
	f := bw.Field{}
	l := bw.Login{}
	us := bw.Uriss{}
	u := bw.Uris{}
	//Fields
	fields, _ := v.GetObjectArray("fields")
	if len(fields) > 0 {
		for _, field := range fields {
			name, _ := field.GetString("name")
			type1, _ := field.GetInt64("type")
			value, _ := field.GetString("value")
			type2 := strconv.FormatInt(type1, 10)
			type3, _ := strconv.Atoi(type2)
			f.Name = name
			f.Type = type3
			f.Value = value
			fs = append(fs, f)
		}
	} else {
		fs = nil
	}
	//Login
	password, _ := checkNullString(v.GetString("login", "password"))
	totp, _ := checkNullString(v.GetString("login", "totp"))
	uris, _ := v.GetObjectArray("login", "uris")
	if len(uris) > 0 {
		for _, uri := range uris {
			match, _ := checkNullInt(uri.GetInt64("match"))
			uir1, _ := checkNullString(uri.GetString("uri"))
			u.Match = match
			u.Uri = uir1
			us = append(us, u)
		}
	} else {
		us = bw.Uriss{
			bw.Uris{},
		}
	}
	username, _ := checkNullString(v.GetString("login", "username"))

	//Org
	organizationId, _ := checkNullString(v.GetString("organizationId"))
	//cipher
	name, _ := checkNullString(v.GetString("name"))
	notes, _ := checkNullString(v.GetString("notes"))
	folderId, _ := checkNullString(v.GetString("folderId"))
	favorite, _ := v.GetBoolean("favorite")
	edit := true
	if update == false {
		id = idv1.String()
	}
	//
	cM.CollectionIds = nil
	cM.FolderId = folderId
	cM.Favorite = favorite
	cM.Edit = edit
	cM.Id = &id
	cM.Type = 1
	cDL.Uri = us[0].Uri
	cDL.Uris = us
	cDL.Username = username
	cDL.Password = password
	cDL.Totp = nil
	cDL.Name = name
	cDL.Notes = notes
	cDL.Fields = &fs
	cM.DataL = &cDL
	cM.DataC = nil
	cM.DataI = nil
	cM.Name = name
	cM.Notes = notes
	cM.OrganizationId = organizationId
	l.Uri = us[0].Uri
	l.Uris = &us
	l.Username = username
	l.Password = password
	l.Totp = totp
	cM.Login = &l
	cM.Card = nil
	cM.Identity = nil
	cM.SecureNote = nil
	cM.Fields = &fs
	cM.Attachments = nil // update
	cipher := "cipherMini"
	cM.OrganizationUseTotp = true
	cM.RevisionDate = time.Now().UTC()
	cM.Object = &cipher

	return cM, nil
}

func unmarshalCipher(v *jason.Object, update bool, Id string) (bw.Cipher, error) {
	idv1, err1 := uuid.NewV1()
	id := Id
	if err1 != nil {
		return bw.Cipher{}, err1
	}
	cM := bw.Cipher{}
	cDL := bw.CipherDataLogin{}
	fs := bw.Fields{}
	f := bw.Field{}
	l := bw.Login{}
	us := bw.Uriss{}
	u := bw.Uris{}
	//Fields
	fields, _ := v.GetObjectArray("fields")
	if len(fields) > 0 {
		for _, field := range fields {
			name, _ := field.GetString("name")
			type1, _ := field.GetInt64("type")
			value, _ := field.GetString("value")
			type2 := strconv.FormatInt(type1, 10)
			type3, _ := strconv.Atoi(type2)
			f.Name = name
			f.Type = type3
			f.Value = value
			fs = append(fs, f)
		}
	} else {
		fs = nil
	}
	//Login
	password, _ := checkNullString(v.GetString("login", "password"))
	totp, _ := checkNullString(v.GetString("login", "totp"))
	//Uri
	uris, _ := v.GetObjectArray("login", "uris")
	if len(uris) > 0 {
		for _, uri := range uris {
			match, _ := checkNullInt(uri.GetInt64("match"))
			uir1, _ := checkNullString(uri.GetString("uri"))
			u.Match = match
			u.Uri = uir1
			us = append(us, u)
		}
	} else {
		us = bw.Uriss{
			bw.Uris{},
		}
	}
	username, _ := checkNullString(v.GetString("login", "username"))

	//Org
	organizationId, _ := checkNullString(v.GetString("organizationId"))
	//cipher
	name, _ := checkNullString(v.GetString("name"))
	notes, _ := checkNullString(v.GetString("notes"))
	folderId, _ := checkNullString(v.GetString("folderId"))
	favorite, _ := v.GetBoolean("favorite")
	edit := true
	if update == false {
		id = idv1.String()
	}
	//
	cM.CollectionIds = nil
	cM.FolderId = folderId
	cM.Favorite = favorite
	cM.Edit = edit
	cM.Id = &id             // create Id
	cM.OrganizationId = nil //&organizationId
	cM.Type = 1
	cDL.Uri = us[0].Uri
	cDL.Uris = us
	cDL.Username = username
	cDL.Password = password
	cDL.Totp = nil
	cDL.Name = name
	cDL.Notes = notes
	cDL.Fields = &fs
	cM.DataL = &cDL
	cM.DataC = nil
	cM.DataI = nil
	cM.Name = name
	cM.Notes = notes
	cM.OrganizationId = organizationId
	l.Uri = us[0].Uri
	l.Uris = &us
	l.Username = username
	l.Password = password
	l.Totp = totp
	cM.Login = &l
	cM.Card = nil
	cM.Identity = nil
	cM.SecureNote = nil
	cM.Fields = &fs
	cM.Attachments = nil // update
	cipher := "cipher"
	cM.OrganizationUseTotp = true
	cM.RevisionDate = time.Now().UTC()
	cM.Object = &cipher

	return cM, nil
}
func unmarshalCipheriOS(v *jason.Object, update bool, Id string) (bw.Cipher, error) {
	idv1, err1 := uuid.NewV1()
	id := Id
	if err1 != nil {
		return bw.Cipher{}, err1
	}
	cM := bw.Cipher{}
	cDL := bw.CipherDataLogin{}
	fs := bw.Fields{}
	f := bw.Field{}
	l := bw.Login{}
	us := bw.Uriss{}
	u := bw.Uris{}
	//Fields
	fields, _ := v.GetObjectArray("Fields")
	if len(fields) > 0 {
		for _, field := range fields {
			name, _ := field.GetString("Name")
			type1, _ := field.GetInt64("Type")
			value, _ := field.GetString("Value")
			type2 := strconv.FormatInt(type1, 10)
			type3, _ := strconv.Atoi(type2)
			f.Name = name
			f.Type = type3
			f.Value = value
			fs = append(fs, f)
		}
	} else {
		fs = nil
	}
	//Login
	password, _ := checkNullString(v.GetString("Login", "Password"))
	totp, _ := checkNullString(v.GetString("Login", "Totp"))
	uris, _ := v.GetObjectArray("Login", "Uirs")
	if len(uris) > 0 {
		for _, uri := range uris {
			match, _ := checkNullInt(uri.GetInt64("Match"))
			uir1, _ := checkNullString(uri.GetString("Uri"))
			u.Match = match
			u.Uri = uir1
			us = append(us, u)
		}
	} else {
		uris = nil
	}
	username, _ := checkNullString(v.GetString("Login", "Username"))

	//Org
	organizationId, _ := checkNullString(v.GetString("OrganizationId"))
	//cipher
	name, _ := checkNullString(v.GetString("Name"))
	notes, _ := checkNullString(v.GetString("Notes"))
	folderId, _ := checkNullString(v.GetString("FolderId"))
	favorite, _ := v.GetBoolean("Favorite")
	edit := true
	if update == false {
		id = idv1.String()
	}
	//
	cM.CollectionIds = nil
	cM.FolderId = folderId
	cM.Favorite = favorite
	cM.Edit = edit
	cM.Id = &id             // create Id
	cM.OrganizationId = nil //&organizationId
	cM.Type = 1
	if len(us) == 0 {
		cDL.Uri = nil
	} else {
		cDL.Uri = us[0].Uri
	}
	cDL.Uris = us
	cDL.Username = username
	cDL.Password = password
	cDL.Totp = totp
	cDL.Name = name
	cDL.Notes = notes
	cDL.Fields = &fs
	cM.DataL = &cDL
	cM.DataC = nil
	cM.DataI = nil
	cM.Name = name
	cM.Notes = notes
	cM.OrganizationId = organizationId
	if len(us) == 0 {
		l.Uri = nil
	} else {
		l.Uri = us[0].Uri
	}
	l.Uris = &us
	l.Username = username
	l.Password = password
	l.Totp = nil
	cM.Login = &l
	cM.Card = nil
	cM.Identity = nil
	cM.SecureNote = nil
	cM.Fields = &fs
	cM.Attachments = nil // update
	cipher := "cipher"
	cM.OrganizationUseTotp = true
	cM.RevisionDate = time.Now().UTC()
	cM.Object = &cipher

	return cM, nil
}
func unmarshalCard(v *jason.Object, update bool, Id string) (bw.Cipher, error) {
	idv1, err1 := uuid.NewV1()
	id := Id
	if err1 != nil {
		return bw.Cipher{}, err1
	}
	cipher := bw.Cipher{}
	card := bw.CipherDataCard{}
	fs := bw.Fields{}
	f := bw.Field{}
	c := bw.Card{}
	//Fields
	fields, _ := v.GetObjectArray("fields")
	if len(fields) > 0 {
		for _, field := range fields {
			name, _ := field.GetString("name")
			type1, _ := field.GetInt64("type")
			value, _ := field.GetString("value")
			type2 := strconv.FormatInt(type1, 10)
			type3, _ := strconv.Atoi(type2)
			f.Name = name
			f.Type = type3
			f.Value = value
			fs = append(fs, f)
		}
	} else {
		fs = nil
	}
	//Card
	brand, _ := checkNullString(v.GetString("card", "brand"))
	cardholderName, _ := checkNullString(v.GetString("card", "cardholderName"))
	code, _ := checkNullString(v.GetString("card", "code"))
	expMonth, _ := checkNullString(v.GetString("card", "expMonth"))
	expYear, _ := checkNullString(v.GetString("card", "expYear"))
	number, _ := checkNullString(v.GetString("card", "number"))
	//
	favorite, _ := v.GetBoolean("favorite")
	folderId, _ := checkNullString(v.GetString("folderId"))
	name, _ := checkNullString(v.GetString("name"))
	notes, _ := checkNullString(v.GetString("notes"))
	organizationId, _ := checkNullString(v.GetString("organizationId"))
	if update == false {
		id = idv1.String()
	}
	//
	cipher.CollectionIds = nil
	cipher.FolderId = folderId
	cipher.Favorite = favorite
	cipher.Edit = true
	cipher.Id = &id
	cipher.OrganizationId = organizationId
	cipher.Type = 3
	cipher.Name = name
	//card
	c.CardholderName = cardholderName
	c.Brand = brand
	c.Number = number
	c.ExpMonth = expMonth
	c.ExpYear = expMonth
	//cipher
	card.CardholderName = cardholderName
	card.Brand = brand
	card.Number = number
	card.ExpMonth = expMonth
	card.ExpYear = expYear
	card.Code = code
	card.Name = name
	card.Notes = notes
	card.Fields = &fs
	cipher.DataC = &card
	cipher.Card = &c
	cipher.Fields = &fs
	cipher.Attachments = nil
	cipher.OrganizationUseTotp = true
	cipher.RevisionDate = time.Now().UTC()
	object := "cipher"
	cipher.Object = &object

	return cipher, nil
}
func unmarshalCardiOS(v *jason.Object, update bool, Id string) (bw.Cipher, error) {
	idv1, err1 := uuid.NewV1()
	id := Id
	if err1 != nil {
		return bw.Cipher{}, err1
	}
	cipher := bw.Cipher{}
	card := bw.CipherDataCard{}
	fs := bw.Fields{}
	f := bw.Field{}
	c := bw.Card{}
	//Fields
	fields, _ := v.GetObjectArray("Fields")
	if len(fields) > 0 {
		for _, field := range fields {
			name, _ := field.GetString("Name")
			type1, _ := field.GetInt64("Type")
			value, _ := field.GetString("Value")
			type2 := strconv.FormatInt(type1, 10)
			type3, _ := strconv.Atoi(type2)
			f.Name = name
			f.Type = type3
			f.Value = value
			fs = append(fs, f)
		}
	} else {
		fs = nil
	}
	//Card
	brand, _ := checkNullString(v.GetString("Card", "Brand"))
	cardholderName, _ := checkNullString(v.GetString("Card", "cardholderName"))
	code, _ := checkNullString(v.GetString("Card", "Code"))
	expMonth, _ := checkNullString(v.GetString("Card", "ExpMonth"))
	expYear, _ := checkNullString(v.GetString("Card", "ExpYear"))
	number, _ := checkNullString(v.GetString("Card", "Number"))
	//
	favorite, _ := v.GetBoolean("Favorite")
	folderId, _ := checkNullString(v.GetString("FolderId"))
	name, _ := checkNullString(v.GetString("Name"))
	notes, _ := checkNullString(v.GetString("Notes"))
	organizationId, _ := checkNullString(v.GetString("OrganizationId"))
	if update == false {
		id = idv1.String()
	}
	//
	cipher.CollectionIds = nil
	cipher.FolderId = folderId
	cipher.Favorite = favorite
	cipher.Edit = true
	cipher.Id = &id
	cipher.OrganizationId = organizationId
	cipher.Type = 3
	cipher.Name = name
	//card
	c.CardholderName = cardholderName
	c.Brand = brand
	c.Number = number
	c.ExpMonth = expMonth
	c.ExpYear = expMonth
	//cipher
	card.CardholderName = cardholderName
	card.Brand = brand
	card.Number = number
	card.ExpMonth = expMonth
	card.ExpYear = expYear
	card.Code = code
	card.Name = name
	card.Notes = notes
	card.Fields = &fs
	cipher.DataC = &card
	cipher.Card = &c
	cipher.Fields = &fs
	cipher.Attachments = nil
	cipher.OrganizationUseTotp = true
	cipher.RevisionDate = time.Now().UTC()
	object := "cipher"
	cipher.Object = &object

	return cipher, nil
}

func transformUser(user bw.OrgUserwId) bw.OrgUser {
	OrgUser := bw.OrgUser{
		Id:        user.Id,
		UserId:    user.UserId,
		Name:      user.Name,
		Email:     user.Email,
		Status:    user.Status,
		Type:      user.Type,
		AccessAll: true,
		Object:    "organizationUserUserDetails",
	}
	return OrgUser
}

func transformCipherToPost(cipher bw.Cipher) bw.CipherPost {
	switch cipher.Type {
	case 1:
		cipher.CollectionIds = &bw.CollectionIds{}
		if cipher.Fields == nil {
			cipher.Fields = &bw.Fields{}
		}
		cipherPost := bw.CipherPost{
			CollectionIds:       cipher.CollectionIds,
			FolderId:            cipher.FolderId,
			Favorite:            cipher.Favorite,
			Edit:                cipher.Edit,
			Id:                  cipher.Id,
			OrganizationId:      cipher.OrganizationId,
			Type:                cipher.Type,
			Data:                cipher.DataL,
			Name:                cipher.Name,
			Notes:               cipher.Notes,
			Login:               cipher.Login,
			Card:                nil,
			Identity:            nil,
			SecureNote:          nil,
			Fields:              cipher.Fields,
			Attachments:         cipher.Attachments,
			OrganizationUseTotp: cipher.OrganizationUseTotp,
			RevisionDate:        cipher.RevisionDate,
			Object:              "cipherDetails", //cipher.Object,
		}
		return cipherPost
	case 3:
		{
			cipher.CollectionIds = &bw.CollectionIds{}
			if len(*cipher.Fields) == 0 {
				cipher.Fields = &bw.Fields{}
			}
			cipherPost := bw.CipherPost{
				CollectionIds:       cipher.CollectionIds,
				FolderId:            cipher.FolderId,
				Favorite:            cipher.Favorite,
				Edit:                cipher.Edit,
				Id:                  cipher.Id,
				OrganizationId:      cipher.OrganizationId,
				Type:                cipher.Type,
				Data:                cipher.DataC,
				Name:                cipher.Name,
				Notes:               cipher.Notes,
				Login:               nil,
				Card:                cipher.Card,
				Identity:            nil,
				SecureNote:          nil,
				Fields:              cipher.Fields,
				Attachments:         cipher.Attachments,
				OrganizationUseTotp: cipher.OrganizationUseTotp,
				RevisionDate:        cipher.RevisionDate,
				Object:              "cipherDetails", //cipher.Object,
			}
			return cipherPost
		}
	default:
		log.Fatal("Can´t transform cipher")
		return bw.CipherPost{}
	}
}

func checkNullString(s string, e error) (*string, error) {
	if len(s) == 0 {
		return nil, e
	} else {
		return &s, e
	}
}
func checkNullInt(i int64, e error) (*int, error) {
	if i == 0 && e != nil {
		return nil, e
	} else {
		type2 := strconv.FormatInt(i, 10)
		type3, _ := strconv.Atoi(type2)
		return &type3, e
	}
}

func containsCipher(ciphersPost bw.CiphersPost, cipher bw.Cipher) bool {
	for _, c := range ciphersPost {
		if *c.Id == *cipher.Id {
			return true
		}
		continue
	}
	return false
}
