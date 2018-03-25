package main

import (
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/Odysseus16/bitwarden-go/internal/api"
	"github.com/Odysseus16/bitwarden-go/internal/auth"
	bw "github.com/Odysseus16/bitwarden-go/internal/common"
	"github.com/Odysseus16/bitwarden-go/internal/database/sqlite"
	"github.com/gorilla/mux"
)

func init() {
	flag.BoolVar(&cfg.initDB, "init", false, "Initalizes the database.")
	flag.StringVar(&cfg.location, "location", "", "Sets the directory for the database")
	flag.StringVar(&cfg.signingKey, "key", "secret", "Sets the signing key")
	flag.IntVar(&cfg.jwtExpire, "tokenTime", 3600, "Sets the ammount of time (in seconds) the generated JSON Web Tokens will last before expiry.")
	flag.StringVar(&cfg.hostAddr, "host", "", "Sets the interface that the application will listen on.")
	flag.StringVar(&cfg.hostPort, "port", "8000", "Sets the port")
	flag.StringVar(&cfg.vaultURL, "vaultURL", "", "Sets the vault proxy url")
	flag.BoolVar(&cfg.disableRegistration, "disableRegistration", false, "Disables user registration.")
}

func main() {
	db := &sqlite.DB{}
	flag.Parse()

	db.SetDir(bw.Cfg.Location)
	err := db.Open()
	if err != nil {
		log.Fatal(err)
	}

	defer db.Close()

	// Create a new database
	if bw.Cfg.InitDB {
		err := db.Init()
		if err != nil {
			log.Fatal(err)
		}
	}

	authHandler := auth.New(db, bw.Cfg.SigningKey, bw.Cfg.JwtExpire)
	apiHandler := api.New(db)

	target := "http://localhost:4001"
	//target := bw.Cfg.HostAddr + ":" + bw.Cfg.HostPort
	remote, err := url.Parse(target)
	if err != nil {
		panic(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(remote)
	//mux := chi.NewRouter()
	mux := mux.NewRouter()

	if bw.Cfg.DisableRegistration == false {
		mux.HandleFunc("/api/accounts/register", authHandler.HandleRegister)
	}
	mux.HandleFunc("/identity/connect/token", authHandler.HandleLogin)

	mux.Handle("/api/accounts/keys", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleKeysUpdate)))
	mux.Handle("/api/accounts/profile", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleProfile)))
	mux.Handle("/api/collections", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleCollections)))
	mux.Handle("/api/folders", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleFolder)))
	mux.Handle("/api/folders/", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleFolderUpdate)))
	mux.Handle("/apifolders", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleFolder))) // The android app want's the address like this, will be fixed in the next version. Issue #174
	mux.Handle("/api/sync", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleSync)))

	mux.Handle("/api/organizations", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleOrg)))
	mux.Handle("/api/organizations/", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleOrg)))
	mux.Handle("/api/organizations/users", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleOrgUsers)))
	mux.Handle("/api/organizations/{orgId}/users/{orgUserId}/accept", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleOrgAcception)))
	mux.Handle("/api/organizations/{orgId}/users/invite", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleOrgInvite)))
	mux.Handle("/api/organizations/{orgId}/users", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleOrgUsers)))
	mux.Handle("/api/users/{userId}/public-key", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleKey)))
	mux.Handle("/api/organizations/{orgId}/users/{orgUserId}/confirm", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleKeyOrg))) //Get new org Key for the specific user! Set this key to the user and update status to 2
	mux.Handle("/api/organizations/{orgId}/collections", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleOrgCollectionGet))).Methods("GET")
	mux.Handle("/api/organizations/{orgId}/collections", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleOrgCollectionPost))).Methods("POST")

	//mux.Handle("/api/ciphers/import", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleImport)))
	mux.Handle("/api/ciphers", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleCipherPost))).Methods("POST")
	mux.Handle("/api/ciphers", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleCipherGet))).Methods("GET")
	mux.Handle("/api/ciphers/organization-details", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleOrgDetailsGet))).Methods("GET")
	mux.Handle("/api/ciphers/admin", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleOrgCipherAdminPost))).Methods("POST")
	mux.Handle("/api/ciphers/{cipherId}", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleCipherUpdateGet))).Methods("GET")
	mux.Handle("/api/ciphers/{cipherId}", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleCipherUpdatePost))).Methods("POST")
	mux.Handle("/api/ciphers/{cipherId}", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleCipherUpdatePost))).Methods("PUT") //iOS APP
	mux.Handle("/api/ciphers/{cipherId}", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleCipherDelete))).Methods("DELETE")  //iOS APP
	mux.Handle("/api/ciphers/{cipherId}/delete", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleCipherDelete))).Methods("POST")
	mux.Handle("/api/ciphers/{Id}/admin", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleOrgEditCipherGet))).Methods("GET")
	mux.Handle("/api/ciphers/{Id}/admin", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleOrgCipherUpdateAdminPost))).Methods("POST")

	mux.HandleFunc("/attachments/", api.HandleAttachments)
	if len(bw.Cfg.VaultURL) > 4 {

		mux.HandleFunc("/{rest:.*}", handler(proxy))
		http.Handle("/", mux)
		http.ListenAndServe(":8000", mux)

	}
	mux.Handle("/api/two-factor/get-authenticator", authHandler.JwtMiddleware(http.HandlerFunc(authHandler.GetAuthenticator)))
	mux.Handle("/api/two-factor/authenticator", authHandler.JwtMiddleware(http.HandlerFunc(authHandler.VerifyAuthenticatorSecret)))
	mux.Handle("/api/two-factor/disable", authHandler.JwtMiddleware(http.HandlerFunc(authHandler.HandleDisableTwoFactor)))
	mux.Handle("/api/two-factor", authHandler.JwtMiddleware(http.HandlerFunc(authHandler.HandleTwoFactor)))
	log.Println("Starting server on " + bw.Cfg.HostAddr + ":" + bw.Cfg.HostPort)
}

func handler(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = mux.Vars(r)["rest"]
		p.ServeHTTP(w, r)
	}
}
