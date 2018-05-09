*(Note: This is still a work in progress.
This project is not associated with the
[Bitwarden](https://bitwarden.com/)
project nor 8bit Solutions LLC.)*

## bitwarden-go

[![Build Status](https://travis-ci.org/Odysseus16/bitwarden-go.svg?branch=master)](https://travis-ci.org/Odysseus16/bitwarden-go)

A golang server compatible with the Bitwarden apps and plugins. The server has a small footprint and could be run locally on your computer, a Raspberry Pi or a small VPS. The data is stored in a local SQLite database.

For more information on the protocol you can read the [documentation](https://github.com/jcs/bitwarden-ruby/blob/master/API.md) provided by [jcs](https://github.com/jcs)
Parts of the work come from VictorNine, who started the project. I will try to submit a pull request, but my time is very limited, so it may take some time. See more under: [VictorNine](https://github.com/VictorNine/bitwarden-go)
Thank you very much VictorNine! 
=======

A server compatible with the Bitwarden apps and plugins. The server has a small footprint and could be run locally on your computer, a Raspberry Pi or a small VPS. The data is stored in a local SQLite database.

For more information on the protocol you can read the [documentation](https://github.com/jcs/bitwarden-ruby/blob/master/API.md) provided by [jcs](https://github.com/jcs)

### Usage
#### Fetching the code
Make sure you have the ```go``` package installed.
*Note: package name may vary based on distribution*

You can then run ```go get github.com/Odysseus16/bitwarden-go``` to fetch the latest code.

#### Build/Install
Run in your favorite terminal:
```
cd $GOPATH/src/github.com/Odysseus16/bitwarden-go/cmd/bitwarden-go
```
followed by
```
go build
```
or
```
go install
```
The former will create an executable named ```bitwarden-go``` in the current directory, and ```go install``` will build and install the executable ```bitwarden-go``` as a system-wide application (located in ```$GOPATH/bin```).
*Note: From here on, this guide assumes you ran ```go install```*

#### Initializing the Database
*Note: This step only has to be performed once*

Run the following to initialize the database:
```
bitwarden-go -init
```
This will create a database called ```db``` in the directory of the application. Use `-location` to set a different directory for the database.
Note: This database is not compatible with VictorNine´s database as I have done several additions and re-orders.

#### Running
To run [bitwarden-go](https://github.com/Odysseus16/bitwarden-go), run the following in the terminal:
```
bitwarden-go
```

#### Usage with Flags
To see all current flags and options with the application, run
```
bitwarden-go -h
```

##### Flags
At the moment these flags are available:
- init: Initializes the database.
- location: Sets the directory for the database
- key: Sets the signing key
- tokenTime: Sets the amount of time (in seconds) the generated JSON Web Tokens will last before expiry.
- host: Sets the interface that the application will listen on.
- port: Sets the port
- VaultURL: Sets the vault proxy url
- Email: Sets the Email for organization invite
- emailPassword: Sets the Email password
- smtpServer: Sets the smtpServer address
- emailPort: Sets the Port for the email server
- printInvite: Print the Invitation for the organization or send an Email
- disableRegistration: Disables user registration.


#### What is working so far:
- Create Users
- Add Ciphers:
    - Login Cipher:
        - Name, Folder, Username, Password, Notes
        - Custom Fields
		- URIs
		- Totp
    - Card Cipher:
        - Name, Folder, Brand, Number, Expiration Month, Expiration Year
        - Custom Fields
- Create Organizations:
    - Invite users with an email or with login-link
    - Login Cipher and Card Cipher as above

#### Organization
Organizational configuration example: (Suppose you run the WebVault at 4001)
**1.  Invitation without Email**
```
bitwarden-go -init
bitwarden-go -VaultURL http://localhost:4001
```
Create an organization and invite people:
Output in the console:  (Yes, there is a small typing error should be Invitation-Link)
```
InvationLink: http://localhost:8000/#/accept-organization?organizationId=46292791-2ec1-11e8-9dbd-a0999b1c5a79&organizationUserId=e19b5720-2fb7-11e8-824f-a0999b1c5a79&email=test@test.com&organizationName=Test&token=CDF
```
Share the link with the person you would like to invite. 

**2.  Invitation with Email**
```
bitwarden-go -init
bitwarden-go -Email your@email.com -emailPassword 123 -smtpServer example.smtp.com -emailPort 587 -printInvite false
bitwarden-go -VaultURL http://localhost:4001
```
Email with the invitation link is sent to the person. 

#### What is planned for the future:
- ~~Full support of Login Cipher~~ (testing required)
- ~~Full support of Card Cipher~~ (testing required)
- Add Identity and SecureNote
- ~~Add Totp~~ (testing required)
- Attachments support
- Collection support



