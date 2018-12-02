package account

//CreationRequest represents the data to be write in the result of the account creation request
type CreationRequest struct {
	EncryptedID       string `json:"encrypted_id"`
	EncryptedKeychain string `json:"encrypted_keychain"`
	Signature         string `json:"signature,omitempty"`
}

//SearchRequest represents the request to send to fetch an account
type SearchRequest struct {
	EncIDHash string
	Signature string
}
