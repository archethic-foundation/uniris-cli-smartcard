package account

//Details defines decrypted account information
type Details struct {
	Wallet Wallet
	Addr   string
}

//SearchResponse defines encrypted account information signed
type SearchResponse struct {
	EncryptedAESKey  string `json:"encrypted_aes_key"`
	EncryptedWallet  string `json:"encrypted_wallet"`
	EncryptedAddress string `json:"encrypted_address"`
	Signature        string `json:"signature,omitempty"`
}

//CreationResult defines account creation result signed
type CreationResult struct {
	Transactions CreationTransactions `json:"transactions"`
	Signature    string               `json:"signature,omitempty"`
}

//CreationTransactions  represents the generated transactions during the the account creation
type CreationTransactions struct {
	ID       Transaction `json:"id" binding:"required"`
	Keychain Transaction `json:"keychain" binding:"required"`
}

//Transaction represents a transaction
type Transaction struct {
	TransactionHash string `json:"transaction_hash" binding:"required"`
	MasterPeerIP    string `json:"master_peer_ip" binding:"required"`
	Signature       string `json:"signature" binding:"required"`
}

//Result defines the enrollement result
type Result struct {
	Transactions CreationTransactions
	Address      string
}
