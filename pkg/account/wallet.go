package account

//Wallet describes the UNIRIS wallet
type Wallet struct {
	Services map[string]walletService `json:"services"`
}

//NewWallet creates a new all with UNIRIS service by default
func NewWallet(irisPvKey string) Wallet {
	w := Wallet{
		Services: make(map[string]walletService, 0),
	}

	w.Services["IRIS"] = walletService{
		PrivateKey: irisPvKey,
	}

	return w
}

//WalletService describes a wallet service
type walletService struct {
	PrivateKey string `json:"privk"`
}
