package rest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/uniris/uniris-cli/pkg/account"
)

//RobotClient defines methods to interact with UNIRIS robot through HTTP
type RobotClient interface {
	account.RobotClient
}

type robotClient struct {
}

//NewRobotClient create http robot client
func NewRobotClient() RobotClient {
	return robotClient{}
}

func (c robotClient) CheckAccountExist(req account.SearchRequest) (bool, error) {
	peerIP, err := getWelcomeNode()
	if err != nil {
		return false, err
	}
	requestURI := fmt.Sprintf("%s/api/account/%s?signature=%s",
		peerIP,
		req.EncIDHash,
		req.Signature,
	)
	r, err := http.Head(requestURI)
	if err != nil {
		return false, err
	}

	errMsg := r.Header.Get("Error")
	if errMsg != "" {
		return false, errors.New(errMsg)
	}

	exist := r.Header.Get("Account-Exist")
	if exist == "true" {
		return true, nil
	}
	return false, nil
}

func (c robotClient) GetAccount(req account.SearchRequest) (*account.SearchResponse, error) {
	peerIP, err := getWelcomeNode()
	if err != nil {
		return nil, err
	}

	requestURI := fmt.Sprintf("%s/api/account/%s?signature=%s",
		peerIP,
		req.EncIDHash,
		req.Signature,
	)
	r, err := http.Get(requestURI)
	if err != nil {
		return nil, err
	}

	defer r.Body.Close()

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	if r.StatusCode == 404 {
		return nil, account.ErrAccountDoesNotExist
	}

	if r.StatusCode != 200 {
		return nil, fmt.Errorf("Unexpected error: %s", string(body))
	}

	var res *account.SearchResponse
	if err = json.Unmarshal(body, &res); err != nil {
		return nil, err
	}
	return res, nil
}

func (c robotClient) CreateAccount(req account.CreationRequest) (*account.CreationResult, error) {
	peerIP, err := getWelcomeNode()
	if err != nil {
		return nil, err
	}

	form, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	r, err := http.Post(
		fmt.Sprintf("%s/api/account", peerIP),
		"application/json",
		bytes.NewBuffer(form))

	if err != nil {
		return nil, err
	}

	defer r.Body.Close()

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	if r.StatusCode != 201 {
		return nil, fmt.Errorf("Unexpected error: %s", string(body))
	}

	var res *account.CreationResult
	if err = json.Unmarshal(body, &res); err != nil {
		return nil, err
	}

	return res, nil
}
