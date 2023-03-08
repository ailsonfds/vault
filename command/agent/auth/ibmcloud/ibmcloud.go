package ibmcloud

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/agent/auth"
)

const (
	typeTrustedProfile            = "trusted_profile"
	defaultCredentialPollInterval = 60
)

type ibmcloudMethod struct {
	logger      hclog.Logger
	authType    string
	saTokenPath string
	profileID   string
	region      string

	// These are used to share the latest creds safely across goroutines.
	credLock  sync.Mutex
	lastCreds *IBMAPIAuthResponseStruct

	// Notifies the outer environment that it should call Authenticate again.
	credsFound chan struct{}

	// Detects that the outer environment is closing.
	stopCh chan struct{}
}

type IBMAPIError struct {
	Metadata struct {
		CollectionType  string `json:"collection_type"`
		CollectionTotal int    `json:"collection_total"`
	} `json:"metadata"`
	Resources []struct {
		ErrorMessage string `json:"error_message"`
	} `json:"resources"`
	Errors []struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
}

type IBMAPIAuthResponseStruct struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Expiration   int    `json:"expiration"`
	Scope        string `json:"scope"`
}

func (r *IBMAPIAuthResponseStruct) IsExpired() bool {
	t := time.UnixMilli(int64(r.Expiration))
	dt := time.Until(t)
	return dt > 0
}

func NewIBMCloudAuthMethod(conf *auth.AuthConfig) (auth.AuthMethod, error) {
	if conf == nil {
		return nil, errors.New("empty config")
	}
	if conf.Config == nil {
		return nil, errors.New("empty config data")
	}

	a := &ibmcloudMethod{
		logger:     conf.Logger,
		credsFound: make(chan struct{}),
		stopCh:     make(chan struct{}),
	}

	typeRaw, ok := conf.Config["type"]
	if !ok {
		return nil, errors.New("missing 'type' value")
	}
	a.authType, ok = typeRaw.(string)
	if !ok {
		return nil, errors.New("could not convert 'type' config value to string")
	}

	switch {
	case a.authType == "":
		return nil, errors.New("'type' value is empty")
	case a.authType != typeTrustedProfile:
		return nil, errors.New("'type' value is invalid")
	}

	saTokenPathRaw, ok := conf.Config["sa_token_path"]
	if !ok {
		return nil, errors.New("missing 'sa_token_path' value")
	}
	a.saTokenPath, ok = saTokenPathRaw.(string)
	if !ok {
		return nil, errors.New("could not convert 'sa_token_path' config value to string")
	}

	regionRaw, ok := conf.Config["region"]
	if ok {
		a.region, ok = regionRaw.(string)
		if !ok {
			return nil, errors.New("could not convert 'region' value into string")
		}
	}

	profileIDRaw, ok := conf.Config["profile_id"]
	if ok {
		a.profileID, ok = profileIDRaw.(string)
		if !ok {
			return nil, errors.New("could not convert 'profile_id' value into string")
		}
	}
	if a.authType == typeTrustedProfile {

		// Check for an optional custom frequency at which we should poll for creds.
		credentialPollIntervalSec := defaultCredentialPollInterval
		if credentialPollIntervalRaw, ok := conf.Config["credential_poll_interval"]; ok {
			if credentialPollInterval, ok := credentialPollIntervalRaw.(int); ok {
				credentialPollIntervalSec = credentialPollInterval
			} else {
				return nil, errors.New("could not convert 'credential_poll_interval' into int")
			}
		}

		// Do an initial population of the creds because we want to err right away if we can't
		// even get a first set.
		creds, err := getIAMCreds(a.saTokenPath, a.profileID)
		if err != nil {
			return nil, err
		}
		a.lastCreds = creds

		go a.pollForCreds(a.saTokenPath, credentialPollIntervalSec)
	}

	return a, nil
}

func (a *ibmcloudMethod) Authenticate(ctx context.Context, client *api.Client) (retToken string, header http.Header, retData map[string]interface{}, retErr error) {
	a.logger.Trace("beginning authentication")

	data := make(map[string]interface{})

	a.credLock.Lock()
	defer a.credLock.Unlock()

	data["token"] = a.lastCreds

	return "auth/ibmcloud/login", nil, data, nil
}

func (a *ibmcloudMethod) NewCreds() chan struct{} {
	return a.credsFound
}

func (a *ibmcloudMethod) CredSuccess() {}

func (a *ibmcloudMethod) Shutdown() {
	close(a.credsFound)
	close(a.stopCh)
}

func (a *ibmcloudMethod) pollForCreds(saTokenPath string, frequencySeconds int) {
	ticker := time.NewTicker(time.Duration(frequencySeconds) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-a.stopCh:
			a.logger.Trace("shutdown triggered, stopping ibmcloud auth handler")
			return
		case <-ticker.C:
			if err := a.checkCreds(saTokenPath); err != nil {
				a.logger.Warn("unable to retrieve current creds, retaining last creds", "error", err)
			}
		}
	}
}

func (a *ibmcloudMethod) checkCreds(saTokenPath string) error {
	a.credLock.Lock()
	defer a.credLock.Unlock()

	a.logger.Trace("checking for new credentials")
	currentCreds, err := getIAMCreds(saTokenPath, a.profileID)
	if err != nil {
		return err
	}

	// These will always have different pointers regardless of whether their
	// values are identical, hence the use of DeepEqual.
	if !a.lastCreds.IsExpired() && reflect.DeepEqual(currentCreds, a.lastCreds) {
		a.logger.Trace("credentials are unchanged and still valid")
		return nil
	}

	a.lastCreds = currentCreds
	a.logger.Trace("new credentials detected, triggering Authenticate")
	a.credsFound <- struct{}{}
	return nil
}

func getIAMCreds(tokenPath, profileID string) (data *IBMAPIAuthResponseStruct, err error) {

	client := &http.Client{}

	// Add payload data
	body := url.Values{}
	cr_token, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, err
	}
	body.Set("cr_token", string(cr_token))
	body.Set("grant_type", "urn:ibm:params:oauth:grant-type:cr-token")
	body.Set("profile_id", profileID)

	req, err := http.NewRequest("POST", "https://iam.cloud.ibm.com/identity/token", strings.NewReader(body.Encode()))
	if err != nil {
		return nil, err
	}
	// Add headers
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		payloadErr := new(IBMAPIError)
		json.NewDecoder(resp.Body).Decode(payloadErr)
		return nil, errors.New(payloadErr.Errors[0].Message)
	}
	if resp.StatusCode != 200 {
		payloadErr := new(IBMAPIError)
		json.NewDecoder(resp.Body).Decode(payloadErr)
		return nil, errors.New(fmt.Sprintf("Unkown status code: %s. Message: %s", resp.Status, resp.Body))
	}

	defer resp.Body.Close()

	data = new(IBMAPIAuthResponseStruct)
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(data)
	if err != nil {
		return nil, err
	}

	return data, err
}
