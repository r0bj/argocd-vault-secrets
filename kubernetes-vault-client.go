package main

import (
	"fmt"
	"net/http"
	"crypto/tls"
	"crypto/x509"
	"path"
	"strings"
	"io/ioutil"

	log "github.com/sirupsen/logrus"
	"github.com/hashicorp/vault/api"
	"gopkg.in/square/go-jose.v2/jwt"
)

// TokenJWTPayload : containts token JWT payload data
type TokenJWTPayload struct {
	serviceAccountName string
	namespace string
}

func buildHTTPClient(url, caCert string) (*http.Client, error) {
	if strings.HasPrefix(url, "http://") {
		return http.DefaultClient, nil
	}

	// Get the SystemCertPool, continue with an empty pool on error
	caCertPool, _ := x509.SystemCertPool()
	if caCertPool == nil {
		caCertPool = x509.NewCertPool()
	}

	if caCert != "" {
		// Read in the cert file
		sslCerts, err := ioutil.ReadFile(caCert)
		if err != nil {
			return nil, fmt.Errorf("Failed to read file %s", caCert)
		}

		// Append our cert to the system pool
		if ok := caCertPool.AppendCertsFromPEM(sslCerts); !ok {
			log.Info("No certs appended, using system certs only")
		}
	}

	// Trust the augmented cert pool in our client
	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
		InsecureSkipVerify: *insecure,
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	httpClient := &http.Client{
		Transport: transport,
	}

	return httpClient, nil
}

func extractServiceAccountData(token string) (TokenJWTPayload, error) {
	parsedJWT, err := jwt.ParseSigned(token)
	if err != nil {
		return TokenJWTPayload{}, fmt.Errorf("Parse JWT token failed: %v", err)
	}

	var claims map[string]interface{}
	err = parsedJWT.UnsafeClaimsWithoutVerification(&claims)
	if err != nil {
		return TokenJWTPayload{}, fmt.Errorf("Cannot deserializes claims from JWT token: %v", err)
	}

	var tokenJWTPayload TokenJWTPayload
	if value, ok := claims["kubernetes.io/serviceaccount/service-account.name"]; ok {
		tokenJWTPayload.serviceAccountName = value.(string)
	} else {
		return TokenJWTPayload{}, fmt.Errorf("Cannot find service-account key in JWT token payload")
	}

	if value, ok := claims["kubernetes.io/serviceaccount/namespace"]; ok {
		tokenJWTPayload.namespace = value.(string)
	} else {
		return TokenJWTPayload{}, fmt.Errorf("Cannot find namespace key in JWT token payload")
	}

	return tokenJWTPayload, nil
}

func vaultLogin(kubeToken, kubeAuthMountPath, vaultRole, caCert string) (*api.Client, error) {
	sa, err := extractServiceAccountData(kubeToken)
	if err != nil {
		return nil, fmt.Errorf("Failed to extract ServiceAccount from token: %v", err)
	}

	httpClient, err := buildHTTPClient(*vaultURL, caCert)
	if err != nil {
		return nil, err
	}

	config := &api.Config{
		Address: *vaultURL,
		HttpClient: httpClient,
	}
	client, err := api.NewClient(config)
	if err != nil {
		return nil, err
	}

	var vaultRoleName string
	if vaultRole != "" {
		vaultRoleName = vaultRole
	} else {
		vaultRoleName = sa.serviceAccountName
	}

	body := map[string]interface{}{
		"role": vaultRoleName,
		"jwt": kubeToken,
	}

	loginPath := path.Join("auth", kubeAuthMountPath, "login")
	loginPath = path.Clean(loginPath)

	result, err := client.Logical().Write(loginPath, body)
	if err != nil {
		return nil, fmt.Errorf("Vault login using path %s failed: %v", loginPath, err)
	}
	log.Debugf("Login results %+v", result)

	client.SetToken(result.Auth.ClientToken)

	return client, nil
}
