package main

import (
	"fmt"
	"os"
	"strings"
	"io/ioutil"
	"regexp"
	"path/filepath"
	"bytes"
	"io"
	"encoding/base64"

	"gopkg.in/alecthomas/kingpin.v2"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const (
	ver string = "0.1"
	logDateLayout string = "2006-01-02 15:04:05"
	annotationVaultPathKey string = "fandom.com/vault-path"
)

var (
	verbose = kingpin.Flag("verbose", "Verbose mode").Short('v').Envar("AVS_VERBOSE").Bool()
	CACert = kingpin.Flag("ca-cert", "TLS CA certificate path").Default("/etc/ssl/certs/wikia_internal_root_ca.crt").Envar("AVS_CA_CERT").String()
	insecure = kingpin.Flag("insecure-ssl", "Accept/Ignore all server SSL certificates").Envar("AVS_INSECURE").Bool()
	vaultURL = kingpin.Flag("vault-url", "Vault URL").Default("https://active.vault.service.consul:8200").Envar("AVS_VAULT_URL").String()
	tokenFile = kingpin.Flag("token-file", "Token file").Default("/var/run/secrets/kubernetes.io/serviceaccount/token").Envar("AVS_TOKEN_FILE").String()
	kubeAuthMountPath = kingpin.Flag("vault-kubernetes-auth-mount-path", "Path where the Kubernetes authentication backend is mounted in Vault").Required().Envar("AVS_VAULT_KUBERNETES_AUTH_MOUNT_PATH").String()
	vaultRole = kingpin.Flag("vault-role", "Vault role. If not specified, current ServiceAccount name will be used as a vault role").Envar("AVS_VAULT_ROLE").String()
	rootPath = kingpin.Arg("root-path", "Root path").Required().String()
)

func listYamlFiles(root string) ([]string, error) {
	var files []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if filepath.Ext(path) == ".yaml" || filepath.Ext(path) == ".yml" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return files, err
	}

	return files, nil
}

func readFilesAsManifests(paths []string) ([]map[string]interface{}, error) {
	var result []map[string]interface{}

	for _, path := range paths {
		file, err := ioutil.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("Cannot read file %s: %v", path, err)
		}

		decoder := yaml.NewDecoder(bytes.NewReader(file))
		for {
			var document map[string]interface{}
			if err := decoder.Decode(&document); err == io.EOF {
				break
			} else if err != nil {
				return nil, fmt.Errorf("YAML document decode error: %v", err)
			}

			result = append(result, document)
		}
	}

	return result, nil
}

func printYaml(manifests []map[string]interface{}) error {
	for _, manifest := range manifests {
		yaml, err := yaml.Marshal(&manifest)
		if err != nil {
			return fmt.Errorf("YAML marshall failed: %v", err)
		}

		fmt.Printf("---\n%s", string(yaml))
	}

	return nil
}

func extractVaultSecretKey(value string) (string, error) {
	re := regexp.MustCompile(`^<([^<> ]+)>$`)
	match := re.FindStringSubmatch(value)
	if match == nil {
		return "", fmt.Errorf("Value do not match pattern <value>: %s", value)
	}

	return match[1], nil
}

func extractAnnotationValue(manifest map[string]interface{}) (string, error) {
	annotationValid := false
	var vaultPath string
	if _, ok := manifest["metadata"]; ok {
		if manifest["metadata"] != nil {
			if _, ok := manifest["metadata"].(map[string]interface{})["annotations"]; ok {
				if manifest["metadata"].(map[string]interface{})["annotations"] != nil {
					if value, ok := manifest["metadata"].(map[string]interface{})["annotations"].(map[string]interface{})[annotationVaultPathKey]; ok {
						if value != nil {
							vaultPath = value.(string)
							annotationValid = true
						}
					}
				}
			}
		}
	}

	if !annotationValid {
		return "", fmt.Errorf("Cannot find annotation")
	}

	return vaultPath, nil
}

func injectVaultDataIntoManifests(manifests []map[string]interface{}) ([]map[string]interface{}, error) {
	kubeToken, err := ioutil.ReadFile(*tokenFile)
	if err != nil {
		return nil, fmt.Errorf("Cannot read read file %s", *tokenFile)
	}

	vaultClient, err := vaultLogin(string(kubeToken), *kubeAuthMountPath, *vaultRole)
	if err != nil {
		return nil, fmt.Errorf("Vault login failed %s", err)
	}

	for _, manifest := range manifests {
		vaultPath, err := extractAnnotationValue(manifest)
		if err != nil {
			continue
		}

		if vaultPath == "" {
			return nil, fmt.Errorf("Vault path cannot be empty")
		}

		vaultPath = strings.TrimPrefix(vaultPath, "/")
		vaultPath = strings.TrimSuffix(vaultPath, "/")
		vaultSecret, err := vaultClient.Logical().Read(vaultPath)
		if err != nil {
			return nil, fmt.Errorf("Cannot fetch vault secret %s: %v", vaultPath, err)
		}

		if vaultSecret == nil {
			return nil, fmt.Errorf("Secret %s does not exists", vaultPath)
		}

		if _, ok := manifest["data"]; ok {
			if manifest["data"] == nil {
				return nil, fmt.Errorf("Manifest field data is empty")
			}

			for manifestItemKey, manifestItemValue := range manifest["data"].(map[string]interface{}) {
				if manifestItemValue == nil {
					return nil, fmt.Errorf("Manifest key %s empty", manifestItemKey)
				}

				extractedValue, err := extractVaultSecretKey(manifestItemValue.(string))
				if err != nil {
					return nil, fmt.Errorf("Extracting value for %s failed: %v", manifestItemKey, err)
				}

				vaultKeyValid := false
				for secretItemKey, secretItemValue := range vaultSecret.Data {
					if extractedValue == secretItemKey {
						manifest["data"].(map[string]interface{})[manifestItemKey] = base64.StdEncoding.EncodeToString([]byte(secretItemValue.(string)))
						vaultKeyValid = true
						break
					}
				}

				if !vaultKeyValid {
					return nil, fmt.Errorf("Cannot find key %s in secret %s", manifestItemValue, vaultPath)
				}
			}
		} else {
			log.Warn("Secret definition does not contain data field")
			continue	
		}

	}

	return manifests, nil
}

func processSecrets(rootPath string) error {
	paths, err := listYamlFiles(rootPath)
	if err != nil {
		return fmt.Errorf("List YAML files failed: %v", err)
	}

	manifests, err := readFilesAsManifests(paths)
	if err != nil {
		return fmt.Errorf("Extract YAML manifests from files failed: %v", err)
	}

	manifests, err = injectVaultDataIntoManifests(manifests)
	if err != nil {
		return err
	}

	if err := printYaml(manifests); err != nil {
		return err
	}

	return nil
}

func main() {
	customFormatter := new(log.TextFormatter)
	customFormatter.TimestampFormat = logDateLayout
	log.SetFormatter(customFormatter)
	customFormatter.FullTimestamp = true

	kingpin.Version(ver)
	kingpin.Parse()

	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	log.Debugf("Starting version %s", ver)

	if err := processSecrets(*rootPath); err != nil {
		log.Fatal(err)
	}
}
