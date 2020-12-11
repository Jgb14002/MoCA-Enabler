package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
)

const baseURL string = "http://192.168.0.1/"

func main() {
	user, userPresent := os.LookupEnv("GATEWAY_USERNAME")
	pass, passPresent := os.LookupEnv("GATEWAY_PASSWORD")

	if !userPresent {
		log.Fatal("Missing environment variable: GATEWAY_USERNAME")
	}

	if !passPresent {
		log.Fatal("Missing environment variable: GATEWAY_PASSWORD")
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatal(err)
	}

	httpClient := &http.Client{
		Jar: jar,
	}

	log.Println("Acquiring authorization tokens...")

	if refreshAuth(httpClient, user, pass) != 200 {
		log.Fatal("Failed to acquire authorization tokens.")
	}

	log.Println("Querying MoCA status...")

	mocaEnabled := isMoCAEnabled(httpClient)
	if !mocaEnabled {
		log.Println("Attempting to enable MoCA...")
	} else {
		log.Fatal("MoCA is already enabled.")
		return
	}

	enableResponseCode := enableMoCA(httpClient, user)
	if enableResponseCode == 200 {
		log.Println("Successfully enabled MoCA.")
	} else {
		log.Println("Failed to enable MoCA.")
	}
}

func refreshAuth(httpClient *http.Client, user string, pass string) int {
	authFormData := url.Values{
		"username": {user},
		"password": {pass},
	}

	authRequest, err := http.NewRequest("POST", baseURL+"check.php", strings.NewReader(authFormData.Encode()))
	if err != nil {
		log.Fatal(err)
	}

	authRequest.Header.Set("User-Agent", "MoCA_Probe/0.1")
	authRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	authResponse, err := httpClient.Do(authRequest)
	if err != nil {
		log.Fatal(err)
	}
	defer authResponse.Body.Close()

	return authResponse.StatusCode
}

func isMoCAEnabled(httpClient *http.Client) bool {
	request, err := http.NewRequest("POST", baseURL+"actionHandler/ajaxSet_userbar.php", nil)
	if err != nil {
		log.Fatal(err)
	}

	request.Header.Set("User-Agent", "MoCA_Probe/0.1")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	appendCsrfpToken(httpClient, request)

	response, err := httpClient.Do(request)
	if err != nil {
		log.Fatal(err)
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}

	var result map[string]interface{}
	json.Unmarshal(body, &result)

	keys := result["mainStatus"].([]interface{})
	if keys == nil || len(keys) < 3 {
		log.Fatal("Received invalid response from router.")
	}

	return keys[2] == "true"
}

func enableMoCA(httpClient *http.Client, user string) int {

	configData := map[string]string{
		"moca_enable": "true",
		"thisUser":    user,
	}

	encodedData, _ := json.Marshal(configData)

	formData := url.Values{
		"configInfo": {string(encodedData)},
	}

	request, err := http.NewRequest("POST", baseURL+"actionHandler/ajaxSet_moca_config.php",
		strings.NewReader(formData.Encode()))
	if err != nil {
		log.Fatal(err)
	}

	request.Header.Set("User-Agent", "MoCA_Probe/0.1")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "*/*")
	appendCsrfpToken(httpClient, request)

	response, err := httpClient.Do(request)
	if err != nil {
		log.Fatal(err)
	}
	defer response.Body.Close()

	return response.StatusCode
}

func findCookie(cookies []*http.Cookie, name string) string {
	len := len(cookies)
	for i := 0; i < len; i++ {
		cookie := cookies[i]
		if cookie.Name == name {
			return cookie.Value
		}
	}
	return ""
}

func appendCsrfpToken(httpClient *http.Client, request *http.Request) {
	url, _ := url.Parse(baseURL)
	token := findCookie(httpClient.Jar.Cookies(url), "csrfp_token")
	if token == "" {
		log.Fatal("Failed to locate csrfp_token from client cookies. Ensure valid credentials were used.")
	}
	request.Header.Set("csrfp_token", token)
}
