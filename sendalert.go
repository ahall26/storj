package main

import (
	"fmt"
	"net/http"
	"strings"
)

func SendAlert(ciphertext string) {

	url := "https://api.pagerduty.com/incidents"
	method := "POST"

	payload := strings.NewReader("{\n    \"incident\": {\n        \"type\": \"incident\",\n        \"title\": \"Decryption Error\",\n        \"service\": {\n            \"id\": \"PEIVHZD\",\n            \"type\": \"service_reference\"\n        },\n        \"body\": {\n            \"type\": \"incident_body\",\n            \"details\": \" Failed Cipher Text: " + ciphertext + " \"\n        }\n    }\n}")

	client := &http.Client{}
	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		fmt.Println(err)
	}
	req.Header.Add("Authorization", "Token token =aETAE2ajHFYssfyXpnZR")
	req.Header.Add("Accept", "application/vnd.pagerduty+json;version=2")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("From", "Regulus-Ain-efc7b0b0@dispostable.com")

	res, err := client.Do(req)

	defer res.Body.Close()

}
