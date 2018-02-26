// FIDO U2F Go Library
// Copyright 2015 The FIDO U2F Go Library Authors. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/kr/pretty"
	"github.com/stephen-soltesz/u2f"
)

const appID = "https://localhost:3483"

var trustedFacets = []string{appID}

// Normally these state variables would be stored in a database.
// For the purposes of the demo, we just store them in memory.
var challenge *u2f.Challenge

var registrations []u2f.Registration
var counter uint32

func registerRequest(w http.ResponseWriter, r *http.Request) {
	c, err := u2f.NewChallenge(appID, trustedFacets, "")
	if err != nil {
		log.Printf("u2f.NewChallenge error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	challenge = c
	req := u2f.NewWebRegisterRequest(c, registrations)

	log.Printf("Register request:")
	var data bytes.Buffer
	json.NewEncoder(&data).Encode(req)
	fmt.Println(data.String())
	fmt.Println()
	w.Write([]byte(data.String()))
}

func registerResponse(w http.ResponseWriter, r *http.Request) {
	var regResp u2f.RegisterResponse
	if err := json.NewDecoder(r.Body).Decode(&regResp); err != nil {
		http.Error(w, "invalid response: "+err.Error(), http.StatusBadRequest)
		return
	}

	pretty.Println("Register response:")
	pretty.Println(regResp)
	pretty.Println()

	if challenge == nil {
		http.Error(w, "challenge not found", http.StatusBadRequest)
		return
	}

	// cfg := &u2f.Config{SkipAttestationVerify: true}
	reg, err := u2f.Register(regResp, *challenge, nil)
	if err != nil {
		log.Printf("u2f.Register error: %v", err)
		http.Error(w, "error verifying response", http.StatusInternalServerError)
		return
	}

	registrations = append(registrations, *reg)
	counter = 0

	pretty.Println("Register success")
	w.Write([]byte("success"))
}

func signRequest(w http.ResponseWriter, r *http.Request) {
	if registrations == nil {
		http.Error(w, "registration missing", http.StatusBadRequest)
		return
	}

	r.ParseForm()
	// TODO: report an error if msg is empty.
	// An empty message will sign 32 random bytes.
	msg := r.Form.Get("message")
	fmt.Printf("Raw query  : %q\n", r.URL.RawQuery)
	fmt.Printf("Raw message: %q\n", msg)

	c, err := u2f.NewChallenge(appID, trustedFacets, msg)
	if err != nil {
		log.Printf("u2f.NewChallenge error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	challenge = c

	req := c.SignRequest(registrations)

	log.Println("Sign request:")
	pretty.Println(req)
	fmt.Println()
	var data bytes.Buffer
	json.NewEncoder(&data).Encode(req)
	fmt.Println(data.String())
	fmt.Println()
	w.Write([]byte(data.String()))
}

func signResponse(w http.ResponseWriter, r *http.Request) {
	var signResp u2f.SignResponse
	if err := json.NewDecoder(r.Body).Decode(&signResp); err != nil {
		http.Error(w, "invalid response: "+err.Error(), http.StatusBadRequest)
		return
	}

	log.Println("Sign response:")
	pretty.Println(signResp)
	pretty.Println()

	if challenge == nil {
		http.Error(w, "challenge missing", http.StatusBadRequest)
		return
	}
	if registrations == nil {
		http.Error(w, "registration missing", http.StatusBadRequest)
		return
	}

	var err error
	for _, reg := range registrations {
		newCounter, authErr := reg.Authenticate(signResp, *challenge, counter)
		if authErr == nil {
			log.Printf("newCounter: %d", newCounter)
			counter = newCounter
			w.Write([]byte("success"))
			return
		}
	}

	log.Printf("VerifySignResponse error: %v", err)
	http.Error(w, "error verifying response", http.StatusInternalServerError)
}

const indexHTML = `
<!DOCTYPE html>
<html>
  <head>
    <script src="//code.jquery.com/jquery-1.11.2.min.js"></script>

    <!-- The original u2f-api.js code can be found here:
    https://github.com/google/u2f-ref-code/blob/master/u2f-gae-demo/war/js/u2f-api.js -->
    <script type="text/javascript" src="https://demo.yubico.com/js/u2f-api.js"></script>

  </head>
  <body>
    <h1>FIDO U2F Go Library Demo</h1>

    <p>NOTE: Open Chrome Developer Tools to see debug console logs.</p>

    <ul>
      <li><a href="javascript:register();">Register token</a></li>
      <li><a href="javascript:sign();">Sign message</a><br/>
        <textarea rows="4" cols="50" id="message">Message to sign.</textarea>
      </li>
    </ul>

    <script>

  function serverError(data) {
    console.log(data);
    console.log('Server error code ' + data.status + ': ' + data.responseText);
  }

  function checkError(resp) {
    if (!('errorCode' in resp)) {
      return false;
    }
    if (resp.errorCode === u2f.ErrorCodes['OK']) {
      return false;
    }
    var msg = 'U2F error code ' + resp.errorCode;
    for (name in u2f.ErrorCodes) {
      if (u2f.ErrorCodes[name] === resp.errorCode) {
        msg += ' (' + name + ')';
      }
    }
    if (resp.errorMessage) {
      msg += ': ' + resp.errorMessage;
    }
    console.log(msg);
    console.log(msg);
    return true;
  }

  function u2fRegistered(resp) {
    console.log(resp);
    if (checkError(resp)) {
      return;
    }
    $.post('/registerResponse', JSON.stringify(resp)).success(function() {
      console.log('Success');
    }).fail(serverError);
  }

  function register() {
    $.getJSON('/registerRequest').success(function(req) {
      console.log(req);
      u2f.register(req.appId, req.registerRequests, req.registeredKeys, u2fRegistered, 30);
      console.log('\nTouch key to register!\n');
    }).fail(serverError);
  }

  function u2fSigned(resp) {
    console.log(resp);
    if (checkError(resp)) {
      return;
    }
    $.post('/signResponse', JSON.stringify(resp)).success(function() {
      console.log('Success');
    }).fail(serverError);
  }

  function sign() {
    // Find the message form in the DOM by id.
    const form = document.getElementById('message');

    // Get the form data and encode it to preserve spaces, new lines, and special characters.
    $.getJSON('/signRequest?message=' + encodeURIComponent(form.value)).success(function(req) {
      console.log(req);
      console.log('\nTouch key to sign!\n');
      u2f.sign(req.appId, req.challenge, req.registeredKeys, u2fSigned, 30);
    }).fail(serverError);
  }

    </script>

  </body>
</html>
`

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(indexHTML))
}

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/registerRequest", registerRequest)
	http.HandleFunc("/registerResponse", registerResponse)
	http.HandleFunc("/signRequest", signRequest)
	http.HandleFunc("/signResponse", signResponse)

	certs, err := tls.X509KeyPair([]byte(tlsCert), []byte(tlsKey))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Running on %s", appID)

	var s http.Server
	s.Addr = ":3483"
	s.TLSConfig = &tls.Config{Certificates: []tls.Certificate{certs}}
	log.Fatal(s.ListenAndServeTLS("", ""))
}
