# ECDH

[![GoDoc](https://godoc.org/github.com/noartem/ecdh?status.svg)](https://pkg.go.dev/github.com/noartem/ecdh)

### _I am not a cryptographer_

The simple implementation of an elliptical curve Diffie-Hellman key exchange method.

`ECDH` **can**:

1. Generate, marshal and unmarshal key pairs
2. Encrypt and decrypt messages
3. Sign and verify messages

## Examples

Generate shared secret, encrypt and decrypt a message

```go
package main

import (
    "github.com/noartem/ecdh"
)

func main() {
	// generate random Alice key pair
	alice, err := ecdh.GenerateKey()
	if err != nil { ... }

	// generate random Bob key pair
	bob, err := ecdh.GenerateKey()
	if err != nil { ... }

	// shared secret in Alice client
	secretAlice, err := alice.GenerateSecret(bob.PublicKey())
	if err != nil { ... }

	// shared secret in Bob client
	secretBob, err := bob.GenerateSecret(alice.PublicKey())
	if err != nil { ... }

	// always (secretAlice.Secret == secretBob.Secret)
	if secretAlice.Secret != secretBob.Secret {
		panic("Impossible")
	}

	// original message writen by Alice
	messageAlice := "Hello, Bob!"

	// encrypted Alice message
	encryptedMessage, err := secretAlice.Encrypt(messageAlice)
	if err != nil { ... }

	// Bob decrypt message and get original message
	messageBob, err := secretBob.Decrypt(encryptedMessage)
	if err != nil { ... }

	// always (messageBob == messageAlice)
	if messageBob != messageAlice {
		panic("Impossible")
	}
}
```

Marshal and unmarshal key pairs

```go
package main

import (
    "github.com/noartem/ecdh"
)

func main() {
	//
	// Alice side
	//

	// generate random Alice key pair
	alice, err := ecdh.GenerateKey()
	if err != nil { ... }

	// Marshal key pair into 2 strings
	privateKeyString, publicKeyString := alice.Marshal()

	// DO NOT SHARE privateKeyString
	// privateKeyString you can store in local storage
	saveInLocalStorage(privateKeyString)

	// Send publicKeyString to Bob
	sendToBob(publicKeyString)


	// Unmarshal alice key pair
	aliceUnmarshaled, err := ecdh.Unmarshal(privateKey, publicKey)
	if err != nil { ... }
	// "alice" == "aliceUnmarshaled" (deep compression)

	//
	// Bob side
	//

	// generate random Bob key pair
	bob, err := ecdh.GenerateKey()
	if err != nil { ... }

	alicePublicKeyString := getAliceKey()

	// unmarshal string from Alice to public key
	alicePublic, err := ecdh.UnmarshalPublic(alicePublicKeyString)
	if err != nil { ... }

	// shared secret in Alice client
	sharedSecret, err := bob.GenerateSecret(alicePublic)
	if err != nil { ... }
}
```

Sing and verify a random hash

```go
package main

import (
	"fmt"

	"github.com/noartem/ecdh"
)

func main() {
	//
	// Alice side
	//

	// generate random Alice key pair
	alice, err := ecdh.GenerateKey()
	if err != nil { ... }

	_, publicKeyString := alice.Marshal()

	R, S, hash, err := alice.Sign()
	if err != nil { ... }

	// R, S and hash is public information

	sendToBob(publicKeyString, R, S, hash)

	aliceUnmarshaled, err := ecdh.Unmarshal(privateKey, publicKey)
	if err != nil { ... }
	// "alice" == "aliceUnmarshaled" (deep compression)


	//
	// Bob side
	//

	// generate random Bob key pair
	bob, err := ecdh.GenerateKey()
	if err != nil { ... }

	alicePublicKeyString, R, S, hash := getAliceKey()

	// Verify verify Alice message
	messageIsReallyFromAlice, err := bob.Verify(R, S, hash, alicePublicKeyString)
	if err != nil { ... }

	// Check if message was signed by Alice
	if messageIsReallyFromAlice {
		fmt.Println("This message was signed by Alice! (and we verified it)")
	}
}
```
