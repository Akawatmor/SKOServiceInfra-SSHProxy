package auth

import "golang.org/x/crypto/ssh"

func fingerprintPublicKey(key ssh.PublicKey) string {
	if key == nil {
		return ""
	}
	return ssh.FingerprintSHA256(key)
}
