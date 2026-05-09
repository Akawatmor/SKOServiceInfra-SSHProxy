package auth

func cloneSecret(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}

	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

func zeroSecret(secret []byte) {
	for idx := range secret {
		secret[idx] = 0
	}
}
