package sftp

const (
	// These values are wired into the vendored golang.org/x/crypto/ssh fork used
	// by this project for both proxy server channels and backend client channels.
	// Remote peers still advertise their own limits independently.
	ChannelWindowSize         = 64 * 1024 * 1024
	ChannelMaxPacketSize      = 256 * 1024
	SFTPMaxConcurrentRequests = 64
	SFTPReadBufferSize        = 256 * 1024
	SFTPWriteBufferSize       = 256 * 1024
)
