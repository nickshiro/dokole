package reality

const (
	sessionIDLenOffset = 38 // handshake header (4) + version (2) + random (32)
	sessionIDOffset    = 39
	sessionIDLen       = 32
)
