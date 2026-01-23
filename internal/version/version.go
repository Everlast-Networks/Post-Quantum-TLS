package version

const (
	ProtocolMagic          = "QTL1"
	ProtocolVersion uint16 = 1

	// V1 hard requirement.
	KEMName = "ML-KEM-1024"

	// Signature context, must match on both ends.
	SigContext = "qtls-v1"
)
