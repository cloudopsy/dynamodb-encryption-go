package crypto

type Option int

const (
	Encrypt Option = iota
	EncryptDeterministically
	DoNothing
)

type EncryptorOption func(*EncryptorDecryptor) error

func WithDefault(option Option) EncryptorOption {
	return func(ed *EncryptorDecryptor) error {
		if ed.options == nil {
			ed.options = make(map[string]Option)
		}
		ed.options["__default__"] = option
		return nil
	}
}

// WithAttribute sets the encryption action for a specific attribute.
func WithAttribute(attributeName string, option Option) EncryptorOption {
	return func(ed *EncryptorDecryptor) error {
		if ed.options == nil {
			ed.options = make(map[string]Option)
		}
		ed.options[attributeName] = option
		return nil
	}
}

// WithKMS configures the EncryptorDecryptor to use an AEAD instance from AWS KMS.
func WithKMS(keyURI string) EncryptorOption {
	return func(e *EncryptorDecryptor) error {
		kmsAEAD, err := setupKmsEnvelopeAEAD(keyURI)
		if err != nil {
			return err
		}
		e.aead = kmsAEAD
		return nil
	}
}
