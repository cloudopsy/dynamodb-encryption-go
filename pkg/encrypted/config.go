package encrypted

// EncryptionAction represents the encryption-related action to be taken on a specific attribute.
type EncryptionAction int

const (
	EncryptNone          EncryptionAction = iota // No encryption should be applied.
	EncryptStandard                              // The attribute should be encrypted using a standard algorithm.
	EncryptDeterministic                         // The attribute should be encrypted deterministically for consistent outcomes.
)

// ClientConfig holds the configuration for client operations, focusing on encryption.
type ClientConfig struct {
	Encryption EncryptionConfig
}

// EncryptionConfig holds encryption-specific settings, including a default action and specific actions for named attributes.
type EncryptionConfig struct {
	DefaultAction   EncryptionAction            // The default encryption action if no specific action is provided.
	SpecificActions map[string]EncryptionAction // Map of attribute names to their specific encryption actions.
}

// NewClientConfig initializes a new ClientConfig, applying any provided functional options.
func NewClientConfig(options ...Option) *ClientConfig {
	config := &ClientConfig{
		Encryption: EncryptionConfig{
			DefaultAction:   EncryptNone, // Default to no encryption unless specified.
			SpecificActions: make(map[string]EncryptionAction),
		},
	}

	// Apply each provided option to the ClientConfig.
	for _, option := range options {
		option(config)
	}

	return config
}

// Option defines a function signature for options that modify ClientConfig.
type Option func(*ClientConfig)

// WithDefaultEncryptionAction sets the default encryption action for the client.
func WithDefaultEncryption(action EncryptionAction) Option {
	return func(c *ClientConfig) {
		c.Encryption.DefaultAction = action
	}
}

// WithEncryption sets a specific encryption action for a named attribute.
func WithEncryption(attributeName string, action EncryptionAction) Option {
	return func(c *ClientConfig) {
		c.Encryption.SpecificActions[attributeName] = action
	}
}

// EncryptedClientOption defines a function signature for options that modify an EncryptedClient.
type EncryptedClientOption func(*EncryptedClient)

// WithClientConfig sets the EncryptedClient's configuration.
func WithClientConfig(config *ClientConfig) EncryptedClientOption {
	return func(ec *EncryptedClient) {
		ec.ClientConfig = config
	}
}
