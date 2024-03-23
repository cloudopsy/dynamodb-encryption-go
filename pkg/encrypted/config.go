package encrypted

// EncryptionAction represents the encryption-related action to be taken on a specific attribute.
type EncryptionAction int

const (
	// EncryptNone indicates that no encryption should be applied.
	EncryptNone EncryptionAction = iota
	// EncryptStandard indicates the attribute should be encrypted using a standard algorithm.
	EncryptStandard
	// EncryptDeterministic indicates the attribute should be encrypted deterministically for consistent outcomes.
	EncryptDeterministic
	// Additional encryption actions can be defined here.
)

// CompressionAction represents the compression action to be taken on a specific attribute.
type CompressionAction int

const (
	// CompressNone indicates no compression should be applied.
	CompressNone CompressionAction = iota
	// CompressGzip indicates the attribute should be compressed using GZip.
	CompressGzip
	// CompressZstd indicates the attribute should be compressed using Zstd.
	CompressZstd
)

// ClientConfig holds the configuration for client operations like encryption and compression.
type ClientConfig struct {
	Encryption  EncryptionConfig
	Compression CompressionConfig
}

// EncryptionConfig holds encryption-specific settings.
type EncryptionConfig struct {
	DefaultAction   EncryptionAction
	SpecificActions map[string]EncryptionAction
}

// CompressionConfig holds compression-specific settings.
type CompressionConfig struct {
	DefaultAction   CompressionAction
	SpecificActions map[string]CompressionAction
}

// NewClientConfig creates a new ClientConfig with provided options.
func NewClientConfig(options ...Option) *ClientConfig {
	config := &ClientConfig{
		Encryption: EncryptionConfig{
			DefaultAction:   EncryptNone,
			SpecificActions: make(map[string]EncryptionAction),
		},
		Compression: CompressionConfig{
			DefaultAction:   CompressNone,
			SpecificActions: make(map[string]CompressionAction),
		},
	}

	for _, option := range options {
		option(config)
	}

	return config
}

// Option applies a configuration to a ClientConfig.
type Option func(*ClientConfig)

// WithDefaultEncryptionAction sets the default encryption action for the client.
func WithDefaultEncryption(action EncryptionAction) Option {
	return func(c *ClientConfig) {
		c.Encryption.DefaultAction = action
	}
}

// WithEncryption sets an encryption action for a specific attribute.
func WithEncryption(attributeName string, action EncryptionAction) Option {
	return func(c *ClientConfig) {
		if c.Encryption.SpecificActions == nil {
			c.Encryption.SpecificActions = make(map[string]EncryptionAction)
		}
		c.Encryption.SpecificActions[attributeName] = action
	}
}
