# DynamoDB Encryption Client for Go

This is a Go library that provides an encrypted client for interacting with Amazon DynamoDB. It allows you to perform common DynamoDB operations such as PutItem, GetItem, Query, Scan, BatchGetItem, BatchWriteItem, and DeleteItem while automatically encrypting and decrypting sensitive data.

## Features

- Encrypt and decrypt DynamoDB items transparently
- Support for standard and deterministic encryption
- Integration with AWS Key Management Service (KMS) for key management
- Customizable encryption actions for individual attributes
- Secure storage and retrieval of cryptographic materials
- High-level interface for working with encrypted DynamoDB tables
- Pagination support for Query and Scan operations

## Encryption Details

This library uses the Tink cryptographic library for performing encryption and decryption operations. Tink provides a set of high-level APIs for common cryptographic tasks and supports a wide range of encryption algorithms.

The default encryption algorithm used by this library is AES-256-GCM (Advanced Encryption Standard with 256-bit keys and Galois/Counter Mode). AES-256-GCM provides authenticated encryption, ensuring both confidentiality and integrity of the encrypted data.

For key management, this library integrates with AWS Key Management Service (KMS). The cryptographic materials, including encryption keys and signing keys, are protected using customer master keys (CMKs) stored in AWS KMS. This allows for secure key generation, storage, and rotation.

The library supports two types of encryption:

- **Standard Encryption:** Each attribute is encrypted independently using a unique data key. This provides strong confidentiality but does not preserve the order or equality of the encrypted values.
- **Deterministic Encryption:** Attributes are encrypted using a deterministic algorithm, which produces the same ciphertext for the same plaintext input. This allows for equality comparison of encrypted values but may leak some information about the data.

The choice between standard and deterministic encryption can be made on a per-attribute basis using attribute actions.

## Installation

To use this library in your Go project, you can install it using go get:

```shell
go get github.com/cloudopsy/dynamodb-encryption-go
```

## Usage

Here's a basic example of how to use the EncryptedClient to perform encrypted DynamoDB operations:

```go
import (
    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/service/dynamodb"
    "github.com/cloudopsy/dynamodb-encryption-go/pkg/encrypted"
    "github.com/cloudopsy/dynamodb-encryption-go/pkg/provider"
)

func main() {
    // Create a new AWS session
    cfg, err := config.LoadDefaultConfig(context.TODO())
    if err != nil {
        log.Fatalf("failed to load AWS configuration: %v", err)
    }

    // Create a DynamoDB client
    dynamodbClient := dynamodb.NewFromConfig(cfg)

    // Create a MetaStore for storing and retrieving metadata
    metaStore, err := store.NewMetaStore(dynamodbClient, "metadata-table")
    if err != nil {
        log.Fatalf("failed to create MetaStore: %v", err)
    }

    // Create a CryptographicMaterialsProvider with the desired key provider (e.g., AWS KMS)
    keyARN := "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    cmProvider, err := provider.NewAwsKmsCryptographicMaterialsProvider(keyARN, nil, metaStore)
    if err != nil {
        log.Fatalf("failed to create CryptographicMaterialsProvider: %v", err)
    }

    // Create a ClientConfig with the desired encryption options
    clientConfig := encrypted.NewClientConfig(
        encrypted.WithDefaultEncryption(encrypted.EncryptNone),
        encrypted.WithEncryption("SensitiveAttribute", encrypted.EncryptStandard),
    )

    // Create an EncryptedClient
    encryptedClient := encrypted.NewEncryptedClient(dynamodbClient, cmProvider, clientConfig)
}
```

Encrypting and Decrypting Items

With the EncryptedClient, you can perform various DynamoDB operations on encrypted items:

```go
// PutItem
item := map[string]types.AttributeValue{
    "ID":   {S: aws.String("123")},
    "Name": {S: aws.String("John")},
    "SensitiveAttribute": {S: aws.String("Sensitive Value")},
}
input := &dynamodb.PutItemInput{
    TableName: aws.String("my-table"),
    Item:      item,
}
_, err := encryptedClient.PutItem(context.TODO(), input)

// GetItem
key := map[string]types.AttributeValue{
    "ID": {S: aws.String("123")},
}
input := &dynamodb.GetItemInput{
    TableName: aws.String("my-table"),
    Key:       key,
}
result, err := encryptedClient.GetItem(context.TODO(), input)

// Query
input := &dynamodb.QueryInput{
    TableName: aws.String("my-table"),
    KeyConditionExpression: aws.String("ID = :id"),
    ExpressionAttributeValues: map[string]types.AttributeValue{
        ":id": {S: aws.String("123")},
    },
}
result, err := encryptedClient.Query(context.TODO(), input)
```

The EncryptedClient transparently encrypts and decrypts items based on the specified encryption options in the ClientConfig. It also handles the storage and retrieval of metadata using the MetaStore.

## MetaStore

The MetaStore is responsible for storing and retrieving metadata associated with encrypted items. It uses a separate DynamoDB table to store the metadata, which includes the encrypted data keys and other relevant information.

When an item is encrypted, the EncryptedClient generates a unique material name based on the item's primary key and stores the encrypted data key and metadata in the MetaStore. When decrypting an item, the EncryptedClient retrieves the corresponding metadata from the MetaStore to obtain the necessary decryption materials.

The MetaStore provides the following key functions:

- **StoreNewMaterial**: Stores new encryption metadata for an item.
- **RetrieveMaterial**: Retrieves the encryption metadata for an item based on its material name and version.
- **CreateTableIfNotExists**: Creates the metadata table if it doesn't exist.

The MetaStore ensures that the encryption metadata is securely stored and can be accessed efficiently during encryption and decryption operations.

## Contributing

Contributions to this library are welcome! If you find a bug, have a feature request, or want to contribute code improvements, please open an issue or submit a pull request on the GitHub repository.

## License

This library is licensed under the MIT License.
