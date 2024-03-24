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

## Installation

To use this library in your Go project, you can install it using go get:

```shell
go get github.com/cloudopsy/dynamodb-encryption-go
```

## Usage

Here's a basic example of how to use the EncryptedClient to perform encrypted DynamoDB operations:

```go
import (
    "context"
    "github.com/aws/aws-sdk-go-v2/service/dynamodb"
    "github.com/cloudopsy/dynamodb-encryption-go/pkg/encrypted"
    "github.com/cloudopsy/dynamodb-encryption-go/pkg/provider"
)

func main() {
    // Create a regular DynamoDB client
    dynamodbClient := dynamodb.NewFromConfig(cfg)

    // Create a key material store
    materialStore, err := store.NewMetaStore(dynamodbClient, "metastore-table")
    if err != nil {
        log.Fatalf("Failed to create key material store: %v", err)
    }
    if err := materialStore.CreateTableIfNotExists(context.Background()); err != nil {
        log.Fatalf("Failed to ensure metastore table exists: %v", err)
    }

    // Create a cryptographic materials provider
    keyURI := "aws-kms://arn:aws:kms:eu-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    cmp, err := provider.NewAwsKmsCryptographicMaterialsProvider(keyURI, nil, materialStore)
    if err != nil {
        log.Fatalf("Failed to create cryptographic materials provider: %v", err)
    }

    // Create an encrypted DynamoDB client
    attributeActions := encrypted.NewAttributeActions(encrypted.AttributeActionDoNothing)
    attributeActions.SetAttributeAction("SensitiveData", encrypted.AttributeActionEncrypt)
    encryptedClient := encrypted.NewEncryptedClient(dynamodbClient, cmp, attributeActions)

    // Perform encrypted DynamoDB operations
    putItemInput := &dynamodb.PutItemInput{
        TableName: aws.String("my-table"),
        Item: map[string]types.AttributeValue{
            "PK":            &types.AttributeValueMemberS{Value: "123"},
            "SK":            &types.AttributeValueMemberS{Value: "456"},
            "SensitiveData": &types.AttributeValueMemberS{Value: "my secret data"},
        },
    }
    _, err = encryptedClient.PutItem(context.Background(), putItemInput)
    if err != nil {
        log.Fatalf("Failed to put encrypted item: %v", err)
    }

    // ... perform other operations ...
}
```

In this example, we create a regular `dynamodb.Client`, a key material store, and a cryptographic materials provider. Then, we create an `EncryptedClient` instance with custom attribute actions to specify which attributes should be encrypted. Finally, we use the `EncryptedClient` to perform operations like PutItem, and the library automatically handles the encryption and decryption of sensitive data.

For more detailed examples and usage instructions, please refer to the documentation and the examples directory in the repository.

## Contributing

Contributions to this library are welcome! If you find a bug, have a feature request, or want to contribute code improvements, please open an issue or submit a pull request on the GitHub repository.

## License

This library is licensed under the MIT License.
