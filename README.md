# Sicet7 - GCM

### Usage

```php
<?php

use Sicet7\GCM\Encryptor;
use Sicet7\GCM\EncryptionVersion;

require_once __DIR__ . '/vendor/autoload.php';

$key = '<keys-should-32-characters-long>';
$data = 'The quick brown fox jumps over the lazy dog';

// Encrypt Data.
$encryptedString = Encryptor::encrypt(
    plainText: $data,
    key: $key,
    version: EncryptionVersion::V2 // It's recommended to use version 2 for all new data, V1 is only here for backwards compatibility
);

// Decrypt Data.
$decryptedData = Encryptor::decrypt(
    cipherText: $encryptedString,
    key: $key
);

//Should output: "The quick brown fox jumps over the lazy dog"
echo $decryptedData;
```