<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use Sicet7\GCM\DecodedCipher;
use Sicet7\GCM\EncryptionVersion;
use Sicet7\GCM\Encryptor;
use Sicet7\GCM\Exceptions\DecodingException;
use Sicet7\GCM\Exceptions\DecryptionException;
use Sicet7\GCM\Exceptions\EncryptionException;
use PHPUnit\Framework\TestCase as BaseTestCase;

#[CoversClass(Encryptor::class), CoversClass(DecodedCipher::class)]
final class EncryptorTest extends BaseTestCase
{
    public const TEST_KEY = '4743fa49fe0a4913aecacab1d200ab87';
    public const TEST_PLAINTEXT = 'The quick brown fox jumps over the lazy dog';
    public const TEST_V1_CIPHERTEXT = 'QTVxc3poRlBmTkw4QkFIbi5CckNWMjRQWXJGNnlnMkMyZk9WY0RfeUlMMU5SME5nQ0lLUjBISGRiTTRpc2xTQ3phMXZ1RWxhYW9nLkZwY3I4dGlVN0tfTzZyYUwtd0w5YVE';
    public const TEST_V2_CIPHERTEXT_OLD = '2$90VVp8oCtWC6H5X7cXf6Jp7vmupNqlfBuf1lLsSrdYgXeNhigdMPstbaPpWU7QOacuvXMxIe7EszPJO2EAflSB955yeda84';
    public const TEST_V2_CIPHERTEXT = '90VVp8oCtWC6H5X7cXf6Jp7vmupNqlfBuf1lLsSrdYgXeNhigdMPstbaPpWU7QOacuvXMxIe7EszPJO2EAflSB955yeda84';

    /**
     * @return void
     * @throws DecodingException
     */
    #[Test]
    public function testDecode(): void
    {
        $decoded = Encryptor::decode(self::TEST_V1_CIPHERTEXT);
        $this->assertSame(EncryptionVersion::V1, $decoded->version, 'Decoding failed to identify the correct version.');
        $this->assertSame('7852a52173e5adb799fa5566d8111f8e990f3864049a4118863cda2c2aff2787', hash('sha256', $decoded->cipherText));
        $this->assertSame('6bbd50cc5ad8dc7f2b0f9f461a296d045e12394f6c9bfaf9e41cf97491e090e5', hash('sha256', $decoded->nonce));
        $this->assertSame('e5f9c433ab446df6192da60b42eeeadef6684b5463fc0a12f4ac25e709b62e25', hash('sha256', $decoded->tag));

        $decoded = Encryptor::decode(self::TEST_V2_CIPHERTEXT);
        $this->assertSame(EncryptionVersion::V2, $decoded->version, 'Decoding failed to identify the correct version.');
        $this->assertSame('b4a671c3dc3089da93f389106df1242d2a1c6c9c8098e3618e751b354fc291b7', hash('sha256', $decoded->cipherText));
        $this->assertSame('c621f87f3f80d38134984d3f07330bfcd4add90394ef92fd3fd9ac1f0a569008', hash('sha256', $decoded->nonce));
        $this->assertSame('1858ff08263167f26689465cacc65a7fc97529b83c65fc429a39f9cc29d4a7b8', hash('sha256', $decoded->tag));
    }

    /**
     * @return void
     * @throws DecodingException
     * @throws DecryptionException
     */
    #[Test, Depends('testDecode')]
    public function testDecrypt(): void
    {
        $decrypted = Encryptor::decrypt(self::TEST_V1_CIPHERTEXT, self::TEST_KEY);
        $this->assertSame(self::TEST_PLAINTEXT, $decrypted, 'Failed to decrypt V1 test message');

        $decrypted = Encryptor::decrypt(self::TEST_V2_CIPHERTEXT, self::TEST_KEY);
        $this->assertSame(self::TEST_PLAINTEXT, $decrypted, 'Failed to decrypt V2 test message');

        $decrypted = Encryptor::decrypt(self::TEST_V2_CIPHERTEXT_OLD, self::TEST_KEY);
        $this->assertSame(self::TEST_PLAINTEXT, $decrypted, 'Failed to decrypt V2 test message');
    }

    /**
     * @return void
     * @throws EncryptionException|DecryptionException|DecodingException
     */
    #[Test, Depends('testDecrypt')]
    public function testEncrypt(): void
    {
        $encrypted = Encryptor::encrypt(
            self::TEST_PLAINTEXT,
            self::TEST_KEY,
            EncryptionVersion::V1
        );
        $this->assertNotSame(self::TEST_PLAINTEXT, $encrypted, 'Encrypt function cannot return the plaintext');
        $decoded = Encryptor::decode($encrypted);
        $this->assertSame(EncryptionVersion::V1, $decoded->version);
        $this->assertSame(self::TEST_PLAINTEXT, Encryptor::decrypt($encrypted, self::TEST_KEY));

        $encrypted = Encryptor::encrypt(
            self::TEST_PLAINTEXT,
            self::TEST_KEY,
            EncryptionVersion::V2
        );
        $this->assertNotSame(self::TEST_PLAINTEXT, $encrypted, 'Encrypt function cannot return the plaintext');
        $decoded = Encryptor::decode($encrypted);
        $this->assertSame(EncryptionVersion::V2, $decoded->version);
        $this->assertSame(self::TEST_PLAINTEXT, Encryptor::decrypt($encrypted, self::TEST_KEY));
    }
}
