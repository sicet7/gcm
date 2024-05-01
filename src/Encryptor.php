<?php

namespace Sicet7\GCM;

use phpseclib3\Crypt\AES;
use phpseclib3\Crypt\Random;
use Sicet7\GCM\Exceptions\DecodingException;
use Sicet7\GCM\Exceptions\DecryptionException;
use Sicet7\GCM\Exceptions\EncryptionException;

final class Encryptor
{
    /**
     * @param string $plainText
     * @param string $key
     * @param EncryptionVersion $version
     * @return string
     * @throws EncryptionException
     */
    public static function encrypt(
        string $plainText,
        string $key,
        EncryptionVersion $version = EncryptionVersion::V2
    ): string {
        try {
            $nonce = Random::string(12);
            $encoder = new AES('gcm');
            $encoder->setTag(Random::string(16));
            $encoder->setNonce($nonce);
            $encoder->setKey($key);
            $encryptedData = $encoder->encrypt($plainText);

            if ($version === EncryptionVersion::V2) {
                $completeString = $nonce . $encryptedData . $encoder->getTag();
            } else {
                $completeString = self::b64Encode($nonce) . '.' .
                    self::b64Encode($encryptedData) . '.' .
                    self::b64Encode($encoder->getTag());
            }

            return self::b64Encode($completeString);
        } catch (\Throwable $throwable) {
            throw new EncryptionException('Failed to encrypt plainText.', $throwable->getCode(), $throwable);
        }
    }

    /**
     * @param string $cipherText
     * @param string $key
     * @return string
     * @throws DecodingException|DecryptionException
     */
    public static function decrypt(
        string $cipherText,
        string $key
    ): string {
        $decoded = self::decode($cipherText);
        try {
            $decoder = new AES('gcm');
            $decoder->setNonce($decoded->nonce);
            $decoder->setTag($decoded->tag);
            $decoder->setKey($key);
            return $decoder->decrypt($decoded->cipherText);
        } catch (\Throwable $throwable) {
            throw new DecryptionException('Failed to decrypt ciphertext', $throwable->getCode(), $throwable);
        }
    }

    /**
     * @param string $cipherText
     * @return DecodedCipher
     * @throws DecodingException
     */
    public static function decode(string $cipherText): DecodedCipher
    {
        $parts = \explode('$', $cipherText);
        $cipherText = self::b64Decode($parts[\array_key_last($parts)]);
        $version = self::readVersion($cipherText);
        if ($version === EncryptionVersion::V2) {
            return new DecodedCipher(
                $version,
                \substr($cipherText, 0, 12),
                \substr($cipherText, 12, -16),
                \substr($cipherText, -16)
            );
        } else {
            if (
                \substr_count($cipherText, '.') != 2 ||
                \count(($parts = \explode('.', $cipherText))) != 3
            ) {
                throw new DecodingException('Failed to decode cipherText part string validation.');
            }
            foreach ($parts as $k => $d) {
                $parts[$k] = self::b64Decode($d);
            }
            return new DecodedCipher(
                $version,
                $parts[0],
                $parts[1],
                $parts[2],
            );
        }
    }

    /**
     * @param string $input
     * @return string
     * @throws DecodingException
     */
    private static function b64Decode(string $input): string
    {
        $remainder = \strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= \str_repeat('=', $padlen);
        }

        $data = \base64_decode(\strtr($input, '-_', '+/'));
        if ($data === false) {
            throw new DecodingException('Failed to decode input as a base64 string');
        }

        return $data;
    }

    /**
     * @param string $input
     * @return string
     */
    private static function b64Encode(string $input): string
    {
        return \str_replace('=', '', \strtr(\base64_encode($input), '+/', '-_'));
    }

    /**
     * @param string $cipherText
     * @return EncryptionVersion
     */
    private static function readVersion(string $cipherText): EncryptionVersion
    {
        if (\preg_match('/^([\w-]+)\\.([\w-]+)\\.([\w-]+)$/', $cipherText) === 1) {
            return EncryptionVersion::V1;
        }
        return EncryptionVersion::V2;
    }
}