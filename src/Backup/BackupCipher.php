<?php

namespace QuietGuard\Monitor\Backup;

use RuntimeException;

/**
 * Streaming hybrid encryption for backup blobs (framework-agnostic).
 *
 * A random symmetric key encrypts the archive with libsodium's secretstream
 * (chunked AEAD), and that key is sealed to the team's X25519 public key. The
 * server only ever stores the opaque result. Restoring requires the team's
 * private key, unwrapped locally from the passphrase, mirroring the server's
 * Argon2id/secretbox wrapping so the operator is never in the loop.
 *
 * Blob layout: [uint32 sealedKeyLen][sealedKey][24-byte header]([uint32 len][chunk])*
 */
class BackupCipher
{
    private const CHUNK = 1 << 16; // 64 KiB plaintext chunks

    public function encryptFile(string $inPath, string $outPath, string $publicKeyBase64): void
    {
        $public = base64_decode($publicKeyBase64, true);

        if ($public === false) {
            throw new RuntimeException('Invalid public key.');
        }

        $symKey = sodium_crypto_secretstream_xchacha20poly1305_keygen();
        [$state, $header] = sodium_crypto_secretstream_xchacha20poly1305_init_push($symKey);
        $sealedKey = sodium_crypto_box_seal($symKey, $public);
        sodium_memzero($symKey);

        $in = $this->open($inPath, 'rb');
        $out = $this->open($outPath, 'wb');

        fwrite($out, pack('N', strlen($sealedKey)));
        fwrite($out, $sealedKey);
        fwrite($out, $header);

        do {
            $chunk = fread($in, self::CHUNK);
            $eof = feof($in);
            $tag = $eof
                ? SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL
                : SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
            $cipher = sodium_crypto_secretstream_xchacha20poly1305_push($state, $chunk, '', $tag);
            fwrite($out, pack('N', strlen($cipher)));
            fwrite($out, $cipher);
        } while (! $eof);

        fclose($in);
        fclose($out);
    }

    public function decryptFile(string $inPath, string $outPath, string $publicKeyBase64, string $privateKeyRaw): void
    {
        $public = base64_decode($publicKeyBase64, true);

        if ($public === false) {
            throw new RuntimeException('Invalid public key.');
        }

        $in = $this->open($inPath, 'rb');

        $sealedKey = $this->readChunk($in, $this->readLength($in));
        $keypair = sodium_crypto_box_keypair_from_secretkey_and_publickey($privateKeyRaw, $public);
        $symKey = sodium_crypto_box_seal_open($sealedKey, $keypair);
        sodium_memzero($keypair);

        if ($symKey === false) {
            fclose($in);
            throw new RuntimeException('Unable to recover the backup key (wrong key pair).');
        }

        $header = $this->readChunk($in, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);
        $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $symKey);
        sodium_memzero($symKey);

        $out = $this->open($outPath, 'wb');
        $final = false;

        try {
            while (! feof($in)) {
                $lenBytes = fread($in, 4);

                if ($lenBytes === false || strlen($lenBytes) < 4) {
                    break;
                }

                $cipher = $this->readChunk($in, unpack('N', $lenBytes)[1]);
                $result = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $cipher);

                if ($result === false) {
                    throw new RuntimeException('Backup is corrupted or has been tampered with.');
                }

                [$message, $tag] = $result;
                fwrite($out, $message);

                if ($tag === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) {
                    $final = true;
                    break;
                }
            }

            // encryptFile() always closes the stream with a FINAL-tagged chunk, so
            // reaching EOF without it means the blob was cut at a frame boundary.
            if (! $final) {
                throw new RuntimeException('Truncated backup blob.');
            }
        } catch (RuntimeException $e) {
            fclose($in);
            fclose($out);
            @unlink($outPath);

            throw $e;
        }

        fclose($in);
        fclose($out);
    }

    /**
     * Unwrap the server-wrapped private key with the team passphrase. Mirrors the
     * server's TeamCipher (Argon2id MODERATE → secretbox, nonce|ciphertext frame).
     */
    public function unwrapPrivateKey(string $wrappedBase64, string $saltBase64, string $passphrase): string
    {
        $wrapped = base64_decode($wrappedBase64, true);
        $salt = base64_decode($saltBase64, true);

        if ($wrapped === false || $salt === false) {
            throw new RuntimeException('Corrupted key material.');
        }

        $kek = sodium_crypto_pwhash(
            SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
            $passphrase,
            $salt,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13,
        );

        $nonce = substr($wrapped, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $cipher = substr($wrapped, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $secret = sodium_crypto_secretbox_open($cipher, $nonce, $kek);
        sodium_memzero($kek);

        if ($secret === false) {
            throw new RuntimeException('Wrong passphrase.');
        }

        return $secret;
    }

    /**
     * @return resource
     */
    private function open(string $path, string $mode)
    {
        $handle = @fopen($path, $mode);

        if ($handle === false) {
            throw new RuntimeException("Unable to open {$path}.");
        }

        return $handle;
    }

    /**
     * @param  resource  $handle
     */
    private function readLength($handle): int
    {
        $bytes = fread($handle, 4);

        if ($bytes === false || strlen($bytes) < 4) {
            throw new RuntimeException('Truncated backup blob.');
        }

        return unpack('N', $bytes)[1];
    }

    /**
     * @param  resource  $handle
     */
    private function readChunk($handle, int $length): string
    {
        $buffer = '';

        while (strlen($buffer) < $length) {
            $part = fread($handle, $length - strlen($buffer));

            if ($part === false || $part === '') {
                throw new RuntimeException('Truncated backup blob.');
            }

            $buffer .= $part;
        }

        return $buffer;
    }
}
