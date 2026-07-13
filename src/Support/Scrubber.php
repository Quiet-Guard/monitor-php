<?php

namespace LaBoiteACode\Monitor\Support;

/**
 * Masks sensitive values by key, recursively. Framework-agnostic.
 *
 * Matching is by lower-cased substring, so a configured "password" also masks
 * "user_password" and "PASSWORD_CONFIRMATION": derived key names must never
 * leak just because the exact spelling was not listed.
 */
class Scrubber
{
    public const MASK = '[scrubbed]';

    /** @var array<int, string> lower-cased needles to mask */
    private array $keys;

    /**
     * @param  array<int, string>  $keys
     */
    public function __construct(array $keys = [])
    {
        $this->keys = array_map('strtolower', $keys);
    }

    /**
     * @param  array<mixed>  $data
     * @return array<mixed>
     */
    public function scrub(array $data): array
    {
        foreach ($data as $key => $value) {
            if (is_string($key) && $this->matches(strtolower($key))) {
                $data[$key] = static::MASK;

                continue;
            }

            if (is_array($value)) {
                $data[$key] = $this->scrub($value);
            }
        }

        return $data;
    }

    private function matches(string $key): bool
    {
        foreach ($this->keys as $needle) {
            if ($needle !== '' && str_contains($key, $needle)) {
                return true;
            }
        }

        return false;
    }
}
