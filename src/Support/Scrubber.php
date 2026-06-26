<?php

namespace LaBoiteACode\Monitor\Support;

/**
 * Masks sensitive values by key, recursively. Framework-agnostic.
 */
class Scrubber
{
    public const MASK = '[FILTERED]';

    /** @var array<int, string> lower-cased keys to mask */
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
            if (is_string($key) && in_array(strtolower($key), $this->keys, true)) {
                $data[$key] = self::MASK;

                continue;
            }

            if (is_array($value)) {
                $data[$key] = $this->scrub($value);
            }
        }

        return $data;
    }
}
