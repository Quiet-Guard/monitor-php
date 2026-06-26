<?php

namespace LaBoiteACode\Monitor;

/**
 * Immutable client configuration shared by every platform adapter.
 */
class Config
{
    /**
     * @param  array<int, string>  $environments  report only from these (empty = all)
     */
    public function __construct(
        public readonly ?string $url,
        public readonly ?string $key,
        public readonly int $timeout = 3,
        public readonly ?string $release = null,
        public readonly array $environments = [],
        public readonly int $traceLimit = 50,
    ) {}

    public function isConfigured(): bool
    {
        return ! empty($this->url) && ! empty($this->key);
    }

    public function reportsFrom(?string $environment): bool
    {
        return $this->environments === [] || in_array($environment, $this->environments, true);
    }
}
