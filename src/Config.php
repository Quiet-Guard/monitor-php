<?php

namespace QuietGuard\Monitor;

use QuietGuard\Monitor\Support\ValueRedactor;

/**
 * Immutable client configuration shared by every platform adapter.
 */
class Config
{
    /**
     * L'adresse du service, appliquée quand rien n'est configuré.
     *
     * Elle vit ICI, dans le code qui lit la valeur, et non seulement dans le
     * gabarit de configuration publiable. Un gabarit est une COPIE : la page
     * d'installation dit à chaque lecteur de le publier, sa copie est figée à
     * la version installée, et elle gagne sur les défauts du paquet. Un défaut
     * écrit là seulement n'atteint donc personne, exactement le cas mesuré sur
     * quietmetrics.dev le 2026-09-08, où la config publiée en 0.2.0 rendait
     * `url` nulle malgré le défaut ajouté en 0.2.1.
     */
    public const HOSTED_URL = 'https://quietguard.dev';

    /**
     * L'adresse de base, déjà normalisée : sans espace, sans barre finale et
     * sans préfixe d'API, puisque chaque appel porte le sien.
     */
    public readonly string $url;

    /**
     * @param  array<int, string>  $environments  report only from these (empty = all)
     * @param  array<int, string>  $redact  value patterns to mask before sending
     * @param  array<string, string>  $customRedactions  label => PCRE pattern
     */
    public function __construct(
        ?string $url,
        public readonly ?string $key,
        public readonly int $timeout = 3,
        public readonly ?string $release = null,
        public readonly array $environments = [],
        public readonly int $traceLimit = 0,
        // On by default. Masking personal data at the source is what article
        // 25.2 calls protection by default, and a setting nobody turns on
        // protects nobody. Pass an empty array to send payloads untouched.
        public readonly array $redact = ValueRedactor::PATTERNS,
        public readonly array $customRedactions = [],
    ) {
        $this->url = self::normaliseUrl($url);
    }

    /**
     * Une adresse de base utilisable, quoi qu'on nous ait donné.
     *
     * Retire le préfixe d'API que l'appelant a pu fournir : chaque chemin
     * porte déjà son `/api/v1`, et « l'URL de base de votre serveur » se lit
     * aussi bien « l'adresse de l'API ». Les deux lectures doivent marcher,
     * parce que la mauvaise répond 404 partout et ressemble trait pour trait
     * à une clé invalide. Une règle qu'il faut respecter est plus faible
     * qu'une forme qu'on ne peut pas rater.
     */
    public static function normaliseUrl(?string $url): string
    {
        $url = rtrim(trim((string) $url), '/');

        if ($url === '') {
            return self::HOSTED_URL;
        }

        return (string) preg_replace('#/api(/v\d+)?$#i', '', $url);
    }

    public function redactor(): ValueRedactor
    {
        return new ValueRedactor($this->redact, $this->customRedactions);
    }

    /**
     * La clé est la seule chose que nous ne pouvons pas deviner.
     *
     * L'adresse en est une : elle vaut le service hébergé par défaut. Exiger
     * les deux faisait échouer une installation à laquelle il ne manquait
     * rien d'irremplaçable, sous un message qui accusait la clé.
     */
    public function isConfigured(): bool
    {
        return ! empty($this->key);
    }

    public function reportsFrom(?string $environment): bool
    {
        return $this->environments === [] || in_array($environment, $this->environments, true);
    }
}
