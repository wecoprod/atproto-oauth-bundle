<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\OAuth;

use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;
use Wecoprod\AtprotoOAuthBundle\Crypto\Base64Url;
use Wecoprod\AtprotoOAuthBundle\Crypto\EcKey;
use Wecoprod\AtprotoOAuthBundle\Crypto\Jwt;

/**
 * Sends requests with a DPoP proof, remembers the server nonce per origin and retries once on use_dpop_nonce.
 */
final class DpopTransport
{
    /** @var array<string, string> */
    private array $nonces = [];

    public function __construct(private readonly HttpClientInterface $httpClient)
    {
    }

    /**
     * @param array<string, mixed> $options HttpClient options; the body must be replayable (string or array)
     * @param string|null          $accessToken set for resource (PDS) requests: adds the ath claim and the Authorization header
     * @param (\Closure(array<string, mixed>): array<string, mixed>)|null $prepare called before each attempt (e.g. to sign a fresh client assertion)
     */
    public function request(string $method, string $url, EcKey $dpopKey, array $options = [], ?string $accessToken = null, ?\Closure $prepare = null): ResponseInterface
    {
        $origin = ServerMetadataResolver::origin($url);
        $prepare ??= static fn (array $options): array => $options;
        $response = $this->send($method, $url, $dpopKey, $prepare($options), $accessToken, $origin);

        $previousNonce = $this->nonces[$origin] ?? null;
        $this->rememberNonce($response, $origin);

        if ($this->isNonceError($response, $accessToken !== null) && ($this->nonces[$origin] ?? null) !== $previousNonce) {
            $response = $this->send($method, $url, $dpopKey, $prepare($options), $accessToken, $origin);
            $this->rememberNonce($response, $origin);
        }

        return $response;
    }

    public function createProof(EcKey $key, string $method, string $url, ?string $nonce = null, ?string $accessToken = null): string
    {
        $parts = parse_url($url);
        $htu = ($parts['scheme'] ?? 'https').'://'.($parts['host'] ?? '').(isset($parts['port']) ? ':'.$parts['port'] : '').($parts['path'] ?? '');

        $payload = [
            'jti' => Jwt::randomId(),
            'htm' => strtoupper($method),
            'htu' => $htu,
            'iat' => time(),
        ];
        if ($nonce !== null) {
            $payload['nonce'] = $nonce;
        }
        if ($accessToken !== null) {
            $payload['ath'] = Base64Url::encode(hash('sha256', $accessToken, true));
        }

        return Jwt::sign(['typ' => 'dpop+jwt', 'jwk' => $key->publicJwk()], $payload, $key);
    }

    /**
     * @param array<string, mixed> $options
     */
    private function send(string $method, string $url, EcKey $dpopKey, array $options, ?string $accessToken, string $origin): ResponseInterface
    {
        $headers = (array) ($options['headers'] ?? []);
        $headers['DPoP'] = $this->createProof($dpopKey, $method, $url, $this->nonces[$origin] ?? null, $accessToken);
        if ($accessToken !== null) {
            $headers['Authorization'] = 'DPoP '.$accessToken;
        }
        $options['headers'] = $headers;

        return $this->httpClient->request($method, $url, $options);
    }

    private function rememberNonce(ResponseInterface $response, string $origin): void
    {
        $nonce = $response->getHeaders(false)['dpop-nonce'][0] ?? null;
        if (\is_string($nonce) && $nonce !== '') {
            $this->nonces[$origin] = $nonce;
        }
    }

    private function isNonceError(ResponseInterface $response, bool $resourceRequest): bool
    {
        $status = $response->getStatusCode();

        if ($resourceRequest) {
            // Resource servers answer 401 with WWW-Authenticate: DPoP error="use_dpop_nonce"
            if ($status !== 401) {
                return false;
            }
            foreach ($response->getHeaders(false)['www-authenticate'] ?? [] as $header) {
                if (str_contains($header, 'use_dpop_nonce')) {
                    return true;
                }
            }
        }

        // Authorization servers answer 400 {"error":"use_dpop_nonce"} (some PDS do the same on 401)
        if ($status !== 400 && $status !== 401) {
            return false;
        }

        try {
            return ($response->toArray(false)['error'] ?? null) === 'use_dpop_nonce';
        } catch (\Throwable) {
            return false;
        }
    }
}
