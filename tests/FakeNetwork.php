<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\Tests;

use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Wecoprod\AtprotoOAuthBundle\Crypto\Jwt;
use Wecoprod\AtprotoOAuthBundle\Identity\DnsResolverInterface;

/**
 * An in-memory atproto world: one PDS (pds.example.com) protected by one authorization server (auth.example.com),
 * one account alice.example.com → did:plc:alice. Records every request so tests can inspect the DPoP proofs.
 */
final class FakeNetwork implements DnsResolverInterface
{
    public const DID = 'did:plc:alice';
    public const HANDLE = 'alice.example.com';
    public const PDS = 'https://pds.example.com';
    public const ISSUER = 'https://auth.example.com';

    /** @var list<array{method: string, url: string, headers: array<string, string>, body: string}> */
    public array $requests = [];

    /** @var array<string, string> */
    public array $txtRecords = ['_atproto.alice.example.com' => 'did='.self::DID];

    public string $nonce = 'nonce-1';
    public int $tokenCounter = 0;
    public bool $refreshRevoked = false;

    /** @var array<string, mixed> */
    public array $didDocument;

    /** @var array<string, mixed> */
    public array $serverMetadata;

    /** @var array<string, \Closure(array{method: string, url: string, headers: array<string, string>, body: string}): MockResponse> */
    public array $xrpcHandlers = [];

    public function __construct()
    {
        $this->didDocument = [
            'id' => self::DID,
            'alsoKnownAs' => ['at://'.self::HANDLE],
            'service' => [[
                'id' => '#atproto_pds',
                'type' => 'AtprotoPersonalDataServer',
                'serviceEndpoint' => self::PDS,
            ]],
        ];
        $this->serverMetadata = [
            'issuer' => self::ISSUER,
            'authorization_endpoint' => self::ISSUER.'/oauth/authorize',
            'token_endpoint' => self::ISSUER.'/oauth/token',
            'pushed_authorization_request_endpoint' => self::ISSUER.'/oauth/par',
            'revocation_endpoint' => self::ISSUER.'/oauth/revoke',
            'authorization_response_iss_parameter_supported' => true,
            'require_pushed_authorization_requests' => true,
            'client_id_metadata_document_supported' => true,
            'scopes_supported' => ['atproto', 'transition:generic'],
            'dpop_signing_alg_values_supported' => ['ES256'],
            'token_endpoint_auth_methods_supported' => ['none', 'private_key_jwt'],
            'code_challenge_methods_supported' => ['S256'],
        ];
    }

    public function txt(string $host): array
    {
        return isset($this->txtRecords[$host]) ? [$this->txtRecords[$host]] : [];
    }

    public function httpClient(): MockHttpClient
    {
        return new MockHttpClient(function (string $method, string $url, array $options): MockResponse {
            $headers = [];
            foreach ($options['headers'] ?? [] as $header) {
                [$name, $value] = explode(': ', $header, 2);
                $headers[strtolower($name)] = $value;
            }
            $request = ['method' => $method, 'url' => $url, 'headers' => $headers, 'body' => (string) ($options['body'] ?? '')];
            $this->requests[] = $request;

            return $this->handle($request);
        });
    }

    /**
     * @return list<array{method: string, url: string, headers: array<string, string>, body: string}>
     */
    public function requestsTo(string $urlPrefix): array
    {
        return array_values(array_filter($this->requests, static fn (array $r) => str_starts_with($r['url'], $urlPrefix)));
    }

    /**
     * @param array{method: string, url: string, headers: array<string, string>, body: string} $request
     */
    private function handle(array $request): MockResponse
    {
        $url = $request['url'];
        $path = (string) parse_url($url, PHP_URL_PATH);

        return match (true) {
            $url === 'https://plc.directory/'.self::DID => self::json($this->didDocument),
            $url === self::PDS.'/.well-known/oauth-protected-resource' => self::json(['resource' => self::PDS, 'authorization_servers' => [self::ISSUER]]),
            $url === self::ISSUER.'/.well-known/oauth-authorization-server' => self::json($this->serverMetadata),
            $url === self::ISSUER.'/.well-known/oauth-protected-resource' => self::json(['error' => 'not found'], 404),
            $url === self::ISSUER.'/oauth/par' => $this->withNonce($request, fn () => self::json(['request_uri' => 'urn:ietf:params:oauth:request_uri:req-1', 'expires_in' => 60], 201)),
            $url === self::ISSUER.'/oauth/token' => $this->withNonce($request, fn () => $this->token($request)),
            $url === self::ISSUER.'/oauth/revoke' => $this->withNonce($request, fn () => new MockResponse('', ['http_code' => 200])),
            str_starts_with($url, self::PDS.'/xrpc/') => $this->xrpc($request, substr($path, 6)),
            default => self::json(['error' => 'not found: '.$url], 404),
        };
    }

    /**
     * @param array{method: string, url: string, headers: array<string, string>, body: string} $request
     * @param \Closure(): MockResponse $handler
     */
    private function withNonce(array $request, \Closure $handler): MockResponse
    {
        $proof = $request['headers']['dpop'] ?? null;
        if ($proof === null) {
            return self::json(['error' => 'invalid_dpop_proof'], 400);
        }
        if ((Jwt::decode($proof)[1]['nonce'] ?? null) !== $this->nonce) {
            return self::json(['error' => 'use_dpop_nonce'], 400, ['DPoP-Nonce' => $this->nonce]);
        }

        return $handler();
    }

    /**
     * @param array{method: string, url: string, headers: array<string, string>, body: string} $request
     */
    private function token(array $request): MockResponse
    {
        parse_str($request['body'], $params);
        if ($params['grant_type'] === 'refresh_token' && $this->refreshRevoked) {
            return self::json(['error' => 'invalid_grant', 'error_description' => 'refresh token revoked'], 400);
        }

        ++$this->tokenCounter;

        return self::json([
            'access_token' => 'access-'.$this->tokenCounter,
            'refresh_token' => 'refresh-'.$this->tokenCounter,
            'token_type' => 'DPoP',
            'expires_in' => 900,
            'scope' => 'atproto transition:generic',
            'sub' => self::DID,
        ]);
    }

    /**
     * @param array{method: string, url: string, headers: array<string, string>, body: string} $request
     */
    private function xrpc(array $request, string $nsid): MockResponse
    {
        $proof = $request['headers']['dpop'] ?? null;
        if ($proof === null || !str_starts_with($request['headers']['authorization'] ?? '', 'DPoP ')) {
            return self::json(['error' => 'AuthMissing'], 401);
        }
        if ((Jwt::decode($proof)[1]['nonce'] ?? null) !== $this->nonce) {
            return self::json(['error' => 'use_dpop_nonce'], 401, ['DPoP-Nonce' => $this->nonce, 'WWW-Authenticate' => 'DPoP error="use_dpop_nonce"']);
        }
        if ($request['headers']['authorization'] !== 'DPoP access-'.$this->tokenCounter) {
            return self::json(['error' => 'invalid_token'], 401, ['WWW-Authenticate' => 'DPoP error="invalid_token"']);
        }

        return isset($this->xrpcHandlers[$nsid]) ? ($this->xrpcHandlers[$nsid])($request) : self::json(['error' => 'MethodNotImplemented'], 501);
    }

    /**
     * @param array<string, mixed>  $data
     * @param array<string, string> $headers
     */
    public static function json(array $data, int $status = 200, array $headers = []): MockResponse
    {
        return new MockResponse(json_encode($data, JSON_THROW_ON_ERROR), [
            'http_code' => $status,
            'response_headers' => ['Content-Type' => 'application/json'] + $headers,
        ]);
    }
}
