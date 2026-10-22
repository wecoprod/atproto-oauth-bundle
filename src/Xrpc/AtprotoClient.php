<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\Xrpc;

use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpExceptionInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;
use Wecoprod\AtprotoOAuthBundle\Exception\AtprotoOAuthException;
use Wecoprod\AtprotoOAuthBundle\Exception\XrpcException;
use Wecoprod\AtprotoOAuthBundle\OAuth\DpopTransport;
use Wecoprod\AtprotoOAuthBundle\OAuth\SessionManager;

/**
 * Authenticated XRPC calls to the user's PDS, on behalf of a DID with a stored session.
 *
 *     $client->post($did, 'com.atproto.repo.createRecord', ['repo' => $did, 'collection' => 'app.bsky.feed.post', 'record' => [...]]);
 */
final class AtprotoClient
{
    public function __construct(
        private readonly SessionManager $sessions,
        private readonly DpopTransport $transport,
    ) {
    }

    /**
     * @param array<string, scalar|list<scalar>|null> $query list values are sent as repeated parameters (uris=a&uris=b)
     *
     * @return array<string, mixed>
     */
    public function get(string $did, string $nsid, array $query = []): array
    {
        return $this->decode($nsid, $this->request($did, 'GET', $nsid, ['query' => $query]));
    }

    /**
     * @param array<string, mixed> $body
     *
     * @return array<string, mixed>
     */
    public function post(string $did, string $nsid, array $body = []): array
    {
        return $this->decode($nsid, $this->request($did, 'POST', $nsid, ['json' => $body]));
    }

    /**
     * @param string $data the raw bytes of the blob
     *
     * @return array<string, mixed> the blob reference, to put in a record embed
     */
    public function uploadBlob(string $did, string $data, string $mimeType): array
    {
        $response = $this->decode('com.atproto.repo.uploadBlob', $this->request($did, 'POST', 'com.atproto.repo.uploadBlob', [
            'body' => $data,
            'headers' => ['Content-Type' => $mimeType],
        ]));

        if (!\is_array($response['blob'] ?? null)) {
            throw new AtprotoOAuthException('uploadBlob returned no blob.');
        }

        return $response['blob'];
    }

    /**
     * Low-level call. Refreshes the session before it expires, and once more if the PDS rejects the access token.
     *
     * @param array{query?: array<string, scalar|list<scalar>|null>, json?: array<string, mixed>, body?: string, headers?: array<string, string>, timeout?: float} $options
     */
    public function request(string $did, string $method, string $nsid, array $options = []): ResponseInterface
    {
        $session = $this->sessions->getSession($did);
        $httpOptions = $options;
        unset($httpOptions['query']);
        $url = rtrim($session->pdsUrl, '/').'/xrpc/'.$nsid.self::queryString($options['query'] ?? []);
        $httpOptions['timeout'] ??= 30;

        try {
            $response = $this->transport->request($method, $url, $session->dpopKey(), $httpOptions, $session->accessToken);
            if ($response->getStatusCode() === 401 && $this->isInvalidToken($response)) {
                $session = $this->sessions->getSession($did, $session->accessToken);
                $response = $this->transport->request($method, $url, $session->dpopKey(), $httpOptions, $session->accessToken);
            }
        } catch (HttpExceptionInterface $e) {
            throw new AtprotoOAuthException(\sprintf('%s failed: %s', $nsid, $e->getMessage()), 0, $e);
        }

        return $response;
    }

    /**
     * @param array<string, scalar|list<scalar>|null> $query
     */
    public static function queryString(array $query): string
    {
        $pairs = [];
        foreach ($query as $name => $value) {
            foreach (\is_array($value) ? $value : [$value] as $item) {
                if ($item === null) {
                    continue;
                }
                $item = \is_bool($item) ? ($item ? 'true' : 'false') : (string) $item;
                $pairs[] = rawurlencode((string) $name).'='.rawurlencode($item);
            }
        }

        return $pairs === [] ? '' : '?'.implode('&', $pairs);
    }

    /**
     * @return array<string, mixed>
     */
    private function decode(string $nsid, ResponseInterface $response): array
    {
        try {
            $status = $response->getStatusCode();
            $content = $response->getContent(false);
        } catch (HttpExceptionInterface $e) {
            throw new AtprotoOAuthException(\sprintf('%s failed: %s', $nsid, $e->getMessage()), 0, $e);
        }

        $data = $content === '' ? [] : json_decode($content, true);
        if ($status >= 400) {
            throw new XrpcException(
                $nsid,
                $status,
                \is_array($data) && \is_string($data['error'] ?? null) ? $data['error'] : null,
                \is_array($data) && \is_string($data['message'] ?? null) ? $data['message'] : null,
            );
        }
        if (!\is_array($data)) {
            throw new AtprotoOAuthException(\sprintf('%s returned invalid JSON.', $nsid));
        }

        return $data;
    }

    private function isInvalidToken(ResponseInterface $response): bool
    {
        foreach ($response->getHeaders(false)['www-authenticate'] ?? [] as $header) {
            if (str_contains($header, 'invalid_token')) {
                return true;
            }
        }

        try {
            $error = $response->toArray(false)['error'] ?? null;
        } catch (\Throwable) {
            return false;
        }

        return \in_array($error, ['invalid_token', 'InvalidToken', 'ExpiredToken'], true);
    }
}
