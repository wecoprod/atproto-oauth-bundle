<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;
use Wecoprod\AtprotoOAuthBundle\OAuth\ClientConfiguration;

/**
 * Public documents fetched by authorization servers: the client metadata (its URL is the client_id) and the JWKS.
 */
final class ClientMetadataController
{
    public function __construct(private readonly ClientConfiguration $config)
    {
    }

    public function metadata(): JsonResponse
    {
        return $this->publicJson($this->config->metadata());
    }

    public function jwks(): JsonResponse
    {
        return $this->publicJson($this->config->jwks());
    }

    /**
     * @param array<string, mixed> $data
     */
    private function publicJson(array $data): JsonResponse
    {
        $response = new JsonResponse($data);
        $response->setEncodingOptions(JSON_UNESCAPED_SLASHES);
        $response->setPublic();
        $response->setMaxAge(300);
        $response->headers->set('Access-Control-Allow-Origin', '*');

        return $response;
    }
}
