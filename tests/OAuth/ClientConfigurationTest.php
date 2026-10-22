<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\Tests\OAuth;

use PHPUnit\Framework\TestCase;
use Wecoprod\AtprotoOAuthBundle\Crypto\EcKey;
use Wecoprod\AtprotoOAuthBundle\OAuth\ClientConfiguration;

final class ClientConfigurationTest extends TestCase
{
    private const CLIENT_ID = 'https://app.example.com/oauth/atproto/client-metadata.json';

    public function testClientUriMustShareTheClientIdOrigin(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('same origin');

        new ClientConfiguration(self::CLIENT_ID, ['https://app.example.com/callback'], EcKey::generate(), clientUri: 'https://www.example.com');
    }

    public function testClientUriOnTheSameOriginIsPublished(): void
    {
        $config = new ClientConfiguration(self::CLIENT_ID, ['https://app.example.com/callback'], EcKey::generate(), clientUri: 'https://APP.example.com/');

        $this->assertSame('https://APP.example.com/', $config->metadata()['client_uri']);
        $this->assertSame('https://app.example.com/oauth/atproto/jwks.json', $config->jwksUri);
    }
}
