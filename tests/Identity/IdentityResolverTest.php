<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\Tests\Identity;

use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Wecoprod\AtprotoOAuthBundle\Exception\IdentityResolutionException;
use Wecoprod\AtprotoOAuthBundle\Identity\IdentityResolver;
use Wecoprod\AtprotoOAuthBundle\Identity\Syntax;
use Wecoprod\AtprotoOAuthBundle\Tests\FakeNetwork;

final class IdentityResolverTest extends TestCase
{
    public function testResolvesAHandleThroughDns(): void
    {
        $network = new FakeNetwork();
        $identity = (new IdentityResolver($network->httpClient(), $network))->resolve('@Alice.Example.com');

        self::assertSame(FakeNetwork::DID, $identity->did);
        self::assertSame(FakeNetwork::HANDLE, $identity->handle);
        self::assertSame(FakeNetwork::PDS, $identity->pdsUrl);
    }

    public function testResolvesAHandleThroughHttpsWhenDnsHasNothing(): void
    {
        $network = new FakeNetwork();
        $network->txtRecords = [];
        $inner = $network->httpClient();
        $client = new MockHttpClient(static function (string $method, string $url, array $options) use ($inner) {
            if ($url === 'https://alice.example.com/.well-known/atproto-did') {
                return new MockResponse(FakeNetwork::DID."\n");
            }

            return $inner->request($method, $url, $options);
        });

        self::assertSame(FakeNetwork::DID, (new IdentityResolver($client, $network))->resolve(FakeNetwork::HANDLE)->did);
    }

    public function testRejectsAHandleTheDidDocumentDoesNotClaim(): void
    {
        $network = new FakeNetwork();
        $network->didDocument['alsoKnownAs'] = ['at://someone-else.example.com'];

        $this->expectException(IdentityResolutionException::class);
        (new IdentityResolver($network->httpClient(), $network))->resolve(FakeNetwork::HANDLE);
    }

    public function testResolvesADidAndDropsAnUnverifiedHandle(): void
    {
        $network = new FakeNetwork();
        $network->txtRecords = [];
        $inner = $network->httpClient();
        $client = new MockHttpClient(static function (string $method, string $url, array $options) use ($inner) {
            if ($url === 'https://alice.example.com/.well-known/atproto-did') {
                return new MockResponse('did:plc:mallory');
            }

            return $inner->request($method, $url, $options);
        });

        $identity = (new IdentityResolver($client, $network))->resolve(FakeNetwork::DID);

        self::assertSame(FakeNetwork::DID, $identity->did);
        self::assertNull($identity->handle);
    }

    public function testResolvesDidWeb(): void
    {
        $client = new MockHttpClient(static fn (string $method, string $url) => match ($url) {
            'https://example.org/.well-known/did.json' => FakeNetwork::json([
                'id' => 'did:web:example.org',
                'service' => [['id' => 'did:web:example.org#atproto_pds', 'type' => 'AtprotoPersonalDataServer', 'serviceEndpoint' => 'https://pds.example.org/']],
            ]),
            default => FakeNetwork::json([], 404),
        });

        $identity = (new IdentityResolver($client, new FakeNetwork()))->resolve('did:web:example.org');

        self::assertSame('https://pds.example.org', $identity->pdsUrl);
    }

    public function testRejectsGarbage(): void
    {
        $network = new FakeNetwork();

        $this->expectException(IdentityResolutionException::class);
        (new IdentityResolver($network->httpClient(), $network))->resolve('not a handle');
    }

    public function testSyntax(): void
    {
        self::assertTrue(Syntax::isHandle('alice.bsky.social'));
        self::assertFalse(Syntax::isHandle('alice'));
        self::assertFalse(Syntax::isHandle('-alice.bsky.social'));
        self::assertTrue(Syntax::isDid('did:plc:z72i7hdynmk6r22z27h6tvur'));
        self::assertFalse(Syntax::isDid('did:plc:'));
        self::assertSame('alice.bsky.social', Syntax::normalizeHandle(' at://Alice.Bsky.Social '));
    }
}
