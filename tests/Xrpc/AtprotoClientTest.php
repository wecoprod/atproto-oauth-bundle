<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\Tests\Xrpc;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Lock\LockFactory;
use Symfony\Component\Lock\Store\InMemoryStore;
use Wecoprod\AtprotoOAuthBundle\Crypto\Base64Url;
use Wecoprod\AtprotoOAuthBundle\Crypto\EcKey;
use Wecoprod\AtprotoOAuthBundle\Crypto\Jwt;
use Wecoprod\AtprotoOAuthBundle\Exception\SessionNotFoundException;
use Wecoprod\AtprotoOAuthBundle\Exception\SessionRevokedException;
use Wecoprod\AtprotoOAuthBundle\Exception\XrpcException;
use Wecoprod\AtprotoOAuthBundle\Identity\IdentityResolver;
use Wecoprod\AtprotoOAuthBundle\OAuth\ClientConfiguration;
use Wecoprod\AtprotoOAuthBundle\OAuth\DpopTransport;
use Wecoprod\AtprotoOAuthBundle\OAuth\OAuthClient;
use Wecoprod\AtprotoOAuthBundle\OAuth\ServerMetadataResolver;
use Wecoprod\AtprotoOAuthBundle\OAuth\Session;
use Wecoprod\AtprotoOAuthBundle\OAuth\SessionManager;
use Wecoprod\AtprotoOAuthBundle\Storage\CacheStateStore;
use Wecoprod\AtprotoOAuthBundle\Storage\InMemorySessionStore;
use Wecoprod\AtprotoOAuthBundle\Tests\FakeNetwork;
use Wecoprod\AtprotoOAuthBundle\Xrpc\AtprotoClient;

final class AtprotoClientTest extends TestCase
{
    private FakeNetwork $network;
    private InMemorySessionStore $sessions;
    private OAuthClient $oauth;
    private SessionManager $manager;
    private AtprotoClient $client;

    protected function setUp(): void
    {
        $this->network = new FakeNetwork();
        $this->sessions = new InMemorySessionStore();
        $http = $this->network->httpClient();
        $transport = new DpopTransport($http);

        $this->oauth = new OAuthClient(
            new ClientConfiguration('https://app.example.net/oauth/atproto/client-metadata.json', ['https://app.example.net/callback'], EcKey::generate()),
            new IdentityResolver($http, $this->network),
            new ServerMetadataResolver($http),
            $transport,
            new CacheStateStore(new ArrayAdapter()),
            $this->sessions,
        );
        $this->manager = new SessionManager($this->oauth, $this->sessions, new LockFactory(new InMemoryStore()));
        $this->client = new AtprotoClient($this->manager, $transport);

        $this->oauth->authorize(FakeNetwork::HANDLE);
        $par = $this->network->requestsTo(FakeNetwork::ISSUER.'/oauth/par');
        parse_str(end($par)['body'], $params);
        $this->oauth->callback(['state' => $params['state'], 'iss' => FakeNetwork::ISSUER, 'code' => 'code']);
    }

    public function testPostSendsADpopBoundRequest(): void
    {
        $this->network->xrpcHandlers['com.atproto.repo.createRecord'] = static function (array $request) {
            $body = json_decode($request['body'], true);

            return FakeNetwork::json(['uri' => 'at://'.$body['repo'].'/app.bsky.feed.post/3abc', 'cid' => 'bafy']);
        };

        $result = $this->client->post(FakeNetwork::DID, 'com.atproto.repo.createRecord', [
            'repo' => FakeNetwork::DID,
            'collection' => 'app.bsky.feed.post',
            'record' => ['text' => 'Hello', 'createdAt' => '2026-10-22T10:00:00Z'],
        ]);

        self::assertSame('at://did:plc:alice/app.bsky.feed.post/3abc', $result['uri']);

        $request = $this->network->requestsTo(FakeNetwork::PDS.'/xrpc/com.atproto.repo.createRecord');
        $last = end($request);
        self::assertSame('DPoP access-1', $last['headers']['authorization']);
        $proof = Jwt::decode($last['headers']['dpop'])[1];
        self::assertSame(Base64Url::encode(hash('sha256', 'access-1', true)), $proof['ath']);
        self::assertSame(FakeNetwork::PDS.'/xrpc/com.atproto.repo.createRecord', $proof['htu']);
    }

    public function testRefreshesAnExpiredSessionBeforeTheCall(): void
    {
        $this->expire();
        $this->network->xrpcHandlers['app.bsky.actor.getProfile'] = static fn () => FakeNetwork::json(['handle' => FakeNetwork::HANDLE]);

        $this->client->get(FakeNetwork::DID, 'app.bsky.actor.getProfile', ['actor' => FakeNetwork::DID]);

        self::assertSame('access-2', $this->sessions->get(FakeNetwork::DID)?->accessToken);
    }

    public function testRefreshesOnceWhenThePdsRejectsTheToken(): void
    {
        $this->network->xrpcHandlers['app.bsky.actor.getProfile'] = static fn () => FakeNetwork::json(['handle' => FakeNetwork::HANDLE]);
        // The server rotated the token (e.g. another client refreshed): the stored access-1 is no longer valid
        ++$this->network->tokenCounter;

        $profile = $this->client->get(FakeNetwork::DID, 'app.bsky.actor.getProfile', ['actor' => FakeNetwork::DID]);

        self::assertSame(FakeNetwork::HANDLE, $profile['handle']);
        self::assertSame('access-3', $this->sessions->get(FakeNetwork::DID)?->accessToken);
    }

    public function testRevokedSessionIsRemoved(): void
    {
        $this->expire();
        $this->network->refreshRevoked = true;

        try {
            $this->client->get(FakeNetwork::DID, 'app.bsky.actor.getProfile');
            self::fail('Expected a SessionRevokedException');
        } catch (SessionRevokedException $e) {
            self::assertSame(FakeNetwork::DID, $e->did);
        }

        self::assertNull($this->sessions->get(FakeNetwork::DID));
        $this->expectException(SessionNotFoundException::class);
        $this->client->get(FakeNetwork::DID, 'app.bsky.actor.getProfile');
    }

    public function testXrpcErrors(): void
    {
        $this->network->xrpcHandlers['com.atproto.repo.createRecord'] = static fn () => FakeNetwork::json(['error' => 'InvalidRequest', 'message' => 'Record/text must not be longer than 300 graphemes'], 400);

        try {
            $this->client->post(FakeNetwork::DID, 'com.atproto.repo.createRecord', []);
            self::fail('Expected an XrpcException');
        } catch (XrpcException $e) {
            self::assertSame(400, $e->statusCode);
            self::assertSame('InvalidRequest', $e->error);
            self::assertStringContainsString('300 graphemes', $e->getMessage());
        }
    }

    public function testUploadBlob(): void
    {
        $this->network->xrpcHandlers['com.atproto.repo.uploadBlob'] = static fn (array $request) => FakeNetwork::json(['blob' => [
            '$type' => 'blob', 'ref' => ['$link' => 'bafkrei'], 'mimeType' => $request['headers']['content-type'], 'size' => \strlen($request['body']),
        ]]);

        $blob = $this->client->uploadBlob(FakeNetwork::DID, 'fake-png-bytes', 'image/png');

        self::assertSame('image/png', $blob['mimeType']);
        self::assertSame(14, $blob['size']);
    }

    public function testQueryStringRepeatsListParameters(): void
    {
        self::assertSame('?uris=at%3A%2F%2Fa&uris=at%3A%2F%2Fb&limit=25&reverse=true', AtprotoClient::queryString([
            'uris' => ['at://a', 'at://b'],
            'limit' => 25,
            'reverse' => true,
            'cursor' => null,
        ]));
        self::assertSame('', AtprotoClient::queryString([]));
    }

    private function expire(): void
    {
        $session = $this->sessions->get(FakeNetwork::DID);
        self::assertInstanceOf(Session::class, $session);
        $this->sessions->save($session->withTokens($session->accessToken, $session->refreshToken, new \DateTimeImmutable('-1 minute'), $session->scope));
    }
}
