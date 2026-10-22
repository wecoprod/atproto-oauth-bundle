<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\Tests\OAuth;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Wecoprod\AtprotoOAuthBundle\Crypto\EcKey;
use Wecoprod\AtprotoOAuthBundle\Crypto\Jwt;
use Wecoprod\AtprotoOAuthBundle\Crypto\Pkce;
use Wecoprod\AtprotoOAuthBundle\Exception\AtprotoOAuthException;
use Wecoprod\AtprotoOAuthBundle\Exception\InvalidStateException;
use Wecoprod\AtprotoOAuthBundle\Exception\OAuthErrorException;
use Wecoprod\AtprotoOAuthBundle\Exception\SessionRevokedException;
use Wecoprod\AtprotoOAuthBundle\Identity\IdentityResolver;
use Wecoprod\AtprotoOAuthBundle\OAuth\ClientConfiguration;
use Wecoprod\AtprotoOAuthBundle\OAuth\DpopTransport;
use Wecoprod\AtprotoOAuthBundle\OAuth\OAuthClient;
use Wecoprod\AtprotoOAuthBundle\OAuth\ServerMetadataResolver;
use Wecoprod\AtprotoOAuthBundle\Storage\CacheStateStore;
use Wecoprod\AtprotoOAuthBundle\Storage\InMemorySessionStore;
use Wecoprod\AtprotoOAuthBundle\Tests\FakeNetwork;

final class OAuthClientTest extends TestCase
{
    private const CLIENT_ID = 'https://app.example.net/oauth/atproto/client-metadata.json';
    private const REDIRECT_URI = 'https://app.example.net/bluesky/callback';

    private FakeNetwork $network;
    private InMemorySessionStore $sessions;
    private EcKey $clientKey;
    private OAuthClient $client;

    protected function setUp(): void
    {
        $this->network = new FakeNetwork();
        $this->sessions = new InMemorySessionStore();
        $this->clientKey = EcKey::generate();
        $http = $this->network->httpClient();

        $this->client = new OAuthClient(
            new ClientConfiguration(self::CLIENT_ID, [self::REDIRECT_URI], $this->clientKey, defaultAuthorizationServer: FakeNetwork::ISSUER),
            new IdentityResolver($http, $this->network),
            new ServerMetadataResolver($http),
            new DpopTransport($http),
            new CacheStateStore(new ArrayAdapter()),
            $this->sessions,
        );
    }

    public function testAuthorizeSendsAPushedAuthorizationRequest(): void
    {
        $url = $this->client->authorize(FakeNetwork::HANDLE, ['userId' => 42]);

        self::assertSame(FakeNetwork::ISSUER.'/oauth/authorize?client_id='.rawurlencode(self::CLIENT_ID).'&request_uri='.rawurlencode('urn:ietf:params:oauth:request_uri:req-1'), $url);

        $par = $this->network->requestsTo(FakeNetwork::ISSUER.'/oauth/par');
        self::assertCount(2, $par, 'first attempt without nonce, second with the nonce from the server');

        parse_str($par[1]['body'], $params);
        self::assertSame('code', $params['response_type']);
        self::assertSame(self::REDIRECT_URI, $params['redirect_uri']);
        self::assertSame('atproto transition:generic', $params['scope']);
        self::assertSame('S256', $params['code_challenge_method']);
        self::assertSame(FakeNetwork::HANDLE, $params['login_hint']);
        self::assertSame(self::CLIENT_ID, $params['client_id']);
        self::assertSame('urn:ietf:params:oauth:client-assertion-type:jwt-bearer', $params['client_assertion_type']);

        [$header, $payload] = Jwt::decode($params['client_assertion']);
        self::assertSame('ES256', $header['alg']);
        self::assertSame($this->clientKey->thumbprint(), $header['kid']);
        self::assertSame(self::CLIENT_ID, $payload['iss']);
        self::assertSame(self::CLIENT_ID, $payload['sub']);
        self::assertSame(FakeNetwork::ISSUER, $payload['aud']);

        parse_str($par[0]['body'], $firstParams);
        self::assertNotSame(Jwt::decode($firstParams['client_assertion'])[1]['jti'], $payload['jti'], 'a fresh assertion on retry');

        [$dpopHeader, $dpopPayload] = Jwt::decode($par[1]['headers']['dpop']);
        self::assertSame('dpop+jwt', $dpopHeader['typ']);
        self::assertSame('EC', $dpopHeader['jwk']['kty']);
        self::assertArrayNotHasKey('d', $dpopHeader['jwk']);
        self::assertSame('POST', $dpopPayload['htm']);
        self::assertSame(FakeNetwork::ISSUER.'/oauth/par', $dpopPayload['htu']);
        self::assertSame('nonce-1', $dpopPayload['nonce']);
        self::assertArrayNotHasKey('ath', $dpopPayload);
    }

    public function testFullFlowStoresTheSession(): void
    {
        $this->client->authorize(FakeNetwork::HANDLE, ['userId' => 42]);
        [$state, $challenge] = $this->parParams();

        $result = $this->client->callback(['state' => $state, 'iss' => FakeNetwork::ISSUER, 'code' => 'code-1']);

        self::assertSame(['userId' => 42], $result->appState);
        self::assertSame(FakeNetwork::DID, $result->session->did);
        self::assertSame(FakeNetwork::HANDLE, $result->session->handle);
        self::assertSame(FakeNetwork::PDS, $result->session->pdsUrl);
        self::assertSame('access-1', $result->session->accessToken);
        self::assertSame('refresh-1', $result->session->refreshToken);
        self::assertFalse($result->session->isExpired());
        self::assertSame($result->session, $this->sessions->get(FakeNetwork::DID));

        $token = $this->network->requestsTo(FakeNetwork::ISSUER.'/oauth/token');
        parse_str(end($token)['body'], $params);
        self::assertSame('authorization_code', $params['grant_type']);
        self::assertSame('code-1', $params['code']);
        self::assertSame($challenge, Pkce::challenge($params['code_verifier']));

        // Same DPoP key for the PAR and the token request: the token is bound to it
        $par = $this->network->requestsTo(FakeNetwork::ISSUER.'/oauth/par');
        self::assertSame(Jwt::decode($par[1]['headers']['dpop'])[0]['jwk'], Jwt::decode(end($token)['headers']['dpop'])[0]['jwk']);
        self::assertSame(Jwt::decode($par[1]['headers']['dpop'])[0]['jwk'], $result->session->dpopKey()->publicJwk());
    }

    public function testFlowStartingFromTheDefaultServer(): void
    {
        $url = $this->client->authorize();
        self::assertStringStartsWith(FakeNetwork::ISSUER.'/oauth/authorize?', $url);

        [$state] = $this->parParams();
        $params = $this->lastParParams();
        self::assertArrayNotHasKey('login_hint', $params);

        $result = $this->client->callback(['state' => $state, 'iss' => FakeNetwork::ISSUER, 'code' => 'code-1']);
        self::assertSame(FakeNetwork::DID, $result->session->did);
    }

    public function testStateIsSingleUse(): void
    {
        $this->client->authorize(FakeNetwork::HANDLE);
        [$state] = $this->parParams();
        $this->client->callback(['state' => $state, 'iss' => FakeNetwork::ISSUER, 'code' => 'code-1']);

        $this->expectException(InvalidStateException::class);
        $this->client->callback(['state' => $state, 'iss' => FakeNetwork::ISSUER, 'code' => 'code-1']);
    }

    public function testRejectsAnotherIssuer(): void
    {
        $this->client->authorize(FakeNetwork::HANDLE);
        [$state] = $this->parParams();

        $this->expectException(AtprotoOAuthException::class);
        $this->expectExceptionMessage('issuer');
        $this->client->callback(['state' => $state, 'iss' => 'https://evil.example.com', 'code' => 'code-1']);
    }

    public function testRejectsAServerThatIsNotAuthoritativeForTheAccount(): void
    {
        $this->client->authorize(FakeNetwork::HANDLE);
        [$state] = $this->parParams();
        // The account moved to a PDS protected by another server between the redirect and the callback
        $this->network->didDocument['service'][0]['serviceEndpoint'] = 'https://other-pds.example.com';

        $this->expectException(AtprotoOAuthException::class);
        $this->client->callback(['state' => $state, 'iss' => FakeNetwork::ISSUER, 'code' => 'code-1']);
    }

    public function testErrorInTheCallback(): void
    {
        $this->client->authorize(FakeNetwork::HANDLE);
        [$state] = $this->parParams();

        try {
            $this->client->callback(['state' => $state, 'iss' => FakeNetwork::ISSUER, 'error' => 'access_denied', 'error_description' => 'User refused']);
            self::fail('Expected an OAuthErrorException');
        } catch (OAuthErrorException $e) {
            self::assertSame('access_denied', $e->error);
        }

        // The state is consumed even on error
        $this->expectException(InvalidStateException::class);
        $this->client->callback(['state' => $state, 'iss' => FakeNetwork::ISSUER, 'code' => 'code-1']);
    }

    public function testRefreshKeepsTheDpopKey(): void
    {
        $session = $this->signIn();

        $refreshed = $this->client->refresh($session);

        self::assertSame('access-2', $refreshed->accessToken);
        self::assertSame('refresh-2', $refreshed->refreshToken);
        self::assertSame($session->dpopKeyPem, $refreshed->dpopKeyPem);

        $token = $this->network->requestsTo(FakeNetwork::ISSUER.'/oauth/token');
        parse_str(end($token)['body'], $params);
        self::assertSame('refresh_token', $params['grant_type']);
        self::assertSame('refresh-1', $params['refresh_token']);
    }

    public function testRevokedRefreshToken(): void
    {
        $session = $this->signIn();
        $this->network->refreshRevoked = true;

        $this->expectException(SessionRevokedException::class);
        $this->client->refresh($session);
    }

    public function testRevoke(): void
    {
        $session = $this->signIn();
        $this->client->revoke($session);

        $revoke = $this->network->requestsTo(FakeNetwork::ISSUER.'/oauth/revoke');
        parse_str(end($revoke)['body'], $params);
        self::assertSame('refresh-1', $params['token']);
    }

    public function testRejectsAnUnregisteredRedirectUri(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->client->authorize(FakeNetwork::HANDLE, [], 'https://evil.example.com/callback');
    }

    public function testRejectsAServerWithoutPar(): void
    {
        unset($this->network->serverMetadata['pushed_authorization_request_endpoint']);

        $this->expectException(AtprotoOAuthException::class);
        $this->client->authorize(FakeNetwork::HANDLE);
    }

    private function signIn(): \Wecoprod\AtprotoOAuthBundle\OAuth\Session
    {
        $this->client->authorize(FakeNetwork::HANDLE);
        [$state] = $this->parParams();

        return $this->client->callback(['state' => $state, 'iss' => FakeNetwork::ISSUER, 'code' => 'code-1'])->session;
    }

    /**
     * @return array{0: string, 1: string} state and code challenge of the last PAR
     */
    private function parParams(): array
    {
        $params = $this->lastParParams();

        return [$params['state'], $params['code_challenge']];
    }

    /**
     * @return array<string, string>
     */
    private function lastParParams(): array
    {
        $par = $this->network->requestsTo(FakeNetwork::ISSUER.'/oauth/par');
        parse_str(end($par)['body'], $params);

        return $params;
    }
}
