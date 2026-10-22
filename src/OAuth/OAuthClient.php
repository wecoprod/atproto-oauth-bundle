<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\OAuth;

use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpExceptionInterface;
use Wecoprod\AtprotoOAuthBundle\Crypto\EcKey;
use Wecoprod\AtprotoOAuthBundle\Crypto\Jwt;
use Wecoprod\AtprotoOAuthBundle\Crypto\Pkce;
use Wecoprod\AtprotoOAuthBundle\Exception\AtprotoOAuthException;
use Wecoprod\AtprotoOAuthBundle\Exception\InvalidStateException;
use Wecoprod\AtprotoOAuthBundle\Exception\OAuthErrorException;
use Wecoprod\AtprotoOAuthBundle\Exception\SessionRevokedException;
use Wecoprod\AtprotoOAuthBundle\Identity\IdentityResolver;
use Wecoprod\AtprotoOAuthBundle\Identity\Syntax;
use Wecoprod\AtprotoOAuthBundle\Storage\SessionStoreInterface;
use Wecoprod\AtprotoOAuthBundle\Storage\StateStoreInterface;

/**
 * The atproto OAuth flow for a confidential client: PAR + PKCE + DPoP + private_key_jwt.
 *
 *  1. authorize() resolves the account (or starts from the default server) and returns the URL to redirect to
 *  2. callback() checks the response, exchanges the code, verifies the account and stores the session
 *  3. refresh() / revoke() operate on a stored session (see SessionManager for the locked variant)
 */
final class OAuthClient
{
    private const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

    public function __construct(
        private readonly ClientConfiguration $config,
        private readonly IdentityResolver $identityResolver,
        private readonly ServerMetadataResolver $metadataResolver,
        private readonly DpopTransport $transport,
        private readonly StateStoreInterface $stateStore,
        private readonly SessionStoreInterface $sessionStore,
    ) {
    }

    /**
     * @param string|null                 $identifier  a handle, a DID, a PDS or authorization server URL, or null for the default server
     * @param array<string, scalar|null> $appState    returned as is by callback()
     *
     * @return string the URL to redirect the user to
     */
    public function authorize(?string $identifier = null, array $appState = [], ?string $redirectUri = null): string
    {
        $redirectUri ??= $this->config->redirectUris[0];
        if (!\in_array($redirectUri, $this->config->redirectUris, true)) {
            throw new \InvalidArgumentException(\sprintf('"%s" is not a registered redirect URI.', $redirectUri));
        }

        $identifier = $identifier !== null ? trim($identifier) : null;
        $expectedDid = null;
        $loginHint = null;

        if ($identifier === null || $identifier === '') {
            $server = $this->metadataResolver->authorizationServerForUrl($this->config->defaultAuthorizationServer);
        } elseif (str_starts_with($identifier, 'https://')) {
            $server = $this->metadataResolver->authorizationServerForUrl($identifier);
        } else {
            $identity = $this->identityResolver->resolve($identifier);
            $expectedDid = $identity->did;
            $loginHint = Syntax::isDid($identifier) ? $identifier : Syntax::normalizeHandle($identifier);
            $server = $this->metadataResolver->authorizationServer($this->metadataResolver->issuerForPds($identity->pdsUrl));
        }

        $dpopKey = EcKey::generate();
        $verifier = Pkce::verifier();
        $state = Jwt::randomId();

        $response = $this->postToServer($server, $server->pushedAuthorizationRequestEndpoint, $dpopKey, array_filter([
            'response_type' => 'code',
            'redirect_uri' => $redirectUri,
            'scope' => $this->config->scope,
            'state' => $state,
            'code_challenge' => Pkce::challenge($verifier),
            'code_challenge_method' => 'S256',
            'login_hint' => $loginHint,
        ], static fn ($value) => $value !== null));

        $requestUri = $response['request_uri'] ?? null;
        if (!\is_string($requestUri) || $requestUri === '') {
            throw new AtprotoOAuthException('The authorization server returned no request_uri.');
        }

        $this->stateStore->save(new AuthorizationState($state, $server->issuer, $verifier, $dpopKey->toPem(), $redirectUri, $expectedDid, $appState));

        return $server->authorizationEndpoint.'?'.http_build_query([
            'client_id' => $this->config->clientId,
            'request_uri' => $requestUri,
        ]);
    }

    /**
     * @param array<string, mixed> $query the query parameters of the callback request
     */
    public function callback(array $query): CallbackResult
    {
        $stateValue = \is_string($query['state'] ?? null) ? $query['state'] : '';
        $state = $this->stateStore->consume($stateValue);

        if (isset($query['error'])) {
            throw new OAuthErrorException((string) $query['error'], isset($query['error_description']) ? (string) $query['error_description'] : null);
        }
        if ($state === null) {
            throw new InvalidStateException('Unknown or expired OAuth state.');
        }
        // RFC 9207: the issuer in the response must be the server the request was sent to
        if (($query['iss'] ?? null) !== $state->issuer) {
            throw new AtprotoOAuthException('The callback issuer does not match the authorization server.');
        }
        $code = $query['code'] ?? null;
        if (!\is_string($code) || $code === '') {
            throw new AtprotoOAuthException('The callback has no authorization code.');
        }

        $server = $this->metadataResolver->authorizationServer($state->issuer);
        $dpopKey = EcKey::fromPem($state->dpopKeyPem);

        $tokens = $this->postToServer($server, $server->tokenEndpoint, $dpopKey, [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $state->redirectUri,
            'code_verifier' => $state->pkceVerifier,
        ]);

        $did = $tokens['sub'] ?? null;
        if (!\is_string($did) || !Syntax::isDid($did)) {
            throw new AtprotoOAuthException('The token response has no valid sub.');
        }
        if ($state->expectedDid !== null && $did !== $state->expectedDid) {
            throw new AtprotoOAuthException('The account that signed in is not the one that was requested.');
        }

        // The authorization server must be the one in charge of this DID, otherwise any server could claim any account
        $identity = $this->identityResolver->resolve($did);
        if ($this->metadataResolver->issuerForPds($identity->pdsUrl) !== $state->issuer) {
            throw new AtprotoOAuthException(\sprintf('The authorization server %s is not authoritative for %s.', $state->issuer, $did));
        }

        $session = $this->sessionFromTokens($tokens, $did, $identity->handle, $identity->pdsUrl, $state->issuer, $state->dpopKeyPem);
        $this->sessionStore->save($session);

        return new CallbackResult($session, $state->appState);
    }

    /**
     * Exchanges the refresh token. Not locked: use SessionManager when several processes may refresh the same session.
     *
     * @throws SessionRevokedException when the authorization server refuses the refresh token
     */
    public function refresh(Session $session): Session
    {
        if ($session->refreshToken === null) {
            throw new SessionRevokedException($session->did);
        }

        $server = $this->metadataResolver->authorizationServer($session->issuer);

        try {
            $tokens = $this->postToServer($server, $server->tokenEndpoint, $session->dpopKey(), [
                'grant_type' => 'refresh_token',
                'refresh_token' => $session->refreshToken,
            ]);
        } catch (OAuthErrorException $e) {
            if ($e->error === 'invalid_grant') {
                throw new SessionRevokedException($session->did, $e);
            }
            throw $e;
        }

        if (($tokens['sub'] ?? null) !== $session->did) {
            throw new AtprotoOAuthException('The refreshed token belongs to another account.');
        }

        return $this->sessionFromTokens($tokens, $session->did, $session->handle, $session->pdsUrl, $session->issuer, $session->dpopKeyPem);
    }

    /** Best effort: revokes the refresh token (and with it the access token) at the authorization server. */
    public function revoke(Session $session): void
    {
        $server = $this->metadataResolver->authorizationServer($session->issuer);
        if ($server->revocationEndpoint === null) {
            return;
        }

        $this->postToServer($server, $server->revocationEndpoint, $session->dpopKey(), [
            'token' => $session->refreshToken ?? $session->accessToken,
        ], expectJson: false);
    }

    /**
     * @param array<string, string> $params
     *
     * @return array<string, mixed>
     */
    private function postToServer(AuthorizationServerMetadata $server, string $endpoint, EcKey $dpopKey, array $params, bool $expectJson = true): array
    {
        $params += [
            'client_id' => $this->config->clientId,
            'client_assertion_type' => self::ASSERTION_TYPE,
        ];

        try {
            // A fresh assertion (new jti) for each attempt: the transport replays the request when the server asks for a DPoP nonce
            $response = $this->transport->request('POST', $endpoint, $dpopKey, ['body' => $params, 'timeout' => 15], null, function (array $options) use ($server): array {
                $options['body']['client_assertion'] = $this->clientAssertion($server->issuer);

                return $options;
            });
            $status = $response->getStatusCode();
            $body = $expectJson || $status >= 400 ? $response->toArray(false) : [];
        } catch (HttpExceptionInterface $e) {
            throw new AtprotoOAuthException(\sprintf('Request to %s failed: %s', $endpoint, $e->getMessage()), 0, $e);
        }

        if ($status >= 400) {
            throw new OAuthErrorException(
                \is_string($body['error'] ?? null) ? $body['error'] : 'server_error',
                \is_string($body['error_description'] ?? null) ? $body['error_description'] : null,
                $status,
            );
        }

        return $body;
    }

    private function clientAssertion(string $audience): string
    {
        $now = time();

        return Jwt::sign(['kid' => $this->config->keyId], [
            'iss' => $this->config->clientId,
            'sub' => $this->config->clientId,
            'aud' => $audience,
            'jti' => Jwt::randomId(),
            'iat' => $now,
            'exp' => $now + 60,
        ], $this->config->clientKey);
    }

    /**
     * @param array<string, mixed> $tokens
     */
    private function sessionFromTokens(array $tokens, string $did, ?string $handle, string $pdsUrl, string $issuer, string $dpopKeyPem): Session
    {
        $accessToken = $tokens['access_token'] ?? null;
        if (!\is_string($accessToken) || $accessToken === '') {
            throw new AtprotoOAuthException('The token response has no access_token.');
        }
        if (strcasecmp((string) ($tokens['token_type'] ?? ''), 'DPoP') !== 0) {
            throw new AtprotoOAuthException('The token response is not a DPoP-bound token.');
        }
        $scope = (string) ($tokens['scope'] ?? '');
        if (!\in_array('atproto', explode(' ', $scope), true)) {
            throw new AtprotoOAuthException('The granted scope does not include atproto.');
        }

        $expiresIn = $tokens['expires_in'] ?? null;

        return new Session(
            $did,
            $handle,
            $pdsUrl,
            $issuer,
            $accessToken,
            \is_string($tokens['refresh_token'] ?? null) ? $tokens['refresh_token'] : null,
            is_numeric($expiresIn) ? (new \DateTimeImmutable())->setTimestamp(time() + (int) $expiresIn) : null,
            $scope,
            $dpopKeyPem,
        );
    }
}
