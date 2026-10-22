# AT Protocol OAuth bundle for Symfony

[![CI](https://github.com/wecoprod/atproto-oauth-bundle/actions/workflows/ci.yml/badge.svg)](https://github.com/wecoprod/atproto-oauth-bundle/actions/workflows/ci.yml)

Lets users of a Symfony application sign in with their [Bluesky](https://bsky.app) / [AT Protocol](https://atproto.com) account and lets the application call their PDS on their behalf (post, upload media, read their data).

It implements the [atproto OAuth profile](https://atproto.com/specs/oauth) as a **confidential client**:

- client metadata document as `client_id` and a public JWKS, served by the bundle
- client authentication with `private_key_jwt` (ES256)
- pushed authorization requests (PAR) and PKCE S256
- DPoP-bound tokens, with server nonces handled for you
- identity resolution: handle → DID → PDS → authorization server, with the checks the spec requires (bidirectional handle, authoritative server, `iss` in the response)
- token refresh before expiry, serialized across workers with `symfony/lock` (refresh tokens are single use)
- revocation

It does not wrap the Bluesky API: `AtprotoClient` gives you authenticated XRPC calls, the lexicons are yours.

Built for and used by [WecoPost](https://wecopost.com).

## Requirements

- PHP 8.2+ with `ext-openssl`
- Symfony 7.2+ or 8.x
- Optional: `symfony/lock` (recommended as soon as you run more than one worker)

## Installation

```bash
composer require wecoprod/atproto-oauth-bundle
```

Register the bundle if Flex did not:

```php
// config/bundles.php
return [
    // ...
    Wecoprod\AtprotoOAuthBundle\WecoprodAtprotoOAuthBundle::class => ['all' => true],
];
```

Generate the client key and keep it secret (environment variable, Symfony secrets...):

```bash
bin/console atproto-oauth:generate-key --base64
```

## Configuration

```yaml
# config/packages/wecoprod_atproto_oauth.yaml
wecoprod_atproto_oauth:
    # Must be the public https URL where the bundle serves the client metadata (see routes below)
    client_id: 'https://app.example.com/oauth/atproto/client-metadata.json'
    redirect_uris:
        - 'https://app.example.com/bluesky/callback'
    private_key: '%env(ATPROTO_OAUTH_PRIVATE_KEY)%'
    client_name: 'My app'
    client_uri: 'https://app.example.com'     # must have the same origin as client_id
    logo_uri: 'https://app.example.com/logo.png'
    tos_uri: 'https://app.example.com/terms'
    policy_uri: 'https://app.example.com/privacy'
    session_store: App\Bluesky\DoctrineSessionStore

    # Defaults
    # scope: 'atproto transition:generic'
    # default_authorization_server: 'https://bsky.social'   # used when the user gives no handle
    # jwks_uri: ~                                            # jwks.json next to the client_id
    # key_id: ~                                              # RFC 7638 thumbprint of the key
    # state_cache: cache.app                                 # PSR-6 pool for the pending authorizations
    # state_ttl: 600
    # lock_factory: ~                                        # "lock.factory" when symfony/lock is installed
    # http_client: http_client
    # allow_private_networks: false                          # handles and URLs come from users: blocks SSRF
```

Import the routes that serve the client metadata and the JWKS:

```yaml
# config/routes/wecoprod_atproto_oauth.yaml
wecoprod_atproto_oauth:
    resource: '@WecoprodAtprotoOAuthBundle/config/routes.php'
```

This adds `GET /oauth/atproto/client-metadata.json` and `GET /oauth/atproto/jwks.json`. They must be reachable without authentication: allow them in your firewall / access control.

## Storing sessions

A session holds an access token, a refresh token and the DPoP private key bound to them. Implement `SessionStoreInterface` with your own storage and **encrypt it at rest**. `Session::toJson()` / `Session::fromJson()` give you a string to encrypt.

```php
use Wecoprod\AtprotoOAuthBundle\OAuth\Session;
use Wecoprod\AtprotoOAuthBundle\Storage\SessionStoreInterface;

final class DoctrineSessionStore implements SessionStoreInterface
{
    public function __construct(private BlueskyAccountRepository $accounts, private Encryptor $encryptor, private EntityManagerInterface $em) {}

    public function get(string $did): ?Session
    {
        $account = $this->accounts->findOneByDid($did);

        return $account?->getOauthSession() ? Session::fromJson($this->encryptor->decrypt($account->getOauthSession())) : null;
    }

    public function save(Session $session): void
    {
        $account = $this->accounts->findOneByDid($session->did) ?? new BlueskyAccount($session->did);
        $account->setOauthSession($this->encryptor->encrypt($session->toJson()));
        $this->em->persist($account);
        $this->em->flush();
    }

    public function delete(string $did): void
    {
        $this->accounts->findOneByDid($did)?->setOauthSession(null);
        $this->em->flush();
    }
}
```

Sessions are keyed by DID: an account connected twice shares one session.

## Signing in

```php
use Wecoprod\AtprotoOAuthBundle\OAuth\OAuthClient;

final class BlueskyController extends AbstractController
{
    #[Route('/bluesky/connect', methods: ['POST'])]
    public function connect(Request $request, OAuthClient $oauth): Response
    {
        // A handle ("alice.bsky.social"), a DID, a PDS URL, or nothing to start on bsky.social
        $handle = $request->request->getString('handle') ?: null;

        return $this->redirect($oauth->authorize($handle, ['userId' => $this->getUser()->getId()]));
    }

    #[Route('/bluesky/callback')]
    public function callback(Request $request, OAuthClient $oauth): Response
    {
        $result = $oauth->callback($request->query->all());
        // $result->session->did, ->handle, ->pdsUrl ; $result->appState['userId']
        // The session is already saved through your SessionStoreInterface.

        return $this->redirectToRoute('accounts');
    }
}
```

`callback()` throws `OAuthErrorException` (the user refused, `$e->error === 'access_denied'`), `InvalidStateException` (expired or replayed callback) or `AtprotoOAuthException`.

## Calling the PDS

```php
use Wecoprod\AtprotoOAuthBundle\Xrpc\AtprotoClient;

$blob = $atproto->uploadBlob($did, file_get_contents($imagePath), 'image/jpeg');

$post = $atproto->post($did, 'com.atproto.repo.createRecord', [
    'repo' => $did,
    'collection' => 'app.bsky.feed.post',
    'record' => [
        '$type' => 'app.bsky.feed.post',
        'text' => 'Hello from Symfony',
        'createdAt' => (new \DateTimeImmutable())->format(\DATE_ATOM),
        'embed' => ['$type' => 'app.bsky.embed.images', 'images' => [['image' => $blob, 'alt' => 'A cat']]],
    ],
]);
// $post['uri'], $post['cid']

$profile = $atproto->get($did, 'app.bsky.actor.getProfile', ['actor' => $did]);
```

The session is refreshed before it expires, and once more if the PDS rejects the token. When the refresh token is refused, `SessionRevokedException` is thrown and the session is deleted: ask the user to sign in again.

Errors returned by the PDS throw `XrpcException` with `$e->statusCode` and `$e->error` (e.g. `InvalidRequest`).

To disconnect an account:

```php
$sessionManager->revoke($did); // revokes at the authorization server (best effort) and deletes the session
```

## Local development

Authorization servers fetch your client metadata from the internet, so `client_id` must be a public https URL. Expose your local app through a tunnel (ngrok, cloudflared, frp...) and use that URL in `client_id` and `redirect_uris`.

## Security notes

- Requests to private networks are blocked by default (`NoPrivateNetworkHttpClient`): handles, DIDs and PDS URLs are user input.
- The client private key signs every token request, and authorization servers bind each session to the key that started it. Removing that key from the JWKS ends those sessions. Key rotation (serving several keys) is not supported yet.
- Report vulnerabilities through GitHub's private vulnerability reporting (Security tab) rather than in a public issue.

## License

MIT, see [LICENSE](LICENSE).
