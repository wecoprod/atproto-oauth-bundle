<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\Tests\Functional;

use PHPUnit\Framework\TestCase;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;
use Wecoprod\AtprotoOAuthBundle\Crypto\EcKey;
use Wecoprod\AtprotoOAuthBundle\OAuth\OAuthClient;
use Wecoprod\AtprotoOAuthBundle\OAuth\SessionManager;
use Wecoprod\AtprotoOAuthBundle\Storage\InMemorySessionStore;
use Wecoprod\AtprotoOAuthBundle\WecoprodAtprotoOAuthBundle;
use Wecoprod\AtprotoOAuthBundle\Xrpc\AtprotoClient;

final class BundleTest extends TestCase
{
    private static string $pem;

    public static function setUpBeforeClass(): void
    {
        self::$pem = base64_encode(EcKey::generate()->toPem());
    }

    public function testServesClientMetadataAndJwks(): void
    {
        $kernel = new TestKernel(self::$pem);
        $kernel->boot();

        $response = $kernel->handle(Request::create('https://app.example.net/oauth/atproto/client-metadata.json'));
        self::assertSame(200, $response->getStatusCode());
        $metadata = json_decode((string) $response->getContent(), true);
        self::assertSame('https://app.example.net/oauth/atproto/client-metadata.json', $metadata['client_id']);
        self::assertSame(['https://app.example.net/bluesky/callback'], $metadata['redirect_uris']);
        self::assertSame('https://app.example.net/oauth/atproto/jwks.json', $metadata['jwks_uri']);
        self::assertSame('private_key_jwt', $metadata['token_endpoint_auth_method']);
        self::assertSame('ES256', $metadata['token_endpoint_auth_signing_alg']);
        self::assertTrue($metadata['dpop_bound_access_tokens']);
        self::assertSame('WecoPost', $metadata['client_name']);
        self::assertArrayNotHasKey('logo_uri', $metadata);

        $response = $kernel->handle(Request::create('https://app.example.net/oauth/atproto/jwks.json'));
        $jwks = json_decode((string) $response->getContent(), true);
        self::assertCount(1, $jwks['keys']);
        self::assertSame(EcKey::fromPem(self::$pem)->thumbprint(), $jwks['keys'][0]['kid']);
        self::assertArrayNotHasKey('d', $jwks['keys'][0]);

        $container = $kernel->getContainer();
        self::assertInstanceOf(OAuthClient::class, $container->get(OAuthClient::class));
        self::assertInstanceOf(SessionManager::class, $container->get(SessionManager::class));
        self::assertInstanceOf(AtprotoClient::class, $container->get(AtprotoClient::class));

        $kernel->shutdown();
    }
}

final class TestKernel extends Kernel
{
    use MicroKernelTrait;

    public function __construct(private readonly string $pem)
    {
        parent::__construct('test', false);
    }

    public function registerBundles(): iterable
    {
        return [new FrameworkBundle(), new WecoprodAtprotoOAuthBundle()];
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir().'/atproto-oauth-bundle-tests/'.md5($this->pem).'/cache';
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir().'/atproto-oauth-bundle-tests/logs';
    }

    protected function configureContainer(ContainerBuilder $container, LoaderInterface $loader): void
    {
        $container->loadFromExtension('framework', [
            'secret' => 'test',
            'test' => true,
            'http_method_override' => false,
            'lock' => 'flock',
        ]);
        $container->register('test.session_store', InMemorySessionStore::class);
        $container->loadFromExtension('wecoprod_atproto_oauth', [
            'client_id' => 'https://app.example.net/oauth/atproto/client-metadata.json',
            'redirect_uris' => ['https://app.example.net/bluesky/callback'],
            'private_key' => $this->pem,
            'client_name' => 'WecoPost',
            'session_store' => 'test.session_store',
        ]);
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->import('@WecoprodAtprotoOAuthBundle/config/routes.php');
    }
}
