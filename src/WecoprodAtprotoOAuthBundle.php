<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle;

use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpClient\NoPrivateNetworkHttpClient;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;
use Symfony\Component\Lock\LockFactory;
use Wecoprod\AtprotoOAuthBundle\Command\GenerateKeyCommand;
use Wecoprod\AtprotoOAuthBundle\Controller\ClientMetadataController;
use Wecoprod\AtprotoOAuthBundle\Crypto\EcKey;
use Wecoprod\AtprotoOAuthBundle\Identity\DnsResolverInterface;
use Wecoprod\AtprotoOAuthBundle\Identity\IdentityResolver;
use Wecoprod\AtprotoOAuthBundle\Identity\NativeDnsResolver;
use Wecoprod\AtprotoOAuthBundle\OAuth\ClientConfiguration;
use Wecoprod\AtprotoOAuthBundle\OAuth\DpopTransport;
use Wecoprod\AtprotoOAuthBundle\OAuth\OAuthClient;
use Wecoprod\AtprotoOAuthBundle\OAuth\ServerMetadataResolver;
use Wecoprod\AtprotoOAuthBundle\OAuth\SessionManager;
use Wecoprod\AtprotoOAuthBundle\Storage\CacheStateStore;
use Wecoprod\AtprotoOAuthBundle\Storage\SessionStoreInterface;
use Wecoprod\AtprotoOAuthBundle\Storage\StateStoreInterface;
use Wecoprod\AtprotoOAuthBundle\Xrpc\AtprotoClient;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

final class WecoprodAtprotoOAuthBundle extends AbstractBundle
{
    protected string $extensionAlias = 'wecoprod_atproto_oauth';

    public function configure(DefinitionConfigurator $definition): void
    {
        $definition->rootNode()
            ->children()
                ->scalarNode('client_id')
                    ->info('https URL of the client metadata document (the bundle serves it at /oauth/atproto/client-metadata.json)')
                    ->isRequired()->cannotBeEmpty()
                ->end()
                ->arrayNode('redirect_uris')
                    ->info('Absolute callback URLs; the first one is the default')
                    ->isRequired()->requiresAtLeastOneElement()
                    ->scalarPrototype()->end()
                ->end()
                ->scalarNode('private_key')
                    ->info('P-256 private key, PEM or base64-encoded PEM (bin/console atproto-oauth:generate-key)')
                    ->isRequired()->cannotBeEmpty()
                ->end()
                ->scalarNode('key_id')->defaultNull()->info('Defaults to the RFC 7638 thumbprint of the key')->end()
                ->scalarNode('jwks_uri')->defaultNull()->info('Defaults to jwks.json next to the client_id')->end()
                ->scalarNode('scope')->defaultValue('atproto transition:generic')->end()
                ->scalarNode('default_authorization_server')->defaultValue('https://bsky.social')->end()
                ->scalarNode('client_name')->defaultNull()->end()
                ->scalarNode('client_uri')->defaultNull()->end()
                ->scalarNode('logo_uri')->defaultNull()->end()
                ->scalarNode('tos_uri')->defaultNull()->end()
                ->scalarNode('policy_uri')->defaultNull()->end()
                ->scalarNode('plc_directory_url')->defaultValue('https://plc.directory')->end()
                ->scalarNode('http_client')->defaultValue('http_client')->info('Service id of the HttpClient')->end()
                ->booleanNode('allow_private_networks')
                    ->info('Handles, DIDs and PDS URLs come from users: requests to private networks are blocked unless enabled (tests, local PDS)')
                    ->defaultFalse()
                ->end()
                ->scalarNode('state_cache')->defaultValue('cache.app')->info('PSR-6 pool for the authorization states')->end()
                ->integerNode('state_ttl')->defaultValue(600)->min(60)->end()
                ->scalarNode('session_store')
                    ->info('Service id implementing SessionStoreInterface; required for OAuthClient, SessionManager and AtprotoClient')
                    ->defaultNull()
                ->end()
                ->scalarNode('lock_factory')
                    ->info('Service id of a Symfony LockFactory; defaults to "lock.factory" when symfony/lock is installed, false to disable')
                    ->defaultNull()
                ->end()
            ->end();
    }

    /**
     * @param array<string, mixed> $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $services = $container->services();
        $prefix = 'wecoprod_atproto_oauth.';

        $services->set($prefix.'client_key', EcKey::class)
            ->factory([EcKey::class, 'fromPem'])
            ->args([$config['private_key']]);

        $services->set(ClientConfiguration::class)
            ->args([
                '$clientId' => $config['client_id'],
                '$redirectUris' => array_values($config['redirect_uris']),
                '$clientKey' => service($prefix.'client_key'),
                '$scope' => $config['scope'],
                '$jwksUri' => $config['jwks_uri'],
                '$keyId' => $config['key_id'],
                '$defaultAuthorizationServer' => $config['default_authorization_server'],
                '$clientName' => $config['client_name'],
                '$clientUri' => $config['client_uri'],
                '$logoUri' => $config['logo_uri'],
                '$tosUri' => $config['tos_uri'],
                '$policyUri' => $config['policy_uri'],
            ]);

        if ($config['allow_private_networks']) {
            $services->alias($prefix.'http_client', $config['http_client']);
        } else {
            $services->set($prefix.'http_client', NoPrivateNetworkHttpClient::class)
                ->args([service($config['http_client'])]);
        }

        $services->set(NativeDnsResolver::class);
        $services->alias(DnsResolverInterface::class, NativeDnsResolver::class);

        $services->set(IdentityResolver::class)
            ->args([service($prefix.'http_client'), service(DnsResolverInterface::class), $config['plc_directory_url']]);
        $services->set(ServerMetadataResolver::class)->args([service($prefix.'http_client')]);
        $services->set(DpopTransport::class)->args([service($prefix.'http_client')]);

        $services->set(CacheStateStore::class)->args([service($config['state_cache']), $config['state_ttl']]);
        $services->alias(StateStoreInterface::class, CacheStateStore::class);

        $services->set($prefix.'controller.client_metadata', ClientMetadataController::class)
            ->args([service(ClientConfiguration::class)])
            ->public()
            ->tag('controller.service_arguments');

        if (class_exists(Command::class)) {
            $services->set(GenerateKeyCommand::class)->tag('console.command');
        }

        if ($config['session_store'] === null) {
            return;
        }

        $services->alias(SessionStoreInterface::class, $config['session_store']);

        $services->set(OAuthClient::class)
            ->args([
                service(ClientConfiguration::class),
                service(IdentityResolver::class),
                service(ServerMetadataResolver::class),
                service(DpopTransport::class),
                service(StateStoreInterface::class),
                service(SessionStoreInterface::class),
            ])
            ->public();

        $lockFactory = $config['lock_factory'];
        $lockArgument = null;
        if ($lockFactory === null && class_exists(LockFactory::class)) {
            $lockArgument = service('lock.factory')->nullOnInvalid();
        } elseif (\is_string($lockFactory) && $lockFactory !== 'false') {
            $lockArgument = service($lockFactory);
        }

        $services->set(SessionManager::class)
            ->args([
                service(OAuthClient::class),
                service(SessionStoreInterface::class),
                $lockArgument,
                service('logger')->nullOnInvalid(),
            ])
            ->public();

        $services->set(AtprotoClient::class)
            ->args([service(SessionManager::class), service(DpopTransport::class)])
            ->public();
    }
}
