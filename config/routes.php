<?php

declare(strict_types=1);

use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

return static function (RoutingConfigurator $routes): void {
    $routes->add('wecoprod_atproto_oauth_client_metadata', '/oauth/atproto/client-metadata.json')
        ->controller('wecoprod_atproto_oauth.controller.client_metadata::metadata')
        ->methods(['GET', 'HEAD']);

    $routes->add('wecoprod_atproto_oauth_jwks', '/oauth/atproto/jwks.json')
        ->controller('wecoprod_atproto_oauth.controller.client_metadata::jwks')
        ->methods(['GET', 'HEAD']);
};
