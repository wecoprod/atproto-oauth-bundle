<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Wecoprod\AtprotoOAuthBundle\Crypto\EcKey;

#[AsCommand(name: 'atproto-oauth:generate-key', description: 'Generates the P-256 private key of the OAuth client (keep it secret)')]
final class GenerateKeyCommand extends Command
{
    protected function configure(): void
    {
        $this->addOption('base64', null, InputOption::VALUE_NONE, 'Print the PEM base64-encoded on one line, for an environment variable');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $key = EcKey::generate();
        $pem = $key->toPem();

        $output->writeln($input->getOption('base64') ? base64_encode($pem) : rtrim($pem));
        $output->writeln(\sprintf('<comment>Key id (thumbprint): %s</comment>', $key->thumbprint()), OutputInterface::VERBOSITY_VERBOSE);

        return Command::SUCCESS;
    }
}
