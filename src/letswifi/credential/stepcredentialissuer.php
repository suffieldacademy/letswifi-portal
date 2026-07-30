<?php declare( strict_types=1 );

/*
 * This file is part of letswifi; a system for easy 802.1x device enrollment
 *
 * Copyright: Jørn Åne de Jong <jorn.dejong@letswifi.eu>
 * Copyright: Paul Dekkers, SURF <paul.dekkers@surf.nl>
 * Copyright: Jason Healy, Suffield Academy <jhealy@suffieldacademy.org>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace letswifi\credential;

use letswifi\credential\CredentialIssuer;
use letswifi\auth\User;
use letswifi\profile\Realm;
use DateTimeImmutable;
use RuntimeException;
use letswifi\profile\ProfileService;
use fyrkat\openssl\X509;
use fyrkat\openssl\PrivateKey;
use fyrkat\openssl\PKCS12;


/**
 * @implements CredentialIssuer<PKCS12>
 *
 * @internal
 *
 * This class is based off the default CertificateCredentialIssuer
 * class.  Instead of generating and signing certs on its own, it
 * sends a CSR to step-ca for signing.
 *
 * There are some important differences from CertificateCredentialIssuer:
 *
 * - The "ident" field is null.  We'll rely on step-ca to generate all
 *   certificate details.
 *
 * - No database logging takes place.  We assume that step-ca will log
 *   the certificate details for us.
 *
 * - The built-in crypto chain is NOT used.  Instead, we rely directly
 *   on the configured step-ca intermediate and root certificates and
 *   include those in the PKCS12 bundle.
 */
class StepCredentialIssuer implements CredentialIssuer
{

	/** @param Closure(string):void $revoke */
	public function __construct(
		public readonly User $user,
		public readonly Realm $realm,
		public readonly DateTimeImmutable $now,
		private readonly ProfileService $profileService,
		private readonly \Closure $revoke,
	) {
	}

	public function issue(): CertificateCredential
	{
	  $pkcs12 = $this->generateClientCertificate($this->user->attributes);

		return new CertificateCredential(
			credentialId: 'anonymous',
			userId: $this->user->userId,
			clientId: $this->user->clientId,
			grantSid: $this->user->grantSid,
			ip: $this->user->ip,
			userAgent: $this->user->userAgent,
			realm: $this->realm,
			pkcs12: $pkcs12,
		);
	}

	/*
	 * Given an array of user attributes (claims), issue a
	 * certificate using step-ca
	 */
	private function generateClientCertificate(array $claims): PKCS12
	{
	    $tmpDir = sys_get_temp_dir() . '/letswifi-step-'
	      . bin2hex(random_bytes(8));

	    mkdir($tmpDir, 0700, true);

	    $rootCert = new X509
	      (
	       'file:///etc/step-cli/certs/root_ca.crt'
	       );

	    $intermediateCert = new X509
	      (
	       'file:///etc/step-cli/certs/intermediate_ca.crt'
	       );
  
	    try {

	      $crtFile  = $tmpDir . '/user.crt';
	      $keyFile = $tmpDir . '/user.key';

	      $argv = [
		       'step',
		       'ca',
		       'certificate',
		       'letswifi',
		       $crtFile,
		       $keyFile,
		       '--provisioner=byod',
		       '--provisioner-password-file=/etc/step-cli/secrets/password-provisioner-byod.txt',
		       '--console',
		       ];

	      // letswifi doesn't have access to as many user details
	      // as MDM, so synthesize some information as a placeholder
	      $argv[] = '--san=urn:sa:product:letswifi';

	      // convert claims to san attributes
	      foreach ($claims as $key => $value) {
		if (str_starts_with($key, 'urn:sa:')) {
		  // claims are always returned as an array;
		  // only take first item
		  $argv[] = '--san=' . $key . ':' . $value[0];
		}
	      }

	      $descriptors = [
			      0 => ['file', '/dev/null', 'r'],
			      1 => ['pipe', 'w'],
			      2 => ['pipe', 'w'],
			      ];

	      $pipes = []; // proc_open will populate

	      $process = proc_open(
				   $argv,
				   $descriptors,
				   $pipes,
				   $tmpDir,
				   [
				    'STEPPATH' => '/etc/step-cli',
				    ],
				   );

	      if (!is_resource($process)) {
		throw new RuntimeException('Unable to start step');
	      }

	      $stdout = stream_get_contents($pipes[1]);
	      $stderr = stream_get_contents($pipes[2]);

	      fclose($pipes[1]);
	      fclose($pipes[2]);

	      $exitCode = proc_close($process);

	      if ($exitCode !== 0) {
		throw new RuntimeException(
					   'Step failed: '
					   . implode(' ', $argv)
					   . ': ' . $stderr
					   );
	      }

	      $leafPem = file_get_contents($crtFile);

	      if (!preg_match(
			      '/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/s',
			      $leafPem,
			      $matches
			      )) {
		throw new RuntimeException('No certificate found');
	      }

	      $userCert = new X509($matches[0]);

	      $userKey = new PrivateKey('file://' . $keyFile);

	      return new PKCS12(
				$userCert,
				$userKey,
				[$intermediateCert, $rootCert]
				);
	      
	    } finally {

		@unlink($keyFile ?? '');
		@unlink($crtFile ?? '');
		@rmdir($tmpDir);
	    }
	}

}
