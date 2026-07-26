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

use DomainException;
use Generator;
use fyrkat\openssl\PKCS12;
use letswifi\configuration\ConfigurationException;
use letswifi\profile\Realm;

/**
 * @extends CredentialLog<PKCS12>
 *
 * @psalm-type statistics = array{first_issued:?\DateTimeImmutable,last_issued:?\DateTimeImmutable,first_expires:?\DateTimeImmutable,last_expires:?\DateTimeImmutable,count:int,...}
 *
 * @internal
 *
 * A simplified CredentialLog that exists only to be a factory for our
 * StepCredentialIssuer.  Other methods are not implemented at this
 * time.
 */
class StepCredentialLog extends CredentialLog
{
	/**
	 * @param string $client Client ID to filter, all clients if null
	 *
	 * @return Generator<CertificateCredential>
	 */
	public function listCredentials( ?Realm $realm = null, ?string $client = null ): Generator
	{
	  if (false) {
	    // function not implemented; return empty Generator
	    yield;
	  }
	}

	public function getCredential( string $credentialId, ?Realm $realm = null, ?string $client = null ): CertificateCredential
	{
	  throw new DomainException( 'Method not implemented' );
	}

	public function revokeCredential( string $credentialId ): void
	{
	  throw new DomainException( 'Method not implemented' );
	}

	public function getCredentialAdministrator(): CredentialAdmin
	{
	  throw new DomainException( 'Method not implemented' );
	}

	protected function createCredentialIssuer( Realm $realm ): StepCredentialIssuer
	{
		return new StepCredentialIssuer(
			user: $this->user,
			realm: $realm,
			now: $this->now,
			profileService: $this->profileService,
			revoke: fn( string $ident ) => $this->revokeCredential( $ident ),
		);
	}

}
