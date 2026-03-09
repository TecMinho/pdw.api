import { Body, Controller, Get, Post } from '@nestjs/common';
import { exportJWK, generateKeyPair } from 'jose';
import { EbsiWallet } from '@cef-ebsi/wallet-lib';
import { JsonWebKey } from 'did-resolver/lib/resolver';
import { EBSIDID } from '../interfaces/ebsi_did';
import {
  createVerifiableCredentialJwt,
  EbsiIssuer,
  EbsiVerifiableAttestation,
} from '@cef-ebsi/verifiable-credential';
import { ES256Signer } from 'did-jwt';
import { config } from 'src/environment/issuers';

/**
 * This endpoint handles holder DID operations.
 */
@Controller('holder')
export class HolderController {
  constructor() {}

  /**
   * Generates a new Decentralized Identifier (DID) using a key pair.
   * This method creates a new DID suitable for use in EBSI (European Blockchain Services Infrastructure),
   * using elliptic curve cryptography (ES256) for generating the key pair. It will use EBSI's DID creation library to
   * generate a did:key:jwk_jcs-pub identifier.
   *
   * @return {Promise<EBSIDID>} A Promise that resolves to an object containing the generated DID,
   * the private key, and public key parameters (x, y) in JWK (JSON Web Key) format.
   * Throws an error if the JWK does not contain required fields.
   */
  @Get('get_new_did')
  async getNewDid(): Promise<EBSIDID> {
    const { publicKey, privateKey } = await generateKeyPair('ES256', {
      extractable: true,
    });

    const publicJwk = await exportJWK(publicKey);
    const privateJwk = await exportJWK(privateKey);

    if (!privateJwk.d || !publicJwk.x || !publicJwk.y) {
      throw new Error('Invalid JWK');
    }

    const ebsiDid = EbsiWallet.createDid(
      'NATURAL_PERSON',
      publicJwk as JsonWebKey,
    );

    return {
      did: ebsiDid,
      privateKey: privateJwk.d,
      x: publicJwk.x,
      y: publicJwk.y,
    };
  }

  @Post('get_did_credential')
  async getDidCredential(@Body() body: any): Promise<any> {
    const {
      did,
    }: {
      did: EBSIDID;
    } = body;
    const now = Math.floor(Date.now() / 1000);
    const expirySeconds = 60 * 60 * 24 * 365; // seconds in 1 year
    const issuedAtIso = new Date(now * 1000).toISOString();
    const validUntilIso = new Date((now + expirySeconds) * 1000).toISOString();
    const schemaId =
      'https://api-conformance.ebsi.eu/trusted-schemas-registry/v3/schemas/zDpWGUBenmqXzurskry9Nsk6vq2R8thh9VSeoRqguoyMD';

    const credentialPayload: EbsiVerifiableAttestation = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      id: `urn:uuid:${this.generateUuid()}`,
      type: ['VerifiableCredential', 'VerifiableAttestation', 'DidAttestation'],
      issuer: did.did,
      issuanceDate: issuedAtIso,
      issued: issuedAtIso,
      validFrom: issuedAtIso,
      validUntil: validUntilIso,
      expirationDate: validUntilIso,
      credentialSubject: {
        id: did.did,
        did: did.did,
      },
      credentialSchema: {
        id: schemaId,
        type: 'FullJsonSchemaValidator2021',
      },
    };

    const issuerKid = `${did.did}#${did.did.split(':').slice(-1)[0]}`;
    const privateKeyBytes = this.base64UrlToBytes(did.privateKey);
    const signer = ES256Signer(privateKeyBytes);

    const ebsiIssuer: EbsiIssuer = {
      did: did.did,
      kid: issuerKid,
      alg: 'ES256',
      signer,
    };

    const credential = await createVerifiableCredentialJwt(
      credentialPayload,
      ebsiIssuer,
      config,
      {
        skipAccreditationsValidation: true,
        skipCredentialSubjectValidation: true,
        skipValidation: true,
        skipStatusValidation: true,
      },
    );

    return {
      credential,
      format: 'jwt_vc',
    };
  }

  private generateUuid(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (char) => {
      const rand = (Math.random() * 16) | 0;
      const value = char === 'x' ? rand : (rand & 0x3) | 0x8;
      return value.toString(16);
    });
  }
  private base64UrlToBytes(value: string): Uint8Array {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
    return Uint8Array.from(Buffer.from(padded, 'base64'));
  }
}
