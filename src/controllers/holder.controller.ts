import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Post,
} from '@nestjs/common';
import { EbsiWallet } from '@cef-ebsi/wallet-lib';
import { JsonWebKey } from 'did-resolver/lib/resolver';
import {
  createVerifiableCredentialJwt,
  EbsiIssuer,
  EbsiVerifiableAttestation,
} from '@cef-ebsi/verifiable-credential';
import { ES256Signer } from 'did-jwt';
import { config } from 'src/environment/issuers';
import * as bip39 from 'bip39';
import { createHash, randomUUID } from 'crypto';
import { p256 } from '@noble/curves/nist.js';
import { EBSIDID, EBSIDIDWithSeed } from '../interfaces/ebsi_did';

@Controller('holder')
export class HolderController {
  /**
   * Generates a new EBSI DID where the mnemonic is the real recovery source.
   * The private/public P-256 keypair is deterministically derived from the mnemonic.
   */
  @Get('get_new_did')
  async getNewDid(): Promise<EBSIDIDWithSeed> {
    const mnemonic = bip39.generateMnemonic(128);

    const { x, y, d } = this.deriveP256JwkFromMnemonic(mnemonic);

    const publicJwk: JsonWebKey = {
      kty: 'EC',
      crv: 'P-256',
      x,
      y,
      key_ops: ['verify'],
    };

    const ebsiDid = EbsiWallet.createDid('NATURAL_PERSON', publicJwk);

    return {
      did: ebsiDid,
      seed: mnemonic,
      privateKey: d,
      x,
      y,
    };
  }

  /**
   * Recovers an EBSI DID from a BIP-39 mnemonic.
   * Because the key pair is deterministically derived from the mnemonic, the resulting
   * DID is always the same for the same mnemonic phrase.
   *
   * @param body - Request payload containing a `mnemonic` string.
   * @returns A DID payload with the recovered `did`, original `seed` (mnemonic),
   * derived `privateKey`, and public key coordinates (`x`, `y`).
   * @throws {BadRequestException} When `mnemonic` is missing or not a valid BIP-39 phrase.
   */
  @Post('recover_did_from_seed')
  async recoverDidFromSeed(
    @Body() body: { mnemonic: string },
  ): Promise<EBSIDIDWithSeed> {
    if (!body?.mnemonic || !bip39.validateMnemonic(body.mnemonic)) {
      throw new BadRequestException('Invalid mnemonic');
    }

    const { x, y, d } = this.deriveP256JwkFromMnemonic(body.mnemonic);

    const publicJwk: JsonWebKey = {
      kty: 'EC',
      crv: 'P-256',
      x,
      y,
      key_ops: ['verify'],
    };

    const ebsiDid = EbsiWallet.createDid('NATURAL_PERSON', publicJwk);

    return {
      did: ebsiDid,
      seed: body.mnemonic,
      privateKey: d,
      x,
      y,
    };
  }

  /**
   * Generates and returns a Verifiable Attestation credential for a given DID using EBSI standards.
   * This endpoint creates a self-attested DidAttestation credential with a 1-year validity period,
   * using the specified EBSI schema and ES256 signature algorithm. The credential is issued by the
   * provided DID and signed with its associated private key.
   *
   * @param body - Request body containing the DID object with `did` and `privateKey` properties.
   * @return {Promise<any>} A Promise that resolves to an object containing the signed JWT credential
   * and format specification (`jwt_vc`). Uses the EBSI trusted schemas registry schema for validation.
   */
  @Post('get_did_credential')
  async getDidCredential(@Body() body: any): Promise<any> {
    const { did }: { did: EBSIDID } = body;

    const now = Math.floor(Date.now() / 1000);
    const expirySeconds = 60 * 60 * 24 * 365;

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

  /**
   * Deterministically derives a valid P-256 private/public JWK from a mnemonic.
   * Same mnemonic => same d, x, y => same DID.
   */
  private deriveP256JwkFromMnemonic(mnemonic: string): {
    d: string;
    x: string;
    y: string;
  } {
    const seed = bip39.mnemonicToSeedSync(mnemonic);

    let candidate = createHash('sha256').update(seed).digest();

    while (!p256.utils.isValidSecretKey(candidate)) {
      candidate = createHash('sha256').update(candidate).digest();
    }

    const privateKeyBytes = new Uint8Array(candidate);

    const publicKey = p256.getPublicKey(privateKeyBytes, false);
    const xBytes = publicKey.slice(1, 33);
    const yBytes = publicKey.slice(33, 65);

    return {
      d: Buffer.from(privateKeyBytes).toString('base64url'),
      x: Buffer.from(xBytes).toString('base64url'),
      y: Buffer.from(yBytes).toString('base64url'),
    };
  }

  private generateUuid(): string {
    return randomUUID();
  }

  private base64UrlToBytes(value: string): Uint8Array {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
    return Uint8Array.from(Buffer.from(padded, 'base64'));
  }
}
