import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Post,
} from '@nestjs/common';
import { EbsiWallet } from '@cef-ebsi/wallet-lib';
import { JsonWebKey } from 'did-resolver/lib/resolver';
import { EBSIDID, EBSIDIDWithSeed } from '../interfaces/ebsi_did';
import {
  createVerifiableCredentialJwt,
  EbsiIssuer,
  EbsiVerifiableAttestation,
} from '@cef-ebsi/verifiable-credential';
import { ES256Signer } from 'did-jwt';
import { config } from 'src/environment/issuers';
import BIP32Factory from 'bip32';
import * as ecc from 'tiny-secp256k1';
import * as bip39 from 'bip39';

/**
 * This endpoint handles holder DID operations.
 */
@Controller('holder')
export class HolderController {
  private bip32;
  constructor() {
    this.bip32 = BIP32Factory(ecc);
  }

  /**
   * Generates a new EBSI DID with BIP-39 mnemonic seed using hierarchical deterministic derivation.
   * This endpoint creates a random 128-bit entropy mnemonic, derives an ES256 key pair using BIP-32/BIP-44
   * path m/44'/0'/0'/0/0, constructs public/private JWK from P-256 coordinates, and creates an EBSI DID
   * for a NATURAL_PERSON. Returns the complete DID package including mnemonic seed and key material.
   *
   * @return {Promise<EBSIDIDWithSeed>} A Promise that resolves to an object containing the newly generated
   * EBSI DID, BIP-39 mnemonic seed, private key (d parameter), and public key coordinates (x, y).
   * Throws Error if public key derivation or JWK construction fails.
   */

  @Get('get_new_did')
  async getNewDid(): Promise<EBSIDIDWithSeed> {
    const mnemonic = bip39.generateMnemonic(128);

    const seed = await bip39.mnemonicToSeed(mnemonic);
    const root = this.bip32.fromSeed(seed);
    const path = "m/44'/0'/0'/0/0";
    const child = root.derivePath(path);
    const privKeyBytes = child.privateKey!;

    const publicKeyBytes = ecc.pointFromScalar(privKeyBytes, false);

    if (!publicKeyBytes) {
      throw new Error('Failed to derive public key');
    }

    const x = publicKeyBytes.slice(1, 33);
    const y = publicKeyBytes.slice(33, 65);

    const publicJwk: JsonWebKey = {
      kty: 'EC',
      crv: 'P-256',
      x: this.uint8ToBase64url(x),
      y: this.uint8ToBase64url(y),
      key_ops: ['verify'],
      ext: true,
      alg: 'ES256',
    };

    const privateJwk: JsonWebKey = {
      ...publicJwk,
      d: this.uint8ToBase64url(privKeyBytes),
      key_ops: ['sign'],
    };

    if (!privateJwk.d || !publicJwk.x || !publicJwk.y) {
      throw new Error('Invalid JWK');
    }

    const ebsiDid = EbsiWallet.createDid('NATURAL_PERSON', publicJwk);

    return {
      did: ebsiDid,
      seed: mnemonic,
      privateKey: privateJwk.d,
      x: publicJwk.x!,
      y: publicJwk.y!,
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

  /**
   * Recovers an EBSI DID from a BIP-39 mnemonic seed phrase using hierarchical deterministic derivation.
   * This endpoint derives an ES256 key pair from the mnemonic using BIP-32/BIP-44 path m/44'/0'/0'/0/0,
   * validates the mnemonic, generates a public/private key pair, and creates an EBSI DID for a
   * NATURAL_PERSON. Returns the DID, seed mnemonic, private key parameter, and public key coordinates.
   *
   * @param body - Request body containing the BIP-39 mnemonic seed phrase.
   * @return {Promise<EBSIDIDWithSeed>} A Promise that resolves to an object containing the recovered
   * EBSI DID, original mnemonic seed, private key (d parameter), and public key coordinates (x, y).
   * Throws BadRequestException for invalid mnemonics or Error for public key derivation failures.
   */

  @Post('recover_did_from_seed')
  async recoverDidFromSeed(
    @Body() body: { mnemonic: string },
  ): Promise<EBSIDIDWithSeed> {
    const { mnemonic } = body;

    if (!bip39.validateMnemonic(mnemonic)) {
      throw new BadRequestException('Invalid mnemonic');
    }

    const seed = await bip39.mnemonicToSeed(mnemonic);
    const root = this.bip32.fromSeed(seed);
    const path = "m/44'/0'/0'/0/0";
    const child = root.derivePath(path);
    const privKeyBytes = child.privateKey!;

    const publicKeyBytes = ecc.pointFromScalar(privKeyBytes, false);
    if (!publicKeyBytes) {
      throw new Error('Failed to derive public key');
    }

    const x = publicKeyBytes.slice(1, 33);
    const y = publicKeyBytes.slice(33, 65);

    const publicJwk: JsonWebKey = {
      kty: 'EC',
      crv: 'P-256',
      x: this.uint8ToBase64url(x),
      y: this.uint8ToBase64url(y),
      key_ops: ['verify'],
      ext: true,
      alg: 'ES256',
    };

    const privateJwk: JsonWebKey = {
      ...publicJwk,
      d: this.uint8ToBase64url(privKeyBytes),
      key_ops: ['sign'],
    };

    const ebsiDid = EbsiWallet.createDid('NATURAL_PERSON', publicJwk);

    return {
      did: ebsiDid,
      seed: mnemonic,
      privateKey: privateJwk.d!,
      x: publicJwk.x!,
      y: publicJwk.y!,
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

  private uint8ToBase64url(bytes: Uint8Array): string {
    let binary = '';
    bytes.forEach((b) => (binary += String.fromCharCode(b)));
    return btoa(binary)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }
}
