import { Controller, Get } from '@nestjs/common';
import { exportJWK, generateKeyPair } from 'jose';
import { EbsiWallet } from '@cef-ebsi/wallet-lib';
import { JsonWebKey } from 'did-resolver/lib/resolver';
import { EBSIDID } from '../interfaces/ebsi_did';

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
    const { publicKey, privateKey } = await generateKeyPair('ES256');

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
}
