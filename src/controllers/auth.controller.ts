import { Body, Controller, Post } from '@nestjs/common';
import { EBSIDID } from '../interfaces/ebsi_did';
import { decodeJwt, importJWK, SignJWT } from 'jose';

/**
 * The authentication controller is responsible for handling the OpenID compliant authorization requests.
 */
@Controller('auth')
export class AuthController {
  /**
   * Handles the OpenID compliant authorization process. This endpoint will sign an ID token and get a code from
   * the issuer's authorization server. This endpoint manually handles redirects, and, through the request location,
   * gets the returned code.
   *
   * @param {Object} body The request body containing the required parameters.
   * @param {string} body.url The URL to send the POST request to retrieve the authorization code.
   * @param {any} body.idToken The ID token to be re-signed and sent to the authorization server.
   * @param {string} body.authorizationUrl The URL of the authorization server. This endpoint MUST be the ID token's JWT's audience.
   * @param {EBSIDID} body.did The holder's DID (Decentralized Identifier) object containing keys and metadata for signing.
   * @return {Promise<string>} A promise that resolves to the retrieved authorization code.
   * @throws {Error} If the authorization code or redirection location cannot be fetched.
   */
  @Post('authorize')
  async getAuthorizationCode(@Body() body: any): Promise<string> {
    const {
      url,
      idToken,
      authorizationUrl,
      did,
    }: { url: string; idToken: any; authorizationUrl: string; did: EBSIDID } =
      body;
    const decoded: any = decodeJwt(idToken);

    const privateKey = await importJWK(
      {
        crv: 'P-256',
        kty: 'EC',
        x: did.x,
        y: did.y,
        d: did.privateKey,
        alg: 'ES256',
        kid: `${did.did}#${did.did.slice(8)}`,
      },
      'ES256',
    );

    const state = decoded.state;

    const updatedJwt = await new SignJWT({
      iss: did.did,
      sub: did.did,
      exp: Number(decoded.iat ?? Date.now() / 1000) + 600,
      iat: decoded.iat,
      nonce: decoded.nonce,
    })
      .setProtectedHeader({
        alg: 'ES256',
        typ: 'JWT',
        kid: `${did.did}#${did.did.slice(8)}`,
      })
      .setAudience(authorizationUrl)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);

    const formData = new URLSearchParams({
      id_token: updatedJwt,
      state,
    });

    const idTokenRes = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: '*/*',
      },
      body: formData,
      redirect: 'manual',
    });

    if (idTokenRes.status !== 302) {
      throw new Error('Unable to fetch authorization code!');
    }

    const location = idTokenRes.headers.get('location');

    if (!location) {
      throw new Error(
        'Unable to fetch authorization code location on redirect!',
      );
    }

    const authorizationCode = new URL(location).searchParams.get('code');

    if (!authorizationCode) {
      throw new Error('Unable to fetch authorization code from redirect!');
    }

    return authorizationCode;
  }
}
