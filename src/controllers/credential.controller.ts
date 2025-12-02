import { Body, Controller, Post } from '@nestjs/common';
import { EBSIDID } from '../interfaces/ebsi_did';
import { decodeJwt, importJWK, SignJWT } from 'jose';

/**
 * The credential controller is used solely for handling the issuance of Verifiable Credentials by communicating with the issuer's
 * issuance server and retrieving a new credential. It handles the normal issuance flow and the deferred issuance flow, while
 * correctly handling and dragging the request's state throughout the issuance process.
 */
@Controller('credentials')
export class CredentialController {
  /**
   * Allows the issuance of a Verifiable Credential. This endpoint will communicate with the issuer's issuance server by
   * providing it with a JWT of type openid4vci-proof+jwt containing the accepted credential types, the format (always jwt_vc),
   * and the proof, containing the proof_type jwt and the proof jwt. This jwt MAY be previously provided by the ID token
   * endpoint or have to be manually defined by our endpoint. If the flow isn't expected to be a deferred flow, the endpoint
   * will return the issued credential and the process will end. Otherwise, it will return an acceptance token. Given that token,
   * the API will wait a defined amount of time before requesting the credential from the deferred endpoint by providing it with
   * the prior returned acceptance token.
   *
   * @todo The deferred flow MUST be handled differently. It works for the conformance tests, but not for all cases.
   *
   * @param {object} body - The request body containing the parameters for credential issuance.
   * @param {string} body.accessToken - The access token required for bearer authorization with the issuance server.
   * @param {string[]} body.types - Credential types that the issuance server should accept. This array will always include
   * VerifiableCredential and VerifiableAttestation, plus the specific type accepted by the issuer.
   * @param {string} body.jwt - A pre-existing JWT (if available) returned by the ID token endpoint, used as proof to substitute
   * the manually constructed JWT proof payload.
   * @param {string} body.issuerEndpoint - URL of the issuer endpoint.
   * @param {string} body.credentialEndpoint - URL of the credential issuance endpoint.
   * @param {string} body.deferredEndpoint - URL of the deferred credential issuance endpoint.
   * @param {EBSIDID} body.did - Decentralized Identifier (DID) object containing key information about the holder.
   * @param {string} [body.state] - Optional state value for issuance. If it's provided, it MUST NOT be ignored, and MUST be sent
   * through the required endpoints.
   * @param {boolean} [body.deferred=false] - Whether to issue credentials in deferred mode.
   * @return {Promise<object>} Returns a Promise resolving to the issued credential(s) or deferred result.
   * @throws Will throw an error if issuance or fetching fails at any step.
   */
  @Post('')
  async issueCredentials(@Body() body: any): Promise<object> {
    const {
      accessToken,
      types,
      jwt,
      issuerEndpoint,
      credentialEndpoint,
      deferredEndpoint,
      did,
      state,
      deferred = false,
    }: {
      accessToken: string;
      types: string[];
      jwt: string;
      issuerEndpoint: string;
      credentialEndpoint: string;
      deferredEndpoint: string;
      did: EBSIDID;
      state?: string;
      deferred?: boolean;
    } = body;

    let jwtPayload: any;

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

    const accessTokenPayload: any = decodeJwt(accessToken);

    const c_nonce = accessTokenPayload.claims
      ? accessTokenPayload.claims.c_nonce
      : accessTokenPayload.nonce;

    if (!c_nonce) {
      throw new Error('No nonce found in access token!');
    }

    if (!jwt) {
      jwtPayload = {
        header: {
          typ: 'openid4vci-proof+jwt',
          kid: `${did.did}#${did.did.slice(8)}`,
        },
        trustedFramework: 'ebsi',
        payload: {
          iat: Math.floor(Date.now() / 1000),
          iss: did.did,
          aud: issuerEndpoint,
          exp: Math.floor(Date.now() / 1000) + 300,
          nonce: c_nonce,
        },
        iat: Math.floor(Date.now() / 1000),
        iss: did.did,
        aud: issuerEndpoint,
        exp: Math.floor(Date.now() / 1000) + 300,
        nonce: c_nonce,
        privateKey: did.privateKey,
      };
    } else {
      jwtPayload = {
        ...decodeJwt(jwt),
        nonce: c_nonce,
      };
    }

    const updatedJwt = await new SignJWT({
      ...jwtPayload,
      nonce: c_nonce,
    })
      .setProtectedHeader({
        alg: 'ES256',
        typ: 'openid4vci-proof+jwt',
        kid: `${did.did}#${did.did.slice(8)}`,
      })
      .setIssuedAt()
      .setExpirationTime('5m')
      .setAudience(issuerEndpoint)
      .setIssuer(jwt ? jwtPayload.aud : jwtPayload.iss)
      .setSubject(jwtPayload.sub)
      .sign(privateKey);

    const credentialsRes = await fetch(credentialEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify({
        types,
        format: 'jwt_vc',
        proof: {
          proof_type: 'jwt',
          jwt: updatedJwt,
        },
        state,
      }),
    });

    if (!credentialsRes.ok) {
      throw new Error('Unable to issue a credential!');
    }

    if (!deferred) {
      return await credentialsRes.json();
    }

    const acceptanceToken = await credentialsRes.json();

    await new Promise((resolve) => setTimeout(resolve, 5000));

    const deferredCredentialsRes = await fetch(deferredEndpoint, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${acceptanceToken.acceptance_token}`,
        Accept: '*/*',
      },
    });

    if (!deferredCredentialsRes.ok) {
      throw new Error('Unable to issue a deferred credential!');
    }

    return await deferredCredentialsRes.json();
  }
}
