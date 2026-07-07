import { Body, Controller, Post } from '@nestjs/common';
import { EBSIDID } from '../interfaces/ebsi_did';
import { decodeJwt, importJWK, SignJWT } from 'jose';
import { randomUUID } from 'crypto';
import { base64ToBytes, ES256Signer } from 'did-jwt';
import type { EbsiIssuer } from '@cef-ebsi/verifiable-credential';
import {
  createVerifiablePresentationJwt,
  CreateVerifiablePresentationJwtOptions,
  EbsiVerifiablePresentation,
} from '@cef-ebsi/verifiable-presentation';
import { config } from '../environment/issuers';
import axios from 'axios';
import { VerifierService } from '../services/verifier.service';
import { createHash, createPublicKey } from 'crypto';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import type { PresentationFrame, Verifier } from '@sd-jwt/core';

function buildSdJwtPresentationFrame(
  selectedFields: string[],
): PresentationFrame<Record<string, unknown>> {
  const frame: Record<string, any> = {};

  for (const field of selectedFields) {
    const parts = field.split('.');

    if (parts[0] === 'achieved') {
      frame.achieved ??= {};
      frame.achieved['0'] = true;
      continue;
    }

    let current = frame;
    for (let index = 0; index < parts.length; index += 1) {
      const part = parts[index];

      if (index === parts.length - 1) {
        current[part] = true;
      } else {
        current[part] ??= {};
        current = current[part];
      }
    }
  }

  return frame;
}
/**
 * Handles the OpenID compliant verification process of a Verifiable Credential.
 */
@Controller('verifier')
export class VerifierController {
  constructor(private readonly verifierService: VerifierService) {}

  /**
   * Validates that all requested fields in a Verifiable Presentation are present in the disclosed fields by the holder.
   *
   * @param {Object} body - The request payload containing the fields to validate.
   * @param {string[]} body.requestedFields - The list of requested fields by the verifier.
   * @param {string[]} body.selectedFields - The list of fields disclosed by the holder.
   * @return {Promise<boolean>} A promise that resolves to true if all requested fields are included in the selected fields, otherwise false.
   */
  @Post('validate_fields')
  async validateFields(@Body() body: any): Promise<boolean> {
    const {
      requestedFields,
      selectedFields,
    }: { requestedFields: string[]; selectedFields: string[] } = body;

    if (!requestedFields || !selectedFields) {
      return false;
    }

    return requestedFields.every((field) => selectedFields.includes(field));
  }

  /**
   * Defines a presentation submission object given a presentation definition provided by a verifier entity.
   *
   * @param {Object} body - The request body containing the presentation definition.
   * @param {string} body.presentationDefinition - The presentation definition provided by the verifier.
   * @return {Object} Returns an object containing the generated presentation details.
   * @return {string} return.id - Randomly generated unique identifier for the presentation.
   * @return {string} return.definition_id - The ID of the presentation definition.
   * @return {Array} return.descriptor_map - An array of descriptor mappings for the presentation.
   */
  @Post('define_presentation')
  async definePresentation(@Body() body: any): Promise<object> {
    const {
      presentationDefinition,
      consented,
    }: { presentationDefinition: any; consented: string[] } = body;

    const presentationDefinitionJson = JSON.parse(presentationDefinition);

    const inputDescriptors = presentationDefinitionJson.input_descriptors;
    const constraints =
      (inputDescriptors[0]?.constraints?.fields as any[]) ?? [];

    const consentedSet = new Set(consented ?? []);

    for (const constraint of constraints) {
      const constraintId = constraint?.id;

      if (!constraintId || constraintId === 'credentialType') {
        continue;
      }

      const paths: string[] = Array.isArray(constraint?.path)
        ? constraint.path
        : [];

      const isCredentialSubjectField = paths.some(
        (path) =>
          path.startsWith('$.credentialSubject.') ||
          path.startsWith('$.vc.credentialSubject.') ||
          path.startsWith('$.'),
      );

      if (!isCredentialSubjectField) {
        continue;
      }

      if (consentedSet.size > 0 && !consentedSet.has(constraintId)) {
        throw new Error(`Mandatory constraint ${constraintId} not consented.`);
      }
    }

    return {
      id: Math.random().toString(36).substring(2, 10),
      definition_id: presentationDefinitionJson.id,
      descriptor_map: inputDescriptors.map(
        (inputDescriptor: any, index: number) => {
          return {
            id: inputDescriptor.id,
            path: '$',
            format: 'jwt_vp',
            path_nested: {
              id: inputDescriptor.id,
              format: 'jwt_vc',
              path: `$.vp.verifiableCredential[${index}]`,
            },
          };
        },
      ),
    };
  }

  /**
   * Creates a Verifiable Presentation and, given that and the previously defined presentation submission, gets the
   * authorization code from the authorization server to continue the verification process. This method is only required
   * in the conformance tests. The normal OpenID flow won't use this method.
   *
   * @param {Object} body The input payload for creating the presentation.
   * @param {any} body.presentationSubmission The presentation submission object.
   * @param {any} body.credentials The verifiable credentials to be included in the presentation.
   * @param {any} body.request The presentation request JWT.
   * @param {string} body.redirectEndpoint The authorization URL to which the presentation is submitted, to retrieve an authorization code.
   * @param {EBSIDID} body.did The DID object containing identifier details and a private key for signing.
   * @return {string} Returns the authorization code retrieved from the redirect location.
   * @throws {Error} Throws an error if any required parameter is missing, if the JWT cannot be created,
   * if the redirect response status is not 302, or if the authorization code cannot be retrieved.
   */
  @Post('create_presentation')
  async createPresentation(@Body() body: any): Promise<string> {
    const {
      presentationSubmission,
      credentials,
      request,
      redirectEndpoint,
      did,
      selectedFields = [],
    }: {
      presentationSubmission: any;
      credentials: any;
      request: any;
      redirectEndpoint: string;
      did: EBSIDID;
      selectedFields?: string[];
    } = body;

    if (!credentials) {
      throw new Error('No credentials provided!');
    }

    if (!presentationSubmission) {
      throw new Error('No presentation submission provided!');
    }

    if (!request) {
      throw new Error('No request provided!');
    }

    if (!redirectEndpoint) {
      throw new Error('No redirect endpoint provided!');
    }

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

    const requestPayload: any = decodeJwt(request);

    const state = requestPayload.state;

    const uuid = `urn:uuid:${randomUUID()}`;

    const updatedJwt = await new SignJWT({
      iss: did.did,
      aud: requestPayload.iss,
      sub: did.did,
      iat: requestPayload.iat,
      nbf: requestPayload.iat,
      exp: requestPayload.exp,
      nonce: requestPayload.nonce,
      jti: uuid,
      vp: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        id: uuid,
        type: ['VerifiablePresentation'],
        holder: did.did,
        verifiableCredential: credentials,
      },
    })
      .setProtectedHeader({
        alg: 'ES256',
        typ: 'JWT',
        kid: `${did.did}#${did.did.slice(8)}`,
      })
      .sign(privateKey);

    if (!updatedJwt) {
      throw new Error('Unable to create a verifiable presentation JWT!');
    }

    const formData = new URLSearchParams({
      presentation_submission: JSON.stringify(presentationSubmission),
      vp_token: updatedJwt,
      state,
    }).toString();

    const idTokenRes = await fetch(redirectEndpoint, {
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

  /**
   * Issues a verifiable presentation based on the provided presentation offer, submissions, DID, and credentials.
   * It uses the EBSI libraries for verifiable presentations, which handle the creation, signing, and verification of the
   * Verifiable Presentation. The result of said verification is then returned.
   *
   * @param {Object} body - The input request payload containing the details needed for issuing the presentation.
   * @param {any} body.presentationOffer - The presentation offer that contains the state and redirect URI.
   * @param {any} body.presentationSubmission - The presentation submission object defined prior.
   * @param {EBSIDID} body.did - The Decentralized Identifier (DID) used as the holder for the verifiable presentation.
   * @param {any[]} body.credentials - An array of verifiable credentials to be included in the presentation.
   * @returns {Promise<boolean>} A promise that resolves to a boolean indicating whether the presentation was successfully
   * issued and verified. Returns `true` if successful, `false` otherwise.
   * @throws {Error} Throws an error if required parameters (presentationSubmission, DID, or credentials) are missing.
   */
  @Post('issue_presentation')
  async issuePresentation(@Body() body: any): Promise<boolean> {
 const {
   presentationOffer,
   presentationSubmission,
   did,
   credentials,
   selectedFields = [],
 }: {
   presentationOffer: any;
   presentationSubmission: any;
   did: EBSIDID;
   credentials: any[];
   selectedFields?: string[];
 } = body;

    if (!presentationSubmission) {
      throw new Error('No presentation submission provided!');
    }

    if (!did) {
      throw new Error('No DID provided!');
    }

    if (!credentials) {
      throw new Error('No credentials provided!');
    }

    const isClientIdVerified = await this.verifierService.verifyClientId(
      presentationOffer.client_id,
    );

    if (!isClientIdVerified) {
      throw new Error('Client ID verification failed!');
    }

    const holder = {
      did: did.did,
      kid: `${did.did}#${did.did.slice(8)}`,
      alg: 'ES256',
      signer: ES256Signer(base64ToBytes(did.privateKey)),
    } satisfies EbsiIssuer;

    const firstCredentialJwt = credentials[0]?.jwt;

    if (!firstCredentialJwt) {
      throw new Error('No credential JWT provided!');
    }

    const state = presentationOffer.state;

    const isSdJwt = firstCredentialJwt.includes('~');

    let vpToken: string;

    if (isSdJwt) {
      const hasher = async (
        data: string | ArrayBuffer,
        algorithm: string,
      ): Promise<Uint8Array> => {
        if (algorithm !== 'sha-256') {
          throw new Error(`Unsupported hash algorithm: ${algorithm}`);
        }

        const buffer =
          typeof data === 'string' ? Buffer.from(data) : Buffer.from(data);

        return Uint8Array.from(createHash('sha256').update(buffer).digest());
      };

      const verifier: Verifier = async () => true;

      const sdjwt = new SDJwtVcInstance({
        verifier,
        hasher,
        hashAlg: 'sha-256',
      });

      const presentationFrame = buildSdJwtPresentationFrame(selectedFields);

      const presentedCredential = await sdjwt.present(
        firstCredentialJwt,
        presentationFrame,
      );

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

      const now = Math.floor(Date.now() / 1000);

      vpToken = await new SignJWT({
        iss: did.did,
        aud: presentationOffer.client_id,
        sub: did.did,
        iat: now,
        nbf: now,
        exp: now + 300,
        nonce: presentationOffer.nonce,
        vp: {
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          id: `urn:uuid:${randomUUID()}`,
          type: ['VerifiablePresentation'],
          holder: did.did,
          verifiableCredential: [presentedCredential],
        },
      })
        .setProtectedHeader({
          alg: 'ES256',
          typ: 'JWT',
          kid: `${did.did}#${did.did.slice(8)}`,
        })
        .sign(privateKey);
    } else {
      const vp = {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        id: `urn:uuid:${randomUUID()}`,
        type: ['VerifiablePresentation'],
        holder: did.did,
        verifiableCredential: credentials.map((credential: any) => {
          return credential.jwt;
        }),
      } satisfies EbsiVerifiablePresentation;

      const audienceObj = decodeJwt(firstCredentialJwt);

      const audience =
        typeof audienceObj?.aud === 'string'
          ? audienceObj.aud
          : typeof audienceObj?.aud === 'object'
            ? audienceObj.aud[0]
            : (audienceObj.iss ?? '');

      const options = {
        timeout: 30_000,
        skipValidation: true,
        skipAccreditationsValidation: true,
        skipStatusValidation: true,
        skipCredentialSubjectValidation: true,
        proofPurpose: 'authentication',
        exp: Math.floor(Date.now() / 1000),
      } satisfies CreateVerifiablePresentationJwtOptions;

      vpToken = await createVerifiablePresentationJwt(
        vp,
        holder,
        audience,
        config,
        options,
      );
    }

    const data = new URLSearchParams({
      vp_token: vpToken,
      presentation_submission: JSON.stringify(presentationSubmission),
      state,
    }).toString();

    const uri =
      presentationOffer.redirect_uri ?? presentationOffer.response_uri;

    try {
      const idTokenRes = await axios.post(uri, data, {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        maxRedirects: 0,
      });

      return idTokenRes.status >= 200 && idTokenRes.status < 300;
    } catch (error) {
      if (
        error.response &&
        error.response.status === 302 &&
        error.response.headers['location']
      ) {
        const location = error.response.headers['location'];
        const authorizationCode = new URL(location).searchParams.get('code');

        return !!authorizationCode;
      }

      console.log('Error issuing presentation:', error.message);
      return false;
    }
  }
}
