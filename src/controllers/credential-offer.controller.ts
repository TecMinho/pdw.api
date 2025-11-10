import {
  Controller,
  Get,
  Query,
  Logger,
} from '@nestjs/common';

/**
 * Controller responsible for handling operations related to credential offers, allowing the retrieval of the provided
 * credential offer URL's data.
 */
@Controller('credential-offer')
export class CredentialOfferController {
  private readonly logger = new Logger(CredentialOfferController.name);

  /**
   * Handles the retrieval of the credential offer, given its URL. This endpoint can handle both the existence of a
   * credential offer URI and an encoded credential offer. If the credential offer contains a credential_offer_uri, the credential
   * offer will be retrieved from that URI and returned by this endpoint. If it contains an encoded credential_offer, the
   * credential_offer will be parsed and returned directly with no further handling. If none of them are present, an error
   * will be thrown.
   *
   * @param {string} offer The credential offer URL. It MUST contain either credential_offer or credential_offer_uri as a query parameter.
   * @return {Promise<object>} A promise that resolves to the processed credential offer object, optionally including the
   * `state` parameter if provided in the query.
   * @throws {Error} Throws an error if no credential offer or credential offer URI is provided, or if the credential offer fetch fails.
   */
  @Get('credential-offer')
  async getCredentialOffer(@Query('offer') offer: string): Promise<object> {
    const offerUrl = new URL(offer);
    this.logger.debug(`OpenID Credential Offer URL: ${offerUrl}`);

    const credentialOfferUri = decodeURIComponent(
      offerUrl.searchParams.get('credential_offer_uri') ?? '',
    );

    const credentialOffer = decodeURIComponent(
      offerUrl.searchParams.get('credential_offer') ?? '',
    );

    const state = decodeURIComponent(offerUrl.searchParams.get('state') ?? '');

    if (!credentialOfferUri && !credentialOffer) {
      throw new Error('No credential offer provided!');
    }

    if (credentialOffer) {
      this.logger.debug(`Credential Offer: ${JSON.parse(credentialOffer)}`);
      return {
        ...JSON.parse(credentialOffer),
        ...(state && {
          state,
        }),
      };
    }

    this.logger.debug(`Credential Offer URI: ${credentialOfferUri}`);

    const credentialOfferRes = await fetch(credentialOfferUri);

    if (!credentialOfferRes.ok) {
      throw new Error('Unable to fetch credential offer!');
    }

    const credentialOfferResult = await credentialOfferRes.json();
    this.logger.debug(
      `Credential Offer: ${JSON.stringify(credentialOfferResult)}`,
    );

    return {
      ...credentialOfferResult,
      ...(state && {
        state,
      }),
    };
  }
}
