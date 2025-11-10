import { Controller, Get, Logger, Query } from '@nestjs/common';

/**
 * Controller responsible for fetching the issuer's published metadata and configuration. Within the OpenID specification,
 * the issuer server MUST make both of these endpoints available. These are a part of the discovery mechanism that allows the
 * wallet to easily find information about a credential issuer.
 */
@Controller('.well-known')
export class WellKnownController {
  private readonly logger = new Logger(WellKnownController.name);

  constructor() {}

  /**
   * Fetches the issuer's OpenID Connect configuration from the provided URL. The OpenID configuration is a standardized
   * way for the client application to discover the location of an OpenID Provider's (OP) endpoints and other configuration details,
   * in this case, the issuer's endpoints and configurations.
   *
   * @param {string} url - The base URL of the issuer whose OpenID Connect configuration needs to be retrieved.
   * @return {Promise<object>} A promise that resolves to the issuer's OpenID Connect configuration object.
   * @throws {Error} If the configuration cannot be fetched or the request fails.
   */
  @Get('openid-configuration')
  async getIssuerConfiguration(@Query('url') url: string): Promise<object> {
    const issuerUrl = new URL(url);
    const base = issuerUrl.toString().replace(/\/+$/, '');
    const wellKnownPath = '/.well-known/openid-configuration';

    const fullUrl = `${base}${wellKnownPath}`;

    this.logger.debug(`Issuer URL: ${fullUrl}`);

    const configurationRes = await fetch(fullUrl);

    if (!configurationRes.ok) {
      throw new Error('Unable to fetch issuer configuration!');
    }

    const configuration = await configurationRes.json();
    this.logger.debug(`Issuer Configuration: ${JSON.stringify(configuration)}`);

    return configuration;
  }

  /**
   * Retrieves the OpenID credential issuer metadata from the provided URL. This service allows the wallet to discover
   * information about the issuer and the credentials it offers.
   *
   * @param {string} url - The base URL of the OpenID credential issuer.
   * @return {Promise<object>} The metadata associated with the OpenID credential issuer.
   * @throws {Error} If the metadata cannot be fetched or the request fails.
   */
  @Get('openid-credential-issuer')
  async getIssuerMetadata(@Query('url') url: string): Promise<object> {
    const issuerUrl = new URL(url);
    const base = issuerUrl.toString().replace(/\/+$/, '');
    const wellKnownPath = '/.well-known/openid-credential-issuer';

    const fullUrl = `${base}${wellKnownPath}`;

    this.logger.debug(`Issuer URL: ${fullUrl}`);

    const metadataRes = await fetch(fullUrl);

    if (!metadataRes.ok) {
      throw new Error('Unable to fetch issuer metadata!');
    }

    const metadata = await metadataRes.json();
    this.logger.debug(`Issuer Metadata: ${JSON.stringify(metadata)}`);

    return metadata;
  }
}
