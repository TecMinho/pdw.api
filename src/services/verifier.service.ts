import { Injectable } from '@nestjs/common';
import { getResolver as ebsiDidResolver } from '@cef-ebsi/ebsi-did-resolver';
import { getResolver as keyDidResolver } from '@cef-ebsi/key-did-resolver';
import { Resolver } from 'did-resolver';
import { config } from '../environment/issuers';

@Injectable()
export class VerifierService {
  constructor() {}

  private getSchema(clientId: string) {
    const ebsiRegExp = /^did:ebsi:[a-zA-Z0-9:\-._]+$/;
    const keyRegExp = /^did:key:[a-zA-Z0-9:\-._]+$/;

    if (!clientId.startsWith('did:')) {
      throw new Error('Invalid clientId format. It must start with "did:".');
    }

    if (ebsiRegExp.test(clientId)) {
      return 'ebsi';
    } else if (keyRegExp.test(clientId)) {
      return 'key';
    } else {
      throw new Error(
        'Invalid clientId format. It must be a valid EBSI or key DID.',
      );
    }
  }

  private async resolveDid(clientId: string, schema: string): Promise<boolean> {
    let didResolver: Resolver;

    if (schema === 'ebsi') {
      const resolverConfig = {
        registry: `https://${config.hosts[0]}/did-registry/${config.services['did-registry']}/identifiers`,
      };
      didResolver = new Resolver(ebsiDidResolver(resolverConfig));
    } else if (schema === 'key') {
      didResolver = new Resolver(keyDidResolver());
    } else {
      throw new Error(`Unsupported DID method: ${clientId}`);
    }

    const doc = await didResolver.resolve(clientId);

    if (doc.didResolutionMetadata.error) {
      throw new Error(
        `DID resolution error: ${doc.didResolutionMetadata.error}`,
      );
    }

    return true;
  }

  async verifyClientId(clientId: string): Promise<boolean> {
    const didSchema = this.getSchema(clientId);
    return await this.resolveDid(clientId, didSchema);
  }
}