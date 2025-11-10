import { EbsiVpEnvConfiguration } from '@cef-ebsi/verifiable-presentation';

export const config = {
  hosts: ['api-pilot.ebsi.eu'],
  scheme: 'ebsi',
  network: {
    name: 'pilot',
    isOptional: false,
  },
  services: {
    'did-registry': 'v5',
    'trusted-issuers-registry': 'v5',
    'trusted-policies-registry': 'v3',
    'trusted-schemas-registry': 'v3',
  },
} as const satisfies EbsiVpEnvConfiguration;
