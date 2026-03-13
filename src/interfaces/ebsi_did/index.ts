export interface EBSIDID {
  did: string;
  privateKey: string;
  x: string;
  y: string;
}

export interface EBSIDIDWithSeed {
  did: string;
  privateKey: string;
  x: string;
  y: string;
  seed: string;
}
