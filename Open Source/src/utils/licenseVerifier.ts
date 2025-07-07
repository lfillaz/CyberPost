

export function verifyLicense(): boolean {

  return true;
}

export function getMachineFingerprint(): string {
  return 'open-source-version';
}

export default {
  verifyLicense,
  getMachineFingerprint
};
