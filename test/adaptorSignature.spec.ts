import { describe, it, expect } from "vitest";
import { schnorr } from "../src/schnorr";
import { AdaptorSignature } from "../src/adaptorSignature";
import ecc from "../src/noble_ecc";

const { schnorrGetExtPubKey } = schnorr.internals;
const { Fn } = schnorr.Point;

const toHex = (a: Uint8Array) => Buffer.from(a).toString("hex");

const msg = Buffer.from("Hello world!", "utf8");

describe("Adaptor signature", () => {
  it("Generating BIP340 valid signatures with secret", () => {
    for (let i = 0; i < 50; i++) {
      const signer = ecc.randomBytes();
      const secret = ecc.randomBytes();
      // s = r + t + H(R + T || P || m) . p
      const fullSig = AdaptorSignature.createFullSignature(secret, signer, msg);
      // verifies if it's a valid bip340 signature
      // s . G = R + T + H(R + T || P || m) . P
      const verify = schnorr.verify(
        AdaptorSignature.to64Sig(fullSig),
        msg,
        schnorr.getPublicKey(signer)
      );

      expect(verify, "should generate a valid signature").to.be.equal(true);
    }
  });

  it(`Generating adaptor signatures by subtracting the secret`, () => {
    for (let i = 0; i < 50; i++) {
      const signer = ecc.randomBytes();
      const secret = ecc.randomBytes();
      // s = r + t + H(R + T || P || m) . p
      const fullSig = AdaptorSignature.createFullSignature(secret, signer, msg);
      // s' = s - t
      const adaptorSig = AdaptorSignature.fromSecret(fullSig, secret);
      // s = s' + t
      const recoveredFullSig = AdaptorSignature.extractFullSignature(
        adaptorSig,
        secret
      );

      expect(toHex(recoveredFullSig)).to.be.equal(
        toHex(AdaptorSignature.to64Sig(fullSig))
      );
    }
  });

  it("Extracting the secret with bip340 signature and adaptor signature", () => {
    for (let i = 0; i < 50; i++) {
      const signer = ecc.randomBytes();
      const secret = ecc.randomBytes();

      const fullSig = AdaptorSignature.createFullSignature(secret, signer, msg);

      const adaptorSig = AdaptorSignature.fromSecret(fullSig, secret);

      const recoveredSecret = AdaptorSignature.extractSecret(
        adaptorSig,
        AdaptorSignature.to64Sig(fullSig)
      );

      expect(toHex(recoveredSecret)).to.be.equal(toHex(secret));
    }
  });

  it(`Commiting to a Adaptor point`, () => {
    for (let i = 0; i < 50; i++) {
      const signer = ecc.randomBytes();
      const { secret, adaptorPoint } = AdaptorSignature.createSecret();

      const nonce = AdaptorSignature.getPerfectNonce(adaptorPoint, signer, msg);

      const fullSig = AdaptorSignature.createFullSignature(
        secret,
        signer,
        msg,
        nonce
      );

      const adaptorSig = AdaptorSignature.fromSecret(fullSig, secret);

      const commitSig = AdaptorSignature.fromAdaptorPoint(
        adaptorPoint,
        signer,
        msg,
        nonce
      );

      expect(toHex(commitSig)).to.be.equal(toHex(adaptorSig));
    }
  });
});
