import { describe, it, expect } from "vitest";
import { schnorr } from "../src/schnorr";
import { AdaptorSignature } from "../src/adaptorSignature";
import { randomBytes } from "../src/utils";

const { schnorrGetExtPubKey } = schnorr.internals;
const { Fn } = schnorr.Point;

const toHex = (a: Uint8Array) => Buffer.from(a).toString("hex");

const msg = Buffer.from("Hello world!", "utf8");

describe("Adaptor signature", () => {
  it("Generating BIP340 valid signatures with secret", () => {
    for (let i = 0; i < 50; i++) {
      const signer = randomBytes();
      const secret = randomBytes();
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
      const signer = randomBytes();
      const secret = randomBytes();
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
      const signer = randomBytes();
      const secret = randomBytes();

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
      const signer = randomBytes();
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

  it(`Swapping - Alice and Bob`, () => {
    for (let i = 0; i < 50; i++) {
      const signer = randomBytes();
      const watcher = randomBytes();

      const { secret, adaptorPoint } = AdaptorSignature.createSecret();

      // Alice the signer creates a signature
      const fullSig = AdaptorSignature.createFullSignature(secret, signer, msg);

      // then the signer creates an adaptor signature and sends to Bob
      const adaptorSig = AdaptorSignature.fromSecret(fullSig, secret);

      // watcher creates a commitment to Adaptor Point and sends to signer
      const nonce = AdaptorSignature.getPerfectNonce(
        adaptorPoint,
        watcher,
        msg
      );

      const commitSig = AdaptorSignature.fromAdaptorPoint(
        adaptorPoint,
        watcher,
        msg,
        nonce
      );

      // signer broadcast the transaction
      // watcher extracts the secret
      const recoveredSecret = AdaptorSignature.extractSecret(
        adaptorSig,
        AdaptorSignature.to64Sig(fullSig)
      );

      expect(toHex(recoveredSecret)).to.be.equal(toHex(secret));

      // now signer broadcast watcher's commit transaction
      const bip340CommitSig = AdaptorSignature.extractFullSignature(
        commitSig,
        secret
      );

      expect(
        schnorr.verify(bip340CommitSig, msg, schnorr.getPublicKey(watcher)),
        "the commit to adaptor point + secret should be valid transaction"
      ).to.true;
    }
  });
});
