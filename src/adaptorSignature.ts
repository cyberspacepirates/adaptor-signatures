import { schnorr } from "./schnorr";
import { abytes, bytesToNumberBE } from "./utils";
const { schnorrGetExtPubKey, challenge, num } = schnorr.internals;
const { taggedHash, lift_x, pointToBytes } = schnorr.utils;
import ecc from "../src/noble_ecc";
const randomBytes = ecc.randomBytes;

const { Fn, BASE } = schnorr.Point;

class Signature {
  static generateNonce(
    auxRand: Uint8Array,
    secretKey: Uint8Array,
    m: Uint8Array
  ) {
    const { bytes: px, scalar: d } = schnorrGetExtPubKey(secretKey); // checks for isWithinCurveOrder
    const a = abytes(auxRand, 32, "auxRand"); // Auxiliary random data a: a 32-byte array
    const t = Fn.toBytes(d ^ bytesToNumberBE(taggedHash("BIP0340/aux", a))); // Let t be the byte-wise xor of bytes(d) and hash/aux(a)
    const rand = taggedHash("BIP0340/nonce", t, px, m); // Let rand = hash/nonce(t || bytes(P) || m)

    return rand;
  }
}

export class AdaptorSignature {
  static createSecret() {
    const random = ecc.randomBytes();
    const { bytes: adaptorPoint, scalar: t } = schnorrGetExtPubKey(random);

    return {
      adaptorPoint,
      secret: Fn.toBytes(t),
    };
  }

  static createFullSignature(
    secret: Uint8Array,
    privateKey: Uint8Array,
    message: Buffer,
    auxRand: Uint8Array = randomBytes()
  ) {
    const m = abytes(message, undefined, "message")!;
    const { bytes: px, scalar: d } = schnorrGetExtPubKey(privateKey); // checks for isWithinCurveOrder
    const { bytes: adaptorPoint, scalar: t } = schnorrGetExtPubKey(secret); // checks for isWithinCurveOrder
    const rand = Signature.generateNonce(auxRand, privateKey, m); // Let rand = hash/nonce(t || bytes(P) || m)
    // Let k' = int(rand) mod n. Fail if k' = 0. Let R = k'⋅G
    const { scalar: k } = schnorrGetExtPubKey(rand);
    const { bytes: R_prime, scalar: r_prime } = schnorrGetExtPubKey(
      Fn.toBytes(Fn.create(k + t))
    );
    // console.log(R_prime.length);
    const e = challenge(R_prime, px, m); // Let e = int(hash/challenge(bytes(R) || bytes(P) || m)) mod n.

    const sig = new Uint8Array(96); // Let sig = bytes(R) || bytes((k + ed) mod n).
    sig.set(adaptorPoint, 0);
    sig.set(R_prime, 32);
    sig.set(Fn.toBytes(Fn.create(r_prime + e * d)), 64);
    return sig;
  }

  static fromSecret(fullSignature: Uint8Array, secret: Uint8Array) {
    const [adaptorPoint, nonce, fullSig] = [
      fullSignature.subarray(0, 32),
      fullSignature.subarray(32, 64),
      fullSignature.subarray(64, 96),
    ];

    const s = num(fullSig);
    const t = num(secret);

    const auxSig = Fn.toBytes(Fn.create(s - t));

    const sig = new Uint8Array(96);
    sig.set(adaptorPoint, 0);
    sig.set(nonce, 32);
    sig.set(auxSig, 64);
    return sig;
  }

  static extractFullSignature(
    adaptorSignature: Uint8Array,
    secret: Uint8Array
  ) {
    const R_prime = adaptorSignature.subarray(32, 64);
    const adaptorSig = adaptorSignature.subarray(64, 96);
    const s = num(adaptorSig);
    const t = num(secret);

    const signature = Fn.toBytes(Fn.create(s + t));

    const fullSig = new Uint8Array(64); // Let sig = bytes(R) || bytes((k + ed) mod n).
    fullSig.set(R_prime, 0);
    fullSig.set(signature, 32);
    return fullSig;
  }

  /***
   * Takes a 96 byte signture and returns 64 byte signature
   **/
  static to64Sig(signature: Uint8Array) {
    let _sig = signature;
    if (_sig.length == 96) {
      _sig = _sig.slice(32);
    }
    return _sig;
  }

  static extractSecret(
    adaptorSignature: Uint8Array,
    fullSignature: Uint8Array
  ) {
    const adaptorSig = adaptorSignature.subarray(64, 96);
    const fullSig = fullSignature.subarray(32, 64);

    const s = num(fullSig);
    const s_prime = num(adaptorSig);

    const secret = Fn.toBytes(Fn.create(s - s_prime));

    return secret;
  }

  static fromAdaptorPoint(
    adaptorPoint: Uint8Array,
    privateKey: Uint8Array,
    message: Buffer,
    auxRand: Uint8Array = randomBytes()
  ) {
    const m = abytes(message, undefined)!;
    const { bytes: px, scalar: d } = schnorrGetExtPubKey(privateKey); // checks for isWithinCurveOrder
    const rand = Signature.generateNonce(auxRand, privateKey, m); // Let rand = hash/nonce(t || bytes(P) || m)
    // Let k' = int(rand) mod n. Fail if k' = 0. Let R = k'⋅G
    const { scalar: k } = schnorrGetExtPubKey(rand);
    const commitPoint = lift_x(num(adaptorPoint));

    const R_prime = pointToBytes(BASE.multiply(k).add(commitPoint));

    // console.log(R_prime.length);
    const e = challenge(R_prime, px, m); // Let e = int(hash/challenge(bytes(R) || bytes(P) || m)) mod n.
    const sig = new Uint8Array(96); // Let sig = bytes(R) || bytes((k + ed) mod n).
    sig.set(adaptorPoint, 0);
    sig.set(R_prime, 32);
    sig.set(Fn.toBytes(Fn.create(k + e * d)), 64);
    return sig;
  }
}
