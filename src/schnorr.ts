/**
 * SECG secp256k1. See [pdf](https://www.secg.org/sec2-v2.pdf).
 *
 * Belongs to Koblitz curves: it has efficiently-computable GLV endomorphism ψ,
 * check out {@link EndomorphismOpts}. Seems to be rigid (not backdoored).
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { Field, mapHashToField, pow2 } from "./abstract/modular";
import {
  type ECDSA,
  ecdsa,
  type EndomorphismOpts,
  type WeierstrassPoint as PointType,
  weierstrass,
  type WeierstrassOpts,
} from "./abstract/weierstrass";

import {
  abytes,
  asciiToBytes,
  bytesToNumberBE,
  concatBytes,
  inRange,
} from "../src/utils";

// Seems like generator was produced from some seed:
// `Pointk1.BASE.multiply(Pointk1.Fn.inv(2n, N)).toAffine().x`
// // gives short x 0x3b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63n
const secp256k1_CURVE: WeierstrassOpts<bigint> = {
  p: BigInt(
    "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
  ),
  n: BigInt(
    "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
  ),
  h: BigInt(1),
  a: BigInt(0),
  b: BigInt(7),
  Gx: BigInt(
    "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
  ),
  Gy: BigInt(
    "0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
  ),
};

const secp256k1_ENDO: EndomorphismOpts = {
  beta: BigInt(
    "0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee"
  ),
  basises: [
    [
      BigInt("0x3086d221a7d46bcde86c90e49284eb15"),
      -BigInt("0xe4437ed6010e88286f547fa90abfe4c3"),
    ],
    [
      BigInt("0x114ca50f7a8e2f3f657c1108d9d44cfd8"),
      BigInt("0x3086d221a7d46bcde86c90e49284eb15"),
    ],
  ],
};

const _0n = /* @__PURE__ */ BigInt(0);
const _1n = /* @__PURE__ */ BigInt(1);
const _2n = /* @__PURE__ */ BigInt(2);

/**
 * √n = n^((p+1)/4) for fields p = 3 mod 4. We unwrap the loop and multiply bit-by-bit.
 * (P+1n/4n).toString(2) would produce bits [223x 1, 0, 22x 1, 4x 0, 11, 00]
 */
function sqrtMod(y: bigint): bigint {
  const P = secp256k1_CURVE.p;
  // prettier-ignore
  const _3n = BigInt(3), _6n = BigInt(6), _11n = BigInt(11), _22n = BigInt(22);
  // prettier-ignore
  const _23n = BigInt(23), _44n = BigInt(44), _88n = BigInt(88);
  const b2 = (y * y * y) % P; // x^3, 11
  const b3 = (b2 * b2 * y) % P; // x^7
  const b6 = (pow2(b3, _3n, P) * b3) % P;
  const b9 = (pow2(b6, _3n, P) * b3) % P;
  const b11 = (pow2(b9, _2n, P) * b2) % P;
  const b22 = (pow2(b11, _11n, P) * b11) % P;
  const b44 = (pow2(b22, _22n, P) * b22) % P;
  const b88 = (pow2(b44, _44n, P) * b44) % P;
  const b176 = (pow2(b88, _88n, P) * b88) % P;
  const b220 = (pow2(b176, _44n, P) * b44) % P;
  const b223 = (pow2(b220, _3n, P) * b3) % P;
  const t1 = (pow2(b223, _23n, P) * b22) % P;
  const t2 = (pow2(t1, _6n, P) * b2) % P;
  const root = pow2(t2, _2n, P);
  if (!Fpk1.eql(Fpk1.sqr(root), y)) throw new Error("Cannot find square root");
  return root;
}

const Fpk1 = Field(secp256k1_CURVE.p, { sqrt: sqrtMod });
const Pointk1 = /* @__PURE__ */ weierstrass(secp256k1_CURVE, {
  Fp: Fpk1,
  endo: secp256k1_ENDO,
});

/**
 * secp256k1 curve, ECDSA and ECDH methods.
 *
 * Field: `2n**256n - 2n**32n - 2n**9n - 2n**8n - 2n**7n - 2n**6n - 2n**4n - 1n`
 *
 * @example
 * ```js
 * import { secp256k1 } from '@noble/curves/secp256k1';
 * const { secretKey, publicKey } = secp256k1.keygen();
 * const msg = new TextEncoder().encode('hello');
 * const sig = secp256k1.sign(msg, secretKey);
 * const isValid = secp256k1.verify(sig, msg, publicKey) === true;
 * ```
 */

export const secp256k1: ECDSA = /* @__PURE__ */ ecdsa(Pointk1, sha256);

// Schnorr signatures are superior to ECDSA from above. Below is Schnorr-specific BIP0340 code.
// https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
/** An object mapping tags to their tagged hash prefix of [SHA256(tag) | SHA256(tag)] */
const TAGGED_HASH_PREFIXES: { [tag: string]: Uint8Array } = {};
function taggedHash(tag: string, ...messages: Uint8Array[]): Uint8Array {
  let tagP = TAGGED_HASH_PREFIXES[tag];
  if (tagP === undefined) {
    const tagH = sha256(asciiToBytes(tag));
    tagP = concatBytes(tagH, tagH);
    TAGGED_HASH_PREFIXES[tag] = tagP;
  }
  return sha256(concatBytes(tagP, ...messages));
}

// ECDSA compact points are 33-byte. Schnorr is 32: we strip first byte 0x02 or 0x03
const pointToBytes = (point: PointType<bigint>) => point.toBytes(true).slice(1);
const hasEven = (y: bigint) => y % _2n === _0n;

// Calculate point, scalar and bytes
function schnorrGetExtPubKey(priv: Uint8Array) {
  const { Fn, BASE } = Pointk1;
  const d_ = Fn.fromBytes(priv);
  const p = BASE.multiply(d_); // P = d'⋅G; 0 < d' < n check is done inside
  const scalar = hasEven(p.y) ? d_ : Fn.neg(d_);
  return { scalar, bytes: pointToBytes(p) };
}
/**
 * lift_x from BIP340. Convert 32-byte x coordinate to elliptic curve point.
 * @returns valid point checked for being on-curve
 */
function lift_x(x: bigint): PointType<bigint> {
  const Fp = Fpk1;
  if (!Fp.isValidNot0(x)) throw new Error("invalid x: Fail if x ≥ p");
  const xx = Fp.create(x * x);
  const c = Fp.create(xx * x + BigInt(7)); // Let c = x³ + 7 mod p.
  let y = Fp.sqrt(c); // Let y = c^(p+1)/4 mod p. Same as sqrt().
  // Return the unique point P such that x(P) = x and
  // y(P) = y if y mod 2 = 0 or y(P) = p-y otherwise.
  if (!hasEven(y)) y = Fp.neg(y);
  const p = Pointk1.fromAffine({ x, y });
  p.assertValidity();
  return p;
}
const num = bytesToNumberBE;
/**
 * Create tagged hash, convert it to bigint, reduce modulo-n.
 */
function challenge(...args: Uint8Array[]): bigint {
  return Pointk1.Fn.create(num(taggedHash("BIP0340/challenge", ...args)));
}

/**
 * Schnorr public key is just `x` coordinate of Point as per BIP340.
 */
function schnorrGetPublicKey(secretKey: Uint8Array): Uint8Array {
  return schnorrGetExtPubKey(secretKey).bytes; // d'=int(sk). Fail if d'=0 or d'≥n. Ret bytes(d'⋅G)
}

/**
 * Creates Schnorr signature as per BIP340. Verifies itself before returning anything.
 * auxRand is optional and is not the sole source of k generation: bad CSPRNG won't be dangerous.
 */
function schnorrSign(
  message: Uint8Array,
  secretKey: Uint8Array,
  auxRand: Uint8Array = randomBytes(32)
): Uint8Array {
  const { Fn } = Pointk1;
  const m = abytes(message, undefined, "message")!;
  const { bytes: px, scalar: d } = schnorrGetExtPubKey(secretKey); // checks for isWithinCurveOrder
  const a = abytes(auxRand, 32, "auxRand"); // Auxiliary random data a: a 32-byte array
  const t = Fn.toBytes(d ^ num(taggedHash("BIP0340/aux", a))); // Let t be the byte-wise xor of bytes(d) and hash/aux(a)
  const rand = taggedHash("BIP0340/nonce", t, px, m); // Let rand = hash/nonce(t || bytes(P) || m)
  // Let k' = int(rand) mod n. Fail if k' = 0. Let R = k'⋅G
  const { bytes: rx, scalar: k } = schnorrGetExtPubKey(rand);
  const e = challenge(rx, px, m); // Let e = int(hash/challenge(bytes(R) || bytes(P) || m)) mod n.
  const sig = new Uint8Array(64); // Let sig = bytes(R) || bytes((k + ed) mod n).
  sig.set(rx, 0);
  sig.set(Fn.toBytes(Fn.create(k + e * d)), 32);
  // If Verify(bytes(P), m, sig) (see below) returns failure, abort
  if (!schnorrVerify(sig, m, px))
    throw new Error("sign: Invalid signature produced");
  return sig;
}

/**
 * Verifies Schnorr signature.
 * Will swallow errors & return false except for initial type validation of arguments.
 */
function schnorrVerify(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array
): boolean {
  const { Fn, BASE } = Pointk1;
  const sig = abytes(signature, 64, "signature");
  const m = abytes(message, undefined, "message");
  const pub = abytes(publicKey, 32, "publicKey");
  try {
    const P = lift_x(num(pub)); // P = lift_x(int(pk)); fail if that fails
    const r = num(sig.subarray(0, 32)); // Let r = int(sig[0:32]); fail if r ≥ p.
    if (!inRange(r, _1n, secp256k1_CURVE.p)) return false;
    const s = num(sig.subarray(32, 64)); // Let s = int(sig[32:64]); fail if s ≥ n.
    if (!inRange(s, _1n, secp256k1_CURVE.n)) return false;
    const e = challenge(Fn.toBytes(r), pointToBytes(P), m); // int(challenge(bytes(r)||bytes(P)||m))%n
    // R = s⋅G - e⋅P, where -eP == (n-e)P
    const R = BASE.multiplyUnsafe(s).add(P.multiplyUnsafe(Fn.neg(e)));
    const { x, y } = R.toAffine();
    // Fail if is_infinite(R) / not has_even_y(R) / x(R) ≠ r.
    if (R.is0() || !hasEven(y) || x !== r) return false;
    return true;
  } catch (error) {
    return false;
  }
}

/**
 * Schnorr signatures over secp256k1.
 * https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
 * @example
 * ```js
 * import { schnorr } from '@noble/curves/secp256k1';
 * const { secretKey, publicKey } = schnorr.keygen();
 * // const publicKey = schnorr.getPublicKey(secretKey);
 * const msg = new TextEncoder().encodadaptorPoint('hello');
 * const sig = schnorr.sign(msg, secretKey);
 * const isValid = schnorr.verify(sig, msg, publicKey);
 * ```
 */
export const schnorr = /* @__PURE__ */ (() => {
  const size = 32;
  const seedLength = 48;
  const randomSecretKey = (seed = randomBytes(seedLength)): Uint8Array => {
    return mapHashToField(seed, secp256k1_CURVE.n);
  };
  function keygen(seed?: Uint8Array) {
    const secretKey = randomSecretKey(seed);
    return { secretKey, publicKey: schnorrGetPublicKey(secretKey) };
  }
  return {
    keygen,
    getPublicKey: schnorrGetPublicKey,
    sign: schnorrSign,
    verify: schnorrVerify,
    Point: Pointk1,
    utils: {
      randomSecretKey,
      taggedHash,
      lift_x,
      pointToBytes,
    },
    internals: {
      challenge,
      schnorrGetPublicKey,
      schnorrGetExtPubKey,
      inRange,
      num,
      hasEven,
    },
    lengths: {
      secretKey: size,
      publicKey: size,
      publicKeyHasPrefix: false,
      signature: size * 2,
      seed: seedLength,
    },
  };
})();
