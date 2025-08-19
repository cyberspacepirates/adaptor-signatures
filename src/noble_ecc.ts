import * as necc from "@noble/secp256k1";

export default {
  randomBytes(number = 32) {
    return necc.utils.randomBytes(number);
  },
};
