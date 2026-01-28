import { decrypt, encrypt } from 'libhmcrypto.so';

type AlgorithmWithIv = 'Blowfish' | 'AES' | 'DES' | 'SM4';
type AlgorithmWithoutIv = 'RSA' | 'ECC' | 'SM2';

function createCryptoClassWithIv(algorithm: AlgorithmWithIv) {
  return class {
    static encrypt(input: ArrayBuffer, key: ArrayBuffer, iv: ArrayBuffer, padding: number): ArrayBuffer {
      return encrypt(algorithm, key, iv, padding, input);
    }

    static decrypt(input: ArrayBuffer, key: ArrayBuffer, iv: ArrayBuffer, padding: number): ArrayBuffer {
      return decrypt(algorithm, key, iv, padding, input);
    }
  };
}

function createCryptoClassWithoutIv(algorithm: AlgorithmWithoutIv) {
  return class {
    static encrypt(input: ArrayBuffer, key: ArrayBuffer, padding: number): ArrayBuffer {
      return encrypt(algorithm, key, new ArrayBuffer(0), padding, input);
    }

    static decrypt(input: ArrayBuffer, key: ArrayBuffer, padding: number): ArrayBuffer {
      return decrypt(algorithm, key, new ArrayBuffer(0), padding, input);
    }
  };
}

export class Crypto {
  static Blowfish = createCryptoClassWithIv('Blowfish');
  static AES = createCryptoClassWithIv('AES');
  static DES = createCryptoClassWithIv('DES');
  static RSA = createCryptoClassWithoutIv('RSA');
  static ECC = createCryptoClassWithoutIv('ECC');
  static SM2 = createCryptoClassWithoutIv('SM2');
  static SM4 = createCryptoClassWithIv('SM4');
}
