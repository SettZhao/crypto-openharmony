import { encrypt, decrypt } from "libhmcrypto.so";

export class Crypto {
  static Blowfish = class {
    static encrypt(input: ArrayBuffer, key: ArrayBuffer, iv: ArrayBuffer, padding: number): ArrayBuffer{
      return encrypt("Blowfish", key, iv, padding, input);
    }
    static decrypt(input: ArrayBuffer, key: ArrayBuffer, iv: ArrayBuffer, padding: number): ArrayBuffer{
      return decrypt("Blowfish", key, iv, padding, input);
    }
  }
}