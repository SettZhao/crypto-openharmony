import { encrypt } from "libhmcrypto.so";

export class Crypto {
  static Blowfish(input: ArrayBuffer, key: ArrayBuffer, iv: ArrayBuffer, padding: number): ArrayBuffer{
    return encrypt("Blowfish", key, iv, padding, input);
  }
}