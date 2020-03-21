import {
  crypto_kdf_KEYBYTES,
  from_base64,
  randombytes_buf,
  ready,
  to_base64
} from "libsodium-wrappers"
import { DataKey, DataKeyProvider } from "./DataKeyProvider"

/** Stub DataKeyProvider for testing  */
export class StubDataKeyProvider implements DataKeyProvider {
  static async forLibsodium(): Promise<StubDataKeyProvider> {
    await ready
    const key = randombytes_buf(crypto_kdf_KEYBYTES)
    return new StubDataKeyProvider(to_base64(key))
  }

  constructor(private dataKey: string) {}

  async generateDataKey(): Promise<DataKey> {
    return {
      encryptedDataKey: from_base64(this.dataKey),
      dataKey: from_base64(this.dataKey)
    }
  }

  async decryptDataKey(encryptedDataKey: Uint8Array): Promise<Uint8Array> {
    return encryptedDataKey
  }
}
