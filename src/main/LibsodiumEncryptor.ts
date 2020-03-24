import stringify from "fast-json-stable-stringify"
import {
  crypto_kdf_derive_from_key,
  crypto_secretbox_easy,
  crypto_secretbox_KEYBYTES,
  crypto_secretbox_NONCEBYTES,
  crypto_secretbox_open_easy,
  from_string,
  memzero,
  randombytes_buf,
  ready,
  to_string
} from "libsodium-wrappers"
import {
  DecryptParams,
  DecryptResult,
  Encryptor,
  EncryptParams,
  EncryptResult
} from "./Encryptor"
import { EncryptionScheme, KeyType } from "./types"

export class LibsodiumEncryptor implements Encryptor {
  public readonly scheme = EncryptionScheme.V0_LIBSODIUM

  async encrypt<T, K extends keyof T>(
    params: EncryptParams<T, K>
  ): Promise<EncryptResult<T, K>> {
    await ready

    const { item, fieldsToEncrypt, dataKey } = params
    const nonce = randombytes_buf(crypto_secretbox_NONCEBYTES)
    const encryptionKey = this.deriveKey(dataKey, KeyType.ENCRYPTION)

    const encryptedFields: { [P in K]: Uint8Array } = {} as any

    fieldsToEncrypt.forEach(name => {
      encryptedFields[name] = crypto_secretbox_easy(
        this.toBuffer(item[name]),
        nonce,
        encryptionKey
      )
    })

    memzero(encryptionKey)

    const encryptedItem = { ...item, ...encryptedFields }
    return { encryptedItem, nonce }
  }

  async decrypt<T, K extends keyof T>(
    params: DecryptParams<T, K>
  ): Promise<DecryptResult<T>> {
    await ready

    const { encryptedItem, fieldsToDecrypt, nonce, dataKey } = params
    const decryptionKey = this.deriveKey(dataKey, KeyType.ENCRYPTION)

    const decryptedItem: { [P in keyof T]: T[P] } = {
      ...encryptedItem
    } as any

    fieldsToDecrypt.forEach(name => {
      const cipherText = encryptedItem[name]
      const json = crypto_secretbox_open_easy(cipherText, nonce, decryptionKey)
      decryptedItem[name] = JSON.parse(to_string(json))
    })

    memzero(decryptionKey)

    return { decryptedItem }
  }

  private deriveKey(dataKey: Uint8Array, keyType: KeyType): Uint8Array {
    const key = crypto_kdf_derive_from_key(
      crypto_secretbox_KEYBYTES,
      keyType,
      "__jayz__", // encryption context: must be 8 chars, per https://libsodium.gitbook.io/doc/key_derivation
      dataKey
    )

    return key
  }

  private toBuffer<T extends {}>(value: T): Uint8Array {
    const json = stringify(value)
    return from_string(json)
  }
}
