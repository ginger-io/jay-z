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
import { DataKeyProvider } from "./DataKeyProvider"

enum KeyType {
  ENCRYPTION = 1,
  SIGNING = 2
}

enum EncryptionVersion {
  V_0 // experimental
}

type EncryptedItemMetadata<T, K extends keyof T> = {
  version: EncryptionVersion
  nonce: Uint8Array
  encryptedDataKey: Uint8Array
  encryptedFieldNames: K[]
}

type EncryptionMaterials = {
  encryptedDataKey: Uint8Array
  derivedEncryptionKey: Uint8Array
  nonce: Uint8Array
}

export type ItemWithEncryptedFields<T, K extends keyof T> = Omit<T, K> &
  {
    [P in K]: Uint8Array
  } & {
    __jayz__metadata: EncryptedItemMetadata<T, K>
  }

export class JayZ {
  constructor(private keyProvider: DataKeyProvider) {}

  async encryptItem<T, K extends keyof T>(
    item: T,
    fieldsToEncrypt: K[]
  ): Promise<ItemWithEncryptedFields<T, K>> {
    const {
      encryptedDataKey,
      derivedEncryptionKey,
      nonce
    } = await this.generateEcryptionKey()

    const encryptedFields: { [P in K]: Uint8Array } = {} as any

    fieldsToEncrypt.forEach(name => {
      encryptedFields[name] = crypto_secretbox_easy(
        this.toBuffer(item[name]),
        nonce,
        derivedEncryptionKey
      )
    })

    memzero(derivedEncryptionKey)

    const __jayz__metadata: EncryptedItemMetadata<T, K> = {
      encryptedDataKey,
      nonce,
      version: EncryptionVersion.V_0,
      encryptedFieldNames: fieldsToEncrypt
    }

    return {
      ...item,
      ...encryptedFields,
      __jayz__metadata
    }
  }

  async decryptItem<T, K extends keyof T>(
    encryptedItem: ItemWithEncryptedFields<T, K>
  ): Promise<T> {
    const {
      nonce,
      encryptedDataKey,
      encryptedFieldNames
    } = encryptedItem.__jayz__metadata

    const decryptedDataKey = await this.keyProvider.decryptDataKey(
      encryptedDataKey
    )

    const decryptionKey = this.deriveEncryptionKey(
      decryptedDataKey,
      KeyType.ENCRYPTION
    )

    const data = { ...encryptedItem }
    delete data.__jayz__metadata

    const decryptedItem: { [P in keyof T]: T[P] } = {
      ...data
    } as any

    encryptedFieldNames.forEach(name => {
      const cipherText = encryptedItem[name]
      const json = crypto_secretbox_open_easy(cipherText, nonce, decryptionKey)
      decryptedItem[name] = JSON.parse(to_string(json))
    })

    return decryptedItem
  }

  private toBuffer(value: any): Uint8Array {
    const json = stringify(value)
    return from_string(json)
  }

  private async generateEcryptionKey(): Promise<EncryptionMaterials> {
    await ready

    const {
      dataKey,
      encryptedDataKey
    } = await this.keyProvider.generateDataKey()

    const nonce = randombytes_buf(crypto_secretbox_NONCEBYTES)
    const derivedEncryptionKey = this.deriveEncryptionKey(
      dataKey,
      KeyType.ENCRYPTION
    )

    // scrub root key from memory since we're done with it
    memzero(dataKey)

    return {
      encryptedDataKey: encryptedDataKey,
      derivedEncryptionKey,
      nonce
    }
  }

  private deriveEncryptionKey(
    dataKey: Uint8Array,
    keyType: KeyType
  ): Uint8Array {
    const key = crypto_kdf_derive_from_key(
      crypto_secretbox_KEYBYTES,
      keyType,
      "__jayz__", // encryption context: must be 8 chars, per https://libsodium.gitbook.io/doc/key_derivation
      dataKey
    )

    return key
  }
}
