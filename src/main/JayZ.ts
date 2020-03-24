import { memzero } from "libsodium-wrappers"
import { DataKeyProvider } from "./DataKeyProvider"
import { Encryptor } from "./Encryptor"
import { LibsodiumEncryptor } from "./LibsodiumEncryptor"
import { EncryptedItemMetadata, EncryptedJayZItem } from "./types"

export class JayZ {
  constructor(
    private keyProvider: DataKeyProvider,
    private encryptor: Encryptor = new LibsodiumEncryptor()
  ) {}

  async encryptItem<T, K extends keyof T>(
    item: T,
    fieldsToEncrypt: K[]
  ): Promise<EncryptedJayZItem<T, K>> {
    const {
      dataKey,
      encryptedDataKey
    } = await this.keyProvider.generateDataKey()

    const { encryptedItem, nonce } = await this.encryptor.encrypt({
      item,
      fieldsToEncrypt,
      dataKey
    })

    memzero(dataKey)

    const __jayz__metadata: EncryptedItemMetadata<T, K> = {
      encryptedDataKey,
      nonce,
      scheme: this.encryptor.scheme,
      encryptedFieldNames: fieldsToEncrypt
    }

    return {
      ...encryptedItem,
      __jayz__metadata
    }
  }

  async decryptItem<T, K extends keyof T>(
    encryptedJayZItem: EncryptedJayZItem<T, K>
  ): Promise<T> {
    const {
      nonce,
      encryptedDataKey,
      encryptedFieldNames
    } = encryptedJayZItem.__jayz__metadata

    const encryptedItem = { ...encryptedJayZItem }
    delete encryptedItem.__jayz__metadata

    const dataKey = await this.keyProvider.decryptDataKey(encryptedDataKey)

    const { decryptedItem } = await this.encryptor.decrypt<T, K>({
      encryptedItem,
      fieldsToDecrypt: encryptedFieldNames,
      dataKey,
      nonce
    })

    memzero(dataKey)

    return decryptedItem
  }
}
