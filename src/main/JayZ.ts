import { memzero } from "libsodium-wrappers"
import { DataKey, DataKeyProvider } from "./DataKeyProvider"
import { Encryptor } from "./Encryptor"
import { LibsodiumEncryptor } from "./LibsodiumEncryptor"
import { EncryptedItemMetadata, EncryptedJayZItem } from "./types"

export type JayZConfig = {
  keyProvider: DataKeyProvider
  encryptor?: Encryptor
  maxUsesPerDataKey?: number
}

export class JayZ {
  private keyProvider: DataKeyProvider
  private encryptor: Encryptor = new LibsodiumEncryptor()

  private maxUsesPerDataKey: number
  private timesDataKeyUsed: number = 0
  private dataKey?: DataKey

  constructor(config: JayZConfig) {
    this.keyProvider = config.keyProvider
    this.encryptor =
      config.encryptor !== undefined
        ? config.encryptor
        : new LibsodiumEncryptor()
    this.maxUsesPerDataKey = config.maxUsesPerDataKey || 1
  }

  async encryptItem<T, K extends keyof T>(
    item: T,
    fieldsToEncrypt: K[]
  ): Promise<EncryptedJayZItem<T, K>> {
    const { dataKey, encryptedDataKey } = await this.getDataKey()
    const { encryptedItem, nonce } = await this.encryptor.encrypt({
      item,
      fieldsToEncrypt,
      dataKey
    })

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

  private async getDataKey(): Promise<DataKey> {
    if (this.dataKey === undefined) {
      this.timesDataKeyUsed = 0
      this.dataKey = await this.keyProvider.generateDataKey()
    } else if (this.timesDataKeyUsed >= this.maxUsesPerDataKey) {
      memzero(this.dataKey.dataKey)
      this.timesDataKeyUsed = 0
      this.dataKey = await this.keyProvider.generateDataKey()
    }

    this.timesDataKeyUsed += 1
    return this.dataKey
  }
}
