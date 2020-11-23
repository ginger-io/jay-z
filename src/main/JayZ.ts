import { memzero, ready } from "libsodium-wrappers"
import { DataKey, DataKeyProvider } from "./DataKeyProvider"
import { Encryptor } from "./Encryptor"
import { LibsodiumEncryptor } from "./LibsodiumEncryptor"
import { EncryptedItemMetadata, EncryptedJayZItem } from "./types"

export type JayZConfig = {
  keyProvider: DataKeyProvider
  encryptor?: Encryptor
  maxUsesPerDataKey?: number
}

export type EncryptItemRequest<T, K extends keyof T> = {
  item: T
  fieldsToEncrypt: K[]
}

export class JayZ {
  private keyProvider: DataKeyProvider
  private encryptor: Encryptor = new LibsodiumEncryptor()

  private maxUsesPerDataKey: number

  private currentDataKey?: Promise<DataKey>
  private currentDataKeyUsesRemaining: number

  constructor(config: JayZConfig) {
    this.keyProvider = config.keyProvider
    this.encryptor =
      config.encryptor !== undefined
        ? config.encryptor
        : new LibsodiumEncryptor()
    this.maxUsesPerDataKey = config.maxUsesPerDataKey || 1
    this.currentDataKeyUsesRemaining = this.maxUsesPerDataKey
  }

  async encryptItems<T, K extends keyof T>(
    itemsToEncrypt: EncryptItemRequest<T, K>[]
  ): Promise<EncryptedJayZItem<T, K>[]> {
    if (itemsToEncrypt.length === 0) {
      return []
    }

    await ready
    const itemsWithKey = await this.zipItemsWithDataKey(itemsToEncrypt)
    const items = itemsWithKey.map(({ itemToEncrypt, key }) => {
      const { item, fieldsToEncrypt } = itemToEncrypt
      const { dataKey, encryptedDataKey } = key
      const { encryptedItem, nonce } = this.encryptor.encrypt({
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
    })

    return items
  }

  async decryptItems<T, K extends keyof T>(
    itemsToDecrypt: EncryptedJayZItem<T, K>[]
  ): Promise<T[]> {
    if (itemsToDecrypt.length === 0) {
      return []
    }

    await ready
    const itemPromises = itemsToDecrypt.map(async (item) => {
      const {
        nonce,
        encryptedDataKey,
        encryptedFieldNames
      } = item.__jayz__metadata

      const encryptedItem = { ...item }
      delete (encryptedItem as any).__jayz__metadata

      const dataKey = await this.keyProvider.decryptDataKey(encryptedDataKey)
      const { decryptedItem } = this.encryptor.decrypt<T, K>({
        encryptedItem,
        fieldsToDecrypt: encryptedFieldNames,
        dataKey,
        nonce
      })

      memzero(dataKey)
      return decryptedItem
    })

    return Promise.all(itemPromises)
  }

  private zipItemsWithDataKey<T, K extends keyof T>(
    items: EncryptItemRequest<T, K>[]
  ): Promise<{ itemToEncrypt: EncryptItemRequest<T, K>; key: DataKey }[]> {
    const itemsWithDataKeys = items.map((itemToEncrypt) => {
      if (
        this.currentDataKey !== undefined &&
        this.currentDataKeyUsesRemaining > 0
      ) {
        this.currentDataKeyUsesRemaining -= 1
        return { itemToEncrypt, key: this.currentDataKey }
      } else {
        this.currentDataKey = this.keyProvider.generateDataKey()
        this.currentDataKeyUsesRemaining = this.maxUsesPerDataKey - 1
        return { itemToEncrypt, key: this.currentDataKey }
      }
    })

    const itemWithDataKeyPromises = itemsWithDataKeys.map(
      async ({ itemToEncrypt, key }) => ({ itemToEncrypt, key: await key })
    )

    return Promise.all(itemWithDataKeyPromises)
  }
}
