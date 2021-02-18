import stringify from "fast-json-stable-stringify"
import {
  crypto_kdf_derive_from_key,
  crypto_secretbox_easy,
  crypto_secretbox_KEYBYTES,
  from_string
} from "libsodium-wrappers"
import { LibsodiumEncryptor } from "../main/LibsodiumEncryptor"
import { FixedDataKeyProvider } from "../main/FixedDataKeyProvider"
import { KeyType } from "../main/types"
import { aBankAccount, BankAccount } from "./util"

describe("LibsodiumEncryptor", () => {
  const account = aBankAccount()
  const encryptor = new LibsodiumEncryptor()
  const fieldsToEncrypt: (keyof BankAccount)[] = [
    "accountNumber",
    "balance",
    "routingNumber",
    "notes"
  ]

  it("should encrypt an item", async () => {
    const dataKeyProvider = await FixedDataKeyProvider.forLibsodium()
    const { dataKey } = await dataKeyProvider.generateDataKey()

    const { encryptedItem, nonce } = await encryptor.encrypt({
      item: account,
      fieldsToEncrypt,
      dataKey
    })

    expect(encryptedItem.pk).toEqual("account-123")
    expect(encryptedItem.sk).toEqual("Flava Flav")

    const encryptionKey = crypto_kdf_derive_from_key(
      crypto_secretbox_KEYBYTES,
      KeyType.ENCRYPTION,
      "__jayz__",
      dataKey
    )

    fieldsToEncrypt.forEach((fieldName) => {
      const expectedValue = crypto_secretbox_easy(
        from_string(stringify(account[fieldName])),
        nonce,
        encryptionKey
      )

      expect(encryptedItem[fieldName]).toEqual(expectedValue)
    })
  })

  it("should decrypt an item", async () => {
    const dataKeyProvider = await FixedDataKeyProvider.forLibsodium()
    const { dataKey } = await dataKeyProvider.generateDataKey()

    const { encryptedItem, nonce } = await encryptor.encrypt({
      item: account,
      fieldsToEncrypt,
      dataKey
    })

    const { decryptedItem } = await encryptor.decrypt({
      encryptedItem,
      nonce,
      dataKey,
      fieldsToDecrypt: fieldsToEncrypt
    })

    expect(decryptedItem).toEqual(account)
  })

  it("should decrypt an item with undefined field", async () => {
    const fieldsToEncrypt: (keyof BankAccount)[] = [
      "accountNumber",
      "balance",
      "routingNumber",
      "notes",
      "bankName"
    ]

    const dataKeyProvider = await FixedDataKeyProvider.forLibsodium()
    const { dataKey } = await dataKeyProvider.generateDataKey()

    const item = { ...account, bankName: undefined }
    const { encryptedItem, nonce } = await encryptor.encrypt({
      item,
      fieldsToEncrypt,
      dataKey
    })

    const { decryptedItem } = await encryptor.decrypt({
      encryptedItem,
      nonce,
      dataKey,
      fieldsToDecrypt: fieldsToEncrypt
    })

    expect(decryptedItem).toEqual(item)
  })

  it("should encrypt and decrypt binary fields", async () => {
    const dataKeyProvider = await FixedDataKeyProvider.forLibsodium()
    const { dataKey } = await dataKeyProvider.generateDataKey()

    const binaryItem = {
      name: "hello world",
      binaryData: Buffer.from("hello world", "utf-8")
    }

    const { encryptedItem, nonce } = await encryptor.encrypt({
      item: binaryItem,
      fieldsToEncrypt: ["name", "binaryData"],
      dataKey
    })

    const { decryptedItem } = await encryptor.decrypt({
      encryptedItem,
      nonce,
      dataKey,
      fieldsToDecrypt: ["name", "binaryData"]
    })

    expect(decryptedItem).toEqual(binaryItem)
  })

  it("should encrypt and decrypt binary fields recursively", async () => {
    const dataKeyProvider = await FixedDataKeyProvider.forLibsodium()
    const { dataKey } = await dataKeyProvider.generateDataKey()

    const binaryItem = {
      name: "hello world",
      data: {
        otherData: {
          binaryData: Buffer.from("hello world", "utf-8")
        }
      }
    }

    const { encryptedItem, nonce } = await encryptor.encrypt({
      item: binaryItem,
      fieldsToEncrypt: ["name", "data"],
      dataKey
    })

    const { decryptedItem } = await encryptor.decrypt({
      encryptedItem,
      nonce,
      dataKey,
      fieldsToDecrypt: ["name", "data"]
    })

    expect(decryptedItem).toEqual(binaryItem)
  })
})
