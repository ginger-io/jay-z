import stringify from "fast-json-stable-stringify"
import {
  crypto_kdf_derive_from_key,
  crypto_secretbox_easy,
  crypto_secretbox_KEYBYTES,
  from_string,
} from "libsodium-wrappers"
import { LibsodiumEncryptor } from "../main/LibsodiumEncryptor"
import { StubDataKeyProvider } from "../main/StubDataKeyProvider"
import { KeyType } from "../main/types"
import { aBankAccount, BankAccount } from "./util"

describe("LibsodiumEncryptor", () => {
  const account = aBankAccount()
  const encryptor = new LibsodiumEncryptor()
  const fieldsToEncrypt: (keyof BankAccount)[] = [
    "accountNumber",
    "balance",
    "routingNumber",
    "notes",
  ]

  it("should encrypt an item", async () => {
    const dataKeyProvider = await StubDataKeyProvider.forLibsodium()
    const { dataKey } = await dataKeyProvider.generateDataKey()

    const { encryptedItem, nonce } = await encryptor.encrypt({
      item: account,
      fieldsToEncrypt,
      dataKey,
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
    const dataKeyProvider = await StubDataKeyProvider.forLibsodium()
    const { dataKey } = await dataKeyProvider.generateDataKey()

    const { encryptedItem, nonce } = await encryptor.encrypt({
      item: account,
      fieldsToEncrypt,
      dataKey,
    })

    const { decryptedItem } = await encryptor.decrypt({
      encryptedItem,
      nonce,
      dataKey,
      fieldsToDecrypt: fieldsToEncrypt,
    })

    expect(decryptedItem).toEqual(account)
  })

  it("should handle binary fields", async () => {
    const dataKeyProvider = await StubDataKeyProvider.forLibsodium()
    const { dataKey } = await dataKeyProvider.generateDataKey()

    const binaryItem = {
      name: "hello world",
      binaryData: Buffer.from("hello world", "utf-8"),
    }

    const { encryptedItem, nonce } = await encryptor.encrypt({
      item: binaryItem,
      fieldsToEncrypt: ["name", "binaryData"],
      dataKey,
    })

    const { decryptedItem } = await encryptor.decrypt({
      encryptedItem,
      nonce,
      dataKey,
      fieldsToDecrypt: ["name", "binaryData"],
    })

    expect(decryptedItem).toEqual(binaryItem)
  })
})
