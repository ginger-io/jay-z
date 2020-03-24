import {
  crypto_kdf_KEYBYTES,
  randombytes_buf,
  ready,
  to_base64
} from "libsodium-wrappers"
import { DataKey, DataKeyProvider } from "../main/DataKeyProvider"
import { JayZ, JayZConfig } from "../main/JayZ"
import { StubDataKeyProvider } from "../main/StubDataKeyProvider"
import { aBankAccount, BankAccount } from "./util"

describe("JayZ", () => {
  beforeAll(async () => await ready)

  const fieldsToEncrypt: (keyof BankAccount)[] = [
    "accountNumber",
    "balance",
    "routingNumber",
    "notes"
  ]

  it("should encrypt an item", async () => {
    const { jayz, bankAccount } = setup()
    const encryptedItem = await jayz.encryptItem(bankAccount, fieldsToEncrypt)

    expect(encryptedItem.pk).toEqual("account-123")
    expect(encryptedItem.sk).toEqual("Flava Flav")
    expect(encryptedItem.accountNumber).not.toEqual("123")
    expect(encryptedItem.routingNumber).not.toEqual("456")
    expect(encryptedItem.balance).not.toEqual(100)
    expect(encryptedItem.notes).not.toEqual({
      previousBalances: [0, 50]
    })
  })

  it("should decrypt an item", async () => {
    const { jayz, bankAccount } = setup()
    const encryptedItem = await jayz.encryptItem(bankAccount, fieldsToEncrypt)
    const decryptedItem = await jayz.decryptItem(encryptedItem)
    expect(decryptedItem).toEqual(bankAccount)
  })

  it("should not reuse data keys by default", async () => {
    const keyProvider = new CountingKeyProvider()
    const { jayz, bankAccount } = setup({
      keyProvider
    })

    expect(keyProvider.keysIssued).toEqual(0)
    await jayz.encryptItem(bankAccount, fieldsToEncrypt)
    expect(keyProvider.keysIssued).toEqual(1)

    await jayz.encryptItem(bankAccount, fieldsToEncrypt)
    expect(keyProvider.keysIssued).toEqual(2)
  })

  it("should reuse data keys when configured to do so", async () => {
    const keyProvider = new CountingKeyProvider()
    const { jayz, bankAccount } = setup({
      keyProvider,
      maxUsesPerDataKey: 2
    })

    const item1 = await jayz.encryptItem(bankAccount, fieldsToEncrypt)
    expect(keyProvider.keysIssued).toEqual(1)

    const item2 = await jayz.encryptItem(bankAccount, fieldsToEncrypt)
    expect(keyProvider.keysIssued).toEqual(1)

    const item3 = await jayz.encryptItem(bankAccount, fieldsToEncrypt)
    expect(keyProvider.keysIssued).toEqual(2)

    expect(await jayz.decryptItem(item1)).toEqual(bankAccount)
    expect(await jayz.decryptItem(item2)).toEqual(bankAccount)
    expect(await jayz.decryptItem(item3)).toEqual(bankAccount)
  })
})

function setup(
  config: JayZConfig = {
    keyProvider: new StubDataKeyProvider(
      to_base64(randombytes_buf(crypto_kdf_KEYBYTES))
    )
  }
): { bankAccount: BankAccount; jayz: JayZ } {
  const bankAccount = aBankAccount()
  const jayz = new JayZ(config)
  return { jayz, bankAccount }
}

class CountingKeyProvider implements DataKeyProvider {
  public keysIssued = 0

  async generateDataKey(): Promise<DataKey> {
    await ready
    const key = randombytes_buf(crypto_kdf_KEYBYTES)
    this.keysIssued += 1
    return {
      encryptedDataKey: key.slice(0),
      dataKey: key.slice(0)
    }
  }

  async decryptDataKey(encryptedDataKey: Uint8Array): Promise<Uint8Array> {
    return encryptedDataKey.slice(0)
  }
}
