import {
  crypto_kdf_KEYBYTES,
  randombytes_buf,
  ready,
  to_base64
} from "libsodium-wrappers"
import { JayZ } from "../main/JayZ"
import { StubDataKeyProvider } from "../main/StubDataKeyProvider"
import { aBankAccount, BankAccount } from "./util"

describe("JayZ", () => {
  beforeAll(async () => await ready)

  it("should encrypt an item", async () => {
    const { jayz, bankAccount } = setup()
    const encryptedItem = await jayz.encryptItem(bankAccount, [
      "accountNumber",
      "balance",
      "routingNumber",
      "notes"
    ])

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
    const encryptedItem = await jayz.encryptItem(bankAccount, [
      "accountNumber",
      "balance",
      "routingNumber",
      "notes"
    ])

    const decryptedItem = await jayz.decryptItem(encryptedItem)

    expect(decryptedItem).toEqual(bankAccount)
  })
})

function setup(): { bankAccount: BankAccount; jayz: JayZ } {
  const key = randombytes_buf(crypto_kdf_KEYBYTES)
  const provider = new StubDataKeyProvider(to_base64(key))
  const bankAccount = aBankAccount()
  const jayz = new JayZ(provider)
  return { jayz, bankAccount }
}
