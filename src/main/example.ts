import { KMSDataKeyProvider, JayZ } from "./index"
import { KMS } from "aws-sdk"

async function run() {
  const kmsKeyId = "..." // the KMS key id or arn you want to use
  const keyProvider = new KMSDataKeyProvider(kmsKeyId, new KMS())
  const jayZ = new JayZ(keyProvider)

  type BankAccount = {
    id: string
    accountNumber: string
    routingNumber: string
  }

  const bankAccount: BankAccount = {
    id: "1",
    accountNumber: "an-123",
    routingNumber: "rn-123"
  }

  const encrypted = await jayZ.encryptItem(bankAccount, [
    "accountNumber",
    "routingNumber"
  ])

  const decryptedItem = await jayZ.decryptItem(encrypted)
}
