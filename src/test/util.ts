export interface BankAccount {
  pk: string // "bank-account-123",
  sk: string // "Flava Flav",
  accountNumber: string
  routingNumber: string
  balance: number
  notes: {
    [key: string]: any
  }
}

export function aBankAccount(): BankAccount {
  return {
    pk: "account-123",
    sk: "Flava Flav",
    accountNumber: "123",
    routingNumber: "456",
    balance: 100,
    notes: {
      previousBalances: [0, 50]
    }
  }
}
