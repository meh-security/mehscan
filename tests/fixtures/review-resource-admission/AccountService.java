package fixtures;

class AccountService {
  AccountRepository accounts;

  Object fixedAccount() {
    return accounts.findById(1L);
  }

  Object dynamicAccount(Long id) {
    return accounts.findById(id);
  }
}
