package fixtures;

class Account {
    String name;
    String role;
    boolean admin;
}

class AccountDto {
    String name;
    String role;
    boolean admin;
}

interface AccountRepository {
    Account save(Account account);
}
