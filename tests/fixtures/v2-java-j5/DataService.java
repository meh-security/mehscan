package fixtures;

interface DataService {
    Object unsafeJpa(String name);
    Object unsafeJdbc(String name);
    Object safeJpa(String name);
    Object safeNamed(String name);
    Account direct(Account account);
    Account copy(AccountDto dto);
    Account copySafe(AccountDto dto);
    Account explicit(AccountDto dto);
    Account jackson(String json);
}
