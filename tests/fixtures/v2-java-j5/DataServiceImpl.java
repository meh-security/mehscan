package fixtures;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.BeanUtils;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import java.util.Map;

class DataServiceImpl implements DataService {
    EntityManager entityManager;
    JdbcTemplate jdbcTemplate;
    NamedParameterJdbcTemplate namedJdbcTemplate;
    AccountRepository accountRepository;
    ObjectMapper objectMapper;

    public Object unsafeJpa(String name) {
        return entityManager.createNativeQuery("select * from account where name='" + name + "'").getResultList();
    }

    public Object unsafeJdbc(String name) {
        return jdbcTemplate.queryForList("select * from account where name='" + name + "'");
    }

    public Object safeJpa(String name) {
        Query query = entityManager.createQuery("select a from Account a where a.name = :name");
        return query.setParameter("name", name).getResultList();
    }

    public Object safeNamed(String name) {
        Map<String, Object> parameters = Map.of("name", name);
        return namedJdbcTemplate.queryForList(
            "select * from account where name = :name", parameters);
    }

    public Account direct(Account account) {
        return accountRepository.save(account);
    }

    public Account copy(AccountDto dto) {
        Account account = new Account();
        BeanUtils.copyProperties(dto, account);
        return accountRepository.save(account);
    }

    public Account copySafe(AccountDto dto) {
        Account account = new Account();
        BeanUtils.copyProperties(dto, account, "role", "admin");
        return accountRepository.save(account);
    }

    public Account explicit(AccountDto dto) {
        Account account = new Account();
        account.setRole(dto.getRole());
        return accountRepository.save(account);
    }

    public Account jackson(String json) {
        Account account = new Account();
        objectMapper.readerForUpdating(account).readValue(json);
        return accountRepository.save(account);
    }
}
