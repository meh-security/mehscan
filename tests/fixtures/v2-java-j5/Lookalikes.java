package fixtures;

class EntityManager { Object createNativeQuery(String query) { return null; } }
class JdbcTemplate { Object queryForList(String query) { return null; } }
class BeanUtils { static void copyProperties(Object source, Object target) {} }

class Lookalikes {
    EntityManager entityManager;
    JdbcTemplate jdbcTemplate;

    void inspect(String value) {
        entityManager.createNativeQuery(value);
        jdbcTemplate.queryForList(value);
        BeanUtils.copyProperties(value, new Object());
    }
}
