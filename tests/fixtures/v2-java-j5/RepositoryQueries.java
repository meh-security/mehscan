package fixtures;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

interface RepositoryQueries {
    @Query(value = "select * from account where name = :name", nativeQuery = true)
    Object byName(@Param("name") String name);

    @Query("select a from Account a where a.enabled = true")
    Object enabled();
}
