package fixtures;

import org.springframework.data.jpa.repository.JpaRepository;

interface AccountRepository extends JpaRepository<Account, Long> {}

class Account {}
