package fixtures;

import org.springframework.data.jpa.repository.JpaRepository;

interface ResourceRepository extends JpaRepository<Resource, Long> {
  Resource findByOwner_id(Long id);
}

class Resource {}
