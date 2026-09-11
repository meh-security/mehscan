package fixtures.lookalike;

interface JpaRepository<T, K> {}
interface FakeRepository extends JpaRepository<Object, Long> {}

class Lookalikes {
  FakeRepository fakeRepository;

  Object read(Long id) {
    return fakeRepository.findById(id);
  }
}
