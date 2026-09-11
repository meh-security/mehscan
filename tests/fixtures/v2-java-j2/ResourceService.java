package fixtures;

interface ResourceService {
  Object find(Long id);
  void delete(Long id);
  Object findOwned(Long id, Object request);
}
