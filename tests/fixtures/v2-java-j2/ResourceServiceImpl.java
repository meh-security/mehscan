package fixtures;

class ResourceServiceImpl implements ResourceService {
  ResourceRepository resourceRepository;
  UserService userService;

  public Object find(Long id) {
    return resourceRepository.findById(id);
  }

  public void delete(Long id) {
    resourceRepository.deleteById(id);
  }

  public Object findOwned(Long id, Object request) {
    User user = userService.getUserFromToken(request);
    return resourceRepository.findByOwner_id(user.getId());
  }
}

interface UserService {
  User getUserFromToken(Object request);
}
class User {
  Long getId() { return 1L; }
}
