import jakarta.persistence.EntityManager as Manager

class Queries(private val manager: Manager) {
    fun lookup(name: String) = manager.createQuery("SELECT o FROM Owner o WHERE o.name = '$name'")
}
