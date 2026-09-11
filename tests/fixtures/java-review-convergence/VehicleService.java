package fixtures;

import org.springframework.data.jpa.repository.JpaRepository;

interface VehicleService {
  Object checkVehicle(VehicleForm vehicleForm, Object request);
  Object deleteProfileVideo(Long videoId);
}

interface VehicleDetailsRepository extends JpaRepository<VehicleDetails, Long> {
  VehicleDetails findByVin(String vin);
}

interface UserService {
  User getUserFromToken(Object request);
}

class VehicleForm {
  String getVin() { return ""; }
  String getPincode() { return ""; }
}

class VehicleDetails {
  String getPincode() { return ""; }
  void setOwner(User user) {}
}

class User {}

interface ProfileVideoRepository extends JpaRepository<ProfileVideo, Long> {}

class ProfileVideo {}
