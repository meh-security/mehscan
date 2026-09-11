package fixtures;

import java.util.Optional;

class VehicleServiceImpl implements VehicleService {
  VehicleDetailsRepository vehicleDetailsRepository;
  UserService userService;
  ProfileVideoRepository profileVideoRepository;

  public Object checkVehicle(VehicleForm vehicleForm, Object request) {
    VehicleDetails checkVehicle = null;
    User user = null;
    checkVehicle = vehicleDetailsRepository.findByVin(vehicleForm.getVin());
    user = userService.getUserFromToken(request);
    if (checkVehicle != null
        && checkVehicle.getPincode().equalsIgnoreCase(vehicleForm.getPincode())) {
      checkVehicle.setOwner(user);
      vehicleDetailsRepository.save(checkVehicle);
      return checkVehicle;
    }
    return null;
  }

  public Object deleteProfileVideo(Long videoId) {
    Optional<ProfileVideo> optionalProfileVideo = profileVideoRepository.findById(videoId);
    if (optionalProfileVideo.isPresent()) {
      return new Response(403);
    }
    return new Response(404);
  }
}

class Response {
  Response(int status) {}
}
