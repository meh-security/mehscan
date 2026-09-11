package fixtures;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

class VehicleController {
  VehicleService vehicleService;

  @PostMapping("/vehicle/claim")
  Object claim(@RequestBody VehicleForm vehicleForm, Object request) {
    return vehicleService.checkVehicle(vehicleForm, request);
  }

  @DeleteMapping("/videos/{video_id}")
  Object delete(@PathVariable("video_id") Long videoId) {
    return vehicleService.deleteProfileVideo(videoId);
  }
}
