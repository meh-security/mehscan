package fixtures;

@interface GetMapping {
  String value();
}
@interface RequestParam {}
@interface RequestPart {}

class MultipartFile {}

class Lookalikes {
  @GetMapping("/fake")
  void fake(@RequestParam String value, @RequestPart MultipartFile file) {}

  void helper(String value) {}
}
