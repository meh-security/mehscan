package fixtures;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;

class DataController {
    DataService dataService;

    @PostMapping("/jpa")
    Object unsafeJpa(@RequestParam String name) { return dataService.unsafeJpa(name); }

    @PostMapping("/jdbc")
    Object unsafeJdbc(@RequestParam String name) { return dataService.unsafeJdbc(name); }

    @PostMapping("/safe-jpa")
    Object safeJpa(@RequestParam String name) { return dataService.safeJpa(name); }

    @PostMapping("/safe-named")
    Object safeNamed(@RequestParam String name) { return dataService.safeNamed(name); }

    @PostMapping("/direct")
    Object direct(@RequestBody Account account) { return dataService.direct(account); }

    @PostMapping("/copy")
    Object copy(@RequestBody AccountDto dto) { return dataService.copy(dto); }

    @PostMapping("/copy-safe")
    Object copySafe(@RequestBody AccountDto dto) { return dataService.copySafe(dto); }

    @PostMapping("/explicit")
    Object explicit(@RequestBody AccountDto dto) { return dataService.explicit(dto); }

    @PostMapping("/jackson")
    Object jackson(@RequestBody String json) { return dataService.jackson(json); }
}
