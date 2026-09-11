struct Command;
struct Url;
struct Client;

impl Command {
    fn new(_: &str) -> Self { Self }
    fn arg(self, _: &str) -> Self { self }
}

impl Url {
    fn parse(_: &str) -> Self { Self }
}

impl Client {
    fn danger_accept_invalid_certs(self, _: bool) -> Self { self }
}

fn unrelated(command: &str, value: &str) {
    let _ = Command::new(command).arg(value);
    let _ = Url::parse(value);
    let _ = Client.danger_accept_invalid_certs(true);
}
