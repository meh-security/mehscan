use std::process::Command as Process;

fn rust_alias_case(command: &str) {
    Process::new(command);
}

mod lookalike {
    pub struct Command;

    impl Command {
        pub fn new(_command: &str) -> Self {
            Self
        }
    }
}

fn unrelated(command: &str) {
    lookalike::Command::new(command);
}
