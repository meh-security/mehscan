struct Path<T>(T);

fn custom(Path(command): Path<String>) {
    std::process::Command::new(command).spawn();
}
