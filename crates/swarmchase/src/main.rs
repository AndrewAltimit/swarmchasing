//! The `swarmchase` binary: everything is in the library ([`swarmchase::run`]).
//! Exit status: 0 ok, 1 an error, 2 a usage error, 3 a floor not met, 4 a
//! watch run with alerts ([`swarmchase::exit`]).

fn main() -> std::process::ExitCode {
    swarmchase::exit_status(swarmchase::run())
}
