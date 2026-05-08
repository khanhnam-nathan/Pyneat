use std::process::Command;
use std::fs;
use std::io::Read;

fn main() {
    // TODO: implement command
    let output = Command::new("ls")
        .arg("-la")
        .output();

    // Debug statements
    println!("Debug: starting application");
    eprintln!("Error occurred");

    // TODO: BUG - fix this
    let mut file = fs::File::open("config.txt").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();

    // Unwrap usage
    let numbers = vec![1, 2, 3];
    let first = numbers.get(0).unwrap();

    // Unsafe block
    unsafe {
        println!("Unsafe code");
    }
}
