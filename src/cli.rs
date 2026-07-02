use std::io::{self, IsTerminal, Write};

pub const RESET: &str = "\x1b[0m";
pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";
pub const RED: &str = "\x1b[31m";
pub const GREEN: &str = "\x1b[32m";
pub const YELLOW: &str = "\x1b[33m";
pub const MAGENTA: &str = "\x1b[35m";
pub const CYAN: &str = "\x1b[36m";

const BANNER: &str = r#"
██████╗  ██████╗ ██████╗  ██████╗ ██╗   ██╗██╗███╗   ██╗██╗  ██╗ ██████╗
██╔══██╗██╔═══██╗██╔══██╗██╔═══██╗██║   ██║██║████╗  ██║██║  ██║██╔═══██╗
██████╔╝██║   ██║██████╔╝██║   ██║██║   ██║██║██╔██╗ ██║███████║██║   ██║
██╔═══╝ ██║   ██║██╔══██╗██║▄▄ ██║██║   ██║██║██║╚██╗██║██╔══██║██║   ██║
██║     ╚██████╔╝██║  ██║╚██████╔╝╚██████╔╝██║██║ ╚████║██║  ██║╚██████╔╝
╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚══▀▀═╝  ╚═════╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝"#;

pub fn print_banner() {
    println!("{YELLOW}{BOLD}{BANNER}{RESET}");
    println!("{DIM}         your API key piggy bank{RESET}");
    println!();
}

pub fn success(message: &str) {
    println!("{GREEN}✔ {message}{RESET}");
}

pub fn error(message: &str) {
    println!("{RED}✘ {message}{RESET}");
}

pub fn info(message: &str) {
    println!("{DIM}{message}{RESET}");
}

fn read_line_or_exit() -> String {
    let mut input = String::new();
    if io::stdin().read_line(&mut input).unwrap() == 0 {
        println!();
        std::process::exit(0);
    }
    input.trim().to_string()
}

pub fn prompt(label: &str) -> String {
    print!("{YELLOW}{label}:{RESET} ");
    io::stdout().flush().unwrap();
    read_line_or_exit()
}

pub fn prompt_secret(label: &str) -> String {
    if io::stdin().is_terminal() {
        rpassword::prompt_password(format!("{MAGENTA}{label}:{RESET} ")).unwrap()
    } else {
        print!("{MAGENTA}{label}:{RESET} ");
        io::stdout().flush().unwrap();
        read_line_or_exit()
    }
}

pub fn prompt_command() -> String {
    print!("{CYAN}{BOLD}porquinho>{RESET} ");
    io::stdout().flush().unwrap();
    read_line_or_exit()
}
