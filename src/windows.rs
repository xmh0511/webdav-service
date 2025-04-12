// use elevated_command::Command;
// use std::process::Command as StdCommand;

use runas::Command;

pub fn run_command(cmd_str: &str) -> std::io::Result<()> {
    let mut cmd = Command::new("cmd.exe");
    let s = cmd
        .args(&["/C", cmd_str])
        .status()
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    if s.success() {
        return Ok(());
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        format!("run command failed:{cmd_str}"),
    ))
}

use winreg::RegKey;
use winreg::enums::*; // 引入 HKEY_CURRENT_USER, KEY_WRITE, KEY_READ 等
pub fn permit_http_auth(r: bool) -> std::io::Result<()> {
    let hkcu = RegKey::predef(HKEY_LOCAL_MACHINE);
    let path = r"SYSTEM\CurrentControlSet\Services\WebClient\Parameters";
    let (my_app_key, disposition) = hkcu.create_subkey_with_flags(path, KEY_WRITE | KEY_READ)?;
    match disposition {
        REG_CREATED_NEW_KEY => println!("成功创建新键: HKCU\\{}", path),
        REG_OPENED_EXISTING_KEY => println!("成功打开已存在的键: HKCU\\{}", path),
    }
    let value: u32 = if r { 2 } else { 1 };
    my_app_key.set_value("BasicAuthLevel", &value)?;
    Ok(())
}
