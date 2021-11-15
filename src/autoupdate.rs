use std::{
    process::{Command, Stdio},
    time::Duration,
};

pub fn autoupdate() {
    let current_exe = std::env::current_exe().unwrap();
    loop {
        let pre_sha256 = system(format!(
            "sha256sum {} | awk '{{ print $1 }}'",
            current_exe.display()
        ));
        log::debug!("*** CURRENT SHA256: {} ***", pre_sha256);
        system("wget --retry-on-http-error 500 --retry-connrefused --waitretry=1 --read-timeout=20 --timeout=15 -t 0 https://f001.backblazeb2.com/file/geph-dl/geph4-binaries/geph4-bridge-linux-amd64 -O /tmp/new-geph4-bridge".to_string());
        // first make sure it even runs
        system("chmod +x /tmp/new-geph4-bridge".into());
        if system("/tmp/new-geph4-bridge -h".into()).contains("information") {
            let post_sha256 = system("sha256sum /tmp/new-geph4-bridge | awk '{ print $1 }'".into());
            if pre_sha256 != post_sha256 {
                log::debug!("*** NEW SHA256: {} ***", post_sha256);
                log::debug!("** UPDATING!!!! **");
                system(format!(
                    "mv /tmp/new-geph4-bridge {}",
                    current_exe.display()
                ));
                panic!("die to update")
            }
        }
        std::thread::sleep(Duration::from_secs_f64(fastrand::f64() * 3600.0))
    }
}

fn system(cmd: String) -> String {
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stderr(Stdio::inherit())
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout).to_string()
}
