use super::structs::Command;
use crossterm::style::Stylize;
use pyo3::types::{PyAnyMethods, PyList, PyListMethods};
use pyo3::{PyResult, Python};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

fn check_security(path: &Path) -> Result<(), String> {
    let metadata = fs::metadata(path).map_err(|e| e.to_string())?;
    let file_uid = metadata.uid();
    let current_uid = unsafe { libc::geteuid() };

    if current_uid != file_uid {
        return Err(format!(
            "{} Running with UID {}, but file '{}' is owned by UID {}. Aborting to prevent privilege escalation.",
            "SECURITY ERROR:".red().bold(),
            current_uid,
            path.display(),
            file_uid
        ));
    }

    if metadata.permissions().mode() & 0o022 == 0 {
        return Err(format!(
            "{} Python rule '{}' is writable by non-owners. Aborting to prevent privilege escalation.",
            "SECURITY ERROR:".red().bold(),
            path.display()
        ));
    }

    Ok(())
}

pub fn process_python_rules(
    command: &Command,
    rule_paths: Vec<PathBuf>,
) -> Result<Vec<String>, String> {
    if rule_paths.is_empty() {
        return Ok(vec![]);
    }
    let module_path = get_common_parent(&rule_paths)
        .ok_or("No common parent found for rule paths".to_string())?;
    let mut fixed_commands: Vec<String> = vec![];
    pyo3::prepare_freethreaded_python();
    Python::with_gil(|py| -> PyResult<()> {
        {
            let raw_sys_path = py.import("sys")?.getattr("path")?;
            let sys_path = raw_sys_path.downcast::<PyList>()?;
            sys_path.insert(0, module_path.to_string_lossy())?;
        }

        for rule_path in rule_paths {
            if let Err(e) = check_security(&rule_path) {
                eprintln!("{}", e);
                continue;
            }

            let module_name = match get_module_name(&module_path, &rule_path) {
                Some(module_name) => module_name,
                None => continue,
            };
            let module = match py.import(&module_name) {
                Ok(module) => module,
                Err(e) => {
                    eprintln!(
                        "{}{}{}",
                        "Failed to import rule module '".yellow(),
                        rule_path.display(),
                        "': ".yellow(),
                    );
                    eprintln!("{e}");
                    continue;
                }
            };
            let match_func = match module.getattr("match") {
                Ok(func) => func,
                Err(e) => {
                    eprintln!(
                        "{}{}{}",
                        "Failed to get 'match' function from rule '".yellow(),
                        rule_path.display(),
                        "': ".yellow(),
                    );
                    eprintln!("{e}");
                    continue;
                }
            };
            let fix_func = match module.getattr("fix") {
                Ok(func) => func,
                Err(e) => {
                    eprintln!(
                        "{}{}{}",
                        "Failed to get 'fix' function from rule '".yellow(),
                        rule_path.display(),
                        "': ".yellow(),
                    );
                    eprintln!("{e}");
                    continue;
                }
            };
            if match_func.is_callable() && fix_func.is_callable() {
                let is_match = match match_func
                    .call1((
                        command.command(),
                        command.output().stdout(),
                        command.output().stderr(),
                    ))
                    .and_then(|result| result.extract::<bool>())
                {
                    Ok(result) => result,
                    Err(e) => {
                        eprintln!(
                            "{}{}{}",
                            "Failed to execute 'match' function in rule '".yellow(),
                            rule_path.display(),
                            "': ".yellow(),
                        );
                        eprintln!("{e}");
                        continue;
                    }
                };
                if is_match {
                    let fixed_command: String = match fix_func
                        .call1((
                            command.command(),
                            command.output().stdout(),
                            command.output().stderr(),
                        ))
                        .and_then(|result| result.extract())
                    {
                        Ok(cmd) => cmd,
                        Err(e) => {
                            eprintln!(
                                "{}{}{}",
                                "Failed to execute 'fix' function in rule '".yellow(),
                                rule_path.display(),
                                "': ".yellow(),
                            );
                            eprintln!("{e}");
                            continue;
                        }
                    };
                    fixed_commands.push(fixed_command);
                }
            } else {
                eprintln!(
                    "{}{}{}",
                    "Rule '".yellow(),
                    rule_path.display(),
                    "' is missing required functions (match, fix)".yellow()
                );
            }
        }
        Ok(())
    })
    .map_err(|err| format!("Failed to process Python rules: {err}"))?;
    Ok(fixed_commands)
}

fn get_module_name(modules_dir_path: &Path, rule_path: &Path) -> Option<String> {
    let mut module_path = match rule_path.strip_prefix(modules_dir_path) {
        Ok(module_path) => module_path.parent().unwrap_or(Path::new("")).to_path_buf(),
        Err(_) => {
            eprintln!(
                "{}{}{}",
                "Rule path '".yellow(),
                rule_path.display(),
                "' is not a subpath of the common parent".yellow()
            );
            return None;
        }
    };
    match rule_path.file_stem() {
        Some(module_stem) => {
            module_path.push(module_stem);
        }
        None => {
            eprintln!(
                "{}{}{}",
                "Rule path '".yellow(),
                rule_path.display(),
                "' has no valid file stem".yellow()
            );
            return None;
        }
    }
    Some(module_path.to_string_lossy().replace(['/', '\\'], "."))
}

fn get_common_parent(paths: &[PathBuf]) -> Option<PathBuf> {
    if paths.is_empty() {
        return None;
    }

    if paths.len() == 1 {
        return Some(paths[0].parent().unwrap_or(Path::new("")).to_path_buf());
    }

    let mut iter = paths.iter();
    let first = iter.next()?.components().collect::<Vec<_>>();

    let common = iter.fold(first, |acc, path| {
        let comps = path.components().collect::<Vec<_>>();
        acc.iter()
            .zip(&comps)
            .take_while(|(a, b)| a == b)
            .map(|(a, _)| *a)
            .collect()
    });

    if common.is_empty() {
        None
    } else {
        Some(common.iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fix::structs::CommandOutput;
    use std::fs;
    use std::io::Write;
    use tempfile::tempdir;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn dummy_command() -> Command {
        let output = CommandOutput::new(String::new(), String::new());
        Command::new("test".to_string(), output)
    }

    #[test]
    fn common_parent_empty() {
        assert_eq!(get_common_parent(&[]), None);
    }

    #[test]
    fn common_parent_single() {
        let paths = vec![PathBuf::from("/a/b/c.py")];
        assert_eq!(get_common_parent(&paths), Some(PathBuf::from("/a/b")));
    }

    #[test]
    fn common_parent_multiple_with_common() {
        let paths = vec![
            PathBuf::from("/a/b/c/d.py"),
            PathBuf::from("/a/b/c/e.py"),
            PathBuf::from("/a/b/c/f/g.py"),
        ];
        assert_eq!(get_common_parent(&paths), Some(PathBuf::from("/a/b/c")));
    }

    #[test]
    fn common_parent_root() {
        let paths = vec![PathBuf::from("/a/b/c.py"), PathBuf::from("/d/e/f.py")];
        assert_eq!(get_common_parent(&paths), Some(PathBuf::from("/")));
    }

    #[test]
    fn module_name_valid() {
        let modules_dir = PathBuf::from("/root/modules");
        let rule_path = PathBuf::from("/root/modules/sub/dir/rule.py");
        assert_eq!(
            get_module_name(&modules_dir, &rule_path),
            Some("sub.dir.rule".to_string())
        );
    }

    #[test]
    fn module_name_not_subpath() {
        let modules_dir = PathBuf::from("/root/modules");
        let rule_path = PathBuf::from("/other/place/rule.py");
        assert_eq!(get_module_name(&modules_dir, &rule_path), None);
    }

    #[test]
    fn module_name_no_file_stem() {
        let modules_dir = PathBuf::from("/root");
        let rule_path = PathBuf::from("/");
        assert_eq!(get_module_name(&modules_dir, &rule_path), None);
    }

    fn create_rule_file(dir: &Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut file = fs::File::create(&path).unwrap();
        write!(file, "{}", content).unwrap();

        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o400);
            fs::set_permissions(&path, perms).unwrap();
        }

        path
    }

    #[cfg(unix)]
    #[test]
    fn create_rule_file_sets_correct_permissions() {
        let temp = tempdir().unwrap();
        let path = create_rule_file(temp.path(), "perm_check.py", "print('test')");
        let metadata = fs::metadata(&path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o400, "File permissions should be set to 400");
    }

    #[cfg(unix)]
    #[test]
    fn import_fails_if_file_not_readable() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("no_read.py");
        {
            let mut file = fs::File::create(&path).unwrap();
            writeln!(file, "def match(c,o,e): return True").unwrap();
            writeln!(file, "def fix(c,o,e): return 'fixed'").unwrap();
        }
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o200);
        fs::set_permissions(&path, perms).unwrap();

        if fs::File::open(&path).is_ok() {
            return;
        }

        let cmd = dummy_command();
        let result = process_python_rules(&cmd, vec![path]);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn process_single_rule_match() {
        let temp = tempdir().unwrap();
        let rule_path = create_rule_file(
            temp.path(),
            "match_ok.py",
            r#"
def match(command, stdout, stderr):
    return True
def fix(command, stdout, stderr):
    return "fixed-command"
"#,
        );
        let cmd = dummy_command();
        let result = process_python_rules(&cmd, vec![rule_path]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec!["fixed-command".to_string()]);
    }

    #[test]
    fn process_rule_no_match() {
        let temp = tempdir().unwrap();
        let rule_path = create_rule_file(
            temp.path(),
            "no_match.py",
            r#"
def match(command, stdout, stderr):
    return False
def fix(command, stdout, stderr):
    return "should-not-be-called"
"#,
        );
        let cmd = dummy_command();
        let result = process_python_rules(&cmd, vec![rule_path]);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn process_rule_missing_match_func() {
        let temp = tempdir().unwrap();
        let rule_path = create_rule_file(
            temp.path(),
            "missing_match.py",
            r#"
def fix(command, stdout, stderr):
    return "something"
"#,
        );
        let cmd = dummy_command();
        let result = process_python_rules(&cmd, vec![rule_path]);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn process_rule_match_raises() {
        let temp = tempdir().unwrap();
        let rule_path = create_rule_file(
            temp.path(),
            "match_raises.py",
            r#"
def match(command, stdout, stderr):
    raise ValueError("oops")
def fix(command, stdout, stderr):
    return "fixed"
"#,
        );
        let cmd = dummy_command();
        let result = process_python_rules(&cmd, vec![rule_path]);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn process_rule_fix_raises() {
        let temp = tempdir().unwrap();
        let rule_path = create_rule_file(
            temp.path(),
            "fix_raises.py",
            r#"
def match(command, stdout, stderr):
    return True
def fix(command, stdout, stderr):
    raise Exception("fix failed")
"#,
        );
        let cmd = dummy_command();
        let result = process_python_rules(&cmd, vec![rule_path]);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn process_multiple_rules() {
        let temp = tempdir().unwrap();
        let rule1 = create_rule_file(
            temp.path(),
            "multi1.py",
            r#"
def match(c, o, e): return True
def fix(c, o, e): return "cmd1"
"#,
        );
        let rule2 = create_rule_file(
            temp.path(),
            "multi2.py",
            r#"
def match(c, o, e): return False
def fix(c, o, e): return "cmd2"
"#,
        );
        let rule3 = create_rule_file(
            temp.path(),
            "multi3.py",
            r#"
def match(c, o, e): return True
def fix(c, o, e): return "cmd3"
"#,
        );
        let cmd = dummy_command();
        let result = process_python_rules(&cmd, vec![rule1, rule2, rule3]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec!["cmd1".to_string(), "cmd3".to_string()]);
    }

    #[test]
    fn process_no_common_parent() {
        let paths = vec![PathBuf::from("a/b.py"), PathBuf::from("c/d.py")];
        let cmd = dummy_command();
        let result = process_python_rules(&cmd, paths);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No common parent found"));
    }

    #[test]
    fn process_empty_rules() {
        let cmd = dummy_command();
        let result = process_python_rules(&cmd, vec![]);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}
