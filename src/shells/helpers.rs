use super::enums::Shell;
use std::str::FromStr;
use std::{env, process};
use sysinfo::{Pid, ProcessRefreshKind, RefreshKind, System};

pub trait ProcessInspector {
    fn get_parent_pid(&self, pid: u32) -> Option<u32>;
    fn get_exe_name(&self, pid: u32) -> Option<String>;
}

struct SysinfoInspector<'a> {
    system: &'a System,
}

impl<'a> ProcessInspector for SysinfoInspector<'a> {
    fn get_parent_pid(&self, pid: u32) -> Option<u32> {
        self.system
            .process(Pid::from_u32(pid))
            .and_then(|p| p.parent().map(|pid| pid.as_u32()))
    }

    fn get_exe_name(&self, pid: u32) -> Option<String> {
        self.system
            .process(Pid::from_u32(pid))
            .and_then(|p| p.exe())
            .and_then(|path| path.file_name())
            .and_then(|name| name.to_str())
            .map(|s| s.to_string())
    }
}

pub fn get_current_shell() -> Option<Shell> {
    get_current_shell_by_env().or_else(get_current_shell_by_process)
}

fn get_current_shell_by_env() -> Option<Shell> {
    env::var("SH_SHELL")
        .ok()
        .and_then(|shell| Shell::from_str(shell.as_str()).ok())
}

fn find_shell_in_process_tree(inspector: &impl ProcessInspector, start_pid: u32) -> Option<Shell> {
    let mut current_process = start_pid;
    loop {
        if let Some(exe_name) = inspector.get_exe_name(current_process)
            && let Ok(shell) = Shell::from_str(&exe_name)
        {
            return Some(shell);
        }

        match inspector.get_parent_pid(current_process) {
            Some(parent_pid) if parent_pid != 0 => current_process = parent_pid,
            _ => return None,
        }
    }
}

fn get_current_shell_by_process() -> Option<Shell> {
    let mut system = System::new();
    system
        .refresh_specifics(RefreshKind::nothing().with_processes(ProcessRefreshKind::everything()));
    let inspector = SysinfoInspector { system: &system };
    find_shell_in_process_tree(&inspector, process::id())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct MockProcessTree {
        parents: HashMap<u32, u32>,
        names: HashMap<u32, String>,
    }

    impl ProcessInspector for MockProcessTree {
        fn get_parent_pid(&self, pid: u32) -> Option<u32> {
            self.parents.get(&pid).copied()
        }

        fn get_exe_name(&self, pid: u32) -> Option<String> {
            self.names.get(&pid).cloned()
        }
    }

    #[test]
    fn find_shell_immediately_at_start_process() {
        let tree = MockProcessTree {
            parents: HashMap::new(),
            names: HashMap::from([(100, "bash".to_string())]),
        };

        let shell = find_shell_in_process_tree(&tree, 100);
        assert!(matches!(shell, Some(Shell::Bash)));
    }

    #[test]
    fn find_shell_deep_in_tree() {
        let tree = MockProcessTree {
            parents: HashMap::from([(300, 200), (200, 100)]),
            names: HashMap::from([
                (100, "bash".to_string()),
                (200, "cargo".to_string()),
                (300, "my_cli_app".to_string()),
            ]),
        };

        let shell = find_shell_in_process_tree(&tree, 300);
        assert!(matches!(shell, Some(Shell::Bash)));
    }

    #[test]
    fn find_shell_skips_non_shell_processes() {
        let tree = MockProcessTree {
            parents: HashMap::from([(400, 300), (300, 200), (200, 100)]),
            names: HashMap::from([
                (100, "zsh".to_string()),
                (200, "node".to_string()),
                (300, "npm".to_string()),
                (400, "my_app".to_string()),
            ]),
        };

        let shell = find_shell_in_process_tree(&tree, 400);
        assert!(matches!(shell, Some(Shell::Zsh)));
    }

    #[test]
    fn no_shell_found_when_no_parent_pid() {
        let tree = MockProcessTree {
            parents: HashMap::new(),
            names: HashMap::from([(100, "cargo".to_string())]),
        };

        let shell = find_shell_in_process_tree(&tree, 100);
        assert!(matches!(shell, None));
    }

    #[test]
    fn no_shell_found_when_parent_pid_is_zero() {
        let tree = MockProcessTree {
            parents: HashMap::from([(100, 0)]),
            names: HashMap::from([
                (100, "cargo".to_string()),
                (0, "init".to_string()),
            ]),
        };

        let shell = find_shell_in_process_tree(&tree, 100);
        assert!(matches!(shell, None));
    }

    #[test]
    fn find_first_matching_shell_in_hierarchy() {
        let tree = MockProcessTree {
            parents: HashMap::from([(500, 400), (400, 300), (300, 200), (200, 100)]),
            names: HashMap::from([
                (100, "bash".to_string()),
                (200, "fish".to_string()),
                (300, "zsh".to_string()),
                (400, "cargo".to_string()),
                (500, "my_app".to_string()),
            ]),
        };

        let shell = find_shell_in_process_tree(&tree, 500);
        assert!(matches!(shell, Some(Shell::Zsh)));
    }

    #[test]
    fn no_shell_found_with_missing_exe_names() {
        let tree = MockProcessTree {
            parents: HashMap::from([(300, 200), (200, 100)]),
            names: HashMap::new(),
        };

        let shell = find_shell_in_process_tree(&tree, 300);
        assert!(matches!(shell, None));
    }

    #[test]
    fn no_shell_found_with_valid_shell_names() {
        let tree = MockProcessTree {
            parents: HashMap::from([(300, 200), (200, 100)]),
            names: HashMap::from([
                (100, "bash_unknown".to_string()),
                (200, "zsh_custom".to_string()),
                (300, "my_cli_app".to_string()),
            ]),
        };

        let shell = find_shell_in_process_tree(&tree, 300);
        assert!(matches!(shell, None));
    }

    #[test]
    fn find_fish_shell_in_process_tree() {
        let tree = MockProcessTree {
            parents: HashMap::from([(200, 100)]),
            names: HashMap::from([
                (100, "fish".to_string()),
                (200, "cargo".to_string()),
            ]),
        };

        let shell = find_shell_in_process_tree(&tree, 200);
        assert!(matches!(shell, Some(Shell::Fish)));
    }

    #[test]
    fn find_zsh_shell_in_process_tree() {
        let tree = MockProcessTree {
            parents: HashMap::from([(200, 100)]),
            names: HashMap::from([
                (100, "zsh".to_string()),
                (200, "cargo".to_string()),
            ]),
        };

        let shell = find_shell_in_process_tree(&tree, 200);
        assert!(matches!(shell, Some(Shell::Zsh)));
    }
}
