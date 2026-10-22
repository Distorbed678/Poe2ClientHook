//! The job file and results file of `gen_batch` (pure text handling, tested on the host).

use std::{collections::HashSet, path::Path};

/// One line of the job file: `area seed topology orientation`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Job {
    pub area: String,
    pub seed: u32,
    /// 1-based index (`map_force_topology`); 0: not forced.
    pub topology: u32,
    /// 0..=7; negative: not forced.
    pub orientation: i32,
}

impl Job {
    pub fn parse(line: &str) -> Option<Job> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let mut f = line.split_whitespace();
        Some(Job {
            area: f.next()?.to_owned(),
            seed: f.next()?.parse().ok()?,
            topology: f.next()?.parse().ok()?,
            orientation: f.next()?.parse().ok()?,
        })
    }

    /// The four key columns of a results line.
    pub fn key(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}",
            self.area, self.seed, self.topology, self.orientation
        )
    }

    pub fn dir_name(&self) -> String {
        format!(
            "{}_{}_{}_{}",
            self.area, self.seed, self.topology, self.orientation
        )
    }
}

/// Jobs of a file (comments and malformed lines skipped).
pub fn read_jobs(path: &Path) -> Vec<Job> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(Job::parse)
        .collect()
}

/// The keys of the jobs a results file already holds (complete lines only: 11 columns, the
/// last one, `detail`, may be empty).
pub fn done_keys(text: &str) -> HashSet<String> {
    text.lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (f.len() >= 10).then(|| f[..4].join("\t"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_lines_parse() {
        let j = Job::parse("G1_8 1001 1 3").unwrap();
        assert_eq!(
            j,
            Job {
                area: "G1_8".into(),
                seed: 1001,
                topology: 1,
                orientation: 3
            }
        );
        assert_eq!(j.key(), "G1_8\t1001\t1\t3");
        assert_eq!(j.dir_name(), "G1_8_1001_1_3");
        assert!(Job::parse("# comment").is_none());
        assert!(Job::parse("G1_8 1001 1").is_none());
        assert_eq!(Job::parse("G1_1\t7\t0\t-1").unwrap().orientation, -1);
    }

    #[test]
    fn done_keys_read_the_first_four_columns() {
        let text = "# header\nG1_8\t1001\t1\t3\tok\t1\t2\t3\t4\t5.0\t\nG1_8\t1002\t1\t3\terror\t0\t0\t0\t0\t1.0\tx\n";
        let keys = done_keys(text);
        assert_eq!(keys.len(), 2);
        assert!(keys.contains("G1_8\t1001\t1\t3"));
        // A line cut short by a crash is not a result.
        assert!(done_keys("G1_8\t1\t1\t3\tok\t5").is_empty());
    }
}
