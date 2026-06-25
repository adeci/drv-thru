use indicatif::HumanBytes;
use iroh::EndpointId;

use crate::client_status::ClientStatus;

pub(super) struct BuildSummary<'a> {
    pub(super) server_id: EndpointId,
    pub(super) installable: &'a str,
    pub(super) drv_path: &'a str,
    pub(super) closure_path_count: usize,
    pub(super) missing_path_count: usize,
    pub(super) build_success: bool,
    pub(super) output_paths: &'a [String],
    pub(super) received_bytes: u64,
}

pub(super) fn print_local_outputs(
    status: &ClientStatus,
    installable: &str,
    output_paths: &[String],
) {
    status.suspend(|| {
        println!("drv-thru: outputs already present locally");
        println!();
        println!("{:<12} {}", "installable", installable);
        println!(
            "{:<12} {} {}",
            "outputs",
            output_paths.len(),
            path_word(output_paths.len())
        );
        println!("{:<12} skipped", "remote");
        println!();
        println!("output paths:");
        for path in output_paths {
            println!("{path}");
        }
    });
}

pub(super) fn print_build(status: &ClientStatus, summary: &BuildSummary<'_>) {
    status.suspend(|| {
        println!(
            "{}",
            if summary.build_success {
                "drv-thru: build complete"
            } else {
                "drv-thru: remote build failed"
            }
        );
        println!();
        println!("drv-thru -> {}", short_endpoint_id(summary.server_id));
        println!("{:<12} {}", "installable", summary.installable);
        println!("{:<12} {}", "drv", summary.drv_path);
        println!(
            "{:<12} {} missing / {} {}",
            "inputs",
            summary.missing_path_count,
            summary.closure_path_count,
            path_word(summary.closure_path_count)
        );
        println!("{:<12} started", "queue");
        println!(
            "{:<12} {}",
            "build",
            if summary.build_success {
                "succeeded"
            } else {
                "failed; see logs above"
            }
        );
        println!(
            "{:<12} {} {}",
            "outputs",
            summary.output_paths.len(),
            path_word(summary.output_paths.len())
        );
        println!(
            "{:<12} {} ({} bytes)",
            "received",
            HumanBytes(summary.received_bytes),
            summary.received_bytes
        );
        println!();
        println!("output paths:");
        for path in summary.output_paths {
            println!("{path}");
        }
    });
}

pub(super) fn path_word(count: usize) -> &'static str {
    if count == 1 { "path" } else { "paths" }
}

fn short_endpoint_id(id: EndpointId) -> String {
    let id = id.to_string();
    let len = id.chars().count();
    if len <= 14 {
        return id;
    }

    let start = id.chars().take(8).collect::<String>();
    let end = id
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>();
    format!("{start}...{end}")
}
