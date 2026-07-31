pub fn upsert_toml_bool(raw: &str, section: &str, key: &str, value: bool) -> String {
    let mut lines = raw.lines().map(str::to_string).collect::<Vec<_>>();
    let assignment = format!("{key} = {}", if value { "true" } else { "false" });
    let section_header = format!("[{section}]");
    let section_start = lines
        .iter()
        .position(|line| line.trim() == section_header.as_str());

    if let Some(section_start) = section_start {
        let section_end = lines
            .iter()
            .enumerate()
            .skip(section_start + 1)
            .find_map(|(index, line)| {
                if line.trim().starts_with('[') && line.trim().ends_with(']') {
                    Some(index)
                } else {
                    None
                }
            })
            .unwrap_or(lines.len());

        if let Some(existing_index) = lines
            .iter()
            .enumerate()
            .take(section_end)
            .skip(section_start + 1)
            .find_map(|(index, line)| {
                let trimmed = line.trim_start();
                if trimmed.starts_with(key) && trimmed[key.len()..].trim_start().starts_with('=') {
                    Some(index)
                } else {
                    None
                }
            })
        {
            lines[existing_index] = assignment;
        } else {
            lines.insert(section_end, assignment);
        }
    } else {
        if !lines.is_empty() && !raw.ends_with('\n') {
            lines.push(String::new());
        }
        lines.push(section_header);
        lines.push(assignment);
    }

    let mut next = lines.join("\n");
    if raw.ends_with('\n') {
        next.push('\n');
    }
    next
}
