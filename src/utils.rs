use anyhow::bail;

pub fn slice_to_array<const N: usize>(input: &[u8]) -> anyhow::Result<[u8; N]> {
    if input.len() >= N {
        bail!(format!(
            "Input length must be less than or equal to {} bytes, but got {}",
            N,
            input.len()
        ));
    }

    // Create a new array and copy the slice into it
    let mut array = [0u8; N];
    array[..input.len()].copy_from_slice(input);
    Ok(array)
}


pub fn filter_zero_bytes(input: &[u8]) -> Vec<u8> {
    input.iter().filter(|&&byte| byte != 0).cloned().collect()
}

pub fn bytes_to_human_readable(bytes: u64) -> String {
    const UNITS: [&str; 7] = ["B", "KB", "MB", "GB", "TB", "PB", "EB"];
    let mut size = bytes as f64;
    let mut unit = "B";

    for current_unit in &UNITS {
        unit = current_unit;
        if size < 1024.0 {
            break;
        }
        size /= 1024.0;
    }

    format!("{:.2} {}", size, unit)
}
