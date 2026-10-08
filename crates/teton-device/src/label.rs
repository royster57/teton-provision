//! Renders the device label QR (SPEC.md §3): terminal, PNG and a printable SVG.

use std::fmt::Write as _;
use std::path::Path;

use anyhow::Result;
use qrcode::{Color, EcLevel, QrCode};
use teton_proto::label::format_id;

/// Quiet zone around the code, in modules (the QR spec asks for 4).
const QUIET: usize = 4;

/// Module matrix with the quiet zone included; `true` = dark.
pub struct Matrix {
    pub width: usize,
    dark: Vec<bool>,
}

impl Matrix {
    pub fn encode(url: &str) -> Result<Self> {
        let code = QrCode::with_error_correction_level(url, EcLevel::M)?;
        let w = code.width();
        let colors = code.to_colors();
        let width = w + 2 * QUIET;
        let mut dark = vec![false; width * width];
        for y in 0..w {
            for x in 0..w {
                dark[(y + QUIET) * width + x + QUIET] = colors[y * w + x] == Color::Dark;
            }
        }
        Ok(Self { width, dark })
    }

    pub fn is_dark(&self, x: usize, y: usize) -> bool {
        x < self.width && y < self.width && self.dark[y * self.width + x]
    }

    /// Two module rows per text line with half blocks, drawn black on an
    /// explicit white background so it scans on dark terminal themes too.
    pub fn to_terminal(&self) -> String {
        let mut out = String::new();
        for y in (0..self.width).step_by(2) {
            out.push_str("\x1b[30;107m");
            for x in 0..self.width {
                out.push(match (self.is_dark(x, y), self.is_dark(x, y + 1)) {
                    (true, true) => '█',
                    (true, false) => '▀',
                    (false, true) => '▄',
                    (false, false) => ' ',
                });
            }
            out.push_str("\x1b[0m\n");
        }
        out
    }

    pub fn write_png(&self, path: &Path, px_per_module: u32) -> Result<()> {
        let size = self.width as u32 * px_per_module;
        let img = image::GrayImage::from_fn(size, size, |x, y| {
            let dark = self.is_dark((x / px_per_module) as usize, (y / px_per_module) as usize);
            image::Luma([if dark { 0 } else { 255 }])
        });
        img.save(path)?;
        Ok(())
    }

    /// A printable 50 × 62 mm label: the QR plus the human-readable ID.
    pub fn to_svg_label(&self, id: &str) -> String {
        let w = self.width;
        let mut path = String::new();
        for y in 0..w {
            for x in 0..w {
                if self.is_dark(x, y) {
                    let _ = write!(path, "M{x} {y}h1v1h-1z");
                }
            }
        }
        let text_y = w as f32 + 2.2;
        let height = w as f32 + 5.0;
        format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" width="50mm" height="{h_mm:.1}mm" viewBox="0 0 {w} {height}">
<rect width="{w}" height="{height}" fill="#fff"/>
<path d="{path}" fill="#000" shape-rendering="crispEdges"/>
<text x="{cx}" y="{text_y}" font-family="DejaVu Sans Mono, monospace" font-size="2.2" text-anchor="middle">Teton device {display}</text>
<text x="{cx}" y="{text_y2}" font-family="DejaVu Sans, sans-serif" font-size="1.4" text-anchor="middle" fill="#444">Scan with the phone camera to set up Wi-Fi</text>
</svg>
"##,
            h_mm = 50.0 * height / w as f32,
            cx = w as f32 / 2.0,
            text_y2 = text_y + 2.0,
            display = format_id(id),
        )
    }
}

/// Writes `label.png` and `label.svg` next to `label.json`.
pub fn write_files(dir: &Path, url: &str, id: &str) -> Result<Matrix> {
    let m = Matrix::encode(url)?;
    m.write_png(&dir.join("label.png"), 10)?;
    std::fs::write(dir.join("label.svg"), m.to_svg_label(id))?;
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_with_quiet_zone() {
        let url = "https://royster57.github.io/teton-provision/#v=1&id=D94816667B99&pk=BIu-oQ8eATqxMpStZeb0CuuTe8bYOQaloFzROzNT3A2NDtIrgDk63kZHPTrspwE3Nn3qHu4V94h-bNqW8dBmTG4";
        let m = Matrix::encode(url).unwrap();
        // The ~130-character URL at EC level M is a version 9 code (53 modules).
        assert!(m.width <= 57 + 2 * QUIET, "width {}", m.width);
        assert!((0..m.width).all(|i| !m.is_dark(i, 0) && !m.is_dark(0, i)));
        assert!(m.is_dark(QUIET, QUIET), "finder pattern corner");
        let term = m.to_terminal();
        assert_eq!(term.lines().count(), m.width.div_ceil(2));
        assert!(m.to_svg_label("D94816667B99").contains("D948-1666-7B99"));
    }
}
