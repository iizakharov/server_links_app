//! Importing a connection from a QR code: a picture file or an image in the clipboard (a screenshot).
use image::GrayImage;
use tauri::AppHandle;
use tauri_plugin_clipboard_manager::ClipboardExt;

use crate::{err, Res};

/// Text of the first QR code found in the picture.
pub fn decode(img: GrayImage) -> Res<String> {
    let mut prepared = rqrr::PreparedImage::prepare(img);
    let grids = prepared.detect_grids();
    if grids.is_empty() {
        return Err("На картинке не найден QR-код".into());
    }
    let mut last = String::new();
    for g in grids {
        match g.decode() {
            Ok((_, text)) => return Ok(text),
            Err(e) => last = e.to_string(),
        }
    }
    Err(format!("QR-код не читается ({last}); попробуйте картинку крупнее или чётче"))
}

#[tauri::command]
pub fn qr_from_file(path: String) -> Res<String> {
    let img = image::open(&path).map_err(|e| format!("Не удалось открыть картинку: {e}"))?;
    decode(img.to_luma8())
}

#[tauri::command]
pub fn qr_from_clipboard(app: AppHandle) -> Res<String> {
    let img = app.clipboard().read_image().map_err(|_| "В буфере обмена нет картинки".to_string())?;
    let rgba = image::RgbaImage::from_raw(img.width(), img.height(), img.rgba().to_vec())
        .ok_or("Картинка в буфере повреждена")
        .map_err(err)?;
    decode(image::DynamicImage::ImageRgba8(rgba).to_luma8())
}

#[cfg(test)]
mod tests {
    use super::decode;

    /// A long AWG 3 key, as the app shares it: rendered to a picture and read back.
    #[test]
    fn reads_back_a_shared_key() {
        let fixtures = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/configs.json")).unwrap();
        let key = fixtures.split('"').find(|s| s.starts_with("vpn://") && s.len() > 800).expect("vpn:// key in fixtures");
        let code = qrcode::QrCode::with_error_correction_level(key.as_bytes(), qrcode::EcLevel::L).unwrap();
        let (w, scale, quiet) = (code.width() as u32, 6, 4);
        let side = (w + 2 * quiet) * scale;
        let colors = code.to_colors();
        let img = image::GrayImage::from_fn(side, side, |x, y| {
            let (cx, cy) = ((x / scale) as i64 - quiet as i64, (y / scale) as i64 - quiet as i64);
            let dark = cx >= 0 && cy >= 0 && cx < w as i64 && cy < w as i64
                && colors[(cy as u32 * w + cx as u32) as usize] == qrcode::Color::Dark;
            image::Luma([if dark { 0 } else { 255 }])
        });
        assert_eq!(decode(img).unwrap(), key);
        assert!(decode(image::GrayImage::from_pixel(200, 200, image::Luma([255]))).is_err());
    }
}
