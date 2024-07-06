use blake2::digest::{Update, VariableOutput};
use blake2::{Blake2bVar, Digest};
use clap::Parser;
use image;
use rqrr;
use serde::{Deserialize, Serialize};
use serde_json;
use std::{borrow::BorrowMut, collections::HashMap, hash::Hash};
use std::{fs, io::Write};
use std::{io, str::Bytes};

use base64::prelude::*;
use std::path;

#[derive(Parser)]
struct Args {
    #[clap(short, long)]
    image_dir: String,
    #[clap(short, long)]
    output_file: String,
}

struct ImageSequence {
    image_dir: path::PathBuf,
}
impl IntoIterator for ImageSequence {
    type Item = image::DynamicImage;
    type IntoIter = ImageSequenceIterator;

    fn into_iter(self) -> Self::IntoIter {
        let mut img_filenames: Vec<String> = fs::read_dir(&self.image_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_str().unwrap().to_string())
            .collect();
        // sort by filename
        img_filenames.sort();
        ImageSequenceIterator {
            image_dir: self.image_dir,
            img_filenames: img_filenames,
            index: 0,
        }
    }
}

struct ImageSequenceIterator {
    image_dir: path::PathBuf,
    img_filenames: Vec<String>,
    index: u32,
}
impl Iterator for ImageSequenceIterator {
    type Item = image::DynamicImage;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index == self.img_filenames.len() as u32 {
            return None;
        }
        let image_path = self
            .image_dir
            .join(&self.img_filenames[self.index as usize]);
        self.index += 1;
        println!("reading image: {:?}", image_path);
        match image::open(image_path) {
            Ok(image) => Some(image),
            Err(_) => None,
        }
    }
}
impl ImageSequenceIterator {
    fn tick_backward(&mut self) {
        if self.index > 0 {
            self.index -= 1;
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct QrSendMetadata {
    qrcode_count: u64,
    id_type: String,
    hash_len: u64,
}

fn get_id_and_len(data: &[u8], md: &QrSendMetadata) -> (u64, usize) {
    let id_len = match md.id_type.as_str() {
        "u64" => 8,
        "u32" => 4,
        "u16" => 2,
        "u8" => 1,
        _ => panic!("Invalid id type"),
    };
    let id = match id_len {
        8 => u64::from_be_bytes(data[0..8].try_into().unwrap()),
        4 => u32::from_be_bytes(data[0..4].try_into().unwrap()) as u64,
        2 => u16::from_be_bytes(data[0..2].try_into().unwrap()) as u64,
        1 => u8::from_be_bytes(data[0..1].try_into().unwrap()) as u64,
        _ => panic!("Invalid id type"),
    };
    return (id, id_len as usize);
}

#[derive(Debug, Clone)]
struct QrSendData {
    id: u64,
    data: Vec<u8>,
    hash: Vec<u8>,
}
impl QrSendData {
    fn from_bytes(data: &[u8], md: &QrSendMetadata) -> Self {
        let hash_len = md.hash_len as usize;
        let (id, id_size) = get_id_and_len(data, md);
        let content = data[id_size..data.len() - hash_len].to_vec();
        let hash = data[data.len() - hash_len..].to_vec();
        QrSendData {
            id: id,
            data: content,
            hash: hash,
        }
    }
}

#[derive(Debug, Clone)]
struct QrSendMd5Data {
    data: Vec<u8>,
    hash: Vec<u8>,
}
impl QrSendMd5Data {
    fn from_bytes(data: &[u8], md: &QrSendMetadata) -> Self {
        let hash_len = md.hash_len as usize;
        let data = data[0..data.len() - hash_len].to_vec();
        let hash = data[data.len() - hash_len..].to_vec();
        QrSendMd5Data {
            data: data,
            hash: hash,
        }
    }
}

fn decode(img: &image::DynamicImage) -> Option<Vec<u8>> {
    let img = img.to_luma8();
    let mut img = rqrr::PreparedImage::prepare(img);
    let grids = img.detect_grids();
    if grids.len() == 0 {
        return None;
    }
    let grid = &grids[0];
    match grid.decode() {
        Ok(content) => Some(BASE64_STANDARD.decode(content.1.as_bytes()).unwrap()),
        Err(_) => None,
    }
}

fn guess_hash_len(data: &[u8]) -> Option<usize> {
    for i in 1..data.len() {
        let mut hasher = Blake2bVar::new(i).unwrap();
        let content = &data[0..data.len() - i];
        let hash = &data[data.len() - i..];
        let mut computed = vec![0; i];
        hasher.update(content);
        hasher.finalize_variable(&mut computed).unwrap();
        if computed == hash {
            return Some(i);
        }
    }
    None
}

struct QrSendDecoder {
    metadata: Option<QrSendMetadata>,
    data_segments: HashMap<u64, QrSendData>,
    total_md5: Vec<u8>,
}
impl QrSendDecoder {
    fn new() -> Self {
        QrSendDecoder {
            metadata: None,
            data_segments: HashMap::new(),
            total_md5: Vec::new(),
        }
    }
    fn verify_segment(&self, data: &[u8]) -> bool {
        let hash_len = match &self.metadata {
            Some(md) => md.hash_len as usize,
            None => match guess_hash_len(data) {
                Some(len) => len,
                None => return false,
            },
        };
        let hash = &data[data.len() - hash_len..];
        let mut hasher = Blake2bVar::new(hash_len).unwrap();
        let mut computed = vec![0u8; hash_len];
        hasher.update(&data[0..data.len() - hash_len]);
        hasher.finalize_variable(&mut computed).unwrap();
        computed == hash
    }
    fn get_metadata(&mut self, img_iter: &mut ImageSequenceIterator) {
        let mut md_str = String::new();
        for img in img_iter {
            match decode(&img) {
                Some(data) => {
                    if !self.verify_segment(&data) {
                        continue;
                    }
                    let hash_len = guess_hash_len(&data).unwrap();
                    if data[0] == 'M' as u8 {
                        md_str.push_str(
                            std::str::from_utf8(&data[1..data.len() - hash_len]).unwrap(),
                        );
                    }
                    if data[data.len() - hash_len - 1] != b'}' {
                        continue;
                    }
                    self.metadata = Some(serde_json::from_str(&md_str).unwrap());
                    return;
                }
                None => continue,
            }
        }
    }
    fn get_data(&mut self, img_iter: &mut ImageSequenceIterator) {
        for img in img_iter {
            match decode(&img) {
                Some(data) => {
                    if !self.verify_segment(&data) {
                        continue;
                    }
                    match data[0] {
                        b'M' => continue,
                        b'D' => {
                            let data =
                                QrSendData::from_bytes(&data[1..], &self.metadata.clone().unwrap());
                            println!("got data id: {}", data.id);
                            self.data_segments.insert(data.id, data);
                        }
                        b'H' => {
                            return;
                        }
                        _ => continue,
                    }
                }
                None => continue,
            }
        }
    }
    fn get_md5(&mut self, img_iter: &mut ImageSequenceIterator) {
        for img in img_iter {
            match decode(&img) {
                Some(data) => {
                    if !self.verify_segment(&data) {
                        continue;
                    }
                    match data[0] {
                        b'H' => {
                            let md5 = QrSendMd5Data::from_bytes(
                                &data[1..],
                                &self.metadata.clone().unwrap(),
                            );
                            self.total_md5 = md5.data;
                            return;
                        }
                        _ => continue,
                    }
                }
                None => continue,
            }
        }
        return;
    }
}

fn main() {
    let args = Args::parse();
    let img_seq = ImageSequence {
        image_dir: path::PathBuf::from(args.image_dir),
    };
    let mut decoder = QrSendDecoder::new();
    let mut img_iter = img_seq.into_iter();
    decoder.get_metadata(&mut img_iter);
    println!("got metadata: {:?}", decoder.metadata);
    decoder.get_data(&mut img_iter);
    img_iter.tick_backward();
    decoder.get_md5(&mut img_iter);
    if let Some(md) = &decoder.metadata {
        println!("total qrcode count: {}", md.qrcode_count);
        println!("received qrcode count: {}", decoder.data_segments.len());
        if md.qrcode_count == decoder.data_segments.len() as u64 {
            let mut data = Vec::new();
            for i in 0..md.qrcode_count {
                let segment = decoder.data_segments.get(&i).unwrap();
                data.extend_from_slice(&segment.data);
            }
            let computed_md5 = md5::compute(&data);
            if hex::encode(computed_md5.0) == hex::encode(&decoder.total_md5) {
                println!("md5 check passed");
                let mut output_file = fs::File::create(args.output_file).unwrap();
                output_file.write_all(&data).unwrap();
            } else {
                println!("md5 check failed");
                println!("computed md5: {}", hex::encode(computed_md5.0));
                println!("received md5: {}", hex::encode(&decoder.total_md5));
            }
        } else {
            let missed_segment = (0..md.qrcode_count)
                .filter(|i| !decoder.data_segments.contains_key(i))
                .collect::<Vec<u64>>();
            println!("missed segments: {:?}", missed_segment);
        }
    }
}
