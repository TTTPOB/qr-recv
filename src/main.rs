use blake2::digest::{Update, VariableOutput};
use blake2::{Blake2bVar, Digest};
use clap::Parser;
use image;
use rqrr;
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
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
        let img_filenames = fs::read_dir(&self.image_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_str().unwrap().to_string())
            .collect();
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
        let image_path = self
            .image_dir
            .join(&self.img_filenames[self.index as usize]);
        self.index += 1;
        match image::open(image_path) {
            Ok(image) => Some(image),
            Err(_) => None,
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
    fn verify(&self) -> bool {
        let mut hasher = Blake2bVar::new(self.hash.len()).unwrap();
        hasher.update(&self.data);
        let mut computed = vec![0; self.hash.len()];
        hasher.finalize_variable(&mut computed).unwrap();
        computed == self.hash
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
    fn verify(&self) -> bool {
        let mut hasher = blake2::Blake2bVar::new(self.hash.len()).unwrap();
        hasher.update(&self.data);
        let mut computed = vec![0; self.hash.len()];
        hasher.finalize_variable(&mut computed).unwrap();
        computed == self.hash
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
        println!("{:?}", computed);
        println!("{:?}", hash);
        if computed == hash {
            return Some(i);
        }
    }
    None
}

fn main() {
    let args = Args::parse();
    let img_seq = ImageSequence {
        image_dir: path::PathBuf::from(args.image_dir),
    };
    let mut md_recved = false;
    let mut md_str = String::new();
    let mut contents = Vec::new();
    let mut id_end = false;
    let mut md5_vec = Vec::new();
    let mut md_vec = Vec::new();
    for img in img_seq.into_iter() {
        if !md_recved {
            let data = decode(&img).unwrap();
            let hash_len = guess_hash_len(&data).unwrap();
            let content = data[0..data.len() - hash_len].to_vec();
            let content_str = String::from_utf8(content).unwrap();
            md_str.push_str(&content_str);
            if !md_str.ends_with("}") {
                continue;
            };
            md_recved = true;
        }
        let md: QrSendMetadata = serde_json::from_str(&md_str).unwrap();
        md_vec.push(md.clone());
        match decode(&img) {
            Some(data) => {
                if id_end {
                    // get md5
                    let md5_data = QrSendMd5Data::from_bytes(&data, &md);
                    if md5_data.verify() {
                        println!("got md5");
                        md5_vec.push(md5_data);
                        break;
                    }
                }
                let data = QrSendData::from_bytes(&data, &md);
                let data_id = data.id;
                println!("got qrcode: {}", data_id);
                if data.verify() {
                    contents.push(data);
                }
                id_end = data_id == (&md.qrcode_count - 1);
            }
            None => (),
        }
    }
    let mut valid_pieces = HashMap::new();
    for p in contents {
        valid_pieces.insert(p.id, p);
    }
    // if all qrcodes are valid, compare md5
    if valid_pieces.len() == md_vec[0].qrcode_count as usize {
        let md5_ = md5_vec[0].clone();
        let joined_pieces = valid_pieces.values().fold(Vec::new(), |mut acc, x| {
            acc.extend_from_slice(&x.data);
            acc
        });
        let computed_md5 = md5::compute(&joined_pieces);
        if format!("{:x}", computed_md5) == hex::encode(md5_.data) {
            println!("md5 matched");
            let mut file = fs::File::create(args.output_file).unwrap();
            file.write_all(&joined_pieces).unwrap();
        } else {
            println!("md5 not matched");
        }
    }
}

#[test]
fn decode_1107() {
    let img = image::open("fixtures/2imgs/frame_001113.jpg").unwrap();
    let data = decode(&img).unwrap();
    println!("{:?}", data);
}
