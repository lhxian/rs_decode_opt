use std::{
    collections::HashMap,
    // time::Instant,
    // thread,
    io::{self, BufRead, Cursor, Read, Seek, SeekFrom},
    sync::Mutex,
};

use crate::{
    hash::{HashKind, ObjectHash, get_hash_kind},
    internal::{
        object::types::ObjectType,
        pack::{
            cache_object::{CacheObject, CacheObjectInfo},
            utils,
        },
    },
};
use flate2::bufread::ZlibDecoder;
use sha1::{Digest, Sha1};
#[derive(Clone)]
pub enum NodeValue {
    Base(ObjectHash),     // oid
    OffsetDelta(usize),   // base offset
    RefDelta(ObjectHash), // base hash
}
pub struct GraphNodeInfo {
    pub offset: usize,
    pub ref_cnt: i32,
    pub parent: i32,
    pub child: Option<Vec<usize>>, // child offset
    pub value: NodeValue,
}
impl GraphNodeInfo {
    pub fn new(offset: usize, value: NodeValue) -> Self {
        Self {
            offset,
            ref_cnt: 0,
            parent: -1,
            child: None,
            value,
        }
    }
}
pub struct DependGraph {
    pub node_cnt: usize,
    pub nodes: Vec<Mutex<GraphNodeInfo>>,

    pub ref_list: HashMap<ObjectHash, Vec<usize>>, // ref, offset
    pub file_buf: Vec<u8>,
    pub work_list: Mutex<Vec<usize>>,
    cur_pos: Mutex<usize>,
}
struct LightWeightReader<R> {
    inner: R,
    pub read_bytes: usize,
}
impl<R: Read> Read for LightWeightReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read_bytes += n;
        Ok(n)
    }
}
impl<R: BufRead> BufRead for LightWeightReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.inner.fill_buf()
    }
    fn consume(&mut self, amt: usize) {
        self.inner.consume(amt);
        self.read_bytes += amt;
    }
}
impl<R> LightWeightReader<R> {
    pub fn clear(&mut self) {
        self.read_bytes = 0;
    }
}
enum LightWeightHash {
    Sha1(Sha1),
    Sha256(sha2::Sha256),
}
impl LightWeightHash {
    fn new() -> Self {
        match get_hash_kind() {
            HashKind::Sha1 => LightWeightHash::Sha1(Sha1::new()),
            HashKind::Sha256 => LightWeightHash::Sha256(sha2::Sha256::new()),
        }
    }
    fn update(&mut self, data: &[u8]) {
        match self {
            LightWeightHash::Sha1(hasher) => hasher.update(data),
            LightWeightHash::Sha256(hasher) => hasher.update(data),
        }
    }
    fn get_hash(self) -> ObjectHash {
        match self {
            LightWeightHash::Sha1(hasher) => ObjectHash::Sha1(hasher.finalize().into()),
            LightWeightHash::Sha256(hasher) => ObjectHash::Sha256(hasher.finalize().into()),
        }
    }
}
impl DependGraph {
    const BUF_SIZE: usize = 8192;
    fn consume_base(
        object_type: ObjectType,
        expected_size: usize,
        reader: &mut (impl BufRead + Send),
        buf: &mut [u8],
    ) -> ObjectHash // oid, raw size, cached data
    {
        let mut deflate = ZlibDecoder::new(reader);
        let mut hasher = LightWeightHash::new();
        let type_bytes = object_type.to_bytes().unwrap();
        hasher.update(type_bytes);
        hasher.update(b" ");
        hasher.update(expected_size.to_string().as_bytes());
        hasher.update(b"\0");
        loop {
            let n = deflate.read(buf).unwrap();
            if n == 0 {
                break;
            }
            // update hash
            hasher.update(&buf[..n]);
        }
        hasher.get_hash()
    }
    fn consume_delta(reader: &mut (impl BufRead + Send), buf: &mut [u8]) {
        let mut deflate = ZlibDecoder::new(reader);
        loop {
            let n = deflate.read(buf).unwrap();
            if n == 0 {
                break;
            }
        }
    }
    pub fn build_graph(pack: &mut (impl BufRead + Send + Seek), object_number: usize) -> Self {
        let cur = pack.seek(SeekFrom::Start(0)).unwrap();
        let end = pack.seek(SeekFrom::End(0)).unwrap();
        let mut graph = DependGraph {
            node_cnt: object_number,
            nodes: Vec::with_capacity(object_number),
            ref_list: HashMap::new(),
            file_buf: Vec::with_capacity((end - cur) as usize),
            work_list: Mutex::new(Vec::with_capacity(object_number / 2 + 1)),
            cur_pos: Mutex::new(0),
        };
        pack.seek(SeekFrom::Start(0)).unwrap();
        pack.read_to_end(&mut graph.file_buf).unwrap();
        // println!("file buf len: {}", graph.file_buf.len());
        // println!("pack size: {}", end - cur);
        let mem_reader = Cursor::new(&mut graph.file_buf[12..]);
        let mut reader = LightWeightReader {
            inner: mem_reader,
            read_bytes: 0,
        };
        let mut buf: [u8; Self::BUF_SIZE] = [0; Self::BUF_SIZE];
        let mut offset: usize = 12;
        for i in 0..object_number {
            let init_offset = offset;
            let (type_bits, expected_size) =
                utils::read_type_and_varint_size(&mut reader, &mut offset).unwrap();
            let t = ObjectType::from_pack_type_u8(type_bits).unwrap();
            match t {
                ObjectType::Commit | ObjectType::Tree | ObjectType::Blob | ObjectType::Tag => {
                    // caculate the oid
                    // let type_byte = t.to_bytes().unwrap();
                    let oid = Self::consume_base(t, expected_size, &mut reader, &mut buf);
                    let base_item = GraphNodeInfo::new(init_offset, NodeValue::Base(oid));
                    graph.nodes.push(Mutex::new(base_item));
                }
                ObjectType::OffsetDelta | ObjectType::OffsetZstdelta => {
                    let (delta_offset, _) = utils::read_offset_encoding(&mut reader).unwrap();
                    Self::consume_delta(&mut reader, &mut buf);
                    let base_offset = init_offset - delta_offset as usize;
                    // inc parent ref cnt
                    let parent_idx = graph
                        .nodes
                        .binary_search_by(|x| {
                            let v = x.lock().unwrap();
                            v.offset.cmp(&base_offset)
                        })
                        .unwrap();
                    {
                        let mut parent = graph.nodes[parent_idx].lock().unwrap();
                        parent.ref_cnt += 1;
                        match &mut parent.child {
                            Some(child) => {
                                child.push(i);
                            }
                            None => {
                                parent.child = Some(vec![i]);
                            }
                        }
                    }
                    let mut delta_item =
                        GraphNodeInfo::new(init_offset, NodeValue::OffsetDelta(base_offset));
                    delta_item.parent = parent_idx as i32;
                    graph.nodes.push(Mutex::new(delta_item));
                }
                ObjectType::HashDelta => {
                    let ref_hash = ObjectHash::from_stream(&mut reader).unwrap();
                    match graph.ref_list.get_mut(&ref_hash) {
                        Some(list) => list.push(i),
                        None => {
                            graph.ref_list.insert(ref_hash, vec![i]);
                        }
                    }
                    Self::consume_delta(&mut reader, &mut buf);
                    let delta_item = GraphNodeInfo::new(init_offset, NodeValue::RefDelta(ref_hash));
                    graph.nodes.push(Mutex::new(delta_item));
                }
                _ => {}
            }
            // update offset
            offset = init_offset + reader.read_bytes;
            reader.clear();
        }
        // check the mt deflate
        graph
    }
    /// take the ready object index, if the work list is not empty, consume 1
    /// else get the next base object in nodes
    pub fn take_idx(&self) -> Option<usize> {
        let mut wl = self.work_list.lock().unwrap();
        if !wl.is_empty() {
            return Some(wl.pop().unwrap());
        }
        let obj_cnt = self.nodes.len();
        // get the next base object
        let mut pos = self.cur_pos.lock().unwrap();
        while *pos < obj_cnt {
            let item = self.nodes[*pos].lock().unwrap();
            if let NodeValue::Base(_) = &item.value {
                let res = *pos;
                *pos += 1;
                return Some(res);
            }
            *pos += 1;
        }
        None
    }
    // return (offset, value)
    fn take_value(&self, idx: usize) -> (usize, NodeValue) {
        let item = self.nodes[idx].lock().unwrap();
        (item.offset, item.value.clone())
    }
    pub fn take(&self, idx: usize) -> CacheObject {
        // TODO: decompress data and build cache object
        // alloc reader
        let (offset, value) = self.take_value(idx);
        let mut cursor = Cursor::new(&self.file_buf[offset..]);
        let mut tmp = 0;
        let (type_bits, expected_size) =
            utils::read_type_and_varint_size(&mut cursor, &mut tmp).unwrap();
        let obj_type = ObjectType::from_pack_type_u8(type_bits).unwrap();
        let mut is_delta = false;
        let info = match value {
            NodeValue::Base(oid) => CacheObjectInfo::BaseObject(obj_type, oid),
            NodeValue::OffsetDelta(base_offset) => {
                is_delta = true;
                let (_, final_size) = utils::read_offset_encoding(&mut cursor).unwrap();
                // can find parent by offset
                match obj_type {
                    ObjectType::OffsetDelta => {
                        CacheObjectInfo::OffsetDelta(base_offset, final_size)
                    }
                    ObjectType::OffsetZstdelta => {
                        CacheObjectInfo::OffsetZstdelta(base_offset, final_size)
                    }
                    _ => unreachable!(),
                }
            }
            NodeValue::RefDelta(_) => {
                is_delta = true;
                let ref_sha = ObjectHash::from_stream(&mut cursor).unwrap();
                let (_, final_size) = utils::read_delta_object_size(&mut cursor).unwrap();
                CacheObjectInfo::HashDelta(ref_sha, final_size)
            }
        };
        let mut deflate = ZlibDecoder::new(&mut cursor);
        let mut deflated_data: Vec<u8> = Vec::with_capacity(expected_size);
        deflate.read_to_end(&mut deflated_data).unwrap();
        let mut crc = crc32fast::Hasher::new();
        let end_pos = offset + cursor.position() as usize;
        crc.update(&self.file_buf[offset..end_pos]);
        CacheObject {
            info,
            offset,
            crc32: crc.finalize(),
            data_decompressed: deflated_data,
            mem_recorder: None,
            is_delta_in_pack: is_delta,
        }
    }
    // no lock the work list, pass work list using parameter
    // return first child and rest child cnt
    pub fn take_child(
        &self,
        cur: usize,
        oid: &ObjectHash,
        work_list: &mut Vec<usize>,
    ) -> (Option<usize>, usize) {
        let mut rest_cnt: usize = 0;
        let mut item = self.nodes[cur].lock().unwrap();
        let first_offset = match &item.child {
            Some(child) => {
                if !child.is_empty() {
                    // add other child to work list
                    rest_cnt += child.len() - 1;
                    let first = child[0];
                    for i in &child[1..] {
                        work_list.push(*i);
                    }
                    Some(first)
                } else {
                    None
                }
            }
            None => None,
        };
        // add ref delta
        let first_child: Option<usize> = match self.ref_list.get(oid) {
            Some(childs) => {
                // add ref cnt
                item.ref_cnt += childs.len() as i32;
                // set parent
                for i in childs.iter() {
                    let mut item = self.nodes[*i].lock().unwrap();
                    item.parent = cur as i32;
                }
                // get the first if offset first is none
                if first_offset.is_none() {
                    rest_cnt += childs.len() - 1;
                    for i in &childs[1..] {
                        work_list.push(*i);
                    }
                    Some(childs[0])
                } else {
                    rest_cnt += childs.len();
                    for i in childs.iter() {
                        work_list.push(*i);
                    }
                    first_offset
                }
            }
            None => first_offset,
        };
        (first_child, rest_cnt)
    }
    pub fn get_parent_index_and_offset(&self, cur: usize) -> (i32, usize) {
        let item = self.nodes[cur].lock().unwrap();
        let parent_idx = item.parent;
        if parent_idx != -1 {
            let parent_item = self.nodes[parent_idx as usize].lock().unwrap();
            (parent_idx, parent_item.offset)
        } else {
            (-1, 0)
        }
    }
    /// return: true if ref cnt is 0
    pub fn dec_ref(&self, idx: usize) -> bool {
        let mut item = self.nodes[idx].lock().unwrap();
        item.ref_cnt -= 1;
        item.ref_cnt == 0
    }
    // pub fn graph_check(&self){
    //     let sz  = self.nodes.len();
    //     let mut delta_cnt =0;
    //     let mut with_parent_cnt :usize =0;
    //     let mut ref_cnt: usize =0;
    //     for i in self.nodes.iter() {
    //         let item = i.lock().unwrap();
    //         if item.parent != -1 {
    //             with_parent_cnt += 1;
    //         }
    //         ref_cnt += item.ref_cnt as usize;
    //         match &item.child {
    //             Some(child) => {
    //                 delta_cnt += child.len();
    //             }
    //             None => {}
    //         }
    //     }
    //     println!("delta cnt: {}", delta_cnt);
    //     println!("node cnt: {}", sz);
    //     println!("with parent cnt: {}", with_parent_cnt);
    //     println!("ref cnt: {}", ref_cnt);
    //     assert!(sz == self.node_cnt);
    // }
}
