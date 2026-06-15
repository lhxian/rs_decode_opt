//! Streaming pack decoder that validates headers, inflates entries, rebuilds deltas (including zstd),
//! and populates caches/metadata for downstream consumers.

use std::{
    // collections::HashMap, 
    io::{BufRead, Cursor, ErrorKind, Read, Seek}, path::PathBuf, sync::{
        Arc, Mutex,
        atomic::{AtomicUsize},
    }, thread::{self, JoinHandle}, 
    // time::Instant, 
    // usize
};

// use axum::Error;
// use bytes::Bytes;
// use flate2::bufread::ZlibDecoder;
// use futures_util::{Stream, StreamExt};
// use futures_util::StreamExt;
use threadpool::ThreadPool;
use tokio::sync::mpsc::UnboundedSender;
use uuid::Uuid;

use crate::{
    errors::GitError,
    hash::{ObjectHash, get_hash_kind, set_hash_kind},
    internal::{
        metadata::{EntryMeta, MetaAttached},
        // object::types::ObjectType,
        pack::{
            DEFAULT_TMP_DIR, Pack,
            cache::{_Cache, Caches},
            cache_object::{CacheObject, CacheObjectInfo},
            entry::Entry,
            utils,
            waitlist::Waitlist,
            // wrapper::Wrapper,
            graph::DependGraph,
        },
    },
    // utils::CountingReader,
    zstdelta,
};

// A reader that counts bytes read and computes CRC32 checksum.
// which is used to verify the integrity of decompressed data.
// pub struct CrcCountingReader<'a, R> {
//     inner: R,
//     bytes_read: u64,
//     crc: &'a mut crc32fast::Hasher,
// }
// impl<R: Read> Read for CrcCountingReader<'_, R> {
//     fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
//         let n = self.inner.read(buf)?;
//         self.bytes_read += n as u64;
//         self.crc.update(&buf[..n]);
//         Ok(n)
//     }
// }
// impl<R: BufRead> BufRead for CrcCountingReader<'_, R> {
//     fn fill_buf(&mut self) -> io::Result<&[u8]> {
//         self.inner.fill_buf()
//     }
//     fn consume(&mut self, amt: usize) {
//         let buf = self.inner.fill_buf().unwrap_or(&[]);
//         self.crc.update(&buf[..amt.min(buf.len())]);
//         self.bytes_read += amt as u64;
//         self.inner.consume(amt);
//     }
// }

// For the convenience of passing parameters
// struct SharedParams {
//     pub pool: Arc<ThreadPool>,
//     pub waitlist: Arc<Waitlist>,
//     pub caches: Arc<Caches>,
//     pub cache_objs_mem_size: Arc<AtomicUsize>,
//     pub callback: Arc<dyn Fn(MetaAttached<Entry, EntryMeta>) + Sync + Send>,
// }


impl Drop for Pack {
    fn drop(&mut self) {
        if self.clean_tmp {
            self.caches.remove_tmp_dir();
        }
    }
}

impl Pack {
    /// # Parameters
    /// - `thread_num`: The number of threads to use for decoding and cache, `None` mean use the number of logical CPUs.
    ///   It can't be zero, or panic <br>
    /// - `mem_limit`: The maximum size of the memory cache in bytes, or None for unlimited.
    ///   The 80% of it will be used for [Caches]  <br>
    ///   ​**Not very accurate, because of memory alignment and other reasons, overuse about 15%** <br>
    /// - `temp_path`: The path to a directory for temporary files, default is "./.cache_temp" <br>
    ///   For example, thread_num = 4 will use up to 8 threads (4 for decoding and 4 for cache) <br>
    /// - `clean_tmp`: whether to remove temp directory when Pack is dropped
    pub fn new(
        thread_num: Option<usize>,
        mem_limit: Option<usize>,
        temp_path: Option<PathBuf>,
        clean_tmp: bool,
    ) -> Self {
        let mut temp_path = temp_path.unwrap_or(PathBuf::from(DEFAULT_TMP_DIR));
        // add 8 random characters as subdirectory, check if the directory exists
        loop {
            let sub_dir = Uuid::new_v4().to_string()[..8].to_string();
            temp_path.push(sub_dir);
            if !temp_path.exists() {
                break;
            }
            temp_path.pop();
        }
        let thread_num = thread_num.unwrap_or_else(num_cpus::get);
        let cache_mem_size = mem_limit.map(|mem_limit| {
            // Use wider math to avoid 32-bit overflow when computing 80%.
            ((mem_limit as u128) * 4 / 5) as usize
        });
        Pack {
            number: 0,
            signature: ObjectHash::default(),
            objects: Vec::new(),
            pool: Arc::new(ThreadPool::new(thread_num)),
            waitlist: Arc::new(Waitlist::new()),
            caches: Arc::new(Caches::new(cache_mem_size, temp_path, thread_num)),
            mem_limit,
            cache_objs_mem: Arc::new(AtomicUsize::default()),
            clean_tmp,
            total_size: 0,
            max_size: 0,
        }
    }

    /// Checks and reads the header of a Git pack file.
    ///
    /// This function reads the first 12 bytes of a pack file, which include the b"PACK" magic identifier,
    /// the version number, and the number of objects in the pack. It verifies that the magic identifier
    /// is correct and that the version number is 2 (which is the version currently supported by Git).
    /// It also collects these header bytes for later use, such as for hashing the entire pack file.
    ///
    /// # Parameters
    /// * `pack` - A mutable reference to an object implementing the `Read` trait,
    ///   representing the source of the pack file data (e.g., file, memory stream).
    ///
    /// # Returns
    /// A `Result` which is:
    /// * `Ok((u32, Vec<u8>))`: On successful reading and validation of the header, returns a tuple where:
    ///     - The first element is the number of objects in the pack file (`u32`).
    ///     - The second element is a vector containing the bytes of the pack file header (`Vec<u8>`).
    /// * `Err(GitError)`: On failure, returns a [`GitError`] with a description of the issue.
    ///
    /// # Errors
    /// This function can return an error in the following situations:
    /// * If the pack file does not start with the "PACK" magic identifier.
    /// * If the pack file's version number is not 2.
    /// * If there are any issues reading from the provided `pack` source.
    pub fn check_header(pack: &mut impl BufRead) -> Result<(u32, Vec<u8>), GitError> {
        // A vector to store the header data for hashing later
        let mut header_data = Vec::new();

        // Read the first 4 bytes which should be "PACK"
        let mut magic = [0; 4];
        // Read the magic "PACK" identifier
        let result = pack.read_exact(&mut magic);
        match result {
            Ok(_) => {
                // Store these bytes for later
                header_data.extend_from_slice(&magic);

                // Check if the magic bytes match "PACK"
                if magic != *b"PACK" {
                    // If not, return an error indicating invalid pack header
                    return Err(GitError::InvalidPackHeader(format!(
                        "{},{},{},{}",
                        magic[0], magic[1], magic[2], magic[3]
                    )));
                }
            }
            Err(e) => {
                // If there is an error in reading, return a GitError
                return Err(GitError::InvalidPackFile(format!(
                    "Error reading magic identifier: {e}"
                )));
            }
        }

        // Read the next 4 bytes for the version number
        let mut version_bytes = [0; 4];
        let result = pack.read_exact(&mut version_bytes); // Read the version number
        match result {
            Ok(_) => {
                // Store these bytes
                header_data.extend_from_slice(&version_bytes);

                // Convert the version bytes to an u32 integer
                let version = u32::from_be_bytes(version_bytes);
                if version != 2 {
                    // Git currently supports version 2, so error if not version 2
                    return Err(GitError::InvalidPackFile(format!(
                        "Version Number is {version}, not 2"
                    )));
                }
            }
            Err(e) => {
                // If there is an error in reading, return a GitError
                return Err(GitError::InvalidPackFile(format!(
                    "Error reading version number: {e}"
                )));
            }
        }

        // Read the next 4 bytes for the number of objects in the pack
        let mut object_num_bytes = [0; 4];
        // Read the number of objects
        let result = pack.read_exact(&mut object_num_bytes);
        match result {
            Ok(_) => {
                // Store these bytes
                header_data.extend_from_slice(&object_num_bytes);
                // Convert the object number bytes to an u32 integer
                let object_num = u32::from_be_bytes(object_num_bytes);
                // Return the number of objects and the header data for further processing
                Ok((object_num, header_data))
            }
            Err(e) => {
                // If there is an error in reading, return a GitError
                Err(GitError::InvalidPackFile(format!(
                    "Error reading object number: {e}"
                )))
            }
        }
    }


    
    // my_decode
    /// Decodes a `Pack` from a `Stream` of `Bytes`, and sends the `Entry` while decoding.
    pub fn decode<F,C>(
        &mut self,
        pack: &mut (impl BufRead + Send + Seek),
        callback: F,
        _pack_id_callback: Option<C>,
    ) -> Result<(), GitError>
    where
        F: Fn(MetaAttached<Entry, EntryMeta>) + Sync + Send + 'static,
        C: FnOnce(ObjectHash) + Send + 'static,
    {
        let result = Pack::check_header(pack);
        match result {
            Ok((object_num, _)) => {
                self.number = object_num as usize;
            }
            Err(e) => {
                return Err(e);
            }
        }
        let graph = Arc::new(DependGraph::build_graph(pack, self.number));
        // graph.graph_check();
        let shared_callback = Arc::new(callback);
        // test data
        let arc_shared_count : Arc<Mutex<usize>>= Arc::new(Mutex::new(0));
        let arc_no_cache_cnt : Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
        let arc_remove_cache_cnt : Arc<Mutex<usize>> = Arc::new(Mutex::new(0));

        for _ in 0..self.pool.max_count() {
            // make value
            let task_graph = graph.clone();
            let task_callback =shared_callback.clone();
            let task_caches= self.caches.clone();

            let task_count = arc_shared_count.clone();
            let task_no_cache_cnt = arc_no_cache_cnt.clone();
            let task_remove_cache_cnt = arc_remove_cache_cnt.clone();
            self.pool.execute(move || {
                let mut cnt: usize =0;
                let mut direct_fall: usize =usize::MAX;
                let mut no_cache_cnt: usize =0;
                let mut remove_cache_cnt: usize =0;
                loop{
                    let consume_index = if direct_fall != usize::MAX {
                        let res =Some(direct_fall);
                        direct_fall = usize::MAX; // set
                        res
                    }else {
                        task_graph.take_idx()
                    };
                    match consume_index {
                        Some(idx) => {
                            cnt += 1;
                            let cache_obj = task_graph.take(idx);
                            let target_obj =match cache_obj.info {
                                CacheObjectInfo::BaseObject(_,_ ) => cache_obj,
                                CacheObjectInfo::OffsetDelta(base_offset, _)  => {
                                    let base_obj = task_caches.get_by_offset(base_offset).unwrap();
                                     Pack::rebuild_delta(cache_obj,base_obj)
                                }
                                CacheObjectInfo::OffsetZstdelta(base_offset,_ ) =>{
                                    let base_obj = task_caches.get_by_offset(base_offset).unwrap();
                                    Pack::rebuild_zstdelta(cache_obj,base_obj)
                                }
                                CacheObjectInfo::HashDelta(base_ref, _) => {
                                    let base_obj = task_caches.get_by_hash(base_ref).unwrap();
                                    Pack::rebuild_delta(cache_obj,base_obj)
                                }
                            };
                            // apply callback to target object
                            task_callback(target_obj.to_entry_metadata());
                            // check ref delta
                            let oid=  match &target_obj.info {
                                CacheObjectInfo::BaseObject(_,oid) => oid,
                                _ => unreachable!()
                            };
                            let offset= target_obj.offset;
                            // lock the work list and decide whether to cache the object
                            {
                                let mut work_list = task_graph.work_list.lock().unwrap();
                                let (first_child ,_)= task_graph.take_child(idx, oid,&mut work_list);
                                match first_child {
                                    Some(child) => {
                                        // cache
                                        direct_fall = child;
                                        // println!("add cache: {}", offset);
                                        task_caches.insert(offset,*oid,target_obj);

                                    }
                                    None => {
                                        // println!("discard");
                                        no_cache_cnt += 1;
                                    } // discard
                                }
                            }
                            // check parent or eliminate
                            let (parent_idx ,parent_offset)= task_graph.get_parent_index_and_offset(idx) ;
                            if parent_idx != -1 && task_graph.dec_ref(parent_idx as usize){
                                // println!("remove cache: {}, cur: {}",parent_offset, offset);
                                task_caches.remove_by_offset(parent_offset);
                                remove_cache_cnt +=1;
                            }

                        }
                        None => {
                            break;
                        }
                    }
                }
                let mut count = task_count.lock().unwrap();
                *count += cnt;
                let mut no_cache = task_no_cache_cnt.lock().unwrap();
                *no_cache += no_cache_cnt;
                let mut remove_cache = task_remove_cache_cnt.lock().unwrap();
                *remove_cache += remove_cache_cnt;
            });
        }
        self.pool.join();
        let work_cnt = arc_shared_count.lock().unwrap();
        println!("task work cnt: {}",*work_cnt);
        println!("no cache cnt: {}",*arc_no_cache_cnt.lock().unwrap());
        println!("remove cache cnt: {}",*arc_remove_cache_cnt.lock().unwrap());

        Ok(())
    }




    // CacheObjects + Index size of Caches
    // fn memory_used(&self) -> usize {
    //     self.cache_objs_mem_used() + self.caches.memory_used_index()
    // }

    //  The total memory used by the CacheObjects of this Pack
    // fn cache_objs_mem_used(&self) -> usize {
    //     self.cache_objs_mem.load(Ordering::Acquire)
    // }



    /// Reconstruct the Delta Object based on the "base object"
    /// and return the new object.
    pub fn rebuild_delta(delta_obj: CacheObject, base_obj: Arc<CacheObject>) -> CacheObject {
        const COPY_INSTRUCTION_FLAG: u8 = 1 << 7;
        const COPY_OFFSET_BYTES: u8 = 4;
        const COPY_SIZE_BYTES: u8 = 3;
        const COPY_ZERO_SIZE: usize = 0x10000;

        let mut stream = Cursor::new(&delta_obj.data_decompressed);

        // Read the base object size
        // (Size Encoding)
        let (base_size, result_size) = utils::read_delta_object_size(&mut stream).unwrap();

        // Get the base object data
        let base_info = &base_obj.data_decompressed;
        assert_eq!(base_info.len(), base_size, "Base object size mismatch");

        let mut result = Vec::with_capacity(result_size);

        loop {
            // Check if the stream has ended, meaning the new object is done
            let instruction = match utils::read_bytes(&mut stream) {
                Ok([instruction]) => instruction,
                Err(err) if err.kind() == ErrorKind::UnexpectedEof => break,
                Err(err) => {
                    panic!(
                        "{}",
                        GitError::DeltaObjectError(format!("Wrong instruction in delta :{err}"))
                    );
                }
            };

            if instruction & COPY_INSTRUCTION_FLAG == 0 {
                // Data instruction; the instruction byte specifies the number of data bytes
                if instruction == 0 {
                    // Appending 0 bytes doesn't make sense, so git disallows it
                    panic!(
                        "{}",
                        GitError::DeltaObjectError(String::from("Invalid data instruction"))
                    );
                }

                // Append the provided bytes
                let mut data = vec![0; instruction as usize];
                stream.read_exact(&mut data).unwrap();
                result.extend_from_slice(&data);
            } else {
                // Copy instruction
                // +----------+---------+---------+---------+---------+-------+-------+-------+
                // | 1xxxxxxx | offset1 | offset2 | offset3 | offset4 | size1 | size2 | size3 |
                // +----------+---------+---------+---------+---------+-------+-------+-------+
                let mut nonzero_bytes = instruction;
                let offset =
                    utils::read_partial_int(&mut stream, COPY_OFFSET_BYTES, &mut nonzero_bytes)
                        .unwrap();
                let mut size =
                    utils::read_partial_int(&mut stream, COPY_SIZE_BYTES, &mut nonzero_bytes)
                        .unwrap();
                if size == 0 {
                    // Copying 0 bytes doesn't make sense, so git assumes a different size
                    size = COPY_ZERO_SIZE;
                }
                // Copy bytes from the base object
                let base_data = base_info.get(offset..(offset + size)).ok_or_else(|| {
                    GitError::DeltaObjectError("Invalid copy instruction".to_string())
                });

                match base_data {
                    Ok(data) => result.extend_from_slice(data),
                    Err(e) => panic!("{}", e),
                }
            }
        }
        assert_eq!(result_size, result.len(), "Result size mismatch");

        let hash = utils::calculate_object_hash(base_obj.object_type(), &result);
        // create new obj from `delta_obj` & `result` instead of modifying `delta_obj` for heap-size recording
        CacheObject {
            info: CacheObjectInfo::BaseObject(base_obj.object_type(), hash),
            offset: delta_obj.offset,
            crc32: delta_obj.crc32,
            data_decompressed: result,
            mem_recorder: None,
            is_delta_in_pack: delta_obj.is_delta_in_pack,
        } // Canonical form (Complete Object)
        // Memory recording will happen after this function returns. See `process_delta`
    }
    pub fn rebuild_zstdelta(delta_obj: CacheObject, base_obj: Arc<CacheObject>) -> CacheObject {
        let result = zstdelta::apply(&base_obj.data_decompressed, &delta_obj.data_decompressed)
            .expect("Failed to apply zstdelta");
        let hash = utils::calculate_object_hash(base_obj.object_type(), &result);
        CacheObject {
            info: CacheObjectInfo::BaseObject(base_obj.object_type(), hash),
            offset: delta_obj.offset,
            crc32: delta_obj.crc32,
            data_decompressed: result,
            mem_recorder: None,
            is_delta_in_pack: delta_obj.is_delta_in_pack,
        } // Canonical form (Complete Object)
        // Memory recording will happen after this function returns. See `process_delta`
    }

    /// Decode a Pack in a new thread and send the CacheObjects while decoding.
    /// <br> Attention: It will consume the `pack` and return in a JoinHandle.
    pub fn decode_async(
        mut self,
        mut pack: impl BufRead + Send + Seek + 'static,
        sender: UnboundedSender<Entry>,
    ) -> JoinHandle<Pack> {
        let kind = get_hash_kind();
        thread::spawn(move || {
            set_hash_kind(kind);
            self.decode(
                &mut pack,
                move |entry| {
                    if let Err(e) = sender.send(entry.inner) {
                        eprintln!("Channel full, failed to send entry: {e:?}");
                    }
                },
                None::<fn(ObjectHash)>,
            )
            .unwrap();
            self
        })
    }

}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{BufReader, Cursor, prelude::*},
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use flate2::{Compression, write::ZlibEncoder};
    use futures_util::TryStreamExt;
    use tokio_util::io::ReaderStream;

    use crate::{
        hash::{HashKind, ObjectHash, set_hash_kind_for_test},
        internal::pack::{Pack, test_pack_download::download_pack_file, tests::init_logger},
    };

    #[tokio::test]
    async fn test_pack_check_header() {
        let (source, _guard) = download_pack_file("medium-sha1.pack");

        let f = fs::File::open(source).unwrap();
        let mut buf_reader = BufReader::new(f);
        let (object_num, _) = Pack::check_header(&mut buf_reader).unwrap();

        assert_eq!(object_num, 35031);
    }


    /// Helper function to run decode tests without delta objects
    fn run_decode_no_delta(filename: &str, kind: HashKind) {
        let _guard = set_hash_kind_for_test(kind);
        let (source, _dl_guard) = download_pack_file(filename);

        let tmp = PathBuf::from("/tmp/.cache_temp");

        let f = fs::File::open(source).unwrap();
        let mut buffered = BufReader::new(f);
        let mut p = Pack::new(None, Some(1024 * 1024 * 20), Some(tmp), true);
        p.decode(&mut buffered, |_| {}, None::<fn(ObjectHash)>)
            .unwrap();
    }
    #[test]
    fn test_pack_decode_without_delta() {
        run_decode_no_delta("small-sha1.pack", HashKind::Sha1);
        run_decode_no_delta("small-sha256.pack", HashKind::Sha256);
    }

    /// Helper function to run decode tests with delta objects
    fn run_decode_with_ref_delta(filename: &str, kind: HashKind) {
        let _guard = set_hash_kind_for_test(kind);
        init_logger();

        let (source, _dl_guard) = download_pack_file(filename);

        let tmp = PathBuf::from("/tmp/.cache_temp");

        let f = fs::File::open(source).unwrap();
        let mut buffered = BufReader::new(f);
        let mut p = Pack::new(None, Some(1024 * 1024 * 20), Some(tmp), true);
        p.decode(&mut buffered, |_| {}, None::<fn(ObjectHash)>)
            .unwrap();
    }
    #[test]
    fn test_pack_decode_with_ref_delta() {
        run_decode_with_ref_delta("ref-delta-sha1.pack", HashKind::Sha1);
        run_decode_with_ref_delta("ref-delta-sha256.pack", HashKind::Sha256);
    }

    /// Helper function to run decode tests without memory limit
    fn run_decode_no_mem_limit(filename: &str, kind: HashKind) {
        let _guard = set_hash_kind_for_test(kind);
        let (source, _dl_guard) = download_pack_file(filename);

        let tmp = PathBuf::from("/tmp/.cache_temp");

        let f = fs::File::open(source).unwrap();
        let mut buffered = BufReader::new(f);
        let mut p = Pack::new(None, None, Some(tmp), true);
        p.decode(&mut buffered, |_| {}, None::<fn(ObjectHash)>)
            .unwrap();
    }
    #[test]
    fn test_pack_decode_no_mem_limit() {
        run_decode_no_mem_limit("small-sha1.pack", HashKind::Sha1);
        run_decode_no_mem_limit("small-sha256.pack", HashKind::Sha256);
    }

    /// Helper function to run decode tests with delta objects
    async fn run_decode_large_with_delta(filename: &str, kind: HashKind) {
        let _guard = set_hash_kind_for_test(kind);
        init_logger();
        let (source, _dl_guard) = download_pack_file(filename);

        let tmp = PathBuf::from("/tmp/.cache_temp");

        let f = fs::File::open(source).unwrap();
        let mut buffered = BufReader::new(f);
        let mut p = Pack::new(
            Some(4),
            Some(1024 * 1024 * 100), //try to avoid dead lock on CI servers with low memory
            Some(tmp.clone()),
            true,
        );
        let rt = p.decode(
            &mut buffered,
            |_obj| {
                // println!("{:?} {}", obj.hash.to_string(), offset);
            },
            None::<fn(ObjectHash)>,
        );
        if let Err(e) = rt {
            fs::remove_dir_all(tmp).unwrap();
            panic!("Error: {e:?}");
        }
    }
    #[tokio::test]
    async fn test_pack_decode_with_large_file_with_delta_without_ref() {
        run_decode_large_with_delta("medium-sha1.pack", HashKind::Sha1).await;
        run_decode_large_with_delta("medium-sha256.pack", HashKind::Sha256).await;
    } // it will be stuck on dropping `Pack` on Windows if `mem_size` is None, so we need `mimalloc`

    /// Helper function to run decode tests with large file stream

    /// Helper function to run decode tests with large file async
    async fn run_decode_large_file_async(filename: &str, kind: HashKind) {
        let _guard = set_hash_kind_for_test(kind);
        let (source, _dl_guard) = download_pack_file(filename);

        let tmp = PathBuf::from("/tmp/.cache_temp");
        let f = fs::File::open(source).unwrap();
        let buffered = BufReader::new(f);
        let p = Pack::new(Some(4), Some(1024 * 1024 * 100), Some(tmp.clone()), true);

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let handle = p.decode_async(buffered, tx); // new thread
        let mut cnt = 0;
        while let Some(_entry) = rx.recv().await {
            cnt += 1; //use entry here
        }
        let p = handle.join().unwrap();
        assert_eq!(cnt, p.number);
    }
    #[tokio::test]
    async fn test_decode_large_file_async() {
        run_decode_large_file_async("medium-sha1.pack", HashKind::Sha1).await;
        run_decode_large_file_async("medium-sha256.pack", HashKind::Sha256).await;
    }

    /// Helper function to run decode tests with delta objects without reference
    fn run_decode_with_delta_no_ref(filename: &str, kind: HashKind) {
        let _guard = set_hash_kind_for_test(kind);
        let (source, _dl_guard) = download_pack_file(filename);

        let tmp = PathBuf::from("/tmp/.cache_temp");

        let f = fs::File::open(source).unwrap();
        let mut buffered = BufReader::new(f);
        let mut p = Pack::new(None, Some(1024 * 1024 * 20), Some(tmp), true);
        p.decode(&mut buffered, |_| {}, None::<fn(ObjectHash)>)
            .unwrap();
    }
    #[test]
    fn test_pack_decode_with_delta_without_ref() {
        run_decode_with_delta_no_ref("medium-sha1.pack", HashKind::Sha1);
        run_decode_with_delta_no_ref("medium-sha256.pack", HashKind::Sha256);
    }

    #[test] // Take too long time
    fn test_pack_decode_multi_task_with_large_file_with_delta_without_ref() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            // For each hash kind, run two decode tasks concurrently to simulate multi-task pressure.
            for (kind, filename) in [
                (HashKind::Sha1, "medium-sha1.pack"),
                (HashKind::Sha256, "medium-sha256.pack"),
            ] {
                let f1 = run_decode_large_with_delta(filename, kind);
                let f2 = run_decode_large_with_delta(filename, kind);
                let _ = futures::future::join(f1, f2).await;
            }
        });
    }
}