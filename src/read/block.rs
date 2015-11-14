use crypto::digest::Digest;
use crypto::sha2::Sha256;

use std::io;
use std::io::{Cursor, Read};

use bytes;
use Error;

pub struct BlockReader<'a> {
    delegate: &'a mut Read,
    next_block_id: u32,
    block: Cursor<Vec<u8>>,
}

impl <'a> BlockReader<'a> {
    pub fn new(delegate: &'a mut Read) -> BlockReader<'a> {
        BlockReader {
            delegate: delegate,
            next_block_id: 0,
            block: Cursor::new(vec![]),
        }
    }

    fn read_next_block(&mut self) -> Result<(), Error> {
        let block_id = bytes::read_u32(self.delegate);
        match block_id {
            Ok(id) => {
                try!(self.check_block_id(id));

                let hash = try!(read_array!(self.delegate, 32));
                let size = try!(bytes::read_u32(self.delegate));

                self.read_and_check_block(size as usize, &hash)
            }
            Err(e) => Err(e),
        }
    }

    fn read_and_check_block(&mut self, size: usize, hash: &[u8; 32]) -> Result<(), Error> {
        let mut buf = vec![0; size];

        try!(self.delegate.read(&mut buf).map_err(|e| Error::Io(e)));
        try!(check_block(&buf, &hash));

        self.block = Cursor::new(buf);
        self.next_block_id += 1;

        Ok(())
    }

    fn block(&mut self) -> &mut Read {
        &mut self.block
    }

    fn check_block_id(&self, block_id: u32) -> Result<(), Error> {
        if self.next_block_id == block_id {
            Ok(())
        } else {
            Err(Error::IncorrectBlockId)
        }
    }
}

impl <'a> Read for BlockReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let result = try!(self.block().read(buf));

        if result > 0 {
            Ok(result)
        } else {
            try!(self.read_next_block().map_err(|e| io::Error::new(io::ErrorKind::Other, e)));
            self.block().read(buf)
        }
    }
}

fn check_block(block: &Vec<u8>, hash: &[u8; 32]) -> Result<(), Error> {
    if block.len() == 0 {
        return Ok(());
    }

    let mut hasher = Sha256::new();
    hasher.input(block);

    let mut buf = [0; 32];
    hasher.result(&mut buf);

    if buf == *hash {
        Ok(())
    } else {
        Err(Error::IncorrectBlockHash)
    }
}
