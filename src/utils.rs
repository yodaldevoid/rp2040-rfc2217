use core::ops::Deref;

use embassy_sync::{
    blocking_mutex::raw::RawMutex,
    pipe::{Pipe, Writer},
};

pub struct Cursor<const N: usize> {
    buf: [u8; N],
    _len: usize,
}

impl<const N: usize> Cursor<N> {
    pub const fn new() -> Self {
        Self {
            buf: [0; N],
            _len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self._len
    }

    pub fn clear(&mut self) {
        self._len = 0;
    }

    pub fn extend_with<E>(
        &mut self,
        f: impl FnOnce(&mut [u8]) -> Result<usize, E>,
    ) -> Result<usize, E> {
        match f(&mut self.buf[self._len..]) {
            Ok(bytes) => {
                self._len += bytes;
                Ok(bytes)
            }
            e => e,
        }
    }

    pub fn consume(&mut self, i: usize) {
        let i = self._len.min(i);
        self._len -= i;
        self.buf.copy_within(i.., 0);
    }
}

impl<const N: usize> Deref for Cursor<N> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.buf[..self._len]
    }
}

pub trait PipeExt {
    async fn write_all(&self, buf: &[u8]);
}

impl<M: RawMutex, const N: usize> PipeExt for Pipe<M, N> {
    async fn write_all(&self, buf: &[u8]) {
        let mut buf = buf;
        while !buf.is_empty() {
            let n = self.write(buf).await;
            assert!(n != 0, "zero-length write.");
            buf = &buf[n..];
        }
    }
}

impl<'a, M: RawMutex, const N: usize> PipeExt for Writer<'a, M, N> {
    async fn write_all(&self, buf: &[u8]) {
        let mut buf = buf;
        while !buf.is_empty() {
            let n = self.write(buf).await;
            assert!(n != 0, "zero-length write.");
            buf = &buf[n..];
        }
    }
}
