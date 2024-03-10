use async_std::io::ReadExt;
use bytes::{Bytes, BytesMut};
use core::task::{Context, Poll};
use std::io::Result;
use std::pin::Pin;

/// Inspired by [`tokio_util::io::ReaderStream`], [`ReaderStream`] converts a
/// [`ReadExt`] into a [`async_std::stream::Stream`] of bytes
#[derive(Debug)]
pub struct ReaderStream<R> {
    reader: Option<R>,
    buffer: BytesMut,
    capacity: usize,
}

impl<R: ReadExt> ReaderStream<R> {
    /// Converts a [`ReadExt`] into a [`async_std::stream::Stream`] of bytes
    /// with a custom read buffer capacity
    pub fn with_capacity(reader: R, capacity: usize) -> Self {
        ReaderStream {
            reader: Some(reader),
            buffer: BytesMut::with_capacity(capacity),
            capacity,
        }
    }
}

impl<R: ReadExt + Unpin> async_std::stream::Stream for ReaderStream<R> {
    type Item = Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let self_mut = self.get_mut();

        let reader = match &mut self_mut.reader {
            Some(reader) => reader,
            None => return Poll::Ready(None),
        };

        let mut temp_buffer = vec![0; self_mut.capacity];

        match Pin::new(reader).poll_read(cx, &mut temp_buffer) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => {
                self_mut.reader.take();
                Poll::Ready(Some(Err(err)))
            }
            Poll::Ready(Ok(0)) => {
                // End of stream
                self_mut.reader.take();
                Poll::Ready(None)
            }
            Poll::Ready(Ok(n)) => {
                // Data read successfully
                self_mut.buffer.extend_from_slice(&temp_buffer[..n]);
                let data = self_mut.buffer.split().freeze();
                Poll::Ready(Some(Ok(data)))
            }
        }
    }
}
