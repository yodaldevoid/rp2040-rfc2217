use core::convert::Infallible;

use defmt::{debug, info, todo, warn};
use embassy_futures::select::{select, Either};
use embassy_sync::{blocking_mutex::raw::RawMutex, channel::Channel, mutex::Mutex, pipe::Pipe};
use embedded_io::{
    asynch::{Read, Write},
    Io,
};
use nom::{
    branch::alt,
    bytes::streaming::{tag, take, take_until, take_until1},
    sequence::{preceded, tuple},
    IResult, Parser,
};

use crate::utils::{Cursor, PipeExt};

const SE: u8 = 240;
const NOP: u8 = 241;
const DM: u8 = 242;
const BRK: u8 = 243;
const IP: u8 = 244;
const AO: u8 = 245;
const AYT: u8 = 246;
const EC: u8 = 247;
const EL: u8 = 248;
const GA: u8 = 249;
const SB: u8 = 250;
const WILL: u8 = 251;
const WONT: u8 = 252;
const DO: u8 = 253;
const DONT: u8 = 254;
const IAC: u8 = 255;

#[derive(Clone, Debug, defmt::Format)]
enum Event<'a> {
    // WILL|WONT|DO|DONT <OPTION>
    Negotiate(Negotiation),
    // IAC SB <OPTION> <PARAMETERS> IAC SE
    SubNegotiate(u8, &'a [u8]),
    // Raw data. The application will have to figure out what these mean.
    Data(&'a [u8]),
    // An IAC <COMMAND> other than those involved in negotiation and sub-options.
    Command(u8),
}

#[derive(Clone, Copy, Debug, defmt::Format)]
enum Negotiation {
    // WILL <OPTION>
    Will(u8),
    // WONT <OPTION>
    Wont(u8),
    // DO <OPTION>
    Do(u8),
    // DONT <OPTION>
    Dont(u8),
}

impl Negotiation {
    fn acceptance(&self) -> bool {
        match self {
            Negotiation::Will(_) | Negotiation::Do(_) => true,
            Negotiation::Wont(_) | Negotiation::Dont(_) => false,
        }
    }
}

impl<'a> Event<'a> {
    // TODO: strip NUL after CR unless in binary mode
    fn parse(i: &'a [u8]) -> IResult<&'a [u8], Self> {
        alt((
            // An escaped IAC.
            // TODO; try to take data after the escaped IAC
            tag(&[IAC, IAC][..]).map(|_| Self::Data(&[IAC])),
            // Will <OPTION>
            preceded(tag(&[IAC, WILL][..]), take(1usize))
                .map(|o: &[u8]| Self::Negotiate(Negotiation::Will(o[0]))),
            // Won't <OPTION>
            preceded(tag(&[IAC, WONT][..]), take(1usize))
                .map(|o: &[u8]| Self::Negotiate(Negotiation::Wont(o[0]))),
            // Do <OPTION>
            preceded(tag(&[IAC, DO][..]), take(1usize))
                .map(|o: &[u8]| Self::Negotiate(Negotiation::Do(o[0]))),
            // Don't <OPTION>
            preceded(tag(&[IAC, DONT][..]), take(1usize))
                .map(|o: &[u8]| Self::Negotiate(Negotiation::Dont(o[0]))),
            // Subnegotiation <OPTION> <PARAMETERS>
            tuple((
                tag(&[IAC, SB][..]),
                take(1usize),
                take_until(&[IAC][..]),
                tag(&[IAC, SE][..]),
            ))
            .map(|(_, o, b, _): (_, &[u8], _, _)| Self::SubNegotiate(o[0], b)),
            // Misc. command
            preceded(tag(&[IAC][..]), take(1usize)).map(|o: &[u8]| Self::Command(o[0])),
            // Some run of data bytes.
            Self::parse_data,
        ))(i)
    }

    fn parse_data(i: &'a [u8]) -> IResult<&'a [u8], Self> {
        let res = take_until1(&[IAC][..]).map(Self::Data).parse(i);
        if res.is_err() && !i.is_empty() && i[0] != IAC {
            return Ok((&[], Self::Data(i)));
        }
        res
    }
}

impl From<Negotiation> for Event<'_> {
    fn from(n: Negotiation) -> Self {
        Self::Negotiate(n)
    }
}

impl Negotiation {
    fn option(&self) -> u8 {
        match self {
            Self::Will(opt) | Self::Wont(opt) | Self::Do(opt) | Self::Dont(opt) => *opt,
        }
    }

    fn code(&self) -> u8 {
        match self {
            Self::Will(_) => WILL,
            Self::Wont(_) => WONT,
            Self::Do(_) => DO,
            Self::Dont(_) => DONT,
        }
    }

    fn encode(&self) -> [u8; 3] {
        [IAC, self.code(), self.option()]
    }
}

// TODO: tests

struct Cursor<const N: usize> {
    buf: [u8; N],
    _len: usize,
}

impl<const N: usize> Cursor<N> {
    fn new() -> Self {
        Self {
            buf: [0; N],
            _len: 0,
        }
    }

    fn len(&self) -> usize {
        self._len
    }

    fn clear(&mut self) {
        self._len = 0;
    }

    fn extend_with<E>(
        &mut self,
        f: impl FnOnce(&mut [u8]) -> Result<usize, E>,
    ) -> Result<usize, E> {
        let bytes = f(&mut self.buf[self._len..])?;
        self._len += bytes;
        Ok(bytes)
    }

    fn consume(&mut self, i: usize) {
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

enum ControlMessage {
    Negotiate(Negotiation),
    // Decoder recieved GA, flush the buffer even without a line end.
    FlushBuffer,
}

struct NvtOptions {
    // Only valid for decoder
    synch: bool,
}

impl Default for NvtOptions {
    fn default() -> Self {
        Self { synch: false }
    }
}

pub struct Codec<M: RawMutex> {
    send_options: Mutex<M, NvtOptions>,
    recv_options: Mutex<M, NvtOptions>,
    telnet_recv: Mutex<M, Cursor<256>>,
    // TODO: maybe doesn't need to be a channel as it is only used internally
    control_channel: Channel<M, ControlMessage, 64>,
    data_recv: Pipe<M, 256>,
    data_send: Pipe<M, 256>,
}

impl<M: RawMutex> Codec<M> {
    pub fn new() -> Self {
        Self {
            send_options: Mutex::new(Default::default()),
            recv_options: Mutex::new(Default::default()),
            telnet_recv: Mutex::new(Cursor::new()),
            control_channel: Channel::new(),
            data_recv: Pipe::new(),
            data_send: Pipe::new(),
        }
    }

    pub async fn reset(&self) {
        *self.send_options.lock().await = Default::default();
        *self.recv_options.lock().await = Default::default();
        self.telnet_recv.lock().await.clear();
        while let Ok(_) = self.control_channel.try_recv() {}
    }

    pub async fn init(&self) {}

    pub async fn start_synch(&self) {
        self.recv_options.lock().await.synch = true;
    }

    pub async fn decode<E>(&self, f: impl FnOnce(&mut [u8]) -> Result<usize, E>) -> Result<(), E> {
        let mut buf = self.telnet_recv.lock().await;

        buf.extend_with(f)?;

        // TODO: keep track of last Incomplete and only try parsing when we have that much.
        loop {
            let used = if let Ok((rest, event)) = Event::parse(&*buf) {
                let synch = self.recv_options.lock().await.synch;
                match (event, synch) {
                    (Event::Data(buf), false) => {
                        self.data_send.write_all(&*buf).await;
                    }
                    (Event::SubNegotiate(_opt, _param), false) => todo!(),
                    (Event::Command(cmd), _) => {
                        match cmd {
                            GA => self.control_channel.send(ControlMessage::FlushBuffer).await,
                            DM => {
                                if synch {
                                    self.recv_options.lock().await.synch = false;
                                }
                            }
                            // Unsupported commands are a NOP.
                            NOP | BRK | IP | AO | AYT | EC | EL => {}
                            // Any unknown commands are treated as a NOP.
                            _ => warn!("Unknown TELNET command {}", cmd),
                        }
                    }
                    (Event::Negotiate(negotiation), false) => {
                        debug!("decoder: {:?}", negotiation);
                        let response = match negotiation {
                            // Ignore disables of unsupported options as we will alway have them
                            // disabled.
                            Negotiation::Wont(_) => None,
                            // Reject unsupported options.
                            Negotiation::Will(option) => {
                                info!("decoder: Rejecting TELNET option {}", option);
                                Some(Negotiation::Wont(option))
                            }
                            // Just pass DO/DONT to the encoder.
                            Negotiation::Do(_) | Negotiation::Dont(_) => Some(negotiation),
                        };
                        if let Some(response) = response {
                            self.control_channel
                                .send(ControlMessage::Negotiate(response))
                                .await;
                        }
                    }
                    (_, true) => {}
                }

                buf.len() - rest.len()
            } else {
                return Ok(());
            };

            buf.consume(used);
        }
    }

    pub async fn encode<E, W: Write + Io<Error = E>>(&self, writer: &mut W) -> Result<(), E> {
        let mut buf = [0; 256];

        // TODO: try to line buffer unless SUPPRESS-GO-AHEAD is enabled
        // TODO: if we send a DO don't send data until we get a response
        match select(self.data_recv.read(&mut buf), self.control_channel.recv()).await {
            Either::First(buf_len) => {
                // TODO: insert LF after CR not followed by NUL unless in binary mode
                for buf in buf[..buf_len].split_inclusive(|b| b == &IAC) {
                    writer.write_all(buf).await?;
                    // If we split on an IAC (only not true on the last slice), escape the IAC.
                    if let Some(&IAC) = buf.last() {
                        writer.write_all(&[IAC]).await?;
                    }
                }
            }
            Either::Second(event) => {
                match event {
                    ControlMessage::Negotiate(negotiation) => {
                        let response = match negotiation {
                            // Ignore disables of unsupported options as we will alway have them
                            // disabled.
                            Negotiation::Dont(_) => None,
                            // Reject unsupported options.
                            Negotiation::Do(option) => {
                                info!("encoder: Rejecting TELNET option {}", option);
                                Some(Negotiation::Wont(option))
                            }
                            // Assume the decoder has already handled WILL/WONT and this is just the
                            // response.
                            Negotiation::Will(o) => Some(Negotiation::Do(o)),
                            Negotiation::Wont(o) => Some(Negotiation::Dont(o)),
                        };
                        if let Some(response) = response {
                            writer.write_all(&response.encode()).await?;
                        }
                    }
                    ControlMessage::FlushBuffer => todo!("flush send buffer"),
                }
            }
        }

        Ok(())
    }

    pub fn data_receiver(&self) -> DataReceiver<'_, M> {
        DataReceiver {
            pipe: &self.data_recv,
        }
    }

    pub fn data_sender(&self) -> DataSender<'_, M> {
        DataSender {
            pipe: &self.data_send,
        }
    }
}

pub struct DataReceiver<'a, M: RawMutex> {
    pipe: &'a Pipe<M, 256>,
}

impl<'a, M: RawMutex> Io for DataReceiver<'a, M> {
    type Error = Infallible;
}

impl<'a, M: RawMutex> Write for DataReceiver<'a, M> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Infallible> {
        Ok(self.pipe.write(buf).await)
    }
}

pub struct DataSender<'a, M: RawMutex> {
    pipe: &'a Pipe<M, 256>,
}

impl<'a, M: RawMutex> DataSender<'a, M> {
    pub fn is_empty(&self) -> bool {
        self.pipe.is_empty()
    }
}

impl<'a, M: RawMutex> Io for DataSender<'a, M> {
    type Error = Infallible;
}

impl<'a, M: RawMutex> Read for DataSender<'a, M> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Infallible> {
        Ok(self.pipe.read(buf).await)
    }
}
