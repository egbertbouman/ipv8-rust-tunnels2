use std::collections::HashSet;
use std::ffi::c_void;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use ffmpeg_next::codec::Context;
use ffmpeg_next::media::Type as MediaType;
use ffmpeg_next::{self as ffmpeg, Codec, Rescale};
use pyo3::prelude::*;

const CACHE_LIMIT: usize = 10;

#[pyclass]
pub struct TranscodeServer {
    api_url: String,
    cache: Arc<dashmap::DashMap<String, MediaMetadata>>,
}

impl TranscodeServer {
    pub fn get_metadata_inner(
        cache: &Arc<dashmap::DashMap<String, MediaMetadata>>,
        stream_url: &str,
    ) -> Result<MediaMetadata, String> {
        if let Some(meta) = cache.get(stream_url) {
            return Ok(meta.clone());
        }

        let input = ffmpeg_next::format::input(stream_url).map_err(|e| format!("Can't open URL: {}", e))?;
        let metadata = MediaMetadata::from_input(&input).map_err(|e| format!("Can't get metadata: {}", e))?;

        if cache.len() >= CACHE_LIMIT {
            let key_to_remove = cache.iter().next().map(|r| r.key().clone());
            if let Some(key) = key_to_remove {
                cache.remove(&key);
            }
        }
        cache.insert(stream_url.to_owned(), metadata.clone());

        Ok(metadata)
    }
}

#[pymethods]
impl TranscodeServer {
    #[new]
    pub fn new(api_url: String) -> Self {
        let _ = ffmpeg::init();
        ffmpeg::util::log::set_level(ffmpeg::util::log::Level::Info);
        TranscodeServer { api_url, cache: Arc::new(dashmap::DashMap::new()) }
    }

    pub fn get_metadata(&self, stream_url: String) -> PyResult<MediaMetadata> {
        Self::get_metadata_inner(&self.cache, &stream_url)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
    }

    pub fn start_server(&self, port: u16) -> PyResult<()> {
        let url = self.api_url.clone();
        let cache = Arc::clone(&self.cache);

        std::thread::spawn(move || {
            let listener = std::net::TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();

            while let Ok((mut socket, _)) = listener.accept() {
                let url_clone = url.clone();
                let cache_clone = cache.clone();

                let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(100);

                std::thread::spawn(move || {
                    let mut buffer = [0; 2048];
                    let mut start_ms: i64 = 0;
                    let codecs;

                    let mut stream_url = String::new();

                    match socket.read(&mut buffer) {
                        Ok(n) if n > 0 => {
                            let request = String::from_utf8_lossy(&buffer[..n]);
                            if let Some(start_str) = extract_query_param(&request, "start") {
                                start_ms = start_str.parse::<i64>().unwrap_or(0);
                            }
                            codecs = SupportedCodecs::from_http_request(&request);

                            let mut api_key = String::new();
                            for line in request.lines() {
                                if line.to_lowercase().starts_with("cookie:") {
                                    for cookie in line["cookie:".len()..].split(';') {
                                        if let Some((key, val)) = cookie.split_once('=') {
                                            if key.trim() == "api_key" {
                                                api_key = val.trim().to_string();
                                                break;
                                            }
                                        }
                                    }
                                    break;
                                }
                            }

                            if let Some(path) = request.split_whitespace().nth(1) {
                                let separator = if path.contains('?') { "&" } else { "?" };
                                stream_url = format!("{}{}{}key={}", url_clone, path, separator, api_key);
                            }
                        }
                        _ => {
                            return;
                        }
                    }

                    if stream_url.is_empty() {
                        return;
                    }

                    info!("Getting metadata for video stream {}", stream_url);
                    let metadata = match Self::get_metadata_inner(&cache_clone, &stream_url) {
                        Ok(m) => m,
                        Err(_) => {
                            let _ = socket.write_all(b"HTTP/1.1 500 Internal Server Error\r\n\r\n");
                            return;
                        }
                    };

                    let response_headers = format!(
                        "HTTP/1.1 200 OK\r\n\
                         Content-Type: video/mp4\r\n\
                         Access-Control-Allow-Origin: *\r\n\
                         Access-Control-Expose-Headers: X-Media-Metadata\r\n\
                         X-Media-Metadata: {}\r\n\
                         Connection: keep-alive\r\n\
                         Transfer-Encoding: chunked\r\n\r\n",
                        metadata.to_json()
                    );
                    info!("HEADERS {}", response_headers);
                    if socket.write_all(response_headers.as_bytes()).is_err() {
                        return;
                    }

                    std::thread::spawn(move || {
                        let session = TranscodeSession::new(stream_url, start_ms, codecs, tx);
                        if let Err(e) = session.run(metadata) {
                            error!("Transcoding failed: {:?}", e);
                        }
                    });

                    while let Ok(bytes) = rx.recv() {
                        if bytes.is_empty() {
                            break;
                        }
                        let chunk_header = format!("{:X}\r\n", bytes.len());
                        if socket.write_all(chunk_header.as_bytes()).is_err()
                            || socket.write_all(&bytes).is_err()
                            || socket.write_all(b"\r\n").is_err()
                        {
                            break;
                        }
                    }
                    let _ = socket.write_all(b"0\r\n\r\n");
                });
            }
        });

        Ok(())
    }
}

struct TranscodeSession {
    url: String,
    start_ms: i64,
    codecs: SupportedCodecs,
    tx: std::sync::mpsc::SyncSender<Vec<u8>>,
    shutdown: AtomicBool,
}

impl TranscodeSession {
    pub fn new(
        url: String,
        start_ms: i64,
        codecs: SupportedCodecs,
        tx: std::sync::mpsc::SyncSender<Vec<u8>>,
    ) -> Self {
        TranscodeSession { url, start_ms, codecs, tx, shutdown: AtomicBool::new(false) }
    }

    unsafe extern "C" fn write_packet_callback(opaque: *mut c_void, buf: *const u8, buf_size: i32) -> i32 {
        let session = &*(opaque as *const TranscodeSession);
        if session.shutdown.load(Ordering::Relaxed) {
            return -1;
        }

        let slice = std::slice::from_raw_parts(buf, buf_size as usize);
        if session.tx.send(slice.to_vec()).is_ok() {
            buf_size
        } else {
            // We assume the browser has dropped the connection, so we should shutdown the session.
            session.shutdown.store(true, Ordering::Relaxed);
            -1
        }
    }

    pub fn run(self, metadata: MediaMetadata) -> Result<(), ffmpeg::Error> {
        let mut input = ffmpeg::format::input(&self.url)?;

        let mut video_stream = VideoStream::from_input(&input)?;
        let mut audio_stream_opt = AudioStream::from_input(&input)?;

        info!("Start transcoding {} video, offset={}", self.start_ms, video_stream.name());
        if let Some(ref stream) = audio_stream_opt {
            info!("Start transcoding {} audio", stream.name());
        }

        if self.start_ms > 0 {
            video_stream.seek(&mut input, self.start_ms);
        }

        let mut video_enc = video_stream.create_encoder(&metadata)?;
        let mut audio_enc_opt = match audio_stream_opt {
            Some(ref stream) => Some(stream.create_encoder()?),
            _ => None,
        };

        let mut output_ctx = ffmpeg::format::output_as(&"stream.mp4", "mp4")?;
        video_stream.to_output(&mut output_ctx, &video_enc)?;
        if let (Some(audio_stream), Some(ref audio_enc)) = (audio_stream_opt.as_ref(), audio_enc_opt.as_ref())
        {
            audio_stream.to_output(&mut output_ctx, audio_enc)?;
        }

        let io_buffer_size = 4096;
        let io_buffer = unsafe { ffmpeg::ffi::av_malloc(io_buffer_size) as *mut u8 };
        if io_buffer.is_null() {
            return Err(ffmpeg::Error::Bug);
        }
        let mut avio = unsafe {
            ffmpeg::ffi::avio_alloc_context(
                io_buffer,
                io_buffer_size as i32,
                1,
                &self as *const TranscodeSession as *mut c_void,
                None,
                Some(Self::write_packet_callback),
                None,
            )
        };
        unsafe {
            (*output_ctx.as_mut_ptr()).pb = avio;
        }

        let mut output_opts = ffmpeg::Dictionary::new();
        output_opts.set("movflags", "frag_keyframe+empty_moov+default_base_moof");
        output_ctx.write_header_with(output_opts)?;

        let mut scaler = None;
        let mut packet_encoder = ffmpeg::Packet::empty();
        let mut packet = ffmpeg::Packet::empty();

        let stopwatch = std::time::Instant::now();
        let burst_buffer_sec = 5.0;
        let seek_start_sec = (self.start_ms as f64) / 1000.0;

        let mut audio_resampler: Option<ffmpeg::software::resampling::Context> = None;
        let mut next_audio_pts: i64 = 0;
        let mut next_video_pts: i64 = 0;
        let mut seek_timestamp_offset: Option<i64> = None;

        let video_enc_name =
            video_enc.codec().map(|c| c.name().to_owned()).unwrap_or_else(|| "unknown".to_owned());

        while packet.read(&mut input).is_ok() {
            if self.shutdown.load(Ordering::Relaxed) {
                info!("Shutting down ffmpeg loop...");
                break;
            }

            let stream_index = packet.stream();
            let in_tb = input.stream(stream_index as usize).unwrap().time_base();

            if stream_index == video_stream.index {
                if let Some(pts) = packet.pts() {
                    let time_in_video = pts as f64 * (in_tb.numerator() as f64 / in_tb.denominator() as f64);
                    let time_since_seek = time_in_video - seek_start_sec;
                    let time_since_start = stopwatch.elapsed().as_secs_f64();

                    if time_since_seek > (time_since_start + burst_buffer_sec) {
                        let time_to_sleep = time_since_seek - (time_since_start + burst_buffer_sec);
                        if time_to_sleep > 0.001 {
                            std::thread::sleep(std::time::Duration::from_secs_f64(time_to_sleep.min(0.1)));
                        }
                    }
                }
            }

            if stream_index == video_stream.index {
                let video_dec = &mut video_stream.decoder;

                if let Err(e) = video_dec.send_packet(&packet) {
                    error!("Failed to decode video: {:?}", e);
                    continue;
                }

                while let Ok(Some(mut frame)) = fetch_frame(video_dec, &mut scaler, &video_enc_name) {
                    let video_frame_duration = (video_enc.time_base().denominator() as i64)
                        / (metadata.fps as i64 * video_enc.time_base().numerator() as i64);

                    let assigned_pts = match frame.pts() {
                        Some(f_pts) => {
                            let rescaled = f_pts.rescale(in_tb, video_enc.time_base());

                            if seek_timestamp_offset.is_none() {
                                seek_timestamp_offset = Some(rescaled);
                            }

                            let relative_pts = rescaled - seek_timestamp_offset.unwrap_or(0);
                            let safe_pts = relative_pts.max(next_video_pts);
                            next_video_pts = safe_pts + video_frame_duration;
                            safe_pts
                        }
                        None => {
                            let safe_pts = next_video_pts;
                            next_video_pts += video_frame_duration;
                            safe_pts
                        }
                    };
                    frame.set_pts(Some(assigned_pts));

                    if let Err(e) = video_enc.send_frame(&frame) {
                        error!("Failed to encode video: {:?}", e);
                        continue;
                    }

                    while video_enc.receive_packet(&mut packet_encoder).is_ok() {
                        write_stream_packet(&mut output_ctx, &mut packet_encoder, 0, video_enc.time_base());
                    }
                }
                continue;
            }

            if let Some(ref mut stream) = audio_stream_opt {
                if stream_index == stream.index {
                    let audio_dec = &mut stream.decoder;
                    let audio_enc = match audio_enc_opt.as_mut() {
                        Some(e) => e,
                        None => continue,
                    };

                    if let Err(e) = audio_dec.send_packet(&packet) {
                        error!("Failed to decode audio: {:?}", e);
                        continue;
                    }

                    while let Ok(Some(audio_frame)) =
                        fetch_audio_frame(audio_dec, audio_enc, &mut audio_resampler, &mut next_audio_pts)
                    {
                        if let Err(e) = audio_enc.send_frame(&audio_frame) {
                            error!("Failed to encode audio: {:?}", e);
                            continue;
                        }

                        while audio_enc.receive_packet(&mut packet_encoder).is_ok() {
                            write_stream_packet(
                                &mut output_ctx,
                                &mut packet_encoder,
                                1,
                                audio_enc.time_base(),
                            );
                        }
                    }
                }
            }
        }

        let _ = output_ctx.write_trailer();
        unsafe {
            // Needed to prevent segfaults
            (*output_ctx.as_mut_ptr()).pb = std::ptr::null_mut();
            ffmpeg::ffi::avio_context_free(&mut avio);
        }
        Ok(())
    }
}

#[pyclass]
#[derive(Clone)]
pub struct MediaMetadata {
    #[pyo3(get, set)]
    pub duration: f64,
    #[pyo3(get, set)]
    pub container: String,
    #[pyo3(get, set)]
    pub has_video: bool,
    #[pyo3(get, set)]
    pub video_codec: String,
    #[pyo3(get, set)]
    pub video_tag: String,
    #[pyo3(get, set)]
    pub width: usize,
    #[pyo3(get, set)]
    pub height: usize,
    #[pyo3(get, set)]
    pub video_bitrate: usize,
    #[pyo3(get, set)]
    pub fps: f64,
    #[pyo3(get, set)]
    pub has_audio: bool,
    #[pyo3(get, set)]
    pub audio_codec: String,
    #[pyo3(get, set)]
    pub audio_tag: String,
    #[pyo3(get, set)]
    pub audio_sample_rate: i32,
    #[pyo3(get, set)]
    pub audio_channels: u16,
    #[pyo3(get, set)]
    pub pix_fmt: String,
}

impl MediaMetadata {
    pub fn from_input(ictx: &ffmpeg::format::context::Input) -> Result<Self, String> {
        let video_stream =
            ictx.streams().best(MediaType::Video).ok_or_else(|| "No video stream found".to_string())?;

        let video_ctx = ffmpeg_next::codec::context::Context::from_parameters(video_stream.parameters())
            .map_err(|e| e.to_string())?;

        let video_decoder =
            video_ctx.decoder().video().map_err(|e| format!("Failed to open video decoder: {}", e))?;

        let mut fps = 0.0;
        let frame_rate = video_stream.rate();
        if frame_rate.numerator() > 0 && frame_rate.denominator() > 0 {
            fps = frame_rate.numerator() as f64 / frame_rate.denominator() as f64;
        }

        let video_tag = unsafe {
            String::from_utf8_lossy(&u32::to_le_bytes((*video_stream.parameters().as_ptr()).codec_tag))
                .chars()
                .filter(|c| c.is_alphanumeric())
                .collect::<String>()
        };

        let mut has_audio = false;
        let mut audio_codec = "unknown".to_string();
        let mut audio_tag = "unknown".to_string();
        let mut audio_sample_rate = 0;
        let mut audio_channels = 0;

        if let Some(a_stream) = ictx.streams().best(MediaType::Audio) {
            if let Ok(audio_ctx) = Context::from_parameters(a_stream.parameters()) {
                if let Ok(a_dec) = audio_ctx.decoder().audio() {
                    has_audio = true;
                    audio_codec = codec_name(a_dec.codec());
                    audio_sample_rate = a_dec.rate() as i32;
                    audio_channels = a_dec.channels();
                    audio_tag = unsafe {
                        String::from_utf8_lossy(&u32::to_le_bytes(
                            (*a_stream.parameters().as_ptr()).codec_tag,
                        ))
                        .chars()
                        .filter(|c| c.is_alphanumeric())
                        .collect::<String>()
                    };
                }
            }
        }

        Ok(MediaMetadata {
            duration: ictx.duration() as f64 / f64::from(ffmpeg::ffi::AV_TIME_BASE),
            container: ictx.format().name().to_owned(),
            has_video: true,
            video_codec: codec_name(video_decoder.codec()),
            video_tag,
            width: video_decoder.width() as usize,
            height: video_decoder.height() as usize,
            video_bitrate: video_decoder.bit_rate(),
            fps,
            has_audio,
            audio_codec,
            audio_tag,
            audio_sample_rate,
            audio_channels,
            pix_fmt: format!("{:?}", video_decoder.format()),
        })
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\
                \"duration\":{},\
                \"container\":\"{}\",\
                \"has_video\":{},\
                \"video_codec\":\"{}\",\
                \"video_tag\":\"{}\",\
                \"width\":{},\
                \"height\":{},\
                \"video_bitrate\":{},\
                \"fps\":{},\
                \"has_audio\":{},\
                \"audio_codec\":\"{}\",\
                \"audio_tag\":\"{}\",\
                \"audio_sample_rate\":{},\
                \"audio_channels\":{},\
                \"pix_fmt\":\"{}\"\
            }}",
            self.duration,
            self.container.replace('"', "\\\""),
            self.has_video,
            self.video_codec.replace('"', "\\\""),
            self.video_tag.replace('"', "\\\""),
            self.width,
            self.height,
            self.video_bitrate,
            self.fps,
            self.has_audio,
            self.audio_codec.replace('"', "\\\""),
            self.audio_tag.replace('"', "\\\""),
            self.audio_sample_rate,
            self.audio_channels,
            self.pix_fmt
        )
    }
}

#[derive(Clone, Debug)]
pub struct SupportedCodecs {
    pub video: HashSet<String>,
    pub audio: HashSet<String>,
}

impl SupportedCodecs {
    pub fn from_http_request(request: &str) -> Self {
        let mut video: HashSet<String> = ["h264"].iter().map(|s| s.to_string()).collect();
        let mut audio: HashSet<String> = ["aac"].iter().map(|s| s.to_string()).collect();

        if let Some(v_str) = extract_query_param(request, "v") {
            video = v_str.split(',').map(|s| s.trim().to_string()).collect();
        }
        if let Some(a_str) = extract_query_param(request, "a") {
            audio = a_str.split(',').map(|s| s.trim().to_string()).collect();
        }

        SupportedCodecs { video, audio }
    }
}

pub struct VideoStream {
    pub index: usize,
    pub time_base: ffmpeg::Rational,
    pub params: ffmpeg::codec::Parameters,
    pub codec_id: ffmpeg::codec::Id,
    pub decoder: ffmpeg::decoder::Video,
}

impl VideoStream {
    pub fn from_input(input: &ffmpeg::format::context::Input) -> Result<Self, ffmpeg::Error> {
        trace!("Searching input for video stream");
        let v_stream = input.streams().best(MediaType::Video).ok_or_else(|| {
            error!("No video stream found");
            ffmpeg::Error::StreamNotFound
        })?;

        let codec_id = v_stream.parameters().id();
        let index = v_stream.index();
        let params = v_stream.parameters().clone();
        let ctx = ffmpeg::codec::context::Context::from_parameters(params.clone())?;
        let decoder = ctx.decoder().video()?;

        Ok(Self { index, time_base: v_stream.time_base(), params, codec_id, decoder })
    }

    pub fn name(&self) -> String {
        format!("{:?}", self.codec_id).to_lowercase()
    }

    pub fn seek(&mut self, input: &mut ffmpeg::format::context::Input, start_ms: i64) {
        let seek_target = start_ms.rescale((1, 1000), self.time_base);
        unsafe {
            let _ = ffmpeg::ffi::avformat_seek_file(
                input.as_mut_ptr(),
                self.index as i32,
                i64::MIN,
                seek_target,
                i64::MAX,
                1, // AVSEEK_FLAG_BACKWARD
            );
        }
    }

    pub fn create_encoder(&self, metadata: &MediaMetadata) -> Result<ffmpeg::encoder::Video, ffmpeg::Error> {
        // Ordered list of encoders we'd like to use
        let encoder_candidates = vec![
            "h264_nvenc",        // NVIDIA
            "h264_videotoolbox", // Apple
            "h264_mf",           // Windows Media Foundation
            "h264_vaapi",        // VAAPI Intel/AMD
        ];

        let target_fps = if metadata.fps > 0.0 { metadata.fps.round() as u32 } else { 30 };
        let mut active_encoder = None;

        for enc_name in encoder_candidates {
            if let Some(codec) = ffmpeg::encoder::find_by_name(enc_name) {
                if let Ok(mut ctx) = ffmpeg::codec::context::Context::new_with_codec(codec).encoder().video()
                {
                    ctx.set_width(metadata.width as u32);
                    ctx.set_height(metadata.height as u32);
                    ctx.set_time_base(ffmpeg::Rational::new(1, target_fps as i32));
                    ctx.set_frame_rate(Some(ffmpeg::Rational::new(target_fps as i32, 1)));
                    ctx.set_gop(target_fps);

                    if enc_name == "h264_vaapi" {
                        ctx.set_format(ffmpeg::util::format::Pixel::VAAPI);
                    } else {
                        ctx.set_format(ffmpeg::util::format::Pixel::YUV420P);
                    }

                    let mut opts = ffmpeg::Dictionary::new();
                    match enc_name {
                        "h264_mf" | "h264_videotoolbox" => {
                            opts.set("rate_control", "3");
                            opts.set("quality", "75");
                        }
                        "h264_nvenc" => {
                            opts.set("preset", "p1");
                            opts.set("rc", "constqp");
                            opts.set("cq", "23");
                        }
                        "h264_vaapi" => {
                            opts.set("qp", "23");
                        }
                        _ => {}
                    }

                    if let Ok(encoder) = ctx.open_with(opts) {
                        debug!("Created encoder {}", enc_name);
                        return Ok(encoder);
                    }
                }
            }
        }

        active_encoder.ok_or_else(|| {
            error!("Failed to find supported encoder");
            ffmpeg::Error::EncoderNotFound
        })
    }

    pub fn to_output(
        &self,
        output_ctx: &mut ffmpeg::format::context::Output,
        video_enc: &ffmpeg::encoder::Video,
    ) -> Result<(), ffmpeg::Error> {
        debug!("Creating video stream");
        let mut video_out_stream = output_ctx.add_stream(None)?;

        let fps_rat = self.decoder.frame_rate().unwrap_or(ffmpeg::Rational::new(30, 1));
        let fps_f64 = if fps_rat.numerator() > 0 && fps_rat.denominator() > 0 {
            fps_rat.numerator() as f64 / fps_rat.denominator() as f64
        } else {
            30.0
        };

        let avg_fps = ffmpeg::Rational::new((fps_f64 * 1000.0).round() as i32, 1000);
        video_out_stream.set_avg_frame_rate(avg_fps);
        video_out_stream.set_parameters(video_enc);
        video_out_stream.set_time_base(video_enc.time_base());

        Ok(())
    }
}

pub struct AudioStream {
    pub index: usize,
    pub time_base: ffmpeg::Rational,
    pub params: ffmpeg::codec::Parameters,
    pub codec_id: ffmpeg::codec::Id,
    pub decoder: ffmpeg::decoder::Audio,
}

impl AudioStream {
    pub fn from_input(input: &ffmpeg::format::context::Input) -> Result<Option<Self>, ffmpeg::Error> {
        trace!("Searching input for audio stream");
        match input.streams().best(MediaType::Audio) {
            Some(a_stream) => {
                let codec_id = a_stream.parameters().id();
                let index = a_stream.index();
                let params = a_stream.parameters().clone();
                let ctx = ffmpeg::codec::context::Context::from_parameters(params.clone())?;
                let decoder = ctx.decoder().audio()?;

                Ok(Some(Self { index, time_base: a_stream.time_base(), params, codec_id, decoder }))
            }
            None => {
                warn!("No audio stream found");
                Ok(None)
            }
        }
    }

    pub fn name(&self) -> String {
        format!("{:?}", self.codec_id).to_lowercase()
    }

    pub fn create_encoder(&self) -> Result<ffmpeg::encoder::Audio, ffmpeg::Error> {
        debug!("Creating audio encoder");
        let codec =
            ffmpeg::encoder::find(ffmpeg::codec::Id::AAC).ok_or_else(|| ffmpeg::Error::EncoderNotFound)?;

        let mut ctx = ffmpeg::codec::context::Context::new_with_codec(codec).encoder().audio()?;
        ctx.set_format(ffmpeg::util::format::Sample::F32(ffmpeg::util::format::sample::Type::Planar));
        ctx.set_rate(self.decoder.rate() as i32);
        ctx.set_channel_layout(ffmpeg::channel_layout::ChannelLayout::STEREO);

        match ctx.open() {
            Ok(enc) => Ok(enc),
            Err(e) => {
                error!("Failed to create audio encoder: {:?}", e);
                Err(e)
            }
        }
    }

    pub fn to_output(
        &self,
        output_ctx: &mut ffmpeg::format::context::Output,
        audio_enc: &ffmpeg::encoder::Audio,
    ) -> Result<(), ffmpeg::Error> {
        debug!("Creating audio stream");
        let mut audio_out_stream = output_ctx.add_stream(None)?;
        audio_out_stream.set_parameters(audio_enc);
        audio_out_stream.set_time_base(audio_enc.time_base());
        Ok(())
    }
}

fn codec_name(codec: Option<Codec>) -> String {
    codec.map(|c| c.name().to_owned()).unwrap_or_else(|| "unknown".to_owned())
}

fn extract_query_param(request: &str, param: &str) -> Option<String> {
    let search_token = format!("{}=", param);
    if let Some(pos) = request.find(&search_token) {
        let remainder = &request[pos + search_token.len()..];
        let end_pos = remainder
            .find(|c: char| c == ' ' || c == '&' || c == '\r' || c == '\n')
            .unwrap_or(remainder.len());
        return Some(remainder[..end_pos].to_string());
    }
    None
}

fn write_stream_packet(
    output_ctx: &mut ffmpeg::format::context::Output,
    pkt: &mut ffmpeg::Packet,
    stream_idx: usize,
    src_time_base: ffmpeg::Rational,
) {
    pkt.set_stream(stream_idx);

    if let Some(out_stream) = output_ctx.stream(stream_idx) {
        pkt.rescale_ts(src_time_base, out_stream.time_base());
    }
    let _ = pkt.write_interleaved(output_ctx);
}

pub fn fetch_frame(
    decoder: &mut ffmpeg::decoder::Video,
    scaler: &mut Option<ffmpeg::software::scaling::Context>,
    encoder_name: &str,
) -> Result<Option<ffmpeg::util::frame::Video>, ffmpeg::Error> {
    let mut frame = ffmpeg::util::frame::Video::empty();

    let target_format = if encoder_name.contains("vaapi") {
        ffmpeg::util::format::Pixel::NV12
    } else {
        ffmpeg::util::format::Pixel::YUV420P
    };

    if decoder.receive_frame(&mut frame).is_ok() {
        let mut normalized_frame = ffmpeg::util::frame::Video::empty();

        // Ensure the frame is 8-bits
        if frame.format() != target_format {
            let s = scaler.get_or_insert_with(|| {
                ffmpeg::software::scaling::Context::get(
                    frame.format(),
                    frame.width(),
                    frame.height(),
                    target_format,
                    frame.width(),
                    frame.height(),
                    ffmpeg::software::scaling::Flags::BILINEAR,
                )
                .unwrap()
            });
            s.run(&frame, &mut normalized_frame)?;
            normalized_frame.set_pts(frame.pts());
            return Ok(Some(normalized_frame));
        } else {
            return Ok(Some(frame));
        }
    }

    Ok(None)
}

pub fn fetch_audio_frame(
    decoder: &mut ffmpeg::decoder::Audio,
    encoder: &ffmpeg::encoder::Audio,
    resampler: &mut Option<ffmpeg::software::resampling::Context>,
    next_pts: &mut i64,
) -> Result<Option<ffmpeg::util::frame::Audio>, ffmpeg::Error> {
    let mut frame = ffmpeg::util::frame::Audio::empty();

    if decoder.receive_frame(&mut frame).is_ok() {
        let r = resampler.get_or_insert_with(|| {
            ffmpeg::software::resampling::Context::get(
                frame.format(),
                frame.channel_layout(),
                frame.rate(),
                encoder.format(),
                encoder.channel_layout(),
                encoder.rate(),
            )
            .unwrap()
        });

        let required_samples = encoder.frame_size() as usize;

        let mut resampled_frame =
            ffmpeg::util::frame::Audio::new(encoder.format(), required_samples, encoder.channel_layout());

        unsafe {
            resampled_frame.alloc(encoder.format(), required_samples, encoder.channel_layout());
        }
        resampled_frame.set_rate(encoder.rate() as u32);

        if r.run(&frame, &mut resampled_frame).is_ok() {
            resampled_frame.set_pts(Some(*next_pts));

            *next_pts += required_samples as i64;

            return Ok(Some(resampled_frame));
        }
    }

    Ok(None)
}
