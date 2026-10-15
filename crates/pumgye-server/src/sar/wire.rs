use super::*;
pub(super) struct Frame {
    pub(super) length: usize,
    pub(super) close: bool,
}
pub(super) async fn read_header<S: AsyncRead + Unpin>(
    io: &mut S,
    first: u8,
) -> std::io::Result<zeroize::Zeroizing<Vec<u8>>> {
    let mut header = zeroize::Zeroizing::new(Vec::with_capacity(1024));
    header.push(first);
    // Restrict reads to header boundary; TLS may still buffer later application data.
    // No second frame is processed until this frame's complete response flush.
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= 16 * 1024 {
            return Err(io_error());
        }
        let byte = io.read_u8().await?;
        if byte == b'\n' && header.last() != Some(&b'\r') {
            return Err(io_error());
        }
        if header.last() == Some(&b'\r') && byte != b'\n' {
            return Err(io_error());
        }
        header.push(byte);
    }
    Ok(header)
}
pub(super) fn parse_header(bytes: &[u8], authority: &str, token: &str) -> Result<Frame, u16> {
    if !bytes.starts_with(b"POST ") || bytes.windows(2).any(|v| v[1] == b'\n' && v[0] != b'\r') {
        return Err(400);
    }
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    if request.parse(bytes).map_err(|_| 400u16)? != httparse::Status::Complete(bytes.len())
        || request.version != Some(1)
    {
        return Err(400);
    }
    if request.method != Some("POST") || request.path != Some("/v1/kubernetes/subjectaccessreviews")
    {
        return Err(404);
    }
    let mut host = None;
    let mut length = None;
    let mut authorization = None;
    let mut content_type = None;
    let mut connection = None;
    for h in request.headers.iter() {
        let value = std::str::from_utf8(h.value).map_err(|_| 400u16)?;
        if value.bytes().any(|b| b < 32 || b == 127) {
            return Err(400);
        }
        let slot = if h.name.eq_ignore_ascii_case("host") {
            Some(&mut host)
        } else if h.name.eq_ignore_ascii_case("content-length") {
            Some(&mut length)
        } else if h.name.eq_ignore_ascii_case("authorization") {
            Some(&mut authorization)
        } else if h.name.eq_ignore_ascii_case("content-type") {
            Some(&mut content_type)
        } else if h.name.eq_ignore_ascii_case("connection") {
            Some(&mut connection)
        } else {
            None
        };
        if let Some(slot) = slot
            && slot.replace(value).is_some()
        {
            return Err(400);
        }
        if [
            "transfer-encoding",
            "trailer",
            "upgrade",
            "expect",
            "content-encoding",
        ]
        .iter()
        .any(|s| h.name.eq_ignore_ascii_case(s))
        {
            return Err(400);
        }
    }
    if host != Some(authority) {
        return Err(400);
    }
    let credential = authorization
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(401u16)?;
    if !crate::credential_matches(credential.as_bytes(), token.as_bytes()) {
        return Err(401);
    }
    if !matches!(
        content_type,
        Some("application/json" | "application/json; charset=utf-8")
    ) {
        return Err(415);
    }
    let length = length.ok_or(400u16)?;
    if length.is_empty()
        || length.len() > 5
        || length.starts_with('0')
        || !length.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(400);
    }
    let length: usize = length.parse().map_err(|_| 400u16)?;
    if length > sar_wire::MAX_BODY {
        return Err(413);
    }
    let close = match connection {
        None | Some("keep-alive") => false,
        Some("close") => true,
        _ => return Err(400),
    };
    Ok(Frame { length, close })
}
pub(super) fn response_header(status: u16, length: usize, close: bool) -> String {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        _ => "Service Unavailable",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {length}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nConnection: {}\r\n\r\n",
        if close { "close" } else { "keep-alive" }
    )
}
