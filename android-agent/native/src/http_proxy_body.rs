use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{Response, StatusCode};

pub(crate) type AgentBody = BoxBody<Bytes, hyper::Error>;

// HTTP proxy 同时处理普通 HTTP 请求和 CONNECT，统一用 boxed body 简化返回类型。
pub(crate) fn boxed<B>(body: B) -> AgentBody
where
    B: hyper::body::Body<Data = Bytes, Error = hyper::Error> + Send + Sync + 'static,
{
    BoxBody::new(body)
}

pub(crate) fn empty() -> AgentBody {
    boxed(Full::new(Bytes::new()).map_err(|err| match err {}))
}

pub(crate) fn text_response(status: StatusCode, text: &'static str) -> Response<AgentBody> {
    Response::builder()
        .status(status)
        .body(boxed(
            Full::new(Bytes::from_static(text.as_bytes())).map_err(|err| match err {}),
        ))
        .unwrap()
}
