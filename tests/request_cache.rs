use std::sync::Arc;
use std::time::Duration;

use _rust::request_cache::{CacheResult, RequestCache};

#[tokio::test]
async fn test_request_cache_stream_lifecycle() {
    let cache = RequestCache::new();
    let pfx = "REQ".to_string();

    let (mut rx, guard) = cache.add(pfx.clone(), 100u32, 10);
    assert!(cache.has(&pfx, 100u32));

    if let CacheResult::Stream(tx) = cache.get(&pfx, 100u32) {
        tx.send(b"DATA".to_vec()).await.unwrap();
    } else {
        panic!();
    }
    assert_eq!(rx.recv().await.unwrap(), b"DATA");

    drop(guard);
    assert!(!cache.has(&pfx, 100u32));
}

#[tokio::test]
async fn test_request_cache_identifiers() {
    let cache = RequestCache::new();
    let pfx = "IDENT".to_string();

    cache.add_identifier(pfx.clone(), 200u32, None, Some(Arc::new(42i32)));
    if let CacheResult::Identifier(Some(any)) = cache.pop(&pfx, 200u32) {
        assert_eq!(*any.downcast_ref::<i32>().unwrap(), 42);
    } else {
        panic!();
    }

    cache.add_identifier(pfx.clone(), 300u32, Some(1), None);
    tokio::time::sleep(Duration::from_millis(1050)).await;
    assert!(!cache.has(&pfx, 300u32));
}
