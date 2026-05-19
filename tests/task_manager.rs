use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use _rust::task_manager::TaskManager;

#[tokio::test]
async fn test_task_manager_spawn_and_cancel() {
    let manager = TaskManager::new(tokio::runtime::Handle::current());

    let task_id = manager.spawn("mock-task", async {
        tokio::time::sleep(Duration::from_secs(10)).await;
    });
    assert_eq!(task_id, 0);
    assert!(manager.cancel_task(task_id));
}

#[tokio::test]
async fn test_task_manager_intervals_and_shutdown() {
    let manager = TaskManager::new(tokio::runtime::Handle::current());
    let tick_counter = Arc::new(AtomicUsize::new(0));
    let t_clone = tick_counter.clone();

    manager.spawn_interval("mock-interval", Duration::from_millis(10), true, move || {
        let c = t_clone.clone();
        async move {
            c.fetch_add(1, Ordering::Relaxed);
        }
    });

    tokio::time::sleep(Duration::from_millis(35)).await;
    assert!(tick_counter.load(Ordering::Relaxed) >= 2);
    manager.shutdown(1).await;
}
