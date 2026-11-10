//! ADR-346: the topic tree's walks (`subscribers`, `retained_matching`)
//! recurse once per topic level, and only `limits.max_topic_levels` bounds
//! the depth. That limit used to accept any u32, so with it and
//! `limits.max_topic_len` raised one device could publish (retained) or
//! subscribe a topic some 800+ levels deep and overflow a data core's
//! 128 KiB stack: a fatal fault that stops the whole broker. The limit is
//! now capped at 128 (`urmqtt_cfg::fields::MAX_TOPIC_LEVELS`); this test
//! walks a tree of exactly that depth on a 128 KiB thread, in the
//! unoptimised test build (larger frames than the kernel's).

use std::sync::Arc;
use urmqtt_broker::{MsgInner, SubOpts, Topics};
use urmqtt_mqtt::QoS;

/// The cap of `limits.max_topic_levels` (cfg and config-schema).
const MAX_TOPIC_LEVELS: usize = 128;
/// A data core's main stack (kernel `layout::MAIN_STACK_SIZE`).
const DATA_CORE_STACK: usize = 128 << 10;

fn walk_at_the_cap() {
    let topic = vec!["a"; MAX_TOPIC_LEVELS].join("/");
    let mut t = Topics::new();
    // A literal subscription along the whole chain: the literal-child call
    // in `collect` is not a tail call, so this is the deepest walk.
    let n = t.intern_filter(&topic);
    t.subscribe(n, 1, SubOpts::default());
    let mut subs = Vec::new();
    t.subscribers(&topic, &mut subs);
    assert_eq!(subs.len(), 1);
    // A retained message at the bottom, found by a literal filter, by `#`
    // (`all_below`) and by `+` levels (`walk_retained`).
    let msg = Arc::new(MsgInner::new(&topic, b"x"));
    t.set_retained(&topic, msg, QoS::AtMostOnce, None);
    let plus = vec!["+"; MAX_TOPIC_LEVELS].join("/");
    for filter in [topic.as_str(), "#", "a/#", plus.as_str()] {
        let mut out = Vec::new();
        t.retained_matching(filter, &mut out);
        assert_eq!(out.len(), 1, "{filter:.16}");
    }
}

#[test]
fn deepest_allowed_topic_fits_a_data_core_stack() {
    std::thread::Builder::new()
        .stack_size(DATA_CORE_STACK)
        .spawn(walk_at_the_cap)
        .unwrap()
        .join()
        .unwrap();
}
