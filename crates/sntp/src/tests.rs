use super::*;

/// 2026-10-31 00:00:00 UTC.
const NOW_MS: i64 = 1_793_404_800_000;
/// The image's build time, a month earlier.
const FLOOR_S: u64 = 1_790_812_800;

fn reply(origin: Ts, t2_ms: i64, t3_ms: i64) -> [u8; PACKET_LEN] {
    let mut p = [0u8; PACKET_LEN];
    p[0] = (4 << 3) | 4;
    p[1] = 2;
    p[24..32].copy_from_slice(&origin.0.to_be_bytes());
    p[32..40].copy_from_slice(&Ts::from_unix_ms(t2_ms as u64).0.to_be_bytes());
    p[40..48].copy_from_slice(&Ts::from_unix_ms(t3_ms as u64).0.to_be_bytes());
    p
}

fn origin() -> Ts {
    Ts::from_unix_ms(NOW_MS as u64).with_nonce(0xdead_beef)
}

#[test]
fn timestamps_round_trip_and_the_era_rolls() {
    for ms in [0u64, 1, 999, 1_000, NOW_MS as u64, 4_102_444_800_123] {
        let back = Ts::from_unix_ms(ms).to_unix_ms().unwrap() as u64;
        assert!(back.abs_diff(ms) <= 1, "{ms} -> {back}");
    }
    // 2040: past the end of era 0 the seconds field wraps and is read as era 1.
    let t = Ts::from_unix_ms(2_240_000_000_000);
    assert!(t.0 >> 32 < 0x8000_0000);
    assert!(t.to_unix_ms().unwrap().abs_diff(2_240_000_000_000) <= 1);
}

#[test]
fn the_request_is_a_v4_client_packet_with_only_the_transmit_time() {
    let p = build_request(origin());
    assert_eq!(p[0], 0x23);
    assert!(p[1..40].iter().all(|&b| b == 0));
    assert_eq!(&p[40..48], &origin().0.to_be_bytes());
}

#[test]
fn a_good_reply_gives_the_offset() {
    // Server is 5 s ahead; 40 ms each way; 2 ms processing.
    let t1 = NOW_MS;
    let t2 = NOW_MS + 5_000 + 40;
    let t3 = t2 + 2;
    let t4 = NOW_MS + 82;
    let s = parse_response(&reply(origin(), t2, t3), origin()).unwrap();
    let m = measure(t1, t4, &s).unwrap();
    assert!((m.offset_ms - 5_000).abs() <= 1, "{m:?}");
    assert_eq!(m.delay_ms, 80);
}

#[test]
fn adversarial_packets_are_refused() {
    let o = origin();
    let good = reply(o, NOW_MS, NOW_MS);
    assert!(parse_response(&good, o).is_ok());
    // Short.
    assert_eq!(parse_response(&good[..47], o), Err(Reject::TooShort));
    // Wrong origin (also: an all-zero origin never matches).
    let mut p = good;
    p[31] ^= 1;
    assert_eq!(parse_response(&p, o), Err(Reject::WrongOrigin));
    assert_eq!(parse_response(&good, Ts(0)), Err(Reject::WrongOrigin));
    // Stratum 0 (kiss of death), 16 and 255.
    for (st, want) in [
        (0, Reject::KissOfDeath),
        (16, Reject::BadStratum),
        (255, Reject::BadStratum),
    ] {
        let mut p = good;
        p[1] = st;
        assert_eq!(parse_response(&p, o), Err(want));
    }
    // LI = 3.
    let mut p = good;
    p[0] |= 3 << 6;
    assert_eq!(parse_response(&p, o), Err(Reject::Unsynchronised));
    // LI 1 and 2 (leap second pending) are fine.
    p[0] = (1 << 6) | (4 << 3) | 4;
    assert!(parse_response(&p, o).is_ok());
    // Modes: client, symmetric, broadcast; versions 2 and 5.
    for b0 in [
        0x23u8,
        0x24 | 0x01,
        (4 << 3) | 5,
        (2 << 3) | 4,
        (5 << 3) | 4,
        4,
    ] {
        let mut p = good;
        p[0] = b0;
        assert_eq!(parse_response(&p, o), Err(Reject::BadMode), "{b0:#x}");
    }
    // Zero receive or transmit time, transmit before receive.
    let mut p = good;
    p[32..40].fill(0);
    assert_eq!(parse_response(&p, o), Err(Reject::BadTimestamps));
    let mut p = good;
    p[40..48].fill(0);
    assert_eq!(parse_response(&p, o), Err(Reject::BadTimestamps));
    assert_eq!(
        parse_response(&reply(o, NOW_MS + 10, NOW_MS), o),
        Err(Reject::BadTimestamps)
    );
    // Root dispersion of a minute.
    let mut p = good;
    p[8..12].copy_from_slice(&(60u32 << 16).to_be_bytes());
    assert_eq!(parse_response(&p, o), Err(Reject::BadRoot));
}

#[test]
fn bogus_round_trips_are_refused() {
    let s = Sample {
        stratum: 2,
        leap: 0,
        t2_ms: NOW_MS,
        t3_ms: NOW_MS,
    };
    // Reply "received" before it was sent, and a 10 s round trip.
    assert_eq!(measure(NOW_MS, NOW_MS - 500, &s), None);
    assert_eq!(measure(NOW_MS, NOW_MS + 10_000, &s), None);
    // Extreme numbers do not overflow.
    let huge = Sample {
        stratum: 2,
        leap: 0,
        t2_ms: i64::MAX,
        t3_ms: i64::MAX,
    };
    assert_eq!(measure(i64::MIN, i64::MAX, &huge), None);
}

#[test]
fn the_median_ignores_one_liar_out_of_three() {
    let c = consensus(&[40, 25_000_000, -3]).unwrap();
    assert_eq!(c.offset_ms, 40);
    assert_eq!((c.answered, c.agreeing), (3, 2));
    assert!(c.offset_ms.abs() < AGREE_MS);
    // The liar the other way.
    let c = consensus(&[-90_000_000, 10, 30]).unwrap();
    assert!(c.offset_ms.abs() < AGREE_MS);
    // Three answers that all differ: no majority.
    assert_eq!(consensus(&[0, 10_000, 20_000]), None);
    // Two that disagree: none either; two that agree: fine.
    assert_eq!(consensus(&[0, 5_000]), None);
    assert!(consensus(&[0, 200]).is_some());
    assert!(consensus(&[7]).is_some());
    assert_eq!(consensus(&[]), None);
    // Four: two honest, two liars in different places.
    assert_eq!(consensus(&[0, 3_000, 90_000, 5]), None);
}

fn bounds() -> Bounds {
    Bounds {
        floor_unix_s: FLOOR_S,
        max_step_ms: 600_000,
    }
}

#[test]
fn an_unknown_clock_may_be_set_far_forward_once() {
    let mut d = Discipline::new(bounds());
    // The RTC said 2020: unknown; the clock reads uptime (5 s).
    let off = NOW_MS - 5_000;
    assert_eq!(
        d.decide(None, off),
        Decision::Apply {
            adjust_ms: off,
            step: StepKind::Boot
        }
    );
    // Afterwards a large step is refused.
    assert_eq!(
        d.decide(Some(NOW_MS), 3_600_000),
        Decision::Refuse(Refusal::TooLarge)
    );
}

#[test]
fn nothing_goes_below_the_build_time() {
    let mut d = Discipline::new(bounds());
    // A server from 1970 on an unknown clock.
    assert_eq!(d.decide(None, 0), Decision::Refuse(Refusal::BelowFloor));
    assert_eq!(
        d.decide(None, FLOOR_S as i64 * 1000 - 1),
        Decision::Refuse(Refusal::BelowFloor)
    );
    assert!(!d.synced);
    // Known clock just above the floor, a small backward step across it.
    let near = FLOOR_S as i64 * 1000 + 100;
    assert_eq!(
        d.decide(Some(near), -500),
        Decision::Refuse(Refusal::BelowFloor)
    );
}

#[test]
fn the_boot_step_forward_is_free_backward_is_bounded() {
    let mut d = Discipline::new(bounds());
    // Known RTC an hour behind NTP... or two years behind.
    assert_eq!(
        d.decide(Some(NOW_MS - 63_000_000_000), 63_000_000_000),
        Decision::Apply {
            adjust_ms: 63_000_000_000,
            step: StepKind::Boot
        }
    );
    let mut d = Discipline::new(bounds());
    // A far backward jump at boot is refused (and does not use the boot step).
    assert_eq!(
        d.decide(Some(NOW_MS + 86_400_000), -86_400_000),
        Decision::Refuse(Refusal::BootBackward)
    );
    assert!(!d.synced);
    assert!(matches!(
        d.decide(Some(NOW_MS + 30_000), -30_000),
        Decision::Apply {
            step: StepKind::Step,
            ..
        }
    ));
}

#[test]
fn later_corrections_are_bounded_each_and_together() {
    let mut d = Discipline::new(Bounds {
        floor_unix_s: FLOOR_S,
        max_step_ms: 1_000,
    });
    assert!(matches!(
        d.decide(Some(NOW_MS), 50),
        Decision::Apply {
            step: StepKind::Slew,
            ..
        }
    ));
    // 10 s: too large.
    assert_eq!(
        d.decide(Some(NOW_MS), 10_000),
        Decision::Refuse(Refusal::TooLarge)
    );
    assert_eq!(
        d.decide(Some(NOW_MS), -10_000),
        Decision::Refuse(Refusal::TooLarge)
    );
    // 800 ms steps: the first fits the budget (800 <= 1000), the second
    // would make 1600.
    assert!(matches!(
        d.decide(Some(NOW_MS), 800),
        Decision::Apply {
            step: StepKind::Step,
            ..
        }
    ));
    assert_eq!(d.drift_ms, 800);
    assert_eq!(
        d.decide(Some(NOW_MS), 800),
        Decision::Refuse(Refusal::DriftBudget)
    );
    // Correcting back is allowed.
    assert!(matches!(
        d.decide(Some(NOW_MS), -800),
        Decision::Apply { .. }
    ));
    assert_eq!(d.drift_ms, 0);
    // Saturating arithmetic: nothing panics on extremes.
    let _ = d.decide(Some(i64::MAX), i64::MAX);
    let _ = d.decide(Some(i64::MIN), i64::MIN);
    let _ = d.decide(None, i64::MIN);
}

// ---- the client ----

const A: (Ip, u16) = ([192, 0, 2, 1], PORT);
const B: (Ip, u16) = ([192, 0, 2, 2], PORT);
const C: (Ip, u16) = ([192, 0, 2, 3], 12300);

/// Runs one round against servers answering with the given clock offset
/// (`None`: silent), 10 ms each way. Returns the outcome.
fn round(
    c: &mut Client<'_>,
    servers: &[(Ip, u16)],
    offsets: &[Option<i64>],
    now: &mut u64,
) -> Outcome {
    let mut pending = Vec::new();
    loop {
        let wall = NOW_MS + *now as i64;
        let (req, out) = c.poll(*now, wall, 0x1234_5678 + *now as u32);
        if let Some(o) = out {
            return o;
        }
        match req {
            Some(r) => {
                let i = servers.iter().position(|s| s.0 == r.dst).unwrap();
                assert_eq!(r.port, servers[i].1);
                pending.push((i, r, wall));
            }
            None => {
                // Network: answers arrive 20 ms later.
                *now += 20;
                for (i, r, t1) in pending.drain(..) {
                    if let Some(off) = offsets[i] {
                        let o = Ts(u64::from_be_bytes(r.payload[40..48].try_into().unwrap()));
                        let t2 = t1 + 10 + off;
                        let p = reply(o, t2, t2);
                        c.input(*now, t1 + 20, servers[i].0, servers[i].1, &p);
                    }
                }
                *now += 1;
            }
        }
    }
}

#[test]
fn three_servers_one_lying_gives_the_honest_time() {
    let servers = [A, B, C];
    let mut c = Client::new(
        Config {
            servers: &servers,
            interval_ms: 3_600_000,
        },
        0,
    );
    let mut now = 0;
    let out = round(
        &mut c,
        &servers,
        &[Some(30), Some(2_000_000_000), Some(-20)],
        &mut now,
    );
    let Outcome::Agreed(k) = out else {
        panic!("{out:?}")
    };
    assert!(k.offset_ms.abs() <= 30, "{k:?}");
    assert_eq!((k.answered, k.agreeing), (3, 2));
    assert_eq!(c.stats.accepted, 3);
}

#[test]
fn a_lone_answer_of_three_is_not_enough_and_retries_back_off() {
    let servers = [A, B, C];
    let mut c = Client::new(
        Config {
            servers: &servers,
            interval_ms: 3_600_000,
        },
        0,
    );
    let mut now = 0;
    let out = round(&mut c, &servers, &[None, Some(9_999_999), None], &mut now);
    assert_eq!(
        out,
        Outcome::Failed {
            answered: 1,
            asked: 3
        }
    );
    // Not before the retry delay, then again; the delay doubles.
    let t = now;
    let (r, o) = c.poll(t + 1_000, NOW_MS, 1);
    assert!(r.is_none() && o.is_none());
    now = t + RETRY_MS;
    let _ = round(&mut c, &servers, &[None, None, None], &mut now);
    let t2 = now;
    let (r, _) = c.poll(t2 + RETRY_MS, NOW_MS, 1);
    assert!(r.is_none(), "second retry waits 2x");
}

#[test]
fn a_success_waits_the_interval_and_rate_limits_rounds() {
    let servers = [A];
    let mut c = Client::new(
        Config {
            servers: &servers,
            interval_ms: 3_600_000,
        },
        0,
    );
    assert_eq!(c.quorum(), 1);
    let mut now = 0;
    let out = round(&mut c, &servers, &[Some(10)], &mut now);
    assert!(matches!(out, Outcome::Agreed(_)));
    c.succeeded(now);
    let (r, _) = c.poll(now + 3_599_000, NOW_MS, 1);
    assert!(r.is_none());
    let (r, _) = c.poll(now + 3_600_000, NOW_MS, 1);
    assert!(r.is_some());
    // A tiny interval cannot exceed one round per MIN_ROUND_GAP_MS.
    let mut c = Client::new(
        Config {
            servers: &servers,
            interval_ms: 1,
        },
        0,
    );
    let mut now = 0;
    let _ = round(&mut c, &servers, &[Some(10)], &mut now);
    c.succeeded(now);
    assert!(c.poll(now + MIN_ROUND_GAP_MS - 1, NOW_MS, 1).0.is_none());
    assert!(c.poll(now + MIN_ROUND_GAP_MS, NOW_MS, 1).0.is_some());
}

#[test]
fn unsolicited_forged_and_replayed_datagrams_are_dropped() {
    let servers = [A, B];
    let mut c = Client::new(
        Config {
            servers: &servers,
            interval_ms: 3_600_000,
        },
        0,
    );
    // Nothing asked yet.
    c.input(0, NOW_MS, A.0, A.1, &reply(origin(), NOW_MS, NOW_MS));
    assert_eq!(c.stats.unsolicited, 1);
    let (ra, _) = c.poll(0, NOW_MS, 7);
    let ra = ra.unwrap();
    let (rb, _) = c.poll(0, NOW_MS, 9);
    let rb = rb.unwrap();
    assert_eq!((ra.dst, rb.dst), (A.0, B.0));
    let oa = Ts(u64::from_be_bytes(ra.payload[40..48].try_into().unwrap()));
    let ob = Ts(u64::from_be_bytes(rb.payload[40..48].try_into().unwrap()));
    assert_ne!(oa, ob);
    // From a third address, from the right address but the wrong port, with
    // a guessed origin, and with B's origin on A's answer.
    c.input(
        5,
        NOW_MS,
        [198, 51, 100, 9],
        PORT,
        &reply(oa, NOW_MS, NOW_MS),
    );
    c.input(5, NOW_MS, A.0, 4444, &reply(oa, NOW_MS, NOW_MS));
    c.input(
        5,
        NOW_MS,
        A.0,
        A.1,
        &reply(origin(), NOW_MS + 9_000_000, NOW_MS + 9_000_000),
    );
    c.input(
        5,
        NOW_MS,
        A.0,
        A.1,
        &reply(ob, NOW_MS + 9_000_000, NOW_MS + 9_000_000),
    );
    assert_eq!(c.stats.accepted, 0);
    assert_eq!(c.stats.unsolicited, 3);
    assert_eq!(c.stats.rejected, 2);
    // The real answers still count after the forgeries, once each.
    c.input(
        10,
        NOW_MS + 10,
        A.0,
        A.1,
        &reply(oa, NOW_MS + 5, NOW_MS + 5),
    );
    c.input(
        10,
        NOW_MS + 10,
        A.0,
        A.1,
        &reply(oa, NOW_MS + 5, NOW_MS + 5),
    );
    c.input(
        10,
        NOW_MS + 10,
        B.0,
        B.1,
        &reply(ob, NOW_MS + 5, NOW_MS + 5),
    );
    assert_eq!(c.stats.accepted, 2);
    assert_eq!(c.stats.unsolicited, 4);
    // Both answered: the round ends at the next poll, with their offset.
    let (r, o) = c.poll(11, NOW_MS + 11, 1);
    assert!(r.is_none());
    assert!(matches!(o, Some(Outcome::Agreed(k)) if k.answered == 2 && k.offset_ms.abs() < 10));
}

#[test]
fn a_kiss_of_death_silences_the_server_for_the_interval() {
    let servers = [A];
    let mut c = Client::new(
        Config {
            servers: &servers,
            interval_ms: 60_000,
        },
        0,
    );
    let r = c.poll(0, NOW_MS, 3).0.unwrap();
    let o = Ts(u64::from_be_bytes(r.payload[40..48].try_into().unwrap()));
    let mut kod = reply(o, NOW_MS, NOW_MS);
    kod[1] = 0;
    kod[12..16].copy_from_slice(b"RATE");
    c.input(5, NOW_MS, A.0, A.1, &kod);
    assert_eq!(c.stats.kiss_of_death, 1);
    let (r, out) = c.poll(6, NOW_MS, 3);
    assert!(r.is_none());
    assert_eq!(
        out,
        Some(Outcome::Failed {
            answered: 0,
            asked: 1
        })
    );
    // Next round: the server is skipped until the interval has passed.
    let mut t = 0;
    let (mut asked, mut ended) = (false, false);
    for step in 0..40 {
        t = 6 + RETRY_MS + step;
        let (r, o) = c.poll(t, NOW_MS, 3);
        asked |= r.is_some();
        ended |= o.is_some();
        if ended {
            break;
        }
    }
    assert!(!asked && ended, "t={t}");
}

#[test]
fn a_request_that_could_not_be_sent_is_retried_in_the_round() {
    let servers = [A, B];
    let mut c = Client::new(
        Config {
            servers: &servers,
            interval_ms: 3_600_000,
        },
        0,
    );
    let r = c.poll(0, NOW_MS, 3).0.unwrap();
    c.unsent(r.dst);
    let again = c.poll(1, NOW_MS, 4).0.unwrap();
    assert_eq!(again.dst, r.dst);
    assert_ne!(again.payload, r.payload, "a fresh nonce");
}

#[test]
fn no_servers_no_traffic() {
    let mut c = Client::new(
        Config {
            servers: &[],
            interval_ms: 3_600_000,
        },
        0,
    );
    assert!(!c.enabled());
    assert_eq!(c.poll(1_000_000, NOW_MS, 1), (None, None));
}
