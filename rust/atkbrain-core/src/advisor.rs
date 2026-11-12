//! 御主开口门闩。红队、SRC、CTF 用同一套，不按赛道分叉。

pub fn assigned_still_open(assigned: &[String], open_intents: &[String]) -> bool {
    if assigned.is_empty() {
        return false;
    }
    assigned.iter().any(|id| open_intents.iter().any(|open| open == id))
}

pub fn should_yield_turn_to_advisor() -> bool {
    false
}

pub fn unfinished_verification(
    turn: i64,
    stall_class: &str,
    no_progress: i64,
    last_steer_turn: Option<i64>,
    hold_turns: i64,
    in_flight: bool,
    hard_turns: i64,
) -> Option<&'static str> {
    let sc = stall_class.trim().to_ascii_lowercase();
    let need_pivot = sc == "method" || sc == "chain";
    let hold_turns = hold_turns.max(0);
    let hard_turns = hard_turns.max(1);
    let turn = turn.max(0);
    let no_progress = no_progress.max(0);
    if need_pivot && no_progress >= hard_turns {
        return None;
    }
    if let Some(last) = last_steer_turn {
        if hold_turns > 0 {
            let elapsed = turn - last;
            if (0..hold_turns).contains(&elapsed) {
                return Some("hold_course");
            }
        }
    }
    if in_flight && !need_pivot {
        return Some("in_flight");
    }
    None
}

pub fn should_review_advisor(
    turn: i64,
    interval: i64,
    stall_class: &str,
    no_progress: i64,
    last_steer_turn: Option<i64>,
    hold_turns: i64,
    in_flight: bool,
    hard_turns: i64,
    pivots: i64,
    first_turns: i64,
) -> (bool, &'static str) {
    let turn = turn.max(0);
    let interval = interval.max(1);
    let first = first_turns.max(0);
    let hold_turns = hold_turns.max(0);
    let hard_turns = hard_turns.max(1);
    let no_progress = no_progress.max(0);
    let pivots_n = pivots.max(0);
    let sc = stall_class.trim().to_ascii_lowercase();
    let need_pivot = sc == "method" || sc == "chain";
    let hard_stuck = need_pivot && no_progress >= hard_turns;
    if last_steer_turn.is_none() && (pivots_n <= 0 || (first > 0 && turn <= first)) {
        return (true, "turn");
    }
    if hard_stuck {
        return (true, "turn");
    }
    if let Some(blocked) = unfinished_verification(
        turn,
        stall_class,
        no_progress,
        last_steer_turn,
        hold_turns,
        in_flight,
        hard_turns,
    ) {
        return (false, blocked);
    }
    if last_steer_turn.is_none() {
        return (true, "turn");
    }
    let elapsed = turn - last_steer_turn.unwrap_or(0);
    if elapsed < interval && !need_pivot {
        return (false, "let_commander");
    }
    if need_pivot || no_progress >= 1 {
        return (true, "turn");
    }
    (false, "progress")
}

pub fn stall_pause_due(no_progress: i64, limit: i64) -> bool {
    let n = no_progress.max(0);
    let cap = limit.max(0);
    cap > 0 && n >= cap
}

pub fn hold_note_text(in_flight: bool, hold_course: bool) -> &'static str {
    if hold_course {
        return "刚下过御主指令，从者还在执行。必须 noop。禁止另起同义散文或改打目录枚举。路线包内的并行子智能体可以继续。红队/SRC/CTF 同样生效。";
    }
    if in_flight {
        return "本轮认领的 Intent 仍开放（当前假设尚未证实或否证）。必须 noop。禁止改打目录枚举；让从者把路线包里的并行验证做完并 resolve_intent。红队/SRC/CTF 同样生效。";
    }
    "（无）"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_turn_asks_and_hold_blocks() {
        assert_eq!(should_review_advisor(1, 3, "none", 0, None, 3, false, 6, 0, 2), (true, "turn"));
        assert_eq!(
            should_review_advisor(2, 3, "none", 0, Some(2), 3, false, 6, 1, 2),
            (false, "hold_course")
        );
        assert!(stall_pause_due(5, 5));
        assert!(!stall_pause_due(4, 5));
        assert!(!should_yield_turn_to_advisor());
    }
}
