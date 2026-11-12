//! 托管网关：白名单模型地址改写，以及平台环境变量别名。

use std::collections::HashMap;

const GATEWAY_SUFFIX: &str = ".tsecbench.gw";

const EXACT_HOSTS: &[&str] = &[
    "api.hunyuan.cloud.tencent.com",
    "api.lkeap.cloud.tencent.com",
    "tokenhub.tencentmaas.com",
    "api.deepseek.com",
    "dashscope.aliyuncs.com",
    "qianfan.baidubce.com",
    "ark.cn-beijing.volces.com",
    "open.bigmodel.cn",
    "api.moonshot.cn",
    "api.siliconflow.cn",
    "spark-api-open.xf-yun.com",
    "api.minimaxi.com",
    "api.stepfun.com",
    "api.lingyiwanwu.com",
    "api.baichuan-ai.com",
    "api.xiaomimimo.com",
    "api.kimi.com",
    "agent-awd.baidu.com",
];

pub fn hosted_enabled(env: &HashMap<String, String>) -> bool {
    truthy(env.get("ATKBRAIN_HOSTED").map(String::as_str))
}

pub fn gateway_enabled(env: &HashMap<String, String>) -> bool {
    truthy(env.get("ATKBRAIN_LLM_GATEWAY").map(String::as_str)) || hosted_enabled(env)
}

fn truthy(val: Option<&str>) -> bool {
    matches!(
        val.unwrap_or("").trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn host_allowed(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        return false;
    }
    if h.ends_with(GATEWAY_SUFFIX) || EXACT_HOSTS.contains(&h.as_str()) {
        return true;
    }
    h.ends_with(".maas.aliyuncs.com")
}

pub fn rewrite_llm_url_for_gateway(url: &str) -> String {
    let raw = url.trim();
    let Some(rest) = raw.split_once("://").map(|(_, rest)| rest) else {
        return raw.to_string();
    };
    let (authority, path) = rest.split_once('/').map(|(a, p)| (a, format!("/{p}"))).unwrap_or((rest, String::new()));
    let (auth, hostport) = match authority.rsplit_once('@') {
        Some((user, host)) => (format!("{user}@"), host),
        None => (String::new(), authority),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && !host.contains(':') => (host, format!(":{port}")),
        _ => (hostport, String::new()),
    };
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || !host_allowed(&host) {
        return raw.to_string();
    }
    let new_host = if host.ends_with(GATEWAY_SUFFIX) {
        host
    } else {
        format!("{host}{GATEWAY_SUFFIX}")
    };
    format!("http://{auth}{new_host}{port}{path}")
}

fn should_rewrite_key(key: &str) -> bool {
    let k = key.to_ascii_uppercase();
    if k.contains("BENCHMARK") {
        return false;
    }
    if k == "ANTHROPIC_API_URL" || k == "OPENAI_API_BASE" || k == "OPENAI_BASE_URL" {
        return true;
    }
    k.contains("BASE_URL") || k.ends_with("_URL") || k.ends_with("_ENDPOINT")
}

pub fn apply_llm_gateway(env: &mut HashMap<String, String>) -> HashMap<String, String> {
    let mut changed = HashMap::new();
    let keys: Vec<String> = env.keys().cloned().collect();
    for key in keys {
        if !should_rewrite_key(&key) {
            continue;
        }
        let old = env.get(&key).cloned().unwrap_or_default();
        if old.trim().is_empty() {
            continue;
        }
        let new = rewrite_llm_url_for_gateway(&old);
        if new != old {
            env.insert(key.clone(), new.clone());
            changed.insert(key, new);
        }
    }
    changed
}

pub fn apply_platform_env_aliases(env: &mut HashMap<String, String>) -> HashMap<String, String> {
    let mut mapped = HashMap::new();
    let fill = |env: &mut HashMap<String, String>, mapped: &mut HashMap<String, String>, dst: &str, srcs: &[&str]| {
        if env.get(dst).map(|s| !s.trim().is_empty()).unwrap_or(false) {
            return;
        }
        for src in srcs {
            let val = env.get(*src).map(|s| s.trim().to_string()).unwrap_or_default();
            if !val.is_empty() {
                env.insert(dst.to_string(), val);
                mapped.insert(dst.to_string(), (*src).to_string());
                return;
            }
        }
    };
    fill(env, &mut mapped, "ATKBRAIN_BENCHMARK_BASE_URL", &["BENCHMARK_BASE_URL"]);
    fill(env, &mut mapped, "ATKBRAIN_BENCHMARK_TOKEN", &["BENCHMARK_TOKEN"]);
    fill(
        env,
        &mut mapped,
        "ATKBRAIN_BENCHMARK_FOCUS_CODES",
        &["BENCHMARK_FOCUS_CODES", "FOCUS_CODES"],
    );
    fill(
        env,
        &mut mapped,
        "ANTHROPIC_AUTH_TOKEN",
        &["DEEPSEEK_API_KEY", "LLM_API_KEY", "OPENAI_API_KEY"],
    );
    fill(
        env,
        &mut mapped,
        "DEEPSEEK_API_KEY",
        &["ANTHROPIC_AUTH_TOKEN", "LLM_API_KEY", "OPENAI_API_KEY"],
    );
    mapped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_allowlisted_host_once() {
        let once = rewrite_llm_url_for_gateway("https://api.deepseek.com/v1");
        assert_eq!(once, "http://api.deepseek.com.tsecbench.gw/v1");
        assert_eq!(rewrite_llm_url_for_gateway(&once), once);
    }

    #[test]
    fn leaves_other_hosts() {
        assert_eq!(
            rewrite_llm_url_for_gateway("https://example.com/v1"),
            "https://example.com/v1"
        );
    }

    #[test]
    fn aliases_benchmark_without_overwriting() {
        let mut env = HashMap::from([
            ("BENCHMARK_BASE_URL".into(), "http://bench".into()),
            ("ATKBRAIN_BENCHMARK_TOKEN".into(), "kept".into()),
            ("BENCHMARK_TOKEN".into(), "other".into()),
        ]);
        apply_platform_env_aliases(&mut env);
        assert_eq!(env.get("ATKBRAIN_BENCHMARK_BASE_URL").map(String::as_str), Some("http://bench"));
        assert_eq!(env.get("ATKBRAIN_BENCHMARK_TOKEN").map(String::as_str), Some("kept"));
    }
}
