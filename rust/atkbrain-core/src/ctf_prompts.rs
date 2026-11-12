//! CTF 题型提示。句子与原先 Python 相同，只服务 objective=flag。

pub const CTF_CATEGORIES: &[&str] = &["web", "pwn", "reverse", "misc", "crypto"];

const WEB: &str = "题型：Web。\n先读附加信息和 workspace/challenge/ 里的源码、配置、注释、备份、robots。有远程入口时，先打开入口和题面点名的路径、参数、账号；响应里像 flag 就立刻 report_flag。\n不要用目录爆破或全端口扫描开局。只打题面已经露出的参数和接口（登录、上传、模板、包含、查询、反序列化）。附件里的源码优先于扫描。没有旗再对题目入口做有限侦察，禁止扫题面没给的主机，禁止超 10 万行的词表。";
const PWN: &str = "题型：PWN。\n附件在 workspace/challenge/。先在本机看文件类型和保护（file、checksec、strings、libc），把漏洞点从二进制里读出来，再决定要不要连远程。\n没有远程地址就只在本地把 flag 从程序或附件里拿出来，不要把二进制当成网站去扫。有题目给的主机和端口时，只连接这个入口（nc / pwntools），禁止扫别的主机、禁止全端口、禁止 rockyou 和 hashcat 全库。拿到 flag 立刻 report_flag。";
const REVERSE: &str = "题型：逆向。\n只分析 workspace/challenge/ 里的程序、脚本和数据。用 strings、ltrace、反汇编把校验、密钥或硬编码 flag 还原出来。\n不要对附件文件名做端口扫描，不要把程序当成 Web 目标。题面没有给出远程地址时，禁止对外连。题面给了调试或验证地址时，只连那一个。还原出的 flag 立刻 report_flag。";
const MISC: &str = "题型：杂项。\n先看附件类型再动手：图片和音频看隐写，pcap/cap 只在包里找 flag 或凭据，压缩包看伪加密和注释，文本先识别编码（base 家族、进制、二维码）。\n流量包里出现的公网地址默认不是攻击目标，除非附加信息写明那是题目入口。不要对杂项附件做目录爆破或口令字典。解出来的 flag 立刻 report_flag。";
const CRYPTO: &str = "题型：密码学。\n先读 workspace/challenge/ 里的脚本和参数（n、e、c、密文、密钥、协议）。按这份脚本实际用的算法做题：小指数、共模、广播、Padding Oracle 只在题面提供了对应预言机时才用。\n不要 hashcat 全库，不要 rockyou。有远程交互时，只按脚本里的协议和题目给的地址说话，不要扫旁站。算出的 flag 立刻 report_flag。";

pub fn normalize_ctf_category(raw: &str) -> &'static str {
    match raw.trim().to_ascii_lowercase().as_str() {
        "web" => "web",
        "pwn" => "pwn",
        "rev" | "reverse" | "re" | "逆向" => "reverse",
        "misc" | "杂项" => "misc",
        "crypto" | "密码" | "密码学" => "crypto",
        _ => "",
    }
}

pub fn ctf_category_prompt(category: &str) -> &'static str {
    match normalize_ctf_category(category) {
        "web" => WEB,
        "pwn" => PWN,
        "reverse" => REVERSE,
        "misc" => MISC,
        "crypto" => CRYPTO,
        _ => "",
    }
}

pub fn ctf_category_label(category: &str) -> &'static str {
    match normalize_ctf_category(category) {
        "web" => "Web",
        "pwn" => "PWN",
        "reverse" => "逆向",
        "misc" => "杂项",
        "crypto" => "密码学",
        _ => "",
    }
}

pub fn brief_for_category(category: &str, attachments: &[String], offline: bool) -> String {
    let prompt = ctf_category_prompt(category);
    if prompt.is_empty() {
        return String::new();
    }
    let mut lines = vec![prompt.to_string()];
    let names: Vec<&str> = attachments.iter().map(|s| s.trim()).filter(|s| !s.is_empty()).take(12).collect();
    if !names.is_empty() {
        lines.push(format!(
            "题目附件在 workspace/challenge/：{}。先在本机读这些文件，不要把文件名当成远程路径去扫。",
            names.join("、")
        ));
    }
    if offline {
        lines.push("本题没有远程入口。只分析附件和附加信息，拿到 flag 后 report_flag。不要扫描。".into());
    }
    lines.join("\n")
}
