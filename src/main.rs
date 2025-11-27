mod crypto;

use std::{
    env,
    net::SocketAddr,
    sync::{Arc, Mutex},
    fs::OpenOptions,
    io::Write as IoWrite,
};

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use crypto::{
    compute_shared_secret, derive_aes256_key, encode_b64, generate_dh_keypair,
    handshake_message_from_parts, parse_handshake_message, sign_ephemeral,
    verify_ephemeral_signature, DhKeyPair, HandshakeMessage,
    generate_and_save_signing_key_pair_with_prefix, LongTermSigning,
    PeerSigning, decrypt_chat_message, encrypt_chat_message,
    load_longterm_signing, load_peer_signing, save_peer_signing_from_b64,
};
use serde::Deserialize;

#[derive(Clone)]
struct AppState {
    role: String,
    id_prefix: String,
    dh_keys: Arc<Mutex<Option<DhKeyPair>>>,
    last_offer: Arc<Mutex<Option<HandshakeMessage>>>,
    longterm_signing: LongTermSigning,
    peer_signing: Arc<Mutex<Option<PeerSigning>>>,
    aes_key: Arc<Mutex<Option<[u8; 32]>>>,
}

#[tokio::main]
async fn main() {
    let mut args = env::args();
    let _program = args.next();
    let port: u16 = match args.next() {
        None => 3000,
        Some(s) => match s.parse() {
            Ok(p) if p > 0 => p,
            _ => {
                eprintln!("無效的埠號 `{s}`，請使用 1-65535 之間的整數，例如：");
                eprintln!("  cargo run              # 預設 3000 埠");
                eprintln!("  cargo run 3001         # 在 3001 埠啟動");
                std::process::exit(1);
            }
        },
    };

    let role = "party".to_string();
    let id_prefix = format!("party_{}", port);

    let longterm_signing = match load_longterm_signing(&id_prefix) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("載入 {id_prefix} 的 Ed25519 簽名金鑰失敗（可能尚未建立金鑰檔）：{e}");
            eprintln!("將自動為本端產生新的簽名金鑰檔案...");
            if let Err(gen_err) = generate_and_save_signing_key_pair_with_prefix(&id_prefix) {
                eprintln!("自動產生簽名金鑰失敗: {gen_err}");
                std::process::exit(1);
            }
            load_longterm_signing(&id_prefix).expect("自動產生後載入簽名金鑰失敗")
        }
    };

    let peer_signing = match load_peer_signing(&id_prefix) {
        Ok(p) => {
            println!("已載入對方的簽名公鑰（Base64）自 {id_prefix}_peer_ed25519_public.b64");
            Some(p)
        }
        Err(e) => {
            println!(
                "尚未設定對方的簽名公鑰或讀取失敗：{e}\n\
請在網頁上貼上對方的簽名公鑰（Base64），我們會將其儲存到 {id_prefix}_peer_ed25519_public.b64。"
            );
            None
        }
    };

    let state = AppState {
        role: role.clone(),
        id_prefix: id_prefix.clone(),
        dh_keys: Arc::new(Mutex::new(None)),
        last_offer: Arc::new(Mutex::new(None)),
        longterm_signing,
        peer_signing: Arc::new(Mutex::new(peer_signing)),
        aes_key: Arc::new(Mutex::new(None)),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/generate", post(generate_offer))
        .route("/download-offer.json", get(download_offer))
        .route("/process", post(process_response))
        .route("/peer-key", post(update_peer_key))
        .route("/encrypt-chat", post(encrypt_chat))
        .route("/decrypt-chat", post(decrypt_chat))
        .with_state(state);

    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    println!(
        "Running server on http://{addr}  (使用方式：cargo run [PORT]，預設 3000 埠)"
    );

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn index(State(state): State<AppState>) -> Html<String> {
    let title = "Diffie-Hellman Handshake & Secure Chat";

    let role_label = "本端";
    let peer_label = "對方";

    let pk_b64 = &state.longterm_signing.pk_b64;
    let sk_preview = mask_secret_preview(&state.longterm_signing.sk_b64);
    let peer_pk_b64_opt: Option<String> = {
        let guard = state.peer_signing.lock().unwrap();
        guard.as_ref().map(|p| p.pk_b64.clone())
    };
    let peer_pk_display = peer_pk_b64_opt
        .as_deref()
        .unwrap_or("（尚未設定對方簽名公鑰）");
    let peer_pk_b64_opt_text = peer_pk_b64_opt.clone().unwrap_or_default();

    let body = format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{title}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 720px; margin: 2rem auto; }}
    textarea {{ width: 100%; height: 200px; }}
    pre {{ background: #f5f5f5; padding: 1rem; overflow-x: auto; }}
    button {{ padding: 0.5rem 1rem; margin-top: 0.5rem; }}
  </style>
</head>
<body>
  <h1>{title}</h1>

  <p><strong>你現在這一端是：{role_label}</strong></p>
  <section>
    <h2>Step 0: 本端長期簽名金鑰 (Ed25519)</h2>
    <p>
      啟動時，程式會嘗試從本地檔案載入本端（{role_label}）的簽名金鑰；
      如果檔案不存在，會自動在本機產生新的簽名金鑰並存檔，然後載入。
    </p>
    <p><strong>簽名公鑰 (Base64, 完整顯示)：</strong></p>
    <pre>{pk_b64}</pre>
    <p><strong>簽名私鑰 (Base64, 只顯示頭尾，中間以星號遮蔽)：</strong></p>
    <pre>{sk_preview}</pre>
  </section>
  <section>
    <h2>Step 0.5: 對方 ({peer_label}) 的簽名公鑰 (Ed25519)</h2>
    <p>
      為了防止中間人攻擊，建議你先在安全通道（例如當面或透過已驗證的管道）
      取得對方 ({peer_label}) 的簽名公鑰 Base64，貼在下方並儲存。之後每次握手時，
      我們會優先使用這個預先設定的公鑰驗證 JSON 裡的簽名，同時檢查 JSON 內附的公鑰是否一致。
    </p>
    <p><strong>目前儲存的對方簽名公鑰 (Base64)：</strong></p>
    <pre>{peer_pk_display}</pre>
    <form id="peer-key-form">
      <label for="peer-key-input"><strong>貼上 / 更新 對方 ({peer_label}) 的簽名公鑰 (Base64)：</strong></label><br>
      <textarea id="peer-key-input" name="peer_key_b64" placeholder="在這裡貼上對方的簽名公鑰 Base64">{peer_pk_b64_opt_text}</textarea><br>
      <button type="submit">儲存對方簽名公鑰</button>
    </form>
    <pre id="peer-key-result"></pre>
  </section>
  <p>
    建議：在本機測試時，可以開兩個 terminal 視窗，分別執行
  </p>
  <pre>
cargo run          # 會在 127.0.0.1:3000 上開啟本端
cargo run 3001     # 會在 127.0.0.1:3001 上開啟另一個實例
  </pre>
  <p>
    然後在瀏覽器分別開啟 <code>http://127.0.0.1:3000/</code> 和
    <code>http://127.0.0.1:3001/</code>，兩邊都可以貼上對方的 JSON 計算共享密鑰。
  </p>

  <section>
    <h2>Step 1: 在本端產生自己的 JSON (本端的 Ephemeral Key + 簽名)</h2>
    <p>
      按下按鈕會在<strong>本端</strong>產生一次性的 Diffie-Hellman 公鑰，
      並用本端的簽名私鑰對它簽名，結果會是 JSON。
      這個 JSON 要傳給對方（另一個瀏覽器分頁中的 {peer_label}）。
    </p>
    <form id="generate-form" method="post" action="/generate">
      <button type="submit">產生 JSON</button>
    </form>
    <p>產生後可以用 <code>/download-offer.json</code> 下載成檔案，再傳給對方。</p>
    <pre id="offer-json"></pre>
  </section>

  <section>
    <h2>Step 2: 在本端貼上<strong>對方 ({peer_label})</strong>傳來的 JSON，計算共享密鑰</h2>
    <form id="process-form" method="post" action="/process">
      <textarea name="json" placeholder="在這裡貼上對方給你的 JSON"></textarea>
      <br>
      <button type="submit">送出並驗證 + 計算共享密鑰</button>
    </form>
    <h3>結果</h3>
    <pre id="result"></pre>
  </section>

  <section>
    <h2>Step 3: 使用協商出的 AES-256 key 進行加密聊天</h2>
    <p>
      當 Step 2 完成後，雙方會各自從共享的大整數密鑰推導出相同的 AES-256 key。
      你可以在下方輸入聊天內容，加密成 Base64 文本（可貼到 WhatsApp 等聊天軟體），
      也可以把對方貼過來的 Base64 密文貼到解密輸入框，自動解密並累積到本地聊天紀錄。
      明文聊天紀錄會同步追加寫入本地檔案（例如 party_3000_chat_history.txt）。
    </p>
    <h3>加密自己要發送的訊息</h3>
    <textarea id="chat-plain-input" placeholder="輸入要發送給對方的明文訊息"></textarea><br>
    <button id="chat-encrypt-button">加密並產生 Base64 密文</button>
    <p><strong>加密後的 Base64 密文（可複製貼到聊天軟體）：</strong></p>
    <pre id="chat-cipher-output"></pre>
    <button id="chat-cipher-copy-button">複製以上 Base64 密文</button>

    <h3>解密對方貼過來的 Base64 密文</h3>
    <textarea id="chat-cipher-input" placeholder="在這裡貼上從聊天軟體收到的 Base64 密文"></textarea>
    <p><strong>解密得到的明文訊息：</strong></p>
    <pre id="chat-decrypt-output"></pre>

    <h3>本地聊天紀錄（本端視角）</h3>
    <div id="chat-history"></div>
  </section>

  <script>
    function appendChatLine(prefix, text) {{
      const history = document.getElementById('chat-history');
      const block = document.createElement('div');
      block.textContent = prefix + text;
      history.appendChild(block);
    }}

    document.getElementById('generate-form').addEventListener('submit', async (e) => {{
      e.preventDefault();
      const res = await fetch('/generate', {{ method: 'POST' }});
      if (!res.ok) {{
        document.getElementById('offer-json').textContent = 'Error: ' + res.status;
        return;
      }}
      const json = await res.json();
      document.getElementById('offer-json').textContent = JSON.stringify(json, null, 2);
    }});

    document.getElementById('process-form').addEventListener('submit', async (e) => {{
      e.preventDefault();
      const data = new FormData(e.target);
      const jsonText = data.get('json');
      const res = await fetch('/process', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ json: jsonText }})
      }});
      const text = await res.text();
      document.getElementById('result').textContent = text;
    }});

    document.getElementById('peer-key-form').addEventListener('submit', async (e) => {{
      e.preventDefault();
      const textarea = document.getElementById('peer-key-input');
      const key_b64 = textarea.value || '';
      const res = await fetch('/peer-key', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ key_b64 }})
      }});
      const text = await res.text();
      document.getElementById('peer-key-result').textContent = text;
    }});

    document.getElementById('chat-encrypt-button').addEventListener('click', async () => {{
      const plain = document.getElementById('chat-plain-input').value || '';
      if (!plain) {{
        return;
      }}
      const res = await fetch('/encrypt-chat', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ plaintext: plain }})
      }});
      const text = await res.text();
      document.getElementById('chat-cipher-output').textContent = text;
      const lines = plain.split(/\\r?\\n/);
      for (const line of lines) {{
        if (line.trim()) {{
          appendChatLine('Me: ', line);
        }}
      }}
    }});

    document.getElementById('chat-cipher-copy-button').addEventListener('click', async () => {{
      const text = document.getElementById('chat-cipher-output').textContent || '';
      if (!text) {{
        return;
      }}
      if (navigator.clipboard && navigator.clipboard.writeText) {{
        try {{
          await navigator.clipboard.writeText(text);
        }} catch (e) {{
          console.warn('Clipboard write failed', e);
        }}
      }}
    }});

    const chatCipherInput = document.getElementById('chat-cipher-input');
    const chatDecryptOutput = document.getElementById('chat-decrypt-output');

    chatCipherInput.addEventListener('input', async (e) => {{
      const cipher = (e.target.value || '').trim();
      if (!cipher.trim()) {{
        chatDecryptOutput.textContent = '';
        return;
      }}
      const res = await fetch('/decrypt-chat', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ ciphertext_b64: cipher }})
      }});
      const text = await res.text();
      chatDecryptOutput.textContent = text;
      if (!text.startsWith('錯誤') && !text.startsWith('尚未') && !text.startsWith('解密失敗')) {{
        const lines = text.split(/\\r?\\n/);
        for (const line of lines) {{
          if (line.trim()) {{
            appendChatLine('Peer: ', line);
          }}
        }}
        // 解密成功後清空輸入框，方便貼上下一個密文
        chatCipherInput.value = '';
      }}
    }});
  </script>
</body>
</html>
"#
    );

    Html(body)
}

async fn generate_offer(State(state): State<AppState>) -> Json<HandshakeMessage> {
    let dh = generate_dh_keypair();

    let eph_dec = dh.public.to_str_radix(10);
    let signature = sign_ephemeral(&state.longterm_signing.signing, &eph_dec);
    let msg = handshake_message_from_parts(
        &state.role,
        &eph_dec,
        &signature,
        &state.longterm_signing.verifying,
    );

    let mut dh_guard = state.dh_keys.lock().unwrap();
    *dh_guard = Some(dh);

    let mut last_offer_guard = state.last_offer.lock().unwrap();
    *last_offer_guard = Some(msg.clone());

    Json(msg)
}

async fn download_offer(State(state): State<AppState>) -> impl IntoResponse {
    let offer = {
        let guard = state.last_offer.lock().unwrap();
        guard.clone()
    };

    let Some(offer) = offer else {
        return (StatusCode::BAD_REQUEST, "尚未產生 JSON，請先在上方按下產生按鈕").into_response();
    };

    let body = serde_json::to_vec_pretty(&offer).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "application/json; charset=utf-8".parse().unwrap(),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{}-offer.json\"", state.role)
            .parse()
            .unwrap(),
    );

    (headers, body).into_response()
}

#[derive(Deserialize)]
struct ProcessRequest {
    json: String,
}

#[derive(Deserialize)]
struct UpdatePeerKeyRequest {
    key_b64: String,
}

#[derive(Deserialize)]
struct EncryptChatRequest {
    plaintext: String,
}

#[derive(Deserialize)]
struct DecryptChatRequest {
    ciphertext_b64: String,
}

async fn process_response(
    State(state): State<AppState>,
    Json(payload): Json<ProcessRequest>,
) -> impl IntoResponse {
    let their_msg: HandshakeMessage = match serde_json::from_str(&payload.json) {
        Ok(m) => m,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("解析 JSON 失敗: {e}"),
            )
                .into_response()
        }
    };

    let (their_eph_pub, their_sig, their_verify) = match parse_handshake_message(&their_msg) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("解析對方 JSON 內容失敗: {e}"),
            )
                .into_response()
        }
    };

    // 先嘗試使用預先設定的對方簽名公鑰驗證（若有），並同時檢查 JSON 內附的公鑰是否一致；
    // 若尚未預先設定，則退回使用 JSON 內附的簽名公鑰驗證。
    {
        let peer_opt = state.peer_signing.lock().unwrap().clone();
        if let Some(peer) = peer_opt {
            // 如果 JSON 內附的簽名公鑰與預先設定的不一致，視為潛在中間人攻擊。
            if peer.pk_b64 != their_msg.signing_public_b64 {
                return (
                    StatusCode::BAD_REQUEST,
                    "JSON 內附的簽名公鑰與本地預先設定的對方公鑰不一致，可能存在中間人攻擊。".to_string(),
                )
                    .into_response();
            }

            if let Err(e) =
                verify_ephemeral_signature(&peer.verifying, &their_msg.ephemeral_public_dec, &their_sig)
            {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("使用預先設定的對方簽名公鑰驗證失敗: {e}"),
                )
                    .into_response();
            }
        } else if let Err(e) =
            verify_ephemeral_signature(&their_verify, &their_msg.ephemeral_public_dec, &their_sig)
        {
            return (
                StatusCode::BAD_REQUEST,
                format!("尚未設定對方簽名公鑰，且使用 JSON 內附公鑰驗證失敗: {e}"),
            )
                .into_response();
        }
    }

    let my_dh = {
        let mut guard = state.dh_keys.lock().unwrap();
        guard.take()
    };

    let Some(my_dh) = my_dh else {
        return (
            StatusCode::BAD_REQUEST,
            "你這一端還沒有先產生自己的 JSON，請先按上面的按鈕產生一次。",
        )
            .into_response();
    };

    let shared = compute_shared_secret(&my_dh.secret, &their_eph_pub);
    let shared_hex = shared.to_str_radix(16);
    let aes_key = derive_aes256_key(&shared);
    let aes_hex = aes_key.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    let aes_b64 = encode_b64(&aes_key);
    let aes_b64_wrapped = wrap_base64(&aes_b64);

    {
        let mut guard = state.aes_key.lock().unwrap();
        *guard = Some(aes_key);
    }

    let response = format!(
        "對方身份簽名驗證成功。\n\
共享大整數密鑰 (hex): {shared_hex}\n\
\n\
從共享密鑰經 HKDF-SHA256 推導出的 AES‑256 key：\n\
  - AES key (hex):  {aes_hex}\n\
  - AES key (Base64):\n{aes_b64_wrapped}\n\
\n\
提醒：雙方各自計算的共享密鑰（以及導出的 AES key）應該一致。你可以在兩端各自貼上對方 JSON，比對這裡顯示的值是否一樣。"
    );

    (StatusCode::OK, response).into_response()
}

fn mask_secret_preview(full_b64: &str) -> String {
    let len = full_b64.len();
    if len <= 16 {
        return full_b64.to_string();
    }
    let head = &full_b64[..8];
    let tail = &full_b64[len - 8..];
    format!("{head}**********{tail}")
}

fn wrap_base64(s: &str) -> String {
    let mut out = String::new();
    let mut line_len = 0usize;
    for ch in s.chars() {
        out.push(ch);
        line_len += 1;
        if line_len == 64 {
            out.push('\n');
            line_len = 0;
        }
    }
    if out.ends_with('\n') {
        // 保持最後沒有多餘換行
        out.pop();
    }
    out
}

async fn update_peer_key(
    State(state): State<AppState>,
    Json(payload): Json<UpdatePeerKeyRequest>,
) -> impl IntoResponse {
    let prefix = state.id_prefix.clone();

    let peer = match save_peer_signing_from_b64(&prefix, &payload.key_b64) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("儲存對方簽名公鑰失敗：{e}"),
            )
                .into_response()
        }
    };

    {
        let mut guard = state.peer_signing.lock().unwrap();
        *guard = Some(peer);
    }

    (
        StatusCode::OK,
        "已更新並儲存對方簽名公鑰（Base64）。之後握手會優先使用此公鑰驗證。".to_string(),
    )
        .into_response()
}

async fn encrypt_chat(
    State(state): State<AppState>,
    Json(payload): Json<EncryptChatRequest>,
) -> impl IntoResponse {
    let aes_key = {
        let guard = state.aes_key.lock().unwrap();
        guard.clone()
    };

    let Some(aes_key) = aes_key else {
        return (
            StatusCode::BAD_REQUEST,
            "尚未建立共享密鑰，請先完成 Step 2 的握手。".to_string(),
        )
            .into_response();
    };

    let cipher_b64 = match encrypt_chat_message(&aes_key, &payload.plaintext) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("加密失敗: {e}"),
            )
                .into_response()
        }
    };

    // 將本端發出的明文訊息追加寫入聊天紀錄檔
    let path = format!("{}_chat_history.txt", state.id_prefix);
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "Me: {}", payload.plaintext);
    }

    let wrapped = wrap_base64(&cipher_b64);

    (StatusCode::OK, wrapped).into_response()
}

async fn decrypt_chat(
    State(state): State<AppState>,
    Json(payload): Json<DecryptChatRequest>,
) -> impl IntoResponse {
    let aes_key = {
        let guard = state.aes_key.lock().unwrap();
        guard.clone()
    };

    let Some(aes_key) = aes_key else {
        return (
            StatusCode::BAD_REQUEST,
            "尚未建立共享密鑰，請先完成 Step 2 的握手。".to_string(),
        )
            .into_response();
    };

    let plaintext = match decrypt_chat_message(&aes_key, &payload.ciphertext_b64) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("解密失敗: {e}"),
            )
                .into_response()
        }
    };

    // 將對方發來的明文訊息追加寫入聊天紀錄檔
    let path = format!("{}_chat_history.txt", state.id_prefix);
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "Peer: {}", plaintext);
    }

    (StatusCode::OK, plaintext).into_response()
}
