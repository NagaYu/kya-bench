# KYA Bench（日本語）

英語版: [README.md](README.md)。参照実装との比較は [docs/conformance-matrix.md](docs/conformance-matrix.md)、ライセンスは Apache-2.0（[LICENSE](LICENSE)）です。

エージェント決済プロトコルの中立コンフォーマンス検証器です。対象と、判定の根拠にした固定版は次のとおりです（詳細は [docs/sources.md](docs/sources.md)）。

| プロトコル | 根拠 | Phase |
|---|---|---|
| Mastercard Verifiable Intent（VI）v0.1-draft | `agent-intent/verifiable-intent@356c296` | 1 |
| Visa Trusted Agent Protocol（TAP） | `visa/trusted-agent-protocol@16d59bd` ＋ Visa 開発者向け仕様ページ（補助） | 2 |
| Google Agent Payments Protocol（AP2）v0.2 | `google-agentic-commerce/AP2@e1ea56d` | 2 |
| TAP＋AP2 の合成、AP2→VI の翻訳等価性 | KYA Bench の規則（[docs/spec-gaps.md](docs/spec-gaps.md) XP 節） | 2 |

- 検証器は例外で落ちず、判定を返します。形式不正も署名不一致も、理由コード付きの判定 JSON になります。
- 完全オフラインで動きます。発行者鍵（JWKS）と TAP のエージェント・レジストリは、ローカルのフィクスチャから読みます。
- 仕様に無い挙動は作りません。未定義のケースは `indeterminate` として返し、[docs/spec-gaps.md](docs/spec-gaps.md) に記録しています。
- 依存は `cryptography` だけです。SD-JWT、JWS、RFC 9421 / RFC 8941 の処理はパッケージ内に実装しているので、全体を監査できます。

## セットアップ

```bash
python3 -m pip install -e '.[test]'
```

```bash
python3 -m pytest
```

インストールせずに動かす場合は `PYTHONPATH=src` を付けてください。テストは `pyproject.toml` の設定で `src` を自動で import パスに加えます。

## 使い方（CLI）

```bash
kya-bench verify fixtures/vectors/autonomous-valid.json --jwks fixtures/jwks.json
```

```bash
kya-bench run-suite fixtures/vectors --jwks fixtures/jwks.json
```

`verify` には、バンドルとベクタのどちらのファイルも渡せます。ベクタを渡すと、ベクタ内の `protocol`、`strictness`、`now` を使います（フラグを指定すればそちらが優先）。

### プロトコルの選択

`verify` は次の順でプロトコルを決めます。

1. `--protocol vi|tap|ap2|composition|translation` の指定
2. ベクタファイルなら、その `protocol` フィールド
3. バンドルの形からの推定:
   - `requests` → TAP
   - `checkout_mandate` / `payment_mandate` → AP2
   - `tap` / `ap2` → 合成
   - `intent` と `probe` → 翻訳
   - それ以外 → VI

出力の `protocol` には `vi` / `tap` / `ap2` / `composition` / `translation` が入ります。理由コードは `TAP_`、`AP2_`、`XPROTO_`、`XLATE_` の接頭辞で名前空間を分けています（VI のコードは Phase 1 のまま接頭辞なし）。

| オプション | 意味 |
|---|---|
| `--strictness strict\|permissive` | 未知の制約型の扱い。**デフォルトは `strict`**（ベクタを渡した場合はベクタの値）。open mandate 内の未知型は、どちらの設定でも reject する |
| `--jwks PATH` | 発行者 JWKS のローカルフィクスチャ（`{iss: {"keys": [JWK...]}}`）。同じディレクトリの `tap_registry.json` も読む |
| `--protocol P` | プロトコルの明示（上記） |
| `--now UNIX` | 検証時刻（出力の `evaluated_at`）。ベクタの時刻は `1790000000`（2026-09-21T14:13:20Z）に固定 |
| `--policy TYPE=MODE` | 型ごとの strictness の上書き（C §5.4）。複数回指定できる |
| `--merchant-pointer PTR` | `checkout_jwt` ペイロード内の加盟店オブジェクトの位置（JSON Pointer。G-02 参照） |
| `--clock-skew SEC` | 時計ずれの許容幅（デフォルト 300 秒） |

`verify` の終了コードは `0` accept、`1` reject、`2` indeterminate（仕様ギャップ）、`3` 入力ファイルが読めない等の使い方エラーです。
`run-suite` の終了コードは、全ベクタが期待どおりなら `0`、1 件でも不一致があれば `1`、使い方エラーは `3` です。

### run-suite の照合モード

| モード | 一致の条件 | 用途 |
|---|---|---|
| 既定（subset 照合） | 判定が `expected_verdict` と等しく、`expected_reason_codes` のすべてが検出コード（理由と警告）に含まれる | 自己スイートの回帰確認。期待値に書いていない警告（例: `AUD_NOT_CHECKED`）が出ても一致とみなす |
| `--strict-codes` | 上記に加え、`expected_reason_codes` に無いコードが 1 つでも出たら不一致 | 他の実装との厳密比較。期待にない警告も差分として報告する |

現在のベクタは既定モードで全件一致します。`--strict-codes` では、警告まで列挙していないベクタ（主に VI の aud / nonce 未照合の警告）が不一致になります。

## ライブラリ API

```python
from kya_bench import LocalJwksResolver, verify

v = verify(bundle_json_or_dict, strictness="strict",  # strictness は必須（デフォルト値なし）
           resolver=LocalJwksResolver.from_file("fixtures/jwks.json"), now=1790000000)
v.verdict, v.identity_ok, v.delegation_chain_ok, v.to_json()
```

`check_constraints(constraints, fulfillment, strictness=..., is_open_mandate=...)` で、制約エンジンだけを単体で使えます。

## 入力：バンドル

いずれも KYA Bench の入力封筒で、各プロトコルのワイヤ形式そのものではありません。

### VI

各層は受け取ったとおりのシリアライズ文字列で渡します。

```jsonc
{
  "l1": "<issuer-jwt>~<disclosure>~",          // L2 署名者が受け取った L1（sd_hash の対象）
  "l2": "<user-jwt>~<disclosure>~...~",
  "l3a": "...", "l3b": "...",                  // Autonomous のみ
  "l2_view_l3a": "...", "l2_view_l3b": "...",  // 各 L3 の sd_hash が束縛する L2 選択ビュー（CF §5.4）
  "expected": {"l2_aud": "...", "l2_nonce": "...", "l3a_aud": "...", "l3a_nonce": "...", "l3b_aud": "...", "l3b_nonce": "..."},
  "network_state": {"cumulative_spent": 0, "occurrence_count": 0}   // budget / agent_recurrence 用（G-05）
}
```

`l2_view_*` を省略すると完全な `l2` で代用し、警告 `L3_VIEW_FALLBACK` を記録します。`expected` を省略すると aud / nonce の照合を行わず、警告を記録します。

### TAP

```jsonc
{"requests": [{
  "method": "POST", "authority": "merchant.example", "path": "/cart/checkout", "query": "",
  "headers": {"signature-input": "sig2=(\"@authority\" \"@path\");created=...;expires=...;keyid=\"primary\";alg=\"rsa-pss-sha256\";nonce=\"...\";tag=\"agent-payer-auth\"",
              "signature": "sig2=:base64:", "content-digest": "sha-256=:...:"},
  "body": "{\"agenticConsumer\": {...}, \"agenticPaymentContainer\": {...}}",   // 生の本文
  "operation": "payment"                                                   // 加盟店が分類した操作: browse | payment
}]}
```

複数のリクエストは同じ nonce キャッシュで順に検証するので、バンドル内のリプレイも検出します。

### AP2（v0.2）

```jsonc
{"checkout_mandate": "<open>~...~~<closed>~...~",   // human-present は closed の 1 トークン
 "payment_mandate":  "<open>~...~~<closed>~...~",
 "expected": {"checkout_aud": "...", "checkout_nonce": "...", "payment_aud": "...", "payment_nonce": "..."},
 "mandate_context": {"total_amount": 0, "total_uses": 0, "last_used_date": 0}}   // budget / recurrence 用
```

### 合成・翻訳

- 合成: `{"tap": <TAP バンドル>, "ap2": <AP2 バンドル>}`（どちらか一方だけでもよい）
- 翻訳: `{"intent": {"payment_constraints": [...], "checkout_constraints": [...], "exp": ...}, "probe": {"payment_amount": {...}, "merchant": {...}}}`

## 出力：正規化判定 JSON

```jsonc
{
  "verdict": "accept | reject | indeterminate",
  "mode": "immediate | autonomous | null",
  "strictness": "strict",
  "evaluated_at": 1790000000,   // 検証時刻（--now）
  "identity_ok": true,          // L1：JWKS 鍵解決、ES256 署名、必須クレーム、vct、有効期限
  "delegation_chain_ok": true,  // L2/L3：cnf による鍵束縛、sd_hash 連鎖、typ、有効期限、モード整合、L3a/L3b 相互参照
  "constraints": [              // 制約 1 件ごと
    {"type": "mandate.payment.amount_range",
     "status": "satisfied | violated | not_checked | skipped_unknown",
     "detail": "Amount exceeded: 50000 > 40000 USD",
     "outcome": "pass | violation | not_evaluated | indeterminate | unknown_rejected | unknown_skipped",
     "mandate": "payment", "index": 0, "registered": true, "messages": ["..."],
     "constraint": {"type": "...", "...": "..."}}   // 元のオブジェクト（未知フィールドも保持）
  ],
  "cross_refs": {"l3a_l3b_match": true, "l3a_l3b_same_pair": true, "l2_sd_hash_l1": true,
                 "l3a_sd_hash_l2_view": true, "l3b_sd_hash_l2_view": true, "l3a_kid_l2_cnf": true,
                 "l3b_kid_l2_cnf": true, "l2_mandate_pairing": true, "l2_checkout_hash": null,
                 "l3b_checkout_hash": true},          // null = 該当なし（L3 が無い等）
  "unknown_constraints": [{"type": "com.acme.x", "mandate": "payment", "index": 0,
                           "handling": "rejected_open_mandate | rejected_strict | skipped_permissive"}],
  "reason_codes": ["SIGNATURE_INVALID"],              // 判定の根拠（reject / indeterminate）。発見順、重複なし
  "reasons":  [{"code": "SIGNATURE_INVALID", "effect": "reject", "layer": "L2", "message": "..."}],
  "warnings": [{"code": "CONSTRAINT_UNKNOWN_SKIPPED", "effect": "warn", "message": "..."}],
  "checks":   [{"id": "L2.sd_hash", "status": "pass | fail | skipped"}],
  "protocol": "vi", "spec_version": "0.1-draft", "spec": {"name": "...", "source": "<repo>@<commit>"},
  "details": { ... }   // TAP / AP2 / 合成のみ: 署名鍵のエージェント、フロー、エージェント鍵など
}
```

TAP / AP2 / 合成でも同じ形で出力します。各フィールドの意味は次のとおりです。

| フィールド | TAP | AP2 | 合成 |
|---|---|---|---|
| `identity_ok` | RFC 9421 署名が検証でき、鍵とエージェントがレジストリで有効 | ルートがトラストリストの鍵で、全ホップの署名が正しい | TAP の `identity_ok` |
| `delegation_chain_ok` | タグと操作が整合し、nonce が新しく、Payment Container が構造的に正しい | `cnf` の連鎖、`sd_hash` / `issuer_jwt_hash`、`typ`、時刻、aud / nonce | AP2 の値（AP2 が無ければ TAP の値） |
| `constraints` | なし | AP2 自身の制約評価 | AP2 の制約 |
| `cross_refs` | CRO / Container と署名の nonce・kid の一致 | `checkout_hash`、`transaction_id`、`payment.reference`、カート合計 | `presenter_matches_mandate_agent` |

判定は次の順で決まります。`reject` 効果の理由が 1 つでもあれば reject、それが無く `SPEC_GAP` があれば indeterminate、どちらも無ければ accept です。
`accept_with_warnings` という判定は作らず、警告はすべて `warnings[]` に入れます。

制約の `status` について:

- 未知の型を reject した場合（open mandate、または STRICT）は `violated` です。
- 仕様ギャップで判定できなかった場合は `not_checked` です。
- どちらも、細かい区別は `outcome` に残します。

理由コードの一覧は [src/kya_bench/reasons.py](src/kya_bench/reasons.py) にあります。

## 検証内容

| 層 | 主な検査 |
|---|---|
| L1 | `alg=ES256`、`typ=sd+jwt`、`kid` 必須 → `iss`+`kid` で JWKS から鍵を解決 → 署名。必須クレーム、`_sd_alg=sha-256`、`vct` は常時可視の URI、Mastercard プロファイルのクレーム、`sd_hash` を持たないこと、`exp` |
| L2 | L1 の `cnf.jwk` で署名されていること。`sd_hash` = 受け取ったままの L1 のハッシュ。VCT からモードを推定し、`typ` と整合すること。`iat` / `exp`、Autonomous の `exp` が L1 の `exp` 以下であること。マンデートのペアリング（孤立・重複の検出）。Immediate：`cnf` と `constraints` を持たないこと、`checkout_hash` の再計算。Autonomous：`cnf.jwk` と `kid`、ペア内で `cnf` が一致すること、制約が 1 件以上あること、`mandate.payment.reference` |
| L3 | ヘッダの `kid` が L2 の `cnf.jwk.kid` と一致し、その鍵で署名されていること。ヘッダに `jwk` を持たないこと。`typ=kb-sd-jwt`。選択的 `sd_hash`（ビューは L2 と同じ基底 JWT 上に組まれ、L2 がコミットしたディスクロージャだけを含むこと）。`cnf` を持たないこと。nonce が L2 と異なること。寿命 1 時間以内。`L3a.transaction_id == L3b.checkout_hash`。Immediate に L3 が付いていたら reject |
| 制約 | 登録済み 8 種すべてを C §4 の手順どおりに評価する。未知の型は、open mandate では常に reject。open でなければ STRICT で reject、PERMISSIVE でスキップし、スキップ時は必ず警告を記録する |

TAP / AP2 / 合成 / 翻訳の検査内容は、各モジュールの冒頭（[tap/verifier.py](src/kya_bench/tap/verifier.py)、[ap2/verifier.py](src/kya_bench/ap2/verifier.py)、[ap2/constraints.py](src/kya_bench/ap2/constraints.py)、[xproto/composition.py](src/kya_bench/xproto/composition.py)、[xproto/translate.py](src/kya_bench/xproto/translate.py)）に、根拠となる repo の箇所とあわせて記載しています。

## コンフォーマンスベクタ

`fixtures/vectors/<id>.json` に 1 ファイル 1 ベクタで置いています。形式は `kya-bench-vector/2` で、そのまま Hugging Face データセットとして公開できる形にしてあります。

```jsonc
{"id": "...", "protocol": "vi | tap | ap2 | composition | translation",
 "kind": "bundle | constraint_check | composition | translation",
 "category": "...", "description": "...", "spec_ref": "CF §5.7 rule 2",
 "strictness": "strict", "now": 1790000000,
 "<payload>": { ... },          // kind ごとのフィールド名（下表）
 "expected_verdict": "reject", "expected_reason_codes": ["SIGNATURE_INVALID"]}
```

| kind | ペイロードのフィールド | 評価方法 |
|---|---|---|
| `bundle` | `bundle` | プロトコルの検証器（VI / TAP / AP2） |
| `constraint_check` | `constraint_check` | VI の制約エンジンを直接呼ぶ |
| `composition` | `presentation` | TAP＋AP2 の束縛 |
| `translation` | `translation` | AP2→VI 翻訳の等価性 |

- 期待が `indeterminate`（仕様ギャップ）のベクタは、`indeterminate` が返れば一致です。
- `fixtures/vectors/manifest.json` に、形式の版、件数、プロトコル別・カテゴリ別の内訳、シードを記録しています。
- 件数は VI 58、TAP 29、AP2 32、合成 10、翻訳 12 の計 141 件です。

### 再生成（決定論的）

```bash
python3 tools/generate_fixtures.py
```

- 同じコマンドで、バイト単位で同一のファイルが生成されます。鍵は固定シード（`kya-bench/vi/phase1`）とラベルから導出し、タイムスタンプは固定、ES256 署名は RFC 6979 の決定論的署名です（AP2 の `checkout_jwt` に関する注記は spec-gaps の AP2 節を参照）。
- 期待判定と主な理由コードは、[src/kya_bench/testing/vectors.py](src/kya_bench/testing/vectors.py)（VI）と [src/kya_bench/testing/phase2_vectors.py](src/kya_bench/testing/phase2_vectors.py)（Phase 2）に手で宣言しています。生成器は検証器の出力をそのまま保存するのではなく、宣言と一致しなければ生成自体を失敗させます。
- `fixtures/jwks.json` は、各 JWKS エンドポイントの代わりになるローカルファイルです（VI の発行者、AP2 のエージェント提供者のトラストリスト、TAP の ID トークン用モック発行者）。
- `fixtures/tap_registry.json` は、Visa 運営ディレクトリの代わりのエージェント・レジストリです（参照実装の agent-registry と同じ形）。
- Ed25519 は固定シードから導出し、RSA はシードした素数生成で作ります。RSA-PSS のソルトもシードとメッセージから導出するため、署名まで含めて再現できます。
- **鍵はすべてテスト専用です**。実在の鍵は使っていません。

## CI

[.github/workflows/ci.yml](.github/workflows/ci.yml) は、Python 3.11 と 3.13 のマトリクスで [tools/ci.sh](tools/ci.sh) を実行します。ローカルでも同じ手順を実行できます。

```bash
bash tools/ci.sh
```

手順は次の 3 つです。

1. pytest
2. ベクタを再生成し、`git diff --exit-code -- fixtures/` で差分が無いことを確認
3. `run-suite` の自己実行

ネットワークを使うのは依存パッケージのインストールだけで、その後の手順はすべてオフラインで動きます。

## 仕様ギャップ

[docs/spec-gaps.md](docs/spec-gaps.md) を参照してください。未定義の各ケースには、[tests/test_spec_gaps.py](tests/test_spec_gaps.py) に `xfail(strict=True)` のテストがあります。
