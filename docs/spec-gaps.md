# VI 仕様ギャップ記録（Phase 1）

対象仕様: Verifiable Intent v0.1-draft（`spec/credential-format.md`、`spec/constraints.md`）
参照コミット: `agent-intent/verifiable-intent@356c29635f1c44df7de02edb58699ca9f29bece6`（2026-04-20）
以下、CF = credential-format.md、C = constraints.md。

KYA Bench は仕様に書かれていない判定を作りません。未定義のケースに当たったら、判定は
`indeterminate` とし、理由コード `SPEC_GAP` と `gap_id` を付けて返します（CLI の終了コードは 2）。

各ギャップのテストは [tests/test_spec_gaps.py](../tests/test_spec_gaps.py) にあります。

- `test_gap_is_indeterminate[G-xx]`: 現在の挙動（indeterminate になること）を固定するテスト。
- `test_gap_has_definite_verdict[G-xx]`: 確定判定（accept / reject）を期待するテスト。`xfail(strict=True)` 付き。
  仕様が確定して実装が追随すると XPASS になり、テスト全体が失敗します。そのときに期待値を確定させてください。

区分は 3 つです。

- **未定義**: 結果が仕様に書かれていない。→ `indeterminate` を返し、xfail テストを置く。
- **矛盾**: 文書同士、または VI と RFC 9901 が食い違う。→ VI 自身の規範例に従い、通常テストで固定する。
- **観察**: 判定は変えないが、ベンチ利用者が知っておくべき性質。

| ID | 区分 | 概要 |
|---|---|---|
| G-01 | 矛盾（裁定済み） | 同一ダイジェストの多重参照（VI の規範例 vs RFC 9901 §4.1・§7.1） |
| G-02 | 未定義 | `checkout_jwt` 内の加盟店 ID の位置と、ID が無い場合の結果 |
| G-03 | 未定義 | L3b `line_items` のスキーマが文書間で食い違う |
| G-04 | 未定義 | 未開示の `acceptable_items` がある場合の品目判定 |
| G-05 | 未定義 | ネットワーク状態を持たない検証器による累積制約の判定 |
| G-06 | 観察（裁定済み） | strictness は適合クレデンシャルの end-to-end 判定に影響しない |
| G-07 | 未定義 | L3 がどのマンデートペアに束縛されるか（複数ペア＋ビュー無し） |
| G-08 | 未定義 | `agent_recurrence` の「現在日付」のタイムゾーン |
| G-09 | 矛盾 | Immediate L2 の寿命：SHOULD（§4.3）と表の「最大」（§7） |
| G-10 | 観察 | allowlist 判定で「この検証器に開示された」範囲をどう取るか |
| G-11 | 未定義 | 登録済み制約が反対側のマンデートに置かれた場合 |
| G-12 | 未定義 | L3a と L2 で `payment_instrument` が異なる場合 |
| G-13 | 未定義 | ワイルドカード行を含む品目ごとの数量上限 |
| G-14 | 未定義 | Immediate L2 でマンデートが 1 件も開示されない場合 |

---

## G-01 同一ダイジェストの多重参照（矛盾）— 裁定済み

**裁定**: VI の規範例と参照実装に従う（2026-10-31 追認）。将来 Issue に投稿する第 1 候補。

**VI 側**（`agent-intent/verifiable-intent@356c296`、Apache-2.0）

1. CF §11.1 の L2 例。同じハッシュが `_sd` と `delegate_payload` の両方に現れる。
   ```json
     "_sd": [
       "<hash-of-checkout-mandate-disclosure>",
       "<hash-of-payment-mandate-disclosure>"
     ],
     "delegate_payload": [
       { "...": "<hash-of-checkout-mandate-disclosure>" },
       { "...": "<hash-of-payment-mandate-disclosure>" }
     ]
   ```
   CF §11.2 の L2・L3a・L3b の例も同じ構造。

2. C §8.1b。同じダイジェスト文字列が `allowed_merchants` と `allowed_payees` の両方から参照される。
   ```json
       "type": "mandate.checkout.allowed_merchants",
       "allowed": [
         { "...": "S2HSMBL-Lye5cYxpCbyGU-TxrDcL-gvvfgOdxfdH3FM" },
         { "...": "NgKlY7bnMEtgVZHQSAcVR5MPGPwtBuFapII8UkYwAjg" }
   ```
   ```json
       "type": "mandate.payment.allowed_payees",
       "allowed": [
         { "...": "S2HSMBL-Lye5cYxpCbyGU-TxrDcL-gvvfgOdxfdH3FM" },
         { "...": "NgKlY7bnMEtgVZHQSAcVR5MPGPwtBuFapII8UkYwAjg" }
   ```

3. 参照実装 `src/verifiable_intent/issuance/user.py`。
   - L168: 受取人の allowlist を、加盟店のディスクロージャハッシュで組み立てている（共有）。
     ```python
     c["allowed"] = _match_merchant_refs(original_allowed, mandate.merchants, merchant_disc_hashes)
     ```
   - L191 / L202: 配列要素のディスクロージャ（`[salt, value]`）も含め、すべてのハッシュを `_sd` に入れている。
     ```python
     sd_hashes = [hash_disclosure(d) for d in disclosures]
     payload["_sd"] = sd_hashes
     ```

**RFC 9901 側**（SD-JWT、2025-11）

- §4.1: "The same digest value MUST NOT appear more than once in the SD-JWT."
- §7.1 手順 4: "If any digest value is encountered more than once in the Issuer-signed JWT payload (directly or recursively via other Disclosures), the SD-JWT MUST be rejected."
- §7.1 手順 3.c.ii.1（`_sd` で見つかったダイジェストについて）: "If the contents of the respective Disclosure is not a JSON array of three elements (salt, claim name, claim value), the SD-JWT MUST be rejected."
  - VI は 2 要素（配列要素）のディスクロージャのハッシュを `_sd` に入れるので、この規定にも反する。

**KYA Bench の挙動**

- 多重参照を許容する。
- `_sd` に列挙された 2 要素ディスクロージャは「VI 流の列挙」として受け入れる。プロパティとして展開はしない。
- `_sd` にも `{"...": d}` にも現れないディスクロージャは、RFC 9901 §7.1 手順 5 どおり `DISCLOSURE_UNREFERENCED` で reject する。
- 同一ディスクロージャの二重提示は `DISCLOSURE_DUPLICATE` で reject する。

RFC 9901 を厳格に適用すると、VI の規範例そのものも、参照実装が発行する全クレデンシャルも reject になる。そのため VI 側に合わせている。

**テスト**: `test_g01_digest_listed_in_sd_and_delegate_payload_is_accepted`、ベクタ `autonomous-valid`

## G-02 `checkout_jwt` 内の加盟店識別子（未定義）

- **箇所**: CF §6.3、C §4.1 手順 4、C §2.4。
- **未定義の点**:
  1. `checkout_jwt` の内容スキーマは v0.1 では「実装定義」。加盟店 `id` がペイロードのどこにあるか（ルートの `id` か、`merchant.id` 等か）が決まっていない。
  2. ID が無い場合、仕様は「この制約は検証できない」と書くだけで、その結果（pass / violation / skip）を定めていない。
- **KYA Bench の挙動**:
  1. 位置は CF §6.3 の文言どおりに読み、ペイロードのルートにある `id`（あれば `name` / `website` も）を加盟店オブジェクトとする。`--merchant-pointer`（JSON Pointer）で上書きできる。
  2. 見つからない場合、`allowed_merchants` は `indeterminate` とし、`SPEC_GAP G-02` を付ける。
  - `checkout_jwt` の署名は加盟店 JWKS が無いため検証しない（CF §6.3 は SHOULD）。毎回 `CHECKOUT_JWT_SIGNATURE_NOT_VERIFIED` の警告を記録する。
- **テスト**: `[G-02]`、`test_e2e_merchant_pointer`

## G-03 L3b `line_items` のスキーマ（未定義）

- **箇所**: CF §5.5・§11.2 の例は `{sku, name, quantity, unit_price, currency}`。C §4.2 手順 5 と §8.2 の例は `{id, item: {id, title}, quantity}` で、照合キーは `item.id`。
- **未定義の点**: L3b の行アイテムの正規スキーマと、照合に使う商品 ID のフィールド。
- **KYA Bench の挙動**: 照合手順を規範的に書いている C §4.2 に従い、`item.id` と整数の `quantity` を読む。読めない行があれば、`line_items` 制約全体を `indeterminate`（G-03）とする。`sku` を代わりに使うことはしない。
- **テスト**: `[G-03]`

## G-04 未開示の `acceptable_items` がある場合（未定義）

- **箇所**: C §4.2。加盟店と受取人については「未開示の参照は失敗原因にならない」と明記されている（§4.1・§4.3 の注記）が、品目には同様の規定が無い。
- **未定義の点**: L3b の品目が開示済みの `acceptable_items` に無く、かつ未開示の参照が残っている場合に、違反とすべきか。`exact` モードの充足判定も同様。
- **KYA Bench の挙動**: `indeterminate`（G-04）。未開示の参照が無ければ、通常どおり violation とする。
- **テスト**: `[G-04]`

## G-05 累積制約とネットワーク状態（未定義）

- **箇所**: C §4.5（budget）、§4.7（`agent_recurrence` の `max_occurrences`）。CF §5.7 規則 9。
- **未定義の点**: 累積消費額と発生回数は決済ネットワークが追跡する状態（MUST）。その状態を持たない検証器がどう判定すべきかが書かれていない。
- **KYA Bench の挙動**:
  - バンドルの `network_state`（`cumulative_spent`、`occurrence_count`）があれば、それを使って完全に判定する。
  - 無い場合は、状態なしで決まる部分だけを判定する。具体的には、最小額・通貨、それに「単発の金額だけで `max` を超えるなら違反」（累積額 ≥ 0 から導ける）。決まらない部分は `indeterminate`（G-05）とする。
- **テスト**: `[G-05]`、`test_g05_resolved_when_network_state_supplied`、`test_budget_with_state`

## G-06 strictness の到達範囲（観察）— 裁定済み

**結論**: 適合するクレデンシャルでは、制約は open mandate にしか存在しない。そのため PERMISSIVE / STRICT の違いは end-to-end の判定を変えない（2026-10-31 追認）。

**根拠となる仕様文言**（`agent-intent/verifiable-intent@356c296`）。いずれも原文の引用で、結論は裏付けられている（要再確認事項なし）。

1. 制約は Autonomous モードにのみ存在する。
   - C 冒頭 Scope:
     > **Scope:** Constraints apply only to Autonomous mode (3-layer) credentials where the user delegates authority to an agent.
   - C §2.2:
     > **Constraints appear ONLY in Autonomous mode credentials.**
2. Autonomous で制約を持つマンデートは open の VCT を持つ。
   - C §2.2:
     > - **Checkout mandate** (`vct: "mandate.checkout.open.1"`): Contains `mandate.checkout.*` constraints …
     > - **Payment mandate** (`vct: "mandate.payment.open.1"`): Contains `mandate.payment.*` constraints …
   - CF §4.5.1 / §4.5.2（表）: `vct` — MUST be `"mandate.checkout.open.1"` / MUST be `"mandate.payment.open.1"`。
   - CF §10: `mandate.checkout.open.1` — "Checkout mandate — open/unfulfilled (L2 Autonomous)"。
3. 制約を評価するときの「open」は、この Autonomous マンデートを指す。
   - C §5.1:
     > | `is_open_mandate` | boolean | `true` for open (Autonomous) mandate constraints |
4. open でないマンデートは、制約を持ってはならない。
   - C §2.2:
     > **Constraints do NOT appear in Immediate mode credentials** (`vct: "mandate.checkout.1"` and `vct: "mandate.payment.1"`)
   - CF §4.4.1 / §4.4.2（Immediate）、§5.5 / §5.6（L3）の "MUST NOT contain:" の項:
     > - `constraints` array (values are final)

1–4 から、`is_open_mandate=false` で制約が評価される経路は、適合するクレデンシャルには無い。適合しない場合（final マンデートに `constraints` がある）は、制約を評価する前に `MANDATE_CONSTRAINTS_FORBIDDEN` で reject される。

**緊張関係**（Issue 候補）: C §5.4 は PERMISSIVE を既定とし、"RECOMMENDED for general-purpose verifiers that need forward compatibility" と書く。end-to-end で到達しない分岐に既定値と推奨が与えられている。C §3.3 の "A mandate MAY contain zero or more constraints." も、モードを限定しない書き方になっている。

**KYA Bench の挙動**

- strictness は必須パラメータ。
- 制約エンジン `check_constraints(is_open_mandate=False)` を直接呼べば、仕様どおりに効く。PERMISSIVE のスキップは必ず `CONSTRAINT_UNKNOWN_SKIPPED` 警告を伴う。
- §5.4 の型別ポリシー上書きにも対応する。ただし open mandate の拒否は上書きできない。

**テスト**

- end-to-end: `test_g06_strictness_does_not_change_conformant_e2e_verdicts`、ベクタ `open-mandate-unknown-constraint` / `-permissive`
- エンジン直呼び（PERMISSIVE のスキップ＋警告が観測できること）: `test_unknown_non_open_permissive_skips_with_warning`、`test_constraint_check_permissive_skip_is_observable`、ベクタ `engine-unknown-non-open-permissive`

## G-07 L3 とマンデートペアの対応付け（未定義）

- **箇所**: CF §8.1–§8.2（L2 は複数ペアを持てる。1 ペアにつき L3a＋L3b は 1 組）、CF §5.4。
- **未定義の点**: L3 がどのペアに対するものかを示す明示的なフィールドが無い。
- **KYA Bench の挙動**: L3 の `sd_hash` が束縛している L2 選択ビュー（`l2_view_l3a` / `l2_view_l3b`）に含まれるマンデートのディスクロージャから、ペアを特定する。ビューが複数ペアのマンデートを含み、一意に決まらない場合は `indeterminate`（G-07）。参照実装は位置（インデックス）で対応付けているが、これは採らない。
- **テスト**: `[G-07]`、`test_g07_resolved_by_selective_views`

## G-08 `agent_recurrence` の「現在日付」（未定義）

- **箇所**: C §4.7 手順 1（現在日付が `start_date`〜`end_date` の範囲内か。両端を含む）。
- **未定義の点**: 日付をどのタイムゾーンで評価するか。
- **KYA Bench の挙動**: 検証時刻を UTC−12 と UTC+14 の両端で日付に変換する。両方とも範囲内なら pass、両方とも範囲外なら violation、結果が分かれたら `indeterminate`（G-08）。
- **テスト**: `[G-08]`、`test_g08_unambiguous_dates_decide`

## G-09 Immediate L2 の寿命（矛盾）

- **箇所**: CF §4.3 は「15 分以内であるべき（SHOULD）」、CF §7 の表は「最大 15 分」（RFC 2119 のキーワード無し）。L1 の 1 年も同じ構図（§3.3 は SHOULD、§7 は最大）。
- **KYA Bench の挙動**: 規範語のある SHOULD を優先し、警告 `TIME_LIFETIME_SHOULD` を記録するだけにする（reject しない）。MUST が明記されているもの、つまり「Autonomous L2 の `exp` は L1 の `exp` を超えない」（CF §7）と「L3 は 1 時間以内」（CF §5.3）は reject する。
- **テスト**: `test_g09_immediate_lifetime_over_15_minutes_warns`

## G-10 「この検証器に開示された」範囲（観察）

- **箇所**: C §4.1・§4.3 手順 2–3、CF §5.4。
- **観察**: 役割ごとに見える範囲が異なる。ネットワーク向けビューは支払いマンデート＋加盟店、加盟店向けビューはチェックアウトマンデート＋品目。このため、役割に厳密に従うと、加盟店も（加盟店ディスクロージャを持たない）ネットワークも `allowed_merchants` を実質的に判定できない。
- **KYA Bench の挙動**: 中立検証器として、バンドルの `l2` プレゼンテーションで開示されたものを「開示済み」とみなす。そこで開示されていなければ、仕様どおりスキップ（pass）する。
- **テスト**: `test_g10_neutral_verifier_uses_full_l2_presentation`

## G-11 制約の配置違い（未定義）

- **箇所**: C §2.2・§3.3（チェックアウト側は `mandate.checkout.*`、支払い側は `mandate.payment.*`）。
- **未定義の点**: 登録済みの型が反対側のマンデートに置かれた場合の結果。
- **KYA Bench の挙動**: 制約自体は評価する。そのうえで `indeterminate`（G-11）を付ける。
- **テスト**: `[G-11]`

## G-12 `payment_instrument` の L2–L3a 整合（未定義）

- **箇所**: CF §4.5.2（L2 の支払いマンデートは `payment_instrument` を持つ）、§5.6（L3a も持つ）、C §2.4（fulfillment に含まれるが、どの制約もこれを参照しない）。
- **未定義の点**: L3a の `payment_instrument` が L2 と一致する必要があるか。
- **KYA Bench の挙動**: 一致すれば pass。異なれば `indeterminate`（G-12）。
- **テスト**: `[G-12]`

## G-13 ワイルドカード行と品目ごとの上限（未定義）

- **箇所**: C §4.2 手順 5c（「その SKU を `acceptable_items` に含む行」の数量合計が上限）。
- **未定義の点**: `acceptable_items` が空のワイルドカード行を「その SKU を含む行」に数えるか。
- **KYA Bench の挙動**: 数える場合と数えない場合の両方で評価する。両方で違反なら violation、両方で適合なら pass、結果が分かれたら `indeterminate`（G-13）。
- **テスト**: `[G-13]`

## G-14 マンデートを 1 件も開示しない Immediate L2（未定義）

- **箇所**: CF §4.6（モードはマンデートの VCT から推定する）、CF §13.4.11（Autonomous では少なくとも 1 件の開示が必須。Immediate には規定が無い）。
- **未定義の点**: Immediate の `typ` を持つ L2 で、`delegate_payload` が全て未開示の場合。モード推定、ペアリング、`checkout_hash` 検証のいずれもできない。
- **KYA Bench の挙動**: `indeterminate`（G-14）。`typ` が Autonomous で開示が 0 件なら、CF §13.4.11 に基づき `MODE_UNDETERMINED` で reject する。
- **テスト**: `[G-14]`

---

# Phase 2: TAP / AP2 / 合成 / 翻訳

固定版は [docs/sources.md](sources.md) を参照してください。ID の接頭辞は TAP-、AP2-、XP- です（VI の G- とは別系列）。
未定義のケースは Phase 1 と同じく `indeterminate` を返し、[tests/test_phase2.py](../tests/test_phase2.py) の `test_phase2_gap_has_definite_verdict` に strict `xfail` を置いています。対応するベクタは `*/spec_gap` カテゴリです。

| ID | 区分 | 概要 |
|---|---|---|
| TAP-01 | 未定義 | CRO / Payment Container のオブジェクト署名の署名ベースが定まらない（**Phase 2 の第 1 号**） |
| TAP-02 | 矛盾→未定義 | 署名パラメータ名 `keyId`（参照エージェント）と `keyid`（RFC 9421・Visa 仕様） |
| TAP-03 | 未定義 | browse 操作に payer タグを付けた場合 |
| AP2-01 | 未定義 | カート合計と Payment の金額が食い違う場合 |
| AP2-02 | 未定義 | Checkout と Payment でフロー（HP / HNP）が異なる場合 |
| AP2-03 | 範囲外 | 3 トークン以上の委任連鎖（エージェント間委任） |
| AP2-04 | 矛盾 | `amount_range` の数値型：スキーマは整数の最小単位、文書の例は小数 |
| AP2-05 | 未定義 | `agent_recurrence` の頻度判定と履歴状態 |
| AP2-06 | 矛盾 | `budget.max` の単位：SDK はドル（×100）、Amount 型はセント |
| AP2-07 | 矛盾 | カート品目の形：UCP スキーマは `item`、文書の例は `product` |
| AP2-08 | 矛盾 | 開示された `acceptable_items` が空の要件：仕様は一致なし、SDK はワイルドカード |
| XP-01 | 未定義 | AP2 側がエージェント鍵を示さない（human-present で `cnf` なし） |
| XP-02 | 未定義 | TAP と AP2 のエージェント同一性を結ぶ規範がない |
| XP-03 | 意味差 | 全件未開示の加盟店 allowlist：AP2 は失敗、VI はスキップ |

## TAP-01 オブジェクト署名の署名ベース（未定義）— Phase 2 の第 1 号

- **箇所**: Visa 開発者向け仕様ページ（2026-10-31 取得）の Agentic Consumer Recognition Object と Agentic Payment Container。repo には該当する実装も記述もない。
- **未定義の点**: 両オブジェクトの `signature` は「署名そのものを除く全フィールドを、受信した順に」署名すると書かれているだけ（取得したページの記述の要約で、逐語引用ではない）。連結方法、区切り、エンコード（JSON の正規化か、値の文字列連結か）、ネストしたオブジェクトの扱いが決まっていない。したがって、独立した実装者が同じ署名ベースを再構成できない。
- **公開事例**: ブリーフにある「独立実装者が第 3 層で止まった件」は、今回の調査では一次資料を特定できなかった。このため判断の根拠は上記の仕様文面だけとしている。
- **KYA Bench の挙動**
  - Payment Container: 仕様は「検証に失敗したら決済処理に使ってはならない」とする。構造（`nonce`、`kid`、`alg`、`signature` の存在）、HTTP 署名との `nonce` 一致、`kid` がレジストリにあることは判定し、違反すれば reject する。署名そのものは検証できないため、構造が正しい場合は `indeterminate`（TAP-01）にする。
  - CRO: 仕様は失敗時に「内容が不正確な可能性がある。使うかは加盟店が決める」とする。リクエストの判定には影響させず、警告 `TAP_CRO_SIGNATURE_UNVERIFIABLE`（`gap_id: TAP-01`）を記録する。
  - フィクスチャの `signature` は、ほかのフィールドの JSON にエージェント鍵で署名した**例示用の値**であり、検証器はこれに依存しない。
- **影響**: ブリーフの合成ケース「TAP payment-intent のみで Payment Container が有効 → accept」は、Container の有効性が判定できないため `indeterminate` になる（ベクタ `comp-tap-payment-with-container`、`tap-apc-signature-undefined`）。

## TAP-02 `keyId` と `keyid`（矛盾→未定義）

- **箇所**: repo の `tap-agent/agent_app.py` は `keyId="..."` を出力し、`cdn-proxy/server.js` もそれを読む。`merchant-backend/.../signature_verification.py` と Visa 仕様ページ、RFC 9421 §2.3 は `keyid`。RFC 8941 のキーは小文字のみなので、`keyId` は構造化フィールドとしても不正。
- **KYA Bench の挙動**: `keyid` は通常どおり処理する。`keyId` しかない場合は残りの検査（署名・レジストリ等）を続けたうえで `indeterminate`（TAP-02）にする。

## TAP-03 browse 操作の payer タグ（未定義）

- **箇所**: Visa 仕様ページはタグを「閲覧は `agent-browser-auth`、決済は `agent-payer-auth`」とする。repo は商品詳細で browser、チェックアウトで payer を使う。逆向きの不一致（決済で browser タグ）は操作の権限外なので reject できる。一方、payer タグで閲覧した場合の扱いはどちらにも書かれていない。
- **KYA Bench の挙動**: `indeterminate`（TAP-03）。

## TAP の解釈（判定を変えない注記）

- **TAP-N1 CRO は助言的**: CRO の欠落・不一致・ID トークン不正は、すべて警告（`TAP_CRO_*`）として記録する。ID トークンはモック発行者のフィクスチャ JWKS で検証する（PS256 / RS256、`kid`、`iss`、`exp`）。
- **TAP-N2 タグ語彙**: repo の `cdn-proxy/server.js` のコメントには `agent-payment-auth` が出てくる。仕様ページは 2 種以外を不可とするため、`TAP_TAG_UNKNOWN` で reject する。
- **TAP-N3 リプレイ**: repo は鍵に関係なく nonce 単位で 1 時間記憶する。仕様ページは「直近 8 分に記録した nonce を拒否」とする。KYA は (keyid, nonce) 単位で 8 分間を窓とし（ブリーフの「同一鍵・窓内」）、キャッシュはプロセス内に持つ。
- **TAP-N4 時刻**: `created` の未来許容は repo の 60 秒（仕様ページは「過去であること」）。`expires < now` で失効（repo）。`expires - created` は 8 分以内（仕様ページ。repo は検査していない）。
- **TAP-N5 アルゴリズム**: `rsa-pss-sha256` は RFC 9421 の登録名ではない（登録は `rsa-pss-sha512`）。repo の実装に合わせ、PSS・MGF1-SHA256・最大ソルト長で検証する。`alg` の大文字小文字は repo と同じく区別しない。鍵の `algorithm` と一致しなければ reject する。
- **TAP-N6 署名ベース**: `@signature-params` には受信した Signature-Input のメンバ文字列をそのまま使う（repo の実装と同じで、RFC 9421 §2.3 の「受信したパラメータ」と整合する）。対応する派生コンポーネントは `@authority`、`@path`、`@method`、`@query` と通常ヘッダ。それ以外やコンポーネントのパラメータは KYA の未対応として `indeterminate` にする（`TAP_COMPONENT_UNSUPPORTED`。仕様ギャップではない）。`Content-Digest` があれば本文と照合する（RFC 9530）。
- **TAP-N7 操作の分類**: どのエンドポイントが決済かは加盟店の文脈であり、TAP は定義しない。バンドルの `operation`（`browse` / `payment`）で与え、無ければ警告 `TAP_OPERATION_NOT_DECLARED` を出す。
- **TAP-N8 未対応**: `browsingIOU`（HTTP 402）、`contextualData` の値検証、暗号化された `payload` は扱わない。仕様ページの表記ゆれ（`idToken` と `IdToken`、`credentialHash` と `paymentCredentialsHash`）は表の綴り（`idToken`）を採る。

## AP2-01 カート合計と Payment 金額（未定義）

- **箇所**: specification.md は Checkout と Payment を `checkout_jwt` のハッシュでのみ結ぶ。`checkout_jwt` の内容は範囲外とされている（「AP2 is agnostic to the contents of the merchant-signed Checkout JWT」）。
- **KYA Bench の挙動**: UCP の `totals[type=total]` と `currency` があれば Payment と比べる。一致すれば pass、異なれば `indeterminate`（AP2-01）。合計が無ければ警告 `AP2_CART_TOTAL_UNAVAILABLE`。

## AP2-02 フローの混在 / AP2-03 委任の深さ（未定義・範囲外）

- Checkout が human-present で Payment が human-not-present、あるいはその逆の組み合わせは、仕様に記述がない → `indeterminate`（AP2-02）。
- 3 トークン以上の連鎖は「Agent-to-Agent Delegation … outside the scope」→ `indeterminate`（AP2-03）。

## AP2-04 `amount_range` の数値（矛盾）

- **箇所**: `open_payment_mandate.json` は `min` / `max` を整数（最小単位）と定義する。`payment_mandate.md` の例は `"max": 100.50`。
- **KYA Bench の挙動**: 整数でない数値が来たら `indeterminate`（AP2-04）。

## AP2-05 `agent_recurrence`（未定義）

- 「前回の提示から頻度を満たすだけ時間が離れていること」の期間境界が定義されていない。また、履歴（mandate context）なしでは判定できない。
- **KYA Bench の挙動**: 履歴が無ければ `indeterminate`。`max_occurrences` は履歴があれば判定する。`ON_DEMAND` 以外で前回日時があれば `indeterminate`。`amount_range` と `budget` の併存は SDK の規則に従って必須とする。

## AP2-06 `budget.max` の単位（矛盾）

- **箇所**: スキーマは `"type": "number"`、文書の例は `1000.00`、SDK は `int(max * 100)`（ドル扱い）。一方、`payment_amount` を含む Amount 型は整数の最小単位。
- **KYA Bench の挙動**: 両方の読み方で評価する。結論が一致すればそれに従い、分かれれば `indeterminate`（AP2-06）。mandate context が無い場合は SDK と同じく違反とする。

## AP2-07 / AP2-08 品目（矛盾）

- AP2-07: UCP の `line_item.json` は `item.id`、`checkout_mandate.md` の例は `product.id`。`item.id` を読めない品目があれば `indeterminate`。
- AP2-08: 仕様は「開示された `acceptable_items` に ID がある場合に一致」とする。SDK の `max_flow_helper.py` は、空の要件をワイルドカードとして扱う。開示が空の要件があれば `indeterminate`。それ以外は仕様の最大フロー（要件数量の合計 ＝ カート数量の合計 ＝ 最大流）で厳密に判定する。

## AP2 の注記

- **v0.2 と用語**: [docs/sources.md](sources.md) を参照。
- **`checkout_jwt` の決定論的署名**: specification.md は `checkout_jwt` に「決定論的でない署名」を求める（レインボーテーブル対策）。フィクスチャは再生成のバイト同一性のため RFC 6979 の決定論的 ECDSA を使っており、この MUST に反する。検証器は 1 つの署名からはこれを判別できない。テスト専用の鍵とデータに限った措置。
- **鍵**: ルートは `kid` によるトラストリスト照合のみ（`x5c` はオフラインでは扱わない）。アルゴリズムは SDK と同じ ES256 のみで、それ以外は KYA の未対応として `indeterminate` にする。
- **加盟店署名**: 加盟店の鍵フィクスチャが無いため、`checkout_jwt` の署名は検証せず、警告を記録する。
- **事前設定値**: agent_authorization.md の処理規則 2「open Mandate の値が closed Mandate で変わっていないこと」を、`vct` / `cnf` / `constraints` / `iat` / `exp` 以外の全クレームに等値で適用する。SDK は一部フィールドだけを比較している。
- **未知の制約**: AP2 では常に失敗（`AP2_CONSTRAINT_UNKNOWN`）。strictness は関係しない。

## XP-01 / XP-02 合成の束縛（未定義）

- **箇所**: TAP にも AP2 にも、互いのエージェント識別子を結ぶ規範はない。TAP のエージェント鍵は Ed25519 / RSA、AP2 のエージェント鍵（`cnf.jwk`）は SDK では P-256 であり、鍵材料が一致することは通常ない。
- **KYA Bench の規則**（ブリーフが期待判定を固定したため、照合方法を定めた）
  - 提示者 ＝ TAP 署名鍵 `keyid` を持つレジストリ上のエージェント。
  - Mandate のエージェント ＝ AP2 のエージェント鍵と同じ公開鍵を登録しているレジストリ上のエージェント。
  - 同一なら束縛成立。異なれば `XPROTO_PRESENTER_MISMATCH` で reject。
- **未定義になる場合**
  - AP2 がエージェント鍵を示さない（human-present で `cnf` なし）→ `indeterminate`（XP-01）。
  - AP2 のエージェント鍵がどのレジストリ・エントリにもない → `indeterminate`（XP-02）。
- そのほか、AP2 単独は accept ＋ `XPROTO_IDENTITY_LAYER_ABSENT`。TAP 単独や TAP / AP2 のいずれかの reject は、そのまま合成の判定に反映する（最悪値をとる）。

## XP-03 翻訳等価性で見つかった意味差

- **ケース**: 加盟店 allowlist の要素がすべて未開示（`{"...": digest}` のみ）。
  - AP2（checkout_mandate.md）: 「`allowed` に開示要素が 1 つも無ければ制約は無効」→ 失敗。
  - VI（constraints.md §4.1 手順 3）: 「開示された加盟店が無ければこの検査をスキップ」→ 通過。
- **判断**: 翻訳器のバグではなく、仕様間の意味差。ベクタ `xlate-undisclosed-allowlist` は `XLATE_DIVERGENT`（reject）を期待値として固定している。
- **そのほかの検証結果**: 範囲内・上限超過・下限未満・通貨不一致・allowlist 外・名前＋サイトでの一致・期限切れ・時計ずれ内・空の allowlist は、すべて一致した（AP2 の SDK も VI も期限に 300 秒の許容を置くため、期限境界も一致する）。小数の上限（AP2-04）と翻訳対象外の型は「判定不能」として扱う。
