# 一次情報（固定版）

KYA Bench が判定の根拠にした資料と、その固定版です。判定 JSON の `spec` フィールドにも同じ値を出力します。

| プロトコル | 一次情報 | 固定版 | 主に参照したファイル |
|---|---|---|---|
| VI | `github.com/agent-intent/verifiable-intent` | `356c29635f1c44df7de02edb58699ca9f29bece6`（2026-04-20） | `spec/credential-format.md`、`spec/constraints.md` |
| TAP | `github.com/visa/trusted-agent-protocol` | `16d59bdf3f8a542bc538d0962edbb80ea30a02af`（2025-10-28、`main`） | `tap-agent/agent_app.py`、`tap-agent/README.md`、`cdn-proxy/server.js`、`cdn-proxy/README.md`、`agent-registry/models.py`、`merchant-backend/app/security/signature_verification.py` |
| TAP（補助） | Visa「Trusted Agent Protocol: Merchant Specification」 `developer.visa.com/docs/trusted-agent-protocol/trusted-agent-protocol-specifications` | 版表記なし。2026-10-31 取得 | 必須パラメータ、8 分の窓、タグ語彙、`agenticConsumer` / `agenticPaymentContainer` |
| AP2 | `github.com/google-agentic-commerce/AP2` | `e1ea56db72a6385bce3e5c1112b3a56ce60acb43`（2026-04-29、v0.2.0 以降） | `docs/ap2/specification.md`、`agent_authorization.md`、`checkout_mandate.md`、`payment_mandate.md`、`code/sdk/schemas/ap2/*.json`、`code/sdk/python/ap2/sdk/{sdjwt/*,constraints.py,max_flow_helper.py,mandate.py}` |
| SD-JWT | RFC 9901 | 2025-11 | §4.1、§7.1 |
| HTTP 署名 | RFC 9421、RFC 8941、RFC 9530 | — | 署名ベース、構造化フィールド、Content-Digest |

## TAP について

- repo は RFC 9421 の HTTP 署名層とエージェント・レジストリの**サンプル実装**です。Consumer Recognition Object（`agenticConsumer`）と Agentic Payment Container（`agenticPaymentContainer`）は、repo のどこにも出てきません。
- そのため、この 2 つについては Visa の開発者向けページ（上表の「補助」）を使いました。このページには版番号も日付もないため、取得日を記録しています。
- repo と開発者向けページが食い違う箇所は `docs/spec-gaps.md` の TAP 節にまとめています。

## AP2 について

- AP2 は v0.2.0（2026-04-28）で設計が変わりました。v0.1 の Intent / Cart / Payment Mandate は廃止され、open / closed の Checkout Mandate と Payment Mandate、それを連鎖させる委任 SD-JWT（`~~` 区切り）になっています。
- Phase 2 のブリーフは v0.1 の用語で書かれていますが、「表現形式は repo の現行サンプルに従う」という指示に従い、v0.2 で実装しました。用語の対応は次のとおりです。

| ブリーフ（v0.1） | v0.2 | vct |
|---|---|---|
| Intent Mandate | open Checkout Mandate ＋ open Payment Mandate | `mandate.checkout.open.1` / `mandate.payment.open.1` |
| Cart Mandate | closed Checkout Mandate（＋ `checkout_jwt`） | `mandate.checkout.1` |
| Payment Mandate | closed Payment Mandate | `mandate.payment.1` |
| human-present | ユーザー（Trusted Surface）が closed Mandate に直接署名した 1 トークン | — |
| human-not-present | ユーザー署名の open Mandate ～～ エージェント署名の closed Mandate | — |
