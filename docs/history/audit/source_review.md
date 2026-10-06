# 原始 Python 檔案逐檔審查

> Historical audit of the legacy implementation. See [source recovery](../README.md) and [current implementation status](../../IMPLEMENTATION_STATUS.md).

2026-10-02。共 70 份原始 Python 檔案，以下每列均經過原始碼閱讀。Issue ID 對照主報告。

INFO 表示該檔沒有單獨確認的協定阻斷問題，不代表整個呼叫鏈已安全。空檔案與只有註解的檔案另外標示。

| 檔案 | 行數 | 問題 | 審查結論 |
| --- | --- | --- | --- |
| `gen_urls.py` | 14 | P2-07 | 頂層執行就寫檔，固定 L8，輸出位置與 README dataset 路徑不同，只有正例且没有 ground truth 欄位 |
| `src/client/io/gdfa_loader.py` | 298 | P1-03 P1-04 P2-01 P2-02 | 容器 body SHA256 與尺寸檢查存在。inv_permute 方向錯，完整讀入再切片複製，row_aids 缺失或尺寸錯可靜默忽略，sidecar 未綁定同一 build |
| `src/client/io/payload_reader.py` | 200 | P2-07 | 預設 binary 讀取合理。可選文字正規化會改變 regex 語言，max_len 負值在不同入口處理不一致，此模組不是主 benchmark 的輸入入口 |
| `src/client/io/row_alph_loader.py` | 137 | P0-02 P1-01 | 有表長、行數與 col 範圍檢查。只支援每 state 每 byte 一個 col 的 single8 格式，將完整字元分組公開，不是 paper 的隱藏全域 Cx |
| `src/client/offline/param_setup.py` | 194 | P1-13 P2-03 | common.* 匯入路徑錯而不能載入，另有一套 SecurityParams，extension state 為占位，未完成 paper 的 setup |
| `src/client/online/abp_decide.py` | 26 | P1-05 P1-09 | 已知 ID 的 ALLOW 優先處理合理，但只能處理上游保留下來的 IDs，未知 ID 預設 BLOCK 與 CLI 不一致 |
| `src/client/online/chooser_http.py` | 69 | P0-02 P1-13 | row 與 col 明文 HTTP，端點 /ot 或 /choose_one 不同於 README server，忽略 preload 失敗，名稱不代表 cryptographic OT |
| `src/client/online/chooser_master.py` | 65 | P0-02 P2-04 | client 持有 master 或完整 key table，col 被忽略，每 row 同 key。大於 32 bytes 的擴展與 dev server 不一致 |
| `src/client/online/engine.py` | 446 | P0-01 P0-02 P1-03 P1-04 P1-05 P1-07 P1-11 P2-04 | 核心是 state-indexed table walk。沒有下一個 pad 的鏈結，解碼與 builder 不同，未驗證 zero tail，對 key 模式做寬鬆猜測，每個 prefix 輸出 ID，cache 跨輸入保留，regex fallback 的 ID 與狀態管理也不同 |
| `src/client/online/gdfa_evaluator.py` | 203 | P1-03 P1-05 | 舊版 BE 欄位解碼，PRG domain 與新 builder 不同，可提前停止，不是 paper 最終列輸出。synthetic test 過關不代表能解目前產物 |
| `src/client/online/ot_client.py` | 53 | P0-02 P1-13 | LocalTrivialOTChooser 直接讀取全部 payload 與 server.sessions 的 seed，是同程序測試替身 |
| `src/client/online/ot_pad_oracle.py` | 78 | P1-03 P1-13 | 有 zero tail 驗證方向，但沿用舊格式和 PRG domain，無法直接配目前 builder |
| `src/client/online/ot_query_builder.py` | 180 | P0-01 P1-11 P1-13 | 以 state row_id 與 byte x 呼叫抽象 TokenSource，有 cmax*kprime 長度檢查與 LRU/batch 去重，但不是 paper 依 input position 產生加密 OT queries，也未接到主 engine |
| `src/client/online/token_http.py` | 96 | P0-02 P2-04 | README 實際 chooser，傳 row、col、master_hex，收到直接 GK。k_bytes 固定 32，統計是 HTTP JSON payload bytes |
| `src/common/abp_canonicalize.py` | 149 | P1-07 P1-08 P2-07 | 移除 scheme 並加入 host、separator、type、party、doc 資訊，但規則端沒有對應編碼。分隔符壓縮、port、userinfo 與 public-suffix fallback 也要明確界定語義 |
| `src/common/crypto/ddh_group.py` | 43 | P0-04 P2-03 | MODP subgroup 參數及 validate_element 可用，與 paper EC P-192 不同本身不必然錯，問題是 receiver 未呼叫驗證。elt 編碼借用 q 寬度在此固定群恰好相等 |
| `src/common/crypto/hmac.py` | 1 | INFO | 只有一行註解，沒有實作。其他模組使用標準庫 hmac，不可當成另有 HMAC 協定 |
| `src/common/crypto/prf.py` | 51 | INFO | HMAC based deterministic expansion，可作為自訂 PRF/KDF primitive。helper 名稱不代表完整標準 HKDF，不能因此繼承上層 OT 安全性 |
| `src/common/crypto/prg.py` | 61 | P1-03 | HMAC counter expansion 和 byte/bit helper 本身可理解，有 domain separation，但呼叫端的 domain 不一致 |
| `src/common/net/messages.py` | 274 | P1-13 | DTO 與 sanity checks 多為另一版介面，from_json 不自動完成全部驗證，與 dev server 的訊息格式未接通，不能視為已實作 paper 網路流程 |
| `src/common/odfa/matrix.py` | 298 | P0-01 P1-01 P1-02 | DFA state-row 和 ODFA edge 結構可用，並非 n by Q matrix，dummy 是可解的 dst0 edge，與 paper random invalid entry 不同 |
| `src/common/odfa/packing.py` | 51 | P1-02 P1-03 | 把 outmax*kprime 當成單一 transition 的總位數，與矩陣 cell / entry 的分層混淆 |
| `src/common/odfa/params.py` | 137 | P1-01 P1-02 | kprime 沒有依 2k+ceil(logQ) 推導，cmax<=alphabet 限制不符合全域群定義，packing 中 outmax 導致 builder 重複放大 |
| `src/common/odfa/permutation.py` | 39 | P1-04 | Fisher-Yates 的 16-bit random modulo 有偏，超過 65536 state 無法均勻選擇，inverse_perm 未驗證唯一性 |
| `src/common/odfa/seed_rules.py` | 17 | P0-01 P1-11 | GK、row、col 的 deterministic seed helper 在現行 builder/engine 路徑可一致，但不是 paper 的 fresh position-state pad chaining |
| `src/common/ot/base_ot2/ddh_ot.py` | 85 | P0-04 | sender 有 B subgroup 驗證，receiver 沒有 A 驗證，A=p-1 能從公開 B 分辨 choice，已重現 |
| `src/common/ot/base_ot2/iknp_extention.py` | 156 | P2-03 | backend=iknp 實際 fallback DirectOTExtension，每個 transfer 重新做 DDH，沒有真正 IKNP、matrix transpose 或 malicious extension proof |
| `src/common/ot/ot_1of256.py` | 57 | P0-03 P2-03 | 1-of-m wrapper，功能可選對一筆，但繼承 XOR 組合洩漏，service 在本地可見，不是 README 網路路徑 |
| `src/common/ot/ot_1ofm.py` | 166 | P0-03 | 各 bit seed 的 PRF XOR 未把完整 message index 納入 domain，四筆 ciphertext XOR 直接等於 plaintext XOR，零 OT query 即洩漏關係 |
| `src/common/urlnorm.py` | 83 | P1-07 P2-07 | legacy URL/HTTP 正規化會去除 scheme，與 domain regex 的 :// 不一致，host split colon 不能正確處理 IPv6 與部分 userinfo/port 情境 |
| `src/common/utils/checks.py` | 96 | INFO | 通用 bytes、範圍及 XOR 檢查，未發現足以單獨改變 paper 語義的問題，上層仍須實際呼叫並檢查協定 invariant |
| `src/common/utils/encode.py` | 164 | INFO | 整數與 bytes 編碼 helper 有明確 endian 參數，問題在各上層使用不同欄位布局，不能靠此檔單独解決 |
| `src/scripts/build_gdfa_offline.py` | 304 | P1-10 P1-13 P2-01 | 另一條 builder，保存全部 rows，OFFLINE key domain 與其他入口不同，若不保存 secrets 無法重建 random pads，聲稱隱藏 permutation 但 public header 仍包含 |
| `src/scripts/easylist_make_smallset.py` | 173 | P1-08 P2-07 | subset filtering 與正負樣本 heuristic，ads 的 negative 是 adsx 而仍命中，domain rule 的 path/option 條件未完整建模 |
| `src/scripts/easylist_smallset_to_rules.py` | 80 | P1-06 P1-13 P2-07 | 輸出 .rules 與目前 loader 不相容，含不支援的 regex escape，HTTP Host 與 request path 順序假設不符一般 request，從正例反推規則會改變原語義 |
| `src/server/io/easylist_loader.py` | 111 | P1-07 P1-08 | 簡化 EasyList-to-regex，domain rule 期待原始 scheme，wildcard/anchor/separator/options/cosmetic/regex 不完整，不是 ABP parser |
| `src/server/io/rule_loader.py` | 155 | P1-09 P1-13 | 轉 RuleSpec 時丟 action、label，每檔 attack_id 重新从 1 開始，flags 型別與 downstream 不一致，只接受 .abp/.txt 而非 Snort .rules |
| `src/server/offline/build_gdfa_from_rules.py` | 439 | P1-01 P1-09 P1-10 P1-13 | 另一套編譯及 GK 輸出入口，cmax=1 被誤稱 faithful，fallback AID 探測與實際結構不完全對應，主 README 未使用此入口，輸出的 GK 應限定 server 所有 |
| `src/server/offline/dfa_combiner.py` | 140 | P1-06 P1-09 | DFA union 和 tagged minimization 有實作，不應因空 minimization.py 判定全無最小化。multiprocessing 對 RegexFlags 的 coercion 會改變語義，沒有完整 Snort content/pcre parser |
| `src/server/offline/dfa_optimizer/char_grouping.py` | 107 | P1-01 | 每 state 依相同 destination 分組這部分合理，卻把每 byte 在單列唯一群誤認為 paper cmax=1 |
| `src/server/offline/dfa_optimizer/minimization.py` | 0 | INFO | 空檔案，真正 minimization 在 regex_to_dfa/chain_rules 中，此檔不提供額外演算法 |
| `src/server/offline/dfa_optimizer/sparsity_analysis.py` | 93 | P1-01 | out-degree 統計可用，suggest_cmax 硬設 1 沒有建立全域 groups 或統計 Cx |
| `src/server/offline/export/gdfa_packager.py` | 127 | P2-01 P2-02 | 容器有固定 header/body/trailer 格式與 body hash，卻 list(rows) 再 join 耗記憶體，sidecar 缺少同一 build 的 manifest 綁定，舊 sidecar 可能殘留 |
| `src/server/offline/gdfa_builder.py` | 262 | P0-01 P1-02 P1-03 P1-04 P1-05 | 只有 state-indexed table，一層 per-entry PRG XOR，無 n、group-key inner layer、next pad、每位置 permutation、cell shuffle。bit packing 和消費端不同 |
| `src/server/offline/key_generator.py` | 116 | P0-01 P1-10 P1-11 | 每 row/col 的 PRF derivation 與主 chooser 的 row-only derivation 是不同設計，沒有 input position freshness 或 next-pad 生成 |
| `src/server/offline/rules_to_dfa/chain_rules.py` | 327 | P1-05 P1-06 P1-09 | union 和保留 tag set 的 minimization 合理，轉 ODFA 時 min(tag) 丟掉 ALLOW 可能性，edge AID 使用 source state，RuleSpec 無 action metadata |
| `src/server/offline/rules_to_dfa/regex_to_dfa.py` | 479 | P1-05 P1-06 | Thompson NFA、subset construction、minimization 存在，但 exact repeat、negated class ignore-case、anchor、escape、Unicode、search semantics 不正確，edge AID 是 source state |
| `src/server/online/gk_loader.py` | 34 | P2-02 | 檢查 key table 長度，但未驗證 metadata 的 SHA，無法保證選到與 GDFA 同版 key material |
| `src/server/online/handler.py` | 71 | P0-02 P1-10 P1-13 | 依賴 manifest 的另一 server API，主 builder 未產生所需 manifest，row payload 直接包含所有 GK，session 與 offline random key material 缺乏一致生命周期 |
| `src/server/online/ot_response_builder.py` | 124 | P0-02 P1-13 | row alphabet 與 payload builder 可做本地模擬，但暴露整列 GK，respond_with_ot1ofm 呼叫不存在的 sender.send，舊测试所需三個 exports 已不存在 |
| `src/server/online/session_manager.py` | 126 | P1-10 P1-11 | session ID 與 TTL 有管理，master derivation 未包含 sid，兩個不同 session 同 keys，random 模式又未和既有 GDFA 綁定 |
| `src/server/ot/dev_ot_server.py` | 85 | P0-02 P1-11 P2-04 | README server 是明文開發服務，start 忽略狀態，choose 忽略 col，接受 client master override，無 input-position OT 或 choice quota |
| `src/test/integration/test_end_to_end.py` | 0 | P2-05 | 0 bytes，沒有 end-to-end 測試 |
| `src/test/unit/test_evaluator.py` | 0 | P2-05 | 0 bytes，沒有測試 |
| `src/test/unit/test_gdfa_builder.py` | 0 | P2-05 | 0 bytes，沒有測試 |
| `src/test/unit/test_offline_gdfa.py` | 93 | P1-13 P2-05 | 執行失敗，從 gdfa_builder 匯入不存在的 ODFAEdge，尚未走到 offline 正確性 assertions |
| `src/test/unit/test_online_eval.py` | 100 | P2-05 | main 執行通過，但自己製作舊格式密文與 FakeOracle，沒有串目前 builder 或真實 OT |
| `src/test/unit/test_online_ot_eval.py` | 130 | P1-13 P2-05 | 執行失敗，從 ot_response_builder 匯入不存在的 RowAlphabet/build_row_ot_plan/make_row_ot_sender |
| `src/test/unit/test_ot.py` | 202 | P0-03 P0-04 P2-05 | main 所有功能測試通過，涵蓋 bytes/ints/256/batch/direct，但不測未選訊息關係或惡意 sender choice privacy |
| `src/test/unit/test_sparsity_analysis.py` | 0 | P2-05 | 0 bytes，沒有測試 |
| `tools/bench_all.py` | 267 | P1-10 P1-12 P2-06 | build 输出 outdir/artifacts，engine cfg 卻仍讀 artifacts/Lx，無 key bridge，subprocess wall time 包入初始化/warmup/輸出及 regex baseline，不能當 paper online 時間 |
| `tools/bench_ot.py` | 107 | P1-11 P1-12 | 初始化一次，warmup 後只清統計不清 GK cache，input encoding 與 bench_zids 不同，量的是 HTTP 開發 chooser |
| `tools/bench_zids.py` | 169 | P1-07 P1-12 | 先做 ABP canonicalization，每次 eval 又初始化 engine，單樣本 percentile 會失敗，both mode 的 mutually exclusive CLI 與所需參數矛盾 |
| `tools/build_artifacts.py` | 685 | P1-05 P1-09 P1-10 P2-01 | 主 builder 會 prefilter/sanitize 丟 flags/action 與重新編號，預設 random pads 沒有 online key export，permute=False，多種 fallback 及重複編譯使 provenance 不明確 |
| `tools/build_from_easylist.py` | 87 | P1-13 | 多處舊 API 不相容，parse_easylist 接收 file object 而需 path，RuleSpec/return arity/keyword/packager/seed helper 呼叫不符 |
| `tools/dfa_mat.py` | 3 | P2-08 | 頂層載入 artifacts/gdfa.bin 的三行診斷 script，非 paper DfaMat 演算法，匯入時會讀大檔 |
| `tools/eval_urls.py` | 46 | P1-07 P1-13 | 建立 LocalTrivialOTChooser 時缺必要 seed_k_bytes，依賴不存在的預設 manifest/產物命名，normalization 路徑與現行 engine 不一致 |
| `tools/export_id_to_action.py` | 32 | P1-09 | 按原始文字行編 ID，略過規則的条件不同於 compiler，無法在 prefilter 後保證 ID 指向同一條規則 |
| `tools/ot_healthcheck.py` | 70 | P1-13 | 舊 port/schema/HMAC domain，期待 session/k_bytes/items/payload_hash 與 dev server 不符，沒有真正 OT 檢查且 request 無 timeout |
| `tools/run_dfa_with_abp.py` | 198 | P1-09 P1-12 | 每 eval 有 cfg 就重新 init，未知 ID 丟棄而不是 library 預設 BLOCK，ABP action 決策建立在已被上游丟失/重排的 metadata 上 |
