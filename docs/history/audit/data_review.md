# 資料、設定與產物附錄

> Historical audit of the legacy implementation. See [source recovery](../README.md) and [current implementation status](../../IMPLEMENTATION_STATUS.md).

以下為 2026-10-02 實際檔案的逐份檢查結果。Bytes 是容器完整大小。Hash OK 只表示 body 與原有 trailer 一致。

## GDFA 容器

| 檔案 | States | outmax | 實際最大 degree | Bytes | 非零 AID 種數 | Identity perm | Hash OK |
| --- | --- | --- | --- | --- | --- | --- | --- |
| artifacts/gdfa.bin | 1419 | 38 | 38 | 65575321 | 0 | False | True |
| artifacts/L12/gdfa.bin | 2237 | 30 | 30 | 64435860 | 200 | True | True |
| artifacts/L128/gdfa.bin | 25632 | 39 | 39 | 1247703574 | 200 | True | True |
| artifacts/L16/gdfa.bin | 3002 | 23 | 23 | 50831941 | 200 | True | True |
| artifacts/L20/gdfa.bin | 3795 | 26 | 26 | 82111490 | 200 | True | True |
| artifacts/L24/gdfa.bin | 4548 | 13 | 13 | 24617398 | 200 | True | True |
| artifacts/L28/gdfa.bin | 5431 | 25 | 25 | 108646230 | 200 | True | True |
| artifacts/L32/gdfa.bin | 6413 | 39 | 39 | 312164677 | 200 | True | True |
| artifacts/L48/gdfa.bin | 9627 | 38 | 38 | 444891627 | 200 | True | True |
| artifacts/L64/gdfa.bin | 12827 | 39 | 39 | 624381784 | 200 | True | True |
| artifacts/L8/gdfa.bin | 1419 | 38 | 38 | 65575323 | 178 | True | True |
| artifacts/small/gdfa.bin | 22 | 6 | 6 | 25579 | 2 | True | True |
| out/bench_pipeline/artifacts/gdfa.bin | 1608 | 36 | 36 | 66694092 | 178 | True | True |
| out/bench_pipeline_L12/artifacts/gdfa.bin | 2237 | 256 | 30 | 4691339288 | 200 | True | True |
| out/bench_pipeline_L128/artifacts/gdfa.bin | 25632 | 256 | 39 | 53754342937 | 200 | True | True |
| out/bench_pipeline_L16/artifacts/gdfa.bin | 3002 | 256 | 23 | 6295664393 | 200 | True | True |
| out/bench_pipeline_L20/artifacts/gdfa.bin | 3795 | 256 | 26 | 7958709894 | 200 | True | True |
| out/bench_pipeline_L24/artifacts/gdfa.bin | 4548 | 256 | 13 | 9537869115 | 200 | True | True |
| out/bench_pipeline_L28/artifacts/gdfa.bin | 5431 | 256 | 25 | 11389658746 | 200 | True | True |
| out/bench_pipeline_L32/artifacts/gdfa.bin | 9627 | 256 | 38 | 20189329518 | 200 | True | True |
| out/bench_pipeline_L48/artifacts/gdfa.bin | 9627 | 256 | 38 | 20189329518 | 200 | True | True |
| out/bench_pipeline_L64/artifacts/gdfa.bin | 12827 | 256 | 39 | 26900234747 | 200 | True | True |
| out/bench_pipeline_L8/artifacts/gdfa.bin | 1419 | 256 | 38 | 2975864862 | 178 | True | True |
| out/bench_single_thread/artifacts/gdfa.bin | 12827 | 39 | 39 | 624381784 | 200 | True | True |

## Engine 設定

| 檔案 | GDFA | 檔案存在 | Chooser | 含 master | 忽略的 gk_index_mode |
| --- | --- | --- | --- | --- | --- |
| configs/engine_init.json | .\artifacts_small\gdfa.bin | False | src.client.online.chooser_ot:OTChooser | False | True |
| configs/engine_init_L12.json | .\artifacts\L12\gdfa.bin | True | src.client.online.token_http:_OTRowChooser | True | False |
| configs/engine_init_L128.json | .\artifacts\L128\gdfa.bin | True | src.client.online.token_http:_OTRowChooser | True | False |
| configs/engine_init_L16.json | .\artifacts\L16\gdfa.bin | True | src.client.online.token_http:_OTRowChooser | True | False |
| configs/engine_init_L20.json | .\artifacts\L20\gdfa.bin | True | src.client.online.token_http:_OTRowChooser | True | False |
| configs/engine_init_L24.json | .\artifacts\L24\gdfa.bin | True | src.client.online.token_http:_OTRowChooser | True | False |
| configs/engine_init_L28.json | .\artifacts\L28\gdfa.bin | True | src.client.online.token_http:_OTRowChooser | True | False |
| configs/engine_init_L32.json | .\artifacts\L32\gdfa.bin | True | src.client.online.token_http:_OTRowChooser | True | False |
| configs/engine_init_L48.json | .\artifacts\L48\gdfa.bin | True | src.client.online.token_http:_OTRowChooser | True | False |
| configs/engine_init_L64.json | .\artifacts\L64\gdfa.bin | True | src.client.online.token_http:_OTRowChooser | True | False |
| configs/engine_init_L8.json | .\artifacts\L8\gdfa.bin | True | src.client.online.token_http:_OTRowChooser | True | False |
| configs/engine_init_small.json | .\artifacts\small\gdfa.bin | True | src.client.online.token_http:_OTRowChooser | True | False |

## 規則檔

useful 此處僅排除空行、! 註解與 [header，並不宣稱是有效 ABP network rules。cosmetic 等仍需單獨分類。

| 檔案 | 行數 | useful | unique useful | domain anchor | allow | options | cosmetic |
| --- | --- | --- | --- | --- | --- | --- | --- |
| rules/easylist copy.txt | 71267 | 70967 | 70963 | 45210 | 738 | 8228 | 23491 |
| rules/easylist.txt | 71266 | 70967 | 70963 | 45210 | 738 | 8228 | 23491 |
| rules/easylist_2k.abp | 2000 | 2000 | 2000 | 2000 | 0 | 0 | 0 |
| rules/easylist_2k.txt | 37228 | 37212 | 37211 | 36525 | 673 | 642 | 0 |
| rules/input200/easylist_12.abp | 200 | 200 | 200 | 200 | 0 | 0 | 0 |
| rules/input200/easylist_128.abp | 200 | 200 | 200 | 200 | 0 | 0 | 0 |
| rules/input200/easylist_16.abp | 200 | 200 | 200 | 200 | 0 | 0 | 0 |
| rules/input200/easylist_20.abp | 200 | 200 | 200 | 200 | 0 | 0 | 0 |
| rules/input200/easylist_24.abp | 200 | 200 | 200 | 200 | 0 | 0 | 0 |
| rules/input200/easylist_28.abp | 200 | 200 | 200 | 200 | 0 | 0 | 0 |
| rules/input200/easylist_32.abp | 200 | 200 | 200 | 200 | 0 | 0 | 0 |
| rules/input200/easylist_48.abp | 200 | 200 | 200 | 200 | 0 | 0 | 0 |
| rules/input200/easylist_64.abp | 200 | 200 | 200 | 200 | 0 | 0 | 0 |
| rules/input200/easylist_8.abp | 200 | 200 | 178 | 200 | 0 | 0 | 0 |
| rules/small.abp | 2 | 2 | 2 | 1 | 1 | 0 | 0 |

## Dataset

| 檔案 | 資料列 | unique | 只有 URL | 符合對應網域規則數 |
| --- | --- | --- | --- | --- |
| rules/input200/dataset/dataset_L128_urls.txt | 200 | 200 | True | 200 |
| rules/input200/dataset/dataset_L12_urls.txt | 200 | 200 | True | 200 |
| rules/input200/dataset/dataset_L16_urls.txt | 200 | 200 | True | 200 |
| rules/input200/dataset/dataset_L20_urls.txt | 200 | 200 | True | 200 |
| rules/input200/dataset/dataset_L24_urls.txt | 200 | 200 | True | 200 |
| rules/input200/dataset/dataset_L28_urls.txt | 200 | 200 | True | 200 |
| rules/input200/dataset/dataset_L32_urls.txt | 200 | 200 | True | 200 |
| rules/input200/dataset/dataset_L48_urls.txt | 200 | 200 | True | 200 |
| rules/input200/dataset/dataset_L64_urls.txt | 200 | 200 | True | 200 |
| rules/input200/dataset/dataset_L8_urls.txt | 200 | 178 | True | 200 |

## CSV

| 檔案 | 列數 | engine NOMATCH | regex NOMATCH | 有填 agree 的列 |
| --- | --- | --- | --- | --- |
| out/bench_pipeline/bench_engine.csv | 200 | 200 | 0 | 0 |
| out/bench_pipeline_L12/bench_engine.csv | 200 | 200 | 0 | 0 |
| out/bench_pipeline_L12/bench_regex.csv | 200 | 0 | 200 | 0 |
| out/bench_pipeline_L128/bench_engine.csv | 200 | 200 | 0 | 0 |
| out/bench_pipeline_L128/bench_regex.csv | 200 | 0 | 200 | 0 |
| out/bench_pipeline_L16/bench_engine.csv | 200 | 200 | 0 | 0 |
| out/bench_pipeline_L16/bench_regex.csv | 200 | 0 | 200 | 0 |
| out/bench_pipeline_L20/bench_engine.csv | 200 | 200 | 0 | 0 |
| out/bench_pipeline_L20/bench_regex.csv | 200 | 0 | 200 | 0 |
| out/bench_pipeline_L24/bench_engine.csv | 200 | 200 | 0 | 0 |
| out/bench_pipeline_L24/bench_regex.csv | 200 | 0 | 200 | 0 |
| out/bench_pipeline_L28/bench_engine.csv | 200 | 200 | 0 | 0 |
| out/bench_pipeline_L28/bench_regex.csv | 200 | 0 | 200 | 0 |
| out/bench_pipeline_L32/bench_engine.csv | 200 | 200 | 0 | 0 |
| out/bench_pipeline_L32/bench_regex.csv | 200 | 0 | 200 | 0 |
| out/bench_pipeline_L48/bench_engine.csv | 200 | 200 | 0 | 0 |
| out/bench_pipeline_L48/bench_regex.csv | 200 | 0 | 200 | 0 |
| out/bench_pipeline_L64/bench_engine.csv | 200 | 200 | 0 | 0 |
| out/bench_pipeline_L64/bench_regex.csv | 200 | 0 | 200 | 0 |
| out/bench_pipeline_L8/bench_engine.csv | 200 | 200 | 0 | 0 |
| out/bench_pipeline_L8/bench_regex.csv | 200 | 0 | 200 | 0 |
| out/bench_single_thread/bench_engine.csv | 200 | 200 | 0 | 0 |
