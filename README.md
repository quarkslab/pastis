# README

**TODO** Adapt to use `libpastis`.

Install:

```shell
python3 ./setup.py develop
```

Run example:

```shell
export HFUZZ_PATH=</path/to/honggfuzz>
export HFUZZ_WS=</path/to/workspace>
mkdir -p /tmp/seeds
echo A > /tmp/seeds/sample
./scripts/hfw-cli.py \
    --target ../programme_etalon_final/micro_http_server/micro_http_server_hf_fuzz_single_without_vuln \
    --target-arguments "wlp0s20f3 5c:80:b6:96:d7:3c 192.168.43.127 255.255.255.0 192.168.43.255" \
    --seeds-directory /tmp/seeds/
coverage_files:
    1b001e9b017ae30046ccc89bce145000.0000000e.honggfuzz.cov
    06ab8b1deed2109e1ba71581374bc81e.00000041.honggfuzz.cov
    fd30aa438f2c9db06d8cef437a00bd20.00000007.honggfuzz.cov
    d04c679a3a56a6107089e3651eb59158.000002c9.honggfuzz.cov
    3802c3fa0897bb76ad4d8f84106732f7.000007ef.honggfuzz.cov
    8830d65b59d5f421480c5ab395eff680.00001678.honggfuzz.cov
    857b5090f5baaa61e4f0631f56c6756b.00000058.honggfuzz.cov
    ba81f69ecc80fd2b28af98d55cfe19de.00001bff.honggfuzz.cov
    0965a5f000000000a505099000000000.00000003.honggfuzz.cov
    fd30aa438f00aa10ea005f437a00bd20.00000007.honggfuzz.cov
    10a8da2569b168321106b5a3bd0d42f0.0000007f.honggfuzz.cov
    f0dbf48fb84d0e4d857d0ed90eace37b.0000000e.honggfuzz.cov
    000000000004430055db000000000000.0000000e.honggfuzz.cov
    f05e1f51071f0bf1115297fdddf2b579.0000003f.honggfuzz.cov
    d5559e9b017ae30046ccc89b6600a800.0000000e.honggfuzz.cov
    ace2a913520d3145892f92b876adf102.0000000d.honggfuzz.cov
    fdc81f9661532b981cf99a40c5301420.0000001f.honggfuzz.cov
    6da3bb4c7797ca551e5294faf5c9b41e.00000010.honggfuzz.cov
    8f6514ab6a999838d72c187cfc6aac6d.00000016.honggfuzz.cov
    9051131983e2db3004353ec2ece141dc.0000003f.honggfuzz.cov
    35600000000000003560000000000000.00000001.honggfuzz.cov
    ba9917345b9b9cc9580dc74308a4008c.0000005d.honggfuzz.cov
    09c9c74e500074db5dce3b1f2cbbce05.000009dc.honggfuzz.cov
    b79d9ad773d971f4b7b0fa64b8c53757.00000012.honggfuzz.cov
    e45558953feaf646ec03337c7d7d3e43.0000000e.honggfuzz.cov
    94fd29f74e286139fe5fea0ee0ef0218.0000001c.honggfuzz.cov
    0f50d70ef5dbe91c7b1589b02d3e8e55.0000167b.honggfuzz.cov
    9f42e43a3ab7a52c0b661cc6dce5276f.0000000c.honggfuzz.cov
    ebfda219cacd2097aad16aef86983637.00000043.honggfuzz.cov
    a06df767699b56f70cb50230cf34e5bf.0000001a.honggfuzz.cov
    e52746b520992f24feb16fd62eec249a.0000000e.honggfuzz.cov
    94fd29f74e286b11fe5fea0ee0e52a18.0000001c.honggfuzz.cov
    d23cea16bbd7fe736523be510e61d56e.00000dff.honggfuzz.cov
    e3b1147d202c48092ed3a40152b9d33e.00001ce5.honggfuzz.cov
    ab5ecb72ecf213dcf243e5bd2a0dc2e6.00000e7a.honggfuzz.cov
    081e16fbb00fb84d857d0e1cceb2d754.00000010.honggfuzz.cov
    a5555501aca266258d4027e55555fd13.0000000e.honggfuzz.cov
    0e8db000000000006dbee00000000000.00000002.honggfuzz.cov
    980bb5262c616d52adb754a723b296e5.0000001e.honggfuzz.cov
    58765446cef28d6cfd6690268ccae3c9.0000000f.honggfuzz.cov
    6881a1035387c34a8a653fa0ef8ff2ff.0000130a.honggfuzz.cov
    72ef5e7f59ec5807db74fd99e740cc91.00000018.honggfuzz.cov
    017e28afc82b66258d49fe95f3d8b513.0000000e.honggfuzz.cov
    9ef2e43a3ab7a52c0b661cc799e5276f.0000000c.honggfuzz.cov
    e6ebdd86ca6ce73f25ba6c61cc4c78fa.0000001f.honggfuzz.cov
    8578fddd086fb981d6451c17f2aa245f.0000002d.honggfuzz.cov
    0a71b0fdfae7e39907d0e2a1de0834e4.0000001f.honggfuzz.cov
    de455b19a1af02fc788ff1a33252e752.0000003f.honggfuzz.cov
    54b73a6932d52b86c2ad572b6f3504b3.0000001c.honggfuzz.cov
    a555c303a5bc04551d8cefc555d55d55.0000001d.honggfuzz.cov
    5260a8e092b6e9e68d020a9116182058.0000000f.honggfuzz.cov
    3c9db000000000006d8cf00000000000.00000002.honggfuzz.cov
    51ba1b914c49c6e5d63e1e32d019fe5f.00000057.honggfuzz.cov
    9ace24c8e5c2a51543e1be86feff5ffe.0000000e.honggfuzz.cov
crash_files:
stats file:
    /tmp/fuzzing/1598642284/statsfile.log
```
