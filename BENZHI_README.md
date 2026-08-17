# task044-piimask

这是一个纯 Go 的敏感信息脱敏服务。它接收自由文本，识别并校验邮箱、手机号、身份证号和银行卡号，按优先级处理重叠命中后返回脱敏文本及原文中的字节偏移。项目不依赖数据库、网络服务或第三方包。

## 标准命令

以下命令均在 `env/` 目录执行：

```bash
go build ./...
go test ./...
go vet ./...
go run . --smoke-test
```

`--smoke-test` 会启动进程内 HTTP 服务并执行健康检查、各类脱敏、校验失败、重叠优先级、字节偏移和请求校验场景，完成后自行退出。

## Benzhi 容器

`build_benzhi_docker.sh` 使用固定的 `benzhi.Dockerfile` 构建评测镜像，参数依次是镜像名和平台，默认值为 `my-project` 与 `linux/amd64`：

```bash
bash build_benzhi_docker.sh piimask-benzhi linux/amd64
docker run --rm -it piimask-benzhi:latest
```

容器启动后进入 shell；构建阶段执行 `go build ./...`，不依赖外部业务服务。
