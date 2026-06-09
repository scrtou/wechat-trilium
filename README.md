# WeChat to TriliumNext Bridge

把微信公众号收到的消息保存到 TriliumNext。支持：

- 文本消息保存
- 图片消息保存
- 语音消息保存为附件
- 按日期归档
- 只处理指定 OpenID
- 明文模式 / AES 加密模式
- systemd 后台运行

## 1. 在新服务器部署

```bash
git clone <你的仓库地址> wechat-trilium
cd wechat-trilium
cp .env.example .env
nano .env
./install.sh --use-existing-env
```

`--use-existing-env` 表示：使用你已经写好的 `.env`，脚本不会交互询问，也不会覆盖 `.env`。

## 2. 必填 `.env` 配置

```env
# 公众号后台服务器配置里填写的 Token，不是 AppSecret
WECHAT_TOKEN=your-random-token

# 公众号 AppID/AppSecret。保存语音和临时素材需要 AppSecret。
WECHAT_APP_ID=wx...
WECHAT_APP_SECRET=...

# 如果公众号后台选择明文模式，这里可留空。
# 如果选择兼容模式/安全模式，填公众号后台 43 位 EncodingAESKey。
WECHAT_AES_KEY=

# TriliumNext
TRILIUM_BASE_URL=https://your-trilium.example.com
TRILIUM_ETAPI_TOKEN=...
TRILIUM_PARENT_NOTE_ID=...

# 监听配置：
# 使用 Nginx/隧道反代时推荐 127.0.0.1
# 直接公网访问 8000 端口时用 0.0.0.0
BIND_HOST=127.0.0.1
PORT=8000

# 只处理指定 OpenID；多个用英文逗号分隔
OWNER_OPENIDS=openid1,openid2
PROCESS_OWNER_ONLY=true

# 是否给自己回复“已保存”
REPLY_TO_OWNER=false

ARCHIVE_TIMEZONE=Asia/Shanghai
```

## 3. 公众号后台配置

服务器 URL 填你的公网地址，例如：

```text
http://your-domain.com/wechat
```

或 HTTPS：

```text
https://your-domain.com/wechat
```

Token 必须和 `.env` 中一致：

```env
WECHAT_TOKEN=...
```

消息加解密方式：

- 明文模式：`WECHAT_AES_KEY` 可留空
- 兼容模式/安全模式：必须填写 `WECHAT_AES_KEY`

## 4. 后台服务命令

查看状态：

```bash
sudo systemctl status wechat-trilium --no-pager
```

查看日志：

```bash
sudo journalctl -u wechat-trilium -f
```

重启：

```bash
sudo systemctl restart wechat-trilium
```

停止：

```bash
sudo systemctl stop wechat-trilium
```

## 5. 更新代码

```bash
cd wechat-trilium
git pull
./install.sh --use-existing-env
```

或只重启：

```bash
sudo systemctl restart wechat-trilium
```

## 6. 图片/语音保存失败：IP 白名单

如果日志出现：

```text
errcode: 40164 invalid ip ... not in whitelist
```

需要把服务器出口 IP 添加到公众号后台 IP 白名单。查看出口 IP：

```bash
curl -4 ifconfig.me
```

然后到公众号后台「基本配置 / IP白名单」添加该 IP。

## 7. 安全注意

不要提交 `.env` 到 Git。仓库里的 `.gitignore` 已经忽略 `.env`、`.venv` 等本地文件。

## 8. systemd 日志里看不到 GET/POST 请求

手动运行 `python app.py` 使用 Flask 开发服务器，会默认打印访问日志。systemd 服务使用 gunicorn，必须开启 access log 才会在 journal 里看到 GET/POST。

当前 `install.sh` 已默认加入：

```text
--access-logfile - --error-logfile - --capture-output --log-level info
```

更新后执行：

```bash
git pull
./install.sh --use-existing-env
sudo journalctl -u wechat-trilium -f
```
