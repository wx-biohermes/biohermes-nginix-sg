# Nginx和PHP安全防护配置指南

本指南提供全面的Nginx和PHP安全防护配置，重点防止路径遍历攻击以及其他常见的Web安全威胁。

## 系统环境信息
- Ubuntu 24.04.3 LTS
- Nginx 1.24.0
- PHP 8.1.33
- PHP-FPM 8.1

## 一、Nginx安全配置

### 1. 创建统一安全配置文件

首先，创建一个专用的安全配置目录和文件：

```bash
mkdir -p /etc/nginx/security
touch /etc/nginx/security/security.conf
```

编辑`/etc/nginx/security/security.conf`文件，添加以下内容：

```nginx
# 全面的Nginx安全配置

# 1. 基本安全头部设置
# 防止XSS攻击
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-XSS-Protection "1; mode=block" always;

# 内容安全策略(CSP) - 根据实际需求调整
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-src 'self'; object-src 'none'" always;

# 2. 文件访问限制

# 禁止访问隐藏文件
location ~ /\. {
    deny all;
    access_log off;
    log_not_found off;
}

# 防止路径遍历攻击
# 检查请求中是否包含../ 或 ..\\ 等路径遍历字符
if ($request_uri ~* "(\.\./|\.\.\\)") {
    return 403;
}

# 限制访问敏感文件和目录
location ~* \.(php|inc|conf|log|sql)$ {
    try_files $uri =404;
}

# 3. 请求限制

# 限制请求方法
if ($request_method !~ ^(GET|POST|HEAD|OPTIONS)$) {
    return 444;
}

# 限制URI长度
if ($request_uri ~ "^[^?]{1000}") {
    return 414;
}

# 4. 文件类型安全

# 禁止PHP文件执行在某些目录
location ~* /(uploads|images|cache|tmp|logs)/.*\.php$ {
    deny all;
}

# 5. 额外的安全措施

# 禁用服务器标识
server_tokens off;

# 隐藏PHP版本信息
fastcgi_hide_header X-Powered-By;

# 限制客户端请求体大小
client_max_body_size 50M;

# 6. 缓冲区安全设置
client_body_buffer_size 16K;
client_header_buffer_size 1k;
large_client_header_buffers 4 8k;
```

### 2. 在Nginx主配置中包含安全配置

编辑`/etc/nginx/nginx.conf`文件，在http块中添加以下行来包含安全配置：

```nginx
include /etc/nginx/security/security.conf;
```

### 3. 增强PHP配置安全性

编辑`/etc/nginx/snippets/php-common.conf`文件，取消注释以下安全相关设置：

```nginx
# 安全增强：禁用FastCGI的PATH_INFO处理（防止某些PHP框架的安全问题）
fastcgi_hide_header X-Powered-By;

# 安全增强：设置FastCGI响应头缓存控制
# 防止敏感信息被缓存
add_header Cache-Control "no-cache, no-store, must-revalidate" always;
add_header Pragma "no-cache" always;
add_header Expires "0" always;
```

### 4. 为所有站点添加安全配置

确保每个站点配置文件都包含安全配置。编辑所有的.conf文件在`/etc/nginx/sites-enabled/`目录下，添加以下行：

```nginx
include /etc/nginx/security/security.conf;
```

## 二、PHP安全配置

### 1. 编辑php.ini文件

编辑`/etc/php/8.1/fpm/php.ini`文件，修改以下设置：

```ini
# 隐藏PHP版本信息
expose_php = Off

# 限制PHP脚本执行时间
max_execution_time = 30

# 限制PHP脚本内存使用
memory_limit = 128M

# 禁用危险函数
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source

# 防止文件路径遍历
open_basedir = "/var/www:/tmp"

# 启用PHP安全模式（如果可用）
# safe_mode = On

# 设置错误报告级别
error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT

# 不在浏览器中显示错误
display_errors = Off

# 记录错误日志
display_startup_errors = Off
log_errors = On
error_log = /var/log/php8.1-errors.log
```

### 2. 编辑PHP-FPM配置

编辑`/etc/php/8.1/fpm/pool.d/www.conf`文件，修改以下设置：

```ini
# 设置PHP-FPM进程的用户和组
user = www-data
group = www-data

# 限制PHP-FPM进程数量
pm = dynamic
pm.max_children = 50
pm.start_servers = 5
pm.min_spare_servers = 5
pm.max_spare_servers = 35

# 设置request_terminate_timeout
; http://php.net/request-terminate-timeout
request_terminate_timeout = 30s

# 启用慢日志
slowlog = /var/log/php8.1-fpm-slow.log
request_slowlog_timeout = 10s
```

## 三、路径遍历攻击防护强化

除了上面的基本安全配置外，特别针对路径遍历攻击，添加以下额外防护措施：

### 1. 创建专门的路径遍历防护配置

创建`/etc/nginx/security/anti_traversal.conf`文件：

```nginx
# 路径遍历攻击防护配置

# 检查URL中是否包含路径遍历字符
if ($request_uri ~* "(\.\./|\.\.\\|%2e%2e/|%2e%2e%5c|%252e%252e/|%252e%252e%5c)") {
    return 403;
}

# 检查请求参数中是否包含路径遍历字符
if ($args ~* "(\.\./|\.\.\\|%2e%2e/|%2e%2e%5c|%252e%252e/|%252e%252e%5c)") {
    return 403;
}

# 确保请求的文件路径在文档根目录内
location ~* \.php$ {
    try_files $uri =404;
    # 额外的路径验证
    set $valid_path 0;
    if ($document_root$fastcgi_script_name ~ ^$document_root) {
        set $valid_path 1;
    }
    if ($valid_path = 0) {
        return 403;
    }
    # 原有PHP配置
    fastcgi_pass unix:/run/php/php8.1-fpm.sock;
    fastcgi_index index.php;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    include fastcgi_params;
}
```

### 2. 在所有站点配置中包含路径遍历防护

在每个站点配置文件中添加：

```nginx
include /etc/nginx/security/anti_traversal.conf;
```

## 四、文件权限设置

确保Web文件和目录具有正确的权限：

```bash
# 设置Web根目录权限
chown -R www-data:www-data /var/www
chmod -R 755 /var/www
find /var/www -type f -exec chmod 644 {} \;

# 保护配置文件
chmod 600 /etc/nginx/nginx.conf
chmod 600 /etc/php/8.1/fpm/php.ini
find /etc/nginx/sites-enabled -type f -exec chmod 644 {} \;
```

## 五、安装和配置ModSecurity (可选但推荐)

ModSecurity是一个开源的Web应用防火墙，可以提供更高级的安全保护：

```bash
# 安装ModSecurity
apt update
apt install libmodsecurity3t64 libmodsecurity-dev libnginx-mod-http-modsecurity -y

# 下载OWASP核心规则集
git clone https://github.com/coreruleset/coreruleset.git /etc/nginx/modsecurity/coreruleset
cp /etc/nginx/modsecurity/coreruleset/crs-setup.conf.example /etc/nginx/modsecurity/coreruleset/crs-setup.conf

# 创建ModSecurity配置文件
touch /etc/nginx/modsecurity/modsecurity.conf
cat > /etc/nginx/modsecurity/modsecurity.conf << EOF
# 启用ModSecurity规则引擎（On：完全启用，DetectionOnly：仅检测不拦截）
SecRuleEngine On

# 允许ModSecurity访问请求体
SecRequestBodyAccess On

# 设置请求体的最大大小（字节）- 这里设置为128MB
SecRuleRequestBodyLimit 134217728

# 设置不包含文件的请求体最大大小（字节）- 这里设置为128KB
SecRuleRequestBodyNoFilesLimit 131072

# PCRE正则表达式匹配限制（防止正则表达式DoS攻击）
SecPcreMatchLimit 1000

# PCRE正则表达式递归匹配限制
SecPcreMatchLimitRecursion 1000

# 事务变量收集点的最大数量
SecRuleTXMaxCollectionPoints 100

# 调试日志文件路径
SecDebugLog /var/log/modsecurity/debug.log

# 调试日志级别（0=关闭，9=最详细）
SecDebugLogLevel 0

# 审计引擎模式（RelevantOnly：仅记录相关事件，On：记录所有，Off：关闭）
SecAuditEngine RelevantOnly

# 审计日志包含的部分（各字母代表不同部分，如A=请求头，B=请求体等）
SecAuditLogParts ABCEFHJKZ

# 审计日志文件路径
SecAuditLog /var/log/modsecurity/audit.log

# 审计日志存储目录
SecAuditLogStorageDir /var/log/modsecurity/audit

# 包含核心规则集的配置文件
Include /etc/nginx/modsecurity/coreruleset/crs-setup.conf

# 包含所有核心规则文件
Include /etc/nginx/modsecurity/coreruleset/rules/*.conf

EOF

# 创建日志目录
mkdir -p /var/log/modsecurity/audit
chown -R www-data:www-data /var/log/modsecurity

# 在Nginx配置中启用ModSecurity
# 在nginx.conf的http块中添加：
# load_module modules/ngx_http_modsecurity_module.so;
# modsecurity on;
# modsecurity_rules_file /etc/nginx/modsecurity/modsecurity.conf;
```

## 六、配置完成后的验证步骤

配置完成后，执行以下命令验证和应用更改：

```bash
# 测试Nginx配置是否正确
nginx -t

# 重启Nginx和PHP-FPM服务
systemctl restart nginx
systemctl restart php8.1-fpm

# 检查服务状态
systemctl status nginx
systemctl status php8.1-fpm
```

## 七、监控和维护

1. 定期检查Nginx和PHP错误日志：
   ```bash
   tail -f /var/log/nginx/error.log
   tail -f /var/log/php8.1-fpm.log
   ```

2. 设置日志轮转，确保日志不会占用过多磁盘空间

3. 定期更新系统和软件包：
   ```bash
   apt update && apt upgrade -y
   ```

4. 考虑安装安全监控工具，如Fail2ban，进一步增强服务器安全性

通过实施以上安全配置，可以有效防止路径遍历攻击和其他常见的Web安全威胁，保护您的所有站点安全。