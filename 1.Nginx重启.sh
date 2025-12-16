#!/bin/bash

# 检查 Nginx 进程是否正在运行
if pgrep -x "nginx" >/dev/null
then
    # 重新加载 Nginx 配置
    reload_result=$(sudo nginx -s reload 2>&1)
    if [ $? -eq 0 ]; then
        echo "Nginx 重新加载成功"
    else
        echo "Nginx 重新加载失败，错误信息: $reload_result"
    fi
    # 测试 Nginx 配置
    test_result=$(sudo nginx -t 2>&1)
    if [ $? -eq 0 ]; then
        echo "Nginx 配置测试成功"
    else
        echo "Nginx 配置测试失败，错误信息: $test_result"
    fi
else
    # 启动 Nginx 服务
    start_result=$(sudo service nginx start 2>&1)
    if [ $? -eq 0 ]; then
        echo "Nginx 启动成功"
    else
        echo "Nginx 启动失败，错误信息: $start_result"
    fi
    # 测试 Nginx 配置
    test_result=$(sudo nginx -t 2>&1)
    if [ $? -eq 0 ]; then
        echo "Nginx 配置测试成功"
    else
        echo "Nginx 配置测试失败，错误信息: $test_result"
    fi
fi