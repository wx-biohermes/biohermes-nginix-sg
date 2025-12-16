#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nginx配置文件格式化工具
用于格式化/etc/nginx/运行站点目录中的所有配置文件
"""

import os
import re
import argparse

def format_nginx_config(config_content):
    """格式化Nginx配置文件内容"""
    # 去除多余的空白行
    lines = [line.strip() for line in config_content.splitlines() if line.strip()]
    
    # 修复server_name跨行吗的问题
    formatted_lines = []
    i = 0
    while i < len(lines):
        line = lines[i]
        # 查找server_name行后面可能紧跟着域名的行
        if line.startswith('server_name'):
            server_names = []
            # 提取当前行中的server_name部分和第一个域名
            if ' ' in line:
                parts = line.split(' ', 1)
                server_name_part = parts[0]
                first_name = parts[1].rstrip(';')
                server_names.append(first_name)
            else:
                server_name_part = line
            
            # 检查下一行是否不包含分号且不是注释
            while i + 1 < len(lines) and ';' not in lines[i + 1] and not lines[i + 1].strip().startswith('#'):
                i += 1
                server_names.append(lines[i].strip())
            
            # 构建正确的server_name行
            if server_names:
                server_name_line = f"{server_name_part} {' '.join(server_names)};"
            else:
                server_name_line = f"{server_name_part};"
            
            formatted_lines.append(server_name_line)
        else:
            formatted_lines.append(line)
        i += 1
    
    # 统一缩进
    indented_lines = []
    indent_level = 0
    indent_size = 4
    for line in formatted_lines:
        # 减少缩进级别（对于以}结尾的行）
        if line.startswith('}'):
            indent_level = max(0, indent_level - 1)
        
        # 添加缩进
        indented_line = ' ' * indent_size * indent_level + line
        indented_lines.append(indented_line)
        
        # 增加缩进级别（对于以{结尾的行）
        if line.endswith('{'):
            indent_level += 1
    
    # 修复注释中的明显错误
    final_lines = []
    for line in indented_lines:
        # 修复"允许来自指定域名的跨域请"为"允许来自指定域名的跨域请求"
        if "允许来自指定域名的跨域请" in line and not line.endswith("请求"):
            line = line.replace("允许来自指定域名的跨域请", "允许来自指定域名的跨域请求")
        final_lines.append(line)
    
    return '\n'.join(final_lines)

def main():
    parser = argparse.ArgumentParser(description='格式化Nginx配置文件')
    parser.add_argument('--dir', default='/etc/nginx/运行站点', help='要格式化的配置文件目录')
    parser.add_argument('--backup', action='store_true', help='备份原始文件')
    args = parser.parse_args()
    
    config_dir = args.dir
    
    if not os.path.isdir(config_dir):
        print(f"错误: 目录 {config_dir} 不存在")
        return
    
    # 获取所有.conf文件
    conf_files = [f for f in os.listdir(config_dir) if f.endswith('.conf')]
    
    if not conf_files:
        print(f"未在 {config_dir} 中找到.conf文件")
        return
    
    print(f"找到 {len(conf_files)} 个配置文件，开始格式化...")
    
    success_count = 0
    fail_count = 0
    
    for conf_file in conf_files:
        file_path = os.path.join(config_dir, conf_file)
        try:
            # 读取文件内容
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 备份原始文件
            if args.backup:
                # 确保备份目录存在
                backup_dir = '/etc/nginx/备份配置'
                os.makedirs(backup_dir, exist_ok=True)
                # 设置备份文件路径
                backup_path = os.path.join(backup_dir, f"{conf_file}.bak")
                with open(backup_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"已备份 {conf_file} 到 {os.path.basename(backup_dir)}/{os.path.basename(backup_path)}")
            
            # 格式化内容
            formatted_content = format_nginx_config(content)
            
            # 写回文件
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(formatted_content)
            
            success_count += 1
            print(f"成功格式化: {conf_file}")
            
        except Exception as e:
            fail_count += 1
            print(f"格式化 {conf_file} 失败: {str(e)}")
    
    print(f"\n格式化完成!")
    print(f"成功: {success_count}")
    print(f"失败: {fail_count}")

if __name__ == '__main__':
    main()