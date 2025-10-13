#!/bin/bash

# 默认分支名称
default_branch="main"

# 获取当前日期和时间
TIME=$(date +"%H:%M:%S")
DATE=$(date +"%Y-%m-%d")

#### 函数定义部分 ####
# 函数：检查并确保分支存在，如果不存在则创建
function ensure_branch() {
    local branch_name=$1
    # 检查本地分支是否存在
    if ! git rev-parse --verify "$branch_name" >/dev/null 2>&1; then
        echo "分支 $branch_name 不存在，正在创建并切换到它"
        # 创建并切换到新分支
        git checkout -b "$branch_name"
    else
        # 如果分支存在，直接切换到它
        git checkout "$branch_name"
    fi
}
# 函数：检查并且汉化分支状态信息
function check_and_translate_git_status() {
    local git_output=$1

    # 获取当前分支名
    local branch_name=$(git rev-parse --abbrev-ref HEAD)

    if [[ "$git_output" =~ "Already up to date." ]] && ! [[ "$git_output" =~ "Saved working directory and index state" ]]; then
        echo "分支 【$branch_name】 已是最新，无需更新。$(date +'%Y-%m-%d %H:%M:%S') "
        return # 避免更多输出
    fi
}

# 函数：尝试从默认分支拉取，并处理未提交更改
function pull_from_default_branch() {
	local default_branch=$1

    ensure_branch "$default_branch"

    # 使用 "ours" 策略选项优先采用本地分支上的更改
    git_pull_output=$(git pull -Xours origin "$default_branch" 2>&1)
    if [ $? -ne 0 ]; then
        echo "合并时遇到冲突，本地更改被优先使用"
    fi
    
	# 检查是否存在被删除的文件
	if git ls-files --deleted | grep -q .; then
		# 提交本地删除的文件仅当它们存在时
		git ls-files --deleted -z | xargs -0 git rm --cached
		git commit -m "删除本地已删除的文件" --allow-empty
	fi

	# 尝试应用之前暂存的变更
	if git stash list | grep -q "On branch $default_branch"; then
		git stash pop
	fi
}

# 函数：检查是否处于游离状态并解决
function resolve_detached_head() {
    if ! git symbolic-ref --quiet HEAD > /dev/null 2>&1; then
        echo "检测到 HEAD 处于游离状态。"
        # 尝试获取最接近的分支名称
        local branch_name="$(git describe --tags --exact-match HEAD 2>/dev/null)"
        
        if [ -z "$branch_name" ]; then
            echo "游离状态未指向任何标签，尝试获取最近的分支名称..."
            branch_name="$(git rev-parse --abbrev-ref HEAD)"
            if [ "$branch_name" = "HEAD" ]; then
                branch_name="$(git name-rev --name-only HEAD)"
                branch_name=${branch_name#remotes/origin/}  # 移除可能的远程前缀
                branch_name=${branch_name%%/*}  # 移除可能的提交路径
            fi
        fi
        
        if [ -n "$branch_name" ] && git show-ref --verify --quiet "refs/heads/$branch_name"; then
            echo "尝试切换到最接近的分支：$branch_name $(date +'%Y-%m-%d %H:%M:%S')"
            git checkout "$branch_name"
        else
            echo "无法确定接近的分支，将切换到默认分支：$default_branch $(date +'%Y-%m-%d %H:%M:%S')"
            git checkout "$default_branch"
        fi
    else
        echo "HEAD 处于正常状态，指向一个分支。"
    fi
}

#### 主要执行流程 ####

# 检查是否在一个 Git 仓库内
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "错误：当前目录不是一个Git仓库。"
    exit 1
fi

# 检查 Git 仓库是否有提交
if ! git rev-parse HEAD >/dev/null 2>&1; then
    echo "当前 Git 仓库中没有发现任何提交。"
    # 创建一个空的初始化提交
    git commit --allow-empty -m "初始化仓库"
else
    echo "已找到当前仓库的 HEAD 引用。"
    # 你可以在这里执行依赖于 HEAD 的其他 Git 命令
fi

# 获取脚本所在的目录作为主仓库路径
main_repository=$(cd "$(dirname "$0")" && pwd)
echo "主仓库目录:【$main_repository】"

# 切换到主仓库目录
cd "$main_repository" || {
    echo "不能切换到主仓库目录【$main_repository】"
    exit 1
}

# 在任何可能更改 HEAD 的 Git 命令前后进行检查
resolve_detached_head

# 从默认分支拉取最新信息，并处理潜在合并冲突
pull_from_default_branch "$default_branch"

resolve_detached_head

#### 处理子模块和远程推送 ####
# 检查是否存在 .gitmodules 文件来判断是否有子模块
if [ -f ".gitmodules" ]; then
    # 检测缺失的子模块并清理
    echo "========== 检查子模块配置 开始 $(date +'%Y-%m-%d %H:%M:%S') =========="

    # 尝试初始化和更新子模块
    git submodule update --init --recursive --progress 2>&1
    echo "========== 初始化子模块并克隆 开始 $(date +'%Y-%m-%d %H:%M:%S') =========="
    git submodule update --init --recursive --depth=1 --progress
    echo "========== 初始化子模块并克隆 完毕 $(date +'%Y-%m-%d %H:%M:%S') =========="

    # 遍历所有子模块，对每个子模块应用变更并推送
    echo "========== 更新所有子模块 开始 $(date +'%Y-%m-%d %H:%M:%S') =========="
    git submodule foreach --recursive '
        echo "正在处理子模块:【$name】"
        # 对于修改、删除、未跟踪的文件，进行 Add/Commit/Push
        # 如果有变更，提交并推送到各自的远程 master 分支
        # 拉取子模块的最新更新
        git pull --progress origin master
        # 更改当前子模块内所有文件和目录的所有者为www
        # sudo chown -R www:www .
        echo "完成处理子模块:【$name】"
        echo "=============" # 单个子模块处理结束
    '
    echo "========== 更新所有子模块 完毕 $(date +'%Y-%m-%d %H:%M:%S') =========="
fi
# 以上是子模块更新的全部代码，确保这篇代码在此处保持不变

# 添加所有改变的文件
git add --all

# 如果有要提交的变更，进行提交
if [[ $(git diff --cached --numstat | wc -l) -gt 0 ]]; then
    git commit -m "增删改 $(date +'%Y-%m-%d %H:%M:%S')"
fi

# 在试图推送之前检查是否处于游离状态
resolve_detached_head

# 推送代码到远程仓库
git push origin "$default_branch"
