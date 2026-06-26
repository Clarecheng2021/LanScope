# LanScope 上传 GitHub 步骤

本文档用于把当前项目上传到 GitHub。以下命令均在项目根目录执行：

```powershell
cd E:\projects\LanScope
```

## 1. 初始化本地 Git 仓库

如果当前目录还不是 Git 仓库，执行：

```powershell
git init -b main
```

## 2. 检查将要提交的文件

```powershell
git status
```

正常情况下应包含以下主要内容：

```text
lanscope/
tests/
.gitignore
LICENSE
pyproject.toml
README.md
使用说明.md
GitHub上传说明.md
```

`.claude/`、`.pytest_cache/`、`__pycache__/`、`*.pyc` 等本地缓存文件不应出现在提交列表中。

## 3. 创建第一次提交

```powershell
git add .
git commit -m "Initial commit"
```

## 4. 在 GitHub 创建空仓库

进入 GitHub 后点击右上角 `+`，选择 `New repository`。

推荐设置：

- Repository name：`LanScope`
- Visibility：按需要选择 `Public` 或 `Private`
- 不勾选 `Add a README file`
- 不勾选 `.gitignore`
- 不勾选 license

创建完成后，复制 GitHub 给出的仓库地址，例如：

```text
https://github.com/你的用户名/LanScope.git
```

## 5. 绑定远程仓库

把下面命令中的地址替换为自己的仓库地址：

```powershell
git remote add origin https://github.com/你的用户名/LanScope.git
```

如果已经添加过远程仓库但地址写错了，可以改用：

```powershell
git remote set-url origin https://github.com/你的用户名/LanScope.git
```

## 6. 上传到 GitHub

```powershell
git push -u origin main
```

第一次上传时 Git 可能会弹出 GitHub 登录窗口，按提示登录并授权即可。

## 7. 后续更新项目

以后每次修改代码后，执行：

```powershell
git status
git add .
git commit -m "Update project"
git push
```

## 8. 建议上传前检查

上传前可以运行测试：

```powershell
python -m pytest
```

也可以检查命令行程序是否能启动：

```powershell
python -m lanscope --help
python -m lanscope.web --help
```
