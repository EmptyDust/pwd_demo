# 加密解密工具 (PWD Demo)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115.0-009688.svg)

一个用于加密、解密和哈希计算的Web应用程序，同时展示了标准库实现和自定义实现的对比。本项目是信息安全概论课程的实践作业。

![应用预览](https://via.placeholder.com/800x400?text=加密解密工具预览)

## ✨ 功能特点

- **DES加密/解密**
  - 标准库实现
  - 自定义实现（从零构建DES算法）

- **RSA加密/解密**
  - 标准库实现
  - 自定义实现（包含密钥生成）

- **SHA1哈希**
  - 标准库实现
  - 自定义实现（展示SHA1的内部工作原理）

- **直观的Web界面**
  - 响应式设计，适配各种设备
  - 使用Tailwind CSS美化界面

## 🚀 快速开始

### 前置要求

- Python 3.8+
- pip（Python包管理器）

### 安装步骤

1. 克隆仓库
   ```bash
   git clone https://github.com/EmptyDust/pwd_demo.git
   cd pwd_demo
   ```

2. 安装依赖
   ```bash
   pip install -r requirements.txt
   ```

3. 启动服务器
   ```bash
   uvicorn main:app --reload
   ```

4. 打开浏览器访问
   ```
   http://localhost:8000
   ```

## 🔧 项目结构

```
pwd_demo/
├── main.py          # FastAPI应用的入口点
├── requirements.txt # 项目依赖列表
├── routers/         # 路由
├── templates/       # HTML模板文件
├── crypto/          
│   ├── des.py       # 标准库实现
│   ├── custom_des.py# 自定义实现
│   ├── rsa.py       # 标准库实现
│   ├── custom_rsa.py# 自定义实现
│   ├── sha1.py      # 标准库实现
│   ├── custom_sha1.py# 自定义实现
└── README.md        # 项目说明文件
```

## 📄 许可证

本项目使用MIT许可证，详情请参阅[LICENSE](LICENSE)文件。

## 📧 联系方式

如果有任何问题或建议，请通过以下方式联系我：

- 邮箱: fenglingyexing@gmail.com
- GitHub: [EmptyDust](https://github.com/EmptyDust)
