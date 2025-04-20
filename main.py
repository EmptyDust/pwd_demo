from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from routers.crypto import router

app = FastAPI()

# 包含路由
app.include_router(router)

# 读取 HTML 模板
with open("templates/index.html", "r", encoding="utf-8") as f:
    HTML_CONTENT = f.read()

@app.get("/", response_class=HTMLResponse)
async def get_home():
    return HTML_CONTENT