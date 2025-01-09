# leigod-auto-python
适用于青龙面板，本地运行
### 使用说明
## 本地运行
1. git clone https://github.com/cjw414522569/leigod-auto-python.git
2. 将 config.json 文件中的 USERNAME_ARR、PASSWORD_ARR 值修改为你自己的雷神账号、密码
3. 此脚本依赖的 Python 库为：requests
4. 运行python main.py

## 青龙面板运行
# 订阅管理
1. 订阅管理-创建订阅
2. 类型：公开仓库
3. 名称：雷神加速器
4. 链接：https://github.com/cjw414522569/leigod-auto-python.git
5. 定时类型：crontab
6. 定时规则（随便填即可，拉下来就可以关掉了）：0 7 * * *
7. 文件后缀：py json

# 定时任务
1.名称：main_load.py
2.命令/脚本：task cjw414522569_leigod-auto-python/main_load.py
3.定时规则（表示每天早上6点15分自动暂停雷神加速器的时长）：15 6 * * *


## References
- [himcs/LeishenAuto](https://github.com/himcs/LeishenAuto)
- [luanche/leigod-auto-pause](https://github.com/luanche/leigod-auto-pause)
