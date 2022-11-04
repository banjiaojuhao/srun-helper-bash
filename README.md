Bash version of [srun_helper](https://github.com/dejianwei/srun_helper)
###
下载srun-helper.sh文件使用。

环境依赖：bash curl

```bash
Usage: 
    Connect network:
        bash srun-helper.sh login --username '3321S150000' --password 'pwd_xxx'
    Disconnect network:
        bash srun-helper.sh logout
    Show this help message:
        bash srun-helper.sh help
    Show network state:
        bash srun-helper.sh
    Optional environments:
        SRUN_INTERFACE: Bind to the interface when send web requests.(default empty)
        SRUN_HOST: IP of authentication page. (default 10.248.98.2)
```
