import os
import sys
import time
import zipfile

# 用法: python jarinject.py <jar> <classesdir> <rel1> <rel2> ...
# 把 classesdir 下缺失于 jar 的类追加进 jar（逐文件快速读取，避免 jar.exe 大读盘
# 触发外部干扰进程的独占扫描/删除）。
jar, cdir = sys.argv[1], sys.argv[2]
need = sys.argv[3:]
missing = [n for n in need if n not in zipfile.ZipFile(jar).namelist()]
added = 0
if missing:
    z = zipfile.ZipFile(jar, 'a', zipfile.ZIP_DEFLATED)
    for rel in missing:
        src = os.path.join(cdir, rel)
        ok = False
        for attempt in range(8):
            try:
                with open(src, 'rb') as f:
                    data = f.read()
                z.writestr(rel, data)
                ok = True
                break
            except (PermissionError, FileNotFoundError):
                time.sleep(0.25)
        if ok:
            added += 1
        else:
            print('INJECT_FAIL', rel)
    z.close()
print('missing=%d added=%d' % (len(missing), added))
sys.exit(0 if not missing else (0 if added == len(missing) else 1))
