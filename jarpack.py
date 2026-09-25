import glob
import os
import subprocess
import sys
import tempfile
import time
import zipfile

# 用法:
#   python jarpack.py <out.jar> <manifest> <classesdir> <libsdir> <rel...>
#   [--core-src <src> --core-deps <cp>]   # 打包前现场编译 kbox-core（关键类读取窗口压到毫秒级）
USAGE = True
args = sys.argv[1:]
core_src = None
core_deps = None
if '--core-src' in args:
    i = args.index('--core-src')
    core_src = args[i + 1]
    core_deps = args[i + 3]
    args = args[:i]

jar, mf, cdir, ldir = args[0:4]
need = args[4:]
tmp = jar + '.tmp'
if os.path.exists(tmp):
    os.remove(tmp)

core_dir = cdir
if core_src:
    core_dir = os.path.join(tempfile.gettempdir(),
                            'kbcore_' + __import__('uuid').uuid4().hex[:8])
    os.makedirs(core_dir)
    files = glob.glob(os.path.join(core_src, '**', '*.java'), recursive=True)
    r = subprocess.run(['javac', '-encoding', 'UTF-8', '--release', '8', '-nowarn',
                        '-d', core_dir, '-cp', core_deps] + files,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if r.returncode != 0:
        print('core compile failed rc=%d' % r.returncode)
        sys.exit(1)

z = zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED)
with open(mf, 'rb') as f:
    z.writestr('META-INF/MANIFEST.MF', f.read())
skipped = []
critical = {}


def read_retry(full, tries=10, step=0.02):
    for attempt in range(tries):
        try:
            with open(full, 'rb') as f:
                return f.read()
        except (PermissionError, FileNotFoundError):
            time.sleep(step)
    return None


# 1) 关键类最先读（毫秒级窗口）
for rel in need:
    full = os.path.join(core_dir, rel.replace('/', os.sep))
    if os.path.exists(full):
        data = read_retry(full)
        if data is not None:
            critical[rel] = data
        else:
            skipped.append(rel)


def add_dir(base):
    for root, dirs, files in os.walk(base):
        for name in files:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, base).replace('\\', '/')
            if rel in critical or rel in z.namelist():
                continue
            data = read_retry(full, tries=3)
            if data is None:
                skipped.append(rel)
                continue
            try:
                z.writestr(rel, data)
            except PermissionError:
                skipped.append(rel)


for rel, data in critical.items():
    z.writestr(rel, data)
add_dir(cdir)   # gui/cli/其他（跳过已写入的关键类）
add_dir(ldir)
z.close()
os.replace(tmp, jar)
names = set(zipfile.ZipFile(jar).namelist())
missing = [n for n in need if n.replace('\\', '/') not in names]
print('packed ok; missing=%s skipped=%d' % (missing, len(skipped)))
sys.exit(1 if missing else 0)
