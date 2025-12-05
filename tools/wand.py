import re
import subprocess
import sys

ALLOC = """
{typ} {name} = malloc({size});

if ({name} == NULL) {{
    perror("malloc failed");
    exit(EXIT_FAILURE);
}}
"""

N = """
{typ} {name} = {arg};
"""

IN = """
copy_data_between_cages(thiscage, {cage}, {arg}, {cage}, (uint64_t){name}, thiscage, {size}, {ctype});
"""

OUT = """
if({arg} != 0) {{
    copy_data_between_cages(
        thiscage,
        {cage},
        (uint64_t) {name},
        thiscage,
        {arg},
        {cage},
        {size},
        {ctype}
    );
}}
"""

FUNC = """
int {name}_grate(uint64_t cageid, uint64_t arg1, uint64_t arg1cage, uint64_t arg2, uint64_t arg2cage, uint64_t arg3, uint64_t arg3cage, uint64_t arg4, uint64_t arg4cage, uint64_t arg5, uint64_t arg5cage, uint64_t arg6, uint64_t arg6cage) {{
    if (!{name}_syscall) {{
        return -1;
    }}
    {pre}
    int ret = {name}_syscall({argnames});
    {post}
    {frees}
    return ret;
}}
"""


def clang_format(code: str, style: str = "file") -> str:
    result = subprocess.run(
        ["clang-format", f"--style={style}"],
        input=code.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return result.stdout.decode("utf-8")


with open("./tools/syscalls", "r") as f:
    syscall_defs = f.read()


syscalls = []


class Syscall:
    def __init__(self, name):
        self.name = name.strip()
        self.args = []
        self.pre = ""
        self.post = ""
        self.func = ""
        self. frees = ""

    def process(self):
        for i, arg in enumerate(self.args[::-1]):
            idx = len(self.args) - i
            if arg.mode == "N":
                self.pre += N.format(typ=arg.typ,
                                     name=arg.name, arg=f'arg{idx}')
            if arg.mode in ["IN", "OUT"]:
                self.pre += (ALLOC+IN).format(
                    typ=arg.typ, name=arg.name,
                    size=arg.size, ctype=arg.ctype,
                    arg=f'arg{idx}', cage=f'arg{idx}cage'
                )
                self.frees += f"free({arg.name});\n"

            if arg.mode == "OUT":
                self.post += OUT.format(
                    typ=arg.typ, name=arg.name,
                    size=arg.size, ctype=arg.ctype,
                    arg=f'arg{idx}', cage=f'arg{idx}cage'
                )

    def function(self):
        self.process()
        if len(self.args) == 0:
            argnames = "cageid"
        else:
            argnames = 'cageid, ' + ', '.join([i.name for i in self.args])
        return clang_format(
            FUNC.format(name=self.name, pre=self.pre,
                        post=self.post, argnames=argnames,
                        frees=self.frees)
        )

    def header(self):
        self.process()
        if len(self.args) != 0:
            argnames = 'int cageid, ' + \
                ', '.join([f'{i.typ} {i.name}' for i in self.args])
        else:
            argnames = 'int cageid'
        header = f'__attribute__((weak)) int {self.name}_syscall({argnames});'
        return header


class Args:
    def __init__(self, mode, typ, name):
        self.mode = mode
        self.typ = typ
        self.name = name

        match = re.match(r'\s*([A-Za-z_]\w*)(?:\s*\[\s*(.*?)\s*\])?\s*$', name)

        name, size = match.groups()
        self.name = name
        self.ctype = "0"
        if not size:
            if "char" in self.typ:
                self.size = "256"
            else:
                self.size = f"sizeof({self.typ.replace('*', '')})"
            if "char" in self.typ:
                self.ctype = "1"
        else:
            self.size = size

    def __str__(self):
        return f"{self.mode} {self.typ} {self.name} {self.size}"


curr = None
for line in syscall_defs.split("\n"):
    if "=" in line:
        curr = Syscall(line.split("=")[0])
        syscalls.append(curr)
        continue

    comp = line.strip().split("\t")
    if len(comp) < 3:
        continue
    mode, typ, name = comp

    curr.args.append(Args(mode, typ, name))

if __name__ == "__main__":
    header = sys.argv[1] == "0"

    for i in syscalls:
        if header:
            print(clang_format(i.header()))
        else:
            print(clang_format(i.function()))
