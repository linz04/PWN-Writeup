# quick maffs

1 + 1 = 2, e^2 that's 9? maybe? idk.

## hint

```js
function foo() {
  return Object.is(Math.exp(NaN), NaN);
}

console.log(foo());
for (let i = 0; i < 0x4000; i++) foo();
console.log(foo());
```

## build

v8 commit-hash `5fe0aa3bc79c0a9d3ad546b79211f07105f09585`

```sh
$ fetch v8 # https://chromium.googlesource.com/chromium/tools/depot_tools.git
$ cd v8
$ ./build/install-build-deps.sh
$ git checkout 5fe0aa3bc79c0a9d3ad546b79211f07105f09585
$ git apply path/to/maffs.patch # challange patch
$ git apply path/to/v8_global.patch # disable built-in d8 global
$ ./tools/dev/v8gen.py x64.release # x64.debug
$ ninja -C ./out.gn/x64.release # x64.debug
```
