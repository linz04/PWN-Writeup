# Pwn sanity check

Basic Bufferoverflow in the vuln() function

```c
int vuln()
{
  char s[60]; // [rsp+0h] [rbp-40h] BYREF
  int v2; // [rsp+3Ch] [rbp-4h]

  puts("tell me a joke");
  fgets(s, 256, stdin);
  if ( v2 != 0xDEADC0DE )
    return puts("will this work?");
  puts("very good, here is a shell for you. ");
  return shell();
}
```
