# Upgrade Reverse Shell

> Reference
>
> - <https://www.youtube.com/watch?v=DqE6DxqJg8Q&ab_channel=0xdf>

```bash
nc -lnvp 443
# waiting for the connection

script /dev/null -c bash
# hit ^Z
stty raw -echo; fg
reset
# type in "screen"
```
