# Building presentation in watch mode

```bash
docker run --rm --init -v $PWD:/home/marp/app/ -e LANG=$LANG -e MARP_USER="$(id -u):$(id -g)" -p 37717:37717 marpteam/marp-cli -w slide-deck.md
```