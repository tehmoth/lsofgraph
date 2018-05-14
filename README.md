Perl version of [zevv/lsofgraph](https://github.com/zevv/lsofgraph)

A small utility to convert Unix `lsof` output to a graph showing FIFO and UNIX interprocess communication.

Generate graph:

````shell
sudo lsof -n -F | perl ./lsofgraph.pl | dot -Tjpg > /tmp/a.jpg
````

or add `unflatten` to the chain for a better layout:

````shell
sudo lsof -n -F | perl ./lsofgraph.pl | unflatten -l 1 -c 6 | dot -T jpg > /tmp/a.jpg
````

![example output](/example.jpg)



