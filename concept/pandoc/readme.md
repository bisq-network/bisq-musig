# Documentation & Github pages

The documentation and concept papers are written in Markdown with extension Katex for writing
LaTex formulas. To get the documentation moved to github pages, they are converted
using pandoc with github actions on every check-in.
To locally preview the html you can use these script in here.
However, you will need to install

```
**pandoc** -- converter from markdown to html 
**katex** -- extension for pandoc to use the LaTex dialect we are using here (MathJax won't do) 
**inotifywait** -- (optional) if you want to use the watch script to convert the markdown to html everytime you save the file.
``` 
## Scripts for local preview

To convert all md-files in directory concept into the output directory

```bash
pan.sh
```

To watch all md-files in the project and convert them whenever they
change on the filesystem.

```bash
watch.sh
```

Both scripts assume that you run them from the directory they are in (/concept/pandoc).

## Documentation on the web

After any commit on the branch 'main' the documentation will be converted automatically
and appears on the github pages at:

[Documentation on Github](https://bisq-network.github.io/bisq-musig/)

