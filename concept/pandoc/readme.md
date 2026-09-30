# Documentation & Github pages

The documentation and concept papers are written in Markdown with extension KaTeX for writing
LaTeX formulas. To get the documentation onto github pages, they are converted
using pandoc with github actions on every check-in to `main`.
To locally preview the html you can use the scripts in here.
However, you will need to install

```
**pandoc** -- converter from markdown to html 
**katex** -- extension for pandoc to use the LaTeX dialect we are using here (MathJax won't do) 
**inotifywait** -- (optional) if you want to use the watch script to convert the markdown to html every time you save the file.
``` 

`pandoc.sh` passes a hard-coded KaTeX path to pandoc (`--katex=...`); adjust it to where
KaTeX's `dist/` directory lives on your machine (e.g. `$(npm root -g)/katex/dist/`).

## Scripts for local preview

To convert all md-files in directory `concept` into the `output` directory

```bash
./pan.sh
```

To watch all md-files in directory `concept` and convert them into the `output` directory
whenever they change on the filesystem.

```bash
./watch.sh
```

To convert a single file:

```bash
./pandoc.sh <input.md> <output.html>
```

All scripts assume that you run them from the directory they are in (`/concept/pandoc`).

## Documentation on the web

After any commit on the branch 'main' the documentation will be converted automatically
and appears on the github pages at:

[Documentation on Github](https://bisq-network.github.io/bisq-musig/)
