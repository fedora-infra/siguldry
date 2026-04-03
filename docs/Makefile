# Build digrams and any other assets for the mdbook.

DOT_SRC  := diagrams
SVG_OUT  := src/diagrams

DOTS := $(wildcard $(DOT_SRC)/*.dot)
SVGS := $(patsubst $(DOT_SRC)/%.dot,$(SVG_OUT)/%.svg,$(DOTS))

.PHONY: all diagrams clean

all: diagrams

diagrams: $(SVGS)

$(SVG_OUT)/%.svg: $(DOT_SRC)/%.dot
	@mkdir -p $(SVG_OUT)
	dot -Tsvg $< -o $@

clean:
	rm -f $(SVG_OUT)/*.svg
