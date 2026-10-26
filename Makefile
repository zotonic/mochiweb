PREFIX := ../
DEST   := $(PREFIX)$(PROJECT)

ERL         ?= erl

REBAR := ./rebar3
REBAR_URL := https://github.com/erlang/rebar3/releases/download/3.27.3/rebar3
REBAR_SHA256 := f1d87d78decfc56b87d971c75ee6355698ec0c49fadd57f2c056043b7ca291b5
REBAR_STAMP := ./.rebar3-$(REBAR_SHA256)

.PHONY: all edoc test clean dialyzer app

all: $(REBAR)
	@$(REBAR) compile

$(REBAR_STAMP):
	rm -f ./.rebar-*
	touch $@
	rm -f $(REBAR)

$(REBAR): $(REBAR_STAMP)
	./tools/download.escript "$(REBAR_URL)" "$(REBAR)" --sha256 "$(REBAR_SHA256)" --executable

edoc: $(REBAR)
	@$(REBAR) edoc

test: $(REBAR)
	@$(REBAR) eunit

clean: $(REBAR)
	@$(REBAR) clean

dialyzer: $(REBAR)
	@$(REBAR) dialyzer

app: $(REBAR)
	@cd $(PREFIX) && $(abspath $(REBAR)) new mochiwebapp $(PROJECT)
