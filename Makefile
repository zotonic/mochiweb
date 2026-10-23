
PREFIX:=../
DEST:=$(PREFIX)$(PROJECT)

REBAR        ?= ./rebar3
REBAR_URL    := https://github.com/erlang/rebar3/releases/download/3.21.0/rebar3

.PHONY: all deps

./rebar3:
	$(ERL) -noshell -s inets -s ssl \
	  -eval '{ok, saved_to_file} = httpc:request(get, {"$(REBAR_URL)", []}, [], [{stream, "./rebar3"}])' \
	  -s init stop
	chmod +x ./rebar3

all: $(REBAR)
	@$(REBAR) get-deps
	@$(REBAR) compile

edoc: $(REBAR)
	@$(REBAR) doc

test: $(REBAR)
	@$(REBAR) eunit

clean: $(REBAR)
	@$(REBAR) clean

build_plt: $(REBAR)
	@$(REBAR) build-plt

dialyzer:
	@$(REBAR) dialyze

app: $(REBAR)
	@$(REBAR) create template=mochiwebapp dest=$(DEST) appid=$(PROJECT)

