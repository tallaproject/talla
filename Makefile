REBAR   = rebar3
PROJECT = talla

all: compile

compile:
	@$(REBAR) compile

rel:
	@$(REBAR) release

clean:
	@$(REBAR) clean

dialyzer:
	@$(REBAR) dialyzer

check:
	@$(REBAR) do eunit -v, ct -v, proper -v

console: rel
	./_build/default/rel/$(PROJECT)/bin/$(PROJECT) console

shell:
	@$(REBAR) shell

.PHONY: compile rel clean dialyzer check console shell
