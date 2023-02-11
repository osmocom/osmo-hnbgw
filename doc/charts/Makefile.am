msc: \
	$(builddir)/hnbgw_context_map.png \
	$(NULL)

dot: \
	$(builddir)/hnbgw_context_map_fsm.png \
	$(NULL)

$(builddir)/%.png: $(srcdir)/%.msc
	mscgen -T png -o $@ $<

$(builddir)/%.png: $(srcdir)/%.dot
	dot -Tpng $< > $@

.PHONY: poll
# remember current dir: in case the build process removes and recreates the dir, re-enter the new dir
W := "$(PWD)"
poll:
	while true; do $(MAKE) -C $W msc dot; sleep 1; done
