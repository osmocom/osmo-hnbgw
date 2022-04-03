msc: \
	$(builddir)/conn_map_ps.png \
	$(NULL)

dot: \
	$(NULL)

$(builddir)/%.png: $(srcdir)/%.msc
	mscgen -T png -o $@ $<

$(builddir)/%.png: $(srcdir)/%.dot
	dot -Tpng $< > $@

$(srcdir)/%.msc: $(srcdir)/%.ladder
	@which ladder_to_msc.py || (echo 'PLEASE POINT YOUR $$PATH AT libosmocore/contrib/ladder_to_msc.py' && false)
	ladder_to_msc.py -i $< -o $@

.PHONY: poll
poll:
	while true; do $(MAKE) msc dot; sleep 1; done
