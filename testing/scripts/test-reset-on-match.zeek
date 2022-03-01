# @TEST-EXEC: zeek -r $TRACES/ticks.pcap item-expire %INPUT
# @TEST-EXEC: cat intel.log > output
# @TEST-EXEC: cat .stdout >> output
# @TEST-EXEC: btest-diff output

@load reset-on-match

redef enum Intel::Where += { SOMEWHERE };
redef Intel::item_expiration = 1sec;
redef table_expire_interval = 1sec;

event zeek_init()
	{
	Intel::insert([$indicator="1.0.0.0", $indicator_type=Intel::ADDR,
		$meta=[$source="source1", $expire=5secs]]);
	Intel::insert([$indicator="2.0.0.0", $indicator_type=Intel::ADDR,
		$meta=[$source="source1", $expire=5secs]]);
	}

global runs = 0;

event connection_established(c: connection)
	{
	print fmt(">> Run %s (%s):", runs, network_time());
	switch (runs)
		{
		case 1:
			# Cause match and hit
			print "Trigger: 1.0.0.0";
			Intel::seen([$host=1.0.0.0,
			             $where=SOMEWHERE]);
			print "Trigger: 2.0.0.0";
			Intel::seen([$host=2.0.0.0,
			             $where=SOMEWHERE]);
			break;
		case 4:
			# Cause match and hit
			print "Trigger: 2.0.0.0";
			Intel::seen([$host=2.0.0.0,
			             $where=SOMEWHERE]);
			break;
		case 8:
			# Cause neither match nor hit
			print "Trigger: 1.0.0.0";
			Intel::seen([$host=1.0.0.0,
			             $where=SOMEWHERE]);
			# Cause match and hit
			print "Trigger: 2.0.0.0";
			Intel::seen([$host=2.0.0.0,
			             $where=SOMEWHERE]);
			break;
		}

	++runs;
	}

event Intel::match(s: Intel::Seen, items: set[Intel::Item])
	{
	for ( i in items )
		print fmt("Match: %s", i);
	}

hook Intel::single_item_expired(item: Intel::Item)
	{
	print fmt("Item expired: %s", item);
	break;
	}
