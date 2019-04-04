# @TEST-EXEC: bro -r $TRACES/ticks.pcap item-expire %INPUT
# @TEST-EXEC: cat intel.log > output
# @TEST-EXEC: cat .stdout >> output
# @TEST-EXEC: btest-diff output

# @TEST-START-FILE intel_expire.dat
#fields	indicator	indicator_type	meta.source	meta.desc	meta.expire
1.0.0.0	Intel::ADDR	source1	this host is bad	2
2.0.0.0	Intel::ADDR	source1	this host is bad	4
# @TEST-END-FILE

@load ../../../scripts/delete-expired.bro

redef Intel::read_files += { "intel_expire.dat" };
redef enum Intel::Where += { SOMEWHERE };
redef Intel::item_expiration = 1sec;
redef table_expire_interval = 1sec;

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
		case 8:
			# Cause neither match nor hit
			print "Trigger: 1.0.0.0";
			Intel::seen([$host=1.0.0.0,
			             $where=SOMEWHERE]);
			print "Trigger: 2.0.0.0";
			Intel::seen([$host=2.0.0.0,
			             $where=SOMEWHERE]);
			break;
		}

	++runs;
	}

event Intel::match(s: Intel::Seen, items: set[Intel::Item])
	{
	local t: time;
	for ( i in items )
		t = i$meta$start_time;
	print fmt("Match: %s Start time: %s", s$indicator, t);
	# Note: The match event does not necessarily indicate a hit
	# in this case, as the per item timeout might be expired.
	}

hook Intel::single_item_expired(item: Intel::Item)
	{
	print fmt("Item expired: %s", item);
	}
