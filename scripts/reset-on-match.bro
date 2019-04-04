##! This script resets expiration timeouts on hits.

module Intel;

hook extend_match(info: Info, s: Seen, items: set[Item]) &priority=5
	{
	for ( item in items )
		{
		# Update start time to reset expiration
		item$meta$start_time = network_time();
		insert(item);
		}
	}
