##! This script adds per item expiration for the intelligence framework.

@load base/frameworks/intel

module Intel;

export {
	## Default expiration interval for single intelligence items that
	## is used in case the loaded intel file does not specify expire
	## metadata. A negative value disables expiration for these items.
	const default_per_item_expiration = -1 min &redef;

	redef record MetaData += {
		## Expiration interval of the intelligence item. In case of multiple
		## meta data instances, each instance will be treated separately.
		## A negative value disables expiration. When the expiration of an
		## item is detected, the hook :zeek:id:`Intel::single_item_expired`
		## will be called. 
		expire:     interval &default=default_per_item_expiration;

		## Internal value: Keeps the start time of the expiration timespan
		## for that item. The start time might be reset to reset expiration.
		start_time: time     &default=network_time();
	};

	## This hook can be used to handle per item expiration of intelligence
	## items. The hook is executed whenever an item is found expired.
	## Note: The time between expiration and execution of the hook might
	## vary depending on item expiration and matches.
	##
	## item: The expired item.
	##
	## If all hook handlers are executed, the expiration timeout will be reset.
	## Otherwise, if one of the handlers terminates using break, the item will
	## be removed.
	global single_item_expired: hook(item: Item);
}

redef item_expiration = 10min;

hook extend_match(info: Info, s: Seen, items: set[Item])
	{
	local matches = |items|;
	for ( item in items )
		{
		local meta = item$meta;
		if ( meta$expire > 0 sec &&
			 meta$start_time + meta$expire < network_time() )
			{
			# Item already expired, check whether it should be removed
			if ( hook single_item_expired(item) )
				{
				# Item should remain: Update start time
				item$meta$start_time = network_time();
				insert(item);
				}
			else
				{
				# Remove item
				--matches;
				remove(item, F);
				}
			}
		}

	if ( matches < 1 )
		# Prevent logging if there was no match at all
		break;
	}

hook Intel::item_expired(indicator: string, indicator_type: Type, metas: set[MetaData])
	{
	for ( meta in metas )
		{
		# Check for expired items
		if ( meta$expire > 0 sec &&
			 meta$start_time + meta$expire < network_time() )
			{
			# Item expired
			local item: Intel::Item = [
				$indicator = indicator,
				$indicator_type = indicator_type,
				$meta = meta
			];
			if ( hook single_item_expired(item) )
				{
				# Item should remain: Update start time
				item$meta$start_time = network_time();
				insert(item);
				}
			else
				{
				# Remove item
				remove(item, F);
				}
			}
		}
	}
