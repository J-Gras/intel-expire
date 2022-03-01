##! This script enables expiration for intelligence items.

module Intel;

redef default_per_item_expiration = 10min;

hook single_item_expired(item: Item) &priority=-10
	{
	# Trigger removal of the expired item.
	break;
}
