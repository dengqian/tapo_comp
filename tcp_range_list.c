#include "tcp_range_list.h"
#include "tcp_base.h"
#include "malloc.h"

#include <stdlib.h>

// void append_to_range_list(struct list_head *list, struct range_t *range)
// {
// 	struct range_t *r = (struct range_t *)MALLOC(sizeof(struct range_t));
// 	memcpy(r, range, sizeof(struct range_t));
// 	list_add_tail(&r->list, list);
// }

void append_to_range_list(struct list_head *list, uint32_t begin, uint32_t end)
{
	struct range_t *range = MALLOC(struct range_t);
	range->begin = begin;
	range->end = end;
	list_add_tail(&range->list, list);
}

uint32_t list_size(struct list_head *list)
{
	struct list_head *p;
	uint32_t size = 0;
	list_for_each(p, list) {
		struct range_t *node = list_entry(p, struct range_t, list);
		size += (node->end - node->begin);
	}

	return size;
}

uint32_t list_range_size(struct list_head *list, uint32_t b, uint32_t e)
{
	struct list_head *p;
	uint32_t size = 0;
	list_for_each(p, list) {
		struct range_t *node = list_entry(p, struct range_t, list);
		if (!before(node->begin, e) || !before(b, node->end))
			continue;
		else
			size += (MIN_SEQ(node->end, e) - MAX_SEQ(node->begin, b));
	}

	return size;
}

int in_range_list(uint32_t n, struct list_head *list)
{
	struct list_head *pos;
	list_for_each_prev(pos, list) {
		struct range_t *r = list_entry(pos, struct range_t, list);
		if (between(n, r->begin, r->end))
			return 1;
		else if (before(n, r->begin))
			return 0;
	}

	return 0;
}

void delete_range_list(struct list_head *list)
{
	delete_list(list, struct range_t, list);
}

//get the number of bytes reordered, record reorder begin and end
int get_reorder(uint32_t seq, struct list_head *list, uint32_t *b, uint32_t *e)
{
	struct list_head *reord_node = list->next;
	*b = seq;
	*e = seq;
	while (reord_node != list) {
		struct range_t *reord = list_entry(reord_node, struct range_t, list);
		if(before(reord->begin, *b))
			*b = reord->begin;
		if(after(reord->end, *e))
			*e = reord->end;
		reord_node = reord_node->next;
	}
	return *e - *b;
}

//get the number of bytes retransed, record retrans begin and end
int get_retrans(uint32_t seq, struct list_head *list, uint32_t *b, uint32_t *e)
{
	
	struct list_head *retrans_node = list->next;
	*b = seq;
	*e = seq;
	while (retrans_node != list) {
		struct range_t *retrans = list_entry(retrans_node, struct range_t, list);
		if(before(retrans->begin, *b))
			*b = retrans->begin;
		if(after(retrans->end, *e))
			*e = retrans->end;
		retrans_node = retrans_node->next;
	}
	return *e - *b;
}

//insert into list ordered by seq
void insert_to_range_list(struct list_head *list, uint32_t begin, uint32_t end)
{
	struct range_t *range = MALLOC(struct range_t);
	range->begin = begin;
	range->end = end;
	struct list_head *temp_node = list;
	while(temp_node->next != list){
		struct range_t *node = list_entry(temp_node, struct range_t, list);
		if(node->begin == end)
			break;
		temp_node = temp_node->next;
	}
	if (temp_node ->next == list)
		temp_node = temp_node->next;
	list_insert(&range->list, temp_node->prev, temp_node);
}

struct list_head *find_node_by_seq(struct list_head *list, uint32_t seq)
{
	struct list_head * pos;
	list_for_each(pos, list){
		struct range_t *node = list_entry(pos, struct range_t, list);
		if(node->begin == seq)
			return pos;
	}
	return NULL;
}
//delete ordered node when incomming the expected pkt
void delete_ordered_node(struct list_head *list,uint32_t seq)
{
	struct list_head *node;
	int seq_num = seq;
	while((node = find_node_by_seq(list, seq_num)) != NULL){
		struct range_t *range = list_entry(node, struct range_t, list);
		seq_num = range->end;
		FREE(range);
		list_delete_entry(node);
	}
}

//delete node with end smaller than seq
void delete_node_before_seq(struct list_head *list, uint32_t seq)
{
	struct list_head *pos;
	list_for_each(pos, list) {
		struct range_t *range = list_entry(pos, struct range_t, list);
		if(range->end <= seq){
			FREE(range);
			list_delete_entry(pos);
		}
		if(range->begin >= seq)
			break;
	}
}
