#ifndef LIBURING_EX_LIST_H
#define LIBURING_EX_LIST_H

struct list_head {
	struct list_head *prev, *next;
};

#ifndef offsetof
#define offsetof(TYPE, FIELD) ((size_t) &((TYPE *)0)->FIELD)
#endif

#ifndef container_of
#define container_of(PTR, TYPE, FIELD) ({			\
	__typeof__(((TYPE *)0)->FIELD) *__FIELD_PTR = (PTR);	\
	(TYPE *)((char *) __FIELD_PTR - offsetof(TYPE, FIELD));	\
})
#endif

static inline void init_list_head(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline void __list_add(struct list_head *new, struct list_head *prev,
			      struct list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	__list_add(new, head->prev, head);
}

static inline void __list_del(struct list_head *prev, struct list_head *next)
{
	next->prev = prev;
	prev->next = next;
}

static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
}

static inline bool list_empty(struct list_head *list)
{
	return list->next == list;
}

#define list_entry(ptr, type, member)		\
	container_of(ptr, type, member)

#define list_first_entry(ptr, type, member)	\
	list_entry((ptr)->next, type, member)

#endif
