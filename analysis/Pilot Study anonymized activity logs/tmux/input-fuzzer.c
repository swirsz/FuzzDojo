```c
/*
 * Advanced tmux fuzz driver with maximum code coverage
 * Fixed for API compatibility (older/newer tmux trees)
 *
 * Fixes included:
 * - screen_write_puts(): removed extra arg (it is printf-like in this tmux)
 * - screen_write_insertmode(): not available -> use MODE_INSERT via mode_set/clear
 * - grid_clear_cell(): not available -> clear by setting grid_default_cell
 * - grid_duplicate_lines(): signature expects 5 args -> pass src/dst grids
 * - paste_add(): expects char * (non-const) -> allocate mutable buffer (tmux owns it)
 * - paste_free_top(): not available -> replaced with paste_get_top()
 * - struct screen has no sx/sy -> use screen_size_x/screen_size_y macros
 * - screen_write_box(): this tmux expects 6 args -> provide enum, cell, title
 */

#include <stddef.h>
#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include "tmux.h"

#define FUZZER_MAXLEN 1024
#define MIN_PANE_WIDTH 10
#define MAX_PANE_WIDTH 160
#define MIN_PANE_HEIGHT 5
#define MAX_PANE_HEIGHT 50

struct event_base *libevent;

typedef struct {
	const u_char *data;
	size_t size;
	size_t offset;
} fuzz_data_t;

static int
fuzz_consume_byte(fuzz_data_t *fd, u_char *out)
{
	if (fd->offset >= fd->size)
		return -1;
	*out = fd->data[fd->offset++];
	return 0;
}

static int
fuzz_consume_u16(fuzz_data_t *fd, u_int *out)
{
	if (fd->offset + 2 > fd->size)
		return -1;
	*out = (fd->data[fd->offset] << 8) | fd->data[fd->offset + 1];
	fd->offset += 2;
	return 0;
}

static size_t
fuzz_remaining(fuzz_data_t *fd)
{
	return fd->size - fd->offset;
}

static const u_char *
fuzz_ptr(fuzz_data_t *fd)
{
	return fd->data + fd->offset;
}

/* Test different screen modes */
static void
test_screen_modes(struct window_pane *wp, u_char mode_byte)
{
	if (!wp || !wp->screen)
		return;

	struct screen_write_ctx ctx;
	screen_write_start(&ctx, wp->screen);

	if (mode_byte & 0x01)
		screen_write_mode_set(&ctx, MODE_CURSOR);
	if (mode_byte & 0x02)
		screen_write_mode_set(&ctx, MODE_WRAP);
	if (mode_byte & 0x04)
		screen_write_mode_set(&ctx, MODE_INSERT);
	if (mode_byte & 0x08)
		screen_write_mode_clear(&ctx, MODE_KCURSOR);
	if (mode_byte & 0x10)
		screen_write_mode_set(&ctx, MODE_KKEYPAD);

	screen_write_stop(&ctx);
}

/* Test screen writing operations */
static void
test_screen_write_ops(struct window_pane *wp, u_char op_byte)
{
	if (!wp || !wp->screen)
		return;

	struct screen_write_ctx ctx;
	struct grid_cell gc;

	screen_write_start(&ctx, wp->screen);

	switch (op_byte & 0x0F) {
	case 0:
		memcpy(&gc, &grid_default_cell, sizeof gc);
		gc.data.data[0] = 'X';
		screen_write_cell(&ctx, &gc);
		break;
	case 1:
		/* printf-like in this tmux; do not pass a length arg */
		screen_write_puts(&ctx, &grid_default_cell, "Test");
		break;
	case 2:
		screen_write_linefeed(&ctx, 0, 8);
		screen_write_carriagereturn(&ctx);
		break;
	case 3:
		screen_write_scrollup(&ctx, 1, 8);
		break;
	case 4:
		screen_write_insertline(&ctx, 1, 8);
		break;
	case 5:
		screen_write_deleteline(&ctx, 1, 8);
		break;
	case 6:
		screen_write_insertcharacter(&ctx, 1, 8);
		break;
	case 7:
		screen_write_deletecharacter(&ctx, 1, 8);
		break;
	case 8:
		screen_write_clearcharacter(&ctx, 1, 8);
		break;
	case 9:
		screen_write_scrollregion(&ctx, 0, 10);
		break;
	case 10:
		/* screen_write_insertmode() not present: toggle MODE_INSERT instead */
		screen_write_mode_set(&ctx, MODE_INSERT);
		break;
	case 11:
		screen_write_alignmenttest(&ctx);
		break;
	default:
		break;
	}

	screen_write_stop(&ctx);
}

/* Test cursor operations */
static void
test_cursor_ops(struct window_pane *wp, u_char op_byte, u_int pane_width, u_int pane_height)
{
	if (!wp || !wp->screen)
		return;

	struct screen_write_ctx ctx;
	screen_write_start(&ctx, wp->screen);

	u_int x = op_byte % pane_width;
	u_int y = (op_byte >> 4) % pane_height;

	switch (op_byte & 0x07) {
	case 0:
		screen_write_cursormove(&ctx, x, y, 0);
		break;
	case 1:
		screen_write_cursorup(&ctx, y);
		break;
	case 2:
		screen_write_cursordown(&ctx, y);
		break;
	case 3:
		screen_write_cursorright(&ctx, x);
		break;
	case 4:
		screen_write_cursorleft(&ctx, x);
		break;
	case 5:
		screen_write_reverseindex(&ctx, 8);
		break;
	case 6:
		screen_write_linefeed(&ctx, 0, 8);
		break;
	case 7:
		screen_write_carriagereturn(&ctx);
		break;
	}

	screen_write_stop(&ctx);
}

/* Test screen clearing operations */
static void
test_clear_ops(struct window_pane *wp, u_char clear_byte)
{
	if (!wp || !wp->screen)
		return;

	struct screen_write_ctx ctx;
	screen_write_start(&ctx, wp->screen);

	switch (clear_byte & 0x03) {
	case 0:
		screen_write_clearscreen(&ctx, 8);
		break;
	case 1:
		screen_write_clearendofscreen(&ctx, 8);
		break;
	case 2:
		screen_write_clearstartofscreen(&ctx, 8);
		break;
	case 3:
		screen_write_clearendofline(&ctx, 8);
		break;
	}

	screen_write_stop(&ctx);
}

/* Test grid operations */
static void
test_grid_ops(struct window_pane *wp, u_char grid_byte, u_int pane_width, u_int pane_height)
{
	if (!wp || !wp->screen || !wp->screen->grid)
		return;

	struct grid *gd = wp->screen->grid;
	u_int x = grid_byte % pane_width;
	u_int y = (grid_byte >> 4) % pane_height;

	if (x >= gd->sx || y >= gd->sy)
		return;

	struct grid_cell gc;

	switch (grid_byte & 0x07) {
	case 0:
		grid_get_cell(gd, x, y, &gc);
		break;
	case 1:
		memcpy(&gc, &grid_default_cell, sizeof gc);
		gc.data.data[0] = 'A' + (grid_byte % 26);
		grid_set_cell(gd, x, y, &gc);
		break;
	case 2:
		memcpy(&gc, &grid_default_cell, sizeof gc);
		grid_set_cell(gd, x, y, &gc);
		break;
	case 3:
		grid_view_get_cell(gd, x, y, &gc);
		break;
	case 4:
		if (y + 1 < gd->sy)
			grid_duplicate_lines(gd, y, gd, y + 1, 1);
		break;
	case 5:
		if (pane_width > 20)
			grid_reflow(gd, pane_width - 10);
		break;
	default:
		break;
	}
}

/* Test window operations */
static void
test_window_ops(struct window *w, u_char win_byte)
{
	if (!w)
		return;

	switch (win_byte & 0x07) {
	case 0:
		if (!TAILQ_EMPTY(&w->panes))
			window_set_active_pane(w, TAILQ_FIRST(&w->panes), 0);
		break;
	case 1:
		window_count_panes(w);
		break;
	case 2:
		window_get_active_at(w, w->sx / 2, w->sy / 2);
		break;
	case 3:
		if (!TAILQ_EMPTY(&w->panes))
			window_pane_find_down(TAILQ_FIRST(&w->panes));
		break;
	case 4:
		if (!TAILQ_EMPTY(&w->panes))
			window_pane_find_up(TAILQ_FIRST(&w->panes));
		break;
	case 5:
		if (!TAILQ_EMPTY(&w->panes))
			window_pane_find_left(TAILQ_FIRST(&w->panes));
		break;
	case 6:
		if (!TAILQ_EMPTY(&w->panes))
			window_pane_find_right(TAILQ_FIRST(&w->panes));
		break;
	default:
		break;
	}
}

/* Test options operations */
static void
test_options_ops(u_char opt_byte)
{
	struct options_entry *oe;
	const char *test_names[] = {
		"monitor-bell",
		"allow-rename",
		"alternate-screen",
		"automatic-rename",
		"remain-on-exit"
	};
	const char *name = test_names[opt_byte % 5];

	switch (opt_byte & 0x07) {
	case 0:
		options_get_number(global_w_options, name);
		break;
	case 1:
		options_set_number(global_w_options, name, opt_byte & 0x01);
		break;
	case 2:
		oe = options_get_only(global_w_options, name);
		if (oe)
			options_get_number(global_w_options, name);
		break;
	case 3:
		options_get_string(global_options, "set-clipboard");
		break;
	default:
		break;
	}
}

/* Test style and colour operations */
static void
test_style_ops(struct window_pane *wp, u_char style_byte)
{
	if (!wp || !wp->screen)
		return;

	struct screen_write_ctx ctx;
	struct grid_cell gc;

	screen_write_start(&ctx, wp->screen);

	memcpy(&gc, &grid_default_cell, sizeof gc);

	switch (style_byte & 0x07) {
	case 0:
		gc.fg = style_byte % 8;
		gc.bg = (style_byte >> 3) % 8;
		screen_write_cell(&ctx, &gc);
		break;
	case 1:
		gc.fg = 8 + (style_byte % 8);
		gc.bg = 8 + ((style_byte >> 3) % 8);
		screen_write_cell(&ctx, &gc);
		break;
	case 2:
		gc.attr = GRID_ATTR_BRIGHT | GRID_ATTR_UNDERSCORE;
		screen_write_cell(&ctx, &gc);
		break;
	case 3:
		gc.attr = GRID_ATTR_DIM | GRID_ATTR_ITALICS;
		screen_write_cell(&ctx, &gc);
		break;
	case 4:
		gc.attr = GRID_ATTR_REVERSE | GRID_ATTR_BLINK;
		screen_write_cell(&ctx, &gc);
		break;
	case 5:
		gc.attr = GRID_ATTR_HIDDEN | GRID_ATTR_STRIKETHROUGH;
		screen_write_cell(&ctx, &gc);
		break;
	default:
		break;
	}

	screen_write_stop(&ctx);
}

/* Test environment operations */
static void
test_environ_ops(u_char env_byte)
{
	const char *test_vars[] = { "TERM", "SHELL", "USER", "PATH", "HOME" };
	const char *var = test_vars[env_byte % 5];

	switch (env_byte & 0x03) {
	case 0:
		environ_find(global_environ, var);
		break;
	case 1:
		environ_set(global_environ, var, 0, "test_value");
		break;
	case 2:
		environ_put(global_environ, "TEST=value", 0);
		break;
	case 3:
		environ_unset(global_environ, var);
		break;
	}
}

/* Test paste buffer operations */
static void
test_paste_ops(u_char paste_byte)
{
	const char *test_data = "test paste data";

	switch (paste_byte & 0x03) {
	case 0: {
		size_t n = strlen(test_data);
		char *buf = xmalloc(n + 1);
		memcpy(buf, test_data, n + 1);
		paste_add(NULL, buf, n); /* tmux likely owns buf */
		break;
	}
	case 1:
		paste_get_top(NULL);
		break;
	case 2:
		paste_get_name("buffer0");
		break;
	case 3:
		paste_get_top(NULL);
		break;
	}
}

/* Test screen redraw operations */
static void
test_screen_redraw(struct window_pane *wp, u_char redraw_byte)
{
	if (!wp || !wp->screen)
		return;

	struct screen_write_ctx ctx;
	screen_write_start(&ctx, wp->screen);

	u_int sx = screen_size_x(wp->screen);
	u_int sy = screen_size_y(wp->screen);

	switch (redraw_byte & 0x07) {
	case 0:
		screen_write_cursormove(&ctx, 0, 0, 0);
		screen_write_clearscreen(&ctx, 8);
		break;
	case 1:
		screen_write_cursormove(&ctx, 0, wp->screen->cy / 2, 0);
		screen_write_clearendofscreen(&ctx, 8);
		break;
	case 2:
		/*
		 * FIX: screen_write_box signature here is:
		 *   screen_write_box(ctx, nx, ny, enum box_lines,
		 *                   const grid_cell*, const char *title)
		 */
		if (sx > 2 && sy > 2)
			screen_write_box(&ctx, sx - 2, sy - 2,
			    BOX_LINES_SINGLE, &grid_default_cell, "fuzz");
		break;
	case 3:
		screen_write_collect_end(&ctx);
		screen_write_collect_add(&ctx, &grid_default_cell);
		break;
	case 4:
		if (sx > 0 && sy > 0)
			screen_write_fast_copy(&ctx, wp->screen, 0, 0, sx, sy);
		break;
	default:
		break;
	}

	screen_write_stop(&ctx);
}

/* Test UTF-8 handling */
static void
test_utf8_ops(struct window_pane *wp, const u_char *data, size_t len)
{
	if (!wp || !wp->screen || len == 0)
		return;

	struct screen_write_ctx ctx;
	struct grid_cell gc;
	struct utf8_data ud;

	screen_write_start(&ctx, wp->screen);

	memcpy(&gc, &grid_default_cell, sizeof gc);

	if (len > 0 && utf8_open(&ud, data[0]) == UTF8_MORE) {
		for (size_t i = 1; i < len && i < sizeof(ud.data); i++) {
			if (utf8_append(&ud, data[i]) == UTF8_DONE)
				break;
		}
	}

	screen_write_stop(&ctx);
}

int
LLVMFuzzerTestOneInput(const u_char *data, size_t size)
{
	struct bufferevent *vpty[2];
	struct window *w;
	struct window_pane *wp, *wp2 = NULL;
	int error;
	fuzz_data_t fd;
	u_char config_byte, config2_byte;
	u_char pane_width_byte, pane_height_byte;
	u_int pane_width, pane_height;
	size_t input_size;

	if (size < 5 || size > FUZZER_MAXLEN)
		return 0;

	fd.data = data;
	fd.size = size;
	fd.offset = 0;

	if (fuzz_consume_byte(&fd, &config_byte) != 0)
		return 0;
	if (fuzz_consume_byte(&fd, &config2_byte) != 0)
		return 0;

	if (fuzz_consume_byte(&fd, &pane_width_byte) != 0)
		return 0;
	if (fuzz_consume_byte(&fd, &pane_height_byte) != 0)
		return 0;

	pane_width = MIN_PANE_WIDTH + (pane_width_byte %
	    (MAX_PANE_WIDTH - MIN_PANE_WIDTH + 1));
	pane_height = MIN_PANE_HEIGHT + (pane_height_byte %
	    (MAX_PANE_HEIGHT - MIN_PANE_HEIGHT + 1));

	w = window_create(pane_width, pane_height, 0, 0);
	if (w == NULL)
		return 0;

	int hlimit = 0;
	if (config_byte & 0x01) {
		u_char hlimit_byte;
		if (fuzz_consume_byte(&fd, &hlimit_byte) == 0)
			hlimit = hlimit_byte * 10;
	}

	wp = window_add_pane(w, NULL, hlimit, 0);
	if (wp == NULL) {
		window_remove_ref(w, __func__);
		return 0;
	}

	bufferevent_pair_new(libevent, BEV_OPT_CLOSE_ON_FREE, vpty);
	if (vpty[0] == NULL || vpty[1] == NULL) {
		if (vpty[0]) bufferevent_free(vpty[0]);
		if (vpty[1]) bufferevent_free(vpty[1]);
		window_remove_ref(w, __func__);
		return 0;
	}

	wp->ictx = input_init(wp, vpty[0], NULL);
	window_add_ref(w, __func__);

	wp->fd = open("/dev/null", O_WRONLY);
	if (wp->fd == -1) {
		bufferevent_free(vpty[0]);
		bufferevent_free(vpty[1]);
		window_remove_ref(w, __func__);
		window_remove_ref(w, __func__);
		return 0;
	}

	wp->event = bufferevent_new(wp->fd, NULL, NULL, NULL, NULL);
	if (wp->event == NULL) {
		close(wp->fd);
		bufferevent_free(vpty[0]);
		bufferevent_free(vpty[1]);
		window_remove_ref(w, __func__);
		window_remove_ref(w, __func__);
		return 0;
	}

	if (config_byte & 0x02) {
		wp2 = window_add_pane(w, wp, 0, LAYOUT_LEFTRIGHT);
		if (wp2) {
			wp2->fd = open("/dev/null", O_WRONLY);
			if (wp2->fd != -1) {
				wp2->event = bufferevent_new(wp2->fd, NULL,
				    NULL, NULL, NULL);
			}
		}
	}

	if (config_byte & 0x04 && wp->screen)
		wp->screen->mode |= MODE_WRAP;

	if (config2_byte & 0x01 && wp->screen)
		wp->screen->mode |= MODE_CURSOR;

	input_size = fuzz_remaining(&fd);

	if (config_byte & 0x08 && input_size > 2) {
		size_t chunk_size = input_size / 3;

		input_parse_buffer(wp, (u_char *)fuzz_ptr(&fd), chunk_size);
		fd.offset += chunk_size;
		while (cmdq_next(NULL) != 0)
			;
		error = event_base_loop(libevent, EVLOOP_NONBLOCK);
		(void)error;

		size_t chunk2_size = (input_size - chunk_size) / 2;
		input_parse_buffer(wp, (u_char *)fuzz_ptr(&fd), chunk2_size);
		fd.offset += chunk2_size;
		while (cmdq_next(NULL) != 0)
			;
		error = event_base_loop(libevent, EVLOOP_NONBLOCK);
		(void)error;

		input_parse_buffer(wp, (u_char *)fuzz_ptr(&fd), fuzz_remaining(&fd));
	} else {
		input_parse_buffer(wp, (u_char *)fuzz_ptr(&fd), input_size);
	}

	while (cmdq_next(NULL) != 0)
		;
	error = event_base_loop(libevent, EVLOOP_NONBLOCK);
	(void)error;

	if (config_byte & 0x10)
		test_screen_modes(wp, config2_byte);
	if (config_byte & 0x20)
		test_screen_write_ops(wp, config2_byte);
	if (config_byte & 0x40)
		test_cursor_ops(wp, config2_byte, pane_width, pane_height);
	if (config_byte & 0x80)
		test_clear_ops(wp, config2_byte);

	while (cmdq_next(NULL) != 0)
		;
	error = event_base_loop(libevent, EVLOOP_NONBLOCK);
	(void)error;

	if (config2_byte & 0x01)
		test_grid_ops(wp, config2_byte, pane_width, pane_height);
	if (config2_byte & 0x02)
		test_window_ops(w, config2_byte);

	if (config2_byte & 0x04) {
		u_int new_width = pane_width / 2 + MIN_PANE_WIDTH;
		u_int new_height = pane_height / 2 + MIN_PANE_HEIGHT;

		if (new_width >= MIN_PANE_WIDTH && new_height >= MIN_PANE_HEIGHT) {
			window_resize(w, new_width, new_height, 0, 0);
			while (cmdq_next(NULL) != 0)
				;
			error = event_base_loop(libevent, EVLOOP_NONBLOCK);
			(void)error;
		}
	}

	if (config2_byte & 0x08)
		window_set_name(w, "fuzz_test");

	if (config2_byte & 0x10)
		layout_fix_panes(w, NULL);

	if (config2_byte & 0x20 && wp->screen) {
		struct grid_cell tmp;
		screen_select_cell(wp->screen, &tmp, &grid_default_cell);
	}

	if (config2_byte & 0x40 && wp->screen) {
		struct screen_write_ctx ctx;
		struct grid_cell gc;

		screen_write_start(&ctx, wp->screen);

		memcpy(&gc, &grid_default_cell, sizeof gc);
		gc.attr |= GRID_ATTR_BRIGHT;
		screen_write_cell(&ctx, &gc);

		gc.attr = GRID_ATTR_DIM;
		screen_write_cell(&ctx, &gc);

		gc.attr = GRID_ATTR_UNDERSCORE;
		screen_write_cell(&ctx, &gc);

		gc.attr = GRID_ATTR_REVERSE;
		screen_write_cell(&ctx, &gc);

		screen_write_stop(&ctx);
	}

	if (config2_byte & 0x80) {
		if (wp && wp->xoff < w->sx && wp->yoff < w->sy)
			window_pane_visible(wp);
	}

	if (fuzz_remaining(&fd) > 0) {
		u_char extra_byte;

		if (fuzz_consume_byte(&fd, &extra_byte) == 0) {
			test_options_ops(extra_byte);
			test_style_ops(wp, extra_byte);
			test_environ_ops(extra_byte);
			test_paste_ops(extra_byte);
			test_screen_redraw(wp, extra_byte);
		}

		if (fuzz_remaining(&fd) > 0) {
			test_utf8_ops(wp, fuzz_ptr(&fd),
			    fuzz_remaining(&fd) < 4 ? fuzz_remaining(&fd) : 4);
		}
	}

	while (cmdq_next(NULL) != 0)
		;
	error = event_base_loop(libevent, EVLOOP_NONBLOCK);
	(void)error;

	while (cmdq_next(NULL) != 0)
		;
	error = event_base_loop(libevent, EVLOOP_NONBLOCK);
	(void)error;

	if (wp2 && wp2->event) {
		bufferevent_free(wp2->event);
		wp2->event = NULL;
	}
	if (wp2 && wp2->fd != -1) {
		close(wp2->fd);
		wp2->fd = -1;
	}

	assert(w->references == 1);
	window_remove_ref(w, __func__);
	bufferevent_free(vpty[0]);
	bufferevent_free(vpty[1]);

	return 0;
}

int
LLVMFuzzerInitialize(__unused int *argc, __unused char ***argv)
{
	const struct options_table_entry *oe;

	global_environ = environ_create();
	global_options = options_create(NULL);
	global_s_options = options_create(NULL);
	global_w_options = options_create(NULL);

	for (oe = options_table; oe->name != NULL; oe++) {
		if (oe->scope & OPTIONS_TABLE_SERVER)
			options_default(global_options, oe);
		if (oe->scope & OPTIONS_TABLE_SESSION)
			options_default(global_s_options, oe);
		if (oe->scope & OPTIONS_TABLE_WINDOW)
			options_default(global_w_options, oe);
	}

	libevent = osdep_event_init();

	options_set_number(global_w_options, "monitor-bell", 0);
	options_set_number(global_w_options, "allow-rename", 1);
	options_set_number(global_options, "set-clipboard", 2);
	options_set_number(global_w_options, "alternate-screen", 1);
	options_set_number(global_w_options, "remain-on-exit", 0);
	options_set_number(global_w_options, "xterm-keys", 1);
	options_set_number(global_w_options, "aggressive-resize", 1);

	socket_path = xstrdup("dummy");
	return 0;
}
```
