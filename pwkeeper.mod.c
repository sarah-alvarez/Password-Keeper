#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x21b5298a, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0xcceaa11a, __VMLINUX_SYMBOL_STR(platform_device_unregister) },
	{ 0x2601d76c, __VMLINUX_SYMBOL_STR(platform_driver_unregister) },
	{ 0x14d59380, __VMLINUX_SYMBOL_STR(__platform_driver_register) },
	{ 0xe15e3efb, __VMLINUX_SYMBOL_STR(platform_device_register_full) },
	{ 0xb44ad4b3, __VMLINUX_SYMBOL_STR(_copy_to_user) },
	{ 0x5280fe65, __VMLINUX_SYMBOL_STR(crypto_destroy_tfm) },
	{ 0xa07f6e2f, __VMLINUX_SYMBOL_STR(crypto_shash_digest) },
	{ 0xd2b09ce5, __VMLINUX_SYMBOL_STR(__kmalloc) },
	{ 0x3735d720, __VMLINUX_SYMBOL_STR(crypto_alloc_shash) },
	{ 0x2493cd7d, __VMLINUX_SYMBOL_STR(cs421net_get_data) },
	{ 0xf98f620c, __VMLINUX_SYMBOL_STR(cs421net_enable) },
	{ 0xd6b8e852, __VMLINUX_SYMBOL_STR(request_threaded_irq) },
	{ 0xe083e17, __VMLINUX_SYMBOL_STR(device_create_file) },
	{ 0x445fdc5d, __VMLINUX_SYMBOL_STR(misc_register) },
	{ 0x4ca9669f, __VMLINUX_SYMBOL_STR(scnprintf) },
	{ 0xa998c975, __VMLINUX_SYMBOL_STR(ns_capable) },
	{ 0x8633522d, __VMLINUX_SYMBOL_STR(task_active_pid_ns) },
	{ 0xad27f361, __VMLINUX_SYMBOL_STR(__warn_printk) },
	{ 0x127459d, __VMLINUX_SYMBOL_STR(kmem_cache_alloc) },
	{ 0x304c4c4f, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0xdb7305a1, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0x362ef408, __VMLINUX_SYMBOL_STR(_copy_from_user) },
	{ 0xdb77260a, __VMLINUX_SYMBOL_STR(current_task) },
	{ 0x7b529401, __VMLINUX_SYMBOL_STR(misc_deregister) },
	{ 0xacb38f5b, __VMLINUX_SYMBOL_STR(device_remove_file) },
	{ 0x6c1988ba, __VMLINUX_SYMBOL_STR(_raw_spin_unlock) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0xdbbee5cd, __VMLINUX_SYMBOL_STR(_raw_spin_lock) },
	{ 0xc1514a3b, __VMLINUX_SYMBOL_STR(free_irq) },
	{ 0xe7051e03, __VMLINUX_SYMBOL_STR(cs421net_disable) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=xt_cs421net";


MODULE_INFO(srcversion, "B352B8495362A3B4B40870E");
