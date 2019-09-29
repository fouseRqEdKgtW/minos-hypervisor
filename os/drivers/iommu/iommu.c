/**
 * Copyright (c) 2014 Anup Patel.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * @file vmm_iommu.c
 * @author Anup Patel (anup@brainfault.org)
 * @brief IOMMU framework implementation for device pass-through
 *
 * The source has been largely adapted from Linux sources:
 * drivers/iommu/iommu.c
 *
 * Copyright (C) 2007-2008 Advanced Micro Devices, Inc.
 * Author: Joerg Roedel <joerg.roedel@amd.com>
 *
 * The original source is licensed under GPL.
 */

#include <minos/minos.h>
#include <minos/iommu.h>

struct iommu_group {
	char *name;
	struct iommu_controller *ctrl;
	struct dlist head;

	mutex_t mutex;
	struct iommu_domain *domain;
	struct dlist devices;
	void *iommu_data;
	void (*iommu_data_release)(void *iommu_data);
};

struct iommu_device {
	struct dlist list;
	struct device *dev;
};

int iommu_controller_register(struct iommu_controller *ctrl)
{
	if (!ctrl)
		return -EINVAL;

	mutex_init(&ctrl->groups_lock);
	init_list(&ctrl->groups);
	mutex_init(&ctrl->domains_lock);
	init_list(&ctrl->domains);
}

int iommu_controller_unregister(struct iommu_controller *ctrl)
{
	if (!ctrl)
		return -EINVAL;
}

struct iommu_controller *iommu_controller_find(const char *name)
{
	return NULL;
}

struct iommu_controller_iterate_priv {
	void *data;
	int (*fn)(struct iommu_controller *, void *);
};

static int iommu_controller_iterate(struct device *dev, void *data)
{
	struct iommu_controller_iterate_priv *p = data;
	struct iommu_controller *ctrl = devdrv_get_data(dev);

	return p->fn(ctrl, p->data);
}

int iommu_controller_iterate(struct iommu_controller *start,
		void *data, int (*fn)(struct iommu_controller *, void *))
{
	struct device *st = (start) ? &start->dev : NULL;
	struct iommu_controller_iterate_priv p;

	if (!fn) {
		return VMM_EINVALID;
	}

	p.data = data;
	p.fn = fn;

	return devdrv_class_device_iterate(&iommuctrl_class, st,
						&p, iommu_controller_iterate);
}

int iommu_controller_for_each_group(struct iommu_controller *ctrl,
		void *data, int (*fn)(struct iommu_group *, void *))
{
	struct iommu_group *group;
	int ret = 0;

	if (!ctrl || !fn)
		return VMM_EINVALID;

	mutex_pend(&ctrl->groups_lock);

	list_for_each_entry(group, &ctrl->groups, head) {
		ret = fn(group, data);
		if (ret)
			break;
	}

	mutex_post(&ctrl->groups_lock);

	return ret;
}

static int iommu_controller_group_count_iter(struct iommu_group *group,
					     void *data)
{
	(*((u32 *)data))++;

	return VMM_OK;
}

u32 iommu_controller_group_count(struct iommu_controller *ctrl)
{
	u32 ret = 0;

	if (!ctrl)
		return 0;

	iommu_controller_for_each_group(ctrl, &ret,
					iommu_controller_group_count_iter);

	return ret;
}

int iommu_controller_for_each_domain(struct iommu_controller *ctrl,
		void *data, int (*fn)(struct iommu_domain *, void *))
{
	struct iommu_domain *domain;
	int ret = 0;

	if (!ctrl || !fn)
		return VMM_EINVALID;

	mutex_pend(&ctrl->domains_lock);

	list_for_each_entry(domain, &ctrl->domains, head) {
		ret = fn(domain, data);
		if (ret)
			break;
	}

	mutex_post(&ctrl->domains_lock);

	return ret;
}

static int iommu_controller_domain_count_iter(struct iommu_domain *domain,
					      void *data)
{
	(*((u32 *)data))++;

	return VMM_OK;
}

u32 iommu_controller_domain_count(struct iommu_controller *ctrl)
{
	u32 ret = 0;

	if (!ctrl)
		return 0;

	iommu_controller_for_each_domain(ctrl, &ret,
					iommu_controller_domain_count_iter);

	return ret;
}

/* =============== IOMMU Group APIs =============== */

struct iommu_group *iommu_group_alloc(const char *name,
					struct iommu_controller *ctrl)
{
	struct iommu_group *group;

	if (!name || !ctrl) {
		return VMM_ERR_PTR(VMM_EINVALID);
	}

	group = zalloc(sizeof(*group));
	if (!group) {
		return VMM_ERR_PTR(VMM_ENOMEM);
	}

	group->name = zalloc(strlen(name) + 1);
	if (!group->name) {
		free(group);
		return VMM_ERR_PTR(VMM_ENOMEM);
	}
	strcpy(group->name, name);
	group->name[strlen(name)] = '\0';
	group->ctrl = ctrl;
	INIT_LIST_HEAD(&group->head);

	xref_init(&group->ref_count);
	INIT_MUTEX(&group->mutex);
	INIT_LIST_HEAD(&group->devices);
	group->domain = NULL;
	BLOCKING_INIT_NOTIFIER_CHAIN(&group->notifier);

	mutex_pend(&ctrl->groups_lock);
	list_add_tail(&group->head, &ctrl->groups);
	mutex_post(&ctrl->groups_lock);

	return group;
}

struct iommu_group *iommu_group_get(struct device *dev)
{
	struct iommu_group *group = dev->iommu_group;

	if (group)
		xref_get(&group->ref_count);

	return group;
}

static void __iommu_group_free(struct xref *ref)
{
	struct iommu_group *group =
			container_of(ref, struct iommu_group, ref_count);

	mutex_pend(&group->ctrl->groups_lock);
	list_del(&group->head);
	mutex_post(&group->ctrl->groups_lock);

	free(group->name);

	if (group->iommu_data_release)
		group->iommu_data_release(group->iommu_data);

	free(group);
}

void iommu_group_free(struct iommu_group *group)
{
	if (group) {
		xref_put(&group->ref_count, __iommu_group_free);
	}
}

void *iommu_group_get_iommudata(struct iommu_group *group)
{
	return (group) ? group->iommu_data : NULL;
}

void iommu_group_set_iommudata(struct iommu_group *group,
				   void *iommu_data,
				   void (*release)(void *iommu_data))
{
	if (!group)
		return;

	group->iommu_data = iommu_data;
	group->iommu_data_release = release;
}

int iommu_group_add_device(struct iommu_group *group,
				struct device *dev)
{
	struct iommu_device *device;

	if (!group || !dev)
		return VMM_EINVALID;

	mutex_pend(&group->mutex);

	list_for_each_entry(device, &group->devices, list) {
		if (device->dev == dev) {
			mutex_post(&group->mutex);
			return VMM_EEXIST;
		}
	}

	device = zalloc(sizeof(*device));
	if (!device) {
		mutex_post(&group->mutex);
		return VMM_ENOMEM;
	}

	device->dev = dev;
	dev->iommu_group = group;
	xref_get(&group->ref_count);
	list_add_tail(&device->list, &group->devices);

	mutex_post(&group->mutex);

	/* Notify any listeners about change to group. */
	blocking_notifier_call(&group->notifier,
				VMM_IOMMU_GROUP_NOTIFY_ADD_DEVICE, dev);

	return 0;
}

void iommu_group_remove_device(struct device *dev)
{
	struct iommu_group *group = dev->iommu_group;
	struct iommu_device *tmp_device, *device = NULL;

	if (!group)
		return;

	/* Pre-notify listeners that a device is being removed. */
	blocking_notifier_call(&group->notifier,
				VMM_IOMMU_GROUP_NOTIFY_DEL_DEVICE, dev);

	mutex_pend(&group->mutex);

	list_for_each_entry(tmp_device, &group->devices, list) {
		if (tmp_device->dev == dev) {
			device = tmp_device;
			list_del(&device->list);
			break;
		}
	}

	mutex_post(&group->mutex);

	if (!device)
		return;

	free(device);
	dev->iommu_group = NULL;

	iommu_group_put(group);
}

int iommu_group_for_each_dev(struct iommu_group *group, void *data,
				 int (*fn)(struct device *, void *))
{
	struct iommu_device *device;
	int ret = 0;

	if (!group || !fn)
		return VMM_EINVALID;

	mutex_pend(&group->mutex);

	list_for_each_entry(device, &group->devices, list) {
		ret = fn(device->dev, data);
		if (ret)
			break;
	}

	mutex_post(&group->mutex);

	return ret;
}

int iommu_group_register_notifier(struct iommu_group *group,
				      struct notifier_block *nb)
{
	if (!group)
		return VMM_EINVALID;

	return blocking_notifier_register(&group->notifier, nb);
}

int iommu_group_unregister_notifier(struct iommu_group *group,
					struct notifier_block *nb)
{
	if (!group)
		return VMM_EINVALID;

	return blocking_notifier_unregister(&group->notifier, nb);
}

const char *iommu_group_name(struct iommu_group *group)
{
	return (group) ? group->name : NULL;
}

struct iommu_controller *iommu_group_controller(
					struct iommu_group *group)
{
	return (group) ? group->ctrl : NULL;
}

/*
 * IOMMU groups are really the natrual working unit of the IOMMU, but
 * the IOMMU API works on domains and devices.  Bridge that gap by
 * iterating over the devices in a group.  Ideally we'd have a single
 * device which represents the requestor ID of the group, but we also
 * allow IOMMU drivers to create policy defined minimum sets, where
 * the physical hardware may be able to distiguish members, but we
 * wish to group them at a higher level (ex. untrusted multi-function
 * PCI devices).  Thus we attach each device.
 */
static int iommu_group_do_attach_device(struct device *dev, void *data)
{
	struct iommu_domain *domain = data;

	if (unlikely(domain->ops->attach_dev == NULL))
		return VMM_ENODEV;

	return domain->ops->attach_dev(domain, dev);
}

static int iommu_group_do_detach_device(struct device *dev, void *data)
{
	struct iommu_domain *domain = data;

	if (unlikely(domain->ops->detach_dev == NULL))
		return VMM_ENODEV;

	domain->ops->detach_dev(domain, dev);

	return VMM_OK;
}

int iommu_group_attach_domain(struct iommu_group *group,
				  struct iommu_domain *domain)
{
	int ret = VMM_OK;

	if (!group || !domain)
		return VMM_EINVALID;

	mutex_pend(&group->mutex);

	if (group->domain == domain) {
		ret = VMM_OK;
		goto out_unlock;
	} else if (group->domain != NULL) {
		ret = VMM_EEXIST;
		goto out_unlock;
	}

	ret = iommu_group_for_each_dev(group, domain,
					 iommu_group_do_attach_device);
	if (ret)
		goto out_unlock;

	iommu_domain_ref(domain);
	group->domain = domain;

out_unlock:
	mutex_post(&group->mutex);

	return ret;
}

int iommu_group_detach_domain(struct iommu_group *group)
{
	int ret = VMM_OK;
	struct iommu_domain *domain;

	if (!group)
		return VMM_EINVALID;

	mutex_pend(&group->mutex);

	domain = group->domain;
	group->domain = NULL;
	if (!domain)
		goto out_unlock;

	ret = iommu_group_for_each_dev(group, domain,
				     iommu_group_do_detach_device);

out_unlock:
	mutex_post(&group->mutex);

	iommu_domain_dref(domain);

	return ret;
}

struct iommu_domain *iommu_group_get_domain(
					struct iommu_group *group)
{
	struct iommu_domain *domain = NULL;

	if (!group)
		return NULL;

	mutex_pend(&group->mutex);
	domain = group->domain;
	iommu_domain_ref(domain);
	mutex_post(&group->mutex);

	return domain;
}

/* =============== IOMMU Domain APIs =============== */

struct iommu_domain *iommu_domain_alloc(const char *name,
					struct bus *bus,
					struct iommu_controller *ctrl,
					unsigned int type)
{
	struct iommu_domain *domain;

	if (bus == NULL || bus->iommu_ops == NULL || ctrl == NULL)
		return NULL;

	if ((type != VMM_IOMMU_DOMAIN_BLOCKED) &&
	    (type != VMM_IOMMU_DOMAIN_IDENTITY) &&
	    (type != VMM_IOMMU_DOMAIN_UNMANAGED) &&
	    (type != VMM_IOMMU_DOMAIN_DMA))
		return NULL;

	domain = bus->iommu_ops->domain_alloc(type, ctrl);
	if (!domain)
		return NULL;

	if (strlcpy(domain->name, name, sizeof(domain->name)) >=
	    sizeof(domain->name)) {
		free(domain);
		return NULL;
	}

	INIT_LIST_HEAD(&domain->head);
	domain->type = type;
	domain->ctrl = ctrl;
	xref_init(&domain->ref_count);
	domain->bus = bus;
	domain->ops = bus->iommu_ops;

	mutex_pend(&ctrl->domains_lock);
	list_add_tail(&domain->head, &ctrl->domains);
	mutex_post(&ctrl->domains_lock);

	return domain;
}

void iommu_domain_ref(struct iommu_domain *domain)
{
	if (domain == NULL)
		return;

	xref_get(&domain->ref_count);
}

static void __iommu_domain_free(struct xref *ref)
{
	struct iommu_domain *domain =
			container_of(ref, struct iommu_domain, ref_count);

	mutex_pend(&domain->ctrl->domains_lock);
	list_del(&domain->head);
	mutex_post(&domain->ctrl->domains_lock);

	if (likely(domain->ops->domain_free != NULL))
		domain->ops->domain_free(domain);
}

void iommu_domain_free(struct iommu_domain *domain)
{
	/* a count to record the usage of the domain */
}

void iommu_set_fault_handler(struct iommu_domain *domain,
				 iommu_fault_handler_t handler,
				 void *token)
{
	BUG_ON(!domain);

	domain->handler = handler;
	domain->handler_token = token;
}

phy_addr_t iommu_iova_to_phys(struct iommu_domain *domain,
				       phy_addr_t iova)
{
	if (unlikely(domain->ops->iova_to_phys == NULL))
		return 0;

	return domain->ops->iova_to_phys(domain, iova);
}

static size_t iommu_pgsize(struct iommu_domain *domain,
			   phy_addr_t addr_merge, size_t size)
{
	unsigned int pgsize_idx;
	size_t pgsize;

	/* Max page size that still fits into 'size' */
	pgsize_idx = __fls(size);

	/* need to consider alignment requirements ? */
	if (likely(addr_merge)) {
		/* Max page size allowed by address */
		unsigned int align_pgsize_idx = __ffs(addr_merge);
		pgsize_idx = min(pgsize_idx, align_pgsize_idx);
	}

	/* build a mask of acceptable page sizes */
	pgsize = (1UL << (pgsize_idx + 1)) - 1;

	/* throw away page sizes not supported by the hardware */
	pgsize &= domain->ops->pgsize_bitmap;

	/* make sure we're still sane */
	BUG_ON(!pgsize);

	/* pick the biggest page */
	pgsize_idx = __fls(pgsize);
	pgsize = 1UL << pgsize_idx;

	return pgsize;
}

int iommu_map(struct iommu_domain *domain, phy_addr_t iova,
		  phy_addr_t paddr, size_t size, int prot)
{
	phy_addr_t orig_iova = iova;
	size_t min_pagesz;
	size_t orig_size = size;
	int ret = 0;

	if (unlikely(domain->ops->unmap == NULL ||
		     domain->ops->pgsize_bitmap == 0UL))
		return VMM_ENODEV;

	/* find out the minimum page size supported */
	min_pagesz = 1 << __ffs(domain->ops->pgsize_bitmap);

	/*
	 * both the virtual address and the physical one, as well as
	 * the size of the mapping, must be aligned (at least) to the
	 * size of the smallest page supported by the hardware
	 */
	if (!is_aligned(iova | paddr | size, min_pagesz)) {
		lerror("IOMMU", "unaligned iova 0x%"PRIPADDR
			   " pa 0x%"PRIPADDR" size 0x%zx "
			   "min_pagesz 0x%zx\n", iova, paddr,
			   size, min_pagesz);
		return VMM_EINVALID;
	}

	pr_debug("IOMMU: map iova 0x%"PRIPADDR
		 " pa 0x%"PRIPADDR" size 0x%zx\n",
		 iova, paddr, size);

	while (size) {
		size_t pgsize = iommu_pgsize(domain, iova | paddr, size);

		pr_debug("IOMMU: mapping iova 0x%"PRIPADDR
			 " pa 0x%"PRIPADDR" size 0x%zx\n",
			 iova, paddr, pgsize);

		ret = domain->ops->map(domain, iova, paddr, pgsize, prot);
		if (ret)
			break;

		iova += pgsize;
		paddr += pgsize;
		size -= pgsize;
	}

	/* unroll mapping in case something went wrong */
	if (ret)
		iommu_unmap(domain, orig_iova, orig_size - size);

	return ret;
}

size_t iommu_unmap(struct iommu_domain *domain,
			phy_addr_t iova, size_t size)
{
	size_t unmapped_page, min_pagesz, unmapped = 0;

	if (unlikely(domain->ops->unmap == NULL ||
		     domain->ops->pgsize_bitmap == 0UL))
		return VMM_ENODEV;

	/* find out the minimum page size supported */
	min_pagesz = 1 << __ffs(domain->ops->pgsize_bitmap);

	/*
	 * The virtual address, as well as the size of the mapping, must be
	 * aligned (at least) to the size of the smallest page supported
	 * by the hardware
	 */
	if (!is_aligned(iova | size, min_pagesz)) {
		lerror("IOMMU", "unaligned iova 0x%"PRIPADDR
			   " size 0x%zx min_pagesz 0x%zx\n", iova,
			   size, min_pagesz);
		return VMM_EINVALID;
	}

	pr_debug("IOMMU: unmap iova 0x%"PRIPADDR" size 0x%zx\n",
		 iova, size);

	/*
	 * Keep iterating until we either unmap 'size' bytes (or more)
	 * or we hit an area that isn't mapped.
	 */
	while (unmapped < size) {
		size_t pgsize = iommu_pgsize(domain, iova, size - unmapped);

		unmapped_page = domain->ops->unmap(domain, iova, pgsize);
		if (!unmapped_page)
			break;

		pr_debug("IOMMU: unmapped iova 0x%"PRIPADDR" size 0x%zx\n",
			 iova, unmapped_page);

		iova += unmapped_page;
		unmapped += unmapped_page;
	}

	return unmapped;
}

int iommu_domain_window_enable(struct iommu_domain *domain,
				   u32 wnd_nr, phy_addr_t paddr,
				   u64 size, int prot)
{
	if (unlikely(domain->ops->domain_window_enable == NULL))
		return VMM_ENODEV;

	return domain->ops->domain_window_enable(domain, wnd_nr,
						 paddr, size, prot);
}

void iommu_domain_window_disable(struct iommu_domain *domain,
				     u32 wnd_nr)
{
	if (unlikely(domain->ops->domain_window_disable == NULL))
		return;

	return domain->ops->domain_window_disable(domain, wnd_nr);
}

int iommu_domain_get_attr(struct iommu_domain *domain,
			      enum iommu_attr attr, void *data)
{
	struct iommu_domain_geometry *geometry;
	bool *paging;
	int ret = 0;
	u32 *count;

	switch (attr) {
	case VMM_DOMAIN_ATTR_GEOMETRY:
		geometry  = data;
		*geometry = domain->geometry;

		break;
	case VMM_DOMAIN_ATTR_PAGING:
		paging  = data;
		*paging = (domain->ops->pgsize_bitmap != 0UL);
		break;
	case VMM_DOMAIN_ATTR_WINDOWS:
		count = data;

		if (domain->ops->domain_get_windows != NULL)
			*count = domain->ops->domain_get_windows(domain);
		else
			ret = VMM_ENODEV;

		break;
	default:
		if (!domain->ops->domain_get_attr)
			return VMM_EINVALID;

		ret = domain->ops->domain_get_attr(domain, attr, data);
	}

	return ret;
}

int iommu_domain_set_attr(struct iommu_domain *domain,
			      enum iommu_attr attr, void *data)
{
	int ret = 0;
	u32 *count;

	switch (attr) {
	case VMM_DOMAIN_ATTR_WINDOWS:
		count = data;

		if (domain->ops->domain_set_windows != NULL)
			ret = domain->ops->domain_set_windows(domain, *count);
		else
			ret = VMM_ENODEV;

		break;
	default:
		if (domain->ops->domain_set_attr == NULL)
			return VMM_EINVALID;

		ret = domain->ops->domain_set_attr(domain, attr, data);
	}

	return ret;
}

static int add_iommu_group(struct device *dev, void *data)
{
	struct iommu_ops *ops = data;

	if (!ops->add_device)
		return VMM_ENODEV;

	WARN_ON(dev->iommu_group);

	ops->add_device(dev);

	return 0;
}

static void iommu_nidtbl_found(struct device_node *node, void *data)
{
	int err;
	iommu_init_t init_fn = match->data;

	if (!init_fn)
		return;

	err = init_fn(node);
	if (err) {
		pr_err("%s: Init %s node failed (error %d)\n",
			   __func__, node->name, err);
	}
}

int __init iommu_init(void)
{
	/* Probe all device tree nodes matching
	 * IOMMU nodeid table enteries.
	 */
#ifdef CONFIG_DEVICE_TREE
	of_iterate_all_node(hv_node, iommu_nidtbl_found, NULL);
#endif

	return 0;
}
