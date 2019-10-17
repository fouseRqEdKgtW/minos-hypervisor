#ifndef __MINOS_MEM_ATTR_H__
#define __MINOS_MEM_ATTR_H__

#define GVM_PGD_PAGE_NR		(__GVM_PGD_PAGE_NR)
#define GVM_PGD_PAGE_ALIGN	(__GVM_PGD_PAGE_ALIGN)

#define MEM_TYPE_SHARED		0
#define MEM_TYPE_IO		1
#define MEM_TYPE_NORMAL		2

#define VM_NONE			(0x00000000)
#define VM_IO			(0x00000001)
#define VM_NORMAL		(0x00000002)
#define VM_SHMEM		(0x00000004)
#define VM_TYPE_MASK		(0x000000ff)

#define VM_DES_FAULT		(0x00000000)
#define VM_DES_BLOCK		(0x00000100)
#define VM_DES_PAGE		(0x00000200)
#define VM_DES_TABLE		(0x00000400)
#define VM_DES_MASK		(0x00000f00)

#define VM_HOST			(0x00001000)

#define VM_FORCE_4K		(0x00010000)
#define VM_FORCE_2M		(0x00020000)
#define VM_FORCE_1G		(0x00040000)

/* the default acess type is 0 means RW */
#define VM_RO			(0x00100000)
#define VM_WO			(0x00200000)
#define VM_RW_MASK		(0x00300000)

#define VM_PT			(0x01000000)	/* mapped as passthough only for IO memory*/
#define VM_BK			(0X02000000)	/* mapped as block */
#define VM_PG			(0x04000000)	/* mapped as page */
#define VM_LN			(0x08000000)	/* mapped as liner */
#define VM_MAP_TYPE_MASK	(0x0f000000)

#define MEM_REGION_NAME_SIZE	32

#define PGD			(0)
#define PUD			(1)
#define PMD			(2)
#define PTE			(3)

#define MAX_MEM_SECTIONS	(32)
#define MEM_BLOCK_SIZE		(0x200000)
#define MEM_BLOCK_SHIFT		(21)
#define PAGES_IN_BLOCK		(MEM_BLOCK_SIZE >> PAGE_SHIFT)

#define PAGE_NR(size)		(size >> PAGE_SHIFT)
#define __PAGE_MASK		(~((1UL << PAGE_SHIFT) - 1))
#define __BLOCK_MASK		(~((1UL << MEM_BLOCK_SHIFT) - 1))

#define GFB_SLAB		(1 << 0)
#define GFB_PAGE		(1 << 1)
#define GPF_PAGE_META		(1 << 2)
#define GFB_VM			(1 << 3)
#define GFB_IO			(1 << 4)
#define GFB_FIXED		(1 << 5)

#define GFB_SLAB_BIT		(0)
#define GFB_PAGE_BIT		(1)
#define GFB_PAGE_META_BIT	(2)
#define GFB_VM_BIT		(3)
#define GFB_IO_BIT		(4)
#define GFB_FIXED_BIT		(5)

#define GFB_MASK		(0xffff)

#endif
