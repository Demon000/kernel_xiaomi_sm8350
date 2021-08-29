// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2016-2020, The Linux Foundation. All rights reserved.
 * Copyright (C) 2020 XiaoMi, Inc.
 */

#include <linux/init.h>
#include <linux/notifier.h>
#include <linux/cpu.h>
#include <linux/moduleparam.h>
#include <linux/cpumask.h>
#include <linux/cpufreq.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/tick.h>
#include <trace/events/power.h>
#include <linux/sysfs.h>
#include <linux/module.h>
#include <linux/input.h>
#include <linux/kthread.h>
#include <linux/sched/core_ctl.h>
#include <soc/qcom/msm_performance.h>
#include <linux/spinlock.h>
#include <linux/circ_buf.h>
#include <linux/ktime.h>
#include <linux/perf_event.h>
#include <linux/errno.h>
#include <linux/topology.h>

#define POLL_INT 25
#define NODE_NAME_MAX_CHARS 16

#ifdef CONFIG_MSM_PERFORMANCE_QGKI
#define QUEUE_POOL_SIZE 512 /*2^8 always keep in 2^x */
#define INST_EV 0x08 /* 0th event*/
#define CYC_EV 0x11 /* 1st event*/
#define INIT "Init"
static DEFINE_PER_CPU(bool, cpu_is_idle);
static DEFINE_PER_CPU(bool, cpu_is_hp);

enum event_idx {
	INST_EVENT,
	CYC_EVENT,
	NO_OF_EVENT
};
#endif

enum cpu_clusters {
	MIN = 0,
	MID = 1,
	MAX = 2,
	CLUSTER_MAX
};

/* To handle cpufreq min/max request */
struct cpu_status {
	unsigned int min;
	unsigned int max;
};
static DEFINE_PER_CPU(struct cpu_status, msm_perf_cpu_stats);
static DEFINE_PER_CPU(struct freq_qos_request, qos_req_min);
static DEFINE_PER_CPU(struct freq_qos_request, qos_req_max);

static cpumask_var_t limit_mask_min;
static cpumask_var_t limit_mask_max;

#ifdef CONFIG_MSM_PERFORMANCE_QGKI
static DECLARE_COMPLETION(gfx_evt_arrival);

struct gpu_data {
	pid_t pid;
	int ctx_id;
	unsigned int timestamp;
	ktime_t arrive_ts;
	int evt_typ;
};

static struct gpu_data gpu_circ_buff[QUEUE_POOL_SIZE];

struct queue_indicies {
	int head;
	int tail;
};
static struct queue_indicies curr_pos;

static DEFINE_SPINLOCK(gfx_circ_buff_lock);

static struct event_data {
	struct perf_event *pevent;
	u64 prev_count;
	u64 cur_delta;
	u64 cached_total_count;
} pmu_events[NO_OF_EVENT][NR_CPUS];

struct events {
	spinlock_t cpu_hotplug_lock;
	bool cpu_hotplug;
	bool init_success;
};
static struct events events_group;
static struct task_struct *events_notify_thread;

static unsigned int aggr_big_nr;
static unsigned int aggr_top_load;
static unsigned int top_load[CLUSTER_MAX];
static unsigned int curr_cap[CLUSTER_MAX];
static bool max_cap_cpus[NR_CPUS];

static atomic_t game_status;
static atomic_t game_status_pid;
#endif
static bool ready_for_freq_updates;

static int freq_qos_request_init(void)
{
	unsigned int cpu;
	int ret;

	struct cpufreq_policy *policy;
	struct freq_qos_request *req;

	for_each_present_cpu(cpu) {
		policy = cpufreq_cpu_get(cpu);
		if (!policy) {
			pr_err("%s: Failed to get cpufreq policy for cpu%d\n",
				__func__, cpu);
			ret = -EAGAIN;
			goto cleanup;
		}
		per_cpu(msm_perf_cpu_stats, cpu).min = 0;
		req = &per_cpu(qos_req_min, cpu);
		ret = freq_qos_add_request(&policy->constraints, req,
			FREQ_QOS_MIN, FREQ_QOS_MIN_DEFAULT_VALUE);
		if (ret < 0) {
			pr_err("%s: Failed to add min freq constraint (%d)\n",
				__func__, ret);
			cpufreq_cpu_put(policy);
			goto cleanup;
		}

		per_cpu(msm_perf_cpu_stats, cpu).max = UINT_MAX;
		req = &per_cpu(qos_req_max, cpu);
		ret = freq_qos_add_request(&policy->constraints, req,
			FREQ_QOS_MAX, FREQ_QOS_MAX_DEFAULT_VALUE);
		if (ret < 0) {
			pr_err("%s: Failed to add max freq constraint (%d)\n",
				__func__, ret);
			cpufreq_cpu_put(policy);
			goto cleanup;
		}

		cpufreq_cpu_put(policy);
	}
	return 0;

cleanup:
	for_each_present_cpu(cpu) {
		req = &per_cpu(qos_req_min, cpu);
		if (req && freq_qos_request_active(req))
			freq_qos_remove_request(req);


		req = &per_cpu(qos_req_max, cpu);
		if (req && freq_qos_request_active(req))
			freq_qos_remove_request(req);

		per_cpu(msm_perf_cpu_stats, cpu).min = 0;
		per_cpu(msm_perf_cpu_stats, cpu).max = UINT_MAX;
	}
	return ret;
}

/*******************************sysfs start************************************/
static int set_cpu_min_freq(const char *buf, const struct kernel_param *kp)
{
	int i, j, ntokens = 0;
	unsigned int val, cpu;
	const char *cp = buf;
	struct cpu_status *i_cpu_stats;
	struct cpufreq_policy policy;
	struct freq_qos_request *req;
	int ret = 0;

	if (!ready_for_freq_updates) {
		ret = freq_qos_request_init();
		if (ret) {
			pr_err("%s: Failed to init qos requests policy for ret=%d\n",
				__func__, ret);
			return ret;
		}
		ready_for_freq_updates = true;
	}

	while ((cp = strpbrk(cp + 1, " :")))
		ntokens++;

	/* CPU:value pair */
	if (!(ntokens % 2))
		return -EINVAL;

	cp = buf;
	cpumask_clear(limit_mask_min);
	for (i = 0; i < ntokens; i += 2) {
		if (sscanf(cp, "%u:%u", &cpu, &val) != 2)
			return -EINVAL;
		if (cpu > (num_present_cpus() - 1))
			return -EINVAL;

		i_cpu_stats = &per_cpu(msm_perf_cpu_stats, cpu);

		i_cpu_stats->min = val;
		cpumask_set_cpu(cpu, limit_mask_min);

		cp = strnchr(cp, strlen(cp), ' ');
		cp++;
	}

	/*
	 * Since on synchronous systems policy is shared amongst multiple
	 * CPUs only one CPU needs to be updated for the limit to be
	 * reflected for the entire cluster. We can avoid updating the policy
	 * of other CPUs in the cluster once it is done for at least one CPU
	 * in the cluster
	 */
	get_online_cpus();
	for_each_cpu(i, limit_mask_min) {
		i_cpu_stats = &per_cpu(msm_perf_cpu_stats, i);

		if (cpufreq_get_policy(&policy, i))
			continue;

		if (cpu_online(i) && (policy.min != i_cpu_stats->min)) {
			req = &per_cpu(qos_req_min, i);
			if (freq_qos_update_request(req, i_cpu_stats->min) < 0)
				break;
		}

		for_each_cpu(j, policy.related_cpus)
			cpumask_clear_cpu(j, limit_mask_min);
	}
	put_online_cpus();

	return 0;
}

static int get_cpu_min_freq(char *buf, const struct kernel_param *kp)
{
	int cnt = 0, cpu;

	for_each_present_cpu(cpu) {
		cnt += scnprintf(buf + cnt, PAGE_SIZE - cnt,
				"%d:%u ", cpu,
				per_cpu(msm_perf_cpu_stats, cpu).min);
	}
	cnt += scnprintf(buf + cnt, PAGE_SIZE - cnt, "\n");
	return cnt;
}

static const struct kernel_param_ops param_ops_cpu_min_freq = {
	.set = set_cpu_min_freq,
	.get = get_cpu_min_freq,
};
module_param_cb(cpu_min_freq, &param_ops_cpu_min_freq, NULL, 0644);

static int set_cpu_max_freq(const char *buf, const struct kernel_param *kp)
{
	int i, j, ntokens = 0;
	unsigned int val, cpu;
	const char *cp = buf;
	struct cpu_status *i_cpu_stats;
	struct cpufreq_policy policy;
	struct freq_qos_request *req;
	int ret = 0;

	if (!ready_for_freq_updates) {
		ret = freq_qos_request_init();
		if (ret) {
			pr_err("%s: Failed to init qos requests policy for ret=%d\n",
				__func__, ret);
			return ret;
		}
		ready_for_freq_updates = true;
	}

	while ((cp = strpbrk(cp + 1, " :")))
		ntokens++;

	/* CPU:value pair */
	if (!(ntokens % 2))
		return -EINVAL;

	cp = buf;
	cpumask_clear(limit_mask_max);
	for (i = 0; i < ntokens; i += 2) {
		if (sscanf(cp, "%u:%u", &cpu, &val) != 2)
			return -EINVAL;
		if (cpu > (num_present_cpus() - 1))
			return -EINVAL;

		i_cpu_stats = &per_cpu(msm_perf_cpu_stats, cpu);

		i_cpu_stats->max = val;
		cpumask_set_cpu(cpu, limit_mask_max);

		cp = strnchr(cp, strlen(cp), ' ');
		cp++;
	}

	get_online_cpus();
	for_each_cpu(i, limit_mask_max) {
		i_cpu_stats = &per_cpu(msm_perf_cpu_stats, i);
		if (cpufreq_get_policy(&policy, i))
			continue;

		if (cpu_online(i) && (policy.max != i_cpu_stats->max)) {
			req = &per_cpu(qos_req_max, i);
			if (freq_qos_update_request(req, i_cpu_stats->max) < 0)
				break;
		}

		for_each_cpu(j, policy.related_cpus)
			cpumask_clear_cpu(j, limit_mask_max);
	}
	put_online_cpus();

	return 0;
}

static int get_cpu_max_freq(char *buf, const struct kernel_param *kp)
{
	int cnt = 0, cpu;

	for_each_present_cpu(cpu) {
		cnt += scnprintf(buf + cnt, PAGE_SIZE - cnt,
				"%d:%u ", cpu,
				per_cpu(msm_perf_cpu_stats, cpu).max);
	}
	cnt += scnprintf(buf + cnt, PAGE_SIZE - cnt, "\n");
	return cnt;
}

static const struct kernel_param_ops param_ops_cpu_max_freq = {
	.set = set_cpu_max_freq,
	.get = get_cpu_max_freq,
};
module_param_cb(cpu_max_freq, &param_ops_cpu_max_freq, NULL, 0644);
#ifdef CONFIG_MSM_PERFORMANCE_QGKI
static struct kobject *events_kobj;

static ssize_t show_cpu_hotplug(struct kobject *kobj,
					struct kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "\n");
}
static struct kobj_attribute cpu_hotplug_attr =
__ATTR(cpu_hotplug, 0444, show_cpu_hotplug, NULL);

static struct attribute *events_attrs[] = {
	&cpu_hotplug_attr.attr,
	NULL,
};

static struct attribute_group events_attr_group = {
	.attrs = events_attrs,
};

static ssize_t show_perf_gfx_evts(struct kobject *kobj,
			   struct kobj_attribute *attr,
			   char *buf)
{
	struct queue_indicies updated_pos;
	unsigned long flags;
	ssize_t retval = 0;
	int idx = 0, size, act_idx, ret = -1;

	ret = wait_for_completion_interruptible(&gfx_evt_arrival);
	if (ret)
		return 0;
	spin_lock_irqsave(&gfx_circ_buff_lock, flags);
	updated_pos.head = curr_pos.head;
	updated_pos.tail = curr_pos.tail;
	size = CIRC_CNT(updated_pos.head, updated_pos.tail, QUEUE_POOL_SIZE);
	curr_pos.tail = (curr_pos.tail + size) % QUEUE_POOL_SIZE;
	spin_unlock_irqrestore(&gfx_circ_buff_lock, flags);

	for (idx = 0; idx < size; idx++) {
		act_idx = (updated_pos.tail + idx) % QUEUE_POOL_SIZE;
		retval += scnprintf(buf + retval, PAGE_SIZE - retval,
			  "%d %d %u %d %lu :",
			  gpu_circ_buff[act_idx].pid,
			  gpu_circ_buff[act_idx].ctx_id,
			  gpu_circ_buff[act_idx].timestamp,
			  gpu_circ_buff[act_idx].evt_typ,
			  ktime_to_us(gpu_circ_buff[act_idx].arrive_ts));
		if (retval >= PAGE_SIZE) {
			pr_err("msm_perf:data limit exceed\n");
			break;
		}
	}
	return retval;
}

static struct kobj_attribute gfx_event_info_attr =
__ATTR(gfx_evt, 0444, show_perf_gfx_evts, NULL);

static ssize_t show_big_nr(struct kobject *kobj,
			   struct kobj_attribute *attr,
			   char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%u\n", aggr_big_nr);
}

static struct kobj_attribute big_nr_attr =
__ATTR(aggr_big_nr, 0444, show_big_nr, NULL);

static ssize_t show_top_load(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%u\n", aggr_top_load);
}

static struct kobj_attribute top_load_attr =
__ATTR(aggr_top_load, 0444, show_top_load, NULL);


static ssize_t show_top_load_cluster(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%u %u %u\n",
					top_load[MIN], top_load[MID],
					top_load[MAX]);
}

static struct kobj_attribute cluster_top_load_attr =
__ATTR(top_load_cluster, 0444, show_top_load_cluster, NULL);

static ssize_t show_curr_cap_cluster(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%u %u %u\n",
					curr_cap[MIN], curr_cap[MID],
					curr_cap[MAX]);
}

static struct kobj_attribute cluster_curr_cap_attr =
__ATTR(curr_cap_cluster, 0444, show_curr_cap_cluster, NULL);

static struct attribute *notify_attrs[] = {
	&big_nr_attr.attr,
	&top_load_attr.attr,
	&cluster_top_load_attr.attr,
	&cluster_curr_cap_attr.attr,
	&gfx_event_info_attr.attr,
	NULL,
};

static struct attribute_group notify_attr_group = {
	.attrs = notify_attrs,
};
static struct kobject *notify_kobj;

/*******************************sysfs ends************************************/

/*****************PMU Data Collection*****************/
static struct perf_event_attr *msm_perf_alloc_attr(void)
{
	struct perf_event_attr *attr = NULL;

	attr = kzalloc(sizeof(struct perf_event_attr), GFP_KERNEL);
	if (!attr)
		return attr;

	attr->type = PERF_TYPE_RAW;
	attr->size = sizeof(struct perf_event_attr);
	attr->pinned = 1;

	return attr;
}

static int set_event(struct event_data *ev, int cpu,
					 struct perf_event_attr *attr)
{
	struct perf_event *pevent;

	pevent = perf_event_create_kernel_counter(attr,
				cpu, NULL, NULL, NULL);
	if (IS_ERR(pevent)) {
		pr_err("msm_perf: %s failed, eventId:0x%x, cpu:%d, error code:%ld\n",
				__func__, attr->config, cpu, PTR_ERR(pevent));
		return PTR_ERR(pevent);
	}
	ev->pevent = pevent;
	perf_event_enable(pevent);

	return 0;
}

static void free_pmu_counters(unsigned int cpu)
{
	int i = 0;

	for (i = 0; i < NO_OF_EVENT; i++) {
		pmu_events[i][cpu].prev_count = 0;
		pmu_events[i][cpu].cur_delta = 0;
		pmu_events[i][cpu].cached_total_count = 0;
		if (pmu_events[i][cpu].pevent) {
			perf_event_disable(pmu_events[i][cpu].pevent);
			perf_event_release_kernel(pmu_events[i][cpu].pevent);
			pmu_events[i][cpu].pevent = NULL;
		}
	}
}

static int init_pmu_counter(void)
{
	struct perf_event_attr *attr = msm_perf_alloc_attr();
	int cpu;
	unsigned long cpu_capacity[NR_CPUS];
	unsigned long min_cpu_capacity = ULONG_MAX;
	int ret = 0;

	if (!attr)
		return -ENOMEM;

	/* Create events per CPU */
	for_each_possible_cpu(cpu) {
		/* create Instruction event */
		attr->config = INST_EV;
		ret = set_event(&pmu_events[INST_EVENT][cpu], cpu, attr);
		if (ret < 0) {
			kfree(attr);
			return ret;
		}
		/* create cycle event */
		attr->config = CYC_EV;
		ret = set_event(&pmu_events[CYC_EVENT][cpu], cpu, attr);
		if (ret < 0) {
			free_pmu_counters(cpu);
			kfree(attr);
			return ret;
		}
		/* find capacity per cpu */
		cpu_capacity[cpu] = arch_scale_cpu_capacity(cpu);
		if (cpu_capacity[cpu] < min_cpu_capacity)
			min_cpu_capacity = cpu_capacity[cpu];
	}

	/* determine cpu index for maximum capacity cpus */
	for_each_possible_cpu(cpu) {
		if (cpu_capacity[cpu] > min_cpu_capacity)
			max_cap_cpus[cpu] = true;
	}

	kfree(attr);
	return 0;
}

static inline void msm_perf_read_event(struct event_data *event)
{
	u64 ev_count = 0;
	u64 total, enabled, running;

	if (!event->pevent)
		return;

	if (!per_cpu(cpu_is_idle, event->pevent->cpu) &&
				!per_cpu(cpu_is_hp, event->pevent->cpu))
		total = perf_event_read_value(event->pevent, &enabled, &running);
	else
		total = event->cached_total_count;

	ev_count = total - event->prev_count;
	event->prev_count = total;
	event->cur_delta = ev_count;

}

static int get_cpu_total_instruction(char *buf, const struct kernel_param *kp)
{
	u64 instruction = 0;
	u64 cycles = 0;
	u64 total_inst_big = 0;
	u64 total_inst_little = 0;
	u64 ipc_big = 0;
	u64 ipc_little = 0;
	int cnt = 0, cpu;

	for_each_possible_cpu(cpu) {
		/* Read Instruction event */
		msm_perf_read_event(&pmu_events[INST_EVENT][cpu]);
		/* Read Cycle event */
		msm_perf_read_event(&pmu_events[CYC_EVENT][cpu]);
		instruction = pmu_events[INST_EVENT][cpu].cur_delta;
		cycles = pmu_events[CYC_EVENT][cpu].cur_delta;
		/* collecting max inst and ipc for max cap and min cap cpus */
		if (max_cap_cpus[cpu]) {
			if (cycles)
				ipc_big = max(ipc_big,
						((instruction*100)/cycles));
			total_inst_big += instruction;
		} else {
			if (cycles)
				ipc_little = max(ipc_little,
						((instruction*100)/cycles));
			total_inst_little += instruction;
		}
	}

	cnt += scnprintf(buf, PAGE_SIZE, "%llu:%llu:%llu:%llu\n",
			total_inst_big, ipc_big,
			total_inst_little, ipc_little);

	return cnt;
}

static const struct kernel_param_ops param_ops_cpu_total_instruction = {
	.set = NULL,
	.get = get_cpu_total_instruction,
};
module_param_cb(inst, &param_ops_cpu_total_instruction, NULL, 0444);


static int restart_events(unsigned int cpu, bool cpu_up)
{
	struct perf_event_attr *attr = msm_perf_alloc_attr();
	int ret = 0;

	if (!attr)
		return -ENOMEM;

	if (cpu_up) {
		/* create Instruction event */
		attr->config = INST_EV;
		ret = set_event(&pmu_events[INST_EVENT][cpu], cpu, attr);
		if (ret < 0) {
			kfree(attr);
			return ret;
		}
		/* create cycle event */
		attr->config = CYC_EV;
		ret = set_event(&pmu_events[CYC_EVENT][cpu], cpu, attr);
		if (ret < 0) {
			free_pmu_counters(cpu);
			kfree(attr);
			return ret;
		}
	} else {
		free_pmu_counters(cpu);
	}

	kfree(attr);
	return 0;
}

static int hotplug_notify_down(unsigned int cpu)
{
	unsigned long flags;

	if (events_group.init_success) {
		spin_lock_irqsave(&(events_group.cpu_hotplug_lock), flags);
		per_cpu(cpu_is_hp, cpu) = true;
		restart_events(cpu, false);
		spin_unlock_irqrestore(&(events_group.cpu_hotplug_lock), flags);
	}

	return 0;
}

static int hotplug_notify_up(unsigned int cpu)
{
	unsigned long flags;

	if (events_group.init_success) {
		spin_lock_irqsave(&(events_group.cpu_hotplug_lock), flags);
		events_group.cpu_hotplug = true;
		restart_events(cpu, true);
		per_cpu(cpu_is_hp, cpu) = false;
		spin_unlock_irqrestore(&(events_group.cpu_hotplug_lock), flags);
		wake_up_process(events_notify_thread);
	}

	return 0;
}

static int msm_perf_idle_read_events(unsigned int cpu)
{
	int ret = 0, i;

	for (i = 0; i < NO_OF_EVENT; i++) {
		if (pmu_events[i][cpu].pevent)
			ret = perf_event_read_local(pmu_events[i][cpu].pevent,
					&pmu_events[i][cpu].cached_total_count, NULL, NULL);
	}

	return ret;
}

static int msm_perf_idle_notif(struct notifier_block *nb, unsigned long action,
							void *data)
{
	int ret = NOTIFY_OK;
	int cpu = smp_processor_id();

	switch (action) {
	case IDLE_START:
		__this_cpu_write(cpu_is_idle, true);
		if (!per_cpu(cpu_is_hp, cpu))
			ret = msm_perf_idle_read_events(cpu);
		break;
	case IDLE_END:
		__this_cpu_write(cpu_is_idle, false);
		break;
	}
	return NOTIFY_OK;
}

static struct notifier_block msm_perf_event_idle_nb = {
	.notifier_call = msm_perf_idle_notif,
};

static int events_notify_userspace(void *data)
{
	unsigned long flags;
	bool notify_change;

	while (1) {

		set_current_state(TASK_INTERRUPTIBLE);
		spin_lock_irqsave(&(events_group.cpu_hotplug_lock), flags);

		if (!events_group.cpu_hotplug) {
			spin_unlock_irqrestore(&(events_group.cpu_hotplug_lock),
									flags);

			schedule();
			if (kthread_should_stop())
				break;
			spin_lock_irqsave(&(events_group.cpu_hotplug_lock),
									flags);
		}

		set_current_state(TASK_RUNNING);
		notify_change = events_group.cpu_hotplug;
		events_group.cpu_hotplug = false;
		spin_unlock_irqrestore(&(events_group.cpu_hotplug_lock), flags);

		if (notify_change)
			sysfs_notify(events_kobj, NULL, "cpu_hotplug");
	}

	return 0;
}

static int init_notify_group(void)
{
	int ret;
	struct kobject *module_kobj;

	module_kobj = kset_find_obj(module_kset, KBUILD_MODNAME);
	if (!module_kobj) {
		pr_err("msm_perf: Couldn't find module kobject\n");
		return -ENOENT;
	}

	notify_kobj = kobject_create_and_add("notify", module_kobj);
	if (!notify_kobj) {
		pr_err("msm_perf: Failed to add notify_kobj\n");
		return -ENOMEM;
	}

	ret = sysfs_create_group(notify_kobj, &notify_attr_group);
	if (ret) {
		kobject_put(notify_kobj);
		pr_err("msm_perf: Failed to create sysfs\n");
		return ret;
	}
	return 0;
}

static int init_events_group(void)
{
	int ret;
	struct kobject *module_kobj;

	module_kobj = kset_find_obj(module_kset, KBUILD_MODNAME);
	if (!module_kobj) {
		pr_err("msm_perf: Couldn't find module kobject\n");
		return -ENOENT;
	}

	events_kobj = kobject_create_and_add("events", module_kobj);
	if (!events_kobj) {
		pr_err("msm_perf: Failed to add events_kobj\n");
		return -ENOMEM;
	}

	ret = sysfs_create_group(events_kobj, &events_attr_group);
	if (ret) {
		pr_err("msm_perf: Failed to create sysfs\n");
		return ret;
	}

	spin_lock_init(&(events_group.cpu_hotplug_lock));
	events_notify_thread = kthread_run(events_notify_userspace,
					NULL, "msm_perf:events_notify");
	if (IS_ERR(events_notify_thread))
		return PTR_ERR(events_notify_thread);

	events_group.init_success = true;

	return 0;
}

static void nr_notify_userspace(struct work_struct *work)
{
	sysfs_notify(notify_kobj, NULL, "aggr_top_load");
	sysfs_notify(notify_kobj, NULL, "aggr_big_nr");
	sysfs_notify(notify_kobj, NULL, "top_load_cluster");
	sysfs_notify(notify_kobj, NULL, "curr_cap_cluster");
}

static int msm_perf_core_ctl_notify(struct notifier_block *nb,
					unsigned long unused,
					void *data)
{
	static unsigned int tld, nrb, i;
	static unsigned int top_ld[CLUSTER_MAX], curr_cp[CLUSTER_MAX];
	static DECLARE_WORK(sysfs_notify_work, nr_notify_userspace);
	struct core_ctl_notif_data *d = data;
	int cluster = 0;

	nrb += d->nr_big;
	tld += d->coloc_load_pct;
	for (cluster = 0; cluster < CLUSTER_MAX; cluster++) {
		top_ld[cluster] += d->ta_util_pct[cluster];
		curr_cp[cluster] += d->cur_cap_pct[cluster];
	}
	i++;
	if (i == POLL_INT) {
		aggr_big_nr = ((nrb%POLL_INT) ? 1 : 0) + nrb/POLL_INT;
		aggr_top_load = tld/POLL_INT;
		for (cluster = 0; cluster < CLUSTER_MAX; cluster++) {
			top_load[cluster] = top_ld[cluster]/POLL_INT;
			curr_cap[cluster] = curr_cp[cluster]/POLL_INT;
			top_ld[cluster] = 0;
			curr_cp[cluster] = 0;
		}
		tld = 0;
		nrb = 0;
		i = 0;
		schedule_work(&sysfs_notify_work);
	}
	return NOTIFY_OK;
}

static struct notifier_block msm_perf_nb = {
	.notifier_call = msm_perf_core_ctl_notify
};

static bool core_ctl_register;
static int set_core_ctl_register(const char *buf, const struct kernel_param *kp)
{
	int ret;
	bool old_val = core_ctl_register;

	ret = param_set_bool(buf, kp);
	if (ret < 0)
		return ret;

	if (core_ctl_register == old_val)
		return 0;

	if (core_ctl_register)
		core_ctl_notifier_register(&msm_perf_nb);
	else
		core_ctl_notifier_unregister(&msm_perf_nb);

	return 0;
}

static const struct kernel_param_ops param_ops_cc_register = {
	.set = set_core_ctl_register,
	.get = param_get_bool,
};
module_param_cb(core_ctl_register, &param_ops_cc_register,
		&core_ctl_register, 0644);

void  msm_perf_events_update(enum evt_update_t update_typ,
			enum gfx_evt_t evt_typ, pid_t pid,
			uint32_t ctx_id, uint32_t timestamp)
{
	unsigned long flags;
	int idx = 0;

	if (update_typ != MSM_PERF_GFX)
		return;

	if (!atomic_read(&game_status) ||
	(pid != atomic_read(&game_status_pid)))
		return;

	spin_lock_irqsave(&gfx_circ_buff_lock, flags);
	idx = curr_pos.head;
	curr_pos.head = ((curr_pos.head + 1) % QUEUE_POOL_SIZE);
	spin_unlock_irqrestore(&gfx_circ_buff_lock, flags);
	gpu_circ_buff[idx].pid = pid;
	gpu_circ_buff[idx].ctx_id = ctx_id;
	gpu_circ_buff[idx].timestamp = timestamp;
	gpu_circ_buff[idx].evt_typ = evt_typ;
	gpu_circ_buff[idx].arrive_ts = ktime_get();

	if (evt_typ == MSM_PERF_QUEUE || evt_typ == MSM_PERF_RETIRED)
		complete(&gfx_evt_arrival);
}



static int set_game_start_event(const char *buf, const struct kernel_param *kp)
{
	long usr_val = 0;
	int ret = strlen(buf);

	kstrtol(buf, 0, &usr_val);
	atomic_set(&game_status, usr_val);
	return ret;
}

static int get_game_start_event(char *buf, const struct kernel_param *kp)
{
	long usr_val  = atomic_read(&game_status);

	return scnprintf(buf, PAGE_SIZE, "%ld\n", usr_val);
}

static const struct kernel_param_ops param_ops_game_start_evt = {
	.set = set_game_start_event,
	.get = get_game_start_event,
};
module_param_cb(evnt_gplaf_status, &param_ops_game_start_evt, NULL, 0644);

static int set_game_start_pid(const char *buf, const struct kernel_param *kp)
{
	long usr_val = 0;
	int ret = strlen(buf);

	kstrtol(buf, 0, &usr_val);
	atomic_set(&game_status_pid, usr_val);
	return ret;
}

static int get_game_start_pid(char *buf, const struct kernel_param *kp)
{
	long usr_val  = atomic_read(&game_status_pid);

	return scnprintf(buf, PAGE_SIZE, "%ld\n", usr_val);
}

static const struct kernel_param_ops param_ops_game_start_pid = {
	.set = set_game_start_pid,
	.get = get_game_start_pid,
};
module_param_cb(evnt_gplaf_pid, &param_ops_game_start_pid, NULL, 0644);

/*******************************GFX Call************************************/

static int splh_notif;
static void init_splh_notif(const char *buf)
{
	/*buf contains the init info from user*/
	if (buf == NULL)
		return;

	pr_debug("msm_perf:Init info for scroll :: %s\n", buf);
}

static void activate_splh_notif(void)
{
	/*received event notification here*/
}

static int set_splh_notif(const char *buf, const struct kernel_param *kp)
{
	int ret;

	if (strnstr(buf, INIT, sizeof(INIT)) != NULL) {
		init_splh_notif(buf);
		return 0;
	}

	ret = param_set_int(buf, kp);
	if (ret < 0)
		return ret;

	activate_splh_notif();

	return ret;
}

static const struct kernel_param_ops param_ops_splh_notification = {
	.set = set_splh_notif,
	.get = param_get_int,
};
module_param_cb(splh_notif, &param_ops_splh_notification, &splh_notif, 0644);

#endif /* CONFIG_MSM_PERFORMANCE_QGKI */
static int __init msm_performance_init(void)
{
#ifdef CONFIG_MSM_PERFORMANCE_QGKI
	unsigned int cpu;
	int ret;
#endif
	if (!alloc_cpumask_var(&limit_mask_min, GFP_KERNEL))
		return -ENOMEM;

	if (!alloc_cpumask_var(&limit_mask_max, GFP_KERNEL)) {
		free_cpumask_var(limit_mask_min);
		return -ENOMEM;
	}
#ifdef CONFIG_MSM_PERFORMANCE_QGKI
	get_online_cpus();
	for_each_possible_cpu(cpu) {
		if (!cpumask_test_cpu(cpu, cpu_online_mask))
			per_cpu(cpu_is_hp, cpu) = true;
	}

	ret = cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN,
		"msm_performance_cpu_hotplug",
		hotplug_notify_up,
		hotplug_notify_down);

	put_online_cpus();

	init_events_group();
	init_notify_group();
	init_pmu_counter();

	idle_notifier_register(&msm_perf_event_idle_nb);
#endif
	return 0;
}
MODULE_LICENSE("GPL v2");
late_initcall(msm_performance_init);
