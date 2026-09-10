import datetime
import functools
import importlib
import os

from apscheduler.events import EVENT_JOB_ERROR, EVENT_JOB_EXECUTED
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

import task_lock
from logger import get_app_logger

app_logger = get_app_logger()


# ---------- TASKSMASTER CLASS ----------
class TasksMaster:

    TASK_DEFAULT_CRON = "*/15 * * * *"
    TASK_JITTER = 240
    TASKS_FOLDER = os.path.join(os.path.dirname(__file__), "tasks")

    def __init__(self, scheduler: BackgroundScheduler):
        self.tasks = self._config_tasks()
        self.scheduler = scheduler
        self.scheduler.add_listener(
            self.job_listener, EVENT_JOB_EXECUTED | EVENT_JOB_ERROR
        )

    def _config_tasks(self):
        """
        Loads tasks from the TASKS_FOLDER and logs how many were found.
        """
        tasks_defined = self._load_tasks_from_folder(self.TASKS_FOLDER)
        app_logger.info(f"Scheduled Tasks Loaded from folder: {self.TASKS_FOLDER}")
        return tasks_defined

    def _load_tasks_from_folder(self, folder_path):
        """
        Loads and registers task modules from a specified folder.

        This function scans the given folder for Python (.py) files, dynamically
        imports each as a module, and looks for two attributes:
        - TASK_CONFIG: A dictionary containing task metadata, specifically the
        'name' and 'cron' (cron schedule string).
        - main: A callable function that represents the task's execution logic.

        Tasks with both attributes are added to a list with their configuration and
        execution function.

        Args:
            folder_path (str): Path to the folder containing task scripts.

        Returns:
            list[dict]: A list of task definitions with keys:
            - 'name' (str): The name of the task.
            - 'filename' (str): The file the task was loaded from.
            - 'cron' (str): The crontab string for scheduling.
            - 'enabled' (bool): Whether the task is enabled.
            - 'run_when_loaded' (bool): Whether to run the task immediately.
        """
        tasks = []

        if not os.path.exists(folder_path):
            app_logger.error(f"{folder_path} does not exist! Unable to load tasks!")
            return tasks

        # we sort the files so that we have a set order, which helps with debugging
        for filename in sorted(os.listdir(folder_path)):

            # skip any non python files, as well as any __pycache__ or .pyc files that might creep in there
            if not filename.endswith(".py") or filename.startswith("__"):
                continue

            module_name = filename[:-3]
            try:
                module = importlib.import_module(f"tasks.{module_name}")
            except Exception as e:
                app_logger.error(f"Failed to import {filename}: {e}")
                continue

            # if we have a tasks config and a main function, we attempt to schedule it
            if hasattr(module, "TASK_CONFIG") and hasattr(module, "main"):

                # ensure task_config is a dict
                if not isinstance(module.TASK_CONFIG, dict):
                    app_logger.error(
                        f"TASK_CONFIG is not a dict in {filename}. Skipping task."
                    )
                    continue

                task_cron = module.TASK_CONFIG.get("cron") or self.TASK_DEFAULT_CRON
                task_name = module.TASK_CONFIG.get("name", module_name)

                # ensure the task_cron is a valid cron value
                try:
                    CronTrigger.from_crontab(task_cron)
                except ValueError as ve:
                    app_logger.error(
                        f"Invalid cron format for task {task_name}: {ve} - Skipping this task"
                    )
                    continue

                task = {
                    "name": module.TASK_CONFIG.get("name", module_name),
                    "filename": filename,
                    "cron": task_cron,
                    "enabled": module.TASK_CONFIG.get("enabled", False),
                    "run_when_loaded": module.TASK_CONFIG.get("run_when_loaded", False),
                    "interval_seconds": module.TASK_CONFIG.get("interval_seconds"),
                    "single_pod": module.TASK_CONFIG.get("single_pod", False),
                }

                tasks.append(task)

            # we are missing things, and we log what's missing
            else:
                if not hasattr(module, "TASK_CONFIG"):
                    app_logger.warning(f"Missing TASK_CONFIG in {filename}")
                elif not hasattr(module, "main"):
                    app_logger.warning(f"Missing main() in {filename}")

        return tasks

    def _add_jobs(self):
        # for each task in the tasks config file...
        for task_to_run in self.tasks:

            # remember, these tasks, are built from the "load_tasks_from_folder" function,
            # if you want to pass data from the TASKS_CONFIG dict, you need to pass it there to get it here.
            task_name = task_to_run.get("name")
            run_when_loaded = task_to_run.get("run_when_loaded")
            module_name = os.path.splitext(task_to_run.get("filename"))[0]
            task_enabled = task_to_run.get("enabled", False)
            interval_seconds = task_to_run.get("interval_seconds")
            single_pod = task_to_run.get("single_pod", False)

            # if no crontab set for this task, we use 15 as the default.
            task_cron = task_to_run.get("cron") or self.TASK_DEFAULT_CRON

            # if task is disabled, skip this one
            if not task_enabled:
                app_logger.info(
                    f"{task_name} is disabled in client config. Skipping task"
                )
                continue
            try:
                if os.path.isfile(
                    os.path.join(self.TASKS_FOLDER, task_to_run.get("filename"))
                ):
                    # schedule the task now that everything has checked out above...
                    self._schedule_task(
                        task_name,
                        module_name,
                        task_cron,
                        run_when_loaded,
                        interval_seconds=interval_seconds,
                        single_pod=single_pod,
                    )
                    if interval_seconds:
                        app_logger.info(
                            f"Scheduled {module_name} interval is set to {interval_seconds}s.",
                            extra={"task": task_to_run},
                        )
                    else:
                        app_logger.info(
                            f"Scheduled {module_name} cron is set to {task_cron}.",
                            extra={"task": task_to_run},
                        )
                else:
                    app_logger.info(
                        f"Skipping invalid or unsafe file: {task_to_run.get('filename')}",
                        extra={"task": task_to_run},
                    )

            except Exception as e:
                app_logger.error(
                    f"Error scheduling task: {e}", extra={"tasks": task_to_run}
                )

    @staticmethod
    def _trigger_period(trigger) -> int:
        """Seconds between two consecutive unjittered fire times of `trigger`.

        Jitter is applied by the scheduler after the trigger produces a time, so
        what this measures is the schedule's true period.
        """
        if isinstance(trigger, IntervalTrigger):
            return int(trigger.interval.total_seconds())

        now = datetime.datetime.now(trigger.timezone)
        first = trigger.get_next_fire_time(None, now)
        second = trigger.get_next_fire_time(first, first)
        return int((second - first).total_seconds())

    @classmethod
    def _lease_seconds(cls, trigger) -> int:
        """How long a single_pod task holds its claim on one occurrence.

        Two constraints pull in opposite directions. The lease must outlast
        TASK_JITTER, or a pod firing late finds it expired and runs the same
        occurrence a second time. And it must expire before the next occurrence,
        or it blocks that one too.

        Twice the jitter window satisfies the first with margin for clock skew;
        clamping to just under the period satisfies the second. A daily task
        therefore holds 480 seconds rather than 24 hours -- long enough to cover
        jitter, short enough that a leader that died leaves no day-long tombstone.
        """
        period = cls._trigger_period(trigger)
        return min(max(period - 5, 5), 2 * cls.TASK_JITTER)

    @staticmethod
    def _guarded(fn, module, job_id: str, lease_seconds: int):
        """Wrap a single_pod task so exactly one pod runs each occurrence.

        A pod that loses the claim calls the module's on_skip() when it defines
        one. That hook exists for tasks where skipping silently would leave the
        pod stale rather than merely idle: refresh_banlist adopts the leader's
        published list through it, and analyze_ips refreshes its process-local
        Prometheus gauges.
        """

        @functools.wraps(fn)
        def run(*args, **kwargs):
            if task_lock.claim(job_id, lease_seconds):
                return fn(*args, **kwargs)

            app_logger.debug(f"{job_id}: another pod holds this occurrence; skipping")
            on_skip = getattr(module, "on_skip", None)
            if on_skip is not None:
                return on_skip()
            return None

        return run

    def _schedule_task(
        self,
        task_name,
        module_name,
        task_cron,
        run_when_loaded,
        interval_seconds=None,
        single_pod=False,
    ):
        try:
            # Dynamically import the module
            module = importlib.import_module(f"tasks.{module_name}")

            # Check if the module has a 'main' function
            if hasattr(module, "main"):
                app_logger.info(f"Scheduling {task_name} - {module_name} Main Function")

                # unique_job_id
                job_identifier = f"{module_name}__{task_name}"

                # Use IntervalTrigger for sub-minute scheduling, CronTrigger otherwise
                if interval_seconds:
                    trigger = IntervalTrigger(seconds=interval_seconds)
                else:
                    if task_cron is None:
                        task_cron = self.TASK_DEFAULT_CRON
                    trigger = CronTrigger.from_crontab(task_cron)

                # The gate lives here rather than inside main(), so a manual run
                # from the maintenance panel stays unconditional.
                job_func = module.main
                if single_pod:
                    lease_seconds = self._lease_seconds(trigger)
                    job_func = self._guarded(
                        module.main, module, job_identifier, lease_seconds
                    )
                    app_logger.info(
                        f"{task_name} runs on one pod per occurrence "
                        f"({lease_seconds}s lease)"
                    )

                # schedule the task / job
                if run_when_loaded:
                    app_logger.info(
                        f"Task: {task_name} is set to run instantly. Scheduling to run on scheduler start"
                    )

                    self.scheduler.add_job(
                        job_func,
                        trigger,
                        id=job_identifier,
                        jitter=self.TASK_JITTER,
                        name=task_name,
                        next_run_time=datetime.datetime.now(),
                        max_instances=1,
                    )
                else:
                    self.scheduler.add_job(
                        job_func,
                        trigger,
                        id=job_identifier,
                        jitter=self.TASK_JITTER,
                        name=task_name,
                        max_instances=1,
                    )
            else:
                app_logger.error(f"{module_name} does not define a 'main' function.")

        except Exception as e:
            app_logger.error(f"Failed to load {module_name}: {e}")

    def job_listener(self, event):
        if event.exception:
            app_logger.error(f"Job {event.job_id} failed: {event.exception}")
        else:
            app_logger.info(f"Job {event.job_id} completed successfully.")

    def run_scheduled_tasks(self):
        """
        Runs and schedules enabled tasks using the background scheduler.

        This method performs the following:
        1. Retrieves the current task configurations and updates internal state.
        2. Adds new jobs to the scheduler based on the latest configuration.
        3. Starts the scheduler to begin executing tasks at their defined intervals.

        This ensures the scheduler is always running with the most up-to-date
        task definitions and enabled status.
        """

        # Add enabled tasks to the scheduler
        self._add_jobs()

        # Start the scheduler to begin executing the scheduled tasks (if not already running)
        if not self.scheduler.running:
            self.scheduler.start()


# ---------- SINGLETON WRAPPER ----------
@functools.cache
def get_tasksmaster() -> TasksMaster:
    """Return the singleton TasksMaster, with its scheduler started."""
    scheduler = BackgroundScheduler()
    tm_instance = TasksMaster(scheduler)
    scheduler.start()
    app_logger.info("TasksMaster scheduler started.")
    return tm_instance
