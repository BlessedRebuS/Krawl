import os
import sys
import datetime
import functools
import threading
import importlib
import importlib.util

from logger import (
    initialize_logging,
    get_app_logger,
    get_access_logger,
    get_credential_logger,
)

app_logger = get_app_logger()

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger
    from apscheduler.events import EVENT_JOB_EXECUTED, EVENT_JOB_ERROR
except ModuleNotFoundError:
    msg = (
        "Required modules are not installed. "
        "Can not continue with module / application loading.\n"
        "Install it with: pip install -r requirements"
    )
    print(msg, file=sys.stderr)
    app_logger.error(msg)
    exit()


# ---------- TASKSMASTER CLASS ----------
class TasksMaster:

    TASK_DEFAULT_CRON = "*/15 * * * *"
    TASK_JITTER = 240
    TASKS_FOLDER = os.path.join(os.path.dirname(__file__), "tasks")

    def __init__(self, scheduler: BackgroundScheduler):
        self.tasks = self._config_tasks()
        self.scheduler = scheduler
        self.last_run_times = {}
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

            path = os.path.join(folder_path, filename)
            module_name = filename[:-3]
            spec = importlib.util.spec_from_file_location(f"tasks.{module_name}", path)
            module = importlib.util.module_from_spec(spec)
            try:
                spec.loader.exec_module(module)
                sys.modules[f"tasks.{module_name}"] = module
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
                        task_name, module_name, task_cron, run_when_loaded
                    )
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

    def _schedule_task(self, task_name, module_name, task_cron, run_when_loaded):
        try:
            # Dynamically import the module
            module = importlib.import_module(f"tasks.{module_name}")

            # Check if the module has a 'main' function
            if hasattr(module, "main"):
                app_logger.info(f"Scheduling {task_name} - {module_name} Main Function")

                # unique_job_id
                job_identifier = f"{module_name}__{task_name}"

                # little insurance to make sure the cron is set to something and not none
                if task_cron is None:
                    task_cron = self.TASK_DEFAULT_CRON

                trigger = CronTrigger.from_crontab(task_cron)

                # schedule the task / job
                if run_when_loaded:
                    app_logger.info(
                        f"Task: {task_name} is set to run instantly. Scheduling to run on scheduler start"
                    )

                    self.scheduler.add_job(
                        module.main,
                        trigger,
                        id=job_identifier,
                        jitter=self.TASK_JITTER,
                        name=task_name,
                        next_run_time=datetime.datetime.now(),
                        max_instances=1,
                    )
                else:
                    self.scheduler.add_job(
                        module.main,
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
        job_id = event.job_id
        self.last_run_times[job_id] = datetime.datetime.now()

        if event.exception:
            app_logger.error(f"Job {event.job_id} failed: {event.exception}")
        else:
            app_logger.info(f"Job {event.job_id} completed successfully.")

    def list_jobs(self):
        scheduled_jobs = self.scheduler.get_jobs()
        jobs_list = []

        for job in scheduled_jobs:
            jobs_list.append(
                {
                    "id": job.id,
                    "name": job.name,
                    "next_run": job.next_run_time,
                }
            )
        return jobs_list

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
T = type


def singleton_loader(func):
    """Decorator to ensure only one instance exists."""
    cache: dict[str, T] = {}
    lock = threading.Lock()

    @functools.wraps(func)
    def wrapper(*args, **kwargs) -> T:
        with lock:
            if func.__name__ not in cache:
                cache[func.__name__] = func(*args, **kwargs)
            return cache[func.__name__]

    return wrapper


@singleton_loader
def get_tasksmaster(scheduler: BackgroundScheduler | None = None) -> TasksMaster:
    """
    Returns the singleton TasksMaster instance.

    - Automatically creates a BackgroundScheduler if none is provided.
    - Automatically starts the scheduler when the singleton is created.

    :param scheduler: Optional APScheduler instance. If None, a new BackgroundScheduler will be created.
    """
    if scheduler is None:
        scheduler = BackgroundScheduler()

    tm_instance = TasksMaster(scheduler)

    # Auto-start scheduler if not already running
    if not scheduler.running:
        scheduler.start()
        app_logger.info(
            "TasksMaster scheduler started automatically with singleton creation."
        )

    return tm_instance
