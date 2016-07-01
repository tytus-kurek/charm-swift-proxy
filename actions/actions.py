#!/usr/bin/python
#
# Copyright 2016 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import os
import sys
import yaml

sys.path.append('hooks/')

from charmhelpers.core.host import service_pause, service_resume
from charmhelpers.core.hookenv import action_fail
from charmhelpers.contrib.openstack.utils import (
    set_unit_paused,
    clear_unit_paused,
)
from lib.swift_utils import assess_status, services
from swift_hooks import CONFIGS


def get_action_parser(actions_yaml_path, action_name,
                      get_services=services):
    """Make an argparse.ArgumentParser seeded from actions.yaml definitions."""
    with open(actions_yaml_path) as fh:
        doc = yaml.load(fh)[action_name]["description"]
    parser = argparse.ArgumentParser(description=doc)
    parser.add_argument("--services", default=get_services())
    # TODO: Add arguments for params defined in the actions.yaml
    return parser


# NOTE(ajkavangh) - swift-proxy has been written with a pause that predates the
# enhanced pause-resume, and allowsa --services argument to be passed to
# control the services that are stopped/started.  Thus, not knowing if changing
# this will break other code, the bulk of this custom code has been retained.

def pause(args):
    """Pause all the swift services.

    @raises Exception if any services fail to stop
    """
    for service in args.services:
        stopped = service_pause(service)
        if not stopped:
            raise Exception("{} didn't stop cleanly.".format(service))
    set_unit_paused()
    assess_status(CONFIGS, args.services)


def resume(args):
    """Resume all the swift services.

    @raises Exception if any services fail to start
    """
    for service in args.services:
        started = service_resume(service)
        if not started:
            raise Exception("{} didn't start cleanly.".format(service))
    clear_unit_paused()
    assess_status(CONFIGS, args.services)


# A dictionary of all the defined actions to callables (which take
# parsed arguments).
ACTIONS = {"pause": pause, "resume": resume}


def main(argv):
    action_name = _get_action_name()
    actions_yaml_path = _get_actions_yaml_path()
    parser = get_action_parser(actions_yaml_path, action_name)
    args = parser.parse_args(argv)
    try:
        action = ACTIONS[action_name]
    except KeyError:
        return "Action %s undefined" % action_name
    else:
        try:
            action(args)
        except Exception as e:
            action_fail(str(e))


def _get_action_name():
    """Return the name of the action."""
    return os.path.basename(__file__)


def _get_actions_yaml_path():
    """Return the path to actions.yaml"""
    cwd = os.path.dirname(__file__)
    return os.path.join(cwd, "..", "actions.yaml")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
