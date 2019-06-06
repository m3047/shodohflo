#!/usr/bin/python3
# Copyright (c) 2019 by Fred Morris Tacoma WA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Running this script creates the __pycache__ entries for the shodohflo package.

You must run it with the argument create, from a user with appropriate privileges
to update the directories.
"""

import sys
from os import path

PATH_HINT = """Your symlink appears to be incorrect.

Or, maybe you didn't create one. Typical install is somewhere like /usr/local/share/
with a symlink somewhere where Python will find it, such as
/usr/local/lib/python3.6/site-packages/

If you wish to create the __pycache__ entries without creating the symlink, specify
"with-path" as the second argument.
"""

def main():
    if len(sys.argv) < 2 or sys.argv[1] != 'create':
        print('This script creates __pycache__ entries if you give it the argument "create".')
        return
    if len(sys.argv) >= 3 and sys.argv[2] == 'with-path':
        sys.path.insert(0,path.dirname(path.dirname(path.abspath(__file__))))

    try:
        import shodohflo
        import shodohflo.fstrm
        import shodohflo.protobuf
        import shodohflo.protobuf.protobuf
        import shodohflo.protobuf.dnstap
    except ModuleNotFoundError:
        print(PATH_HINT)
    
    return

if __name__ == "__main__":
    main()
    
