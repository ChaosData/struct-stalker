# Copyright (c) NCC Group, 2018
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from __future__ import print_function

import lldb
import shlex
import argparse
import traceback
import sys

#import test

PROT_NONE  = 0x00
PROT_READ  = 0x01
PROT_WRITE = 0x02
PROT_EXEC  = 0x04

access_log = open("access.log", "wb")

def __lldb_init_module(debugger, internal_dict):
  lldb.command("struct-stalker")(struct_stalker_command)
  lldb.command("mprotect")(mprotect_command)

def mprotect_command(dbg, cmdline, res, idict):
  addr, flags = cmdline.split(' ')
  if addr.startswith("0x"):
    addr = int(addr, 16)
  else:
    addr = int(addr, 10)

  thread = lldb.debugger.GetSelectedTarget().GetProcess().GetSelectedThread()
  frame = thread.GetSelectedFrame()

  stack_orig_str = frame.FindRegister("rsp").GetValue()
  new_stack_str = hex(int(stack_orig_str, 16) - 4096)
  frame.FindRegister("rsp").SetValueFromCString(new_stack_str)

  len = 4096
  mprotect_cmd = 'expression -- (int)mprotect(0x{:x}, {}, {})'.format(
    addr, len, flags
  )

  lldbrepl = lldb.debugger.GetCommandInterpreter()
  res = lldb.SBCommandReturnObject()

  lldbrepl.HandleCommand(mprotect_cmd, res)
  out_str = res.GetOutput()
  print("> out: " + str(out_str))
  res.Clear()

  thread = lldb.debugger.GetSelectedTarget().GetProcess().GetSelectedThread()
  frame = thread.GetSelectedFrame() # critically important to have this line
  frame.FindRegister("rsp").SetValueFromCString(stack_orig_str)

def check_hex(value):
  try:
    return int(hex(int(value, 16)), 16)
  except ValueError:
    raise argparse.ArgumentTypeError("%s is an invalid hex value" % value)

def parse_args(cmdline):
  argv = shlex.split(cmdline, False, True)

  parser = argparse.ArgumentParser(
    prog="struct-stalker",
    description='stalks structs...'
  )
  mutexg = parser.add_mutually_exclusive_group()

  mutexg.add_argument('-a', '--address', metavar='<address>', type=check_hex,
                      help="Breakpoint address to set up at. (On OS X, you might need to `process launch --stop-at-entry -- ...`)")
  mutexg.add_argument('-f', '--function', metavar='<function>', type=str,
                      default="main",
                      help="Breakpoint function to set up at.")

  mutexg.add_argument('-s', '--start', dest='start', metavar='[arguments...]',
                      nargs='*', default=None,
                      help="Take control of the debugger to continue.")

  parser.add_argument('-l', '--local', dest='local',
                      action='store_true', default=False,
                      help="Flag for whether or not variable is local.")
  parser.add_argument('struct', metavar='[struct]', type=str, nargs='?',
                      help="Variable to trace. If a pointer, the varible " +
                           "itself will not be traced.")
  return parser.parse_args(argv)

bps_by_id = {

}

bps_by_addr = {

}

bps = {

}

proc_consts = {

}

def get_platform(dbg):
  return dbg.GetSelectedTarget().platform.GetOSDescription().split(' ')[0].lower()

def get_process_key(dbg):
  pid = dbg.GetSelectedTarget().process.id
  path = dbg.GetSelectedTarget().GetExecutable().fullpath
  return "%s_%s" % (pid, path)

def struct_stalker_command(dbg, cmdline, res, idict):
  print(">> struct_stalker_command")
  args = parse_args(cmdline)

  if args.start != None:
    main_bp = dbg.GetSelectedTarget().BreakpointCreateByName("main")
    main_bp.SetOneShot(True)
    #main_bp.SetScriptCallbackFunction('__init__.main_bp_callback')
    # desc = lldb.SBStream()
    # main_bp.GetDescription(desc)
    # print("desc: " + desc.GetData())

    #for bl in main_bp:
    #  #print("bl.GetLoadAddress(): " + str(bl.GetLoadAddress()))
    print("main_bp.GetID(): " + str(main_bp.GetID()))

    bps_by_id[main_bp.GetID()] = { # GetLoadAddress() is an unset long (-1/FFFF...)
      "handler": main_bp_handler
    }
    try:
      debugger_loop(dbg, args.start)
    except KeyboardInterrupt: # doesn't work
      sys.exit(0)
  else:
    bp = None
    if args.address != None:
      bp = dbg.GetSelectedTarget().BreakpointCreateByAddress(args.address)
    elif args.function != None:
      bp = dbg.GetSelectedTarget().BreakpointCreateByName(args.function)
    else:
      print("struct-stalker: error: too few arguments")
      return
    bp.SetOneShot(True)

    # for bl in bp:
    #   print("bl.GetID(): " + str(bl.GetID()))
    print("bp.GetID(): " + str(bp.GetID()))

    bps_by_id[bp.GetID()] = {
      "handler": varframe_bp_handler,
      "var_name": args.struct,
      "local": args.local,
      "platform": get_platform(dbg)
    }
    #bp.SetScriptCallbackFunction('__init__.varframe_bp_callback')


tracers = {
  # '<base_addr>': [ [<bp_addr>, <size>, "<name>"],... ]
}

def get_bp_id(bp_loc):
  print(">> get_bp_id")
  print("> bp_loc: " + str(bp_loc))
  return int(str(bp_loc).split('.')[0])

def callback_handler_thread_wait(pbid):
  while True:
    if "thread_notify" not in bps_by_id[pbid]:
      continue
    if bps_by_id[pbid]["thread_notify"] == True:
      break

def callback_handler_thread_notify(bpid):
  bps_by_id[bpid]["thread_notify"] = True

def callback_handler_thread_clear(bpid):
  del bps_by_id[bpid]["thread_notify"]


def main_bp_callback(frame, bp_loc, dict):
  print(">> main_bp_callback")
  # print("> frame: " + str(type(frame)) + " : " + str(frame))
  # print("> bp_loc: " + str(type(bp_loc)) + " : " + str(bp_loc))
  # print("> dict: " + str(type(dict)) + " : " + str(dict.keys()))

  # target = lldb.debugger.GetSelectedTarget()
  # val = target.EvaluateExpression('(size_t)sizeof(void*)')
  # print("sizeof(void*): " + str(val.GetValue()))
  # sys.exit(1)
  bp_id = get_bp_id(bp_loc)
  try:
    main_bp_handler(frame, bp_id)
  except Exception:
    traceback.print_exc()
  callback_handler_thread_notify(bp_id)
  return False

  # bp_id = get_bp_id(bp_loc)
  # bps_by_id[bp_id]['frame'] = frame
  # callback_handler_thread_notify(bp_id)
  # #main_bp_handler(get_bp_id(bp_loc))

def main_bp_handler(frane, bp_id, bp_addr):
  #import time
  #time.sleep(2)
  print(">> main_bp_handler")
  #callback_handler_thread_wait(bp_id)

  # print("> id: " + str(lldb.debugger.GetID()))
  process_key = get_process_key(lldb.debugger)
  if process_key not in proc_consts:
    print("> process_key not found, setting up")
    lldbrepl = lldb.debugger.GetCommandInterpreter()
    nullres = lldb.SBCommandReturnObject()
    lldbrepl.HandleCommand('process handle SIGSEGV --notify true --pass false --stop true', nullres)
    lldbrepl.HandleCommand('process handle SIGBUS --notify true --pass false --stop true', nullres)

    pgszres = lldb.SBCommandReturnObject()
    lldbrepl.HandleCommand('expression --flat --format x -- (int)getpagesize()', pgszres)
    PAGE_SIZE = int(pgszres.GetOutput().split('=')[1].strip(), 16)

    pszres = lldb.SBCommandReturnObject()
    lldbrepl.HandleCommand('expression --flat -- (size_t)sizeof(void*)', pszres)
    POINTER_SIZE = int(pszres.GetOutput().split('=')[1].strip(), 10)
    PAGE_BOUND_MASK = ((PAGE_SIZE-1) ^ ((2**(POINTER_SIZE*8))-1))

    print("> process_key: " + str(process_key))

    proc_consts[process_key] = {
      'PAGE_SIZE': PAGE_SIZE,
      'POINTER_SIZE': POINTER_SIZE,
      'PAGE_BOUND_MASK': PAGE_BOUND_MASK
    }
  print("<< main_bp_handler")

def varframe_bp_callback(frame, bp_loc, dict):
  #print("> FRAME: " + str(frame))
  bp_id = get_bp_id(bp_loc)
  try:
    varframe_bp_handler(frame, bp_id, frame.GetPC())
  except Exception:
    traceback.print_exc()
  callback_handler_thread_notify(bp_id)
  #varframe_bp_handler(bp_id)
  return False


ARGS = [True, False, False, True]
LOCALS = [False, True, False, True]
STATICS = [False, False, True, True]

# def is_invalid_pointer(addr):
#   if ftd != 0 and ftd != 0xffffffffffffffff and (
#     (ftd & 0xffffffffffff0000) > 0)

# we pretty much know for certain that these make something invalid
def is_invalid_pointer(addr):
  return addr == 0 or \
         addr == 0xffffffffffffffff or \
         addr >= 0xffffffffffff0000


def varframe_bp_handler(frame, bp_id, bp_addr):
  print(">> varframe_bp_handler <<")

  bp_data = bps_by_id[bp_id]
  process_key = get_process_key(lldb.debugger)
  bp_data['process_key'] = process_key


  # print("> frame: " + str(frame))
  # print("> frame.pc: " + str(frame.GetPC()))
  # print("> frame.get_parent_frame: " + str(frame.get_parent_frame()))
  ret_pc = frame.get_parent_frame().GetPC() # get this early b/c the mprotect might break getting it later
  print("> ret_pc: " + str(ret_pc))

  # lldbrepl = lldb.debugger.GetCommandInterpreter()
  # res = lldb.SBCommandReturnObject()
  # lldbrepl.HandleCommand('thread backtrace', res)
  # print("> res: " + str(res))
  # lldbrepl.HandleCommand('x/10gx ' + hex(sp - 0x20), res)
  # print("> res: " + str(res))

  # print("> frame: " + str(frame))
  # print("> frame.pc: " + str(frame.GetPC()))
  # print("> parent_frame: " + str(frame.get_parent_frame()))
  # print("> parent_frame.pc: " + str(frame.get_parent_frame().GetPC()))

  var_name = bp_data['var_name']

  #vars = frame.GetVariables(True, True, True, True) # arguments, locals, statics, in_scope_only

  if bp_data['local']:
    vars = frame.GetVariables(*LOCALS)
  else:
    vars = frame.GetVariables(True, False, True, True)  # arguments, locals, statics, in_scope_onl

  var = vars.GetFirstValueByName(var_name)
  print("> var_name: " + str(var_name))
  print("> var: " + str(var))
  print("> var.location: " + str(var.location))

  comment = '''
  print(var.location)
  print(var.size)
  print(var.GetNumChildren())
  print(var.GetTypeName())
  print(var.type.GetTypeClass())
  print(str(type(var.type)))

  for i in range(var.GetNumChildren()):
    print(">>>>")
    v = var.GetChildAtIndex(i)
    print(v.name)
    print(v.location)
    print(v.size)
    print(v.GetTypeName())
    print(v.value)
  print(dir(var))
  '''

  if var.location == None:
    print("< failed to set bp (lack of metadata)")
    return False
  var_loc = int(var.location, 16)
  var_type = var.type

  if var_type.IsPointerType() or var_type.IsReferenceType() and not bp_data['local']:
    # we can assume local pointers are uninitialized and that derefing them is bad
    # however, for non-local pointers, we will do want to deref them if valid-ish

    e = lldb.SBError()
    if not is_invalid_pointer(var_loc):
      if var_type.IsPointerType():
        var_type = var_type.GetPointeeType()
      else:
        var_type = var_type.GetDereferencedType()
      print("> var_loc (before): " + hex(var_loc))
      var_loc = lldb.debugger.GetSelectedTarget().GetProcess().ReadPointerFromMemory(var_loc, e)
      print("> var_loc (after): " + hex(var_loc))
      print("> e.value: " + str(e.value))
      #sys.exit(1)


  locked_pages = []
  if not bp_data['local']:
    locked_pages = lock_recursive(var_loc, var_type, bp_data)
  else:
    locked_pages = lock(var_loc, var_type, bp_data)

  # set up teardown

  # thread = lldb.debugger.GetSelectedTarget().GetProcess().GetSelectedThread()
  # print("> thread: " + str(thread))
  # frame = thread.GetSelectedFrame()
  #
  # pc = frame.get_parent_frame().GetPC()
  print("> ret_pc: " + str(ret_pc))
  bp = lldb.debugger.GetSelectedTarget().BreakpointCreateByAddress(ret_pc)
  bp.SetOneShot(True)
  #sys.exit(1)

  bp_info = {
    "handler": varteardown_bp_handler,
    "var_name": bp_data['var_name'],
    "locked_pages": locked_pages,
    "process_key": bp_data['process_key'],
    "bp_addr": ret_pc,
    "bp_id": bp.GetID()
  }

  bps_by_id[bp.GetID()] = bp_info
  bps_by_addr[ret_pc] = bp_info

  #sys.exit(1)
  return False # continue

def varteardown_bp_handler(frame, bp_id, bp_addr):
  print(">> varteardown_bp_handler")
  #sys.exit(1)
  if bp_id is not None:
    bp_data = bps_by_id[bp_id]
  else:
    bp_data = bps_by_addr[bp_addr]

  print("> bp_id: " + str(bp_data['bp_id']))
  print("> bp_addr: " + str(bp_data['bp_addr']))

  del bps_by_addr[bp_data['bp_addr']]
  del bps_by_id[bp_data['bp_id']]

  target = lldb.debugger.GetSelectedTarget()
  target.BreakpointDelete(bp_data['bp_id'])

  var_name = bp_data["var_name"]
  locked_pages = bp_data["locked_pages"]
  print("> var_name: " + str(var_name))
  print("> locked_pages: " + str(locked_pages))

  consts = proc_consts[bp_data['process_key']]
  for lp in locked_pages:
    lldbrepl = lldb.debugger.GetCommandInterpreter()
    mpres = lldb.SBCommandReturnObject()
    mprotect(lldbrepl, lp["mprotect_addr"], lp["mprotect_len"], PROT_READ|PROT_WRITE|PROT_EXEC, mpres, consts)
    print("> unlock mprotect: " + str(mpres))
    del tracers[lp['pg']]

  print("> tracers: " + str(tracers))

  #sys.exit(1)
  pass

def lock_recursive(loc, t, bp_data):
  print(">> lock_recursive")
  print("> loc: " + str(loc))
  locked_pages = []
  if t.GetTypeClass() == lldb.eTypeClassUnion:
    print("> skip union!")
    # skip unions
    return locked_pages

  for i in range(t.GetNumberOfFields()):
    f = t.GetFieldAtIndex(i)
    if f.is_bitfield:
      continue
    print("> loc: " + hex(loc))
    off = f.byte_offset
    print("> off: " + hex(off))
    f_loc = loc + off
    print("> f_loc: " + hex(f_loc))

    ft = f.type

    print("> ft: " + str(ft))
    if ft.IsPointerType() or ft.IsReferenceType():
      e = lldb.SBError()
      ftd = lldb.debugger.GetSelectedTarget().GetProcess().ReadPointerFromMemory(f_loc, e)
      print("> ftd: " + str(ftd))
      if not is_invalid_pointer(ftd):
        locked_pages += lock_recursive(ftd, ft, bp_data)
      else:
        print("> not valid address")
    # else:
    #   print("> ft: not a pointer/reference")

  locked_pages += lock(loc, t, bp_data)
  return locked_pages

def lock(loc, t, bp_data):
  print(">> lock")
  locked_pages = []

  print("> loc: " + str(loc))
  print("> t: " + str(t))
  print("> bp_data: " + str(bp_data))

  sz = t.size

  # print("> f(8): " + str(get_field_info(t, 8)))
  # print("> f(16): " + str(get_field_info(t, 16)))
  # print("> f(12): " + str(get_field_info(t, 12)))

  consts = proc_consts[bp_data['process_key']]
  print("PAGE_BOUND_MASK: " + str(consts['PAGE_BOUND_MASK']))

  membp_base_page = loc & consts['PAGE_BOUND_MASK']

  if membp_base_page not in tracers:
    tracers[membp_base_page] = []

  mprotect_len = loc - membp_base_page + sz
  num_pages = mprotect_len / consts['PAGE_SIZE']
  num_pages += 0 if (mprotect_len % consts['PAGE_SIZE'])==0 else 1

  for i in range(num_pages):
    pg = membp_base_page + (i*consts['PAGE_SIZE'])
    if pg not in tracers:
      tracers[pg] = []
    page_lock = {
      'location': loc,
      'size': sz,
      'data': bp_data,
      'type': t,
      'parents': [],
      'mprotect_addr': membp_base_page,
      'mprotect_len': mprotect_len,
      'pg': pg,
      'process_key': bp_data['process_key']
    }
    tracers[pg].append(page_lock)
    locked_pages.append(page_lock)

  lldbrepl = lldb.debugger.GetCommandInterpreter()
  mpres = lldb.SBCommandReturnObject()
  print("> process state b4 mprotect: " + str(lldb.debugger.GetSelectedTarget().GetProcess().state))
  mprotect(lldbrepl, membp_base_page, mprotect_len, PROT_NONE, mpres, consts)
  print("> lock mprotect: " + str(mpres))

  return locked_pages

def escape_args(args):
  ret = []
  for arg in args:
    ret.append("'" + arg.replace("'", "'\\''") + "'")
  return ret

def debugger_loop(dbg, start_args):

  print(">> debugger_loop")
  print("> id: " + str(dbg.GetID()))
  print("> getAsync(): " + str(dbg.GetAsync()))
  dbg.SetAsync(True)
  if dbg.GetSelectedTarget().GetProcess().state == 0: # need to run it
    print("> running!")
    dbg.HandleCommand("r " + ' '.join(escape_args(start_args)))
  else:
    #dbg.HandleCommand("continue")
    print("> already running????")
    dbg.GetSelectedTarget().GetProcess().Continue()

  #repl_listener = dbg.GetListener()
  tbcaster = dbg.GetSelectedTarget().GetBroadcaster()
  print("> tbcaster: " + str(tbcaster.GetName()))

  #repl_listener.StopListeningForEvents(tbcaster, 0xffffffff)
  #repl_listener.StopListeningForEventClass(dbg, lldb.debugger.GetCommandInterpreter().GetBroadcaster().GetName(), 0xffffffff) # "lldb.commandInterpreter"
  #tbcaster.RemoveListener(repl_listener, 0xffffffff)



  process = dbg.GetSelectedTarget().GetProcess()
  #print(dir(process))

  filters = ["lldb.commandInterpreter", "lldb.anonymous", "lldb.communication",
             "lldb.thread", "lldb.targetList", "lldb.process", "lldb.target"]

  listener = lldb.SBListener('struct-stalker')
  #listener = dbg.GetListener()

  #for f in filters:
  #  listener.StopListeningForEventClass(dbg, f, 0xffffffff)

  #filter_name = "lldb.target"
  #listener.StartListeningForEventClass(dbg, filter_name, 0xffffffff)
  process.GetBroadcaster().AddListener(listener, 0xffffffff)

  #tbcaster.AddListener(listener, 4)
  #tbcaster.AddListener(listener, 0xffffffff)
  #tbcaster.AddListener(listener, lldb.SBCommandInterpreter.eBroadcastBitQuitCommandReceived)
  #listener.StartListeningForEvents(tbcaster, 0xffffffff)
  #listener.StartListeningForEvents(tbcaster, lldb.SBCommandInterpreter.eBroadcastBitQuitCommandReceived)


  print("> loop start <")
  while True:
    if dbg.GetSelectedTarget().GetProcess().GetState() == lldb.eStateExited:
      print("< EXIT detected by process state check")
      break
    # todo: if not async, need to detect that process is already stopped otherwise we loop forever waiting

    #dbg.SetAsync(False)
    print("> process state: " + str(dbg.GetSelectedTarget().GetProcess().GetState()))
    try:
      event = lldb.SBEvent()
      #res = listener.WaitForEvent(4294967295, event) # UINT32_MAX # misses exit
      res = listener.WaitForEvent(1, event)
      print("> res: " + str(res))
      if not res:
        print("> event.GetType(): " + str(event.GetType()))
        #if event.GetType() == 0:
        #  print("break!")
        #  break
        continue
      print(">>>>>>>>>>>>>>>>>>>>>>>>>>")
      print("> event: " + str(event))
      print("> type: " + str(event.GetType()))
      if not lldb.SBProcess.EventIsProcessEvent(event):
        continue
      # if event.GetType() == lldb.SBCommandInterpreter.eBroadcastBitQuitCommandReceived: # 0x4, quit
      #   print("< quitting!")
      #   break
      if event.GetType() != lldb.SBProcess.eBroadcastBitStateChanged: # 0x1, state-changed
        continue
      state = lldb.SBProcess.GetStateFromEvent(event)
      print("> state: " + str(state))
      if state == lldb.eStateInvalid:
        continue
      elif state == lldb.eStateStopped:
        print(">>>> state: stopped!! <<<<")
        process_stopped_threads(dbg)
        #dbg.SetAsync(True)
        #dbg.HandleCommand("continue")
        print("> continue")
        process.Continue()
      elif state == lldb.eStateRunning:
        print("> state: running!")
        continue
      else:
        print("> ?????")
        #dbg.SetAsync(True)
        #dbg.HandleCommand("continue")
        process.Continue()
    except Exception as e:
      print("exception: " + str(e))
      traceback.print_exc()

      break

  #tbcaster.AddListener(repl_listener, 0xffffffff)
  #repl_listener.StartListeningForEvents(tbcaster, 0xffffffff)
  #listener.StartListeningForEventClass(dbg, filter_name, 0xffffffff)

def process_stopped_threads(dbg): # todo
  print(">> process_stopped_threads")
  process = dbg.GetSelectedTarget().GetProcess()
  print("> process: " + str(process))
  num_threads = process.GetNumThreads() # likely racey
  current_thread = process.GetSelectedThread()
  current_thread_id = current_thread.GetThreadID()

  platform = get_platform(dbg)

  for i in range(num_threads):
    t = process.GetThreadAtIndex(i)
    if t == None or not t.IsValid():
      continue
    if not t.IsStopped():
      continue
    tid = t.GetThreadID()
    if tid == current_thread_id:
      continue
    desc = lldb.SBStream()
    t.GetDescription(desc)
    info = parse_thread_description(platform, desc.GetData())
    if info == None:
      continue
    if info['thread_index'] != i:
      continue
    if info['thread_id'] != tid+1:
      continue
    on_bad_access(dbg, info)
  desc = lldb.SBStream()
  print(">>>")
  import time
  time.sleep(0.1) # fight some sort of double free race condition
  current_thread.GetDescription(desc)
  print("> desc: " + desc.GetData())
  info = parse_thread_description(platform, desc.GetData())
  print("> info: " + str(info))
  if info == None:
    return
  if info['thread_id'] != current_thread_id:
    return
  on_bad_access(dbg, info)


def parse_thread_description(platform, desc_str):
  print(">> parse_thread_description")
  if platform == "linux":
    return parse_thread_description_linux(desc_str)
  elif platform == "darwin":
    return parse_thread_description_darwin(desc_str)
  else:
    print("> Unsupported platform: " + str(platform))
    return None

def parse_thread_description_linux(desc_str):
  print(">> parse_thread_description_linux")
  if desc_str == None:
    return None
  desc_str = desc_str.strip()
  if desc_str == '':
    return None

  parts = desc_str.split(' = ')
  if len(parts) != 4:
    if 'instruction step into' in parts[-1]:
      return None
    return None
  tidx, tid_instaddr_name, queue, stopreason_code_accessaddr = parts
  stop_reason = stopreason_code_accessaddr.split('(')[0].strip()
  if "breakpoint" in stop_reason:
    print("breakpoint!!!!!")
    return None
  elif 'SIGSEGV' not in stop_reason:
    print("> unexpected stop reason for: " + repr(desc_str))
    return None

  return {
    'thread_index': int(tidx.split(':')[0].split('#')[1], 10),
    'thread_id': int(tid_instaddr_name.split(',')[0], 10),
    'instruction_address': int(
      tid_instaddr_name.split(',')[1].strip().split(' ')[0], 16
    ),
    'access_address': int(
      stopreason_code_accessaddr.split(': ')[-1].strip(')'), 16
    )
  }

def parse_thread_description_darwin(desc_str):
  print(">> parse_thread_description_darwin")
  if desc_str == None:
    return None
  desc_str = desc_str.strip()
  if desc_str == '':
    return None

  print("> desc: " + desc_str)

  parts = desc_str.split(' = ')
  if len(parts) != 4:
    if 'instruction step into' in parts[-1]:
      return None
    return None
  tidx, tid_instaddr_name, queue, stopreason_code_accessaddr = parts
  stop_reason = stopreason_code_accessaddr.split('(')[0].strip()
  if "breakpoint" in stop_reason:
    print("breakpoint!!!!!")
    print("> tid_instaddr_name: " + tid_instaddr_name)
    bp_name = tid_instaddr_name.split('`')[1].split('(')[0]
    bp_id = int(desc_str.split('breakpoint')[1].strip().split('.')[0], 10)
    bp_addr = int(desc_str.split(',')[1].strip(' ').split(' ')[0], 16)
    print("bp_addr: " + str(bp_addr))
    print("bp_id: " + str(bp_id))
    if bp_id in bps_by_id:
      thread = lldb.debugger.GetSelectedTarget().GetProcess().GetSelectedThread()
      frame = thread.GetSelectedFrame()

      bp_handler = bps_by_id[bp_id]['handler']
      try:
        bp_handler(frame, bp_id, None)
      except Exception:
        traceback.print_exc()

      # print("> waiting for callback to complete")
      # #callback_handler_thread_wait(bp_id)
      #
      # print("> _thread_: " + str(thread))
      # print("> _frame_: " + str(frame))

      # print("> _thread_.GetNumFrames(): " + str(thread.GetNumFrames()))

      # for frame in thread:
      #   print("> _frame_: " + str(frame))

      # may need to `return None` here
    else:
      print("> breakpoint handler not found for: " + bp_name + ": " + str(bp_id))
    return None
  elif stop_reason != 'EXC_BAD_ACCESS':
    print("> unexpected stop reason for: " + repr(desc_str))
    return

  return {
    'thread_index': int(tidx.split(':')[0].split('#')[1], 10),
    'thread_id': int(tid_instaddr_name.split(',')[0], 16),
    'instruction_address': int(
      tid_instaddr_name.split(',')[1].strip().split(' ')[0], 16
    ),
    'access_address': int(
      stopreason_code_accessaddr.split('=')[-1].strip(')'), 16
    )
  }


def on_bad_access(dbg, thread_info):
  print(">> on_bad_access")
  access_address = thread_info['access_address']
  inst_addr = thread_info['instruction_address']

  process_key = get_process_key(dbg)
  if process_key == None:
    print("> Could not find process key")
    return
  consts = proc_consts[process_key]
  if consts == None:
    print("> Could not find process constants for process_key " + str(process_key))
    return

  bp_page = access_address & consts['PAGE_BOUND_MASK']
  print("> bp_page: " + str(bp_page))
  if bp_page not in tracers:
    print("tracers: " + str(tracers))
    print("bp_page: " + str(bp_page))
    thread = lldb.debugger.GetSelectedTarget().GetProcess().GetSelectedThread()
    frame = thread.GetSelectedFrame()
    print("> frame: " + str(frame))
    print("> unmapped page accessed")
    sys.exit(1)
    return

  print("> variable access:")

  lst = tracers[bp_page]
  #print("> lst: " + str(lst))
  bp = None
  for entry in lst:
    loc = entry['location']
    sz = entry['size']
    if loc <= access_address and access_address <= (loc+sz):
      bp = entry
      break

  mprotect_addr = 0
  mprotect_len = 0
  print(">==>")
  dump_value = False
  if bp is not None:
    #print("=  variable: " + bp['name'])
    print("=  offset: " + hex(access_address-bp['location']))
    print("<==<")
    dump_value = True
  else:
    print("=  unknown access to watched page: 0x{:x} by instruction at 0x{:x}".format(access_address, inst_addr))
    # still need to unlock the page to step
    bp = {
     "mprotect_addr": bp_page,
     "mprotect_len": consts["PAGE_SIZE"]
    }
    #bp = tracers[bp_page][0]

  lldb.debugger.HandleCommand("frame select")
  mprotect_addr = bp['mprotect_addr']
  mprotect_len = bp['mprotect_len']
  thread_id = thread_info['thread_id']
  vals = mprotect_twostep(mprotect_addr, mprotect_len, thread_id, consts, thread_info, bp, dump_value)

  # if dump_value:
  #   original = vals['original']
  #   modified = vals['modified']
  #


def mprotect_twostep(addr, len, thread_id, consts, thread_info, bp, dump_value = False):
  print(">> mprotect_twostep")
  lldb.debugger.SetAsync(False) # needed so that frame-related calls complete in mprotect
  res = lldb.SBCommandReturnObject()
  process = lldb.debugger.GetSelectedTarget().GetProcess()
  lldbrepl = lldb.debugger.GetCommandInterpreter()
  mprotect(lldbrepl, addr, len, PROT_READ|PROT_WRITE|PROT_EXEC, res, consts)

  thread = lldb.debugger.GetSelectedTarget().GetProcess().GetSelectedThread()
  frame = thread.GetFrameAtIndex(0)
  print("> frame (pre-step): " + str(frame))


  if dump_value:

    original_value = None
    original_value_ptr = None
    modified_value = None
    modified_value_ptr = None

    access_address = thread_info['access_address']
    inst_addr = thread_info['instruction_address']
    var_loc = bp['location']

    offset = access_address - var_loc

    t = bp['type']
    ts = t.GetByteSize()
    #print(">> [access] type seen as " + str(t))

    has_fields = t.GetNumberOfFields() > 0

    if has_fields:
      field, shift = get_field_info(t, offset)
    else:
      field = t
      shift = access_address - var_loc
    fo = None
    fs = None
    if field is not None:
      if has_fields:
        fo = field.GetOffsetInBytes()
        fs = field.GetType().GetByteSize()
      else:
        fo = 0
        fs = t.GetByteSize()
      if shift == 0:
        if has_fields:
          print(">> [access] field {} of {} @ {}".format(
            field, t.GetName(), hex(var_loc)
          ))
        else:
          print(">> [access] value of {} @ {}".format(
            t.GetName(), hex(var_loc)
          ))
      else:
        if has_fields:
          print(">> [access] field (field offset: {}) {} of {} @ {}".format(
            field, hex(shift), t.GetName(), hex(var_loc)
          ))
        else:
          print(">> [access] value (offset: {}) of {} @ {}".format(
            hex(shift), t.GetName(), hex(var_loc)
          ))

      e = lldb.SBError()
      original_value = process.ReadMemory(var_loc+fo, fs, e)
      if fs == consts['POINTER_SIZE']:
        original_value_ptr = process.ReadPointerFromMemory(var_loc+fo, e)
      #print(">> [access] original value: " + original_value.encode('hex'))

      res = lldb.SBCommandReturnObject()

      #lldbrepl.HandleCommand("x/1i $rip", res)
      lldbrepl.HandleCommand("disassemble -F intel -c 1 -s $rip", res)
      out_str = res.GetOutput()
      print(">> [access] " + out_str.split("\n")[1])

      pass

    process.GetThreadByID(thread_id).StepInstruction(False)

    if field is not None:
      e = lldb.SBError()
      modified_value = process.ReadMemory(var_loc+fo, fs, e)
      if fs == consts['POINTER_SIZE']:
        modified_value_ptr = process.ReadPointerFromMemory(var_loc+fo, e)
      #print(">> [access] modified value: " + modified_value.encode('hex'))
      if modified_value != original_value:
        print(">> [access] modified: {} >> {}".format(
          original_value.encode('hex'), modified_value.encode('hex')
        ))
        if has_fields:
          ft = field.GetType()
        else:
          ft = t
        if ft.IsPointerType() or ft.IsReferenceType():
          #print(">> [access] prev-type: " + ft.GetName())
          if ft.IsPointerType():
            ftd = ft.GetPointeeType()
          else:
            ftd = ft.GetDereferencedType()
          # todo: sync w/ tracers
          #print(">> [access] deref-type: " + ftd.GetName())

          if not is_invalid_pointer(original_value_ptr):
            base = original_value_ptr & consts['PAGE_BOUND_MASK']
            s = original_value_ptr - base
            mprotect(lldbrepl, base, s+ftd.GetByteSize(), PROT_READ|PROT_WRITE|PROT_EXEC, res, consts)
            pass
          if not is_invalid_pointer(modified_value_ptr):
            #print(">> [access] locking " + ftd.GetName())
            lock(modified_value_ptr, ftd, bp)
            pass
    else:
      print(">> [access] field is None!!!")
  else:
    process.GetThreadByID(thread_id).StepInstruction(False)

  process.SetSelectedThreadByID(thread_id)

  thread = lldb.debugger.GetSelectedTarget().GetProcess().GetSelectedThread()

  # if this trips on a ret, when we step, we step into our breakpoint without realizing it
  # therefore, we need to detect if that's the case and handle our breakpoint

  thread_msg = str(thread)

  frame = thread.GetFrameAtIndex(0)
  print("> frame (post-step): " + str(frame))
  pc = frame.GetPC()
  print("> pc: " + str(pc))

  lldbrepl = lldb.debugger.GetCommandInterpreter()
  res = lldb.SBCommandReturnObject()
  mprotect(lldbrepl, addr, len, PROT_NONE, res, consts)

  if "breakpoint" in thread_msg:
    print("> stepped into breakpoint by \"breakpoint\"!!")
    platform = get_platform(lldb.debugger)
    parse_thread_description(platform, thread_msg)
  elif pc in bps_by_addr: # shouldn't hit
    print("> stepped into breakpoint by addr!!")
    bp_handler = bps_by_addr[pc]['handler']
    try:
      bp_handler(frame, None, pc)
    except Exception:
      traceback.print_exc()

    pass

  lldb.debugger.SetAsync(True)

def mprotect(lldbrepl, addr, len, flags, res, consts):
  print(">> mprotect")
  print("> addr: " + str(addr))
  print("> len: " + str(len))
  print("> flags: " + str(flags))
  thread = lldb.debugger.GetSelectedTarget().GetProcess().GetSelectedThread()
  print("> thread: " + str(thread))
  for f in thread:
    print("> f: " + str(f))

  frame = thread.GetSelectedFrame()

  print("> frame: " + str(frame))
  rsp = frame.FindRegister("rsp")
  print("> rsp: " + str(rsp))
  stack_orig_str = frame.FindRegister("rsp").GetValue()
  print("> stack: " + str(stack_orig_str))
  new_stack_str = hex(int(stack_orig_str, 16) - consts['PAGE_SIZE'])
  frame.FindRegister("rsp").SetValueFromCString(new_stack_str)

  mprotect_cmd = 'expression -- (int)mprotect(0x{:x}, {}, {})'.format(
    addr, len, flags
  )
  print("> mprotect_cmd: " + mprotect_cmd)
  #sys.exit(1)

  lldbrepl.HandleCommand(mprotect_cmd, res)
  out_str = res.GetOutput()
  print("> out: " + str(out_str))
  #sys.exit(1)
  res.Clear()
  out = None
  if out_str != None:
    out = int(out_str.split('=')[1].strip(), 10)

  thread = lldb.debugger.GetSelectedTarget().GetProcess().GetSelectedThread()
  frame = thread.GetSelectedFrame() # critically important to have this line
  frame.FindRegister("rsp").SetValueFromCString(stack_orig_str)
  # if "$5" in out_str: # works
  #   print("> $5 found")
  #   print("> tracers: " + str(tracers))
  #   sys.exit(1)
  # if "$9" in out_str:  # broken in c++ init
  #   print("> $ found")
  #   print("> tracers: " + str(tracers))
  #   sys.exit(1)

def get_field_info(t, off):
  for i in range(t.GetNumberOfFields()):
    field = t.GetFieldAtIndex(i)
    #print("> field: " + str(field))
    fo = field.GetOffsetInBytes()
    #print("> fo: " + str(fo))
    fs = field.GetType().GetByteSize()
    if fo <= off < (fo + fs):
      return field, (off - fo)
  print(">> [access] failed to find offset {} in type {}".format(off, t.GetName()))
  return None, None
