import logging

from triton import CPUSIZE, MemoryAccess
from tritondse import Addr, FormatStringSanitizer, IntegerOverflowSanitizer, NullDerefSanitizer, ProcessState, \
    SymbolicExecutor, \
    UAFSanitizer
from tritondse.sanitizers import mk_new_crashing_seed


class AlertValidator(object):

    @staticmethod
    def validate(typ: str, se: SymbolicExecutor, pstate: ProcessState, addr: Addr) -> bool:
        """
        This function is called by intrinsic_callback in order to verify defaults
        and vulnerabilities.

        :param typ: Type of the alert as a string
        :param se: The current symbolic executor
        :param pstate: The current process state of the execution
        :param addr: The instruction address of the intrinsic call
        :return: True if a vulnerability has been verified
        """
        # BUFFER_OVERFLOW related alerts
        if typ == "SV_STRBO_UNBOUND_COPY":
            size = se.pstate.get_argument_value(2)
            ptr = se.pstate.get_argument_value(3)

            # Runtime check
            if len(se.pstate.memory.read_string(ptr)) >= size:
                # FIXME: Do we have to define the seed as CRASH even if there is no crash?
                # FIXME: Maybe we have to define a new TAG like BUG or VULN or whatever
                return True

            # Symbolic check
            actx = se.pstate.actx
            predicate = [se.pstate.tt_ctx.getPathPredicate()]

            # For each memory cell, try to proof that they can be different from \0
            for i in range(size + 1):   # +1 in order to proof that we can at least do an off-by-one
                cell = se.pstate.tt_ctx.getMemoryAst(MemoryAccess(ptr + i, CPUSIZE.BYTE))
                predicate.append(cell != 0)

            # FIXME: Maybe we can generate models until unsat in order to find the bigger string

            model = se.pstate.tt_ctx.getModel(actx.land(predicate))
            if model:
                crash_seed = mk_new_crashing_seed(se, model)
                se.workspace.save_seed(crash_seed)
                logging.info(f'Model found for a seed which may lead to a crash ({crash_seed.filename})')
                return True

            return False

        ######################################################################

        # BUFFER_OVERFLOW related alerts
        elif typ == "SV_STRBO_BOUND_COPY_OVERFLOW":
            dst_size = se.pstate.get_argument_value(2)
            ptr_inpt = se.pstate.get_argument_value(3)
            max_size = se.pstate.get_argument_value(4)

            # Runtime check
            if max_size >= dst_size and len(se.pstate.memory.read_string(ptr_inpt)) >= dst_size:
                # FIXME: Do we have to define the seed as CRASH even if there is no crash?
                # FIXME: Maybe we have to define a new TAG like BUG or VULN or whatever
                return True

            # Symbolic check
            actx = se.pstate.actx
            max_size_s = se.pstate.get_argument_symbolic(4).getAst()
            predicate = [se.pstate.tt_ctx.getPathPredicate(), max_size_s >= dst_size]

            # For each memory cell, try to proof that they can be different from \0
            for i in range(dst_size + 1):   # +1 in order to proof that we can at least do an off-by-one
                cell = se.pstate.tt_ctx.getMemoryAst(MemoryAccess(ptr_inpt + i, CPUSIZE.BYTE))
                predicate.append(cell != 0)

            # FIXME: Maybe we can generate models until unsat in order to find the bigger string

            model = se.pstate.tt_ctx.getModel(actx.land(predicate))
            if model:
                crash_seed = mk_new_crashing_seed(se, model)
                se.workspace.save_seed(crash_seed)
                logging.info(f'Model found for a seed which may lead to a crash ({crash_seed.filename})')
                return True

            return False

        ######################################################################

        # BUFFER_OVERFLOW related alerts
        elif typ == "ABV_GENERAL":
            logging.warning(f'ABV_GENERAL encounter but can not check the issue. This issue will be handle if the program will crash.')
            return False

        ######################################################################

        # All INTEGER_OVERFLOW related alerts
        elif typ == "NUM_OVERFLOW":
            return IntegerOverflowSanitizer.check(se, pstate, pstate.current_instruction)

        ######################################################################

        # All USE_AFTER_FREE related alerts
        elif typ in ["UFM_DEREF_MIGHT", "UFM_FFM_MUST", "UFM_FFM_MIGHT"]:
            ptr = se.pstate.get_argument_value(2)
            return UAFSanitizer.check(se, pstate, ptr, f'UAF detected at {ptr:#x}')

        ######################################################################

        # All FORMAT_STRING related alerts
        elif typ in ["SV_TAINTED_FMTSTR", "SV_FMTSTR_GENERIC"]:
            ptr = se.pstate.get_argument_value(2)
            return FormatStringSanitizer.check(se, pstate, addr, ("", ptr))

        ######################################################################

        # All INVALID_MEMORY related alerts
        # FIXME: NPD_CHECK_MIGHT and NPD_CONST_CALL are not supported by klocwork-alert-inserter
        elif typ in ["NPD_FUNC_MUST", "NPD_FUNC_MIGHT", "NPD_CHECK_MIGHT", "NPD_CONST_CALL"]:
            ptr = se.pstate.get_argument_value(2)
            return NullDerefSanitizer.check(se, pstate, ptr, f'Invalid memory access at {ptr:#x}')

        ######################################################################

        elif typ == "MISRA_ETYPE_CATEGORY_DIFFERENT_2012":
            expr = se.pstate.get_argument_symbolic(2).getAst()

            # Runtime check
            if expr.isSigned():
                # FIXME: Do we have to define the seed as CRASH even if there is no crash?
                # FIXME: Maybe we have to define a new TAG like BUG or VULN or whatever
                return True

            # Symbolic check
            actx = se.pstate.tt_ctx.getAstContext()
            size = expr.getBitvectorSize() - 1
            predicate = [se.pstate.tt_ctx.getPathPredicate(), actx.extract(size - 1, size - 1, expr) == 1]

            model = se.pstate.tt_ctx.getModel(actx.land(predicate))
            if model:
                crash_seed = mk_new_crashing_seed(se, model)
                se.workspace.save_seed(crash_seed)
                logging.info(f'Model found for a seed which may lead to a crash ({crash_seed.filename})')
                return True
            return False

        else:
            logging.error(f"Unsupported alert kind {typ}")
