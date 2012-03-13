# - Determine if the Broccoli Perl bindings are available
#
# Usage of this module as follows:
#
#  find_package(PerlInterp REQUIRED)
#  find_package(PerlBroccoli)
#
# Variables defined by this module:
#
#  PERLBROCCOLI_FOUND             Perl successfully imports broccoli bindings

if (NOT PERLBROCCOLI_FOUND)
    execute_process(COMMAND "${PERL_EXECUTABLE}" -MBroccoli -e ''
                    RESULT_VARIABLE PERLBROCCOLI_IMPORT_RESULT)

    if (PERLBROCCOLI_IMPORT_RESULT)
        # python returned non-zero exit status
        set(BROCCOLI_PERL_MODULE false)
    else ()
        set(BROCCOLI_PERL_MODULE true)
    endif ()
endif ()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PerlBroccoli DEFAULT_MSG BROCCOLI_PERL_MODULE)
