 * 
 * */

#include "std_testcase.h"

#ifndef OMITBAD

void CWE571_Expression_Always_True__unsigned_int_01_bad() 
{
    /* Ensure (0 <= intBad < UINT_MAX) and that uIntBad is pseudo-random */
    unsigned int uIntBad = (unsigned int)(rand() * 2);

    /* FLAW: This expression is always true */
    if (uIntBad >= 0) 
    {
        printLine("Always prints");
    }
}

#endif /* OMITBAD */