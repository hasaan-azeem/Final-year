from .sql_injection     import SQLInjectionModule
from .xss               import XSSModule
from .open_redirect     import OpenRedirectModule
from .ssrf              import SSRFModule
from .command_injection import CommandInjectionModule
from .path_traversal    import PathTraversalModule
from .xxe               import XXEModule
from .ssti              import SSTIModule
from .idor              import IDORModule
from .csrf              import CSRFModule

ALL_MODULES = [
    SQLInjectionModule,
    XSSModule,
    OpenRedirectModule,
    SSRFModule,
    CommandInjectionModule,
    PathTraversalModule,
    XXEModule,
    SSTIModule,
    IDORModule,
    CSRFModule,
]

__all__ = [
    "SQLInjectionModule", "XSSModule", "OpenRedirectModule", "SSRFModule",
    "CommandInjectionModule", "PathTraversalModule", "XXEModule",
    "SSTIModule", "IDORModule", "CSRFModule", "ALL_MODULES",
]