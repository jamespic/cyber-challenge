cyber-challenge
===============

Some toy examples, to demonstrate ideas that could be used in DARPA's Cyber Grand Challenge.

**DO NOT USE THESE EXAMPLES IN PRODUCTION. THEY WILL EAT YOUR CHILDREN**

SQLInject
---------

Rewrites the bytecode of Java classes containing SQL injection vulnerabilities, and makes them immune to
SQL injection. It replaces Statements with PreparedStatements wherever it feels it can usefully do so.

The approach is deliberately dumb, and totally unsafe. It's effectively find-and-replace on
java bytecode, and will destroy your code in a wide array of situations. A more mature solution would
be to build a tree representation of the bytecode, and operate on the tree structure. Data flow should
also be considered carefully.

CSRF Proxy
----------

A simple Python proxy, that protects an application from CSRF.

It modifies the HTML on-the-fly, to implement the double-submit-cookie pattern. Again, it's totally unsafe,
and makes a wide array of unjustifiable assumptions about the wrapped application. It's also riddled with bugs,
that are probably not worth fixing.
