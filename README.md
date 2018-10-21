# About
Getting the corresponding landing pad for C++ exception in object file including executable file and shared library. This tool parses .gcc_except_table from a specific object file.

# build and run tests
<pre><code>
$ make
$ gcc_except_table object_file addr
</code></pre>
e.g.)
<pre><code>
$ gcc_except_table test/test 0x4008e2
</code></pre>
