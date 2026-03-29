Command line used to find this crash:

afl-fuzz -Q -i /home/ajay/MARLFuzz/BinFuzz/seeds/llama/corpus -o /home/ajay/MARLFuzz/BinFuzz/production_workspace/fuzzing_baseline/36b7a35b_1771627143 -m none -t 5000 -V 7200 -p fast -x /home/ajay/MARLFuzz/BinFuzz/seeds/llama/llama.dict -- /home/ajay/MARLFuzz/Linux_bin/V1/llama-bench -m @@ -n 1 -p 0

If you can't reproduce a bug outside of afl-fuzz, be sure to set the same
memory limit. The limit used for this fuzzing session was 0 B.

Need a tool to minimize test cases before investigating the crashes or sending
them to a vendor? Check out the afl-tmin that comes with the fuzzer!

Found any cool bugs in open-source tools using afl-fuzz? If yes, please post
to https://github.com/AFLplusplus/AFLplusplus/issues/286 once the issues
 are fixed :)

