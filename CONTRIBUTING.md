Introduction
============

liburing welcomes contributions, whether they be bug fixes, features, or
documentation additions/updates. However, we do have some rules in place
to govern the sanity of the project, and all contributions should follow
the guidelines in this document. The main reasons for the rules are:

1) Keep the code consistent
2) Keep the git repository consistent
3) Maintain bisectability

Commit format
=============

Each commit should do one thing, and one thing only. If you find yourself,
in the commit message, adding phrases like "Also do [...]" or "While in
here [...]", then that's a sign that the change should have been split
into multiple commits. If your change includes some refactoring of code to
make your change possible, then that refactoring should be a separate
commit, done first. That means this preparatory commit won't have any
functional changes, and hence should be a no-op. It also means that your
main commit, with the change that you actually care about, will be smaller
and easier to review.

Each commit must stand on its own in terms of what it provides, and how it
works. Lots of changes are just a single commit, but for something a bit
more involved, it's not uncommon to have a pull request contain multiple
commits. Make each commit as simple as possible, and not any simpler. We'd
much rather see 10 simple commits than 2 more complicated ones. If you
stumble across something that needs fixing while making an unrelated
change, then please make that change as a separate commit, explaining why
it's being made.

Each commit in a series must be buildable, it's not enough that the end
result is buildable. See reason 3 in the introduction for why that's the
case.

No fixup commits! Sometimes people post a change and errors are pointed
out in the commit, and the author then does a followup fix for that error.
This isn't acceptable, please squash fixup commits into the commit that
introduced the problem in the first place. See reasons 1-3 in the
introduction series for why that is.

Commit message
==============

A good commit explains the WHY of a commit - explain the reason for this
commit to exist. Don't explain what the code in commit does, that should
be readily apparent from just reading the code. liburing commits follow
the following format:

Title

Body of commit

Signed-off-by: ```My Identity <my@email.com>```

That is, a descriptive title on the first line, then an empty line, then
the body of the commit message, then an empty line, and finally an SOB
tag. Example:

```
commit 513ed8e5a0e0705fc2b3e98f0eeea8eea5cf2d3f
Author: Jens Axboe <axboe@kernel.dk>
Date:   Thu Sep 12 09:38:56 2024 -0600

    test/register-restrictions: use T_* exit values
    
    This test invents its own exit codes, for some reason. Switch it to
    using the normal exit values.
    
    Signed-off-by: Jens Axboe <axboe@kernel.dk>
```

Since this change is pretty trivial, a huge explanation need not be given
as to the reasonings for the change. However, for more complicated
changes, better reasonings should be given.

Each commit message should be formatted so each full line is 72-74 chars
wide. For many of us, GitHub is not the primary location, and git log is
often used in a terminal to browse the repo. Breaking lines at 72-74
characters retains readability in an xterm/terminal.

Pull Requests
=============

The git repository itself is the canonical location for information. It's
quite fine to provide a lengthy explanation for a pull request on GitHub,
however please ensure that this doesn't come at the expense of the commit
messages themselves being lacking. The commit messages should stand on
their own and contain everything that you'd otherwise put in the PR
message. If you've worked on projects that send patches before, consider
the PR message similar to the cover letter for a series of patches.

Most contributors seem to use GH for sending patches, which is fine. If
you prefer using email, then patches can also be sent to the io_uring
mailing list: io-uring@vger.kernel.org.

liburing doesn't squash-on-rebase, or other heinous practices sometimes
seen elsewhere. Patches are applied directly, and pull requests are
merged with a merge commit. If meta data needs to go into the merge
commit, then it will go into the merge commit message. This means that
you don't need to continually rebase your changes on top of the master
branch.

Testing changes
===============

You should ALWAYS test your changes, no matter how trivial or obviously
correect they may seem. Nobody is infallible, and making mistakes is only
human.

liburing contains a wide variety of functional tests. If you make changes
to liburing, then you should run the test cases. This is done by building
the repo and running ```make runtests```. Note that some of the liburing
tests test for defects in older kernels, and hence it's possible that they
will crash on an outdated kernel that doesn't contain fixes from the
stable kernel tree. If in doubt, building and running the tests in a vm is
encouraged.
