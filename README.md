# Take GROUP action!
The goal of this repository is to give a reference code for digital signatures (and eventually other primitives) based on <a href = 'https://eprint.iacr.org/2020/1188.pdf'>*Cryptographic Group Actions*</a>. Some of the schemes we can reframe using this model are:
- <a href = 'https://www.less-project.com'>LESS</a>;
- <a href = 'https://www.meds-pqc.org/'>MEDS</a>;
- <a href = 'https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/round-1/spec-files/ALTEQ-Spec-web.pdf'>ALTEQ</a>;
- <a href = 'https://eprint.iacr.org/2019/498'>CSI-FiSh</a>;

### Core design ideas for the repo (open for discussion)

**Hash & Commitment:** for this purpose we always use the function `cmt(input, lam)` from `general_purpose.py` that takes as input any object, convert it to a string and hash it; then it returns `lam` bits in hexadecimal format in a string.  

**Seeds:** they are inteded as integers, an integer `s` can be used as seed in two ways:
- via feeding `s` as `SEED` during the object geenration: `obj = X(param, SEED = s`;
- using the sage construction:
```
with seed(s) : random_function()
```
- when we want to act using a group element generated by `seed` on `x` we just feed it to the action function in the position of the group element. 
IMPO: do _not_ use the method `set_random_seed()`, this would change the internal randomness used for sage functionalities (not desired for cryptohraphic primitives).



![gra](https://github.com/giacomoborin/take-group-action/assets/64214430/d8f3ba50-a95f-4a7c-a55a-1a3efa22ef5d)
