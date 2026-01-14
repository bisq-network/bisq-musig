# Adaptor signatures with Musig2

This article is tailored to 2of2 Multisig and how to use
the [library musig2](https://github.com/conduition/musig2) for adaptor signatures.

An adaptor signature is a construction, where one party must reveal a secret when it wants to use a signature prepared
by another party.
This explanation is tailored towards 2of2 scriptless Multisig. Generalising to n-of-n should be straight forward, if
needed.
Let's assume Bob wants Alice to reveal the secret $t$. Bob (and Alice) will create a signature for a payout transaction
of a 2of2 multisig such that when Alice uses it, she must reveal $t$ to Bob.

Let

$$T=t \cdot G $$
$$\begin{aligned}
\text{where}& \hspace{1000pt} \\
t & \text{ is secret adaptor, the secret which will be revealed} \\
T &\text{ is public adaptor} \\
G &\text{ is the Generator point of secp256k1} \\
m &\text{ (the message) is the serialisation of a transaction which spends the output of the 2of2 Multisig.}
\end{aligned}
$$

The function $H_{tagged}(x_1,...,x_n)$ is a hash function where the name 'tagged' is used as literal to init the hash
and if $x_i$ is a Curvepoint then we use the compressed x-key instead. Operator '||' stands for concatenation.

$$H_{tagged}(x_1,...,x_n):=sha256(sha256(sha256('tagged')~||~sha256('tagged'))||x_1||...||x_n)$$

## key aggregation

Technically the key aggregation is of course not part of the signing process. However, for creating the signature using
MuSig2, the aggregated key must be constructed in this way.

$P_a = p_a \cdot G$ is Alice Public Key
generated from random secret key (must not be related nor coming from HD wallet, just ephemeral). The $P_a$ is send to Bob.

Alice does the Key Aggregation in MuSig2

$$(1) \hspace{5pt} P = a_a \cdot P_a + a_b \cdot P_b$$

$$\begin{aligned}
\text{where}& \\
a_a &= H_{agg}(sha256(P_a,P_b),P_a)  \hspace{1000pt} \\
a_b &= 1 \\
P_a &\ne P_b \\
\end{aligned}
$$

by calling `KeyAggContext::new([P_a,P_b])` with the pubkeys of all participants.
$a_i$ is called the coefficients.

### Sign round 1

Alice creates 2 Nonces:
$R_{a,1}$ and $R_{a,2}$ and sends them around. She keeps the secret nonce $r_{a,1}$ and $r_{a,2}$ for herself.
This is done via `SecNonce::generate(...).public_nonce()` and sending the public nonce to Bob.

Up to here, its independent of the message and can be precalculated.

### Sign round 2

From collected Nonce the aggregated Nonce $R$ is calculated:

$$\begin{aligned}
(2)~~ R_1 &= R_{a,1} + R_{b,1} \\
R_2 &= R_{a,2} + R_{b,2} \\
b &= H_{non}(R_1 , R_2, P, m) \\
(3)~~ R &= R_1 + b \cdot R_2 + T
\end{aligned}$$

Note that the $T$ is added to $R$, this seperates normal MuSig2 from adaptive MuSig2.
This is done via `AggNonce::sum()` and `musig2::adaptor::sign_partial(T)`. This is split into 2 methods, the aggregated Nounce is in `musig2`
without Adaptor T, it will be added in the second method right before generating the partial signature.

Alice creates her partial signature

$$(4)\hspace{5pt} s_a = r_{a,1} + b \cdot r_{a,2} + a_a \cdot H_{sig}(R,P,m) \cdot p_a$$

$s_a$ is the partial signature calculated via `musig2::adaptor::sign_partial(T)` (Note that the public Nonces have been
exchanged already)

Note, that when Bob calculates his partial signature with (4) he can be sure, that his signature can only be used with
the adaptor $T$, since $R$ is part of the hash-function and $R$ is dependent of $T$.
The partial signature get exchanged. And the other side can verify the validity of the partial signature.
We can multiply equation (4) with $G$ and verify the partial signature with this form:

$$s_a \cdot G = R_{a,1} + b \cdot R_{a,2}+a_a \cdot H_{sig}(R,P,m) \cdot P_a$$

This is being done by calling
`musig2::adaptor::verify_partial()` which is also done within `musig2::adaptor::sign_partial(T)`. Partial signature
from other parties should be verified using this method. AdamISZ pointed out that there is a possible
[Forgery with a fake key in MuSig2](https://gist.github.com/AdamISZ/ca974ed67889cedc738c4a1f65ff620b). This does not
apply to our use case, since the necessary ramification for the forgery are not given.

## Signature aggregation

The partial signatures get aggregated using

$$s=s_a+s_b$$

with the method `musig2::adaptor::aggregate_partial_signatures()`. Since we added a $T$ into the signature (3), this is only a
pre-signature, not a valid signature.
We can prove that this pre-signature is indeed a valid adaptor signature by multiplying with $G$ and
setting $e:=H_{sig}(R,P,m)$:

$$\begin{aligned}
s\cdot G &= s_a\cdot G+s_b\cdot G ;| ~~ with (4) \\
&=(r_{a,1} + b \cdot r_{a,2} + a_a \cdot e \cdot p_a)\cdot G + (r_{b,1}+b \cdot r_{b,2} + a_b \cdot e \cdot p_b)\cdot G \\
&=R_{a,1}+b\cdot R_{a,2} + a_a\cdot e \cdot P_a + R_{b,1}+b\cdot R_{b,2} + a_b\cdot e \cdot P_b;| ~~ with (2) \\
&= R_1 + b \cdot R_2 + a_a \cdot e \cdot P_a + a_b \cdot e \cdot P_b;| ~~ with (1) \\
&= R_1 + b \cdot R_2 + e \cdot P;| ~~ with (3) \\
&= R - T + e \cdot P
\end{aligned}$$

that means

$$\begin{aligned}
s \cdot G + T &= R+e \cdot P \\
\Leftrightarrow (s + t) \cdot G &= R + e \cdot P
\end{aligned}$$

so with the discrete logarithm (DLOG) of $T$, which is  $t$, we would have a valid signature.

This is being verified by calling `musig2::adaptor::aggregate_partial_signatures()`.

Alice
has the knowledge of $t$ and can make this a valid signature.
Alice must "adapt" the pre-signature with `t`using `adaptor_signature.adapt(adaptor_secret)` and
gets  $s' = s+t$. To verify that the final signature $s'$ is correct, we call `musig2::verify_single()`

Alice can use the signature $Sig(s',R)$ and broadcast the Transaction. In the mempool or on the
blockchain, Bob can
find $s'$. Bob can calculate $t=s' - s$ by using `adaptor_signature.reveal_secret(&valid_signature)`
with $s, s'$.
