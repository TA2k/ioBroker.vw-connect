.class public final Lvp/t0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public A:Ljava/lang/Long;

.field public B:J

.field public C:Ljava/lang/String;

.field public D:I

.field public E:I

.field public F:J

.field public G:Ljava/lang/String;

.field public H:[B

.field public I:I

.field public J:J

.field public K:J

.field public L:J

.field public M:J

.field public N:J

.field public O:J

.field public P:Ljava/lang/String;

.field public Q:Z

.field public R:J

.field public S:J

.field public final a:Lvp/g1;

.field public final b:Ljava/lang/String;

.field public c:Ljava/lang/String;

.field public d:Ljava/lang/String;

.field public e:Ljava/lang/String;

.field public f:Ljava/lang/String;

.field public g:J

.field public h:J

.field public i:J

.field public j:Ljava/lang/String;

.field public k:J

.field public l:Ljava/lang/String;

.field public m:J

.field public n:J

.field public o:Z

.field public p:Z

.field public q:Ljava/lang/Boolean;

.field public r:J

.field public s:Ljava/util/ArrayList;

.field public t:Ljava/lang/String;

.field public u:Z

.field public v:J

.field public w:J

.field public x:I

.field public y:Z

.field public z:Ljava/lang/Long;


# direct methods
.method public constructor <init>(Lvp/g1;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 5
    .line 6
    .line 7
    invoke-static {p2}, Lno/c0;->e(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lvp/t0;->a:Lvp/g1;

    .line 11
    .line 12
    iput-object p2, p0, Lvp/t0;->b:Ljava/lang/String;

    .line 13
    .line 14
    iget-object p0, p1, Lvp/g1;->j:Lvp/e1;

    .line 15
    .line 16
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p0}, Lvp/e1;->a0()V

    .line 20
    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final A(J)V
    .locals 3

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-boolean v0, p0, Lvp/t0;->Q:Z

    .line 12
    .line 13
    iget-wide v1, p0, Lvp/t0;->w:J

    .line 14
    .line 15
    cmp-long v1, v1, p1

    .line 16
    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    const/4 v1, 0x1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v1, 0x0

    .line 22
    :goto_0
    or-int/2addr v0, v1

    .line 23
    iput-boolean v0, p0, Lvp/t0;->Q:Z

    .line 24
    .line 25
    iput-wide p1, p0, Lvp/t0;->w:J

    .line 26
    .line 27
    return-void
.end method

.method public final B(J)V
    .locals 3

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-boolean v0, p0, Lvp/t0;->Q:Z

    .line 12
    .line 13
    iget-wide v1, p0, Lvp/t0;->B:J

    .line 14
    .line 15
    cmp-long v1, v1, p1

    .line 16
    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    const/4 v1, 0x1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v1, 0x0

    .line 22
    :goto_0
    or-int/2addr v0, v1

    .line 23
    iput-boolean v0, p0, Lvp/t0;->Q:Z

    .line 24
    .line 25
    iput-wide p1, p0, Lvp/t0;->B:J

    .line 26
    .line 27
    return-void
.end method

.method public final C()Ljava/lang/String;
    .locals 1

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lvp/t0;->C:Ljava/lang/String;

    .line 12
    .line 13
    return-object p0
.end method

.method public final D()Ljava/lang/String;
    .locals 1

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lvp/t0;->b:Ljava/lang/String;

    .line 12
    .line 13
    return-object p0
.end method

.method public final E()Ljava/lang/String;
    .locals 1

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lvp/t0;->c:Ljava/lang/String;

    .line 12
    .line 13
    return-object p0
.end method

.method public final F(Ljava/lang/String;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-boolean v0, p0, Lvp/t0;->Q:Z

    .line 12
    .line 13
    iget-object v1, p0, Lvp/t0;->c:Ljava/lang/String;

    .line 14
    .line 15
    invoke-static {v1, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    xor-int/lit8 v1, v1, 0x1

    .line 20
    .line 21
    or-int/2addr v0, v1

    .line 22
    iput-boolean v0, p0, Lvp/t0;->Q:Z

    .line 23
    .line 24
    iput-object p1, p0, Lvp/t0;->c:Ljava/lang/String;

    .line 25
    .line 26
    return-void
.end method

.method public final G()Ljava/lang/String;
    .locals 1

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lvp/t0;->d:Ljava/lang/String;

    .line 12
    .line 13
    return-object p0
.end method

.method public final H(Ljava/lang/String;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    const/4 v1, 0x1

    .line 16
    if-ne v1, v0, :cond_0

    .line 17
    .line 18
    const/4 p1, 0x0

    .line 19
    :cond_0
    iget-boolean v0, p0, Lvp/t0;->Q:Z

    .line 20
    .line 21
    iget-object v2, p0, Lvp/t0;->d:Ljava/lang/String;

    .line 22
    .line 23
    invoke-static {v2, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    xor-int/2addr v1, v2

    .line 28
    or-int/2addr v0, v1

    .line 29
    iput-boolean v0, p0, Lvp/t0;->Q:Z

    .line 30
    .line 31
    iput-object p1, p0, Lvp/t0;->d:Ljava/lang/String;

    .line 32
    .line 33
    return-void
.end method

.method public final I(Ljava/lang/String;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-boolean v0, p0, Lvp/t0;->Q:Z

    .line 12
    .line 13
    iget-object v1, p0, Lvp/t0;->e:Ljava/lang/String;

    .line 14
    .line 15
    invoke-static {v1, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    xor-int/lit8 v1, v1, 0x1

    .line 20
    .line 21
    or-int/2addr v0, v1

    .line 22
    iput-boolean v0, p0, Lvp/t0;->Q:Z

    .line 23
    .line 24
    iput-object p1, p0, Lvp/t0;->e:Ljava/lang/String;

    .line 25
    .line 26
    return-void
.end method

.method public final J()Ljava/lang/String;
    .locals 1

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lvp/t0;->f:Ljava/lang/String;

    .line 12
    .line 13
    return-object p0
.end method

.method public final K(Ljava/lang/String;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-boolean v0, p0, Lvp/t0;->Q:Z

    .line 12
    .line 13
    iget-object v1, p0, Lvp/t0;->f:Ljava/lang/String;

    .line 14
    .line 15
    invoke-static {v1, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    xor-int/lit8 v1, v1, 0x1

    .line 20
    .line 21
    or-int/2addr v0, v1

    .line 22
    iput-boolean v0, p0, Lvp/t0;->Q:Z

    .line 23
    .line 24
    iput-object p1, p0, Lvp/t0;->f:Ljava/lang/String;

    .line 25
    .line 26
    return-void
.end method

.method public final L(J)V
    .locals 3

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-boolean v0, p0, Lvp/t0;->Q:Z

    .line 12
    .line 13
    iget-wide v1, p0, Lvp/t0;->h:J

    .line 14
    .line 15
    cmp-long v1, v1, p1

    .line 16
    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    const/4 v1, 0x1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v1, 0x0

    .line 22
    :goto_0
    or-int/2addr v0, v1

    .line 23
    iput-boolean v0, p0, Lvp/t0;->Q:Z

    .line 24
    .line 25
    iput-wide p1, p0, Lvp/t0;->h:J

    .line 26
    .line 27
    return-void
.end method

.method public final M(J)V
    .locals 3

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-boolean v0, p0, Lvp/t0;->Q:Z

    .line 12
    .line 13
    iget-wide v1, p0, Lvp/t0;->i:J

    .line 14
    .line 15
    cmp-long v1, v1, p1

    .line 16
    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    const/4 v1, 0x1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v1, 0x0

    .line 22
    :goto_0
    or-int/2addr v0, v1

    .line 23
    iput-boolean v0, p0, Lvp/t0;->Q:Z

    .line 24
    .line 25
    iput-wide p1, p0, Lvp/t0;->i:J

    .line 26
    .line 27
    return-void
.end method

.method public final N()Ljava/lang/String;
    .locals 1

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lvp/t0;->j:Ljava/lang/String;

    .line 12
    .line 13
    return-object p0
.end method

.method public final O(Ljava/lang/String;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-boolean v0, p0, Lvp/t0;->Q:Z

    .line 12
    .line 13
    iget-object v1, p0, Lvp/t0;->j:Ljava/lang/String;

    .line 14
    .line 15
    invoke-static {v1, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    xor-int/lit8 v1, v1, 0x1

    .line 20
    .line 21
    or-int/2addr v0, v1

    .line 22
    iput-boolean v0, p0, Lvp/t0;->Q:Z

    .line 23
    .line 24
    iput-object p1, p0, Lvp/t0;->j:Ljava/lang/String;

    .line 25
    .line 26
    return-void
.end method

.method public final P()J
    .locals 2

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-wide v0, p0, Lvp/t0;->k:J

    .line 12
    .line 13
    return-wide v0
.end method

.method public final Q(J)V
    .locals 3

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-boolean v0, p0, Lvp/t0;->Q:Z

    .line 12
    .line 13
    iget-wide v1, p0, Lvp/t0;->k:J

    .line 14
    .line 15
    cmp-long v1, v1, p1

    .line 16
    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    const/4 v1, 0x1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v1, 0x0

    .line 22
    :goto_0
    or-int/2addr v0, v1

    .line 23
    iput-boolean v0, p0, Lvp/t0;->Q:Z

    .line 24
    .line 25
    iput-wide p1, p0, Lvp/t0;->k:J

    .line 26
    .line 27
    return-void
.end method

.method public final R(Ljava/lang/String;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-boolean v0, p0, Lvp/t0;->Q:Z

    .line 12
    .line 13
    iget-object v1, p0, Lvp/t0;->l:Ljava/lang/String;

    .line 14
    .line 15
    invoke-static {v1, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    xor-int/lit8 v1, v1, 0x1

    .line 20
    .line 21
    or-int/2addr v0, v1

    .line 22
    iput-boolean v0, p0, Lvp/t0;->Q:Z

    .line 23
    .line 24
    iput-object p1, p0, Lvp/t0;->l:Ljava/lang/String;

    .line 25
    .line 26
    return-void
.end method

.method public final S(J)V
    .locals 3

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-boolean v0, p0, Lvp/t0;->Q:Z

    .line 12
    .line 13
    iget-wide v1, p0, Lvp/t0;->m:J

    .line 14
    .line 15
    cmp-long v1, v1, p1

    .line 16
    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    const/4 v1, 0x1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v1, 0x0

    .line 22
    :goto_0
    or-int/2addr v0, v1

    .line 23
    iput-boolean v0, p0, Lvp/t0;->Q:Z

    .line 24
    .line 25
    iput-wide p1, p0, Lvp/t0;->m:J

    .line 26
    .line 27
    return-void
.end method

.method public final a(J)V
    .locals 3

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-boolean v0, p0, Lvp/t0;->Q:Z

    .line 12
    .line 13
    iget-wide v1, p0, Lvp/t0;->n:J

    .line 14
    .line 15
    cmp-long v1, v1, p1

    .line 16
    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    const/4 v1, 0x1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v1, 0x0

    .line 22
    :goto_0
    or-int/2addr v0, v1

    .line 23
    iput-boolean v0, p0, Lvp/t0;->Q:Z

    .line 24
    .line 25
    iput-wide p1, p0, Lvp/t0;->n:J

    .line 26
    .line 27
    return-void
.end method

.method public final b()J
    .locals 2

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-wide v0, p0, Lvp/t0;->r:J

    .line 12
    .line 13
    return-wide v0
.end method

.method public final c(J)V
    .locals 3

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-boolean v0, p0, Lvp/t0;->Q:Z

    .line 12
    .line 13
    iget-wide v1, p0, Lvp/t0;->r:J

    .line 14
    .line 15
    cmp-long v1, v1, p1

    .line 16
    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    const/4 v1, 0x1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v1, 0x0

    .line 22
    :goto_0
    or-int/2addr v0, v1

    .line 23
    iput-boolean v0, p0, Lvp/t0;->Q:Z

    .line 24
    .line 25
    iput-wide p1, p0, Lvp/t0;->r:J

    .line 26
    .line 27
    return-void
.end method

.method public final d(Z)V
    .locals 2

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-boolean v0, p0, Lvp/t0;->Q:Z

    .line 12
    .line 13
    iget-boolean v1, p0, Lvp/t0;->o:Z

    .line 14
    .line 15
    if-eq v1, p1, :cond_0

    .line 16
    .line 17
    const/4 v1, 0x1

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    const/4 v1, 0x0

    .line 20
    :goto_0
    or-int/2addr v0, v1

    .line 21
    iput-boolean v0, p0, Lvp/t0;->Q:Z

    .line 22
    .line 23
    iput-boolean p1, p0, Lvp/t0;->o:Z

    .line 24
    .line 25
    return-void
.end method

.method public final e(J)V
    .locals 5

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmp-long v0, p1, v0

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v2, 0x1

    .line 7
    if-ltz v0, :cond_0

    .line 8
    .line 9
    move v0, v2

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    move v0, v1

    .line 12
    :goto_0
    invoke-static {v0}, Lno/c0;->a(Z)V

    .line 13
    .line 14
    .line 15
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 16
    .line 17
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 18
    .line 19
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 23
    .line 24
    .line 25
    iget-boolean v0, p0, Lvp/t0;->Q:Z

    .line 26
    .line 27
    iget-wide v3, p0, Lvp/t0;->g:J

    .line 28
    .line 29
    cmp-long v3, v3, p1

    .line 30
    .line 31
    if-eqz v3, :cond_1

    .line 32
    .line 33
    move v1, v2

    .line 34
    :cond_1
    or-int/2addr v0, v1

    .line 35
    iput-boolean v0, p0, Lvp/t0;->Q:Z

    .line 36
    .line 37
    iput-wide p1, p0, Lvp/t0;->g:J

    .line 38
    .line 39
    return-void
.end method

.method public final f(J)V
    .locals 3

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-boolean v0, p0, Lvp/t0;->Q:Z

    .line 12
    .line 13
    iget-wide v1, p0, Lvp/t0;->R:J

    .line 14
    .line 15
    cmp-long v1, v1, p1

    .line 16
    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    const/4 v1, 0x1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v1, 0x0

    .line 22
    :goto_0
    or-int/2addr v0, v1

    .line 23
    iput-boolean v0, p0, Lvp/t0;->Q:Z

    .line 24
    .line 25
    iput-wide p1, p0, Lvp/t0;->R:J

    .line 26
    .line 27
    return-void
.end method

.method public final g(J)V
    .locals 3

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-boolean v0, p0, Lvp/t0;->Q:Z

    .line 12
    .line 13
    iget-wide v1, p0, Lvp/t0;->S:J

    .line 14
    .line 15
    cmp-long v1, v1, p1

    .line 16
    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    const/4 v1, 0x1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v1, 0x0

    .line 22
    :goto_0
    or-int/2addr v0, v1

    .line 23
    iput-boolean v0, p0, Lvp/t0;->Q:Z

    .line 24
    .line 25
    iput-wide p1, p0, Lvp/t0;->S:J

    .line 26
    .line 27
    return-void
.end method

.method public final h(J)V
    .locals 9

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v1, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    iget-object v0, v0, Lvp/g1;->i:Lvp/p0;

    .line 6
    .line 7
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v1}, Lvp/e1;->a0()V

    .line 11
    .line 12
    .line 13
    iget-wide v1, p0, Lvp/t0;->g:J

    .line 14
    .line 15
    add-long/2addr v1, p1

    .line 16
    const-wide/32 v3, 0x7fffffff

    .line 17
    .line 18
    .line 19
    cmp-long v5, v1, v3

    .line 20
    .line 21
    iget-object v6, p0, Lvp/t0;->b:Ljava/lang/String;

    .line 22
    .line 23
    if-lez v5, :cond_0

    .line 24
    .line 25
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 26
    .line 27
    .line 28
    iget-object v1, v0, Lvp/p0;->m:Lvp/n0;

    .line 29
    .line 30
    const-string v2, "Bundle index overflow. appId"

    .line 31
    .line 32
    invoke-static {v6}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 33
    .line 34
    .line 35
    move-result-object v5

    .line 36
    invoke-virtual {v1, v5, v2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    const-wide/16 v1, -0x1

    .line 40
    .line 41
    add-long/2addr v1, p1

    .line 42
    :cond_0
    iget-wide p1, p0, Lvp/t0;->F:J

    .line 43
    .line 44
    const-wide/16 v7, 0x1

    .line 45
    .line 46
    add-long/2addr p1, v7

    .line 47
    cmp-long v3, p1, v3

    .line 48
    .line 49
    if-lez v3, :cond_1

    .line 50
    .line 51
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 52
    .line 53
    .line 54
    iget-object p1, v0, Lvp/p0;->m:Lvp/n0;

    .line 55
    .line 56
    const-string p2, "Delivery index overflow. appId"

    .line 57
    .line 58
    invoke-static {v6}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    invoke-virtual {p1, v0, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    const-wide/16 p1, 0x0

    .line 66
    .line 67
    :cond_1
    const/4 v0, 0x1

    .line 68
    iput-boolean v0, p0, Lvp/t0;->Q:Z

    .line 69
    .line 70
    iput-wide v1, p0, Lvp/t0;->g:J

    .line 71
    .line 72
    iput-wide p1, p0, Lvp/t0;->F:J

    .line 73
    .line 74
    return-void
.end method

.method public final i(J)V
    .locals 3

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-boolean v0, p0, Lvp/t0;->Q:Z

    .line 12
    .line 13
    iget-wide v1, p0, Lvp/t0;->J:J

    .line 14
    .line 15
    cmp-long v1, v1, p1

    .line 16
    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    const/4 v1, 0x1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v1, 0x0

    .line 22
    :goto_0
    or-int/2addr v0, v1

    .line 23
    iput-boolean v0, p0, Lvp/t0;->Q:Z

    .line 24
    .line 25
    iput-wide p1, p0, Lvp/t0;->J:J

    .line 26
    .line 27
    return-void
.end method

.method public final j(J)V
    .locals 3

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-boolean v0, p0, Lvp/t0;->Q:Z

    .line 12
    .line 13
    iget-wide v1, p0, Lvp/t0;->K:J

    .line 14
    .line 15
    cmp-long v1, v1, p1

    .line 16
    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    const/4 v1, 0x1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v1, 0x0

    .line 22
    :goto_0
    or-int/2addr v0, v1

    .line 23
    iput-boolean v0, p0, Lvp/t0;->Q:Z

    .line 24
    .line 25
    iput-wide p1, p0, Lvp/t0;->K:J

    .line 26
    .line 27
    return-void
.end method

.method public final k(J)V
    .locals 3

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-boolean v0, p0, Lvp/t0;->Q:Z

    .line 12
    .line 13
    iget-wide v1, p0, Lvp/t0;->L:J

    .line 14
    .line 15
    cmp-long v1, v1, p1

    .line 16
    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    const/4 v1, 0x1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v1, 0x0

    .line 22
    :goto_0
    or-int/2addr v0, v1

    .line 23
    iput-boolean v0, p0, Lvp/t0;->Q:Z

    .line 24
    .line 25
    iput-wide p1, p0, Lvp/t0;->L:J

    .line 26
    .line 27
    return-void
.end method

.method public final l(J)V
    .locals 3

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-boolean v0, p0, Lvp/t0;->Q:Z

    .line 12
    .line 13
    iget-wide v1, p0, Lvp/t0;->M:J

    .line 14
    .line 15
    cmp-long v1, v1, p1

    .line 16
    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    const/4 v1, 0x1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v1, 0x0

    .line 22
    :goto_0
    or-int/2addr v0, v1

    .line 23
    iput-boolean v0, p0, Lvp/t0;->Q:Z

    .line 24
    .line 25
    iput-wide p1, p0, Lvp/t0;->M:J

    .line 26
    .line 27
    return-void
.end method

.method public final m(J)V
    .locals 3

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-boolean v0, p0, Lvp/t0;->Q:Z

    .line 12
    .line 13
    iget-wide v1, p0, Lvp/t0;->O:J

    .line 14
    .line 15
    cmp-long v1, v1, p1

    .line 16
    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    const/4 v1, 0x1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v1, 0x0

    .line 22
    :goto_0
    or-int/2addr v0, v1

    .line 23
    iput-boolean v0, p0, Lvp/t0;->Q:Z

    .line 24
    .line 25
    iput-wide p1, p0, Lvp/t0;->O:J

    .line 26
    .line 27
    return-void
.end method

.method public final n(J)V
    .locals 3

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-boolean v0, p0, Lvp/t0;->Q:Z

    .line 12
    .line 13
    iget-wide v1, p0, Lvp/t0;->N:J

    .line 14
    .line 15
    cmp-long v1, v1, p1

    .line 16
    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    const/4 v1, 0x1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v1, 0x0

    .line 22
    :goto_0
    or-int/2addr v0, v1

    .line 23
    iput-boolean v0, p0, Lvp/t0;->Q:Z

    .line 24
    .line 25
    iput-wide p1, p0, Lvp/t0;->N:J

    .line 26
    .line 27
    return-void
.end method

.method public final o()Z
    .locals 1

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-boolean p0, p0, Lvp/t0;->Q:Z

    .line 12
    .line 13
    return p0
.end method

.method public final p(I)V
    .locals 2

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-boolean v0, p0, Lvp/t0;->Q:Z

    .line 12
    .line 13
    iget v1, p0, Lvp/t0;->D:I

    .line 14
    .line 15
    if-eq v1, p1, :cond_0

    .line 16
    .line 17
    const/4 v1, 0x1

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    const/4 v1, 0x0

    .line 20
    :goto_0
    or-int/2addr v0, v1

    .line 21
    iput-boolean v0, p0, Lvp/t0;->Q:Z

    .line 22
    .line 23
    iput p1, p0, Lvp/t0;->D:I

    .line 24
    .line 25
    return-void
.end method

.method public final q(I)V
    .locals 2

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-boolean v0, p0, Lvp/t0;->Q:Z

    .line 12
    .line 13
    iget v1, p0, Lvp/t0;->E:I

    .line 14
    .line 15
    if-eq v1, p1, :cond_0

    .line 16
    .line 17
    const/4 v1, 0x1

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    const/4 v1, 0x0

    .line 20
    :goto_0
    or-int/2addr v0, v1

    .line 21
    iput-boolean v0, p0, Lvp/t0;->Q:Z

    .line 22
    .line 23
    iput p1, p0, Lvp/t0;->E:I

    .line 24
    .line 25
    return-void
.end method

.method public final r(J)V
    .locals 3

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-boolean v0, p0, Lvp/t0;->Q:Z

    .line 12
    .line 13
    iget-wide v1, p0, Lvp/t0;->F:J

    .line 14
    .line 15
    cmp-long v1, v1, p1

    .line 16
    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    const/4 v1, 0x1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v1, 0x0

    .line 22
    :goto_0
    or-int/2addr v0, v1

    .line 23
    iput-boolean v0, p0, Lvp/t0;->Q:Z

    .line 24
    .line 25
    iput-wide p1, p0, Lvp/t0;->F:J

    .line 26
    .line 27
    return-void
.end method

.method public final s()Ljava/lang/String;
    .locals 1

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lvp/t0;->G:Ljava/lang/String;

    .line 12
    .line 13
    return-object p0
.end method

.method public final t()I
    .locals 1

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget p0, p0, Lvp/t0;->I:I

    .line 12
    .line 13
    return p0
.end method

.method public final u()Ljava/lang/String;
    .locals 2

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lvp/t0;->P:Ljava/lang/String;

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    invoke-virtual {p0, v1}, Lvp/t0;->v(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    return-object v0
.end method

.method public final v(Ljava/lang/String;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-boolean v0, p0, Lvp/t0;->Q:Z

    .line 12
    .line 13
    iget-object v1, p0, Lvp/t0;->P:Ljava/lang/String;

    .line 14
    .line 15
    invoke-static {v1, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    xor-int/lit8 v1, v1, 0x1

    .line 20
    .line 21
    or-int/2addr v0, v1

    .line 22
    iput-boolean v0, p0, Lvp/t0;->Q:Z

    .line 23
    .line 24
    iput-object p1, p0, Lvp/t0;->P:Ljava/lang/String;

    .line 25
    .line 26
    return-void
.end method

.method public final w()Ljava/lang/Boolean;
    .locals 1

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lvp/t0;->q:Ljava/lang/Boolean;

    .line 12
    .line 13
    return-object p0
.end method

.method public final x(Ljava/util/List;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lvp/t0;->s:Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-static {v0, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-nez v0, :cond_1

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    iput-boolean v0, p0, Lvp/t0;->Q:Z

    .line 21
    .line 22
    if-eqz p1, :cond_0

    .line 23
    .line 24
    new-instance v0, Ljava/util/ArrayList;

    .line 25
    .line 26
    invoke-direct {v0, p1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 27
    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const/4 v0, 0x0

    .line 31
    :goto_0
    iput-object v0, p0, Lvp/t0;->s:Ljava/util/ArrayList;

    .line 32
    .line 33
    :cond_1
    return-void
.end method

.method public final y()Z
    .locals 1

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-boolean p0, p0, Lvp/t0;->u:Z

    .line 12
    .line 13
    return p0
.end method

.method public final z(J)V
    .locals 3

    .line 1
    iget-object v0, p0, Lvp/t0;->a:Lvp/g1;

    .line 2
    .line 3
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 4
    .line 5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 9
    .line 10
    .line 11
    iget-boolean v0, p0, Lvp/t0;->Q:Z

    .line 12
    .line 13
    iget-wide v1, p0, Lvp/t0;->v:J

    .line 14
    .line 15
    cmp-long v1, v1, p1

    .line 16
    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    const/4 v1, 0x1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v1, 0x0

    .line 22
    :goto_0
    or-int/2addr v0, v1

    .line 23
    iput-boolean v0, p0, Lvp/t0;->Q:Z

    .line 24
    .line 25
    iput-wide p1, p0, Lvp/t0;->v:J

    .line 26
    .line 27
    return-void
.end method
