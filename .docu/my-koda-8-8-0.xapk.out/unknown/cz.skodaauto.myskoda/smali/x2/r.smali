.class public abstract Lx2/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/m;


# instance fields
.field public d:Lx2/r;

.field public e:Lpw0/a;

.field public f:I

.field public g:I

.field public h:Lx2/r;

.field public i:Lx2/r;

.field public j:Lv3/k1;

.field public k:Lv3/f1;

.field public l:Z

.field public m:Z

.field public n:Z

.field public o:Z

.field public p:La4/b;

.field public q:Z


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p0, p0, Lx2/r;->d:Lx2/r;

    .line 5
    .line 6
    const/4 v0, -0x1

    .line 7
    iput v0, p0, Lx2/r;->g:I

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final L0()Lvy0/b0;
    .locals 3

    .line 1
    iget-object v0, p0, Lx2/r;->e:Lpw0/a;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-static {p0}, Lv3/f;->y(Lv3/m;)Lv3/o1;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    check-cast v0, Lw3/t;

    .line 10
    .line 11
    invoke-virtual {v0}, Lw3/t;->getCoroutineContext()Lpx0/g;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-static {p0}, Lv3/f;->y(Lv3/m;)Lv3/o1;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    check-cast v1, Lw3/t;

    .line 20
    .line 21
    invoke-virtual {v1}, Lw3/t;->getCoroutineContext()Lpx0/g;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    sget-object v2, Lvy0/h1;->d:Lvy0/h1;

    .line 26
    .line 27
    invoke-interface {v1, v2}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    check-cast v1, Lvy0/i1;

    .line 32
    .line 33
    new-instance v2, Lvy0/k1;

    .line 34
    .line 35
    invoke-direct {v2, v1}, Lvy0/k1;-><init>(Lvy0/i1;)V

    .line 36
    .line 37
    .line 38
    invoke-interface {v0, v2}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    invoke-static {v0}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    iput-object v0, p0, Lx2/r;->e:Lpw0/a;

    .line 47
    .line 48
    :cond_0
    return-object v0
.end method

.method public M0()Z
    .locals 0

    .line 1
    instance-of p0, p0, Le1/n;

    .line 2
    .line 3
    xor-int/lit8 p0, p0, 0x1

    .line 4
    .line 5
    return p0
.end method

.method public N0()V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lx2/r;->q:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const-string v0, "node attached multiple times"

    .line 6
    .line 7
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    iget-object v0, p0, Lx2/r;->k:Lv3/f1;

    .line 11
    .line 12
    if-eqz v0, :cond_1

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_1
    const-string v0, "attach invoked on a node without a coordinator"

    .line 16
    .line 17
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    :goto_0
    const/4 v0, 0x1

    .line 21
    iput-boolean v0, p0, Lx2/r;->q:Z

    .line 22
    .line 23
    iput-boolean v0, p0, Lx2/r;->n:Z

    .line 24
    .line 25
    return-void
.end method

.method public O0()V
    .locals 4

    .line 1
    iget-boolean v0, p0, Lx2/r;->q:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const-string v0, "Cannot detach a node that is not attached"

    .line 6
    .line 7
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    iget-boolean v0, p0, Lx2/r;->n:Z

    .line 11
    .line 12
    if-eqz v0, :cond_1

    .line 13
    .line 14
    const-string v0, "Must run runAttachLifecycle() before markAsDetached()"

    .line 15
    .line 16
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    :cond_1
    iget-boolean v0, p0, Lx2/r;->o:Z

    .line 20
    .line 21
    if-eqz v0, :cond_2

    .line 22
    .line 23
    const-string v0, "Must run runDetachLifecycle() before markAsDetached()"

    .line 24
    .line 25
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    :cond_2
    const/4 v0, 0x0

    .line 29
    iput-boolean v0, p0, Lx2/r;->q:Z

    .line 30
    .line 31
    iget-object v0, p0, Lx2/r;->e:Lpw0/a;

    .line 32
    .line 33
    if-eqz v0, :cond_3

    .line 34
    .line 35
    new-instance v1, Lp3/w;

    .line 36
    .line 37
    const-string v2, "The Modifier.Node was detached"

    .line 38
    .line 39
    const/4 v3, 0x1

    .line 40
    invoke-direct {v1, v2, v3}, Lj1/c;-><init>(Ljava/lang/String;I)V

    .line 41
    .line 42
    .line 43
    invoke-static {v0, v1}, Lvy0/e0;->j(Lvy0/b0;Ljava/util/concurrent/CancellationException;)V

    .line 44
    .line 45
    .line 46
    const/4 v0, 0x0

    .line 47
    iput-object v0, p0, Lx2/r;->e:Lpw0/a;

    .line 48
    .line 49
    :cond_3
    return-void
.end method

.method public P0()V
    .locals 0

    .line 1
    return-void
.end method

.method public Q0()V
    .locals 0

    .line 1
    return-void
.end method

.method public R0()V
    .locals 0

    .line 1
    return-void
.end method

.method public S0()V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lx2/r;->q:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const-string v0, "reset() called on an unattached node"

    .line 6
    .line 7
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    invoke-virtual {p0}, Lx2/r;->R0()V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public T0()V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lx2/r;->q:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const-string v0, "Must run markAsAttached() prior to runAttachLifecycle"

    .line 6
    .line 7
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    iget-boolean v0, p0, Lx2/r;->n:Z

    .line 11
    .line 12
    if-nez v0, :cond_1

    .line 13
    .line 14
    const-string v0, "Must run runAttachLifecycle() only once after markAsAttached()"

    .line 15
    .line 16
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    :cond_1
    const/4 v0, 0x0

    .line 20
    iput-boolean v0, p0, Lx2/r;->n:Z

    .line 21
    .line 22
    invoke-virtual {p0}, Lx2/r;->P0()V

    .line 23
    .line 24
    .line 25
    const/4 v0, 0x1

    .line 26
    iput-boolean v0, p0, Lx2/r;->o:Z

    .line 27
    .line 28
    return-void
.end method

.method public U0()V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lx2/r;->q:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const-string v0, "node detached multiple times"

    .line 6
    .line 7
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    iget-object v0, p0, Lx2/r;->k:Lv3/f1;

    .line 11
    .line 12
    if-eqz v0, :cond_1

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_1
    const-string v0, "detach invoked on a node without a coordinator"

    .line 16
    .line 17
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    :goto_0
    iget-boolean v0, p0, Lx2/r;->o:Z

    .line 21
    .line 22
    if-nez v0, :cond_2

    .line 23
    .line 24
    const-string v0, "Must run runDetachLifecycle() once after runAttachLifecycle() and before markAsDetached()"

    .line 25
    .line 26
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    :cond_2
    const/4 v0, 0x0

    .line 30
    iput-boolean v0, p0, Lx2/r;->o:Z

    .line 31
    .line 32
    iget-object v0, p0, Lx2/r;->p:La4/b;

    .line 33
    .line 34
    if-eqz v0, :cond_3

    .line 35
    .line 36
    invoke-virtual {v0}, La4/b;->invoke()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    :cond_3
    invoke-virtual {p0}, Lx2/r;->Q0()V

    .line 40
    .line 41
    .line 42
    return-void
.end method

.method public V0(Lx2/r;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lx2/r;->d:Lx2/r;

    .line 2
    .line 3
    return-void
.end method

.method public W0(Lv3/f1;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lx2/r;->k:Lv3/f1;

    .line 2
    .line 3
    return-void
.end method
