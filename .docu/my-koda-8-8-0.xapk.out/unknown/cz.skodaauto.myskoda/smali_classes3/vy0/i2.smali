.class public final Lvy0/i2;
.super Laz0/p;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ljava/lang/ThreadLocal;

.field private volatile threadLocalIsSet:Z


# direct methods
.method public constructor <init>(Lkotlin/coroutines/Continuation;Lpx0/g;)V
    .locals 2

    .line 1
    sget-object v0, Lvy0/j2;->d:Lvy0/j2;

    .line 2
    .line 3
    invoke-interface {p2, v0}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    invoke-interface {p2, v0}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    move-object v0, p2

    .line 15
    :goto_0
    invoke-direct {p0, p1, v0}, Laz0/p;-><init>(Lkotlin/coroutines/Continuation;Lpx0/g;)V

    .line 16
    .line 17
    .line 18
    new-instance v0, Ljava/lang/ThreadLocal;

    .line 19
    .line 20
    invoke-direct {v0}, Ljava/lang/ThreadLocal;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Lvy0/i2;->h:Ljava/lang/ThreadLocal;

    .line 24
    .line 25
    invoke-interface {p1}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    sget-object v0, Lpx0/c;->d:Lpx0/c;

    .line 30
    .line 31
    invoke-interface {p1, v0}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    instance-of p1, p1, Lvy0/x;

    .line 36
    .line 37
    if-nez p1, :cond_1

    .line 38
    .line 39
    const/4 p1, 0x0

    .line 40
    invoke-static {p2, p1}, Laz0/b;->n(Lpx0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    invoke-static {p2, p1}, Laz0/b;->g(Lpx0/g;Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {p0, p2, p1}, Lvy0/i2;->r0(Lpx0/g;Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    :cond_1
    return-void
.end method


# virtual methods
.method public final o0()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lvy0/i2;->q0()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final p0()Z
    .locals 2

    .line 1
    iget-boolean v0, p0, Lvy0/i2;->threadLocalIsSet:Z

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    iget-object v0, p0, Lvy0/i2;->h:Ljava/lang/ThreadLocal;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    if-nez v0, :cond_0

    .line 13
    .line 14
    move v0, v1

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    const/4 v0, 0x0

    .line 17
    :goto_0
    iget-object p0, p0, Lvy0/i2;->h:Ljava/lang/ThreadLocal;

    .line 18
    .line 19
    invoke-virtual {p0}, Ljava/lang/ThreadLocal;->remove()V

    .line 20
    .line 21
    .line 22
    xor-int/lit8 p0, v0, 0x1

    .line 23
    .line 24
    return p0
.end method

.method public final q0()V
    .locals 2

    .line 1
    iget-boolean v0, p0, Lvy0/i2;->threadLocalIsSet:Z

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    iget-object v0, p0, Lvy0/i2;->h:Ljava/lang/ThreadLocal;

    .line 6
    .line 7
    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    check-cast v0, Llx0/l;

    .line 12
    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    iget-object v1, v0, Llx0/l;->d:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v1, Lpx0/g;

    .line 18
    .line 19
    iget-object v0, v0, Llx0/l;->e:Ljava/lang/Object;

    .line 20
    .line 21
    invoke-static {v1, v0}, Laz0/b;->g(Lpx0/g;Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    :cond_0
    iget-object p0, p0, Lvy0/i2;->h:Ljava/lang/ThreadLocal;

    .line 25
    .line 26
    invoke-virtual {p0}, Ljava/lang/ThreadLocal;->remove()V

    .line 27
    .line 28
    .line 29
    :cond_1
    return-void
.end method

.method public final r0(Lpx0/g;Ljava/lang/Object;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lvy0/i2;->threadLocalIsSet:Z

    .line 3
    .line 4
    iget-object p0, p0, Lvy0/i2;->h:Ljava/lang/ThreadLocal;

    .line 5
    .line 6
    new-instance v0, Llx0/l;

    .line 7
    .line 8
    invoke-direct {v0, p1, p2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0, v0}, Ljava/lang/ThreadLocal;->set(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public final x(Ljava/lang/Object;)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lvy0/i2;->q0()V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Lvy0/e0;->I(Ljava/lang/Object;)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    iget-object p0, p0, Laz0/p;->g:Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-interface {p0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    const/4 v1, 0x0

    .line 15
    invoke-static {v0, v1}, Laz0/b;->n(Lpx0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    sget-object v3, Laz0/b;->d:Lj51/i;

    .line 20
    .line 21
    if-eq v2, v3, :cond_0

    .line 22
    .line 23
    invoke-static {p0, v0, v2}, Lvy0/e0;->Q(Lkotlin/coroutines/Continuation;Lpx0/g;Ljava/lang/Object;)Lvy0/i2;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    :cond_0
    :try_start_0
    invoke-interface {p0, p1}, Lkotlin/coroutines/Continuation;->resumeWith(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 28
    .line 29
    .line 30
    if-eqz v1, :cond_2

    .line 31
    .line 32
    invoke-virtual {v1}, Lvy0/i2;->p0()Z

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    if-eqz p0, :cond_1

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_1
    return-void

    .line 40
    :cond_2
    :goto_0
    invoke-static {v0, v2}, Laz0/b;->g(Lpx0/g;Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :catchall_0
    move-exception p0

    .line 45
    if-eqz v1, :cond_3

    .line 46
    .line 47
    invoke-virtual {v1}, Lvy0/i2;->p0()Z

    .line 48
    .line 49
    .line 50
    move-result p1

    .line 51
    if-eqz p1, :cond_4

    .line 52
    .line 53
    :cond_3
    invoke-static {v0, v2}, Laz0/b;->g(Lpx0/g;Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    :cond_4
    throw p0
.end method
