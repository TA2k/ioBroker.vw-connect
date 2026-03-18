.class public abstract Llp/gf;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lay0/k;Lkotlin/coroutines/Continuation;Lla/u;)Ljava/lang/Object;
    .locals 2

    .line 1
    invoke-virtual {p2}, Lla/u;->l()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p2}, Lla/u;->o()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    invoke-virtual {p2}, Lla/u;->m()Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0

    .line 24
    :cond_0
    invoke-interface {p1}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    sget-object v1, Lla/x;->d:Lla/x;

    .line 29
    .line 30
    invoke-interface {v0, v1}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    if-nez v0, :cond_1

    .line 35
    .line 36
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0

    .line 41
    :cond_1
    invoke-static {p0, p1, p2}, Llp/gf;->c(Lay0/k;Lkotlin/coroutines/Continuation;Lla/u;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    return-object p0
.end method

.method public static varargs b(Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-string p1, "PowerAuthLibrary"

    .line 6
    .line 7
    invoke-static {p1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public static final c(Lay0/k;Lkotlin/coroutines/Continuation;Lla/u;)Ljava/lang/Object;
    .locals 3

    .line 1
    new-instance v0, Lew/f;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, p0, v2, v1}, Lew/f;-><init>(Lay0/k;Lkotlin/coroutines/Continuation;I)V

    .line 6
    .line 7
    .line 8
    invoke-interface {p1}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    sget-object v1, Lla/z;->e:Lla/y;

    .line 13
    .line 14
    invoke-interface {p0, v1}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    check-cast p0, Lla/z;

    .line 19
    .line 20
    if-eqz p0, :cond_0

    .line 21
    .line 22
    iget-object p0, p0, Lla/z;->d:Lpx0/d;

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    move-object p0, v2

    .line 26
    :goto_0
    if-eqz p0, :cond_1

    .line 27
    .line 28
    invoke-static {p0, v0, p1}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0

    .line 33
    :cond_1
    new-instance p0, Lvy0/l;

    .line 34
    .line 35
    invoke-static {p1}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    const/4 v1, 0x1

    .line 40
    invoke-direct {p0, v1, p1}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p0}, Lvy0/l;->q()V

    .line 44
    .line 45
    .line 46
    :try_start_0
    iget-object p1, p2, Lla/u;->d:Lla/a0;

    .line 47
    .line 48
    if-eqz p1, :cond_2

    .line 49
    .line 50
    new-instance v1, Lio/i;

    .line 51
    .line 52
    const/4 v2, 0x2

    .line 53
    invoke-direct {v1, p0, p2, v0, v2}, Lio/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {p1, v1}, Lla/a0;->execute(Ljava/lang/Runnable;)V

    .line 57
    .line 58
    .line 59
    goto :goto_2

    .line 60
    :catch_0
    move-exception p1

    .line 61
    goto :goto_1

    .line 62
    :cond_2
    const-string p1, "internalTransactionExecutor"

    .line 63
    .line 64
    invoke-static {p1}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    throw v2
    :try_end_0
    .catch Ljava/util/concurrent/RejectedExecutionException; {:try_start_0 .. :try_end_0} :catch_0

    .line 68
    :goto_1
    new-instance p2, Ljava/lang/IllegalStateException;

    .line 69
    .line 70
    const-string v0, "Unable to acquire a thread to perform the database transaction."

    .line 71
    .line 72
    invoke-direct {p2, v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {p0, p2}, Lvy0/l;->c(Ljava/lang/Throwable;)Z

    .line 76
    .line 77
    .line 78
    :goto_2
    invoke-virtual {p0}, Lvy0/l;->p()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 83
    .line 84
    return-object p0
.end method
