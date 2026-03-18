.class public final Lg1/h1;
.super Lg1/d1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public C:Lg1/i1;

.field public D:Lg1/w1;

.field public E:Z

.field public F:Lay0/o;

.field public G:Lay0/o;

.field public H:Z


# virtual methods
.method public final e1(Lg1/c1;Lg1/c1;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lg1/h1;->C:Lg1/i1;

    .line 2
    .line 3
    sget-object v1, Le1/w0;->d:Le1/w0;

    .line 4
    .line 5
    new-instance v1, Le1/e;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    const/16 v3, 0x1b

    .line 9
    .line 10
    invoke-direct {v1, v3, p1, p0, v2}, Le1/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    invoke-interface {v0, v1, p2}, Lg1/i1;->a(Le1/e;Lg1/c1;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 18
    .line 19
    if-ne p0, p1, :cond_0

    .line 20
    .line 21
    return-object p0

    .line 22
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    return-object p0
.end method

.method public final f1(J)V
    .locals 8

    .line 1
    iget-boolean v0, p0, Lx2/r;->q:Z

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    iget-object v0, p0, Lg1/h1;->F:Lay0/o;

    .line 6
    .line 7
    sget-object v1, Lg1/f1;->a:Lg1/e1;

    .line 8
    .line 9
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    invoke-virtual {p0}, Lx2/r;->L0()Lvy0/b0;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    sget-object v1, Lvy0/c0;->g:Lvy0/c0;

    .line 21
    .line 22
    new-instance v2, Lg1/g1;

    .line 23
    .line 24
    const/4 v7, 0x0

    .line 25
    const/4 v6, 0x0

    .line 26
    move-object v3, p0

    .line 27
    move-wide v4, p1

    .line 28
    invoke-direct/range {v2 .. v7}, Lg1/g1;-><init>(Lg1/h1;JLkotlin/coroutines/Continuation;I)V

    .line 29
    .line 30
    .line 31
    const/4 p0, 0x1

    .line 32
    invoke-static {v0, v6, v1, v2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 33
    .line 34
    .line 35
    :cond_1
    :goto_0
    return-void
.end method

.method public final g1(J)V
    .locals 8

    .line 1
    iget-boolean v0, p0, Lx2/r;->q:Z

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    iget-object v0, p0, Lg1/h1;->G:Lay0/o;

    .line 6
    .line 7
    sget-object v1, Lg1/f1;->b:Lg1/e1;

    .line 8
    .line 9
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    invoke-virtual {p0}, Lx2/r;->L0()Lvy0/b0;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    sget-object v1, Lvy0/c0;->g:Lvy0/c0;

    .line 21
    .line 22
    new-instance v2, Lg1/g1;

    .line 23
    .line 24
    const/4 v7, 0x1

    .line 25
    const/4 v6, 0x0

    .line 26
    move-object v3, p0

    .line 27
    move-wide v4, p1

    .line 28
    invoke-direct/range {v2 .. v7}, Lg1/g1;-><init>(Lg1/h1;JLkotlin/coroutines/Continuation;I)V

    .line 29
    .line 30
    .line 31
    const/4 p0, 0x1

    .line 32
    invoke-static {v0, v6, v1, v2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 33
    .line 34
    .line 35
    :cond_1
    :goto_0
    return-void
.end method

.method public final h1()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lg1/h1;->E:Z

    .line 2
    .line 3
    return p0
.end method
