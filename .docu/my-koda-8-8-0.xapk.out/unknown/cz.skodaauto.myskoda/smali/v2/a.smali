.class public final Lv2/a;
.super Lv2/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public final C(Lay0/k;Lay0/k;)Lv2/b;
    .locals 1

    .line 1
    new-instance p0, Lc41/g;

    .line 2
    .line 3
    const/16 v0, 0x17

    .line 4
    .line 5
    invoke-direct {p0, v0, p1, p2}, Lc41/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    new-instance p1, Lv2/k;

    .line 9
    .line 10
    const/4 p2, 0x0

    .line 11
    invoke-direct {p1, p2, p0}, Lv2/k;-><init>(ILay0/k;)V

    .line 12
    .line 13
    .line 14
    invoke-static {p1}, Lv2/l;->f(Lay0/k;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    check-cast p0, Lv2/f;

    .line 19
    .line 20
    check-cast p0, Lv2/b;

    .line 21
    .line 22
    return-object p0
.end method

.method public final c()V
    .locals 1

    .line 1
    sget-object v0, Lv2/l;->c:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    invoke-virtual {p0}, Lv2/f;->o()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 5
    .line 6
    .line 7
    monitor-exit v0

    .line 8
    return-void

    .line 9
    :catchall_0
    move-exception p0

    .line 10
    monitor-exit v0

    .line 11
    throw p0
.end method

.method public final k()V
    .locals 0

    .line 1
    invoke-static {}, Lv2/p;->h()V

    .line 2
    .line 3
    .line 4
    const/4 p0, 0x0

    .line 5
    throw p0
.end method

.method public final l()V
    .locals 0

    .line 1
    invoke-static {}, Lv2/p;->h()V

    .line 2
    .line 3
    .line 4
    const/4 p0, 0x0

    .line 5
    throw p0
.end method

.method public final m()V
    .locals 0

    .line 1
    invoke-static {}, Lv2/l;->a()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final u(Lay0/k;)Lv2/f;
    .locals 1

    .line 1
    new-instance p0, Lfk/b;

    .line 2
    .line 3
    const/4 v0, 0x5

    .line 4
    invoke-direct {p0, v0, p1}, Lfk/b;-><init>(ILay0/k;)V

    .line 5
    .line 6
    .line 7
    new-instance p1, Lv2/k;

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    invoke-direct {p1, v0, p0}, Lv2/k;-><init>(ILay0/k;)V

    .line 11
    .line 12
    .line 13
    invoke-static {p1}, Lv2/l;->f(Lay0/k;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    check-cast p0, Lv2/f;

    .line 18
    .line 19
    check-cast p0, Lv2/e;

    .line 20
    .line 21
    return-object p0
.end method

.method public final w()Lv2/p;
    .locals 1

    .line 1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 2
    .line 3
    const-string v0, "Cannot apply the global snapshot directly. Call Snapshot.advanceGlobalSnapshot"

    .line 4
    .line 5
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    throw p0
.end method
