.class public final Lum/o;
.super Ljava/util/concurrent/FutureTask;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Lum/p;


# virtual methods
.method public final done()V
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    :try_start_0
    invoke-virtual {p0}, Ljava/util/concurrent/FutureTask;->isCancelled()Z

    .line 3
    .line 4
    .line 5
    move-result v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    iput-object v0, p0, Lum/o;->d:Lum/p;

    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    :try_start_1
    iget-object v1, p0, Lum/o;->d:Lum/p;

    .line 12
    .line 13
    invoke-virtual {p0}, Ljava/util/concurrent/FutureTask;->get()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    check-cast v2, Lum/n;

    .line 18
    .line 19
    invoke-virtual {v1, v2}, Lum/p;->d(Lum/n;)V
    :try_end_1
    .catch Ljava/lang/InterruptedException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 20
    .line 21
    .line 22
    goto :goto_0

    .line 23
    :catchall_0
    move-exception v1

    .line 24
    goto :goto_1

    .line 25
    :catch_0
    move-exception v1

    .line 26
    :try_start_2
    iget-object v2, p0, Lum/o;->d:Lum/p;

    .line 27
    .line 28
    new-instance v3, Lum/n;

    .line 29
    .line 30
    invoke-direct {v3, v1}, Lum/n;-><init>(Ljava/lang/Throwable;)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v2, v3}, Lum/p;->d(Lum/n;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 34
    .line 35
    .line 36
    :goto_0
    iput-object v0, p0, Lum/o;->d:Lum/p;

    .line 37
    .line 38
    return-void

    .line 39
    :goto_1
    iput-object v0, p0, Lum/o;->d:Lum/p;

    .line 40
    .line 41
    throw v1
.end method
