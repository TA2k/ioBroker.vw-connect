.class public final Lg11/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Z

.field public b:Z

.field public c:Ljava/lang/Object;


# virtual methods
.method public a()V
    .locals 4

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-boolean v0, p0, Lg11/k;->a:Z

    .line 3
    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    monitor-exit p0

    .line 7
    return-void

    .line 8
    :catchall_0
    move-exception v0

    .line 9
    goto :goto_2

    .line 10
    :cond_0
    const/4 v0, 0x1

    .line 11
    iput-boolean v0, p0, Lg11/k;->a:Z

    .line 12
    .line 13
    iput-boolean v0, p0, Lg11/k;->b:Z

    .line 14
    .line 15
    iget-object v0, p0, Lg11/k;->c:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v0, Lbb/i;

    .line 18
    .line 19
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 20
    const/4 v1, 0x0

    .line 21
    if-eqz v0, :cond_2

    .line 22
    .line 23
    :try_start_1
    iget-object v2, v0, Lbb/i;->e:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v2, Ljava/lang/Runnable;

    .line 26
    .line 27
    iget-object v3, v0, Lbb/i;->g:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast v3, Lbb/x;

    .line 30
    .line 31
    iget-object v0, v0, Lbb/i;->f:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast v0, Ljava/lang/Runnable;

    .line 34
    .line 35
    if-nez v2, :cond_1

    .line 36
    .line 37
    invoke-virtual {v3}, Lbb/x;->cancel()V

    .line 38
    .line 39
    .line 40
    invoke-interface {v0}, Ljava/lang/Runnable;->run()V

    .line 41
    .line 42
    .line 43
    goto :goto_1

    .line 44
    :catchall_1
    move-exception v0

    .line 45
    goto :goto_0

    .line 46
    :cond_1
    invoke-interface {v2}, Ljava/lang/Runnable;->run()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 47
    .line 48
    .line 49
    goto :goto_1

    .line 50
    :goto_0
    monitor-enter p0

    .line 51
    :try_start_2
    iput-boolean v1, p0, Lg11/k;->b:Z

    .line 52
    .line 53
    invoke-virtual {p0}, Ljava/lang/Object;->notifyAll()V

    .line 54
    .line 55
    .line 56
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 57
    throw v0

    .line 58
    :catchall_2
    move-exception v0

    .line 59
    :try_start_3
    monitor-exit p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 60
    throw v0

    .line 61
    :cond_2
    :goto_1
    monitor-enter p0

    .line 62
    :try_start_4
    iput-boolean v1, p0, Lg11/k;->b:Z

    .line 63
    .line 64
    invoke-virtual {p0}, Ljava/lang/Object;->notifyAll()V

    .line 65
    .line 66
    .line 67
    monitor-exit p0

    .line 68
    return-void

    .line 69
    :catchall_3
    move-exception v0

    .line 70
    monitor-exit p0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_3

    .line 71
    throw v0

    .line 72
    :goto_2
    :try_start_5
    monitor-exit p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 73
    throw v0
.end method
