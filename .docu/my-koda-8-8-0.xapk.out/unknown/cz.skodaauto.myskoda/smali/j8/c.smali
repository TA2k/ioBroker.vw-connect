.class public final synthetic Lj8/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lj8/l;
.implements Lon/g;


# instance fields
.field public final synthetic d:Z

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ZLjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput-object p2, p0, Lj8/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    iput-object p3, p0, Lj8/c;->f:Ljava/lang/Object;

    .line 4
    .line 5
    iput-boolean p1, p0, Lj8/c;->d:Z

    .line 6
    .line 7
    iput-object p4, p0, Lj8/c;->g:Ljava/lang/Object;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public a(Ljava/lang/Exception;)V
    .locals 8

    .line 1
    iget-object v0, p0, Lj8/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lts/b;

    .line 4
    .line 5
    iget-object v1, p0, Lj8/c;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Laq/k;

    .line 8
    .line 9
    iget-object v2, p0, Lj8/c;->g:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v2, Lms/a;

    .line 12
    .line 13
    if-eqz p1, :cond_0

    .line 14
    .line 15
    invoke-virtual {v1, p1}, Laq/k;->c(Ljava/lang/Exception;)Z

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    iget-boolean p0, p0, Lj8/c;->d:Z

    .line 20
    .line 21
    if-eqz p0, :cond_2

    .line 22
    .line 23
    new-instance p0, Ljava/util/concurrent/CountDownLatch;

    .line 24
    .line 25
    const/4 p1, 0x1

    .line 26
    invoke-direct {p0, p1}, Ljava/util/concurrent/CountDownLatch;-><init>(I)V

    .line 27
    .line 28
    .line 29
    new-instance v3, Ljava/lang/Thread;

    .line 30
    .line 31
    new-instance v4, Lno/nordicsemi/android/ble/o0;

    .line 32
    .line 33
    const/16 v5, 0xa

    .line 34
    .line 35
    invoke-direct {v4, v5, v0, p0}, Lno/nordicsemi/android/ble/o0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    invoke-direct {v3, v4}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {v3}, Ljava/lang/Thread;->start()V

    .line 42
    .line 43
    .line 44
    sget-object v0, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 45
    .line 46
    sget-object v3, Lms/v;->a:Ljava/util/concurrent/ExecutorService;

    .line 47
    .line 48
    const-wide/16 v3, 0x2

    .line 49
    .line 50
    const/4 v5, 0x0

    .line 51
    :try_start_0
    invoke-virtual {v0, v3, v4}, Ljava/util/concurrent/TimeUnit;->toNanos(J)J

    .line 52
    .line 53
    .line 54
    move-result-wide v3

    .line 55
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 56
    .line 57
    .line 58
    move-result-wide v6
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 59
    add-long/2addr v6, v3

    .line 60
    :goto_0
    :try_start_1
    sget-object v0, Ljava/util/concurrent/TimeUnit;->NANOSECONDS:Ljava/util/concurrent/TimeUnit;

    .line 61
    .line 62
    invoke-virtual {p0, v3, v4, v0}, Ljava/util/concurrent/CountDownLatch;->await(JLjava/util/concurrent/TimeUnit;)Z
    :try_end_1
    .catch Ljava/lang/InterruptedException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 63
    .line 64
    .line 65
    if-eqz v5, :cond_2

    .line 66
    .line 67
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    invoke-virtual {p0}, Ljava/lang/Thread;->interrupt()V

    .line 72
    .line 73
    .line 74
    goto :goto_2

    .line 75
    :catchall_0
    move-exception p0

    .line 76
    move p1, v5

    .line 77
    goto :goto_1

    .line 78
    :catch_0
    :try_start_2
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 79
    .line 80
    .line 81
    move-result-wide v3
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 82
    sub-long v3, v6, v3

    .line 83
    .line 84
    move v5, p1

    .line 85
    goto :goto_0

    .line 86
    :catchall_1
    move-exception p0

    .line 87
    :goto_1
    if-eqz p1, :cond_1

    .line 88
    .line 89
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 90
    .line 91
    .line 92
    move-result-object p1

    .line 93
    invoke-virtual {p1}, Ljava/lang/Thread;->interrupt()V

    .line 94
    .line 95
    .line 96
    :cond_1
    throw p0

    .line 97
    :cond_2
    :goto_2
    invoke-virtual {v1, v2}, Laq/k;->d(Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    return-void
.end method

.method public d(ILt7/q0;[I)Lhr/x0;
    .locals 11

    .line 1
    iget-object v0, p0, Lj8/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lj8/o;

    .line 4
    .line 5
    iget-object v1, p0, Lj8/c;->f:Ljava/lang/Object;

    .line 6
    .line 7
    move-object v6, v1

    .line 8
    check-cast v6, Lj8/i;

    .line 9
    .line 10
    iget-object v1, p0, Lj8/c;->g:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, [I

    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    new-instance v9, Lj8/d;

    .line 18
    .line 19
    invoke-direct {v9, v0, v6}, Lj8/d;-><init>(Lj8/o;Lj8/i;)V

    .line 20
    .line 21
    .line 22
    aget v10, v1, p1

    .line 23
    .line 24
    invoke-static {}, Lhr/h0;->o()Lhr/e0;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    const/4 v1, 0x0

    .line 29
    move v5, v1

    .line 30
    :goto_0
    iget v1, p2, Lt7/q0;->a:I

    .line 31
    .line 32
    if-ge v5, v1, :cond_0

    .line 33
    .line 34
    new-instance v2, Lj8/e;

    .line 35
    .line 36
    aget v7, p3, v5

    .line 37
    .line 38
    iget-boolean v8, p0, Lj8/c;->d:Z

    .line 39
    .line 40
    move v3, p1

    .line 41
    move-object v4, p2

    .line 42
    invoke-direct/range {v2 .. v10}, Lj8/e;-><init>(ILt7/q0;ILj8/i;IZLj8/d;I)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {v0, v2}, Lhr/b0;->a(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    add-int/lit8 v5, v5, 0x1

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_0
    invoke-virtual {v0}, Lhr/e0;->i()Lhr/x0;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    return-object p0
.end method
