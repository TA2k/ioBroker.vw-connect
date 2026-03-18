.class public final Lj0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/concurrent/RunnableScheduledFuture;


# instance fields
.field public final d:Ljava/util/concurrent/atomic/AtomicReference;

.field public final e:J

.field public final f:Ljava/util/concurrent/Callable;

.field public final g:Ly4/k;


# direct methods
.method public constructor <init>(Landroid/os/Handler;JLjava/util/concurrent/Callable;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/concurrent/atomic/AtomicReference;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lj0/b;->d:Ljava/util/concurrent/atomic/AtomicReference;

    .line 11
    .line 12
    iput-wide p2, p0, Lj0/b;->e:J

    .line 13
    .line 14
    iput-object p4, p0, Lj0/b;->f:Ljava/util/concurrent/Callable;

    .line 15
    .line 16
    new-instance p2, Lil/g;

    .line 17
    .line 18
    invoke-direct {p2, p0, p1, p4}, Lil/g;-><init>(Lj0/b;Landroid/os/Handler;Ljava/util/concurrent/Callable;)V

    .line 19
    .line 20
    .line 21
    invoke-static {p2}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    iput-object p1, p0, Lj0/b;->g:Ly4/k;

    .line 26
    .line 27
    return-void
.end method


# virtual methods
.method public final cancel(Z)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lj0/b;->g:Ly4/k;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ly4/k;->cancel(Z)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final compareTo(Ljava/lang/Object;)I
    .locals 3

    .line 1
    check-cast p1, Ljava/util/concurrent/Delayed;

    .line 2
    .line 3
    sget-object v0, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lj0/b;->getDelay(Ljava/util/concurrent/TimeUnit;)J

    .line 6
    .line 7
    .line 8
    move-result-wide v1

    .line 9
    invoke-interface {p1, v0}, Ljava/util/concurrent/Delayed;->getDelay(Ljava/util/concurrent/TimeUnit;)J

    .line 10
    .line 11
    .line 12
    move-result-wide p0

    .line 13
    invoke-static {v1, v2, p0, p1}, Ljava/lang/Long;->compare(JJ)I

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    return p0
.end method

.method public final get()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lj0/b;->g:Ly4/k;

    .line 2
    iget-object p0, p0, Ly4/k;->e:Ly4/j;

    .line 3
    invoke-virtual {p0}, Ly4/g;->get()Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final get(JLjava/util/concurrent/TimeUnit;)Ljava/lang/Object;
    .locals 0

    .line 4
    iget-object p0, p0, Lj0/b;->g:Ly4/k;

    .line 5
    iget-object p0, p0, Ly4/k;->e:Ly4/j;

    .line 6
    invoke-virtual {p0, p1, p2, p3}, Ly4/g;->get(JLjava/util/concurrent/TimeUnit;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final getDelay(Ljava/util/concurrent/TimeUnit;)J
    .locals 4

    .line 1
    iget-wide v0, p0, Lj0/b;->e:J

    .line 2
    .line 3
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 4
    .line 5
    .line 6
    move-result-wide v2

    .line 7
    sub-long/2addr v0, v2

    .line 8
    sget-object p0, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 9
    .line 10
    invoke-virtual {p1, v0, v1, p0}, Ljava/util/concurrent/TimeUnit;->convert(JLjava/util/concurrent/TimeUnit;)J

    .line 11
    .line 12
    .line 13
    move-result-wide p0

    .line 14
    return-wide p0
.end method

.method public final isCancelled()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lj0/b;->g:Ly4/k;

    .line 2
    .line 3
    invoke-virtual {p0}, Ly4/k;->isCancelled()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final isDone()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lj0/b;->g:Ly4/k;

    .line 2
    .line 3
    iget-object p0, p0, Ly4/k;->e:Ly4/j;

    .line 4
    .line 5
    invoke-virtual {p0}, Ly4/g;->isDone()Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public final isPeriodic()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final run()V
    .locals 2

    .line 1
    iget-object v0, p0, Lj0/b;->d:Ljava/util/concurrent/atomic/AtomicReference;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicReference;->getAndSet(Ljava/lang/Object;)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    check-cast v0, Ly4/h;

    .line 9
    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    :try_start_0
    iget-object p0, p0, Lj0/b;->f:Ljava/util/concurrent/Callable;

    .line 13
    .line 14
    invoke-interface {p0}, Ljava/util/concurrent/Callable;->call()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-virtual {v0, p0}, Ly4/h;->b(Ljava/lang/Object;)Z
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :catch_0
    move-exception p0

    .line 23
    invoke-virtual {v0, p0}, Ly4/h;->d(Ljava/lang/Throwable;)Z

    .line 24
    .line 25
    .line 26
    :cond_0
    return-void
.end method
