.class public final Lvp/e1;
.super Lvp/n1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final o:Ljava/util/concurrent/atomic/AtomicLong;


# instance fields
.field public g:Lvp/d1;

.field public h:Lvp/d1;

.field public final i:Ljava/util/concurrent/PriorityBlockingQueue;

.field public final j:Ljava/util/concurrent/LinkedBlockingQueue;

.field public final k:Lvp/b1;

.field public final l:Lvp/b1;

.field public final m:Ljava/lang/Object;

.field public final n:Ljava/util/concurrent/Semaphore;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ljava/util/concurrent/atomic/AtomicLong;

    .line 2
    .line 3
    const-wide/high16 v1, -0x8000000000000000L

    .line 4
    .line 5
    invoke-direct {v0, v1, v2}, Ljava/util/concurrent/atomic/AtomicLong;-><init>(J)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lvp/e1;->o:Ljava/util/concurrent/atomic/AtomicLong;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(Lvp/g1;)V
    .locals 1

    .line 1
    invoke-direct {p0, p1}, Lvp/n1;-><init>(Lvp/g1;)V

    .line 2
    .line 3
    .line 4
    new-instance p1, Ljava/lang/Object;

    .line 5
    .line 6
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lvp/e1;->m:Ljava/lang/Object;

    .line 10
    .line 11
    new-instance p1, Ljava/util/concurrent/Semaphore;

    .line 12
    .line 13
    const/4 v0, 0x2

    .line 14
    invoke-direct {p1, v0}, Ljava/util/concurrent/Semaphore;-><init>(I)V

    .line 15
    .line 16
    .line 17
    iput-object p1, p0, Lvp/e1;->n:Ljava/util/concurrent/Semaphore;

    .line 18
    .line 19
    new-instance p1, Ljava/util/concurrent/PriorityBlockingQueue;

    .line 20
    .line 21
    invoke-direct {p1}, Ljava/util/concurrent/PriorityBlockingQueue;-><init>()V

    .line 22
    .line 23
    .line 24
    iput-object p1, p0, Lvp/e1;->i:Ljava/util/concurrent/PriorityBlockingQueue;

    .line 25
    .line 26
    new-instance p1, Ljava/util/concurrent/LinkedBlockingQueue;

    .line 27
    .line 28
    invoke-direct {p1}, Ljava/util/concurrent/LinkedBlockingQueue;-><init>()V

    .line 29
    .line 30
    .line 31
    iput-object p1, p0, Lvp/e1;->j:Ljava/util/concurrent/LinkedBlockingQueue;

    .line 32
    .line 33
    new-instance p1, Lvp/b1;

    .line 34
    .line 35
    const-string v0, "Thread death: Uncaught exception on worker thread"

    .line 36
    .line 37
    invoke-direct {p1, p0, v0}, Lvp/b1;-><init>(Lvp/e1;Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    iput-object p1, p0, Lvp/e1;->k:Lvp/b1;

    .line 41
    .line 42
    new-instance p1, Lvp/b1;

    .line 43
    .line 44
    const-string v0, "Thread death: Uncaught exception on network thread"

    .line 45
    .line 46
    invoke-direct {p1, p0, v0}, Lvp/b1;-><init>(Lvp/e1;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    iput-object p1, p0, Lvp/e1;->l:Lvp/b1;

    .line 50
    .line 51
    return-void
.end method


# virtual methods
.method public final a0()V
    .locals 1

    .line 1
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object p0, p0, Lvp/e1;->g:Lvp/d1;

    .line 6
    .line 7
    if-ne v0, p0, :cond_0

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 11
    .line 12
    const-string v0, "Call expected from worker thread"

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw p0
.end method

.method public final b0()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final e0()V
    .locals 1

    .line 1
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object p0, p0, Lvp/e1;->h:Lvp/d1;

    .line 6
    .line 7
    if-ne v0, p0, :cond_0

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 11
    .line 12
    const-string v0, "Call expected from network thread"

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw p0
.end method

.method public final f0()V
    .locals 1

    .line 1
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object p0, p0, Lvp/e1;->g:Lvp/d1;

    .line 6
    .line 7
    if-eq v0, p0, :cond_0

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 11
    .line 12
    const-string v0, "Call not expected from worker thread"

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw p0
.end method

.method public final g0()Z
    .locals 1

    .line 1
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object p0, p0, Lvp/e1;->g:Lvp/d1;

    .line 6
    .line 7
    if-ne v0, p0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x1

    .line 10
    return p0

    .line 11
    :cond_0
    const/4 p0, 0x0

    .line 12
    return p0
.end method

.method public final h0(Ljava/util/concurrent/Callable;)Lvp/c1;
    .locals 2

    .line 1
    invoke-virtual {p0}, Lvp/n1;->c0()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lvp/c1;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, p0, p1, v1}, Lvp/c1;-><init>(Lvp/e1;Ljava/util/concurrent/Callable;Z)V

    .line 8
    .line 9
    .line 10
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    iget-object v1, p0, Lvp/e1;->g:Lvp/d1;

    .line 15
    .line 16
    if-ne p1, v1, :cond_1

    .line 17
    .line 18
    iget-object p1, p0, Lvp/e1;->i:Ljava/util/concurrent/PriorityBlockingQueue;

    .line 19
    .line 20
    invoke-virtual {p1}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 21
    .line 22
    .line 23
    move-result p1

    .line 24
    if-nez p1, :cond_0

    .line 25
    .line 26
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast p0, Lvp/g1;

    .line 29
    .line 30
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 31
    .line 32
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 33
    .line 34
    .line 35
    iget-object p0, p0, Lvp/p0;->m:Lvp/n0;

    .line 36
    .line 37
    const-string p1, "Callable skipped the worker queue."

    .line 38
    .line 39
    invoke-virtual {p0, p1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    :cond_0
    invoke-virtual {v0}, Ljava/util/concurrent/FutureTask;->run()V

    .line 43
    .line 44
    .line 45
    return-object v0

    .line 46
    :cond_1
    invoke-virtual {p0, v0}, Lvp/e1;->n0(Lvp/c1;)V

    .line 47
    .line 48
    .line 49
    return-object v0
.end method

.method public final i0(Ljava/util/concurrent/Callable;)Lvp/c1;
    .locals 2

    .line 1
    invoke-virtual {p0}, Lvp/n1;->c0()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lvp/c1;

    .line 5
    .line 6
    const/4 v1, 0x1

    .line 7
    invoke-direct {v0, p0, p1, v1}, Lvp/c1;-><init>(Lvp/e1;Ljava/util/concurrent/Callable;Z)V

    .line 8
    .line 9
    .line 10
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    iget-object v1, p0, Lvp/e1;->g:Lvp/d1;

    .line 15
    .line 16
    if-ne p1, v1, :cond_0

    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/util/concurrent/FutureTask;->run()V

    .line 19
    .line 20
    .line 21
    return-object v0

    .line 22
    :cond_0
    invoke-virtual {p0, v0}, Lvp/e1;->n0(Lvp/c1;)V

    .line 23
    .line 24
    .line 25
    return-object v0
.end method

.method public final j0(Ljava/lang/Runnable;)V
    .locals 3

    .line 1
    invoke-virtual {p0}, Lvp/n1;->c0()V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 5
    .line 6
    .line 7
    new-instance v0, Lvp/c1;

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    const-string v2, "Task exception on worker thread"

    .line 11
    .line 12
    invoke-direct {v0, p0, p1, v1, v2}, Lvp/c1;-><init>(Lvp/e1;Ljava/lang/Runnable;ZLjava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0, v0}, Lvp/e1;->n0(Lvp/c1;)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public final k0(Ljava/util/concurrent/atomic/AtomicReference;JLjava/lang/String;Ljava/lang/Runnable;)Ljava/lang/Object;
    .locals 2

    .line 1
    const-string v0, "Interrupted waiting for "

    .line 2
    .line 3
    monitor-enter p1

    .line 4
    :try_start_0
    iget-object v1, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast v1, Lvp/g1;

    .line 7
    .line 8
    iget-object v1, v1, Lvp/g1;->j:Lvp/e1;

    .line 9
    .line 10
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {v1, p5}, Lvp/e1;->j0(Ljava/lang/Runnable;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 14
    .line 15
    .line 16
    :try_start_1
    invoke-virtual {p1, p2, p3}, Ljava/lang/Object;->wait(J)V
    :try_end_1
    .catch Ljava/lang/InterruptedException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 17
    .line 18
    .line 19
    :try_start_2
    monitor-exit p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 20
    invoke-virtual {p1}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    if-nez p1, :cond_0

    .line 25
    .line 26
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast p0, Lvp/g1;

    .line 29
    .line 30
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 31
    .line 32
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 33
    .line 34
    .line 35
    iget-object p0, p0, Lvp/p0;->m:Lvp/n0;

    .line 36
    .line 37
    const-string p2, "Timed out waiting for "

    .line 38
    .line 39
    invoke-virtual {p2, p4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p2

    .line 43
    invoke-virtual {p0, p2}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    :cond_0
    return-object p1

    .line 47
    :catchall_0
    move-exception p0

    .line 48
    goto :goto_0

    .line 49
    :catch_0
    :try_start_3
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast p0, Lvp/g1;

    .line 52
    .line 53
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 54
    .line 55
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 56
    .line 57
    .line 58
    iget-object p0, p0, Lvp/p0;->m:Lvp/n0;

    .line 59
    .line 60
    invoke-virtual {p4}, Ljava/lang/String;->length()I

    .line 61
    .line 62
    .line 63
    move-result p2

    .line 64
    add-int/lit8 p2, p2, 0x18

    .line 65
    .line 66
    new-instance p3, Ljava/lang/StringBuilder;

    .line 67
    .line 68
    invoke-direct {p3, p2}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {p3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    invoke-virtual {p3, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object p2

    .line 81
    invoke-virtual {p0, p2}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    monitor-exit p1

    .line 85
    const/4 p0, 0x0

    .line 86
    return-object p0

    .line 87
    :goto_0
    monitor-exit p1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 88
    throw p0
.end method

.method public final l0(Ljava/lang/Runnable;)V
    .locals 3

    .line 1
    invoke-virtual {p0}, Lvp/n1;->c0()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lvp/c1;

    .line 5
    .line 6
    const/4 v1, 0x1

    .line 7
    const-string v2, "Task exception on worker thread"

    .line 8
    .line 9
    invoke-direct {v0, p0, p1, v1, v2}, Lvp/c1;-><init>(Lvp/e1;Ljava/lang/Runnable;ZLjava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p0, v0}, Lvp/e1;->n0(Lvp/c1;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public final m0(Ljava/lang/Runnable;)V
    .locals 3

    .line 1
    invoke-virtual {p0}, Lvp/n1;->c0()V

    .line 2
    .line 3
    .line 4
    const-string v0, "Task exception on network thread"

    .line 5
    .line 6
    new-instance v1, Lvp/c1;

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    invoke-direct {v1, p0, p1, v2, v0}, Lvp/c1;-><init>(Lvp/e1;Ljava/lang/Runnable;ZLjava/lang/String;)V

    .line 10
    .line 11
    .line 12
    iget-object p1, p0, Lvp/e1;->m:Ljava/lang/Object;

    .line 13
    .line 14
    monitor-enter p1

    .line 15
    :try_start_0
    iget-object v0, p0, Lvp/e1;->j:Ljava/util/concurrent/LinkedBlockingQueue;

    .line 16
    .line 17
    invoke-interface {v0, v1}, Ljava/util/concurrent/BlockingQueue;->add(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    iget-object v1, p0, Lvp/e1;->h:Lvp/d1;

    .line 21
    .line 22
    if-nez v1, :cond_0

    .line 23
    .line 24
    new-instance v1, Lvp/d1;

    .line 25
    .line 26
    const-string v2, "Measurement Network"

    .line 27
    .line 28
    invoke-direct {v1, p0, v2, v0}, Lvp/d1;-><init>(Lvp/e1;Ljava/lang/String;Ljava/util/concurrent/BlockingQueue;)V

    .line 29
    .line 30
    .line 31
    iput-object v1, p0, Lvp/e1;->h:Lvp/d1;

    .line 32
    .line 33
    iget-object v0, p0, Lvp/e1;->l:Lvp/b1;

    .line 34
    .line 35
    invoke-virtual {v1, v0}, Ljava/lang/Thread;->setUncaughtExceptionHandler(Ljava/lang/Thread$UncaughtExceptionHandler;)V

    .line 36
    .line 37
    .line 38
    iget-object p0, p0, Lvp/e1;->h:Lvp/d1;

    .line 39
    .line 40
    invoke-virtual {p0}, Ljava/lang/Thread;->start()V

    .line 41
    .line 42
    .line 43
    goto :goto_0

    .line 44
    :catchall_0
    move-exception p0

    .line 45
    goto :goto_1

    .line 46
    :cond_0
    iget-object p0, v1, Lvp/d1;->d:Ljava/lang/Object;

    .line 47
    .line 48
    monitor-enter p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 49
    :try_start_1
    invoke-virtual {p0}, Ljava/lang/Object;->notifyAll()V

    .line 50
    .line 51
    .line 52
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 53
    :goto_0
    :try_start_2
    monitor-exit p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 54
    return-void

    .line 55
    :catchall_1
    move-exception v0

    .line 56
    :try_start_3
    monitor-exit p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 57
    :try_start_4
    throw v0

    .line 58
    :goto_1
    monitor-exit p1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 59
    throw p0
.end method

.method public final n0(Lvp/c1;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lvp/e1;->m:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lvp/e1;->i:Ljava/util/concurrent/PriorityBlockingQueue;

    .line 5
    .line 6
    invoke-virtual {v1, p1}, Ljava/util/concurrent/PriorityBlockingQueue;->add(Ljava/lang/Object;)Z

    .line 7
    .line 8
    .line 9
    iget-object p1, p0, Lvp/e1;->g:Lvp/d1;

    .line 10
    .line 11
    if-nez p1, :cond_0

    .line 12
    .line 13
    new-instance p1, Lvp/d1;

    .line 14
    .line 15
    const-string v2, "Measurement Worker"

    .line 16
    .line 17
    invoke-direct {p1, p0, v2, v1}, Lvp/d1;-><init>(Lvp/e1;Ljava/lang/String;Ljava/util/concurrent/BlockingQueue;)V

    .line 18
    .line 19
    .line 20
    iput-object p1, p0, Lvp/e1;->g:Lvp/d1;

    .line 21
    .line 22
    iget-object v1, p0, Lvp/e1;->k:Lvp/b1;

    .line 23
    .line 24
    invoke-virtual {p1, v1}, Ljava/lang/Thread;->setUncaughtExceptionHandler(Ljava/lang/Thread$UncaughtExceptionHandler;)V

    .line 25
    .line 26
    .line 27
    iget-object p0, p0, Lvp/e1;->g:Lvp/d1;

    .line 28
    .line 29
    invoke-virtual {p0}, Ljava/lang/Thread;->start()V

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :catchall_0
    move-exception p0

    .line 34
    goto :goto_1

    .line 35
    :cond_0
    iget-object p0, p1, Lvp/d1;->d:Ljava/lang/Object;

    .line 36
    .line 37
    monitor-enter p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 38
    :try_start_1
    invoke-virtual {p0}, Ljava/lang/Object;->notifyAll()V

    .line 39
    .line 40
    .line 41
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 42
    :goto_0
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 43
    return-void

    .line 44
    :catchall_1
    move-exception p1

    .line 45
    :try_start_3
    monitor-exit p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 46
    :try_start_4
    throw p1

    .line 47
    :goto_1
    monitor-exit v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 48
    throw p0
.end method
