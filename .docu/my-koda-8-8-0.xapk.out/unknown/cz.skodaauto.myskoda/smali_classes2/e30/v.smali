.class public final Le30/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Z

.field public final b:Z

.field public final c:Ljava/lang/Object;

.field public final d:Ljava/lang/Object;

.field public final e:Ljava/lang/Object;

.field public final f:Ljava/io/Serializable;

.field public final g:Ljava/io/Serializable;

.field public final h:Ljava/io/Serializable;

.field public final i:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Landroid/os/Looper;Lw7/r;Lw7/k;)V
    .locals 6

    .line 11
    new-instance v1, Ljava/util/concurrent/CopyOnWriteArraySet;

    invoke-direct {v1}, Ljava/util/concurrent/CopyOnWriteArraySet;-><init>()V

    const/4 v5, 0x1

    move-object v0, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    invoke-direct/range {v0 .. v5}, Le30/v;-><init>(Ljava/util/concurrent/CopyOnWriteArraySet;Landroid/os/Looper;Lw7/r;Lw7/k;Z)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    const-string v0, "id"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Le30/v;->c:Ljava/lang/Object;

    .line 3
    iput-object p4, p0, Le30/v;->d:Ljava/lang/Object;

    .line 4
    iput-object p5, p0, Le30/v;->e:Ljava/lang/Object;

    .line 5
    iput-boolean p2, p0, Le30/v;->a:Z

    .line 6
    iput-boolean p3, p0, Le30/v;->b:Z

    .line 7
    iput-object p6, p0, Le30/v;->f:Ljava/io/Serializable;

    .line 8
    iput-object p7, p0, Le30/v;->g:Ljava/io/Serializable;

    .line 9
    iput-object p8, p0, Le30/v;->h:Ljava/io/Serializable;

    .line 10
    iput-object p9, p0, Le30/v;->i:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/util/concurrent/CopyOnWriteArraySet;Landroid/os/Looper;Lw7/r;Lw7/k;Z)V
    .locals 0

    .line 12
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 13
    iput-object p3, p0, Le30/v;->c:Ljava/lang/Object;

    .line 14
    iput-object p1, p0, Le30/v;->f:Ljava/io/Serializable;

    .line 15
    iput-object p4, p0, Le30/v;->e:Ljava/lang/Object;

    .line 16
    new-instance p1, Ljava/lang/Object;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Le30/v;->i:Ljava/lang/Object;

    .line 17
    new-instance p1, Ljava/util/ArrayDeque;

    invoke-direct {p1}, Ljava/util/ArrayDeque;-><init>()V

    iput-object p1, p0, Le30/v;->g:Ljava/io/Serializable;

    .line 18
    new-instance p1, Ljava/util/ArrayDeque;

    invoke-direct {p1}, Ljava/util/ArrayDeque;-><init>()V

    iput-object p1, p0, Le30/v;->h:Ljava/io/Serializable;

    .line 19
    new-instance p1, Lw7/i;

    invoke-direct {p1, p0}, Lw7/i;-><init>(Le30/v;)V

    invoke-virtual {p3, p2, p1}, Lw7/r;->a(Landroid/os/Looper;Landroid/os/Handler$Callback;)Lw7/t;

    move-result-object p1

    .line 20
    iput-object p1, p0, Le30/v;->d:Ljava/lang/Object;

    .line 21
    iput-boolean p5, p0, Le30/v;->b:Z

    return-void
.end method


# virtual methods
.method public a(Ljava/lang/Object;)V
    .locals 2

    .line 1
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Le30/v;->i:Ljava/lang/Object;

    .line 5
    .line 6
    monitor-enter v0

    .line 7
    :try_start_0
    iget-boolean v1, p0, Le30/v;->a:Z

    .line 8
    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    monitor-exit v0

    .line 12
    return-void

    .line 13
    :catchall_0
    move-exception p0

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    iget-object p0, p0, Le30/v;->f:Ljava/io/Serializable;

    .line 16
    .line 17
    check-cast p0, Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 18
    .line 19
    new-instance v1, Lw7/l;

    .line 20
    .line 21
    invoke-direct {v1, p1}, Lw7/l;-><init>(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0, v1}, Ljava/util/concurrent/CopyOnWriteArraySet;->add(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    monitor-exit v0

    .line 28
    return-void

    .line 29
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 30
    throw p0
.end method

.method public b()V
    .locals 5

    .line 1
    iget-object v0, p0, Le30/v;->d:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lw7/t;

    .line 4
    .line 5
    iget-object v1, p0, Le30/v;->g:Ljava/io/Serializable;

    .line 6
    .line 7
    check-cast v1, Ljava/util/ArrayDeque;

    .line 8
    .line 9
    invoke-virtual {p0}, Le30/v;->f()V

    .line 10
    .line 11
    .line 12
    iget-object p0, p0, Le30/v;->h:Ljava/io/Serializable;

    .line 13
    .line 14
    check-cast p0, Ljava/util/ArrayDeque;

    .line 15
    .line 16
    invoke-virtual {p0}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    if-eqz v2, :cond_0

    .line 21
    .line 22
    goto :goto_1

    .line 23
    :cond_0
    iget-object v2, v0, Lw7/t;->a:Landroid/os/Handler;

    .line 24
    .line 25
    const/4 v3, 0x1

    .line 26
    invoke-virtual {v2, v3}, Landroid/os/Handler;->hasMessages(I)Z

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    if-nez v2, :cond_1

    .line 31
    .line 32
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 33
    .line 34
    .line 35
    invoke-static {}, Lw7/t;->b()Lw7/s;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    iget-object v4, v0, Lw7/t;->a:Landroid/os/Handler;

    .line 40
    .line 41
    invoke-virtual {v4, v3}, Landroid/os/Handler;->obtainMessage(I)Landroid/os/Message;

    .line 42
    .line 43
    .line 44
    move-result-object v3

    .line 45
    iput-object v3, v2, Lw7/s;->a:Landroid/os/Message;

    .line 46
    .line 47
    iget-object v0, v0, Lw7/t;->a:Landroid/os/Handler;

    .line 48
    .line 49
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 50
    .line 51
    .line 52
    invoke-virtual {v0, v3}, Landroid/os/Handler;->sendMessageAtFrontOfQueue(Landroid/os/Message;)Z

    .line 53
    .line 54
    .line 55
    invoke-virtual {v2}, Lw7/s;->a()V

    .line 56
    .line 57
    .line 58
    :cond_1
    invoke-virtual {v1}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    invoke-virtual {v1, p0}, Ljava/util/ArrayDeque;->addAll(Ljava/util/Collection;)Z

    .line 63
    .line 64
    .line 65
    invoke-virtual {p0}, Ljava/util/ArrayDeque;->clear()V

    .line 66
    .line 67
    .line 68
    if-nez v0, :cond_2

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_2
    :goto_0
    invoke-virtual {v1}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 72
    .line 73
    .line 74
    move-result p0

    .line 75
    if-nez p0, :cond_3

    .line 76
    .line 77
    invoke-virtual {v1}, Ljava/util/ArrayDeque;->peekFirst()Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    check-cast p0, Ljava/lang/Runnable;

    .line 82
    .line 83
    invoke-interface {p0}, Ljava/lang/Runnable;->run()V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v1}, Ljava/util/ArrayDeque;->removeFirst()Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    goto :goto_0

    .line 90
    :cond_3
    :goto_1
    return-void
.end method

.method public c(ILw7/j;)V
    .locals 3

    .line 1
    invoke-virtual {p0}, Le30/v;->f()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 5
    .line 6
    iget-object v1, p0, Le30/v;->f:Ljava/io/Serializable;

    .line 7
    .line 8
    check-cast v1, Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 9
    .line 10
    invoke-direct {v0, v1}, Ljava/util/concurrent/CopyOnWriteArraySet;-><init>(Ljava/util/Collection;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Le30/v;->h:Ljava/io/Serializable;

    .line 14
    .line 15
    check-cast p0, Ljava/util/ArrayDeque;

    .line 16
    .line 17
    new-instance v1, Lb/p;

    .line 18
    .line 19
    const/4 v2, 0x6

    .line 20
    invoke-direct {v1, p1, v2, v0, p2}, Lb/p;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0, v1}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method public d()V
    .locals 5

    .line 1
    invoke-virtual {p0}, Le30/v;->f()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Le30/v;->i:Ljava/lang/Object;

    .line 5
    .line 6
    monitor-enter v0

    .line 7
    const/4 v1, 0x1

    .line 8
    :try_start_0
    iput-boolean v1, p0, Le30/v;->a:Z

    .line 9
    .line 10
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 11
    iget-object v0, p0, Le30/v;->f:Ljava/io/Serializable;

    .line 12
    .line 13
    check-cast v0, Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 14
    .line 15
    invoke-virtual {v0}, Ljava/util/concurrent/CopyOnWriteArraySet;->iterator()Ljava/util/Iterator;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    if-eqz v2, :cond_1

    .line 24
    .line 25
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    check-cast v2, Lw7/l;

    .line 30
    .line 31
    iget-object v3, p0, Le30/v;->e:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast v3, Lw7/k;

    .line 34
    .line 35
    iput-boolean v1, v2, Lw7/l;->d:Z

    .line 36
    .line 37
    iget-boolean v4, v2, Lw7/l;->c:Z

    .line 38
    .line 39
    if-eqz v4, :cond_0

    .line 40
    .line 41
    const/4 v4, 0x0

    .line 42
    iput-boolean v4, v2, Lw7/l;->c:Z

    .line 43
    .line 44
    iget-object v4, v2, Lw7/l;->a:Ljava/lang/Object;

    .line 45
    .line 46
    iget-object v2, v2, Lw7/l;->b:Lb6/f;

    .line 47
    .line 48
    invoke-virtual {v2}, Lb6/f;->i()Lt7/m;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    invoke-interface {v3, v4, v2}, Lw7/k;->a(Ljava/lang/Object;Lt7/m;)V

    .line 53
    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_1
    iget-object p0, p0, Le30/v;->f:Ljava/io/Serializable;

    .line 57
    .line 58
    check-cast p0, Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 59
    .line 60
    invoke-virtual {p0}, Ljava/util/concurrent/CopyOnWriteArraySet;->clear()V

    .line 61
    .line 62
    .line 63
    return-void

    .line 64
    :catchall_0
    move-exception p0

    .line 65
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 66
    throw p0
.end method

.method public e(ILw7/j;)V
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2}, Le30/v;->c(ILw7/j;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Le30/v;->b()V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public f()V
    .locals 1

    .line 1
    iget-boolean v0, p0, Le30/v;->b:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    iget-object p0, p0, Le30/v;->d:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Lw7/t;

    .line 13
    .line 14
    iget-object p0, p0, Lw7/t;->a:Landroid/os/Handler;

    .line 15
    .line 16
    invoke-virtual {p0}, Landroid/os/Handler;->getLooper()Landroid/os/Looper;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-virtual {p0}, Landroid/os/Looper;->getThread()Ljava/lang/Thread;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    if-ne v0, p0, :cond_1

    .line 25
    .line 26
    const/4 p0, 0x1

    .line 27
    goto :goto_0

    .line 28
    :cond_1
    const/4 p0, 0x0

    .line 29
    :goto_0
    invoke-static {p0}, Lw7/a;->j(Z)V

    .line 30
    .line 31
    .line 32
    return-void
.end method
