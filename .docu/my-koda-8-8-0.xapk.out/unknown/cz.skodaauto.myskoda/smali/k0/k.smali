.class public final Lk0/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/common/util/concurrent/ListenableFuture;


# instance fields
.field public d:Ljava/util/ArrayList;

.field public e:Ljava/util/ArrayList;

.field public final f:Z

.field public final g:Ljava/util/concurrent/atomic/AtomicInteger;

.field public final h:Ly4/k;

.field public i:Ly4/h;


# direct methods
.method public constructor <init>(Ljava/util/ArrayList;ZLj0/a;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk0/k;->d:Ljava/util/ArrayList;

    .line 5
    .line 6
    new-instance v0, Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 13
    .line 14
    .line 15
    iput-object v0, p0, Lk0/k;->e:Ljava/util/ArrayList;

    .line 16
    .line 17
    iput-boolean p2, p0, Lk0/k;->f:Z

    .line 18
    .line 19
    new-instance p2, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 20
    .line 21
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    invoke-direct {p2, p1}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V

    .line 26
    .line 27
    .line 28
    iput-object p2, p0, Lk0/k;->g:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 29
    .line 30
    new-instance p1, Lj1/a;

    .line 31
    .line 32
    const/4 p2, 0x6

    .line 33
    invoke-direct {p1, p0, p2}, Lj1/a;-><init>(Ljava/lang/Object;I)V

    .line 34
    .line 35
    .line 36
    invoke-static {p1}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    iput-object p1, p0, Lk0/k;->h:Ly4/k;

    .line 41
    .line 42
    new-instance p1, Laq/p;

    .line 43
    .line 44
    const/16 p2, 0x9

    .line 45
    .line 46
    invoke-direct {p1, p0, p2}, Laq/p;-><init>(Ljava/lang/Object;I)V

    .line 47
    .line 48
    .line 49
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 50
    .line 51
    .line 52
    move-result-object p2

    .line 53
    invoke-virtual {p0, p2, p1}, Lk0/k;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 54
    .line 55
    .line 56
    iget-object p1, p0, Lk0/k;->d:Ljava/util/ArrayList;

    .line 57
    .line 58
    invoke-virtual {p1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 59
    .line 60
    .line 61
    move-result p1

    .line 62
    if-eqz p1, :cond_0

    .line 63
    .line 64
    iget-object p1, p0, Lk0/k;->i:Ly4/h;

    .line 65
    .line 66
    new-instance p2, Ljava/util/ArrayList;

    .line 67
    .line 68
    iget-object p0, p0, Lk0/k;->e:Ljava/util/ArrayList;

    .line 69
    .line 70
    invoke-direct {p2, p0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {p1, p2}, Ly4/h;->b(Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    return-void

    .line 77
    :cond_0
    const/4 p1, 0x0

    .line 78
    move p2, p1

    .line 79
    :goto_0
    iget-object v0, p0, Lk0/k;->d:Ljava/util/ArrayList;

    .line 80
    .line 81
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 82
    .line 83
    .line 84
    move-result v0

    .line 85
    if-ge p2, v0, :cond_1

    .line 86
    .line 87
    iget-object v0, p0, Lk0/k;->e:Ljava/util/ArrayList;

    .line 88
    .line 89
    const/4 v1, 0x0

    .line 90
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    add-int/lit8 p2, p2, 0x1

    .line 94
    .line 95
    goto :goto_0

    .line 96
    :cond_1
    iget-object p2, p0, Lk0/k;->d:Ljava/util/ArrayList;

    .line 97
    .line 98
    :goto_1
    invoke-virtual {p2}, Ljava/util/ArrayList;->size()I

    .line 99
    .line 100
    .line 101
    move-result v0

    .line 102
    if-ge p1, v0, :cond_2

    .line 103
    .line 104
    invoke-virtual {p2, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v0

    .line 108
    check-cast v0, Lcom/google/common/util/concurrent/ListenableFuture;

    .line 109
    .line 110
    new-instance v1, Liq/a;

    .line 111
    .line 112
    const/4 v2, 0x1

    .line 113
    invoke-direct {v1, p1, v2, p0, v0}, Liq/a;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    invoke-interface {v0, p3, v1}, Lcom/google/common/util/concurrent/ListenableFuture;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 117
    .line 118
    .line 119
    add-int/lit8 p1, p1, 0x1

    .line 120
    .line 121
    goto :goto_1

    .line 122
    :cond_2
    return-void
.end method


# virtual methods
.method public final a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lk0/k;->h:Ly4/k;

    .line 2
    .line 3
    iget-object p0, p0, Ly4/k;->e:Ly4/j;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Ly4/g;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final cancel(Z)Z
    .locals 2

    .line 1
    iget-object v0, p0, Lk0/k;->d:Ljava/util/ArrayList;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    check-cast v1, Lcom/google/common/util/concurrent/ListenableFuture;

    .line 20
    .line 21
    invoke-interface {v1, p1}, Ljava/util/concurrent/Future;->cancel(Z)Z

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    iget-object p0, p0, Lk0/k;->h:Ly4/k;

    .line 26
    .line 27
    invoke-virtual {p0, p1}, Ly4/k;->cancel(Z)Z

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    return p0
.end method

.method public final get()Ljava/lang/Object;
    .locals 3

    .line 5
    iget-object v0, p0, Lk0/k;->d:Ljava/util/ArrayList;

    if-eqz v0, :cond_2

    .line 6
    invoke-virtual {p0}, Lk0/k;->isDone()Z

    move-result v1

    if-nez v1, :cond_2

    .line 7
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_2

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lcom/google/common/util/concurrent/ListenableFuture;

    .line 8
    :cond_1
    :goto_0
    invoke-interface {v1}, Ljava/util/concurrent/Future;->isDone()Z

    move-result v2

    if-nez v2, :cond_0

    .line 9
    :try_start_0
    invoke-interface {v1}, Ljava/util/concurrent/Future;->get()Ljava/lang/Object;
    :try_end_0
    .catch Ljava/lang/Error; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    .line 10
    :catchall_0
    iget-boolean v2, p0, Lk0/k;->f:Z

    if-eqz v2, :cond_1

    goto :goto_1

    :catch_0
    move-exception p0

    .line 11
    throw p0

    :catch_1
    move-exception p0

    .line 12
    throw p0

    .line 13
    :cond_2
    :goto_1
    iget-object p0, p0, Lk0/k;->h:Ly4/k;

    .line 14
    iget-object p0, p0, Ly4/k;->e:Ly4/j;

    .line 15
    invoke-virtual {p0}, Ly4/g;->get()Ljava/lang/Object;

    move-result-object p0

    .line 16
    check-cast p0, Ljava/util/List;

    return-object p0
.end method

.method public final get(JLjava/util/concurrent/TimeUnit;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lk0/k;->h:Ly4/k;

    .line 2
    iget-object p0, p0, Ly4/k;->e:Ly4/j;

    .line 3
    invoke-virtual {p0, p1, p2, p3}, Ly4/g;->get(JLjava/util/concurrent/TimeUnit;)Ljava/lang/Object;

    move-result-object p0

    .line 4
    check-cast p0, Ljava/util/List;

    return-object p0
.end method

.method public final isCancelled()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lk0/k;->h:Ly4/k;

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
    iget-object p0, p0, Lk0/k;->h:Ly4/k;

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
