.class public final Lw0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh0/l1;


# instance fields
.field public final a:Lh0/z;

.field public final b:Landroidx/lifecycle/i0;

.field public c:Lw0/h;

.field public final d:Landroidx/core/app/a0;

.field public e:Lk0/d;

.field public f:Z


# direct methods
.method public constructor <init>(Lh0/z;Landroidx/lifecycle/i0;Landroidx/core/app/a0;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-boolean v0, p0, Lw0/c;->f:Z

    .line 6
    .line 7
    iput-object p1, p0, Lw0/c;->a:Lh0/z;

    .line 8
    .line 9
    iput-object p2, p0, Lw0/c;->b:Landroidx/lifecycle/i0;

    .line 10
    .line 11
    iput-object p3, p0, Lw0/c;->d:Landroidx/core/app/a0;

    .line 12
    .line 13
    monitor-enter p0

    .line 14
    :try_start_0
    invoke-virtual {p2}, Landroidx/lifecycle/g0;->d()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    check-cast p1, Lw0/h;

    .line 19
    .line 20
    iput-object p1, p0, Lw0/c;->c:Lw0/h;

    .line 21
    .line 22
    monitor-exit p0

    .line 23
    return-void

    .line 24
    :catchall_0
    move-exception p1

    .line 25
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 26
    throw p1
.end method


# virtual methods
.method public final a(Ljava/lang/Object;)V
    .locals 6

    .line 1
    check-cast p1, Lh0/a0;

    .line 2
    .line 3
    sget-object v0, Lh0/a0;->i:Lh0/a0;

    .line 4
    .line 5
    sget-object v1, Lw0/h;->d:Lw0/h;

    .line 6
    .line 7
    if-eq p1, v0, :cond_2

    .line 8
    .line 9
    sget-object v0, Lh0/a0;->g:Lh0/a0;

    .line 10
    .line 11
    if-eq p1, v0, :cond_2

    .line 12
    .line 13
    sget-object v0, Lh0/a0;->f:Lh0/a0;

    .line 14
    .line 15
    if-eq p1, v0, :cond_2

    .line 16
    .line 17
    sget-object v0, Lh0/a0;->e:Lh0/a0;

    .line 18
    .line 19
    if-ne p1, v0, :cond_0

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    sget-object v0, Lh0/a0;->j:Lh0/a0;

    .line 23
    .line 24
    if-eq p1, v0, :cond_1

    .line 25
    .line 26
    sget-object v0, Lh0/a0;->k:Lh0/a0;

    .line 27
    .line 28
    if-eq p1, v0, :cond_1

    .line 29
    .line 30
    sget-object v0, Lh0/a0;->h:Lh0/a0;

    .line 31
    .line 32
    if-ne p1, v0, :cond_3

    .line 33
    .line 34
    :cond_1
    iget-boolean p1, p0, Lw0/c;->f:Z

    .line 35
    .line 36
    if-nez p1, :cond_3

    .line 37
    .line 38
    invoke-virtual {p0, v1}, Lw0/c;->b(Lw0/h;)V

    .line 39
    .line 40
    .line 41
    new-instance p1, Ljava/util/ArrayList;

    .line 42
    .line 43
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 44
    .line 45
    .line 46
    new-instance v0, La0/h;

    .line 47
    .line 48
    iget-object v1, p0, Lw0/c;->a:Lh0/z;

    .line 49
    .line 50
    invoke-direct {v0, p0, v1, p1}, La0/h;-><init>(Lw0/c;Lh0/z;Ljava/util/ArrayList;)V

    .line 51
    .line 52
    .line 53
    invoke-static {v0}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    invoke-static {v0}, Lk0/d;->b(Lcom/google/common/util/concurrent/ListenableFuture;)Lk0/d;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    new-instance v2, Lw0/b;

    .line 62
    .line 63
    invoke-direct {v2, p0}, Lw0/b;-><init>(Lw0/c;)V

    .line 64
    .line 65
    .line 66
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 67
    .line 68
    .line 69
    move-result-object v3

    .line 70
    invoke-static {v0, v2, v3}, Lk0/h;->g(Lcom/google/common/util/concurrent/ListenableFuture;Lk0/a;Ljava/util/concurrent/Executor;)Lk0/b;

    .line 71
    .line 72
    .line 73
    move-result-object v0

    .line 74
    new-instance v2, Lw0/b;

    .line 75
    .line 76
    invoke-direct {v2, p0}, Lw0/b;-><init>(Lw0/c;)V

    .line 77
    .line 78
    .line 79
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 80
    .line 81
    .line 82
    move-result-object v3

    .line 83
    new-instance v4, Lh6/e;

    .line 84
    .line 85
    const/16 v5, 0x9

    .line 86
    .line 87
    invoke-direct {v4, v2, v5}, Lh6/e;-><init>(Ljava/lang/Object;I)V

    .line 88
    .line 89
    .line 90
    invoke-static {v0, v4, v3}, Lk0/h;->g(Lcom/google/common/util/concurrent/ListenableFuture;Lk0/a;Ljava/util/concurrent/Executor;)Lk0/b;

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    iput-object v0, p0, Lw0/c;->e:Lk0/d;

    .line 95
    .line 96
    new-instance v2, Lrn/i;

    .line 97
    .line 98
    const/16 v3, 0x15

    .line 99
    .line 100
    invoke-direct {v2, p0, p1, v1, v3}, Lrn/i;-><init>(Ljava/lang/Object;Ljava/io/Serializable;Ljava/lang/Object;I)V

    .line 101
    .line 102
    .line 103
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 104
    .line 105
    .line 106
    move-result-object p1

    .line 107
    new-instance v1, Lk0/g;

    .line 108
    .line 109
    const/4 v3, 0x0

    .line 110
    invoke-direct {v1, v3, v0, v2}, Lk0/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    invoke-virtual {v0, p1, v1}, Lk0/d;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 114
    .line 115
    .line 116
    const/4 p1, 0x1

    .line 117
    iput-boolean p1, p0, Lw0/c;->f:Z

    .line 118
    .line 119
    return-void

    .line 120
    :cond_2
    :goto_0
    invoke-virtual {p0, v1}, Lw0/c;->b(Lw0/h;)V

    .line 121
    .line 122
    .line 123
    iget-boolean p1, p0, Lw0/c;->f:Z

    .line 124
    .line 125
    if-eqz p1, :cond_3

    .line 126
    .line 127
    const/4 p1, 0x0

    .line 128
    iput-boolean p1, p0, Lw0/c;->f:Z

    .line 129
    .line 130
    iget-object v0, p0, Lw0/c;->e:Lk0/d;

    .line 131
    .line 132
    if-eqz v0, :cond_3

    .line 133
    .line 134
    invoke-interface {v0, p1}, Ljava/util/concurrent/Future;->cancel(Z)Z

    .line 135
    .line 136
    .line 137
    const/4 p1, 0x0

    .line 138
    iput-object p1, p0, Lw0/c;->e:Lk0/d;

    .line 139
    .line 140
    :cond_3
    return-void
.end method

.method public final b(Lw0/h;)V
    .locals 3

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lw0/c;->c:Lw0/h;

    .line 3
    .line 4
    invoke-virtual {v0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    monitor-exit p0

    .line 11
    return-void

    .line 12
    :catchall_0
    move-exception p1

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    iput-object p1, p0, Lw0/c;->c:Lw0/h;

    .line 15
    .line 16
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 17
    const-string v0, "StreamStateObserver"

    .line 18
    .line 19
    new-instance v1, Ljava/lang/StringBuilder;

    .line 20
    .line 21
    const-string v2, "Update Preview stream state to "

    .line 22
    .line 23
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    invoke-static {v0, v1}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    iget-object p0, p0, Lw0/c;->b:Landroidx/lifecycle/i0;

    .line 37
    .line 38
    invoke-virtual {p0, p1}, Landroidx/lifecycle/i0;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    return-void

    .line 42
    :goto_0
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 43
    throw p1
.end method

.method public final onError(Ljava/lang/Throwable;)V
    .locals 1

    .line 1
    iget-object p1, p0, Lw0/c;->e:Lk0/d;

    .line 2
    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    invoke-interface {p1, v0}, Ljava/util/concurrent/Future;->cancel(Z)Z

    .line 7
    .line 8
    .line 9
    const/4 p1, 0x0

    .line 10
    iput-object p1, p0, Lw0/c;->e:Lk0/d;

    .line 11
    .line 12
    :cond_0
    sget-object p1, Lw0/h;->d:Lw0/h;

    .line 13
    .line 14
    invoke-virtual {p0, p1}, Lw0/c;->b(Lw0/h;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method
