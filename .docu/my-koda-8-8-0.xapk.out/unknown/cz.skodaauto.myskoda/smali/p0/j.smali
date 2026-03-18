.class public final Lp0/j;
.super Lh0/t0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final o:Ly4/k;

.field public p:Ly4/h;

.field public q:Lh0/t0;

.field public r:Lp0/l;


# direct methods
.method public constructor <init>(Landroid/util/Size;I)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lh0/t0;-><init>(Landroid/util/Size;I)V

    .line 2
    .line 3
    .line 4
    new-instance p1, Lgr/k;

    .line 5
    .line 6
    const/16 p2, 0x16

    .line 7
    .line 8
    invoke-direct {p1, p0, p2}, Lgr/k;-><init>(Ljava/lang/Object;I)V

    .line 9
    .line 10
    .line 11
    invoke-static {p1}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    iput-object p1, p0, Lp0/j;->o:Ly4/k;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 2

    .line 1
    invoke-super {p0}, Lh0/t0;->a()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lp0/f;

    .line 5
    .line 6
    const/4 v1, 0x2

    .line 7
    invoke-direct {v0, p0, v1}, Lp0/f;-><init>(Lp0/j;I)V

    .line 8
    .line 9
    .line 10
    invoke-static {v0}, Llp/k1;->d(Ljava/lang/Runnable;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public final f()Lcom/google/common/util/concurrent/ListenableFuture;
    .locals 0

    .line 1
    iget-object p0, p0, Lp0/j;->o:Ly4/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public final g(Lh0/t0;Ljava/lang/Runnable;)Z
    .locals 10

    .line 1
    const-string v0, ")"

    .line 2
    .line 3
    const-string v1, ") must match the parent("

    .line 4
    .line 5
    iget-object v2, p0, Lh0/t0;->h:Landroid/util/Size;

    .line 6
    .line 7
    invoke-static {}, Llp/k1;->a()V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    iget v3, p1, Lh0/t0;->i:I

    .line 14
    .line 15
    iget-object v4, p1, Lh0/t0;->h:Landroid/util/Size;

    .line 16
    .line 17
    iget-object v5, p0, Lp0/j;->q:Lh0/t0;

    .line 18
    .line 19
    const/4 v6, 0x0

    .line 20
    if-ne v5, p1, :cond_0

    .line 21
    .line 22
    return v6

    .line 23
    :cond_0
    const/4 v7, 0x1

    .line 24
    if-nez v5, :cond_1

    .line 25
    .line 26
    move v5, v7

    .line 27
    goto :goto_0

    .line 28
    :cond_1
    move v5, v6

    .line 29
    :goto_0
    const-string v8, "A different provider has been set. To change the provider, call SurfaceEdge#invalidate before calling SurfaceEdge#setProvider"

    .line 30
    .line 31
    invoke-static {v8, v5}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {v2, v4}, Landroid/util/Size;->equals(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v5

    .line 38
    new-instance v8, Ljava/lang/StringBuilder;

    .line 39
    .line 40
    const-string v9, "The provider\'s size("

    .line 41
    .line 42
    invoke-direct {v8, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {v8, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {v8, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    invoke-virtual {v8, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    invoke-virtual {v8, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v2

    .line 61
    invoke-static {v5, v2}, Ljp/ed;->b(ZLjava/lang/String;)V

    .line 62
    .line 63
    .line 64
    iget v2, p0, Lh0/t0;->i:I

    .line 65
    .line 66
    if-ne v2, v3, :cond_2

    .line 67
    .line 68
    move v6, v7

    .line 69
    :cond_2
    const-string v4, "The provider\'s format("

    .line 70
    .line 71
    invoke-static {v2, v3, v4, v1, v0}, Lf2/m0;->f(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    invoke-static {v6, v0}, Ljp/ed;->b(ZLjava/lang/String;)V

    .line 76
    .line 77
    .line 78
    iget-object v0, p0, Lh0/t0;->a:Ljava/lang/Object;

    .line 79
    .line 80
    monitor-enter v0

    .line 81
    :try_start_0
    iget-boolean v1, p0, Lh0/t0;->c:Z

    .line 82
    .line 83
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 84
    xor-int/lit8 v0, v1, 0x1

    .line 85
    .line 86
    const-string v1, "The parent is closed. Call SurfaceEdge#invalidate() before setting a new provider."

    .line 87
    .line 88
    invoke-static {v1, v0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 89
    .line 90
    .line 91
    iput-object p1, p0, Lp0/j;->q:Lh0/t0;

    .line 92
    .line 93
    invoke-virtual {p1}, Lh0/t0;->c()Lcom/google/common/util/concurrent/ListenableFuture;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    iget-object v1, p0, Lp0/j;->p:Ly4/h;

    .line 98
    .line 99
    invoke-static {v0, v1}, Lk0/h;->e(Lcom/google/common/util/concurrent/ListenableFuture;Ly4/h;)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {p1}, Lh0/t0;->d()V

    .line 103
    .line 104
    .line 105
    iget-object p0, p0, Lh0/t0;->e:Ly4/k;

    .line 106
    .line 107
    invoke-static {p0}, Lk0/h;->d(Lcom/google/common/util/concurrent/ListenableFuture;)Lcom/google/common/util/concurrent/ListenableFuture;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    new-instance v0, Lp0/g;

    .line 112
    .line 113
    const/4 v1, 0x1

    .line 114
    invoke-direct {v0, p1, v1}, Lp0/g;-><init>(Lh0/t0;I)V

    .line 115
    .line 116
    .line 117
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 118
    .line 119
    .line 120
    move-result-object v1

    .line 121
    invoke-interface {p0, v1, v0}, Lcom/google/common/util/concurrent/ListenableFuture;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 122
    .line 123
    .line 124
    iget-object p0, p1, Lh0/t0;->g:Ly4/k;

    .line 125
    .line 126
    invoke-static {p0}, Lk0/h;->d(Lcom/google/common/util/concurrent/ListenableFuture;)Lcom/google/common/util/concurrent/ListenableFuture;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    invoke-static {}, Llp/hb;->d()Lj0/c;

    .line 131
    .line 132
    .line 133
    move-result-object p1

    .line 134
    invoke-interface {p0, p1, p2}, Lcom/google/common/util/concurrent/ListenableFuture;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 135
    .line 136
    .line 137
    return v7

    .line 138
    :catchall_0
    move-exception p0

    .line 139
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 140
    throw p0
.end method
