.class public final Lu/g1;
.super Lu/d1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/Object;

.field public final b:Lu/x0;

.field public final c:Lj0/h;

.field public final d:Lj0/c;

.field public e:Lu/o0;

.field public f:Lro/f;

.field public g:Ly4/k;

.field public h:Ly4/h;

.field public i:Lk0/d;

.field public j:Ljava/util/List;

.field public k:Z

.field public l:Z

.field public m:Z

.field public final n:Lj0/c;

.field public final o:Ljava/lang/Object;

.field public p:Ljava/util/ArrayList;

.field public q:Lk0/k;

.field public final r:Lc8/g;

.field public final s:Lpv/g;

.field public final t:Lb6/f;

.field public final u:La8/t1;

.field public final v:Ljava/util/concurrent/atomic/AtomicBoolean;


# direct methods
.method public constructor <init>(Ld01/x;Ld01/x;Lu/x0;Lj0/h;Lj0/c;Landroid/os/Handler;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance p6, Ljava/lang/Object;

    .line 5
    .line 6
    invoke-direct {p6}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p6, p0, Lu/g1;->a:Ljava/lang/Object;

    .line 10
    .line 11
    const/4 p6, 0x0

    .line 12
    iput-object p6, p0, Lu/g1;->j:Ljava/util/List;

    .line 13
    .line 14
    const/4 p6, 0x0

    .line 15
    iput-boolean p6, p0, Lu/g1;->k:Z

    .line 16
    .line 17
    iput-boolean p6, p0, Lu/g1;->l:Z

    .line 18
    .line 19
    iput-boolean p6, p0, Lu/g1;->m:Z

    .line 20
    .line 21
    iput-object p3, p0, Lu/g1;->b:Lu/x0;

    .line 22
    .line 23
    iput-object p4, p0, Lu/g1;->c:Lj0/h;

    .line 24
    .line 25
    iput-object p5, p0, Lu/g1;->d:Lj0/c;

    .line 26
    .line 27
    new-instance p3, Ljava/lang/Object;

    .line 28
    .line 29
    invoke-direct {p3}, Ljava/lang/Object;-><init>()V

    .line 30
    .line 31
    .line 32
    iput-object p3, p0, Lu/g1;->o:Ljava/lang/Object;

    .line 33
    .line 34
    new-instance p3, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 35
    .line 36
    invoke-direct {p3, p6}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 37
    .line 38
    .line 39
    iput-object p3, p0, Lu/g1;->v:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 40
    .line 41
    new-instance p3, Lc8/g;

    .line 42
    .line 43
    invoke-direct {p3}, Ljava/lang/Object;-><init>()V

    .line 44
    .line 45
    .line 46
    const-class p4, Landroidx/camera/camera2/internal/compat/quirk/TextureViewIsClosedQuirk;

    .line 47
    .line 48
    invoke-virtual {p2, p4}, Ld01/x;->k(Ljava/lang/Class;)Z

    .line 49
    .line 50
    .line 51
    move-result p4

    .line 52
    iput-boolean p4, p3, Lc8/g;->a:Z

    .line 53
    .line 54
    const-class p4, Landroidx/camera/camera2/internal/compat/quirk/PreviewOrientationIncorrectQuirk;

    .line 55
    .line 56
    invoke-virtual {p1, p4}, Ld01/x;->k(Ljava/lang/Class;)Z

    .line 57
    .line 58
    .line 59
    move-result p4

    .line 60
    iput-boolean p4, p3, Lc8/g;->b:Z

    .line 61
    .line 62
    const-class p4, Landroidx/camera/camera2/internal/compat/quirk/ConfigureSurfaceToSecondarySessionFailQuirk;

    .line 63
    .line 64
    invoke-virtual {p1, p4}, Ld01/x;->k(Ljava/lang/Class;)Z

    .line 65
    .line 66
    .line 67
    move-result p4

    .line 68
    iput-boolean p4, p3, Lc8/g;->c:Z

    .line 69
    .line 70
    iput-object p3, p0, Lu/g1;->r:Lc8/g;

    .line 71
    .line 72
    new-instance p3, Lb6/f;

    .line 73
    .line 74
    const-class p4, Landroidx/camera/camera2/internal/compat/quirk/CaptureSessionStuckQuirk;

    .line 75
    .line 76
    invoke-virtual {p1, p4}, Ld01/x;->k(Ljava/lang/Class;)Z

    .line 77
    .line 78
    .line 79
    move-result p4

    .line 80
    if-nez p4, :cond_0

    .line 81
    .line 82
    const-class p4, Landroidx/camera/camera2/internal/compat/quirk/IncorrectCaptureStateQuirk;

    .line 83
    .line 84
    invoke-virtual {p1, p4}, Ld01/x;->k(Ljava/lang/Class;)Z

    .line 85
    .line 86
    .line 87
    move-result p1

    .line 88
    if-eqz p1, :cond_1

    .line 89
    .line 90
    :cond_0
    const/4 p6, 0x1

    .line 91
    :cond_1
    invoke-direct {p3, p6}, Lb6/f;-><init>(Z)V

    .line 92
    .line 93
    .line 94
    iput-object p3, p0, Lu/g1;->t:Lb6/f;

    .line 95
    .line 96
    new-instance p1, Lpv/g;

    .line 97
    .line 98
    invoke-direct {p1, p2}, Lpv/g;-><init>(Ld01/x;)V

    .line 99
    .line 100
    .line 101
    iput-object p1, p0, Lu/g1;->s:Lpv/g;

    .line 102
    .line 103
    new-instance p1, La8/t1;

    .line 104
    .line 105
    invoke-direct {p1, p2}, La8/t1;-><init>(Ld01/x;)V

    .line 106
    .line 107
    .line 108
    iput-object p1, p0, Lu/g1;->u:La8/t1;

    .line 109
    .line 110
    iput-object p5, p0, Lu/g1;->n:Lj0/c;

    .line 111
    .line 112
    return-void
.end method


# virtual methods
.method public final a(Lu/g1;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lu/g1;->e:Lu/o0;

    .line 2
    .line 3
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lu/g1;->e:Lu/o0;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lu/o0;->a(Lu/g1;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final b(Lu/g1;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lu/g1;->e:Lu/o0;

    .line 2
    .line 3
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lu/g1;->e:Lu/o0;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lu/o0;->b(Lu/g1;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final c(Lu/g1;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lu/g1;->o:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lu/g1;->r:Lc8/g;

    .line 5
    .line 6
    iget-object v2, p0, Lu/g1;->p:Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-virtual {v1, v2}, Lc8/g;->b(Ljava/util/ArrayList;)V

    .line 9
    .line 10
    .line 11
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    .line 12
    const-string v0, "onClosed()"

    .line 13
    .line 14
    invoke-virtual {p0, v0}, Lu/g1;->k(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    iget-object v1, p0, Lu/g1;->a:Ljava/lang/Object;

    .line 18
    .line 19
    monitor-enter v1

    .line 20
    :try_start_1
    iget-boolean v0, p0, Lu/g1;->k:Z

    .line 21
    .line 22
    const/4 v2, 0x0

    .line 23
    if-nez v0, :cond_0

    .line 24
    .line 25
    const/4 v0, 0x1

    .line 26
    iput-boolean v0, p0, Lu/g1;->k:Z

    .line 27
    .line 28
    iget-object v0, p0, Lu/g1;->g:Ly4/k;

    .line 29
    .line 30
    const-string v3, "Need to call openCaptureSession before using this API."

    .line 31
    .line 32
    invoke-static {v0, v3}, Ljp/ed;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    iget-object v0, p0, Lu/g1;->g:Ly4/k;

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :catchall_0
    move-exception p0

    .line 39
    goto :goto_4

    .line 40
    :cond_0
    move-object v0, v2

    .line 41
    :goto_0
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 42
    iget-object v3, p0, Lu/g1;->a:Ljava/lang/Object;

    .line 43
    .line 44
    monitor-enter v3

    .line 45
    :try_start_2
    iget-object v1, p0, Lu/g1;->j:Ljava/util/List;

    .line 46
    .line 47
    if-eqz v1, :cond_2

    .line 48
    .line 49
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 54
    .line 55
    .line 56
    move-result v4

    .line 57
    if-eqz v4, :cond_1

    .line 58
    .line 59
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v4

    .line 63
    check-cast v4, Lh0/t0;

    .line 64
    .line 65
    invoke-virtual {v4}, Lh0/t0;->b()V

    .line 66
    .line 67
    .line 68
    goto :goto_1

    .line 69
    :cond_1
    iput-object v2, p0, Lu/g1;->j:Ljava/util/List;

    .line 70
    .line 71
    goto :goto_2

    .line 72
    :catchall_1
    move-exception p0

    .line 73
    goto :goto_3

    .line 74
    :cond_2
    :goto_2
    monitor-exit v3
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 75
    iget-object v1, p0, Lu/g1;->t:Lb6/f;

    .line 76
    .line 77
    invoke-virtual {v1}, Lb6/f;->x()V

    .line 78
    .line 79
    .line 80
    if-eqz v0, :cond_3

    .line 81
    .line 82
    new-instance v1, Lu/e1;

    .line 83
    .line 84
    const/4 v2, 0x0

    .line 85
    invoke-direct {v1, p0, p1, v2}, Lu/e1;-><init>(Lu/g1;Lu/g1;I)V

    .line 86
    .line 87
    .line 88
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    iget-object p1, v0, Ly4/k;->e:Ly4/j;

    .line 93
    .line 94
    invoke-virtual {p1, p0, v1}, Ly4/g;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 95
    .line 96
    .line 97
    :cond_3
    return-void

    .line 98
    :goto_3
    :try_start_3
    monitor-exit v3
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 99
    throw p0

    .line 100
    :goto_4
    :try_start_4
    monitor-exit v1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 101
    throw p0

    .line 102
    :catchall_2
    move-exception p0

    .line 103
    :try_start_5
    monitor-exit v0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 104
    throw p0
.end method

.method public final d(Lu/g1;)V
    .locals 7

    .line 1
    iget-object v0, p0, Lu/g1;->e:Lu/o0;

    .line 2
    .line 3
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lu/g1;->a:Ljava/lang/Object;

    .line 7
    .line 8
    monitor-enter v0

    .line 9
    :try_start_0
    iget-object v1, p0, Lu/g1;->j:Ljava/util/List;

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    if-eqz v1, :cond_1

    .line 13
    .line 14
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    if-eqz v3, :cond_0

    .line 23
    .line 24
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    check-cast v3, Lh0/t0;

    .line 29
    .line 30
    invoke-virtual {v3}, Lh0/t0;->b()V

    .line 31
    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    iput-object v2, p0, Lu/g1;->j:Ljava/util/List;

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :catchall_0
    move-exception p0

    .line 38
    goto :goto_7

    .line 39
    :cond_1
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 40
    iget-object v0, p0, Lu/g1;->t:Lb6/f;

    .line 41
    .line 42
    invoke-virtual {v0}, Lb6/f;->x()V

    .line 43
    .line 44
    .line 45
    iget-object v0, p0, Lu/g1;->b:Lu/x0;

    .line 46
    .line 47
    invoke-virtual {v0}, Lu/x0;->h()Ljava/util/ArrayList;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 56
    .line 57
    .line 58
    move-result v3

    .line 59
    if-eqz v3, :cond_5

    .line 60
    .line 61
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v3

    .line 65
    check-cast v3, Lu/g1;

    .line 66
    .line 67
    if-ne v3, p0, :cond_2

    .line 68
    .line 69
    goto :goto_6

    .line 70
    :cond_2
    iget-object v4, v3, Lu/g1;->a:Ljava/lang/Object;

    .line 71
    .line 72
    monitor-enter v4

    .line 73
    :try_start_1
    iget-object v5, v3, Lu/g1;->j:Ljava/util/List;

    .line 74
    .line 75
    if-eqz v5, :cond_4

    .line 76
    .line 77
    invoke-interface {v5}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 78
    .line 79
    .line 80
    move-result-object v5

    .line 81
    :goto_3
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 82
    .line 83
    .line 84
    move-result v6

    .line 85
    if-eqz v6, :cond_3

    .line 86
    .line 87
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v6

    .line 91
    check-cast v6, Lh0/t0;

    .line 92
    .line 93
    invoke-virtual {v6}, Lh0/t0;->b()V

    .line 94
    .line 95
    .line 96
    goto :goto_3

    .line 97
    :cond_3
    iput-object v2, v3, Lu/g1;->j:Ljava/util/List;

    .line 98
    .line 99
    goto :goto_4

    .line 100
    :catchall_1
    move-exception p0

    .line 101
    goto :goto_5

    .line 102
    :cond_4
    :goto_4
    monitor-exit v4
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 103
    iget-object v3, v3, Lu/g1;->t:Lb6/f;

    .line 104
    .line 105
    invoke-virtual {v3}, Lb6/f;->x()V

    .line 106
    .line 107
    .line 108
    goto :goto_2

    .line 109
    :goto_5
    :try_start_2
    monitor-exit v4
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 110
    throw p0

    .line 111
    :cond_5
    :goto_6
    iget-object v1, v0, Lu/x0;->b:Ljava/lang/Object;

    .line 112
    .line 113
    monitor-enter v1

    .line 114
    :try_start_3
    iget-object v0, v0, Lu/x0;->e:Ljava/lang/Object;

    .line 115
    .line 116
    check-cast v0, Ljava/util/LinkedHashSet;

    .line 117
    .line 118
    invoke-interface {v0, p0}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    .line 119
    .line 120
    .line 121
    monitor-exit v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 122
    iget-object p0, p0, Lu/g1;->e:Lu/o0;

    .line 123
    .line 124
    invoke-virtual {p0, p1}, Lu/o0;->d(Lu/g1;)V

    .line 125
    .line 126
    .line 127
    return-void

    .line 128
    :catchall_2
    move-exception p0

    .line 129
    :try_start_4
    monitor-exit v1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 130
    throw p0

    .line 131
    :goto_7
    :try_start_5
    monitor-exit v0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 132
    throw p0
.end method

.method public final e(Lu/g1;)V
    .locals 7

    .line 1
    const-string v0, "Session onConfigured()"

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Lu/g1;->k(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lu/g1;->s:Lpv/g;

    .line 7
    .line 8
    iget-object v1, p0, Lu/g1;->b:Lu/x0;

    .line 9
    .line 10
    iget-object v2, v1, Lu/x0;->b:Ljava/lang/Object;

    .line 11
    .line 12
    monitor-enter v2

    .line 13
    :try_start_0
    new-instance v3, Ljava/util/ArrayList;

    .line 14
    .line 15
    iget-object v1, v1, Lu/x0;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v1, Ljava/util/LinkedHashSet;

    .line 18
    .line 19
    invoke-direct {v3, v1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 20
    .line 21
    .line 22
    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    .line 23
    iget-object v1, p0, Lu/g1;->b:Lu/x0;

    .line 24
    .line 25
    invoke-virtual {v1}, Lu/x0;->f()Ljava/util/ArrayList;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    iget-object v2, v0, Lpv/g;->e:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v2, Landroidx/camera/camera2/internal/compat/quirk/CaptureSessionOnClosedNotCalledQuirk;

    .line 32
    .line 33
    if-eqz v2, :cond_2

    .line 34
    .line 35
    new-instance v2, Ljava/util/LinkedHashSet;

    .line 36
    .line 37
    invoke-direct {v2}, Ljava/util/LinkedHashSet;-><init>()V

    .line 38
    .line 39
    .line 40
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 41
    .line 42
    .line 43
    move-result-object v3

    .line 44
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 45
    .line 46
    .line 47
    move-result v4

    .line 48
    if-eqz v4, :cond_1

    .line 49
    .line 50
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v4

    .line 54
    check-cast v4, Lu/g1;

    .line 55
    .line 56
    if-ne v4, p1, :cond_0

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_0
    invoke-interface {v2, v4}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_1
    :goto_1
    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 64
    .line 65
    .line 66
    move-result-object v2

    .line 67
    :goto_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 68
    .line 69
    .line 70
    move-result v3

    .line 71
    if-eqz v3, :cond_2

    .line 72
    .line 73
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v3

    .line 77
    check-cast v3, Lu/g1;

    .line 78
    .line 79
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 80
    .line 81
    .line 82
    invoke-virtual {v3, v3}, Lu/g1;->d(Lu/g1;)V

    .line 83
    .line 84
    .line 85
    goto :goto_2

    .line 86
    :cond_2
    iget-object v2, p0, Lu/g1;->e:Lu/o0;

    .line 87
    .line 88
    invoke-static {v2}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    iget-object v2, p0, Lu/g1;->b:Lu/x0;

    .line 92
    .line 93
    iget-object v3, v2, Lu/x0;->b:Ljava/lang/Object;

    .line 94
    .line 95
    monitor-enter v3

    .line 96
    :try_start_1
    iget-object v4, v2, Lu/x0;->c:Ljava/lang/Object;

    .line 97
    .line 98
    check-cast v4, Ljava/util/LinkedHashSet;

    .line 99
    .line 100
    invoke-interface {v4, p0}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    iget-object v4, v2, Lu/x0;->e:Ljava/lang/Object;

    .line 104
    .line 105
    check-cast v4, Ljava/util/LinkedHashSet;

    .line 106
    .line 107
    invoke-interface {v4, p0}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    monitor-exit v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 111
    invoke-virtual {v2}, Lu/x0;->h()Ljava/util/ArrayList;

    .line 112
    .line 113
    .line 114
    move-result-object v2

    .line 115
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 116
    .line 117
    .line 118
    move-result-object v2

    .line 119
    :goto_3
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 120
    .line 121
    .line 122
    move-result v3

    .line 123
    if-eqz v3, :cond_6

    .line 124
    .line 125
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v3

    .line 129
    check-cast v3, Lu/g1;

    .line 130
    .line 131
    if-ne v3, p0, :cond_3

    .line 132
    .line 133
    goto :goto_7

    .line 134
    :cond_3
    iget-object v4, v3, Lu/g1;->a:Ljava/lang/Object;

    .line 135
    .line 136
    monitor-enter v4

    .line 137
    :try_start_2
    iget-object v5, v3, Lu/g1;->j:Ljava/util/List;

    .line 138
    .line 139
    if-eqz v5, :cond_5

    .line 140
    .line 141
    invoke-interface {v5}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 142
    .line 143
    .line 144
    move-result-object v5

    .line 145
    :goto_4
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 146
    .line 147
    .line 148
    move-result v6

    .line 149
    if-eqz v6, :cond_4

    .line 150
    .line 151
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object v6

    .line 155
    check-cast v6, Lh0/t0;

    .line 156
    .line 157
    invoke-virtual {v6}, Lh0/t0;->b()V

    .line 158
    .line 159
    .line 160
    goto :goto_4

    .line 161
    :cond_4
    const/4 v5, 0x0

    .line 162
    iput-object v5, v3, Lu/g1;->j:Ljava/util/List;

    .line 163
    .line 164
    goto :goto_5

    .line 165
    :catchall_0
    move-exception p0

    .line 166
    goto :goto_6

    .line 167
    :cond_5
    :goto_5
    monitor-exit v4
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 168
    iget-object v3, v3, Lu/g1;->t:Lb6/f;

    .line 169
    .line 170
    invoke-virtual {v3}, Lb6/f;->x()V

    .line 171
    .line 172
    .line 173
    goto :goto_3

    .line 174
    :goto_6
    :try_start_3
    monitor-exit v4
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 175
    throw p0

    .line 176
    :cond_6
    :goto_7
    iget-object p0, p0, Lu/g1;->e:Lu/o0;

    .line 177
    .line 178
    invoke-virtual {p0, p1}, Lu/o0;->e(Lu/g1;)V

    .line 179
    .line 180
    .line 181
    iget-object p0, v0, Lpv/g;->e:Ljava/lang/Object;

    .line 182
    .line 183
    check-cast p0, Landroidx/camera/camera2/internal/compat/quirk/CaptureSessionOnClosedNotCalledQuirk;

    .line 184
    .line 185
    if-eqz p0, :cond_9

    .line 186
    .line 187
    new-instance p0, Ljava/util/LinkedHashSet;

    .line 188
    .line 189
    invoke-direct {p0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 190
    .line 191
    .line 192
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 193
    .line 194
    .line 195
    move-result-object v0

    .line 196
    :goto_8
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 197
    .line 198
    .line 199
    move-result v1

    .line 200
    if-eqz v1, :cond_8

    .line 201
    .line 202
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 203
    .line 204
    .line 205
    move-result-object v1

    .line 206
    check-cast v1, Lu/g1;

    .line 207
    .line 208
    if-ne v1, p1, :cond_7

    .line 209
    .line 210
    goto :goto_9

    .line 211
    :cond_7
    invoke-interface {p0, v1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 212
    .line 213
    .line 214
    goto :goto_8

    .line 215
    :cond_8
    :goto_9
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 216
    .line 217
    .line 218
    move-result-object p0

    .line 219
    :goto_a
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 220
    .line 221
    .line 222
    move-result p1

    .line 223
    if-eqz p1, :cond_9

    .line 224
    .line 225
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 226
    .line 227
    .line 228
    move-result-object p1

    .line 229
    check-cast p1, Lu/g1;

    .line 230
    .line 231
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 232
    .line 233
    .line 234
    invoke-virtual {p1, p1}, Lu/g1;->c(Lu/g1;)V

    .line 235
    .line 236
    .line 237
    goto :goto_a

    .line 238
    :cond_9
    return-void

    .line 239
    :catchall_1
    move-exception p0

    .line 240
    :try_start_4
    monitor-exit v3
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 241
    throw p0

    .line 242
    :catchall_2
    move-exception p0

    .line 243
    :try_start_5
    monitor-exit v2
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 244
    throw p0
.end method

.method public final f(Lu/g1;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lu/g1;->e:Lu/o0;

    .line 2
    .line 3
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lu/g1;->e:Lu/o0;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lu/o0;->f(Lu/g1;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final g(Lu/g1;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lu/g1;->a:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-boolean v1, p0, Lu/g1;->m:Z

    .line 5
    .line 6
    if-nez v1, :cond_0

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    iput-boolean v1, p0, Lu/g1;->m:Z

    .line 10
    .line 11
    iget-object v1, p0, Lu/g1;->g:Ly4/k;

    .line 12
    .line 13
    const-string v2, "Need to call openCaptureSession before using this API."

    .line 14
    .line 15
    invoke-static {v1, v2}, Ljp/ed;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lu/g1;->g:Ly4/k;

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :catchall_0
    move-exception p0

    .line 22
    goto :goto_1

    .line 23
    :cond_0
    const/4 v1, 0x0

    .line 24
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 25
    if-eqz v1, :cond_1

    .line 26
    .line 27
    new-instance v0, Lu/e1;

    .line 28
    .line 29
    const/4 v2, 0x1

    .line 30
    invoke-direct {v0, p0, p1, v2}, Lu/e1;-><init>(Lu/g1;Lu/g1;I)V

    .line 31
    .line 32
    .line 33
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    iget-object p1, v1, Ly4/k;->e:Ly4/j;

    .line 38
    .line 39
    invoke-virtual {p1, p0, v0}, Ly4/g;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 40
    .line 41
    .line 42
    :cond_1
    return-void

    .line 43
    :goto_1
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 44
    throw p0
.end method

.method public final h(Lu/g1;Landroid/view/Surface;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lu/g1;->e:Lu/o0;

    .line 2
    .line 3
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lu/g1;->e:Lu/o0;

    .line 7
    .line 8
    invoke-virtual {p0, p1, p2}, Lu/o0;->h(Lu/g1;Landroid/view/Surface;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final i()V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x1

    .line 3
    iget-object v2, p0, Lu/g1;->v:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 4
    .line 5
    invoke-virtual {v2, v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;->compareAndSet(ZZ)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    const-string v0, "close() has been called. Skip this invocation."

    .line 12
    .line 13
    invoke-virtual {p0, v0}, Lu/g1;->k(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :cond_0
    iget-object v0, p0, Lu/g1;->u:La8/t1;

    .line 18
    .line 19
    iget-boolean v0, v0, La8/t1;->b:Z

    .line 20
    .line 21
    if-eqz v0, :cond_1

    .line 22
    .line 23
    :try_start_0
    const-string v0, "Call abortCaptures() before closing session."

    .line 24
    .line 25
    invoke-virtual {p0, v0}, Lu/g1;->k(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    iget-object v0, p0, Lu/g1;->f:Lro/f;

    .line 29
    .line 30
    const-string v1, "Need to call openCaptureSession before using this API."

    .line 31
    .line 32
    invoke-static {v0, v1}, Ljp/ed;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    iget-object v0, p0, Lu/g1;->f:Lro/f;

    .line 36
    .line 37
    iget-object v0, v0, Lro/f;->e:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast v0, Lb81/c;

    .line 40
    .line 41
    iget-object v0, v0, Lb81/c;->e:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast v0, Landroid/hardware/camera2/CameraCaptureSession;

    .line 44
    .line 45
    invoke-virtual {v0}, Landroid/hardware/camera2/CameraCaptureSession;->abortCaptures()V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 46
    .line 47
    .line 48
    goto :goto_0

    .line 49
    :catch_0
    move-exception v0

    .line 50
    new-instance v1, Ljava/lang/StringBuilder;

    .line 51
    .line 52
    const-string v2, "Exception when calling abortCaptures()"

    .line 53
    .line 54
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    invoke-virtual {p0, v0}, Lu/g1;->k(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    :cond_1
    :goto_0
    const-string v0, "Session call close()"

    .line 68
    .line 69
    invoke-virtual {p0, v0}, Lu/g1;->k(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    iget-object v0, p0, Lu/g1;->t:Lb6/f;

    .line 73
    .line 74
    invoke-virtual {v0}, Lb6/f;->m()Lcom/google/common/util/concurrent/ListenableFuture;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    new-instance v1, Lu/f1;

    .line 79
    .line 80
    const/4 v2, 0x1

    .line 81
    invoke-direct {v1, p0, v2}, Lu/f1;-><init>(Lu/g1;I)V

    .line 82
    .line 83
    .line 84
    iget-object p0, p0, Lu/g1;->c:Lj0/h;

    .line 85
    .line 86
    invoke-interface {v0, p0, v1}, Lcom/google/common/util/concurrent/ListenableFuture;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 87
    .line 88
    .line 89
    return-void
.end method

.method public final j(Landroid/hardware/camera2/CameraCaptureSession;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lu/g1;->f:Lro/f;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lro/f;

    .line 6
    .line 7
    invoke-direct {v0, p1}, Lro/f;-><init>(Landroid/hardware/camera2/CameraCaptureSession;)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lu/g1;->f:Lro/f;

    .line 11
    .line 12
    :cond_0
    return-void
.end method

.method public final k(Ljava/lang/String;)V
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "["

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    const-string p0, "] "

    .line 12
    .line 13
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    const-string p1, "SyncCaptureSessionImpl"

    .line 24
    .line 25
    invoke-static {p1, p0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method public final l()Z
    .locals 1

    .line 1
    iget-object v0, p0, Lu/g1;->a:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lu/g1;->g:Ly4/k;

    .line 5
    .line 6
    if-eqz p0, :cond_0

    .line 7
    .line 8
    const/4 p0, 0x1

    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 p0, 0x0

    .line 11
    :goto_0
    monitor-exit v0

    .line 12
    return p0

    .line 13
    :catchall_0
    move-exception p0

    .line 14
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 15
    throw p0
.end method

.method public final m(Landroid/hardware/camera2/CameraDevice;Lw/m;Ljava/util/List;)Lcom/google/common/util/concurrent/ListenableFuture;
    .locals 8

    .line 1
    iget-object v0, p0, Lu/g1;->o:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lu/g1;->b:Lu/x0;

    .line 5
    .line 6
    invoke-virtual {v1}, Lu/x0;->f()Ljava/util/ArrayList;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    new-instance v2, Ljava/util/ArrayList;

    .line 11
    .line 12
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    if-eqz v3, :cond_0

    .line 24
    .line 25
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    check-cast v3, Lu/g1;

    .line 30
    .line 31
    iget-object v4, v3, Lu/g1;->n:Lj0/c;

    .line 32
    .line 33
    iget-object v3, v3, Lu/g1;->t:Lb6/f;

    .line 34
    .line 35
    invoke-virtual {v3}, Lb6/f;->m()Lcom/google/common/util/concurrent/ListenableFuture;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    new-instance v5, Ldu/f;

    .line 40
    .line 41
    const-wide/16 v6, 0x5dc

    .line 42
    .line 43
    invoke-direct {v5, v3, v4, v6, v7}, Ldu/f;-><init>(Ljava/lang/Object;Ljava/lang/Object;J)V

    .line 44
    .line 45
    .line 46
    invoke-static {v5}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 47
    .line 48
    .line 49
    move-result-object v3

    .line 50
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    goto :goto_0

    .line 54
    :catchall_0
    move-exception p0

    .line 55
    goto :goto_1

    .line 56
    :cond_0
    new-instance v1, Lk0/k;

    .line 57
    .line 58
    new-instance v3, Ljava/util/ArrayList;

    .line 59
    .line 60
    invoke-direct {v3, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 61
    .line 62
    .line 63
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 64
    .line 65
    .line 66
    move-result-object v2

    .line 67
    const/4 v4, 0x0

    .line 68
    invoke-direct {v1, v3, v4, v2}, Lk0/k;-><init>(Ljava/util/ArrayList;ZLj0/a;)V

    .line 69
    .line 70
    .line 71
    iput-object v1, p0, Lu/g1;->q:Lk0/k;

    .line 72
    .line 73
    invoke-static {v1}, Lk0/d;->b(Lcom/google/common/util/concurrent/ListenableFuture;)Lk0/d;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    new-instance v2, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;

    .line 78
    .line 79
    invoke-direct {v2, p0, p1, p2, p3}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    iget-object p0, p0, Lu/g1;->c:Lj0/h;

    .line 83
    .line 84
    invoke-static {v1, v2, p0}, Lk0/h;->g(Lcom/google/common/util/concurrent/ListenableFuture;Lk0/a;Ljava/util/concurrent/Executor;)Lk0/b;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    invoke-static {p0}, Lk0/h;->d(Lcom/google/common/util/concurrent/ListenableFuture;)Lcom/google/common/util/concurrent/ListenableFuture;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    monitor-exit v0

    .line 93
    return-object p0

    .line 94
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 95
    throw p0
.end method

.method public final n(Ljava/util/List;Landroid/hardware/camera2/CameraCaptureSession$CaptureCallback;)I
    .locals 2

    .line 1
    iget-object v0, p0, Lu/g1;->f:Lro/f;

    .line 2
    .line 3
    const-string v1, "Need to call openCaptureSession before using this API."

    .line 4
    .line 5
    invoke-static {v0, v1}, Ljp/ed;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lu/g1;->f:Lro/f;

    .line 9
    .line 10
    iget-object v0, v0, Lro/f;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v0, Lb81/c;

    .line 13
    .line 14
    iget-object v0, v0, Lb81/c;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v0, Landroid/hardware/camera2/CameraCaptureSession;

    .line 17
    .line 18
    iget-object p0, p0, Lu/g1;->c:Lj0/h;

    .line 19
    .line 20
    invoke-virtual {v0, p1, p0, p2}, Landroid/hardware/camera2/CameraCaptureSession;->setRepeatingBurstRequests(Ljava/util/List;Ljava/util/concurrent/Executor;Landroid/hardware/camera2/CameraCaptureSession$CaptureCallback;)I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    return p0
.end method

.method public final o(Landroid/hardware/camera2/CaptureRequest;Landroid/hardware/camera2/CameraCaptureSession$CaptureCallback;)I
    .locals 2

    .line 1
    iget-object v0, p0, Lu/g1;->t:Lb6/f;

    .line 2
    .line 3
    invoke-virtual {v0, p2}, Lb6/f;->k(Landroid/hardware/camera2/CameraCaptureSession$CaptureCallback;)Landroid/hardware/camera2/CameraCaptureSession$CaptureCallback;

    .line 4
    .line 5
    .line 6
    move-result-object p2

    .line 7
    iget-object v0, p0, Lu/g1;->f:Lro/f;

    .line 8
    .line 9
    const-string v1, "Need to call openCaptureSession before using this API."

    .line 10
    .line 11
    invoke-static {v0, v1}, Ljp/ed;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    iget-object v0, p0, Lu/g1;->f:Lro/f;

    .line 15
    .line 16
    iget-object v0, v0, Lro/f;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v0, Lb81/c;

    .line 19
    .line 20
    iget-object v0, v0, Lb81/c;->e:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v0, Landroid/hardware/camera2/CameraCaptureSession;

    .line 23
    .line 24
    iget-object p0, p0, Lu/g1;->c:Lj0/h;

    .line 25
    .line 26
    invoke-virtual {v0, p1, p0, p2}, Landroid/hardware/camera2/CameraCaptureSession;->setSingleRepeatingRequest(Landroid/hardware/camera2/CaptureRequest;Ljava/util/concurrent/Executor;Landroid/hardware/camera2/CameraCaptureSession$CaptureCallback;)I

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    return p0
.end method

.method public final p(Ljava/util/ArrayList;)Lcom/google/common/util/concurrent/ListenableFuture;
    .locals 4

    .line 1
    iget-object v0, p0, Lu/g1;->a:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-boolean v1, p0, Lu/g1;->l:Z

    .line 5
    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    new-instance p0, Ljava/util/concurrent/CancellationException;

    .line 9
    .line 10
    const-string p1, "Opener is disabled"

    .line 11
    .line 12
    invoke-direct {p0, p1}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    new-instance p1, Lk0/j;

    .line 16
    .line 17
    const/4 v1, 0x1

    .line 18
    invoke-direct {p1, p0, v1}, Lk0/j;-><init>(Ljava/lang/Object;I)V

    .line 19
    .line 20
    .line 21
    monitor-exit v0

    .line 22
    return-object p1

    .line 23
    :catchall_0
    move-exception p0

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    iget-object v1, p0, Lu/g1;->c:Lj0/h;

    .line 26
    .line 27
    iget-object v2, p0, Lu/g1;->d:Lj0/c;

    .line 28
    .line 29
    invoke-static {p1, v1, v2}, Lkp/y9;->b(Ljava/util/List;Lj0/h;Lj0/c;)Ly4/k;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    invoke-static {v1}, Lk0/d;->b(Lcom/google/common/util/concurrent/ListenableFuture;)Lk0/d;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    new-instance v2, La0/h;

    .line 38
    .line 39
    const/16 v3, 0x1a

    .line 40
    .line 41
    invoke-direct {v2, v3, p0, p1}, La0/h;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    iget-object p1, p0, Lu/g1;->c:Lj0/h;

    .line 45
    .line 46
    invoke-static {v1, v2, p1}, Lk0/h;->g(Lcom/google/common/util/concurrent/ListenableFuture;Lk0/a;Ljava/util/concurrent/Executor;)Lk0/b;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    iput-object p1, p0, Lu/g1;->i:Lk0/d;

    .line 51
    .line 52
    invoke-static {p1}, Lk0/h;->d(Lcom/google/common/util/concurrent/ListenableFuture;)Lcom/google/common/util/concurrent/ListenableFuture;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    monitor-exit v0

    .line 57
    return-object p0

    .line 58
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 59
    throw p0
.end method

.method public final q()Z
    .locals 5

    .line 1
    iget-object v0, p0, Lu/g1;->o:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    invoke-virtual {p0}, Lu/g1;->l()Z

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    const/4 v2, 0x1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    iget-object v1, p0, Lu/g1;->r:Lc8/g;

    .line 12
    .line 13
    iget-object v3, p0, Lu/g1;->p:Ljava/util/ArrayList;

    .line 14
    .line 15
    invoke-virtual {v1, v3}, Lc8/g;->b(Ljava/util/ArrayList;)V

    .line 16
    .line 17
    .line 18
    goto :goto_0

    .line 19
    :catchall_0
    move-exception p0

    .line 20
    goto :goto_3

    .line 21
    :cond_0
    iget-object v1, p0, Lu/g1;->q:Lk0/k;

    .line 22
    .line 23
    if-eqz v1, :cond_1

    .line 24
    .line 25
    invoke-virtual {v1, v2}, Lk0/k;->cancel(Z)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 26
    .line 27
    .line 28
    :cond_1
    :goto_0
    const/4 v1, 0x0

    .line 29
    :try_start_1
    iget-object v3, p0, Lu/g1;->a:Ljava/lang/Object;

    .line 30
    .line 31
    monitor-enter v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    .line 32
    :try_start_2
    iget-boolean v4, p0, Lu/g1;->l:Z

    .line 33
    .line 34
    if-nez v4, :cond_3

    .line 35
    .line 36
    iget-object v4, p0, Lu/g1;->i:Lk0/d;

    .line 37
    .line 38
    if-eqz v4, :cond_2

    .line 39
    .line 40
    move-object v1, v4

    .line 41
    :cond_2
    iput-boolean v2, p0, Lu/g1;->l:Z

    .line 42
    .line 43
    goto :goto_1

    .line 44
    :catchall_1
    move-exception p0

    .line 45
    goto :goto_2

    .line 46
    :cond_3
    :goto_1
    invoke-virtual {p0}, Lu/g1;->l()Z

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    xor-int/2addr p0, v2

    .line 51
    monitor-exit v3
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 52
    if-eqz v1, :cond_4

    .line 53
    .line 54
    :try_start_3
    invoke-interface {v1, v2}, Ljava/util/concurrent/Future;->cancel(Z)Z

    .line 55
    .line 56
    .line 57
    :cond_4
    monitor-exit v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 58
    return p0

    .line 59
    :goto_2
    :try_start_4
    monitor-exit v3
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 60
    :try_start_5
    throw p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 61
    :catchall_2
    move-exception p0

    .line 62
    if-eqz v1, :cond_5

    .line 63
    .line 64
    :try_start_6
    invoke-interface {v1, v2}, Ljava/util/concurrent/Future;->cancel(Z)Z

    .line 65
    .line 66
    .line 67
    :cond_5
    throw p0

    .line 68
    :goto_3
    monitor-exit v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 69
    throw p0
.end method

.method public final r()Lro/f;
    .locals 1

    .line 1
    iget-object v0, p0, Lu/g1;->f:Lro/f;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lu/g1;->f:Lro/f;

    .line 7
    .line 8
    return-object p0
.end method
