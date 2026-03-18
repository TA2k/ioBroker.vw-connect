.class public final Lb8/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public A:I

.field public B:Z

.field public final a:Landroid/content/Context;

.field public final b:Ljava/util/concurrent/Executor;

.field public final c:Lb8/g;

.field public final d:Landroid/media/metrics/PlaybackSession;

.field public final e:J

.field public final f:Lt7/o0;

.field public final g:Lt7/n0;

.field public final h:Ljava/util/HashMap;

.field public final i:Ljava/util/HashMap;

.field public j:Ljava/lang/String;

.field public k:Landroid/media/metrics/PlaybackMetrics$Builder;

.field public l:I

.field public m:I

.field public n:I

.field public o:Lt7/f0;

.field public p:Lb81/a;

.field public q:Lb81/a;

.field public r:Lb81/a;

.field public s:Lt7/o;

.field public t:Lt7/o;

.field public u:Lt7/o;

.field public v:Z

.field public w:I

.field public x:Z

.field public y:I

.field public z:I


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroid/media/metrics/PlaybackSession;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    iput-object p1, p0, Lb8/j;->a:Landroid/content/Context;

    .line 9
    .line 10
    iput-object p2, p0, Lb8/j;->d:Landroid/media/metrics/PlaybackSession;

    .line 11
    .line 12
    invoke-static {}, Lw7/a;->q()Ljava/util/concurrent/Executor;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    iput-object p1, p0, Lb8/j;->b:Ljava/util/concurrent/Executor;

    .line 17
    .line 18
    new-instance p1, Lt7/o0;

    .line 19
    .line 20
    invoke-direct {p1}, Lt7/o0;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object p1, p0, Lb8/j;->f:Lt7/o0;

    .line 24
    .line 25
    new-instance p1, Lt7/n0;

    .line 26
    .line 27
    invoke-direct {p1}, Lt7/n0;-><init>()V

    .line 28
    .line 29
    .line 30
    iput-object p1, p0, Lb8/j;->g:Lt7/n0;

    .line 31
    .line 32
    new-instance p1, Ljava/util/HashMap;

    .line 33
    .line 34
    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    .line 35
    .line 36
    .line 37
    iput-object p1, p0, Lb8/j;->i:Ljava/util/HashMap;

    .line 38
    .line 39
    new-instance p1, Ljava/util/HashMap;

    .line 40
    .line 41
    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    .line 42
    .line 43
    .line 44
    iput-object p1, p0, Lb8/j;->h:Ljava/util/HashMap;

    .line 45
    .line 46
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 47
    .line 48
    .line 49
    move-result-wide p1

    .line 50
    iput-wide p1, p0, Lb8/j;->e:J

    .line 51
    .line 52
    const/4 p1, 0x0

    .line 53
    iput p1, p0, Lb8/j;->m:I

    .line 54
    .line 55
    iput p1, p0, Lb8/j;->n:I

    .line 56
    .line 57
    new-instance p1, Lb8/g;

    .line 58
    .line 59
    invoke-direct {p1}, Lb8/g;-><init>()V

    .line 60
    .line 61
    .line 62
    iput-object p1, p0, Lb8/j;->c:Lb8/g;

    .line 63
    .line 64
    iput-object p0, p1, Lb8/g;->d:Lb8/j;

    .line 65
    .line 66
    return-void
.end method


# virtual methods
.method public final a(Lb81/a;)Z
    .locals 1

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iget-object p1, p1, Lb81/a;->f:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p1, Ljava/lang/String;

    .line 6
    .line 7
    iget-object p0, p0, Lb8/j;->c:Lb8/g;

    .line 8
    .line 9
    monitor-enter p0

    .line 10
    :try_start_0
    iget-object v0, p0, Lb8/g;->f:Ljava/lang/String;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 11
    .line 12
    monitor-exit p0

    .line 13
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    if-eqz p0, :cond_0

    .line 18
    .line 19
    const/4 p0, 0x1

    .line 20
    return p0

    .line 21
    :catchall_0
    move-exception p1

    .line 22
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 23
    throw p1

    .line 24
    :cond_0
    const/4 p0, 0x0

    .line 25
    return p0
.end method

.method public final b()V
    .locals 7

    .line 1
    iget-object v0, p0, Lb8/j;->k:Landroid/media/metrics/PlaybackMetrics$Builder;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_3

    .line 5
    .line 6
    iget-boolean v2, p0, Lb8/j;->B:Z

    .line 7
    .line 8
    if-eqz v2, :cond_3

    .line 9
    .line 10
    iget v2, p0, Lb8/j;->A:I

    .line 11
    .line 12
    invoke-static {v0, v2}, La6/c;->v(Landroid/media/metrics/PlaybackMetrics$Builder;I)V

    .line 13
    .line 14
    .line 15
    iget-object v0, p0, Lb8/j;->k:Landroid/media/metrics/PlaybackMetrics$Builder;

    .line 16
    .line 17
    iget v2, p0, Lb8/j;->y:I

    .line 18
    .line 19
    invoke-static {v0, v2}, La6/c;->y(Landroid/media/metrics/PlaybackMetrics$Builder;I)V

    .line 20
    .line 21
    .line 22
    iget-object v0, p0, Lb8/j;->k:Landroid/media/metrics/PlaybackMetrics$Builder;

    .line 23
    .line 24
    iget v2, p0, Lb8/j;->z:I

    .line 25
    .line 26
    invoke-static {v0, v2}, La6/c;->B(Landroid/media/metrics/PlaybackMetrics$Builder;I)V

    .line 27
    .line 28
    .line 29
    iget-object v0, p0, Lb8/j;->h:Ljava/util/HashMap;

    .line 30
    .line 31
    iget-object v2, p0, Lb8/j;->j:Ljava/lang/String;

    .line 32
    .line 33
    invoke-virtual {v0, v2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    check-cast v0, Ljava/lang/Long;

    .line 38
    .line 39
    iget-object v2, p0, Lb8/j;->k:Landroid/media/metrics/PlaybackMetrics$Builder;

    .line 40
    .line 41
    const-wide/16 v3, 0x0

    .line 42
    .line 43
    if-nez v0, :cond_0

    .line 44
    .line 45
    move-wide v5, v3

    .line 46
    goto :goto_0

    .line 47
    :cond_0
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 48
    .line 49
    .line 50
    move-result-wide v5

    .line 51
    :goto_0
    invoke-static {v2, v5, v6}, La6/c;->p(Landroid/media/metrics/PlaybackMetrics$Builder;J)V

    .line 52
    .line 53
    .line 54
    iget-object v0, p0, Lb8/j;->i:Ljava/util/HashMap;

    .line 55
    .line 56
    iget-object v2, p0, Lb8/j;->j:Ljava/lang/String;

    .line 57
    .line 58
    invoke-virtual {v0, v2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    check-cast v0, Ljava/lang/Long;

    .line 63
    .line 64
    iget-object v2, p0, Lb8/j;->k:Landroid/media/metrics/PlaybackMetrics$Builder;

    .line 65
    .line 66
    if-nez v0, :cond_1

    .line 67
    .line 68
    move-wide v5, v3

    .line 69
    goto :goto_1

    .line 70
    :cond_1
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 71
    .line 72
    .line 73
    move-result-wide v5

    .line 74
    :goto_1
    invoke-static {v2, v5, v6}, Lb8/h;->o(Landroid/media/metrics/PlaybackMetrics$Builder;J)V

    .line 75
    .line 76
    .line 77
    iget-object v2, p0, Lb8/j;->k:Landroid/media/metrics/PlaybackMetrics$Builder;

    .line 78
    .line 79
    if-eqz v0, :cond_2

    .line 80
    .line 81
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 82
    .line 83
    .line 84
    move-result-wide v5

    .line 85
    cmp-long v0, v5, v3

    .line 86
    .line 87
    if-lez v0, :cond_2

    .line 88
    .line 89
    const/4 v0, 0x1

    .line 90
    goto :goto_2

    .line 91
    :cond_2
    move v0, v1

    .line 92
    :goto_2
    invoke-static {v2, v0}, Lb8/h;->n(Landroid/media/metrics/PlaybackMetrics$Builder;I)V

    .line 93
    .line 94
    .line 95
    iget-object v0, p0, Lb8/j;->k:Landroid/media/metrics/PlaybackMetrics$Builder;

    .line 96
    .line 97
    invoke-static {v0}, Lb8/h;->f(Landroid/media/metrics/PlaybackMetrics$Builder;)Landroid/media/metrics/PlaybackMetrics;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    new-instance v2, La8/z;

    .line 102
    .line 103
    const/16 v3, 0xc

    .line 104
    .line 105
    invoke-direct {v2, v3, p0, v0}, La8/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    iget-object v0, p0, Lb8/j;->b:Ljava/util/concurrent/Executor;

    .line 109
    .line 110
    invoke-interface {v0, v2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 111
    .line 112
    .line 113
    :cond_3
    const/4 v0, 0x0

    .line 114
    iput-object v0, p0, Lb8/j;->k:Landroid/media/metrics/PlaybackMetrics$Builder;

    .line 115
    .line 116
    iput-object v0, p0, Lb8/j;->j:Ljava/lang/String;

    .line 117
    .line 118
    iput v1, p0, Lb8/j;->A:I

    .line 119
    .line 120
    iput v1, p0, Lb8/j;->y:I

    .line 121
    .line 122
    iput v1, p0, Lb8/j;->z:I

    .line 123
    .line 124
    iput-object v0, p0, Lb8/j;->s:Lt7/o;

    .line 125
    .line 126
    iput-object v0, p0, Lb8/j;->t:Lt7/o;

    .line 127
    .line 128
    iput-object v0, p0, Lb8/j;->u:Lt7/o;

    .line 129
    .line 130
    iput-boolean v1, p0, Lb8/j;->B:Z

    .line 131
    .line 132
    return-void
.end method

.method public final c(Lt7/p0;Lh8/b0;)V
    .locals 8

    .line 1
    iget-object v0, p0, Lb8/j;->k:Landroid/media/metrics/PlaybackMetrics$Builder;

    .line 2
    .line 3
    if-nez p2, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    iget-object p2, p2, Lh8/b0;->a:Ljava/lang/Object;

    .line 7
    .line 8
    invoke-virtual {p1, p2}, Lt7/p0;->b(Ljava/lang/Object;)I

    .line 9
    .line 10
    .line 11
    move-result p2

    .line 12
    const/4 v1, -0x1

    .line 13
    if-ne p2, v1, :cond_1

    .line 14
    .line 15
    :goto_0
    return-void

    .line 16
    :cond_1
    iget-object v1, p0, Lb8/j;->g:Lt7/n0;

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-virtual {p1, p2, v1, v2}, Lt7/p0;->f(ILt7/n0;Z)Lt7/n0;

    .line 20
    .line 21
    .line 22
    iget p2, v1, Lt7/n0;->c:I

    .line 23
    .line 24
    iget-object v1, p0, Lb8/j;->f:Lt7/o0;

    .line 25
    .line 26
    invoke-virtual {p1, p2, v1}, Lt7/p0;->n(ILt7/o0;)V

    .line 27
    .line 28
    .line 29
    iget-object p1, v1, Lt7/o0;->c:Lt7/x;

    .line 30
    .line 31
    iget-object p1, p1, Lt7/x;->b:Lt7/u;

    .line 32
    .line 33
    const/4 p2, 0x2

    .line 34
    const/4 v3, 0x1

    .line 35
    if-nez p1, :cond_2

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_2
    iget-object v2, p1, Lt7/u;->a:Landroid/net/Uri;

    .line 39
    .line 40
    iget-object p1, p1, Lt7/u;->b:Ljava/lang/String;

    .line 41
    .line 42
    invoke-static {v2, p1}, Lw7/w;->x(Landroid/net/Uri;Ljava/lang/String;)I

    .line 43
    .line 44
    .line 45
    move-result p1

    .line 46
    if-eqz p1, :cond_5

    .line 47
    .line 48
    if-eq p1, v3, :cond_4

    .line 49
    .line 50
    if-eq p1, p2, :cond_3

    .line 51
    .line 52
    move v2, v3

    .line 53
    goto :goto_1

    .line 54
    :cond_3
    const/4 v2, 0x4

    .line 55
    goto :goto_1

    .line 56
    :cond_4
    const/4 v2, 0x5

    .line 57
    goto :goto_1

    .line 58
    :cond_5
    const/4 v2, 0x3

    .line 59
    :goto_1
    invoke-static {v0, v2}, Lb8/h;->z(Landroid/media/metrics/PlaybackMetrics$Builder;I)V

    .line 60
    .line 61
    .line 62
    iget-wide v4, v1, Lt7/o0;->l:J

    .line 63
    .line 64
    const-wide v6, -0x7fffffffffffffffL    # -4.9E-324

    .line 65
    .line 66
    .line 67
    .line 68
    .line 69
    cmp-long p1, v4, v6

    .line 70
    .line 71
    if-eqz p1, :cond_6

    .line 72
    .line 73
    iget-boolean p1, v1, Lt7/o0;->j:Z

    .line 74
    .line 75
    if-nez p1, :cond_6

    .line 76
    .line 77
    iget-boolean p1, v1, Lt7/o0;->h:Z

    .line 78
    .line 79
    if-nez p1, :cond_6

    .line 80
    .line 81
    invoke-virtual {v1}, Lt7/o0;->a()Z

    .line 82
    .line 83
    .line 84
    move-result p1

    .line 85
    if-nez p1, :cond_6

    .line 86
    .line 87
    iget-wide v4, v1, Lt7/o0;->l:J

    .line 88
    .line 89
    invoke-static {v4, v5}, Lw7/w;->N(J)J

    .line 90
    .line 91
    .line 92
    move-result-wide v4

    .line 93
    invoke-static {v0, v4, v5}, Lb8/h;->A(Landroid/media/metrics/PlaybackMetrics$Builder;J)V

    .line 94
    .line 95
    .line 96
    :cond_6
    invoke-virtual {v1}, Lt7/o0;->a()Z

    .line 97
    .line 98
    .line 99
    move-result p1

    .line 100
    if-eqz p1, :cond_7

    .line 101
    .line 102
    goto :goto_2

    .line 103
    :cond_7
    move p2, v3

    .line 104
    :goto_2
    invoke-static {v0, p2}, Lb8/h;->D(Landroid/media/metrics/PlaybackMetrics$Builder;I)V

    .line 105
    .line 106
    .line 107
    iput-boolean v3, p0, Lb8/j;->B:Z

    .line 108
    .line 109
    return-void
.end method

.method public final d(Lb8/a;Ljava/lang/String;)V
    .locals 0

    .line 1
    iget-object p1, p1, Lb8/a;->d:Lh8/b0;

    .line 2
    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    invoke-virtual {p1}, Lh8/b0;->b()Z

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    if-nez p1, :cond_2

    .line 10
    .line 11
    :cond_0
    iget-object p1, p0, Lb8/j;->j:Ljava/lang/String;

    .line 12
    .line 13
    invoke-virtual {p2, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    if-nez p1, :cond_1

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_1
    invoke-virtual {p0}, Lb8/j;->b()V

    .line 21
    .line 22
    .line 23
    :cond_2
    :goto_0
    iget-object p1, p0, Lb8/j;->h:Ljava/util/HashMap;

    .line 24
    .line 25
    invoke-virtual {p1, p2}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    iget-object p0, p0, Lb8/j;->i:Ljava/util/HashMap;

    .line 29
    .line 30
    invoke-virtual {p0, p2}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    return-void
.end method

.method public final e(IJLt7/o;)V
    .locals 3

    .line 1
    invoke-static {p1}, Lb8/h;->k(I)Landroid/media/metrics/TrackChangeEvent$Builder;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    iget-wide v0, p0, Lb8/j;->e:J

    .line 6
    .line 7
    sub-long/2addr p2, v0

    .line 8
    invoke-static {p1, p2, p3}, La6/c;->l(Landroid/media/metrics/TrackChangeEvent$Builder;J)Landroid/media/metrics/TrackChangeEvent$Builder;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    const/4 p2, 0x1

    .line 13
    if-eqz p4, :cond_a

    .line 14
    .line 15
    invoke-static {p1}, Lb8/h;->B(Landroid/media/metrics/TrackChangeEvent$Builder;)V

    .line 16
    .line 17
    .line 18
    const/4 p3, 0x2

    .line 19
    invoke-static {p1, p3}, La6/c;->q(Landroid/media/metrics/TrackChangeEvent$Builder;I)V

    .line 20
    .line 21
    .line 22
    iget-object v0, p4, Lt7/o;->m:Ljava/lang/String;

    .line 23
    .line 24
    if-eqz v0, :cond_0

    .line 25
    .line 26
    invoke-static {p1, v0}, La6/c;->r(Landroid/media/metrics/TrackChangeEvent$Builder;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    :cond_0
    iget-object v0, p4, Lt7/o;->n:Ljava/lang/String;

    .line 30
    .line 31
    if-eqz v0, :cond_1

    .line 32
    .line 33
    invoke-static {p1, v0}, La6/c;->x(Landroid/media/metrics/TrackChangeEvent$Builder;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    :cond_1
    iget-object v0, p4, Lt7/o;->k:Ljava/lang/String;

    .line 37
    .line 38
    if-eqz v0, :cond_2

    .line 39
    .line 40
    invoke-static {p1, v0}, La6/c;->A(Landroid/media/metrics/TrackChangeEvent$Builder;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    :cond_2
    iget v0, p4, Lt7/o;->j:I

    .line 44
    .line 45
    const/4 v1, -0x1

    .line 46
    if-eq v0, v1, :cond_3

    .line 47
    .line 48
    invoke-static {p1, v0}, La6/c;->w(Landroid/media/metrics/TrackChangeEvent$Builder;I)V

    .line 49
    .line 50
    .line 51
    :cond_3
    iget v0, p4, Lt7/o;->u:I

    .line 52
    .line 53
    if-eq v0, v1, :cond_4

    .line 54
    .line 55
    invoke-static {p1, v0}, La6/c;->z(Landroid/media/metrics/TrackChangeEvent$Builder;I)V

    .line 56
    .line 57
    .line 58
    :cond_4
    iget v0, p4, Lt7/o;->v:I

    .line 59
    .line 60
    if-eq v0, v1, :cond_5

    .line 61
    .line 62
    invoke-static {p1, v0}, La6/c;->C(Landroid/media/metrics/TrackChangeEvent$Builder;I)V

    .line 63
    .line 64
    .line 65
    :cond_5
    iget v0, p4, Lt7/o;->F:I

    .line 66
    .line 67
    if-eq v0, v1, :cond_6

    .line 68
    .line 69
    invoke-static {p1, v0}, La6/c;->D(Landroid/media/metrics/TrackChangeEvent$Builder;I)V

    .line 70
    .line 71
    .line 72
    :cond_6
    iget v0, p4, Lt7/o;->G:I

    .line 73
    .line 74
    if-eq v0, v1, :cond_7

    .line 75
    .line 76
    invoke-static {p1, v0}, Lb8/h;->w(Landroid/media/metrics/TrackChangeEvent$Builder;I)V

    .line 77
    .line 78
    .line 79
    :cond_7
    iget-object v0, p4, Lt7/o;->d:Ljava/lang/String;

    .line 80
    .line 81
    if-eqz v0, :cond_9

    .line 82
    .line 83
    sget-object v2, Lw7/w;->a:Ljava/lang/String;

    .line 84
    .line 85
    const-string v2, "-"

    .line 86
    .line 87
    invoke-virtual {v0, v2, v1}, Ljava/lang/String;->split(Ljava/lang/String;I)[Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v0

    .line 91
    const/4 v1, 0x0

    .line 92
    aget-object v1, v0, v1

    .line 93
    .line 94
    array-length v2, v0

    .line 95
    if-lt v2, p3, :cond_8

    .line 96
    .line 97
    aget-object p3, v0, p2

    .line 98
    .line 99
    goto :goto_0

    .line 100
    :cond_8
    const/4 p3, 0x0

    .line 101
    :goto_0
    invoke-static {v1, p3}, Landroid/util/Pair;->create(Ljava/lang/Object;Ljava/lang/Object;)Landroid/util/Pair;

    .line 102
    .line 103
    .line 104
    move-result-object p3

    .line 105
    iget-object v0, p3, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 106
    .line 107
    check-cast v0, Ljava/lang/String;

    .line 108
    .line 109
    invoke-static {p1, v0}, Lb8/h;->x(Landroid/media/metrics/TrackChangeEvent$Builder;Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    iget-object p3, p3, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 113
    .line 114
    if-eqz p3, :cond_9

    .line 115
    .line 116
    check-cast p3, Ljava/lang/String;

    .line 117
    .line 118
    invoke-static {p1, p3}, Lb8/h;->C(Landroid/media/metrics/TrackChangeEvent$Builder;Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    :cond_9
    iget p3, p4, Lt7/o;->y:F

    .line 122
    .line 123
    const/high16 p4, -0x40800000    # -1.0f

    .line 124
    .line 125
    cmpl-float p4, p3, p4

    .line 126
    .line 127
    if-eqz p4, :cond_b

    .line 128
    .line 129
    invoke-static {p1, p3}, Lb8/h;->v(Landroid/media/metrics/TrackChangeEvent$Builder;F)V

    .line 130
    .line 131
    .line 132
    goto :goto_1

    .line 133
    :cond_a
    invoke-static {p1}, Lb8/h;->u(Landroid/media/metrics/TrackChangeEvent$Builder;)V

    .line 134
    .line 135
    .line 136
    :cond_b
    :goto_1
    iput-boolean p2, p0, Lb8/j;->B:Z

    .line 137
    .line 138
    invoke-static {p1}, Lb8/h;->l(Landroid/media/metrics/TrackChangeEvent$Builder;)Landroid/media/metrics/TrackChangeEvent;

    .line 139
    .line 140
    .line 141
    move-result-object p1

    .line 142
    new-instance p2, La8/z;

    .line 143
    .line 144
    const/16 p3, 0x9

    .line 145
    .line 146
    invoke-direct {p2, p3, p0, p1}, La8/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 147
    .line 148
    .line 149
    iget-object p0, p0, Lb8/j;->b:Ljava/util/concurrent/Executor;

    .line 150
    .line 151
    invoke-interface {p0, p2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 152
    .line 153
    .line 154
    return-void
.end method
