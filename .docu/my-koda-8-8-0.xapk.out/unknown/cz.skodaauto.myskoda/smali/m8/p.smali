.class public final Lm8/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lm8/i0;


# instance fields
.field public a:Lhr/h0;

.field public b:Lt7/o;

.field public c:J

.field public d:J

.field public e:Ljava/util/concurrent/Executor;

.field public final synthetic f:Lm8/t;


# direct methods
.method public constructor <init>(Lm8/t;Landroid/content/Context;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lm8/p;->f:Lm8/t;

    .line 5
    .line 6
    invoke-static {p2}, Lw7/w;->B(Landroid/content/Context;)Z

    .line 7
    .line 8
    .line 9
    sget-object p1, Lhr/h0;->e:Lhr/f0;

    .line 10
    .line 11
    sget-object p1, Lhr/x0;->h:Lhr/x0;

    .line 12
    .line 13
    iput-object p1, p0, Lm8/p;->a:Lhr/h0;

    .line 14
    .line 15
    const-wide p1, -0x7fffffffffffffffL    # -4.9E-324

    .line 16
    .line 17
    .line 18
    .line 19
    .line 20
    iput-wide p1, p0, Lm8/p;->d:J

    .line 21
    .line 22
    sget-object p1, Lm8/t;->o:Lha/c;

    .line 23
    .line 24
    iput-object p1, p0, Lm8/p;->e:Ljava/util/concurrent/Executor;

    .line 25
    .line 26
    return-void
.end method


# virtual methods
.method public final b()V
    .locals 3

    .line 1
    iget-object p0, p0, Lm8/p;->f:Lm8/t;

    .line 2
    .line 3
    iget v0, p0, Lm8/t;->l:I

    .line 4
    .line 5
    const/4 v1, 0x2

    .line 6
    if-ne v0, v1, :cond_0

    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    iget-object v0, p0, Lm8/t;->i:Lw7/t;

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    if-eqz v0, :cond_1

    .line 13
    .line 14
    iget-object v0, v0, Lw7/t;->a:Landroid/os/Handler;

    .line 15
    .line 16
    invoke-virtual {v0, v2}, Landroid/os/Handler;->removeCallbacksAndMessages(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    :cond_1
    iput-object v2, p0, Lm8/t;->j:Landroid/util/Pair;

    .line 20
    .line 21
    iput v1, p0, Lm8/t;->l:I

    .line 22
    .line 23
    return-void
.end method

.method public final c()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final d(J)V
    .locals 0

    .line 1
    iput-wide p1, p0, Lm8/p;->c:J

    .line 2
    .line 3
    return-void
.end method

.method public final e()V
    .locals 4

    .line 1
    iget-wide v0, p0, Lm8/p;->d:J

    .line 2
    .line 3
    iget-object p0, p0, Lm8/p;->f:Lm8/t;

    .line 4
    .line 5
    iget-wide v2, p0, Lm8/t;->m:J

    .line 6
    .line 7
    cmp-long v0, v2, v0

    .line 8
    .line 9
    if-ltz v0, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, Lm8/t;->e:Lm8/c;

    .line 12
    .line 13
    invoke-virtual {p0}, Lm8/c;->e()V

    .line 14
    .line 15
    .line 16
    :cond_0
    return-void
.end method

.method public final f(Ljava/util/List;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lm8/p;->a:Lhr/h0;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lhr/h0;->equals(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    invoke-static {p1}, Lhr/h0;->p(Ljava/util/Collection;)Lhr/h0;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    iput-object p1, p0, Lm8/p;->a:Lhr/h0;

    .line 15
    .line 16
    iget-object p0, p0, Lm8/p;->b:Lt7/o;

    .line 17
    .line 18
    if-nez p0, :cond_1

    .line 19
    .line 20
    :goto_0
    return-void

    .line 21
    :cond_1
    invoke-virtual {p0}, Lt7/o;->a()Lt7/n;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    iget-object p0, p0, Lt7/o;->D:Lt7/f;

    .line 26
    .line 27
    if-eqz p0, :cond_2

    .line 28
    .line 29
    invoke-virtual {p0}, Lt7/f;->d()Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-eqz v0, :cond_2

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_2
    sget-object p0, Lt7/f;->h:Lt7/f;

    .line 37
    .line 38
    :goto_1
    iput-object p0, p1, Lt7/n;->C:Lt7/f;

    .line 39
    .line 40
    invoke-virtual {p1}, Lt7/n;->a()Lt7/o;

    .line 41
    .line 42
    .line 43
    const/4 p0, 0x0

    .line 44
    throw p0
.end method

.method public final g(Z)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lm8/p;->f:Lm8/t;

    .line 2
    .line 3
    iget-object p0, p0, Lm8/t;->e:Lm8/c;

    .line 4
    .line 5
    const/4 p1, 0x0

    .line 6
    iget-object p0, p0, Lm8/c;->a:Lm8/y;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lm8/y;->b(Z)Z

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public final h()V
    .locals 0

    .line 1
    return-void
.end method

.method public final i(JLm8/h;)Z
    .locals 0

    .line 1
    const/4 p1, 0x0

    .line 2
    invoke-static {p1}, Lw7/a;->j(Z)V

    .line 3
    .line 4
    .line 5
    iget-object p0, p0, Lm8/p;->f:Lm8/t;

    .line 6
    .line 7
    iget p0, p0, Lm8/t;->n:I

    .line 8
    .line 9
    const/4 p2, -0x1

    .line 10
    if-eq p0, p2, :cond_1

    .line 11
    .line 12
    if-eqz p0, :cond_0

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    const/4 p0, 0x0

    .line 16
    throw p0

    .line 17
    :cond_1
    :goto_0
    return p1
.end method

.method public final isInitialized()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final j(Lt7/o;)Z
    .locals 9

    .line 1
    const-string v0, "Color transfer "

    .line 2
    .line 3
    iget-object p0, p0, Lm8/p;->f:Lm8/t;

    .line 4
    .line 5
    iget v1, p0, Lm8/t;->l:I

    .line 6
    .line 7
    const/4 v2, 0x1

    .line 8
    const/4 v3, 0x0

    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    move v1, v2

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move v1, v3

    .line 14
    :goto_0
    invoke-static {v1}, Lw7/a;->j(Z)V

    .line 15
    .line 16
    .line 17
    iget-object v1, p1, Lt7/o;->D:Lt7/f;

    .line 18
    .line 19
    if-eqz v1, :cond_1

    .line 20
    .line 21
    invoke-virtual {v1}, Lt7/f;->d()Z

    .line 22
    .line 23
    .line 24
    move-result v4

    .line 25
    if-eqz v4, :cond_1

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_1
    sget-object v1, Lt7/f;->h:Lt7/f;

    .line 29
    .line 30
    :goto_1
    iget v1, v1, Lt7/f;->c:I

    .line 31
    .line 32
    const-string v4, "EGL_EXT_gl_colorspace_bt2020_pq"

    .line 33
    .line 34
    const/16 v5, 0x21

    .line 35
    .line 36
    const/4 v6, 0x7

    .line 37
    if-ne v1, v6, :cond_4

    .line 38
    .line 39
    :try_start_0
    sget v7, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 40
    .line 41
    const/16 v8, 0x22

    .line 42
    .line 43
    if-ge v7, v8, :cond_4

    .line 44
    .line 45
    if-lt v7, v5, :cond_2

    .line 46
    .line 47
    invoke-static {v4}, Lw7/a;->u(Ljava/lang/String;)Z

    .line 48
    .line 49
    .line 50
    move-result v7

    .line 51
    if-eqz v7, :cond_2

    .line 52
    .line 53
    move v7, v2

    .line 54
    goto :goto_2

    .line 55
    :catch_0
    move-exception p0

    .line 56
    goto :goto_5

    .line 57
    :cond_2
    move v7, v3

    .line 58
    :goto_2
    if-nez v7, :cond_3

    .line 59
    .line 60
    goto :goto_3

    .line 61
    :cond_3
    new-instance p1, Lt7/f;

    .line 62
    .line 63
    goto :goto_6

    .line 64
    :cond_4
    :goto_3
    const/4 v7, 0x6

    .line 65
    if-ne v1, v7, :cond_6

    .line 66
    .line 67
    sget v6, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 68
    .line 69
    if-lt v6, v5, :cond_5

    .line 70
    .line 71
    invoke-static {v4}, Lw7/a;->u(Ljava/lang/String;)Z

    .line 72
    .line 73
    .line 74
    move-result v4

    .line 75
    if-eqz v4, :cond_5

    .line 76
    .line 77
    goto :goto_4

    .line 78
    :cond_5
    move v2, v3

    .line 79
    goto :goto_4

    .line 80
    :cond_6
    if-ne v1, v6, :cond_7

    .line 81
    .line 82
    const-string v2, "EGL_EXT_gl_colorspace_bt2020_hlg"

    .line 83
    .line 84
    invoke-static {v2}, Lw7/a;->u(Ljava/lang/String;)Z

    .line 85
    .line 86
    .line 87
    move-result v2

    .line 88
    :cond_7
    :goto_4
    if-nez v2, :cond_8

    .line 89
    .line 90
    const-string v2, "PlaybackVidGraphWrapper"

    .line 91
    .line 92
    sget-object v3, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 93
    .line 94
    new-instance v3, Ljava/lang/StringBuilder;

    .line 95
    .line 96
    invoke-direct {v3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    const-string v0, " is not supported. Falling back to OpenGl tone mapping."

    .line 103
    .line 104
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 105
    .line 106
    .line 107
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object v0

    .line 111
    invoke-static {v2, v0}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    sget-object p1, Lt7/f;->h:Lt7/f;
    :try_end_0
    .catch Lw7/h; {:try_start_0 .. :try_end_0} :catch_0

    .line 115
    .line 116
    goto :goto_6

    .line 117
    :goto_5
    new-instance v0, Lm8/h0;

    .line 118
    .line 119
    invoke-direct {v0, p0, p1}, Lm8/h0;-><init>(Ljava/lang/Exception;Lt7/o;)V

    .line 120
    .line 121
    .line 122
    throw v0

    .line 123
    :cond_8
    :goto_6
    iget-object p1, p0, Lm8/t;->f:Lw7/r;

    .line 124
    .line 125
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 126
    .line 127
    .line 128
    move-result-object v0

    .line 129
    invoke-static {v0}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 130
    .line 131
    .line 132
    const/4 v1, 0x0

    .line 133
    invoke-virtual {p1, v0, v1}, Lw7/r;->a(Landroid/os/Looper;Landroid/os/Handler$Callback;)Lw7/t;

    .line 134
    .line 135
    .line 136
    move-result-object p1

    .line 137
    iput-object p1, p0, Lm8/t;->i:Lw7/t;

    .line 138
    .line 139
    iget-object p0, p0, Lm8/t;->b:Lm8/r;

    .line 140
    .line 141
    invoke-virtual {p0}, Lm8/r;->a()V

    .line 142
    .line 143
    .line 144
    throw v1
.end method

.method public final k()V
    .locals 2

    .line 1
    iget-object p0, p0, Lm8/p;->f:Lm8/t;

    .line 2
    .line 3
    iget-object v0, p0, Lm8/t;->h:Li4/c;

    .line 4
    .line 5
    invoke-virtual {v0}, Li4/c;->P()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, Lm8/t;->e:Lm8/c;

    .line 12
    .line 13
    invoke-virtual {p0}, Lm8/c;->k()V

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :cond_0
    new-instance v0, Li4/c;

    .line 18
    .line 19
    invoke-direct {v0}, Li4/c;-><init>()V

    .line 20
    .line 21
    .line 22
    iget-object v1, p0, Lm8/t;->h:Li4/c;

    .line 23
    .line 24
    invoke-virtual {v1}, Li4/c;->P()I

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-gtz v1, :cond_1

    .line 29
    .line 30
    iput-object v0, p0, Lm8/t;->h:Li4/c;

    .line 31
    .line 32
    return-void

    .line 33
    :cond_1
    iget-object p0, p0, Lm8/t;->h:Li4/c;

    .line 34
    .line 35
    invoke-virtual {p0}, Li4/c;->J()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    check-cast p0, Lm8/s;

    .line 40
    .line 41
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    const/4 p0, 0x0

    .line 45
    throw p0
.end method

.method public final l()Landroid/view/Surface;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    invoke-static {p0}, Lw7/a;->j(Z)V

    .line 3
    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    throw p0
.end method

.method public final m()V
    .locals 1

    .line 1
    iget-object p0, p0, Lm8/p;->f:Lm8/t;

    .line 2
    .line 3
    iget-boolean v0, p0, Lm8/t;->d:Z

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Lm8/t;->e:Lm8/c;

    .line 8
    .line 9
    invoke-virtual {p0}, Lm8/c;->m()V

    .line 10
    .line 11
    .line 12
    :cond_0
    return-void
.end method

.method public final n(Lm8/x;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lm8/p;->f:Lm8/t;

    .line 2
    .line 3
    iget-object p0, p0, Lm8/t;->e:Lm8/c;

    .line 4
    .line 5
    iput-object p1, p0, Lm8/c;->i:Lm8/x;

    .line 6
    .line 7
    return-void
.end method

.method public final o()V
    .locals 1

    .line 1
    iget-object p0, p0, Lm8/p;->f:Lm8/t;

    .line 2
    .line 3
    iget-boolean v0, p0, Lm8/t;->d:Z

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Lm8/t;->e:Lm8/c;

    .line 8
    .line 9
    invoke-virtual {p0}, Lm8/c;->o()V

    .line 10
    .line 11
    .line 12
    :cond_0
    return-void
.end method

.method public final p(I)V
    .locals 0

    .line 1
    iget-object p0, p0, Lm8/p;->f:Lm8/t;

    .line 2
    .line 3
    iget-object p0, p0, Lm8/t;->e:Lm8/c;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lm8/c;->p(I)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final q(F)V
    .locals 0

    .line 1
    iget-object p0, p0, Lm8/p;->f:Lm8/t;

    .line 2
    .line 3
    iget-object p0, p0, Lm8/t;->e:Lm8/c;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lm8/c;->q(F)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final r()V
    .locals 1

    .line 1
    sget-object v0, Lw7/q;->c:Lw7/q;

    .line 2
    .line 3
    iget v0, v0, Lw7/q;->a:I

    .line 4
    .line 5
    iget-object p0, p0, Lm8/p;->f:Lm8/t;

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    iput-object v0, p0, Lm8/t;->j:Landroid/util/Pair;

    .line 9
    .line 10
    return-void
.end method

.method public final s(Landroid/view/Surface;Lw7/q;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lm8/p;->f:Lm8/t;

    .line 2
    .line 3
    iget-object v0, p0, Lm8/t;->j:Landroid/util/Pair;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object v0, v0, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v0, Landroid/view/Surface;

    .line 10
    .line 11
    invoke-virtual {v0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    iget-object v0, p0, Lm8/t;->j:Landroid/util/Pair;

    .line 18
    .line 19
    iget-object v0, v0, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v0, Lw7/q;

    .line 22
    .line 23
    invoke-virtual {v0, p2}, Lw7/q;->equals(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    return-void

    .line 30
    :cond_0
    invoke-static {p1, p2}, Landroid/util/Pair;->create(Ljava/lang/Object;Ljava/lang/Object;)Landroid/util/Pair;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    iput-object p1, p0, Lm8/t;->j:Landroid/util/Pair;

    .line 35
    .line 36
    iget p0, p2, Lw7/q;->a:I

    .line 37
    .line 38
    return-void
.end method

.method public final t(Z)V
    .locals 5

    .line 1
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 2
    .line 3
    .line 4
    .line 5
    .line 6
    iput-wide v0, p0, Lm8/p;->d:J

    .line 7
    .line 8
    iget-object p0, p0, Lm8/p;->f:Lm8/t;

    .line 9
    .line 10
    iget-object v2, p0, Lm8/t;->e:Lm8/c;

    .line 11
    .line 12
    iget v3, p0, Lm8/t;->l:I

    .line 13
    .line 14
    const/4 v4, 0x1

    .line 15
    if-ne v3, v4, :cond_2

    .line 16
    .line 17
    iget v3, p0, Lm8/t;->k:I

    .line 18
    .line 19
    add-int/2addr v3, v4

    .line 20
    iput v3, p0, Lm8/t;->k:I

    .line 21
    .line 22
    invoke-virtual {v2, p1}, Lm8/c;->t(Z)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, p0, Lm8/t;->h:Li4/c;

    .line 26
    .line 27
    invoke-virtual {p1}, Li4/c;->P()I

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    if-le p1, v4, :cond_0

    .line 32
    .line 33
    iget-object p1, p0, Lm8/t;->h:Li4/c;

    .line 34
    .line 35
    invoke-virtual {p1}, Li4/c;->J()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    iget-object p1, p0, Lm8/t;->h:Li4/c;

    .line 40
    .line 41
    invoke-virtual {p1}, Li4/c;->P()I

    .line 42
    .line 43
    .line 44
    move-result p1

    .line 45
    if-eq p1, v4, :cond_1

    .line 46
    .line 47
    iput-wide v0, p0, Lm8/t;->m:J

    .line 48
    .line 49
    iget-object p1, p0, Lm8/t;->i:Lw7/t;

    .line 50
    .line 51
    invoke-static {p1}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    new-instance v0, Lm8/o;

    .line 55
    .line 56
    const/4 v1, 0x0

    .line 57
    invoke-direct {v0, p0, v1}, Lm8/o;-><init>(Ljava/lang/Object;I)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {p1, v0}, Lw7/t;->c(Ljava/lang/Runnable;)Z

    .line 61
    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_1
    iget-object p0, p0, Lm8/t;->h:Li4/c;

    .line 65
    .line 66
    invoke-virtual {p0}, Li4/c;->J()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    check-cast p0, Lm8/s;

    .line 71
    .line 72
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 73
    .line 74
    .line 75
    const/4 p0, 0x0

    .line 76
    throw p0

    .line 77
    :cond_2
    :goto_1
    return-void
.end method

.method public final u(Lt7/o;JILjava/util/List;)V
    .locals 0

    .line 1
    const/4 p2, 0x0

    .line 2
    invoke-static {p2}, Lw7/a;->j(Z)V

    .line 3
    .line 4
    .line 5
    invoke-static {p5}, Lhr/h0;->p(Ljava/util/Collection;)Lhr/h0;

    .line 6
    .line 7
    .line 8
    move-result-object p2

    .line 9
    iput-object p2, p0, Lm8/p;->a:Lhr/h0;

    .line 10
    .line 11
    iput-object p1, p0, Lm8/p;->b:Lt7/o;

    .line 12
    .line 13
    invoke-virtual {p1}, Lt7/o;->a()Lt7/n;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    iget-object p1, p1, Lt7/o;->D:Lt7/f;

    .line 18
    .line 19
    if-eqz p1, :cond_0

    .line 20
    .line 21
    invoke-virtual {p1}, Lt7/f;->d()Z

    .line 22
    .line 23
    .line 24
    move-result p2

    .line 25
    if-eqz p2, :cond_0

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    sget-object p1, Lt7/f;->h:Lt7/f;

    .line 29
    .line 30
    :goto_0
    iput-object p1, p0, Lt7/n;->C:Lt7/f;

    .line 31
    .line 32
    invoke-virtual {p0}, Lt7/n;->a()Lt7/o;

    .line 33
    .line 34
    .line 35
    const/4 p0, 0x0

    .line 36
    throw p0
.end method

.method public final v(JJ)V
    .locals 2

    .line 1
    iget-wide v0, p0, Lm8/p;->c:J

    .line 2
    .line 3
    add-long/2addr p1, v0

    .line 4
    iget-object p0, p0, Lm8/p;->f:Lm8/t;

    .line 5
    .line 6
    iget-object p0, p0, Lm8/t;->e:Lm8/c;

    .line 7
    .line 8
    invoke-virtual {p0, p1, p2, p3, p4}, Lm8/c;->v(JJ)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final w(Z)V
    .locals 1

    .line 1
    iget-object p0, p0, Lm8/p;->f:Lm8/t;

    .line 2
    .line 3
    iget-boolean v0, p0, Lm8/t;->d:Z

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Lm8/t;->e:Lm8/c;

    .line 8
    .line 9
    invoke-virtual {p0, p1}, Lm8/c;->w(Z)V

    .line 10
    .line 11
    .line 12
    :cond_0
    return-void
.end method

.method public final x(Lm8/g;)V
    .locals 0

    .line 1
    sget-object p1, Llr/a;->d:Llr/a;

    .line 2
    .line 3
    iput-object p1, p0, Lm8/p;->e:Ljava/util/concurrent/Executor;

    .line 4
    .line 5
    return-void
.end method
