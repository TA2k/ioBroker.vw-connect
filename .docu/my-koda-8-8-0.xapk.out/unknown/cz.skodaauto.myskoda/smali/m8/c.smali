.class public final Lm8/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lm8/i0;


# instance fields
.field public final a:Lm8/y;

.field public final b:Lm8/d0;

.field public final c:Ljava/util/ArrayDeque;

.field public d:Landroid/view/Surface;

.field public e:Lt7/o;

.field public f:J

.field public g:Lm8/g0;

.field public h:Ljava/util/concurrent/Executor;

.field public i:Lm8/x;


# direct methods
.method public constructor <init>(Lm8/y;Lw7/r;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lm8/c;->a:Lm8/y;

    .line 5
    .line 6
    iput-object p2, p1, Lm8/y;->l:Lw7/r;

    .line 7
    .line 8
    new-instance p2, Lm8/d0;

    .line 9
    .line 10
    new-instance v0, Lb81/a;

    .line 11
    .line 12
    const/16 v1, 0x11

    .line 13
    .line 14
    invoke-direct {v0, p0, v1}, Lb81/a;-><init>(Ljava/lang/Object;I)V

    .line 15
    .line 16
    .line 17
    invoke-direct {p2, v0, p1}, Lm8/d0;-><init>(Lb81/a;Lm8/y;)V

    .line 18
    .line 19
    .line 20
    iput-object p2, p0, Lm8/c;->b:Lm8/d0;

    .line 21
    .line 22
    new-instance p1, Ljava/util/ArrayDeque;

    .line 23
    .line 24
    invoke-direct {p1}, Ljava/util/ArrayDeque;-><init>()V

    .line 25
    .line 26
    .line 27
    iput-object p1, p0, Lm8/c;->c:Ljava/util/ArrayDeque;

    .line 28
    .line 29
    new-instance p1, Lt7/n;

    .line 30
    .line 31
    invoke-direct {p1}, Lt7/n;-><init>()V

    .line 32
    .line 33
    .line 34
    new-instance p2, Lt7/o;

    .line 35
    .line 36
    invoke-direct {p2, p1}, Lt7/o;-><init>(Lt7/n;)V

    .line 37
    .line 38
    .line 39
    iput-object p2, p0, Lm8/c;->e:Lt7/o;

    .line 40
    .line 41
    const-wide p1, -0x7fffffffffffffffL    # -4.9E-324

    .line 42
    .line 43
    .line 44
    .line 45
    .line 46
    iput-wide p1, p0, Lm8/c;->f:J

    .line 47
    .line 48
    sget-object p1, Lm8/g0;->a:Lm8/f0;

    .line 49
    .line 50
    iput-object p1, p0, Lm8/c;->g:Lm8/g0;

    .line 51
    .line 52
    new-instance p1, Lha/c;

    .line 53
    .line 54
    const/4 p2, 0x1

    .line 55
    invoke-direct {p1, p2}, Lha/c;-><init>(I)V

    .line 56
    .line 57
    .line 58
    iput-object p1, p0, Lm8/c;->h:Ljava/util/concurrent/Executor;

    .line 59
    .line 60
    new-instance p1, Lm8/a;

    .line 61
    .line 62
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 63
    .line 64
    .line 65
    iput-object p1, p0, Lm8/c;->i:Lm8/x;

    .line 66
    .line 67
    return-void
.end method


# virtual methods
.method public final b()V
    .locals 0

    .line 1
    return-void
.end method

.method public final c()Z
    .locals 4

    .line 1
    iget-object p0, p0, Lm8/c;->b:Lm8/d0;

    .line 2
    .line 3
    iget-wide v0, p0, Lm8/d0;->i:J

    .line 4
    .line 5
    const-wide v2, -0x7fffffffffffffffL    # -4.9E-324

    .line 6
    .line 7
    .line 8
    .line 9
    .line 10
    cmp-long v2, v0, v2

    .line 11
    .line 12
    if-eqz v2, :cond_0

    .line 13
    .line 14
    iget-wide v2, p0, Lm8/d0;->h:J

    .line 15
    .line 16
    cmp-long p0, v2, v0

    .line 17
    .line 18
    if-nez p0, :cond_0

    .line 19
    .line 20
    const/4 p0, 0x1

    .line 21
    return p0

    .line 22
    :cond_0
    const/4 p0, 0x0

    .line 23
    return p0
.end method

.method public final d(J)V
    .locals 0

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 4
    .line 5
    .line 6
    throw p0
.end method

.method public final e()V
    .locals 4

    .line 1
    iget-object p0, p0, Lm8/c;->b:Lm8/d0;

    .line 2
    .line 3
    iget-wide v0, p0, Lm8/d0;->g:J

    .line 4
    .line 5
    const-wide v2, -0x7fffffffffffffffL    # -4.9E-324

    .line 6
    .line 7
    .line 8
    .line 9
    .line 10
    cmp-long v0, v0, v2

    .line 11
    .line 12
    if-nez v0, :cond_0

    .line 13
    .line 14
    const-wide/high16 v0, -0x8000000000000000L

    .line 15
    .line 16
    iput-wide v0, p0, Lm8/d0;->g:J

    .line 17
    .line 18
    iput-wide v0, p0, Lm8/d0;->h:J

    .line 19
    .line 20
    :cond_0
    iget-wide v0, p0, Lm8/d0;->g:J

    .line 21
    .line 22
    iput-wide v0, p0, Lm8/d0;->i:J

    .line 23
    .line 24
    return-void
.end method

.method public final f(Ljava/util/List;)V
    .locals 0

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 4
    .line 5
    .line 6
    throw p0
.end method

.method public final g(Z)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lm8/c;->a:Lm8/y;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lm8/y;->b(Z)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final h()V
    .locals 0

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 4
    .line 5
    .line 6
    throw p0
.end method

.method public final i(JLm8/h;)Z
    .locals 8

    .line 1
    iget-object v0, p0, Lm8/c;->c:Ljava/util/ArrayDeque;

    .line 2
    .line 3
    invoke-virtual {v0, p3}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    iget-object p3, p0, Lm8/c;->b:Lm8/d0;

    .line 7
    .line 8
    iget-object v0, p3, Lm8/d0;->f:Lcom/google/android/material/datepicker/w;

    .line 9
    .line 10
    iget v1, v0, Lcom/google/android/material/datepicker/w;->g:I

    .line 11
    .line 12
    iget-object v2, v0, Lcom/google/android/material/datepicker/w;->i:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v2, [J

    .line 15
    .line 16
    array-length v3, v2

    .line 17
    const/4 v4, 0x1

    .line 18
    if-ne v1, v3, :cond_1

    .line 19
    .line 20
    array-length v1, v2

    .line 21
    shl-int/2addr v1, v4

    .line 22
    if-ltz v1, :cond_0

    .line 23
    .line 24
    new-array v3, v1, [J

    .line 25
    .line 26
    array-length v5, v2

    .line 27
    iget v6, v0, Lcom/google/android/material/datepicker/w;->e:I

    .line 28
    .line 29
    sub-int/2addr v5, v6

    .line 30
    const/4 v7, 0x0

    .line 31
    invoke-static {v2, v6, v3, v7, v5}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 32
    .line 33
    .line 34
    iget-object v2, v0, Lcom/google/android/material/datepicker/w;->i:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v2, [J

    .line 37
    .line 38
    invoke-static {v2, v7, v3, v5, v6}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 39
    .line 40
    .line 41
    iput v7, v0, Lcom/google/android/material/datepicker/w;->e:I

    .line 42
    .line 43
    iget v2, v0, Lcom/google/android/material/datepicker/w;->g:I

    .line 44
    .line 45
    sub-int/2addr v2, v4

    .line 46
    iput v2, v0, Lcom/google/android/material/datepicker/w;->f:I

    .line 47
    .line 48
    iput-object v3, v0, Lcom/google/android/material/datepicker/w;->i:Ljava/lang/Object;

    .line 49
    .line 50
    sub-int/2addr v1, v4

    .line 51
    iput v1, v0, Lcom/google/android/material/datepicker/w;->h:I

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 55
    .line 56
    invoke-direct {p0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 57
    .line 58
    .line 59
    throw p0

    .line 60
    :cond_1
    :goto_0
    iget v1, v0, Lcom/google/android/material/datepicker/w;->f:I

    .line 61
    .line 62
    add-int/2addr v1, v4

    .line 63
    iget v2, v0, Lcom/google/android/material/datepicker/w;->h:I

    .line 64
    .line 65
    and-int/2addr v1, v2

    .line 66
    iput v1, v0, Lcom/google/android/material/datepicker/w;->f:I

    .line 67
    .line 68
    iget-object v2, v0, Lcom/google/android/material/datepicker/w;->i:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast v2, [J

    .line 71
    .line 72
    aput-wide p1, v2, v1

    .line 73
    .line 74
    iget v1, v0, Lcom/google/android/material/datepicker/w;->g:I

    .line 75
    .line 76
    add-int/2addr v1, v4

    .line 77
    iput v1, v0, Lcom/google/android/material/datepicker/w;->g:I

    .line 78
    .line 79
    iput-wide p1, p3, Lm8/d0;->g:J

    .line 80
    .line 81
    const-wide p1, -0x7fffffffffffffffL    # -4.9E-324

    .line 82
    .line 83
    .line 84
    .line 85
    .line 86
    iput-wide p1, p3, Lm8/d0;->i:J

    .line 87
    .line 88
    iget-object p1, p0, Lm8/c;->h:Ljava/util/concurrent/Executor;

    .line 89
    .line 90
    new-instance p2, La0/d;

    .line 91
    .line 92
    const/16 p3, 0x1d

    .line 93
    .line 94
    invoke-direct {p2, p0, p3}, La0/d;-><init>(Ljava/lang/Object;I)V

    .line 95
    .line 96
    .line 97
    invoke-interface {p1, p2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 98
    .line 99
    .line 100
    return v4
.end method

.method public final isInitialized()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final j(Lt7/o;)Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final k()V
    .locals 1

    .line 1
    iget-object p0, p0, Lm8/c;->a:Lm8/y;

    .line 2
    .line 3
    iget v0, p0, Lm8/y;->e:I

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    iput v0, p0, Lm8/y;->e:I

    .line 9
    .line 10
    :cond_0
    return-void
.end method

.method public final l()Landroid/view/Surface;
    .locals 0

    .line 1
    iget-object p0, p0, Lm8/c;->d:Landroid/view/Surface;

    .line 2
    .line 3
    invoke-static {p0}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public final m()V
    .locals 0

    .line 1
    iget-object p0, p0, Lm8/c;->a:Lm8/y;

    .line 2
    .line 3
    invoke-virtual {p0}, Lm8/y;->e()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final n(Lm8/x;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lm8/c;->i:Lm8/x;

    .line 2
    .line 3
    return-void
.end method

.method public final o()V
    .locals 0

    .line 1
    iget-object p0, p0, Lm8/c;->a:Lm8/y;

    .line 2
    .line 3
    invoke-virtual {p0}, Lm8/y;->d()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final p(I)V
    .locals 1

    .line 1
    iget-object p0, p0, Lm8/c;->a:Lm8/y;

    .line 2
    .line 3
    iget-object p0, p0, Lm8/y;->b:Lm8/c0;

    .line 4
    .line 5
    iget v0, p0, Lm8/c0;->j:I

    .line 6
    .line 7
    if-ne v0, p1, :cond_0

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    iput p1, p0, Lm8/c0;->j:I

    .line 11
    .line 12
    const/4 p1, 0x1

    .line 13
    invoke-virtual {p0, p1}, Lm8/c0;->d(Z)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public final q(F)V
    .locals 0

    .line 1
    iget-object p0, p0, Lm8/c;->a:Lm8/y;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lm8/y;->i(F)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final r()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Lm8/c;->d:Landroid/view/Surface;

    .line 3
    .line 4
    iget-object p0, p0, Lm8/c;->a:Lm8/y;

    .line 5
    .line 6
    invoke-virtual {p0, v0}, Lm8/y;->h(Landroid/view/Surface;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public final s(Landroid/view/Surface;Lw7/q;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lm8/c;->d:Landroid/view/Surface;

    .line 2
    .line 3
    iget-object p0, p0, Lm8/c;->a:Lm8/y;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lm8/y;->h(Landroid/view/Surface;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final t(Z)V
    .locals 9

    .line 1
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 2
    .line 3
    .line 4
    .line 5
    .line 6
    const-wide/16 v2, 0x0

    .line 7
    .line 8
    const/4 v4, 0x1

    .line 9
    if-eqz p1, :cond_0

    .line 10
    .line 11
    iget-object p1, p0, Lm8/c;->a:Lm8/y;

    .line 12
    .line 13
    iget-object v5, p1, Lm8/y;->b:Lm8/c0;

    .line 14
    .line 15
    iput-wide v2, v5, Lm8/c0;->m:J

    .line 16
    .line 17
    const-wide/16 v6, -0x1

    .line 18
    .line 19
    iput-wide v6, v5, Lm8/c0;->p:J

    .line 20
    .line 21
    iput-wide v6, v5, Lm8/c0;->n:J

    .line 22
    .line 23
    iput-wide v0, p1, Lm8/y;->h:J

    .line 24
    .line 25
    iput-wide v0, p1, Lm8/y;->f:J

    .line 26
    .line 27
    iget v5, p1, Lm8/y;->e:I

    .line 28
    .line 29
    invoke-static {v5, v4}, Ljava/lang/Math;->min(II)I

    .line 30
    .line 31
    .line 32
    move-result v5

    .line 33
    iput v5, p1, Lm8/y;->e:I

    .line 34
    .line 35
    iput-wide v0, p1, Lm8/y;->i:J

    .line 36
    .line 37
    :cond_0
    iget-object p1, p0, Lm8/c;->b:Lm8/d0;

    .line 38
    .line 39
    iget-object v5, p1, Lm8/d0;->d:Li4/c;

    .line 40
    .line 41
    iget-object v6, p1, Lm8/d0;->f:Lcom/google/android/material/datepicker/w;

    .line 42
    .line 43
    const/4 v7, 0x0

    .line 44
    iput v7, v6, Lcom/google/android/material/datepicker/w;->e:I

    .line 45
    .line 46
    const/4 v8, -0x1

    .line 47
    iput v8, v6, Lcom/google/android/material/datepicker/w;->f:I

    .line 48
    .line 49
    iput v7, v6, Lcom/google/android/material/datepicker/w;->g:I

    .line 50
    .line 51
    iput-wide v0, p1, Lm8/d0;->g:J

    .line 52
    .line 53
    iput-wide v0, p1, Lm8/d0;->h:J

    .line 54
    .line 55
    iput-wide v0, p1, Lm8/d0;->i:J

    .line 56
    .line 57
    iget-object v0, p1, Lm8/d0;->e:Li4/c;

    .line 58
    .line 59
    invoke-virtual {v0}, Li4/c;->P()I

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    if-lez v1, :cond_3

    .line 64
    .line 65
    invoke-virtual {v0}, Li4/c;->P()I

    .line 66
    .line 67
    .line 68
    move-result v1

    .line 69
    if-lez v1, :cond_1

    .line 70
    .line 71
    move v1, v4

    .line 72
    goto :goto_0

    .line 73
    :cond_1
    move v1, v7

    .line 74
    :goto_0
    invoke-static {v1}, Lw7/a;->c(Z)V

    .line 75
    .line 76
    .line 77
    :goto_1
    invoke-virtual {v0}, Li4/c;->P()I

    .line 78
    .line 79
    .line 80
    move-result v1

    .line 81
    if-le v1, v4, :cond_2

    .line 82
    .line 83
    invoke-virtual {v0}, Li4/c;->J()Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    goto :goto_1

    .line 87
    :cond_2
    invoke-virtual {v0}, Li4/c;->J()Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v0

    .line 91
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 92
    .line 93
    .line 94
    check-cast v0, Ljava/lang/Long;

    .line 95
    .line 96
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 97
    .line 98
    .line 99
    move-result-wide v0

    .line 100
    iput-wide v0, p1, Lm8/d0;->k:J

    .line 101
    .line 102
    :cond_3
    invoke-virtual {v5}, Li4/c;->P()I

    .line 103
    .line 104
    .line 105
    move-result p1

    .line 106
    if-lez p1, :cond_6

    .line 107
    .line 108
    invoke-virtual {v5}, Li4/c;->P()I

    .line 109
    .line 110
    .line 111
    move-result p1

    .line 112
    if-lez p1, :cond_4

    .line 113
    .line 114
    move v7, v4

    .line 115
    :cond_4
    invoke-static {v7}, Lw7/a;->c(Z)V

    .line 116
    .line 117
    .line 118
    :goto_2
    invoke-virtual {v5}, Li4/c;->P()I

    .line 119
    .line 120
    .line 121
    move-result p1

    .line 122
    if-le p1, v4, :cond_5

    .line 123
    .line 124
    invoke-virtual {v5}, Li4/c;->J()Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    goto :goto_2

    .line 128
    :cond_5
    invoke-virtual {v5}, Li4/c;->J()Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object p1

    .line 132
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 133
    .line 134
    .line 135
    check-cast p1, Lt7/a1;

    .line 136
    .line 137
    invoke-virtual {v5, v2, v3, p1}, Li4/c;->f(JLjava/lang/Object;)V

    .line 138
    .line 139
    .line 140
    :cond_6
    iget-object p0, p0, Lm8/c;->c:Ljava/util/ArrayDeque;

    .line 141
    .line 142
    invoke-virtual {p0}, Ljava/util/ArrayDeque;->clear()V

    .line 143
    .line 144
    .line 145
    return-void
.end method

.method public final u(Lt7/o;JILjava/util/List;)V
    .locals 10

    .line 1
    invoke-interface {p5}, Ljava/util/List;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result p5

    .line 5
    invoke-static {p5}, Lw7/a;->j(Z)V

    .line 6
    .line 7
    .line 8
    iget p5, p1, Lt7/o;->u:I

    .line 9
    .line 10
    iget v0, p1, Lt7/o;->v:I

    .line 11
    .line 12
    iget-object v1, p0, Lm8/c;->e:Lt7/o;

    .line 13
    .line 14
    iget v2, v1, Lt7/o;->u:I

    .line 15
    .line 16
    const-wide/16 v3, 0x1

    .line 17
    .line 18
    const-wide v5, -0x7fffffffffffffffL    # -4.9E-324

    .line 19
    .line 20
    .line 21
    .line 22
    .line 23
    iget-object v7, p0, Lm8/c;->b:Lm8/d0;

    .line 24
    .line 25
    if-ne p5, v2, :cond_0

    .line 26
    .line 27
    iget v1, v1, Lt7/o;->v:I

    .line 28
    .line 29
    if-eq v0, v1, :cond_2

    .line 30
    .line 31
    :cond_0
    iget-object v1, v7, Lm8/d0;->d:Li4/c;

    .line 32
    .line 33
    iget-wide v8, v7, Lm8/d0;->g:J

    .line 34
    .line 35
    cmp-long v2, v8, v5

    .line 36
    .line 37
    if-nez v2, :cond_1

    .line 38
    .line 39
    const-wide/16 v8, 0x0

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_1
    add-long/2addr v8, v3

    .line 43
    :goto_0
    new-instance v2, Lt7/a1;

    .line 44
    .line 45
    invoke-direct {v2, p5, v0}, Lt7/a1;-><init>(II)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {v1, v8, v9, v2}, Li4/c;->f(JLjava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    :cond_2
    iget p5, p1, Lt7/o;->y:F

    .line 52
    .line 53
    iget-object v0, p0, Lm8/c;->e:Lt7/o;

    .line 54
    .line 55
    iget v0, v0, Lt7/o;->y:F

    .line 56
    .line 57
    cmpl-float v0, p5, v0

    .line 58
    .line 59
    if-eqz v0, :cond_3

    .line 60
    .line 61
    iget-object v0, p0, Lm8/c;->a:Lm8/y;

    .line 62
    .line 63
    invoke-virtual {v0, p5}, Lm8/y;->g(F)V

    .line 64
    .line 65
    .line 66
    :cond_3
    iput-object p1, p0, Lm8/c;->e:Lt7/o;

    .line 67
    .line 68
    iget-wide v0, p0, Lm8/c;->f:J

    .line 69
    .line 70
    cmp-long p1, p2, v0

    .line 71
    .line 72
    if-eqz p1, :cond_6

    .line 73
    .line 74
    iget-object p1, v7, Lm8/d0;->f:Lcom/google/android/material/datepicker/w;

    .line 75
    .line 76
    iget p1, p1, Lcom/google/android/material/datepicker/w;->g:I

    .line 77
    .line 78
    if-nez p1, :cond_4

    .line 79
    .line 80
    iget-object p1, v7, Lm8/d0;->b:Lm8/y;

    .line 81
    .line 82
    invoke-virtual {p1, p4}, Lm8/y;->f(I)V

    .line 83
    .line 84
    .line 85
    iput-wide p2, v7, Lm8/d0;->k:J

    .line 86
    .line 87
    goto :goto_2

    .line 88
    :cond_4
    iget-object p1, v7, Lm8/d0;->e:Li4/c;

    .line 89
    .line 90
    iget-wide p4, v7, Lm8/d0;->g:J

    .line 91
    .line 92
    cmp-long v0, p4, v5

    .line 93
    .line 94
    if-nez v0, :cond_5

    .line 95
    .line 96
    const-wide/high16 p4, -0x4000000000000000L    # -2.0

    .line 97
    .line 98
    goto :goto_1

    .line 99
    :cond_5
    add-long/2addr p4, v3

    .line 100
    :goto_1
    invoke-static {p2, p3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 101
    .line 102
    .line 103
    move-result-object v0

    .line 104
    invoke-virtual {p1, p4, p5, v0}, Li4/c;->f(JLjava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    :goto_2
    iput-wide p2, p0, Lm8/c;->f:J

    .line 108
    .line 109
    :cond_6
    return-void
.end method

.method public final v(JJ)V
    .locals 1

    .line 1
    :try_start_0
    iget-object v0, p0, Lm8/c;->b:Lm8/d0;

    .line 2
    .line 3
    invoke-virtual {v0, p1, p2, p3, p4}, Lm8/d0;->a(JJ)V
    :try_end_0
    .catch La8/o; {:try_start_0 .. :try_end_0} :catch_0

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :catch_0
    move-exception p1

    .line 8
    new-instance p2, Lm8/h0;

    .line 9
    .line 10
    iget-object p0, p0, Lm8/c;->e:Lt7/o;

    .line 11
    .line 12
    invoke-direct {p2, p1, p0}, Lm8/h0;-><init>(Ljava/lang/Exception;Lt7/o;)V

    .line 13
    .line 14
    .line 15
    throw p2
.end method

.method public final w(Z)V
    .locals 0

    .line 1
    iget-object p0, p0, Lm8/c;->a:Lm8/y;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lm8/y;->c(Z)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final x(Lm8/g;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lm8/c;->g:Lm8/g0;

    .line 2
    .line 3
    sget-object p1, Llr/a;->d:Llr/a;

    .line 4
    .line 5
    iput-object p1, p0, Lm8/c;->h:Ljava/util/concurrent/Executor;

    .line 6
    .line 7
    return-void
.end method
