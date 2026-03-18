.class public final Lp3/i0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt4/c;
.implements Lkotlin/coroutines/Continuation;


# instance fields
.field public final synthetic d:Lp3/j0;

.field public final e:Lvy0/l;

.field public f:Lvy0/l;

.field public g:Lp3/l;

.field public final h:Lpx0/h;

.field public final synthetic i:Lp3/j0;


# direct methods
.method public constructor <init>(Lp3/j0;Lvy0/l;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lp3/i0;->i:Lp3/j0;

    .line 5
    .line 6
    iput-object p1, p0, Lp3/i0;->d:Lp3/j0;

    .line 7
    .line 8
    iput-object p2, p0, Lp3/i0;->e:Lvy0/l;

    .line 9
    .line 10
    sget-object p1, Lp3/l;->e:Lp3/l;

    .line 11
    .line 12
    iput-object p1, p0, Lp3/i0;->g:Lp3/l;

    .line 13
    .line 14
    sget-object p1, Lpx0/h;->d:Lpx0/h;

    .line 15
    .line 16
    iput-object p1, p0, Lp3/i0;->h:Lpx0/h;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final G0(J)J
    .locals 0

    .line 1
    iget-object p0, p0, Lp3/i0;->d:Lp3/j0;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2}, Lt4/c;->G0(J)J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    return-wide p0
.end method

.method public final Q(F)I
    .locals 0

    .line 1
    iget-object p0, p0, Lp3/i0;->d:Lp3/j0;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lt4/c;->Q(F)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final V(J)F
    .locals 0

    .line 1
    iget-object p0, p0, Lp3/i0;->d:Lp3/j0;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2}, Lt4/c;->V(J)F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final a()F
    .locals 0

    .line 1
    iget-object p0, p0, Lp3/i0;->d:Lp3/j0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lp3/j0;->a()F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    new-instance v0, Lvy0/l;

    .line 2
    .line 3
    invoke-static {p2}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    .line 6
    move-result-object p2

    .line 7
    const/4 v1, 0x1

    .line 8
    invoke-direct {v0, v1, p2}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Lvy0/l;->q()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lp3/i0;->g:Lp3/l;

    .line 15
    .line 16
    iput-object v0, p0, Lp3/i0;->f:Lvy0/l;

    .line 17
    .line 18
    invoke-virtual {v0}, Lvy0/l;->p()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 23
    .line 24
    return-object p0
.end method

.method public final d()J
    .locals 9

    .line 1
    iget-object p0, p0, Lp3/i0;->i:Lp3/j0;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    iget-object v0, v0, Lv3/h0;->C:Lw3/h2;

    .line 11
    .line 12
    invoke-interface {v0}, Lw3/h2;->d()J

    .line 13
    .line 14
    .line 15
    move-result-wide v0

    .line 16
    invoke-interface {p0, v0, v1}, Lt4/c;->G0(J)J

    .line 17
    .line 18
    .line 19
    move-result-wide v0

    .line 20
    iget-wide v2, p0, Lp3/j0;->B:J

    .line 21
    .line 22
    const/16 p0, 0x20

    .line 23
    .line 24
    shr-long v4, v0, p0

    .line 25
    .line 26
    long-to-int v4, v4

    .line 27
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    shr-long v5, v2, p0

    .line 32
    .line 33
    long-to-int v5, v5

    .line 34
    int-to-float v5, v5

    .line 35
    sub-float/2addr v4, v5

    .line 36
    const/4 v5, 0x0

    .line 37
    invoke-static {v5, v4}, Ljava/lang/Math;->max(FF)F

    .line 38
    .line 39
    .line 40
    move-result v4

    .line 41
    const/high16 v6, 0x40000000    # 2.0f

    .line 42
    .line 43
    div-float/2addr v4, v6

    .line 44
    const-wide v7, 0xffffffffL

    .line 45
    .line 46
    .line 47
    .line 48
    .line 49
    and-long/2addr v0, v7

    .line 50
    long-to-int v0, v0

    .line 51
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    and-long v1, v2, v7

    .line 56
    .line 57
    long-to-int v1, v1

    .line 58
    int-to-float v1, v1

    .line 59
    sub-float/2addr v0, v1

    .line 60
    invoke-static {v5, v0}, Ljava/lang/Math;->max(FF)F

    .line 61
    .line 62
    .line 63
    move-result v0

    .line 64
    div-float/2addr v0, v6

    .line 65
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 66
    .line 67
    .line 68
    move-result v1

    .line 69
    int-to-long v1, v1

    .line 70
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    int-to-long v3, v0

    .line 75
    shl-long v0, v1, p0

    .line 76
    .line 77
    and-long v2, v3, v7

    .line 78
    .line 79
    or-long/2addr v0, v2

    .line 80
    return-wide v0
.end method

.method public final f()Lw3/h2;
    .locals 0

    .line 1
    iget-object p0, p0, Lp3/i0;->i:Lp3/j0;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    iget-object p0, p0, Lv3/h0;->C:Lw3/h2;

    .line 11
    .line 12
    return-object p0
.end method

.method public final g(JLay0/n;Lrx0/a;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p4, Lp3/g0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p4

    .line 6
    check-cast v0, Lp3/g0;

    .line 7
    .line 8
    iget v1, v0, Lp3/g0;->g:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lp3/g0;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lp3/g0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p4}, Lp3/g0;-><init>(Lp3/i0;Lrx0/a;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p4, v0, Lp3/g0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lp3/g0;->g:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p0, v0, Lp3/g0;->d:Lvy0/x1;

    .line 37
    .line 38
    :try_start_0
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :catchall_0
    move-exception v0

    .line 43
    move-object p1, v0

    .line 44
    goto :goto_2

    .line 45
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 46
    .line 47
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 48
    .line 49
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_2
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    const-wide/16 v4, 0x0

    .line 57
    .line 58
    cmp-long p4, p1, v4

    .line 59
    .line 60
    if-gtz p4, :cond_3

    .line 61
    .line 62
    iget-object p4, p0, Lp3/i0;->f:Lvy0/l;

    .line 63
    .line 64
    if-eqz p4, :cond_3

    .line 65
    .line 66
    new-instance v2, Lp3/n;

    .line 67
    .line 68
    invoke-direct {v2, p1, p2}, Lp3/n;-><init>(J)V

    .line 69
    .line 70
    .line 71
    invoke-static {v2}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 72
    .line 73
    .line 74
    move-result-object v2

    .line 75
    invoke-virtual {p4, v2}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    :cond_3
    iget-object p4, p0, Lp3/i0;->i:Lp3/j0;

    .line 79
    .line 80
    invoke-virtual {p4}, Lx2/r;->L0()Lvy0/b0;

    .line 81
    .line 82
    .line 83
    move-result-object p4

    .line 84
    new-instance v4, Le2/f0;

    .line 85
    .line 86
    const/4 v9, 0x4

    .line 87
    const/4 v8, 0x0

    .line 88
    move-object v7, p0

    .line 89
    move-wide v5, p1

    .line 90
    invoke-direct/range {v4 .. v9}, Le2/f0;-><init>(JLjava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 91
    .line 92
    .line 93
    const/4 p0, 0x3

    .line 94
    invoke-static {p4, v8, v8, v4, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    :try_start_1
    iput-object p0, v0, Lp3/g0;->d:Lvy0/x1;

    .line 99
    .line 100
    iput v3, v0, Lp3/g0;->g:I

    .line 101
    .line 102
    invoke-interface {p3, v7, v0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object p4
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 106
    if-ne p4, v1, :cond_4

    .line 107
    .line 108
    return-object v1

    .line 109
    :cond_4
    :goto_1
    sget-object p1, Lp3/b;->e:Lp3/b;

    .line 110
    .line 111
    invoke-interface {p0, p1}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 112
    .line 113
    .line 114
    return-object p4

    .line 115
    :goto_2
    sget-object p2, Lp3/b;->e:Lp3/b;

    .line 116
    .line 117
    invoke-interface {p0, p2}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 118
    .line 119
    .line 120
    throw p1
.end method

.method public final getContext()Lpx0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lp3/i0;->h:Lpx0/h;

    .line 2
    .line 3
    return-object p0
.end method

.method public final i(JLay0/n;Lrx0/a;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p4, Lp3/h0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p4

    .line 6
    check-cast v0, Lp3/h0;

    .line 7
    .line 8
    iget v1, v0, Lp3/h0;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lp3/h0;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lp3/h0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p4}, Lp3/h0;-><init>(Lp3/i0;Lrx0/a;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p4, v0, Lp3/h0;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lp3/h0;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    :try_start_0
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Lp3/n; {:try_start_0 .. :try_end_0} :catch_0

    .line 37
    .line 38
    .line 39
    return-object p4

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    :try_start_1
    iput v3, v0, Lp3/h0;->f:I

    .line 52
    .line 53
    invoke-virtual {p0, p1, p2, p3, v0}, Lp3/i0;->g(JLay0/n;Lrx0/a;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object p0
    :try_end_1
    .catch Lp3/n; {:try_start_1 .. :try_end_1} :catch_0

    .line 57
    if-ne p0, v1, :cond_3

    .line 58
    .line 59
    return-object v1

    .line 60
    :cond_3
    return-object p0

    .line 61
    :catch_0
    const/4 p0, 0x0

    .line 62
    return-object p0
.end method

.method public final m(F)J
    .locals 0

    .line 1
    iget-object p0, p0, Lp3/i0;->d:Lp3/j0;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lt4/c;->m(F)J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    return-wide p0
.end method

.method public final n(J)J
    .locals 0

    .line 1
    iget-object p0, p0, Lp3/i0;->d:Lp3/j0;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2}, Lt4/c;->n(J)J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    return-wide p0
.end method

.method public final n0(I)F
    .locals 0

    .line 1
    iget-object p0, p0, Lp3/i0;->d:Lp3/j0;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lt4/c;->n0(I)F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final o0(F)F
    .locals 0

    .line 1
    iget-object p0, p0, Lp3/i0;->d:Lp3/j0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lp3/j0;->a()F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    div-float/2addr p1, p0

    .line 8
    return p1
.end method

.method public final resumeWith(Ljava/lang/Object;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lp3/i0;->i:Lp3/j0;

    .line 2
    .line 3
    iget-object v1, v0, Lp3/j0;->y:Ln2/b;

    .line 4
    .line 5
    monitor-enter v1

    .line 6
    :try_start_0
    iget-object v0, v0, Lp3/j0;->x:Ln2/b;

    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ln2/b;->l(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 9
    .line 10
    .line 11
    monitor-exit v1

    .line 12
    iget-object p0, p0, Lp3/i0;->e:Lvy0/l;

    .line 13
    .line 14
    invoke-virtual {p0, p1}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :catchall_0
    move-exception p0

    .line 19
    monitor-exit v1

    .line 20
    throw p0
.end method

.method public final s(J)F
    .locals 0

    .line 1
    iget-object p0, p0, Lp3/i0;->d:Lp3/j0;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2}, Lt4/c;->s(J)F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final t0()F
    .locals 0

    .line 1
    iget-object p0, p0, Lp3/i0;->d:Lp3/j0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lp3/j0;->t0()F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final w0(F)F
    .locals 0

    .line 1
    iget-object p0, p0, Lp3/i0;->d:Lp3/j0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lp3/j0;->a()F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    mul-float/2addr p0, p1

    .line 8
    return p0
.end method

.method public final x(I)J
    .locals 0

    .line 1
    iget-object p0, p0, Lp3/i0;->d:Lp3/j0;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lt4/c;->x(I)J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    return-wide p0
.end method

.method public final y(F)J
    .locals 0

    .line 1
    iget-object p0, p0, Lp3/i0;->d:Lp3/j0;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lt4/c;->y(F)J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    return-wide p0
.end method

.method public final z0(J)I
    .locals 0

    .line 1
    iget-object p0, p0, Lp3/i0;->d:Lp3/j0;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2}, Lt4/c;->z0(J)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
