.class public final Lp3/j0;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lp3/x;
.implements Lt4/c;
.implements Lv3/t1;


# instance fields
.field public A:Lp3/k;

.field public B:J

.field public r:Ljava/lang/Object;

.field public s:Ljava/lang/Object;

.field public t:[Ljava/lang/Object;

.field public u:Landroidx/compose/ui/input/pointer/PointerInputEventHandler;

.field public v:Lvy0/x1;

.field public w:Lp3/k;

.field public final x:Ln2/b;

.field public final y:Ln2/b;

.field public final z:Ln2/b;


# direct methods
.method public constructor <init>(Ljava/lang/Object;Ljava/lang/Object;[Ljava/lang/Object;Landroidx/compose/ui/input/pointer/PointerInputEventHandler;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lx2/r;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lp3/j0;->r:Ljava/lang/Object;

    .line 5
    .line 6
    iput-object p2, p0, Lp3/j0;->s:Ljava/lang/Object;

    .line 7
    .line 8
    iput-object p3, p0, Lp3/j0;->t:[Ljava/lang/Object;

    .line 9
    .line 10
    iput-object p4, p0, Lp3/j0;->u:Landroidx/compose/ui/input/pointer/PointerInputEventHandler;

    .line 11
    .line 12
    sget-object p1, Lp3/f0;->a:Lp3/k;

    .line 13
    .line 14
    iput-object p1, p0, Lp3/j0;->w:Lp3/k;

    .line 15
    .line 16
    new-instance p1, Ln2/b;

    .line 17
    .line 18
    const/16 p2, 0x10

    .line 19
    .line 20
    new-array p3, p2, [Lp3/i0;

    .line 21
    .line 22
    invoke-direct {p1, p3}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    iput-object p1, p0, Lp3/j0;->x:Ln2/b;

    .line 26
    .line 27
    iput-object p1, p0, Lp3/j0;->y:Ln2/b;

    .line 28
    .line 29
    new-instance p1, Ln2/b;

    .line 30
    .line 31
    new-array p2, p2, [Lp3/i0;

    .line 32
    .line 33
    invoke-direct {p1, p2}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    iput-object p1, p0, Lp3/j0;->z:Ln2/b;

    .line 37
    .line 38
    const-wide/16 p1, 0x0

    .line 39
    .line 40
    iput-wide p1, p0, Lp3/j0;->B:J

    .line 41
    .line 42
    return-void
.end method


# virtual methods
.method public final H0()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lp3/j0;->Z0()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final Q0()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lp3/j0;->Z0()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final X0(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

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
    new-instance p2, Lp3/i0;

    .line 15
    .line 16
    invoke-direct {p2, p0, v0}, Lp3/i0;-><init>(Lp3/j0;Lvy0/l;)V

    .line 17
    .line 18
    .line 19
    iget-object v1, p0, Lp3/j0;->y:Ln2/b;

    .line 20
    .line 21
    monitor-enter v1

    .line 22
    :try_start_0
    iget-object p0, p0, Lp3/j0;->x:Ln2/b;

    .line 23
    .line 24
    invoke-virtual {p0, p2}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    new-instance p0, Lpx0/i;

    .line 28
    .line 29
    invoke-static {p1, p2, p2}, Ljp/hg;->a(Lay0/n;Lkotlin/coroutines/Continuation;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    invoke-static {p1}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 38
    .line 39
    invoke-direct {p0, p1, v2}, Lpx0/i;-><init>(Lkotlin/coroutines/Continuation;Lqx0/a;)V

    .line 40
    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lpx0/i;->resumeWith(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 45
    .line 46
    .line 47
    monitor-exit v1

    .line 48
    new-instance p0, La3/f;

    .line 49
    .line 50
    const/16 p1, 0x1a

    .line 51
    .line 52
    invoke-direct {p0, p2, p1}, La3/f;-><init>(Ljava/lang/Object;I)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {v0, p0}, Lvy0/l;->s(Lay0/k;)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {v0}, Lvy0/l;->p()Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    return-object p0

    .line 63
    :catchall_0
    move-exception p0

    .line 64
    monitor-exit v1

    .line 65
    throw p0
.end method

.method public final Y0(Lp3/k;Lp3/l;)V
    .locals 6

    .line 1
    iget-object v0, p0, Lp3/j0;->y:Ln2/b;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lp3/j0;->z:Ln2/b;

    .line 5
    .line 6
    iget-object v2, p0, Lp3/j0;->x:Ln2/b;

    .line 7
    .line 8
    iget v3, v1, Ln2/b;->f:I

    .line 9
    .line 10
    invoke-virtual {v1, v3, v2}, Ln2/b;->f(ILn2/b;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 11
    .line 12
    .line 13
    monitor-exit v0

    .line 14
    :try_start_1
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    const/4 v1, 0x0

    .line 19
    if-eqz v0, :cond_3

    .line 20
    .line 21
    const/4 v2, 0x1

    .line 22
    if-eq v0, v2, :cond_1

    .line 23
    .line 24
    const/4 v2, 0x2

    .line 25
    if-ne v0, v2, :cond_0

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_0
    new-instance p1, La8/r0;

    .line 29
    .line 30
    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    .line 31
    .line 32
    .line 33
    throw p1

    .line 34
    :catchall_0
    move-exception p1

    .line 35
    goto :goto_3

    .line 36
    :cond_1
    iget-object v0, p0, Lp3/j0;->z:Ln2/b;

    .line 37
    .line 38
    iget v3, v0, Ln2/b;->f:I

    .line 39
    .line 40
    sub-int/2addr v3, v2

    .line 41
    iget-object v0, v0, Ln2/b;->d:[Ljava/lang/Object;

    .line 42
    .line 43
    array-length v2, v0

    .line 44
    if-ge v3, v2, :cond_5

    .line 45
    .line 46
    :goto_0
    if-ltz v3, :cond_5

    .line 47
    .line 48
    aget-object v2, v0, v3

    .line 49
    .line 50
    check-cast v2, Lp3/i0;

    .line 51
    .line 52
    iget-object v4, v2, Lp3/i0;->g:Lp3/l;

    .line 53
    .line 54
    if-ne p2, v4, :cond_2

    .line 55
    .line 56
    iget-object v4, v2, Lp3/i0;->f:Lvy0/l;

    .line 57
    .line 58
    if-eqz v4, :cond_2

    .line 59
    .line 60
    iput-object v1, v2, Lp3/i0;->f:Lvy0/l;

    .line 61
    .line 62
    invoke-virtual {v4, p1}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    :cond_2
    add-int/lit8 v3, v3, -0x1

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_3
    :goto_1
    iget-object v0, p0, Lp3/j0;->z:Ln2/b;

    .line 69
    .line 70
    iget-object v2, v0, Ln2/b;->d:[Ljava/lang/Object;

    .line 71
    .line 72
    iget v0, v0, Ln2/b;->f:I

    .line 73
    .line 74
    const/4 v3, 0x0

    .line 75
    :goto_2
    if-ge v3, v0, :cond_5

    .line 76
    .line 77
    aget-object v4, v2, v3

    .line 78
    .line 79
    check-cast v4, Lp3/i0;

    .line 80
    .line 81
    iget-object v5, v4, Lp3/i0;->g:Lp3/l;

    .line 82
    .line 83
    if-ne p2, v5, :cond_4

    .line 84
    .line 85
    iget-object v5, v4, Lp3/i0;->f:Lvy0/l;

    .line 86
    .line 87
    if-eqz v5, :cond_4

    .line 88
    .line 89
    iput-object v1, v4, Lp3/i0;->f:Lvy0/l;

    .line 90
    .line 91
    invoke-virtual {v5, p1}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 92
    .line 93
    .line 94
    :cond_4
    add-int/lit8 v3, v3, 0x1

    .line 95
    .line 96
    goto :goto_2

    .line 97
    :cond_5
    iget-object p0, p0, Lp3/j0;->z:Ln2/b;

    .line 98
    .line 99
    invoke-virtual {p0}, Ln2/b;->i()V

    .line 100
    .line 101
    .line 102
    return-void

    .line 103
    :goto_3
    iget-object p0, p0, Lp3/j0;->z:Ln2/b;

    .line 104
    .line 105
    invoke-virtual {p0}, Ln2/b;->i()V

    .line 106
    .line 107
    .line 108
    throw p1

    .line 109
    :catchall_1
    move-exception p0

    .line 110
    monitor-exit v0

    .line 111
    throw p0
.end method

.method public final Z0()V
    .locals 4

    .line 1
    iget-object v0, p0, Lp3/j0;->v:Lvy0/x1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    new-instance v1, Lp3/w;

    .line 6
    .line 7
    const-string v2, "Pointer input was reset"

    .line 8
    .line 9
    const/4 v3, 0x1

    .line 10
    invoke-direct {v1, v2, v3}, Lj1/c;-><init>(Ljava/lang/String;I)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {v0, v1}, Lvy0/p1;->A(Ljava/util/concurrent/CancellationException;)V

    .line 14
    .line 15
    .line 16
    const/4 v0, 0x0

    .line 17
    iput-object v0, p0, Lp3/j0;->v:Lvy0/x1;

    .line 18
    .line 19
    :cond_0
    return-void
.end method

.method public final a()F
    .locals 0

    .line 1
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p0, p0, Lv3/h0;->A:Lt4/c;

    .line 6
    .line 7
    invoke-interface {p0}, Lt4/c;->a()F

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method public final d()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lp3/j0;->Z0()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final l0()V
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lp3/j0;->A:Lp3/k;

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    goto/16 :goto_2

    .line 8
    .line 9
    :cond_0
    iget-object v1, v1, Lp3/k;->a:Ljava/lang/Object;

    .line 10
    .line 11
    move-object v2, v1

    .line 12
    check-cast v2, Ljava/util/Collection;

    .line 13
    .line 14
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    const/4 v3, 0x0

    .line 19
    move v4, v3

    .line 20
    :goto_0
    if-ge v4, v2, :cond_3

    .line 21
    .line 22
    invoke-interface {v1, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v5

    .line 26
    check-cast v5, Lp3/t;

    .line 27
    .line 28
    iget-boolean v5, v5, Lp3/t;->d:Z

    .line 29
    .line 30
    if-eqz v5, :cond_2

    .line 31
    .line 32
    new-instance v2, Ljava/util/ArrayList;

    .line 33
    .line 34
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    invoke-direct {v2, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 39
    .line 40
    .line 41
    move-object v4, v1

    .line 42
    check-cast v4, Ljava/util/Collection;

    .line 43
    .line 44
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 45
    .line 46
    .line 47
    move-result v4

    .line 48
    :goto_1
    if-ge v3, v4, :cond_1

    .line 49
    .line 50
    invoke-interface {v1, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v5

    .line 54
    check-cast v5, Lp3/t;

    .line 55
    .line 56
    iget-wide v7, v5, Lp3/t;->a:J

    .line 57
    .line 58
    iget-wide v11, v5, Lp3/t;->c:J

    .line 59
    .line 60
    iget-wide v9, v5, Lp3/t;->b:J

    .line 61
    .line 62
    iget v14, v5, Lp3/t;->e:F

    .line 63
    .line 64
    iget-boolean v6, v5, Lp3/t;->d:Z

    .line 65
    .line 66
    iget v5, v5, Lp3/t;->i:I

    .line 67
    .line 68
    move/from16 v19, v6

    .line 69
    .line 70
    new-instance v6, Lp3/t;

    .line 71
    .line 72
    const/4 v13, 0x0

    .line 73
    const-wide/16 v22, 0x0

    .line 74
    .line 75
    move-wide v15, v9

    .line 76
    move-wide/from16 v17, v11

    .line 77
    .line 78
    move/from16 v20, v19

    .line 79
    .line 80
    move/from16 v21, v5

    .line 81
    .line 82
    invoke-direct/range {v6 .. v23}, Lp3/t;-><init>(JJJZFJJZZIJ)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {v2, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    add-int/lit8 v3, v3, 0x1

    .line 89
    .line 90
    goto :goto_1

    .line 91
    :cond_1
    new-instance v1, Lp3/k;

    .line 92
    .line 93
    const/4 v3, 0x0

    .line 94
    invoke-direct {v1, v2, v3}, Lp3/k;-><init>(Ljava/util/List;Lcom/google/android/gms/internal/measurement/i4;)V

    .line 95
    .line 96
    .line 97
    iput-object v1, v0, Lp3/j0;->w:Lp3/k;

    .line 98
    .line 99
    sget-object v2, Lp3/l;->d:Lp3/l;

    .line 100
    .line 101
    invoke-virtual {v0, v1, v2}, Lp3/j0;->Y0(Lp3/k;Lp3/l;)V

    .line 102
    .line 103
    .line 104
    sget-object v2, Lp3/l;->e:Lp3/l;

    .line 105
    .line 106
    invoke-virtual {v0, v1, v2}, Lp3/j0;->Y0(Lp3/k;Lp3/l;)V

    .line 107
    .line 108
    .line 109
    sget-object v2, Lp3/l;->f:Lp3/l;

    .line 110
    .line 111
    invoke-virtual {v0, v1, v2}, Lp3/j0;->Y0(Lp3/k;Lp3/l;)V

    .line 112
    .line 113
    .line 114
    iput-object v3, v0, Lp3/j0;->A:Lp3/k;

    .line 115
    .line 116
    return-void

    .line 117
    :cond_2
    add-int/lit8 v4, v4, 0x1

    .line 118
    .line 119
    goto :goto_0

    .line 120
    :cond_3
    :goto_2
    return-void
.end method

.method public final t0()F
    .locals 0

    .line 1
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p0, p0, Lv3/h0;->A:Lt4/c;

    .line 6
    .line 7
    invoke-interface {p0}, Lt4/c;->t0()F

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method public final v0(Lp3/k;Lp3/l;J)V
    .locals 3

    .line 1
    iput-wide p3, p0, Lp3/j0;->B:J

    .line 2
    .line 3
    sget-object p3, Lp3/l;->d:Lp3/l;

    .line 4
    .line 5
    if-ne p2, p3, :cond_0

    .line 6
    .line 7
    iput-object p1, p0, Lp3/j0;->w:Lp3/k;

    .line 8
    .line 9
    :cond_0
    iget-object p3, p0, Lp3/j0;->v:Lvy0/x1;

    .line 10
    .line 11
    const/4 p4, 0x0

    .line 12
    if-nez p3, :cond_1

    .line 13
    .line 14
    invoke-virtual {p0}, Lx2/r;->L0()Lvy0/b0;

    .line 15
    .line 16
    .line 17
    move-result-object p3

    .line 18
    sget-object v0, Lvy0/c0;->g:Lvy0/c0;

    .line 19
    .line 20
    new-instance v1, Ln00/f;

    .line 21
    .line 22
    const/16 v2, 0x9

    .line 23
    .line 24
    invoke-direct {v1, p0, p4, v2}, Ln00/f;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    const/4 v2, 0x1

    .line 28
    invoke-static {p3, p4, v0, v1, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 29
    .line 30
    .line 31
    move-result-object p3

    .line 32
    iput-object p3, p0, Lp3/j0;->v:Lvy0/x1;

    .line 33
    .line 34
    :cond_1
    invoke-virtual {p0, p1, p2}, Lp3/j0;->Y0(Lp3/k;Lp3/l;)V

    .line 35
    .line 36
    .line 37
    iget-object p2, p1, Lp3/k;->a:Ljava/lang/Object;

    .line 38
    .line 39
    move-object p3, p2

    .line 40
    check-cast p3, Ljava/util/Collection;

    .line 41
    .line 42
    invoke-interface {p3}, Ljava/util/Collection;->size()I

    .line 43
    .line 44
    .line 45
    move-result p3

    .line 46
    const/4 v0, 0x0

    .line 47
    :goto_0
    if-ge v0, p3, :cond_3

    .line 48
    .line 49
    invoke-interface {p2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    check-cast v1, Lp3/t;

    .line 54
    .line 55
    invoke-static {v1}, Lp3/s;->d(Lp3/t;)Z

    .line 56
    .line 57
    .line 58
    move-result v1

    .line 59
    if-nez v1, :cond_2

    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_2
    add-int/lit8 v0, v0, 0x1

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_3
    move-object p1, p4

    .line 66
    :goto_1
    iput-object p1, p0, Lp3/j0;->A:Lp3/k;

    .line 67
    .line 68
    return-void
.end method
