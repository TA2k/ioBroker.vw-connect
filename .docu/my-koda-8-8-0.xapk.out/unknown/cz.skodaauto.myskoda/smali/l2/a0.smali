.class public final Ll2/a0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll2/w;


# instance fields
.field public A:Lay0/n;

.field public final d:Ll2/x;

.field public final e:Leb/j0;

.field public final f:Ljava/util/concurrent/atomic/AtomicReference;

.field public final g:Ljava/lang/Object;

.field public final h:Landroidx/collection/t0;

.field public final i:Ll2/f2;

.field public final j:Landroidx/collection/q0;

.field public final k:Landroidx/collection/r0;

.field public final l:Landroidx/collection/r0;

.field public final m:Landroidx/collection/q0;

.field public final n:Lm2/a;

.field public final o:Lm2/a;

.field public final p:Landroidx/collection/q0;

.field public q:Landroidx/collection/q0;

.field public r:Z

.field public s:Lt0/c;

.field public t:Ll2/m1;

.field public u:Ll2/a0;

.field public v:I

.field public final w:Lh6/e;

.field public final x:Ljp/uf;

.field public final y:Ll2/t;

.field public z:I


# direct methods
.method public constructor <init>(Ll2/x;Leb/j0;)V
    .locals 10

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll2/a0;->d:Ll2/x;

    .line 5
    .line 6
    iput-object p2, p0, Ll2/a0;->e:Leb/j0;

    .line 7
    .line 8
    new-instance v0, Ljava/util/concurrent/atomic/AtomicReference;

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    iput-object v0, p0, Ll2/a0;->f:Ljava/util/concurrent/atomic/AtomicReference;

    .line 15
    .line 16
    new-instance v0, Ljava/lang/Object;

    .line 17
    .line 18
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 19
    .line 20
    .line 21
    iput-object v0, p0, Ll2/a0;->g:Ljava/lang/Object;

    .line 22
    .line 23
    new-instance v0, Landroidx/collection/r0;

    .line 24
    .line 25
    invoke-direct {v0}, Landroidx/collection/r0;-><init>()V

    .line 26
    .line 27
    .line 28
    new-instance v5, Landroidx/collection/t0;

    .line 29
    .line 30
    invoke-direct {v5, v0}, Landroidx/collection/t0;-><init>(Landroidx/collection/r0;)V

    .line 31
    .line 32
    .line 33
    iput-object v5, p0, Ll2/a0;->h:Landroidx/collection/t0;

    .line 34
    .line 35
    new-instance v4, Ll2/f2;

    .line 36
    .line 37
    invoke-direct {v4}, Ll2/f2;-><init>()V

    .line 38
    .line 39
    .line 40
    invoke-virtual {p1}, Ll2/x;->d()Z

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    if-eqz v0, :cond_0

    .line 45
    .line 46
    new-instance v0, Landroidx/collection/b0;

    .line 47
    .line 48
    invoke-direct {v0}, Landroidx/collection/b0;-><init>()V

    .line 49
    .line 50
    .line 51
    iput-object v0, v4, Ll2/f2;->n:Landroidx/collection/b0;

    .line 52
    .line 53
    :cond_0
    invoke-virtual {p1}, Ll2/x;->f()Z

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    if-eqz v0, :cond_1

    .line 58
    .line 59
    invoke-virtual {v4}, Ll2/f2;->e()V

    .line 60
    .line 61
    .line 62
    :cond_1
    iput-object v4, p0, Ll2/a0;->i:Ll2/f2;

    .line 63
    .line 64
    invoke-static {}, Ljp/v1;->b()Landroidx/collection/q0;

    .line 65
    .line 66
    .line 67
    move-result-object v0

    .line 68
    iput-object v0, p0, Ll2/a0;->j:Landroidx/collection/q0;

    .line 69
    .line 70
    new-instance v0, Landroidx/collection/r0;

    .line 71
    .line 72
    invoke-direct {v0}, Landroidx/collection/r0;-><init>()V

    .line 73
    .line 74
    .line 75
    iput-object v0, p0, Ll2/a0;->k:Landroidx/collection/r0;

    .line 76
    .line 77
    new-instance v0, Landroidx/collection/r0;

    .line 78
    .line 79
    invoke-direct {v0}, Landroidx/collection/r0;-><init>()V

    .line 80
    .line 81
    .line 82
    iput-object v0, p0, Ll2/a0;->l:Landroidx/collection/r0;

    .line 83
    .line 84
    invoke-static {}, Ljp/v1;->b()Landroidx/collection/q0;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    iput-object v0, p0, Ll2/a0;->m:Landroidx/collection/q0;

    .line 89
    .line 90
    new-instance v6, Lm2/a;

    .line 91
    .line 92
    invoke-direct {v6}, Lm2/a;-><init>()V

    .line 93
    .line 94
    .line 95
    iput-object v6, p0, Ll2/a0;->n:Lm2/a;

    .line 96
    .line 97
    new-instance v7, Lm2/a;

    .line 98
    .line 99
    invoke-direct {v7}, Lm2/a;-><init>()V

    .line 100
    .line 101
    .line 102
    iput-object v7, p0, Ll2/a0;->o:Lm2/a;

    .line 103
    .line 104
    invoke-static {}, Ljp/v1;->b()Landroidx/collection/q0;

    .line 105
    .line 106
    .line 107
    move-result-object v0

    .line 108
    iput-object v0, p0, Ll2/a0;->p:Landroidx/collection/q0;

    .line 109
    .line 110
    invoke-static {}, Ljp/v1;->b()Landroidx/collection/q0;

    .line 111
    .line 112
    .line 113
    move-result-object v0

    .line 114
    iput-object v0, p0, Ll2/a0;->q:Landroidx/collection/q0;

    .line 115
    .line 116
    new-instance v8, Lh6/e;

    .line 117
    .line 118
    const/16 v0, 0xf

    .line 119
    .line 120
    invoke-direct {v8, p1, v0}, Lh6/e;-><init>(Ljava/lang/Object;I)V

    .line 121
    .line 122
    .line 123
    iput-object v8, p0, Ll2/a0;->w:Lh6/e;

    .line 124
    .line 125
    new-instance v0, Ljp/uf;

    .line 126
    .line 127
    invoke-direct {v0}, Ljp/uf;-><init>()V

    .line 128
    .line 129
    .line 130
    iput-object v0, p0, Ll2/a0;->x:Ljp/uf;

    .line 131
    .line 132
    new-instance v1, Ll2/t;

    .line 133
    .line 134
    move-object v9, p0

    .line 135
    move-object v3, p1

    .line 136
    move-object v2, p2

    .line 137
    invoke-direct/range {v1 .. v9}, Ll2/t;-><init>(Leb/j0;Ll2/x;Ll2/f2;Landroidx/collection/t0;Lm2/a;Lm2/a;Lh6/e;Ll2/a0;)V

    .line 138
    .line 139
    .line 140
    invoke-virtual {v3, v1}, Ll2/x;->o(Ll2/t;)V

    .line 141
    .line 142
    .line 143
    iput-object v1, v9, Ll2/a0;->y:Ll2/t;

    .line 144
    .line 145
    sget-object p0, Ll2/i;->a:Lt2/b;

    .line 146
    .line 147
    iput-object p0, v9, Ll2/a0;->A:Lay0/n;

    .line 148
    .line 149
    return-void
.end method


# virtual methods
.method public final A(Lay0/n;)V
    .locals 3

    .line 1
    invoke-virtual {p0}, Ll2/a0;->i()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p0}, Ll2/a0;->p()V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Ll2/a0;->d:Ll2/x;

    .line 9
    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    const/16 v0, 0x64

    .line 13
    .line 14
    iget-object v2, p0, Ll2/a0;->y:Ll2/t;

    .line 15
    .line 16
    iput v0, v2, Ll2/t;->z:I

    .line 17
    .line 18
    const/4 v0, 0x1

    .line 19
    iput-boolean v0, v2, Ll2/t;->y:Z

    .line 20
    .line 21
    iput-object p1, p0, Ll2/a0;->A:Lay0/n;

    .line 22
    .line 23
    invoke-virtual {v1, p0, p1}, Ll2/x;->a(Ll2/a0;Lay0/n;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v2}, Ll2/t;->t()V

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :cond_0
    iput-object p1, p0, Ll2/a0;->A:Lay0/n;

    .line 31
    .line 32
    invoke-virtual {v1, p0, p1}, Ll2/x;->a(Ll2/a0;Lay0/n;)V

    .line 33
    .line 34
    .line 35
    return-void
.end method

.method public final a()V
    .locals 2

    .line 1
    iget-object v0, p0, Ll2/a0;->f:Ljava/util/concurrent/atomic/AtomicReference;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 5
    .line 6
    .line 7
    iget-object v0, p0, Ll2/a0;->n:Lm2/a;

    .line 8
    .line 9
    iget-object v0, v0, Lm2/a;->b:Lm2/l0;

    .line 10
    .line 11
    invoke-virtual {v0}, Lm2/l0;->d()V

    .line 12
    .line 13
    .line 14
    iget-object v0, p0, Ll2/a0;->o:Lm2/a;

    .line 15
    .line 16
    iget-object v0, v0, Lm2/a;->b:Lm2/l0;

    .line 17
    .line 18
    invoke-virtual {v0}, Lm2/l0;->d()V

    .line 19
    .line 20
    .line 21
    iget-object v0, p0, Ll2/a0;->h:Landroidx/collection/t0;

    .line 22
    .line 23
    iget-object v1, v0, Landroidx/collection/t0;->d:Landroidx/collection/r0;

    .line 24
    .line 25
    invoke-virtual {v1}, Landroidx/collection/r0;->g()Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-nez v1, :cond_0

    .line 30
    .line 31
    iget-object v1, p0, Ll2/a0;->x:Ljp/uf;

    .line 32
    .line 33
    iget-object p0, p0, Ll2/a0;->y:Ll2/t;

    .line 34
    .line 35
    invoke-virtual {p0}, Ll2/t;->z()Lw2/b;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    :try_start_0
    invoke-virtual {v1, v0, p0}, Ljp/uf;->g(Ljava/util/Set;Lw2/b;)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {v1}, Ljp/uf;->b()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 43
    .line 44
    .line 45
    invoke-virtual {v1}, Ljp/uf;->a()V

    .line 46
    .line 47
    .line 48
    return-void

    .line 49
    :catchall_0
    move-exception p0

    .line 50
    invoke-virtual {v1}, Ljp/uf;->a()V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_0
    return-void
.end method

.method public final b(Ljava/lang/Object;Z)V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, Ll2/a0;->j:Landroidx/collection/q0;

    .line 6
    .line 7
    invoke-virtual {v2, v1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    if-eqz v2, :cond_6

    .line 12
    .line 13
    instance-of v3, v2, Landroidx/collection/r0;

    .line 14
    .line 15
    iget-object v4, v0, Ll2/a0;->k:Landroidx/collection/r0;

    .line 16
    .line 17
    iget-object v5, v0, Ll2/a0;->l:Landroidx/collection/r0;

    .line 18
    .line 19
    iget-object v0, v0, Ll2/a0;->p:Landroidx/collection/q0;

    .line 20
    .line 21
    if-eqz v3, :cond_4

    .line 22
    .line 23
    check-cast v2, Landroidx/collection/r0;

    .line 24
    .line 25
    iget-object v3, v2, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 26
    .line 27
    iget-object v2, v2, Landroidx/collection/r0;->a:[J

    .line 28
    .line 29
    array-length v6, v2

    .line 30
    add-int/lit8 v6, v6, -0x2

    .line 31
    .line 32
    if-ltz v6, :cond_6

    .line 33
    .line 34
    const/4 v8, 0x0

    .line 35
    :goto_0
    aget-wide v9, v2, v8

    .line 36
    .line 37
    not-long v11, v9

    .line 38
    const/4 v13, 0x7

    .line 39
    shl-long/2addr v11, v13

    .line 40
    and-long/2addr v11, v9

    .line 41
    const-wide v13, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 42
    .line 43
    .line 44
    .line 45
    .line 46
    and-long/2addr v11, v13

    .line 47
    cmp-long v11, v11, v13

    .line 48
    .line 49
    if-eqz v11, :cond_3

    .line 50
    .line 51
    sub-int v11, v8, v6

    .line 52
    .line 53
    not-int v11, v11

    .line 54
    ushr-int/lit8 v11, v11, 0x1f

    .line 55
    .line 56
    const/16 v12, 0x8

    .line 57
    .line 58
    rsub-int/lit8 v11, v11, 0x8

    .line 59
    .line 60
    const/4 v13, 0x0

    .line 61
    :goto_1
    if-ge v13, v11, :cond_2

    .line 62
    .line 63
    const-wide/16 v14, 0xff

    .line 64
    .line 65
    and-long/2addr v14, v9

    .line 66
    const-wide/16 v16, 0x80

    .line 67
    .line 68
    cmp-long v14, v14, v16

    .line 69
    .line 70
    if-gez v14, :cond_1

    .line 71
    .line 72
    shl-int/lit8 v14, v8, 0x3

    .line 73
    .line 74
    add-int/2addr v14, v13

    .line 75
    aget-object v14, v3, v14

    .line 76
    .line 77
    check-cast v14, Ll2/u1;

    .line 78
    .line 79
    invoke-static {v0, v1, v14}, Ljp/v1;->i(Landroidx/collection/q0;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    move-result v15

    .line 83
    if-nez v15, :cond_1

    .line 84
    .line 85
    invoke-virtual {v14, v1}, Ll2/u1;->d(Ljava/lang/Object;)Ll2/s0;

    .line 86
    .line 87
    .line 88
    move-result-object v15

    .line 89
    sget-object v7, Ll2/s0;->d:Ll2/s0;

    .line 90
    .line 91
    if-eq v15, v7, :cond_1

    .line 92
    .line 93
    iget-object v7, v14, Ll2/u1;->g:Landroidx/collection/q0;

    .line 94
    .line 95
    if-eqz v7, :cond_0

    .line 96
    .line 97
    if-nez p2, :cond_0

    .line 98
    .line 99
    invoke-virtual {v5, v14}, Landroidx/collection/r0;->a(Ljava/lang/Object;)Z

    .line 100
    .line 101
    .line 102
    goto :goto_2

    .line 103
    :cond_0
    invoke-virtual {v4, v14}, Landroidx/collection/r0;->a(Ljava/lang/Object;)Z

    .line 104
    .line 105
    .line 106
    :cond_1
    :goto_2
    shr-long/2addr v9, v12

    .line 107
    add-int/lit8 v13, v13, 0x1

    .line 108
    .line 109
    goto :goto_1

    .line 110
    :cond_2
    if-ne v11, v12, :cond_6

    .line 111
    .line 112
    :cond_3
    if-eq v8, v6, :cond_6

    .line 113
    .line 114
    add-int/lit8 v8, v8, 0x1

    .line 115
    .line 116
    goto :goto_0

    .line 117
    :cond_4
    check-cast v2, Ll2/u1;

    .line 118
    .line 119
    invoke-static {v0, v1, v2}, Ljp/v1;->i(Landroidx/collection/q0;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 120
    .line 121
    .line 122
    move-result v0

    .line 123
    if-nez v0, :cond_6

    .line 124
    .line 125
    invoke-virtual {v2, v1}, Ll2/u1;->d(Ljava/lang/Object;)Ll2/s0;

    .line 126
    .line 127
    .line 128
    move-result-object v0

    .line 129
    sget-object v1, Ll2/s0;->d:Ll2/s0;

    .line 130
    .line 131
    if-eq v0, v1, :cond_6

    .line 132
    .line 133
    iget-object v0, v2, Ll2/u1;->g:Landroidx/collection/q0;

    .line 134
    .line 135
    if-eqz v0, :cond_5

    .line 136
    .line 137
    if-nez p2, :cond_5

    .line 138
    .line 139
    invoke-virtual {v5, v2}, Landroidx/collection/r0;->a(Ljava/lang/Object;)Z

    .line 140
    .line 141
    .line 142
    return-void

    .line 143
    :cond_5
    invoke-virtual {v4, v2}, Landroidx/collection/r0;->a(Ljava/lang/Object;)Z

    .line 144
    .line 145
    .line 146
    :cond_6
    return-void
.end method

.method public final c(Ljava/util/Set;Z)V
    .locals 33

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p2

    .line 6
    .line 7
    instance-of v3, v1, Ln2/d;

    .line 8
    .line 9
    iget-object v4, v0, Ll2/a0;->m:Landroidx/collection/q0;

    .line 10
    .line 11
    const/4 v5, 0x0

    .line 12
    const/16 v14, 0x8

    .line 13
    .line 14
    if-eqz v3, :cond_b

    .line 15
    .line 16
    check-cast v1, Ln2/d;

    .line 17
    .line 18
    iget-object v1, v1, Ln2/d;->d:Landroidx/collection/r0;

    .line 19
    .line 20
    iget-object v3, v1, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 21
    .line 22
    iget-object v1, v1, Landroidx/collection/r0;->a:[J

    .line 23
    .line 24
    array-length v15, v1

    .line 25
    add-int/lit8 v15, v15, -0x2

    .line 26
    .line 27
    if-ltz v15, :cond_a

    .line 28
    .line 29
    const/4 v6, 0x0

    .line 30
    const-wide/16 v16, 0x80

    .line 31
    .line 32
    const-wide/16 v18, 0xff

    .line 33
    .line 34
    :goto_0
    aget-wide v8, v1, v6

    .line 35
    .line 36
    const/4 v7, 0x7

    .line 37
    const-wide v20, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 38
    .line 39
    .line 40
    .line 41
    .line 42
    not-long v10, v8

    .line 43
    shl-long/2addr v10, v7

    .line 44
    and-long/2addr v10, v8

    .line 45
    and-long v10, v10, v20

    .line 46
    .line 47
    cmp-long v10, v10, v20

    .line 48
    .line 49
    if-eqz v10, :cond_9

    .line 50
    .line 51
    sub-int v10, v6, v15

    .line 52
    .line 53
    not-int v10, v10

    .line 54
    ushr-int/lit8 v10, v10, 0x1f

    .line 55
    .line 56
    rsub-int/lit8 v10, v10, 0x8

    .line 57
    .line 58
    const/4 v11, 0x0

    .line 59
    :goto_1
    if-ge v11, v10, :cond_8

    .line 60
    .line 61
    and-long v22, v8, v18

    .line 62
    .line 63
    cmp-long v12, v22, v16

    .line 64
    .line 65
    if-gez v12, :cond_7

    .line 66
    .line 67
    shl-int/lit8 v12, v6, 0x3

    .line 68
    .line 69
    add-int/2addr v12, v11

    .line 70
    aget-object v12, v3, v12

    .line 71
    .line 72
    move/from16 v22, v7

    .line 73
    .line 74
    instance-of v7, v12, Ll2/u1;

    .line 75
    .line 76
    if-eqz v7, :cond_1

    .line 77
    .line 78
    check-cast v12, Ll2/u1;

    .line 79
    .line 80
    invoke-virtual {v12, v5}, Ll2/u1;->d(Ljava/lang/Object;)Ll2/s0;

    .line 81
    .line 82
    .line 83
    :cond_0
    move-object/from16 v29, v1

    .line 84
    .line 85
    move-wide/from16 v26, v8

    .line 86
    .line 87
    move/from16 p1, v15

    .line 88
    .line 89
    goto/16 :goto_6

    .line 90
    .line 91
    :cond_1
    invoke-virtual {v0, v12, v2}, Ll2/a0;->b(Ljava/lang/Object;Z)V

    .line 92
    .line 93
    .line 94
    invoke-virtual {v4, v12}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v7

    .line 98
    if-eqz v7, :cond_0

    .line 99
    .line 100
    instance-of v12, v7, Landroidx/collection/r0;

    .line 101
    .line 102
    if-eqz v12, :cond_5

    .line 103
    .line 104
    check-cast v7, Landroidx/collection/r0;

    .line 105
    .line 106
    iget-object v12, v7, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 107
    .line 108
    iget-object v7, v7, Landroidx/collection/r0;->a:[J

    .line 109
    .line 110
    array-length v13, v7

    .line 111
    add-int/lit8 v13, v13, -0x2

    .line 112
    .line 113
    if-ltz v13, :cond_0

    .line 114
    .line 115
    move/from16 v25, v14

    .line 116
    .line 117
    move/from16 p1, v15

    .line 118
    .line 119
    const/4 v5, 0x0

    .line 120
    :goto_2
    aget-wide v14, v7, v5

    .line 121
    .line 122
    move-wide/from16 v26, v8

    .line 123
    .line 124
    move-object v9, v7

    .line 125
    not-long v7, v14

    .line 126
    shl-long v7, v7, v22

    .line 127
    .line 128
    and-long/2addr v7, v14

    .line 129
    and-long v7, v7, v20

    .line 130
    .line 131
    cmp-long v7, v7, v20

    .line 132
    .line 133
    if-eqz v7, :cond_4

    .line 134
    .line 135
    sub-int v7, v5, v13

    .line 136
    .line 137
    not-int v7, v7

    .line 138
    ushr-int/lit8 v7, v7, 0x1f

    .line 139
    .line 140
    rsub-int/lit8 v7, v7, 0x8

    .line 141
    .line 142
    const/4 v8, 0x0

    .line 143
    :goto_3
    if-ge v8, v7, :cond_3

    .line 144
    .line 145
    and-long v28, v14, v18

    .line 146
    .line 147
    cmp-long v28, v28, v16

    .line 148
    .line 149
    if-gez v28, :cond_2

    .line 150
    .line 151
    shl-int/lit8 v28, v5, 0x3

    .line 152
    .line 153
    add-int v28, v28, v8

    .line 154
    .line 155
    aget-object v28, v12, v28

    .line 156
    .line 157
    move-object/from16 v29, v1

    .line 158
    .line 159
    move-object/from16 v1, v28

    .line 160
    .line 161
    check-cast v1, Ll2/h0;

    .line 162
    .line 163
    invoke-virtual {v0, v1, v2}, Ll2/a0;->b(Ljava/lang/Object;Z)V

    .line 164
    .line 165
    .line 166
    goto :goto_4

    .line 167
    :cond_2
    move-object/from16 v29, v1

    .line 168
    .line 169
    :goto_4
    shr-long v14, v14, v25

    .line 170
    .line 171
    add-int/lit8 v8, v8, 0x1

    .line 172
    .line 173
    move-object/from16 v1, v29

    .line 174
    .line 175
    goto :goto_3

    .line 176
    :cond_3
    move-object/from16 v29, v1

    .line 177
    .line 178
    move/from16 v1, v25

    .line 179
    .line 180
    if-ne v7, v1, :cond_6

    .line 181
    .line 182
    goto :goto_5

    .line 183
    :cond_4
    move-object/from16 v29, v1

    .line 184
    .line 185
    :goto_5
    if-eq v5, v13, :cond_6

    .line 186
    .line 187
    add-int/lit8 v5, v5, 0x1

    .line 188
    .line 189
    move-object v7, v9

    .line 190
    move-wide/from16 v8, v26

    .line 191
    .line 192
    move-object/from16 v1, v29

    .line 193
    .line 194
    const/16 v25, 0x8

    .line 195
    .line 196
    goto :goto_2

    .line 197
    :cond_5
    move-object/from16 v29, v1

    .line 198
    .line 199
    move-wide/from16 v26, v8

    .line 200
    .line 201
    move/from16 p1, v15

    .line 202
    .line 203
    check-cast v7, Ll2/h0;

    .line 204
    .line 205
    invoke-virtual {v0, v7, v2}, Ll2/a0;->b(Ljava/lang/Object;Z)V

    .line 206
    .line 207
    .line 208
    :cond_6
    :goto_6
    const/16 v1, 0x8

    .line 209
    .line 210
    goto :goto_7

    .line 211
    :cond_7
    move-object/from16 v29, v1

    .line 212
    .line 213
    move/from16 v22, v7

    .line 214
    .line 215
    move-wide/from16 v26, v8

    .line 216
    .line 217
    move/from16 p1, v15

    .line 218
    .line 219
    move v1, v14

    .line 220
    :goto_7
    shr-long v8, v26, v1

    .line 221
    .line 222
    add-int/lit8 v11, v11, 0x1

    .line 223
    .line 224
    move/from16 v15, p1

    .line 225
    .line 226
    move v14, v1

    .line 227
    move/from16 v7, v22

    .line 228
    .line 229
    move-object/from16 v1, v29

    .line 230
    .line 231
    const/4 v5, 0x0

    .line 232
    goto/16 :goto_1

    .line 233
    .line 234
    :cond_8
    move-object/from16 v29, v1

    .line 235
    .line 236
    move/from16 v22, v7

    .line 237
    .line 238
    move v1, v14

    .line 239
    move/from16 p1, v15

    .line 240
    .line 241
    if-ne v10, v1, :cond_12

    .line 242
    .line 243
    move/from16 v15, p1

    .line 244
    .line 245
    goto :goto_8

    .line 246
    :cond_9
    move-object/from16 v29, v1

    .line 247
    .line 248
    move/from16 v22, v7

    .line 249
    .line 250
    :goto_8
    if-eq v6, v15, :cond_12

    .line 251
    .line 252
    add-int/lit8 v6, v6, 0x1

    .line 253
    .line 254
    move-object/from16 v1, v29

    .line 255
    .line 256
    const/4 v5, 0x0

    .line 257
    const/16 v14, 0x8

    .line 258
    .line 259
    goto/16 :goto_0

    .line 260
    .line 261
    :cond_a
    const-wide/16 v16, 0x80

    .line 262
    .line 263
    const-wide/16 v18, 0xff

    .line 264
    .line 265
    const-wide v20, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 266
    .line 267
    .line 268
    .line 269
    .line 270
    const/16 v22, 0x7

    .line 271
    .line 272
    goto/16 :goto_c

    .line 273
    .line 274
    :cond_b
    const-wide/16 v16, 0x80

    .line 275
    .line 276
    const-wide/16 v18, 0xff

    .line 277
    .line 278
    const-wide v20, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 279
    .line 280
    .line 281
    .line 282
    .line 283
    const/16 v22, 0x7

    .line 284
    .line 285
    check-cast v1, Ljava/lang/Iterable;

    .line 286
    .line 287
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 288
    .line 289
    .line 290
    move-result-object v1

    .line 291
    :cond_c
    :goto_9
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 292
    .line 293
    .line 294
    move-result v3

    .line 295
    if-eqz v3, :cond_12

    .line 296
    .line 297
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 298
    .line 299
    .line 300
    move-result-object v3

    .line 301
    instance-of v5, v3, Ll2/u1;

    .line 302
    .line 303
    if-eqz v5, :cond_d

    .line 304
    .line 305
    check-cast v3, Ll2/u1;

    .line 306
    .line 307
    const/4 v5, 0x0

    .line 308
    invoke-virtual {v3, v5}, Ll2/u1;->d(Ljava/lang/Object;)Ll2/s0;

    .line 309
    .line 310
    .line 311
    goto :goto_9

    .line 312
    :cond_d
    const/4 v5, 0x0

    .line 313
    invoke-virtual {v0, v3, v2}, Ll2/a0;->b(Ljava/lang/Object;Z)V

    .line 314
    .line 315
    .line 316
    invoke-virtual {v4, v3}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 317
    .line 318
    .line 319
    move-result-object v3

    .line 320
    if-eqz v3, :cond_c

    .line 321
    .line 322
    instance-of v6, v3, Landroidx/collection/r0;

    .line 323
    .line 324
    if-eqz v6, :cond_11

    .line 325
    .line 326
    check-cast v3, Landroidx/collection/r0;

    .line 327
    .line 328
    iget-object v6, v3, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 329
    .line 330
    iget-object v3, v3, Landroidx/collection/r0;->a:[J

    .line 331
    .line 332
    array-length v7, v3

    .line 333
    add-int/lit8 v7, v7, -0x2

    .line 334
    .line 335
    if-ltz v7, :cond_c

    .line 336
    .line 337
    const/4 v8, 0x0

    .line 338
    :goto_a
    aget-wide v9, v3, v8

    .line 339
    .line 340
    not-long v11, v9

    .line 341
    shl-long v11, v11, v22

    .line 342
    .line 343
    and-long/2addr v11, v9

    .line 344
    and-long v11, v11, v20

    .line 345
    .line 346
    cmp-long v11, v11, v20

    .line 347
    .line 348
    if-eqz v11, :cond_10

    .line 349
    .line 350
    sub-int v11, v8, v7

    .line 351
    .line 352
    not-int v11, v11

    .line 353
    ushr-int/lit8 v11, v11, 0x1f

    .line 354
    .line 355
    const/16 v25, 0x8

    .line 356
    .line 357
    rsub-int/lit8 v14, v11, 0x8

    .line 358
    .line 359
    const/4 v11, 0x0

    .line 360
    :goto_b
    if-ge v11, v14, :cond_f

    .line 361
    .line 362
    and-long v12, v9, v18

    .line 363
    .line 364
    cmp-long v12, v12, v16

    .line 365
    .line 366
    if-gez v12, :cond_e

    .line 367
    .line 368
    shl-int/lit8 v12, v8, 0x3

    .line 369
    .line 370
    add-int/2addr v12, v11

    .line 371
    aget-object v12, v6, v12

    .line 372
    .line 373
    check-cast v12, Ll2/h0;

    .line 374
    .line 375
    invoke-virtual {v0, v12, v2}, Ll2/a0;->b(Ljava/lang/Object;Z)V

    .line 376
    .line 377
    .line 378
    :cond_e
    const/16 v12, 0x8

    .line 379
    .line 380
    shr-long/2addr v9, v12

    .line 381
    add-int/lit8 v11, v11, 0x1

    .line 382
    .line 383
    goto :goto_b

    .line 384
    :cond_f
    const/16 v12, 0x8

    .line 385
    .line 386
    if-ne v14, v12, :cond_c

    .line 387
    .line 388
    :cond_10
    if-eq v8, v7, :cond_c

    .line 389
    .line 390
    add-int/lit8 v8, v8, 0x1

    .line 391
    .line 392
    goto :goto_a

    .line 393
    :cond_11
    check-cast v3, Ll2/h0;

    .line 394
    .line 395
    invoke-virtual {v0, v3, v2}, Ll2/a0;->b(Ljava/lang/Object;Z)V

    .line 396
    .line 397
    .line 398
    goto :goto_9

    .line 399
    :cond_12
    :goto_c
    const-string v1, "null cannot be cast to non-null type Scope of androidx.compose.runtime.collection.ScopeMap"

    .line 400
    .line 401
    iget-object v3, v0, Ll2/a0;->j:Landroidx/collection/q0;

    .line 402
    .line 403
    iget-object v5, v0, Ll2/a0;->k:Landroidx/collection/r0;

    .line 404
    .line 405
    if-eqz v2, :cond_22

    .line 406
    .line 407
    iget-object v2, v0, Ll2/a0;->l:Landroidx/collection/r0;

    .line 408
    .line 409
    invoke-virtual {v2}, Landroidx/collection/r0;->h()Z

    .line 410
    .line 411
    .line 412
    move-result v6

    .line 413
    if-eqz v6, :cond_22

    .line 414
    .line 415
    iget-object v6, v3, Landroidx/collection/q0;->a:[J

    .line 416
    .line 417
    array-length v7, v6

    .line 418
    add-int/lit8 v7, v7, -0x2

    .line 419
    .line 420
    if-ltz v7, :cond_21

    .line 421
    .line 422
    const/4 v8, 0x0

    .line 423
    :goto_d
    aget-wide v9, v6, v8

    .line 424
    .line 425
    not-long v11, v9

    .line 426
    shl-long v11, v11, v22

    .line 427
    .line 428
    and-long/2addr v11, v9

    .line 429
    and-long v11, v11, v20

    .line 430
    .line 431
    cmp-long v11, v11, v20

    .line 432
    .line 433
    if-eqz v11, :cond_20

    .line 434
    .line 435
    sub-int v11, v8, v7

    .line 436
    .line 437
    not-int v11, v11

    .line 438
    ushr-int/lit8 v11, v11, 0x1f

    .line 439
    .line 440
    const/16 v25, 0x8

    .line 441
    .line 442
    rsub-int/lit8 v14, v11, 0x8

    .line 443
    .line 444
    const/4 v11, 0x0

    .line 445
    :goto_e
    if-ge v11, v14, :cond_1f

    .line 446
    .line 447
    and-long v12, v9, v18

    .line 448
    .line 449
    cmp-long v12, v12, v16

    .line 450
    .line 451
    if-gez v12, :cond_1e

    .line 452
    .line 453
    shl-int/lit8 v12, v8, 0x3

    .line 454
    .line 455
    add-int/2addr v12, v11

    .line 456
    iget-object v13, v3, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 457
    .line 458
    aget-object v13, v13, v12

    .line 459
    .line 460
    iget-object v13, v3, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 461
    .line 462
    aget-object v13, v13, v12

    .line 463
    .line 464
    instance-of v15, v13, Landroidx/collection/r0;

    .line 465
    .line 466
    if-eqz v15, :cond_1a

    .line 467
    .line 468
    check-cast v13, Landroidx/collection/r0;

    .line 469
    .line 470
    iget-object v15, v13, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 471
    .line 472
    iget-object v4, v13, Landroidx/collection/r0;->a:[J

    .line 473
    .line 474
    array-length v0, v4

    .line 475
    add-int/lit8 v0, v0, -0x2

    .line 476
    .line 477
    if-ltz v0, :cond_18

    .line 478
    .line 479
    move-object/from16 v24, v4

    .line 480
    .line 481
    move-wide/from16 v26, v9

    .line 482
    .line 483
    const/4 v4, 0x0

    .line 484
    :goto_f
    aget-wide v9, v24, v4

    .line 485
    .line 486
    move-object/from16 v28, v6

    .line 487
    .line 488
    move/from16 p2, v7

    .line 489
    .line 490
    not-long v6, v9

    .line 491
    shl-long v6, v6, v22

    .line 492
    .line 493
    and-long/2addr v6, v9

    .line 494
    and-long v6, v6, v20

    .line 495
    .line 496
    cmp-long v6, v6, v20

    .line 497
    .line 498
    if-eqz v6, :cond_17

    .line 499
    .line 500
    sub-int v6, v4, v0

    .line 501
    .line 502
    not-int v6, v6

    .line 503
    ushr-int/lit8 v6, v6, 0x1f

    .line 504
    .line 505
    const/16 v25, 0x8

    .line 506
    .line 507
    rsub-int/lit8 v6, v6, 0x8

    .line 508
    .line 509
    const/4 v7, 0x0

    .line 510
    :goto_10
    if-ge v7, v6, :cond_16

    .line 511
    .line 512
    and-long v29, v9, v18

    .line 513
    .line 514
    cmp-long v29, v29, v16

    .line 515
    .line 516
    if-gez v29, :cond_15

    .line 517
    .line 518
    shl-int/lit8 v29, v4, 0x3

    .line 519
    .line 520
    move/from16 v30, v7

    .line 521
    .line 522
    add-int v7, v29, v30

    .line 523
    .line 524
    aget-object v29, v15, v7

    .line 525
    .line 526
    move-wide/from16 v31, v9

    .line 527
    .line 528
    move-object/from16 v9, v29

    .line 529
    .line 530
    check-cast v9, Ll2/u1;

    .line 531
    .line 532
    invoke-virtual {v2, v9}, Landroidx/collection/r0;->c(Ljava/lang/Object;)Z

    .line 533
    .line 534
    .line 535
    move-result v10

    .line 536
    if-nez v10, :cond_13

    .line 537
    .line 538
    invoke-virtual {v5, v9}, Landroidx/collection/r0;->c(Ljava/lang/Object;)Z

    .line 539
    .line 540
    .line 541
    move-result v9

    .line 542
    if-eqz v9, :cond_14

    .line 543
    .line 544
    :cond_13
    invoke-virtual {v13, v7}, Landroidx/collection/r0;->m(I)V

    .line 545
    .line 546
    .line 547
    :cond_14
    :goto_11
    const/16 v7, 0x8

    .line 548
    .line 549
    goto :goto_12

    .line 550
    :cond_15
    move/from16 v30, v7

    .line 551
    .line 552
    move-wide/from16 v31, v9

    .line 553
    .line 554
    goto :goto_11

    .line 555
    :goto_12
    shr-long v9, v31, v7

    .line 556
    .line 557
    add-int/lit8 v25, v30, 0x1

    .line 558
    .line 559
    move/from16 v7, v25

    .line 560
    .line 561
    goto :goto_10

    .line 562
    :cond_16
    const/16 v7, 0x8

    .line 563
    .line 564
    if-ne v6, v7, :cond_19

    .line 565
    .line 566
    :cond_17
    if-eq v4, v0, :cond_19

    .line 567
    .line 568
    add-int/lit8 v4, v4, 0x1

    .line 569
    .line 570
    move/from16 v7, p2

    .line 571
    .line 572
    move-object/from16 v6, v28

    .line 573
    .line 574
    goto :goto_f

    .line 575
    :cond_18
    move-object/from16 v28, v6

    .line 576
    .line 577
    move/from16 p2, v7

    .line 578
    .line 579
    move-wide/from16 v26, v9

    .line 580
    .line 581
    :cond_19
    invoke-virtual {v13}, Landroidx/collection/r0;->g()Z

    .line 582
    .line 583
    .line 584
    move-result v0

    .line 585
    goto :goto_14

    .line 586
    :cond_1a
    move-object/from16 v28, v6

    .line 587
    .line 588
    move/from16 p2, v7

    .line 589
    .line 590
    move-wide/from16 v26, v9

    .line 591
    .line 592
    invoke-static {v13, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 593
    .line 594
    .line 595
    check-cast v13, Ll2/u1;

    .line 596
    .line 597
    invoke-virtual {v2, v13}, Landroidx/collection/r0;->c(Ljava/lang/Object;)Z

    .line 598
    .line 599
    .line 600
    move-result v0

    .line 601
    if-nez v0, :cond_1c

    .line 602
    .line 603
    invoke-virtual {v5, v13}, Landroidx/collection/r0;->c(Ljava/lang/Object;)Z

    .line 604
    .line 605
    .line 606
    move-result v0

    .line 607
    if-eqz v0, :cond_1b

    .line 608
    .line 609
    goto :goto_13

    .line 610
    :cond_1b
    const/4 v0, 0x0

    .line 611
    goto :goto_14

    .line 612
    :cond_1c
    :goto_13
    const/4 v0, 0x1

    .line 613
    :goto_14
    if-eqz v0, :cond_1d

    .line 614
    .line 615
    invoke-virtual {v3, v12}, Landroidx/collection/q0;->l(I)Ljava/lang/Object;

    .line 616
    .line 617
    .line 618
    :cond_1d
    :goto_15
    const/16 v7, 0x8

    .line 619
    .line 620
    goto :goto_16

    .line 621
    :cond_1e
    move-object/from16 v28, v6

    .line 622
    .line 623
    move/from16 p2, v7

    .line 624
    .line 625
    move-wide/from16 v26, v9

    .line 626
    .line 627
    goto :goto_15

    .line 628
    :goto_16
    shr-long v9, v26, v7

    .line 629
    .line 630
    add-int/lit8 v11, v11, 0x1

    .line 631
    .line 632
    move-object/from16 v0, p0

    .line 633
    .line 634
    move/from16 v7, p2

    .line 635
    .line 636
    move-object/from16 v6, v28

    .line 637
    .line 638
    goto/16 :goto_e

    .line 639
    .line 640
    :cond_1f
    move-object/from16 v28, v6

    .line 641
    .line 642
    move/from16 p2, v7

    .line 643
    .line 644
    const/16 v7, 0x8

    .line 645
    .line 646
    if-ne v14, v7, :cond_21

    .line 647
    .line 648
    move/from16 v7, p2

    .line 649
    .line 650
    goto :goto_17

    .line 651
    :cond_20
    move-object/from16 v28, v6

    .line 652
    .line 653
    :goto_17
    if-eq v8, v7, :cond_21

    .line 654
    .line 655
    add-int/lit8 v8, v8, 0x1

    .line 656
    .line 657
    move-object/from16 v0, p0

    .line 658
    .line 659
    move-object/from16 v6, v28

    .line 660
    .line 661
    goto/16 :goto_d

    .line 662
    .line 663
    :cond_21
    invoke-virtual {v2}, Landroidx/collection/r0;->b()V

    .line 664
    .line 665
    .line 666
    invoke-virtual/range {p0 .. p0}, Ll2/a0;->h()V

    .line 667
    .line 668
    .line 669
    return-void

    .line 670
    :cond_22
    invoke-virtual {v5}, Landroidx/collection/r0;->h()Z

    .line 671
    .line 672
    .line 673
    move-result v0

    .line 674
    if-eqz v0, :cond_31

    .line 675
    .line 676
    iget-object v0, v3, Landroidx/collection/q0;->a:[J

    .line 677
    .line 678
    array-length v2, v0

    .line 679
    add-int/lit8 v2, v2, -0x2

    .line 680
    .line 681
    if-ltz v2, :cond_30

    .line 682
    .line 683
    const/4 v4, 0x0

    .line 684
    :goto_18
    aget-wide v6, v0, v4

    .line 685
    .line 686
    not-long v8, v6

    .line 687
    shl-long v8, v8, v22

    .line 688
    .line 689
    and-long/2addr v8, v6

    .line 690
    and-long v8, v8, v20

    .line 691
    .line 692
    cmp-long v8, v8, v20

    .line 693
    .line 694
    if-eqz v8, :cond_2f

    .line 695
    .line 696
    sub-int v8, v4, v2

    .line 697
    .line 698
    not-int v8, v8

    .line 699
    ushr-int/lit8 v8, v8, 0x1f

    .line 700
    .line 701
    const/16 v25, 0x8

    .line 702
    .line 703
    rsub-int/lit8 v14, v8, 0x8

    .line 704
    .line 705
    const/4 v8, 0x0

    .line 706
    :goto_19
    if-ge v8, v14, :cond_2e

    .line 707
    .line 708
    and-long v9, v6, v18

    .line 709
    .line 710
    cmp-long v9, v9, v16

    .line 711
    .line 712
    if-gez v9, :cond_23

    .line 713
    .line 714
    const/4 v9, 0x1

    .line 715
    goto :goto_1a

    .line 716
    :cond_23
    const/4 v9, 0x0

    .line 717
    :goto_1a
    if-eqz v9, :cond_2d

    .line 718
    .line 719
    shl-int/lit8 v9, v4, 0x3

    .line 720
    .line 721
    add-int/2addr v9, v8

    .line 722
    iget-object v10, v3, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 723
    .line 724
    aget-object v10, v10, v9

    .line 725
    .line 726
    iget-object v10, v3, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 727
    .line 728
    aget-object v10, v10, v9

    .line 729
    .line 730
    instance-of v11, v10, Landroidx/collection/r0;

    .line 731
    .line 732
    if-eqz v11, :cond_2b

    .line 733
    .line 734
    check-cast v10, Landroidx/collection/r0;

    .line 735
    .line 736
    iget-object v11, v10, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 737
    .line 738
    iget-object v12, v10, Landroidx/collection/r0;->a:[J

    .line 739
    .line 740
    array-length v13, v12

    .line 741
    add-int/lit8 v13, v13, -0x2

    .line 742
    .line 743
    if-ltz v13, :cond_29

    .line 744
    .line 745
    move-wide/from16 v26, v6

    .line 746
    .line 747
    const/4 v15, 0x0

    .line 748
    :goto_1b
    aget-wide v6, v12, v15

    .line 749
    .line 750
    move-object/from16 v24, v11

    .line 751
    .line 752
    move-object/from16 v28, v12

    .line 753
    .line 754
    not-long v11, v6

    .line 755
    shl-long v11, v11, v22

    .line 756
    .line 757
    and-long/2addr v11, v6

    .line 758
    and-long v11, v11, v20

    .line 759
    .line 760
    cmp-long v11, v11, v20

    .line 761
    .line 762
    if-eqz v11, :cond_28

    .line 763
    .line 764
    sub-int v11, v15, v13

    .line 765
    .line 766
    not-int v11, v11

    .line 767
    ushr-int/lit8 v11, v11, 0x1f

    .line 768
    .line 769
    const/16 v25, 0x8

    .line 770
    .line 771
    rsub-int/lit8 v11, v11, 0x8

    .line 772
    .line 773
    const/4 v12, 0x0

    .line 774
    :goto_1c
    if-ge v12, v11, :cond_27

    .line 775
    .line 776
    and-long v29, v6, v18

    .line 777
    .line 778
    cmp-long v29, v29, v16

    .line 779
    .line 780
    if-gez v29, :cond_24

    .line 781
    .line 782
    const/16 v29, 0x1

    .line 783
    .line 784
    goto :goto_1d

    .line 785
    :cond_24
    const/16 v29, 0x0

    .line 786
    .line 787
    :goto_1d
    if-eqz v29, :cond_26

    .line 788
    .line 789
    shl-int/lit8 v29, v15, 0x3

    .line 790
    .line 791
    move-object/from16 v30, v0

    .line 792
    .line 793
    add-int v0, v29, v12

    .line 794
    .line 795
    aget-object v29, v24, v0

    .line 796
    .line 797
    move-wide/from16 v31, v6

    .line 798
    .line 799
    move-object/from16 v6, v29

    .line 800
    .line 801
    check-cast v6, Ll2/u1;

    .line 802
    .line 803
    invoke-virtual {v5, v6}, Landroidx/collection/r0;->c(Ljava/lang/Object;)Z

    .line 804
    .line 805
    .line 806
    move-result v6

    .line 807
    if-eqz v6, :cond_25

    .line 808
    .line 809
    invoke-virtual {v10, v0}, Landroidx/collection/r0;->m(I)V

    .line 810
    .line 811
    .line 812
    :cond_25
    :goto_1e
    const/16 v7, 0x8

    .line 813
    .line 814
    goto :goto_1f

    .line 815
    :cond_26
    move-object/from16 v30, v0

    .line 816
    .line 817
    move-wide/from16 v31, v6

    .line 818
    .line 819
    goto :goto_1e

    .line 820
    :goto_1f
    shr-long v31, v31, v7

    .line 821
    .line 822
    add-int/lit8 v12, v12, 0x1

    .line 823
    .line 824
    move-object/from16 v0, v30

    .line 825
    .line 826
    move-wide/from16 v6, v31

    .line 827
    .line 828
    goto :goto_1c

    .line 829
    :cond_27
    move-object/from16 v30, v0

    .line 830
    .line 831
    const/16 v7, 0x8

    .line 832
    .line 833
    if-ne v11, v7, :cond_2a

    .line 834
    .line 835
    goto :goto_20

    .line 836
    :cond_28
    move-object/from16 v30, v0

    .line 837
    .line 838
    :goto_20
    if-eq v15, v13, :cond_2a

    .line 839
    .line 840
    add-int/lit8 v15, v15, 0x1

    .line 841
    .line 842
    move-object/from16 v11, v24

    .line 843
    .line 844
    move-object/from16 v12, v28

    .line 845
    .line 846
    move-object/from16 v0, v30

    .line 847
    .line 848
    goto :goto_1b

    .line 849
    :cond_29
    move-object/from16 v30, v0

    .line 850
    .line 851
    move-wide/from16 v26, v6

    .line 852
    .line 853
    :cond_2a
    invoke-virtual {v10}, Landroidx/collection/r0;->g()Z

    .line 854
    .line 855
    .line 856
    move-result v0

    .line 857
    goto :goto_21

    .line 858
    :cond_2b
    move-object/from16 v30, v0

    .line 859
    .line 860
    move-wide/from16 v26, v6

    .line 861
    .line 862
    invoke-static {v10, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 863
    .line 864
    .line 865
    check-cast v10, Ll2/u1;

    .line 866
    .line 867
    invoke-virtual {v5, v10}, Landroidx/collection/r0;->c(Ljava/lang/Object;)Z

    .line 868
    .line 869
    .line 870
    move-result v0

    .line 871
    :goto_21
    if-eqz v0, :cond_2c

    .line 872
    .line 873
    invoke-virtual {v3, v9}, Landroidx/collection/q0;->l(I)Ljava/lang/Object;

    .line 874
    .line 875
    .line 876
    :cond_2c
    :goto_22
    const/16 v7, 0x8

    .line 877
    .line 878
    goto :goto_23

    .line 879
    :cond_2d
    move-object/from16 v30, v0

    .line 880
    .line 881
    move-wide/from16 v26, v6

    .line 882
    .line 883
    goto :goto_22

    .line 884
    :goto_23
    shr-long v9, v26, v7

    .line 885
    .line 886
    add-int/lit8 v8, v8, 0x1

    .line 887
    .line 888
    move-wide v6, v9

    .line 889
    move-object/from16 v0, v30

    .line 890
    .line 891
    goto/16 :goto_19

    .line 892
    .line 893
    :cond_2e
    move-object/from16 v30, v0

    .line 894
    .line 895
    const/16 v7, 0x8

    .line 896
    .line 897
    if-ne v14, v7, :cond_30

    .line 898
    .line 899
    goto :goto_24

    .line 900
    :cond_2f
    move-object/from16 v30, v0

    .line 901
    .line 902
    const/16 v7, 0x8

    .line 903
    .line 904
    :goto_24
    if-eq v4, v2, :cond_30

    .line 905
    .line 906
    add-int/lit8 v4, v4, 0x1

    .line 907
    .line 908
    move-object/from16 v0, v30

    .line 909
    .line 910
    goto/16 :goto_18

    .line 911
    .line 912
    :cond_30
    invoke-virtual/range {p0 .. p0}, Ll2/a0;->h()V

    .line 913
    .line 914
    .line 915
    invoke-virtual {v5}, Landroidx/collection/r0;->b()V

    .line 916
    .line 917
    .line 918
    :cond_31
    return-void
.end method

.method public final d()V
    .locals 5

    .line 1
    iget-object v0, p0, Ll2/a0;->g:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Ll2/a0;->n:Lm2/a;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Ll2/a0;->e(Lm2/a;)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0}, Ll2/a0;->n()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    .line 11
    .line 12
    monitor-exit v0

    .line 13
    return-void

    .line 14
    :catchall_0
    move-exception v1

    .line 15
    :try_start_1
    iget-object v2, p0, Ll2/a0;->h:Landroidx/collection/t0;

    .line 16
    .line 17
    iget-object v2, v2, Landroidx/collection/t0;->d:Landroidx/collection/r0;

    .line 18
    .line 19
    invoke-virtual {v2}, Landroidx/collection/r0;->g()Z

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    if-nez v2, :cond_0

    .line 24
    .line 25
    iget-object v2, p0, Ll2/a0;->x:Ljp/uf;

    .line 26
    .line 27
    iget-object v3, p0, Ll2/a0;->h:Landroidx/collection/t0;

    .line 28
    .line 29
    iget-object v4, p0, Ll2/a0;->y:Ll2/t;

    .line 30
    .line 31
    invoke-virtual {v4}, Ll2/t;->z()Lw2/b;

    .line 32
    .line 33
    .line 34
    move-result-object v4
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 35
    :try_start_2
    invoke-virtual {v2, v3, v4}, Ljp/uf;->g(Ljava/util/Set;Lw2/b;)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {v2}, Ljp/uf;->b()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 39
    .line 40
    .line 41
    :try_start_3
    invoke-virtual {v2}, Ljp/uf;->a()V

    .line 42
    .line 43
    .line 44
    goto :goto_0

    .line 45
    :catchall_1
    move-exception v1

    .line 46
    goto :goto_1

    .line 47
    :catchall_2
    move-exception v1

    .line 48
    invoke-virtual {v2}, Ljp/uf;->a()V

    .line 49
    .line 50
    .line 51
    throw v1

    .line 52
    :cond_0
    :goto_0
    throw v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 53
    :goto_1
    :try_start_4
    invoke-virtual {p0}, Ll2/a0;->a()V

    .line 54
    .line 55
    .line 56
    throw v1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_3

    .line 57
    :catchall_3
    move-exception p0

    .line 58
    monitor-exit v0

    .line 59
    throw p0
.end method

.method public final dispose()V
    .locals 9

    .line 1
    iget-object v0, p0, Ll2/a0;->g:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Ll2/a0;->y:Ll2/t;

    .line 5
    .line 6
    iget-boolean v1, v1, Ll2/t;->F:Z

    .line 7
    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    const-string v1, "Composition is disposed while composing. If dispose is triggered by a call in @Composable function, consider wrapping it with SideEffect block."

    .line 11
    .line 12
    invoke-static {v1}, Ll2/q1;->b(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    goto :goto_0

    .line 16
    :catchall_0
    move-exception p0

    .line 17
    goto/16 :goto_5

    .line 18
    .line 19
    :cond_0
    :goto_0
    iget v1, p0, Ll2/a0;->z:I

    .line 20
    .line 21
    const/4 v2, 0x3

    .line 22
    if-eq v1, v2, :cond_6

    .line 23
    .line 24
    iput v2, p0, Ll2/a0;->z:I

    .line 25
    .line 26
    sget-object v1, Ll2/i;->b:Lt2/b;

    .line 27
    .line 28
    iput-object v1, p0, Ll2/a0;->A:Lay0/n;

    .line 29
    .line 30
    iget-object v1, p0, Ll2/a0;->y:Ll2/t;

    .line 31
    .line 32
    iget-object v1, v1, Ll2/t;->L:Lm2/a;

    .line 33
    .line 34
    if-eqz v1, :cond_1

    .line 35
    .line 36
    invoke-virtual {p0, v1}, Ll2/a0;->e(Lm2/a;)V

    .line 37
    .line 38
    .line 39
    :cond_1
    iget-object v1, p0, Ll2/a0;->i:Ll2/f2;

    .line 40
    .line 41
    iget v1, v1, Ll2/f2;->e:I

    .line 42
    .line 43
    const/4 v2, 0x0

    .line 44
    const/4 v3, 0x1

    .line 45
    if-lez v1, :cond_2

    .line 46
    .line 47
    move v1, v3

    .line 48
    goto :goto_1

    .line 49
    :cond_2
    move v1, v2

    .line 50
    :goto_1
    if-nez v1, :cond_3

    .line 51
    .line 52
    iget-object v4, p0, Ll2/a0;->h:Landroidx/collection/t0;

    .line 53
    .line 54
    iget-object v4, v4, Landroidx/collection/t0;->d:Landroidx/collection/r0;

    .line 55
    .line 56
    invoke-virtual {v4}, Landroidx/collection/r0;->g()Z

    .line 57
    .line 58
    .line 59
    move-result v4

    .line 60
    if-nez v4, :cond_5

    .line 61
    .line 62
    :cond_3
    iget-object v4, p0, Ll2/a0;->x:Ljp/uf;

    .line 63
    .line 64
    iget-object v5, p0, Ll2/a0;->h:Landroidx/collection/t0;

    .line 65
    .line 66
    iget-object v6, p0, Ll2/a0;->y:Ll2/t;

    .line 67
    .line 68
    invoke-virtual {v6}, Ll2/t;->z()Lw2/b;

    .line 69
    .line 70
    .line 71
    move-result-object v6
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 72
    :try_start_1
    invoke-virtual {v4, v5, v6}, Ljp/uf;->g(Ljava/util/Set;Lw2/b;)V

    .line 73
    .line 74
    .line 75
    if-eqz v1, :cond_4

    .line 76
    .line 77
    iget-object v1, p0, Ll2/a0;->i:Ll2/f2;

    .line 78
    .line 79
    invoke-virtual {v1}, Ll2/f2;->i()Ll2/i2;

    .line 80
    .line 81
    .line 82
    move-result-object v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 83
    :try_start_2
    iget-object v5, p0, Ll2/a0;->x:Ljp/uf;

    .line 84
    .line 85
    iget v6, v1, Ll2/i2;->t:I

    .line 86
    .line 87
    new-instance v7, Lh2/y5;

    .line 88
    .line 89
    const/16 v8, 0x1a

    .line 90
    .line 91
    invoke-direct {v7, v5, v8}, Lh2/y5;-><init>(Ljava/lang/Object;I)V

    .line 92
    .line 93
    .line 94
    invoke-virtual {v1, v6, v7}, Ll2/i2;->n(ILay0/n;)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {v1}, Ll2/i2;->G()Z
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 98
    .line 99
    .line 100
    :try_start_3
    invoke-virtual {v1, v3}, Ll2/i2;->e(Z)V

    .line 101
    .line 102
    .line 103
    iget-object v1, p0, Ll2/a0;->e:Leb/j0;

    .line 104
    .line 105
    invoke-virtual {v1}, Leb/j0;->r()V

    .line 106
    .line 107
    .line 108
    iget-object v1, p0, Ll2/a0;->e:Leb/j0;

    .line 109
    .line 110
    invoke-interface {v1}, Ll2/c;->f()V

    .line 111
    .line 112
    .line 113
    invoke-virtual {v4}, Ljp/uf;->c()V

    .line 114
    .line 115
    .line 116
    goto :goto_2

    .line 117
    :catchall_1
    move-exception p0

    .line 118
    goto :goto_3

    .line 119
    :catchall_2
    move-exception p0

    .line 120
    invoke-virtual {v1, v2}, Ll2/i2;->e(Z)V

    .line 121
    .line 122
    .line 123
    throw p0

    .line 124
    :cond_4
    :goto_2
    invoke-virtual {v4}, Ljp/uf;->b()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 125
    .line 126
    .line 127
    :try_start_4
    invoke-virtual {v4}, Ljp/uf;->a()V

    .line 128
    .line 129
    .line 130
    :cond_5
    iget-object v1, p0, Ll2/a0;->y:Ll2/t;

    .line 131
    .line 132
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 133
    .line 134
    .line 135
    const-string v2, "Compose:Composer.dispose"

    .line 136
    .line 137
    invoke-static {v2}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 138
    .line 139
    .line 140
    :try_start_5
    iget-object v2, v1, Ll2/t;->b:Ll2/x;

    .line 141
    .line 142
    invoke-virtual {v2, v1}, Ll2/x;->s(Ll2/o;)V

    .line 143
    .line 144
    .line 145
    iget-object v2, v1, Ll2/t;->E:Ljava/util/ArrayList;

    .line 146
    .line 147
    invoke-virtual {v2}, Ljava/util/ArrayList;->clear()V

    .line 148
    .line 149
    .line 150
    iget-object v2, v1, Ll2/t;->s:Ljava/util/ArrayList;

    .line 151
    .line 152
    invoke-virtual {v2}, Ljava/util/ArrayList;->clear()V

    .line 153
    .line 154
    .line 155
    iget-object v2, v1, Ll2/t;->e:Lm2/a;

    .line 156
    .line 157
    iget-object v2, v2, Lm2/a;->b:Lm2/l0;

    .line 158
    .line 159
    invoke-virtual {v2}, Lm2/l0;->d()V

    .line 160
    .line 161
    .line 162
    const/4 v2, 0x0

    .line 163
    iput-object v2, v1, Ll2/t;->v:Landroidx/collection/b0;

    .line 164
    .line 165
    iget-object v1, v1, Ll2/t;->a:Leb/j0;

    .line 166
    .line 167
    invoke-virtual {v1}, Leb/j0;->r()V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    .line 168
    .line 169
    .line 170
    :try_start_6
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 171
    .line 172
    .line 173
    goto :goto_4

    .line 174
    :catchall_3
    move-exception p0

    .line 175
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 176
    .line 177
    .line 178
    throw p0

    .line 179
    :goto_3
    invoke-virtual {v4}, Ljp/uf;->a()V

    .line 180
    .line 181
    .line 182
    throw p0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 183
    :cond_6
    :goto_4
    monitor-exit v0

    .line 184
    iget-object v0, p0, Ll2/a0;->d:Ll2/x;

    .line 185
    .line 186
    invoke-virtual {v0, p0}, Ll2/x;->t(Ll2/a0;)V

    .line 187
    .line 188
    .line 189
    return-void

    .line 190
    :goto_5
    monitor-exit v0

    .line 191
    throw p0
.end method

.method public final e(Lm2/a;)V
    .locals 33

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v0, p1

    .line 4
    .line 5
    iget-object v2, v1, Ll2/a0;->o:Lm2/a;

    .line 6
    .line 7
    iget-object v3, v1, Ll2/a0;->y:Ll2/t;

    .line 8
    .line 9
    invoke-virtual {v3}, Ll2/t;->z()Lw2/b;

    .line 10
    .line 11
    .line 12
    move-result-object v4

    .line 13
    iget-object v5, v1, Ll2/a0;->x:Ljp/uf;

    .line 14
    .line 15
    iget-object v6, v1, Ll2/a0;->h:Landroidx/collection/t0;

    .line 16
    .line 17
    invoke-virtual {v5, v6, v4}, Ljp/uf;->g(Ljava/util/Set;Lw2/b;)V

    .line 18
    .line 19
    .line 20
    :try_start_0
    iget-object v4, v0, Lm2/a;->b:Lm2/l0;

    .line 21
    .line 22
    invoke-virtual {v4}, Lm2/l0;->f()Z

    .line 23
    .line 24
    .line 25
    move-result v4
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_5

    .line 26
    if-eqz v4, :cond_1

    .line 27
    .line 28
    :try_start_1
    iget-object v0, v2, Lm2/a;->b:Lm2/l0;

    .line 29
    .line 30
    invoke-virtual {v0}, Lm2/l0;->f()Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-eqz v0, :cond_0

    .line 35
    .line 36
    iget-object v0, v1, Ll2/a0;->t:Ll2/m1;

    .line 37
    .line 38
    if-nez v0, :cond_0

    .line 39
    .line 40
    invoke-virtual {v5}, Ljp/uf;->b()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 41
    .line 42
    .line 43
    goto :goto_0

    .line 44
    :catchall_0
    move-exception v0

    .line 45
    goto :goto_1

    .line 46
    :cond_0
    :goto_0
    invoke-virtual {v5}, Ljp/uf;->a()V

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    :goto_1
    invoke-virtual {v5}, Ljp/uf;->a()V

    .line 51
    .line 52
    .line 53
    throw v0

    .line 54
    :cond_1
    :try_start_2
    const-string v4, "Compose:applyChanges"

    .line 55
    .line 56
    invoke-static {v4}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_5

    .line 57
    .line 58
    .line 59
    :try_start_3
    iget-object v4, v1, Ll2/a0;->t:Ll2/m1;

    .line 60
    .line 61
    if-eqz v4, :cond_2

    .line 62
    .line 63
    iget-object v6, v4, Ll2/m1;->k:Lil/g;

    .line 64
    .line 65
    if-eqz v6, :cond_2

    .line 66
    .line 67
    goto :goto_2

    .line 68
    :catchall_1
    move-exception v0

    .line 69
    move-object/from16 v26, v5

    .line 70
    .line 71
    goto/16 :goto_f

    .line 72
    .line 73
    :cond_2
    iget-object v6, v1, Ll2/a0;->e:Leb/j0;

    .line 74
    .line 75
    :goto_2
    if-eqz v4, :cond_3

    .line 76
    .line 77
    iget-object v4, v4, Ll2/m1;->j:Ljp/uf;

    .line 78
    .line 79
    if-nez v4, :cond_4

    .line 80
    .line 81
    :cond_3
    move-object v4, v5

    .line 82
    :cond_4
    iget-object v7, v1, Ll2/a0;->i:Ll2/f2;

    .line 83
    .line 84
    invoke-virtual {v7}, Ll2/f2;->i()Ll2/i2;

    .line 85
    .line 86
    .line 87
    move-result-object v7
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 88
    const/4 v8, 0x0

    .line 89
    :try_start_4
    invoke-virtual {v3}, Ll2/t;->z()Lw2/b;

    .line 90
    .line 91
    .line 92
    move-result-object v3

    .line 93
    invoke-virtual {v0, v6, v7, v4, v3}, Lm2/a;->d(Ll2/c;Ll2/i2;Ljp/uf;Lm2/k0;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_7

    .line 94
    .line 95
    .line 96
    const/4 v0, 0x1

    .line 97
    :try_start_5
    invoke-virtual {v7, v0}, Ll2/i2;->e(Z)V

    .line 98
    .line 99
    .line 100
    invoke-interface {v6}, Ll2/c;->f()V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 101
    .line 102
    .line 103
    :try_start_6
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 104
    .line 105
    .line 106
    invoke-virtual {v5}, Ljp/uf;->c()V

    .line 107
    .line 108
    .line 109
    invoke-virtual {v5}, Ljp/uf;->d()V

    .line 110
    .line 111
    .line 112
    iget-boolean v3, v1, Ll2/a0;->r:Z

    .line 113
    .line 114
    if-eqz v3, :cond_13

    .line 115
    .line 116
    const-string v3, "Compose:unobserve"

    .line 117
    .line 118
    invoke-static {v3}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_5

    .line 119
    .line 120
    .line 121
    :try_start_7
    iput-boolean v8, v1, Ll2/a0;->r:Z

    .line 122
    .line 123
    iget-object v3, v1, Ll2/a0;->j:Landroidx/collection/q0;

    .line 124
    .line 125
    iget-object v4, v3, Landroidx/collection/q0;->a:[J

    .line 126
    .line 127
    array-length v6, v4

    .line 128
    add-int/lit8 v6, v6, -0x2

    .line 129
    .line 130
    if-ltz v6, :cond_11

    .line 131
    .line 132
    move v7, v8

    .line 133
    :goto_3
    aget-wide v9, v4, v7

    .line 134
    .line 135
    not-long v11, v9

    .line 136
    const/4 v13, 0x7

    .line 137
    shl-long/2addr v11, v13

    .line 138
    and-long/2addr v11, v9

    .line 139
    const-wide v14, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 140
    .line 141
    .line 142
    .line 143
    .line 144
    and-long/2addr v11, v14

    .line 145
    cmp-long v11, v11, v14

    .line 146
    .line 147
    if-eqz v11, :cond_10

    .line 148
    .line 149
    sub-int v11, v7, v6

    .line 150
    .line 151
    not-int v11, v11

    .line 152
    ushr-int/lit8 v11, v11, 0x1f

    .line 153
    .line 154
    const/16 v12, 0x8

    .line 155
    .line 156
    rsub-int/lit8 v11, v11, 0x8

    .line 157
    .line 158
    move v0, v8

    .line 159
    :goto_4
    if-ge v0, v11, :cond_f

    .line 160
    .line 161
    const-wide/16 v16, 0xff

    .line 162
    .line 163
    and-long v18, v9, v16

    .line 164
    .line 165
    const-wide/16 v20, 0x80

    .line 166
    .line 167
    cmp-long v18, v18, v20

    .line 168
    .line 169
    if-gez v18, :cond_e

    .line 170
    .line 171
    shl-int/lit8 v18, v7, 0x3

    .line 172
    .line 173
    move/from16 v19, v13

    .line 174
    .line 175
    add-int v13, v18, v0

    .line 176
    .line 177
    move-wide/from16 v22, v14

    .line 178
    .line 179
    iget-object v14, v3, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 180
    .line 181
    aget-object v14, v14, v13

    .line 182
    .line 183
    iget-object v14, v3, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 184
    .line 185
    aget-object v14, v14, v13

    .line 186
    .line 187
    instance-of v15, v14, Landroidx/collection/r0;

    .line 188
    .line 189
    if-eqz v15, :cond_b

    .line 190
    .line 191
    check-cast v14, Landroidx/collection/r0;

    .line 192
    .line 193
    iget-object v15, v14, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 194
    .line 195
    iget-object v8, v14, Landroidx/collection/r0;->a:[J

    .line 196
    .line 197
    move/from16 v24, v12

    .line 198
    .line 199
    array-length v12, v8
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_3

    .line 200
    add-int/lit8 v12, v12, -0x2

    .line 201
    .line 202
    move/from16 v25, v0

    .line 203
    .line 204
    move-object/from16 v27, v4

    .line 205
    .line 206
    move-object/from16 v26, v5

    .line 207
    .line 208
    if-ltz v12, :cond_9

    .line 209
    .line 210
    const/4 v0, 0x0

    .line 211
    :goto_5
    :try_start_8
    aget-wide v4, v8, v0

    .line 212
    .line 213
    move-wide/from16 v28, v9

    .line 214
    .line 215
    move-object v10, v8

    .line 216
    not-long v8, v4

    .line 217
    shl-long v8, v8, v19

    .line 218
    .line 219
    and-long/2addr v8, v4

    .line 220
    and-long v8, v8, v22

    .line 221
    .line 222
    cmp-long v8, v8, v22

    .line 223
    .line 224
    if-eqz v8, :cond_8

    .line 225
    .line 226
    sub-int v8, v0, v12

    .line 227
    .line 228
    not-int v8, v8

    .line 229
    ushr-int/lit8 v8, v8, 0x1f

    .line 230
    .line 231
    rsub-int/lit8 v8, v8, 0x8

    .line 232
    .line 233
    const/4 v9, 0x0

    .line 234
    :goto_6
    if-ge v9, v8, :cond_7

    .line 235
    .line 236
    and-long v30, v4, v16

    .line 237
    .line 238
    cmp-long v30, v30, v20

    .line 239
    .line 240
    if-gez v30, :cond_5

    .line 241
    .line 242
    shl-int/lit8 v30, v0, 0x3

    .line 243
    .line 244
    move-wide/from16 v31, v4

    .line 245
    .line 246
    add-int v4, v30, v9

    .line 247
    .line 248
    aget-object v5, v15, v4

    .line 249
    .line 250
    check-cast v5, Ll2/u1;

    .line 251
    .line 252
    invoke-virtual {v5}, Ll2/u1;->b()Z

    .line 253
    .line 254
    .line 255
    move-result v5

    .line 256
    if-nez v5, :cond_6

    .line 257
    .line 258
    invoke-virtual {v14, v4}, Landroidx/collection/r0;->m(I)V

    .line 259
    .line 260
    .line 261
    goto :goto_7

    .line 262
    :catchall_2
    move-exception v0

    .line 263
    goto/16 :goto_b

    .line 264
    .line 265
    :cond_5
    move-wide/from16 v31, v4

    .line 266
    .line 267
    :cond_6
    :goto_7
    shr-long v4, v31, v24

    .line 268
    .line 269
    add-int/lit8 v9, v9, 0x1

    .line 270
    .line 271
    goto :goto_6

    .line 272
    :cond_7
    move/from16 v4, v24

    .line 273
    .line 274
    if-ne v8, v4, :cond_a

    .line 275
    .line 276
    :cond_8
    if-eq v0, v12, :cond_a

    .line 277
    .line 278
    add-int/lit8 v0, v0, 0x1

    .line 279
    .line 280
    move-object v8, v10

    .line 281
    move-wide/from16 v9, v28

    .line 282
    .line 283
    const/16 v24, 0x8

    .line 284
    .line 285
    goto :goto_5

    .line 286
    :cond_9
    move-wide/from16 v28, v9

    .line 287
    .line 288
    :cond_a
    invoke-virtual {v14}, Landroidx/collection/r0;->g()Z

    .line 289
    .line 290
    .line 291
    move-result v0

    .line 292
    goto :goto_8

    .line 293
    :catchall_3
    move-exception v0

    .line 294
    move-object/from16 v26, v5

    .line 295
    .line 296
    goto/16 :goto_b

    .line 297
    .line 298
    :cond_b
    move/from16 v25, v0

    .line 299
    .line 300
    move-object/from16 v27, v4

    .line 301
    .line 302
    move-object/from16 v26, v5

    .line 303
    .line 304
    move-wide/from16 v28, v9

    .line 305
    .line 306
    const-string v0, "null cannot be cast to non-null type Scope of androidx.compose.runtime.collection.ScopeMap"

    .line 307
    .line 308
    invoke-static {v14, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 309
    .line 310
    .line 311
    check-cast v14, Ll2/u1;

    .line 312
    .line 313
    invoke-virtual {v14}, Ll2/u1;->b()Z

    .line 314
    .line 315
    .line 316
    move-result v0

    .line 317
    if-nez v0, :cond_c

    .line 318
    .line 319
    const/4 v0, 0x1

    .line 320
    goto :goto_8

    .line 321
    :cond_c
    const/4 v0, 0x0

    .line 322
    :goto_8
    if-eqz v0, :cond_d

    .line 323
    .line 324
    invoke-virtual {v3, v13}, Landroidx/collection/q0;->l(I)Ljava/lang/Object;

    .line 325
    .line 326
    .line 327
    :cond_d
    const/16 v4, 0x8

    .line 328
    .line 329
    goto :goto_9

    .line 330
    :cond_e
    move/from16 v25, v0

    .line 331
    .line 332
    move-object/from16 v27, v4

    .line 333
    .line 334
    move-object/from16 v26, v5

    .line 335
    .line 336
    move-wide/from16 v28, v9

    .line 337
    .line 338
    move/from16 v19, v13

    .line 339
    .line 340
    move-wide/from16 v22, v14

    .line 341
    .line 342
    move v4, v12

    .line 343
    :goto_9
    shr-long v9, v28, v4

    .line 344
    .line 345
    add-int/lit8 v0, v25, 0x1

    .line 346
    .line 347
    move v12, v4

    .line 348
    move/from16 v13, v19

    .line 349
    .line 350
    move-wide/from16 v14, v22

    .line 351
    .line 352
    move-object/from16 v5, v26

    .line 353
    .line 354
    move-object/from16 v4, v27

    .line 355
    .line 356
    const/4 v8, 0x0

    .line 357
    goto/16 :goto_4

    .line 358
    .line 359
    :cond_f
    move-object/from16 v27, v4

    .line 360
    .line 361
    move-object/from16 v26, v5

    .line 362
    .line 363
    move v4, v12

    .line 364
    if-ne v11, v4, :cond_12

    .line 365
    .line 366
    goto :goto_a

    .line 367
    :cond_10
    move-object/from16 v27, v4

    .line 368
    .line 369
    move-object/from16 v26, v5

    .line 370
    .line 371
    :goto_a
    if-eq v7, v6, :cond_12

    .line 372
    .line 373
    add-int/lit8 v7, v7, 0x1

    .line 374
    .line 375
    move-object/from16 v5, v26

    .line 376
    .line 377
    move-object/from16 v4, v27

    .line 378
    .line 379
    const/4 v0, 0x1

    .line 380
    const/4 v8, 0x0

    .line 381
    goto/16 :goto_3

    .line 382
    .line 383
    :cond_11
    move-object/from16 v26, v5

    .line 384
    .line 385
    :cond_12
    invoke-virtual {v1}, Ll2/a0;->h()V
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_2

    .line 386
    .line 387
    .line 388
    :try_start_9
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 389
    .line 390
    .line 391
    goto :goto_c

    .line 392
    :catchall_4
    move-exception v0

    .line 393
    goto :goto_10

    .line 394
    :goto_b
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 395
    .line 396
    .line 397
    throw v0
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_4

    .line 398
    :catchall_5
    move-exception v0

    .line 399
    move-object/from16 v26, v5

    .line 400
    .line 401
    goto :goto_10

    .line 402
    :cond_13
    move-object/from16 v26, v5

    .line 403
    .line 404
    :goto_c
    :try_start_a
    iget-object v0, v2, Lm2/a;->b:Lm2/l0;

    .line 405
    .line 406
    invoke-virtual {v0}, Lm2/l0;->f()Z

    .line 407
    .line 408
    .line 409
    move-result v0

    .line 410
    if-eqz v0, :cond_14

    .line 411
    .line 412
    iget-object v0, v1, Ll2/a0;->t:Ll2/m1;

    .line 413
    .line 414
    if-nez v0, :cond_14

    .line 415
    .line 416
    invoke-virtual/range {v26 .. v26}, Ljp/uf;->b()V
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_6

    .line 417
    .line 418
    .line 419
    goto :goto_d

    .line 420
    :catchall_6
    move-exception v0

    .line 421
    goto :goto_e

    .line 422
    :cond_14
    :goto_d
    invoke-virtual/range {v26 .. v26}, Ljp/uf;->a()V

    .line 423
    .line 424
    .line 425
    return-void

    .line 426
    :goto_e
    invoke-virtual/range {v26 .. v26}, Ljp/uf;->a()V

    .line 427
    .line 428
    .line 429
    throw v0

    .line 430
    :catchall_7
    move-exception v0

    .line 431
    move-object/from16 v26, v5

    .line 432
    .line 433
    const/4 v3, 0x0

    .line 434
    :try_start_b
    invoke-virtual {v7, v3}, Ll2/i2;->e(Z)V

    .line 435
    .line 436
    .line 437
    throw v0
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_8

    .line 438
    :catchall_8
    move-exception v0

    .line 439
    :goto_f
    :try_start_c
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 440
    .line 441
    .line 442
    throw v0
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_4

    .line 443
    :goto_10
    :try_start_d
    iget-object v2, v2, Lm2/a;->b:Lm2/l0;

    .line 444
    .line 445
    invoke-virtual {v2}, Lm2/l0;->f()Z

    .line 446
    .line 447
    .line 448
    move-result v2

    .line 449
    if-eqz v2, :cond_15

    .line 450
    .line 451
    iget-object v1, v1, Ll2/a0;->t:Ll2/m1;

    .line 452
    .line 453
    if-nez v1, :cond_15

    .line 454
    .line 455
    invoke-virtual/range {v26 .. v26}, Ljp/uf;->b()V
    :try_end_d
    .catchall {:try_start_d .. :try_end_d} :catchall_9

    .line 456
    .line 457
    .line 458
    goto :goto_11

    .line 459
    :catchall_9
    move-exception v0

    .line 460
    goto :goto_12

    .line 461
    :cond_15
    :goto_11
    invoke-virtual/range {v26 .. v26}, Ljp/uf;->a()V

    .line 462
    .line 463
    .line 464
    throw v0

    .line 465
    :goto_12
    invoke-virtual/range {v26 .. v26}, Ljp/uf;->a()V

    .line 466
    .line 467
    .line 468
    throw v0
.end method

.method public final f()V
    .locals 5

    .line 1
    iget-object v0, p0, Ll2/a0;->g:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Ll2/a0;->o:Lm2/a;

    .line 5
    .line 6
    iget-object v1, v1, Lm2/a;->b:Lm2/l0;

    .line 7
    .line 8
    invoke-virtual {v1}, Lm2/l0;->g()Z

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    iget-object v1, p0, Ll2/a0;->o:Lm2/a;

    .line 15
    .line 16
    invoke-virtual {p0, v1}, Ll2/a0;->e(Lm2/a;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 17
    .line 18
    .line 19
    goto :goto_0

    .line 20
    :catchall_0
    move-exception v1

    .line 21
    goto :goto_1

    .line 22
    :cond_0
    :goto_0
    monitor-exit v0

    .line 23
    return-void

    .line 24
    :goto_1
    :try_start_1
    iget-object v2, p0, Ll2/a0;->h:Landroidx/collection/t0;

    .line 25
    .line 26
    iget-object v2, v2, Landroidx/collection/t0;->d:Landroidx/collection/r0;

    .line 27
    .line 28
    invoke-virtual {v2}, Landroidx/collection/r0;->g()Z

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    if-nez v2, :cond_1

    .line 33
    .line 34
    iget-object v2, p0, Ll2/a0;->x:Ljp/uf;

    .line 35
    .line 36
    iget-object v3, p0, Ll2/a0;->h:Landroidx/collection/t0;

    .line 37
    .line 38
    iget-object v4, p0, Ll2/a0;->y:Ll2/t;

    .line 39
    .line 40
    invoke-virtual {v4}, Ll2/t;->z()Lw2/b;

    .line 41
    .line 42
    .line 43
    move-result-object v4
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 44
    :try_start_2
    invoke-virtual {v2, v3, v4}, Ljp/uf;->g(Ljava/util/Set;Lw2/b;)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {v2}, Ljp/uf;->b()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 48
    .line 49
    .line 50
    :try_start_3
    invoke-virtual {v2}, Ljp/uf;->a()V

    .line 51
    .line 52
    .line 53
    goto :goto_2

    .line 54
    :catchall_1
    move-exception v1

    .line 55
    goto :goto_3

    .line 56
    :catchall_2
    move-exception v1

    .line 57
    invoke-virtual {v2}, Ljp/uf;->a()V

    .line 58
    .line 59
    .line 60
    throw v1

    .line 61
    :cond_1
    :goto_2
    throw v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 62
    :goto_3
    :try_start_4
    invoke-virtual {p0}, Ll2/a0;->a()V

    .line 63
    .line 64
    .line 65
    throw v1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_3

    .line 66
    :catchall_3
    move-exception p0

    .line 67
    monitor-exit v0

    .line 68
    throw p0
.end method

.method public final g()V
    .locals 5

    .line 1
    iget-object v0, p0, Ll2/a0;->g:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Ll2/a0;->y:Ll2/t;

    .line 5
    .line 6
    const/4 v2, 0x0

    .line 7
    iput-object v2, v1, Ll2/t;->v:Landroidx/collection/b0;

    .line 8
    .line 9
    iget-object v1, p0, Ll2/a0;->h:Landroidx/collection/t0;

    .line 10
    .line 11
    iget-object v1, v1, Landroidx/collection/t0;->d:Landroidx/collection/r0;

    .line 12
    .line 13
    invoke-virtual {v1}, Landroidx/collection/r0;->g()Z

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    if-nez v1, :cond_0

    .line 18
    .line 19
    iget-object v1, p0, Ll2/a0;->x:Ljp/uf;

    .line 20
    .line 21
    iget-object v2, p0, Ll2/a0;->h:Landroidx/collection/t0;

    .line 22
    .line 23
    iget-object v3, p0, Ll2/a0;->y:Ll2/t;

    .line 24
    .line 25
    invoke-virtual {v3}, Ll2/t;->z()Lw2/b;

    .line 26
    .line 27
    .line 28
    move-result-object v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 29
    :try_start_1
    invoke-virtual {v1, v2, v3}, Ljp/uf;->g(Ljava/util/Set;Lw2/b;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v1}, Ljp/uf;->b()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 33
    .line 34
    .line 35
    :try_start_2
    invoke-virtual {v1}, Ljp/uf;->a()V

    .line 36
    .line 37
    .line 38
    goto :goto_0

    .line 39
    :catchall_0
    move-exception v1

    .line 40
    goto :goto_1

    .line 41
    :catchall_1
    move-exception v2

    .line 42
    invoke-virtual {v1}, Ljp/uf;->a()V

    .line 43
    .line 44
    .line 45
    throw v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 46
    :cond_0
    :goto_0
    monitor-exit v0

    .line 47
    return-void

    .line 48
    :goto_1
    :try_start_3
    iget-object v2, p0, Ll2/a0;->h:Landroidx/collection/t0;

    .line 49
    .line 50
    iget-object v2, v2, Landroidx/collection/t0;->d:Landroidx/collection/r0;

    .line 51
    .line 52
    invoke-virtual {v2}, Landroidx/collection/r0;->g()Z

    .line 53
    .line 54
    .line 55
    move-result v2

    .line 56
    if-nez v2, :cond_1

    .line 57
    .line 58
    iget-object v2, p0, Ll2/a0;->x:Ljp/uf;

    .line 59
    .line 60
    iget-object v3, p0, Ll2/a0;->h:Landroidx/collection/t0;

    .line 61
    .line 62
    iget-object v4, p0, Ll2/a0;->y:Ll2/t;

    .line 63
    .line 64
    invoke-virtual {v4}, Ll2/t;->z()Lw2/b;

    .line 65
    .line 66
    .line 67
    move-result-object v4
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 68
    :try_start_4
    invoke-virtual {v2, v3, v4}, Ljp/uf;->g(Ljava/util/Set;Lw2/b;)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {v2}, Ljp/uf;->b()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_3

    .line 72
    .line 73
    .line 74
    :try_start_5
    invoke-virtual {v2}, Ljp/uf;->a()V

    .line 75
    .line 76
    .line 77
    goto :goto_2

    .line 78
    :catchall_2
    move-exception v1

    .line 79
    goto :goto_3

    .line 80
    :catchall_3
    move-exception v1

    .line 81
    invoke-virtual {v2}, Ljp/uf;->a()V

    .line 82
    .line 83
    .line 84
    throw v1

    .line 85
    :cond_1
    :goto_2
    throw v1
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 86
    :goto_3
    :try_start_6
    invoke-virtual {p0}, Ll2/a0;->a()V

    .line 87
    .line 88
    .line 89
    throw v1
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_4

    .line 90
    :catchall_4
    move-exception p0

    .line 91
    monitor-exit v0

    .line 92
    throw p0
.end method

.method public final h()V
    .locals 33

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Ll2/a0;->m:Landroidx/collection/q0;

    .line 4
    .line 5
    iget-object v2, v1, Landroidx/collection/q0;->a:[J

    .line 6
    .line 7
    array-length v3, v2

    .line 8
    add-int/lit8 v3, v3, -0x2

    .line 9
    .line 10
    const/4 v8, 0x7

    .line 11
    const-wide v9, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 12
    .line 13
    .line 14
    .line 15
    .line 16
    const/16 v12, 0x8

    .line 17
    .line 18
    if-ltz v3, :cond_c

    .line 19
    .line 20
    const/4 v14, 0x0

    .line 21
    const-wide/16 v15, 0x80

    .line 22
    .line 23
    :goto_0
    aget-wide v4, v2, v14

    .line 24
    .line 25
    const-wide/16 v17, 0xff

    .line 26
    .line 27
    not-long v6, v4

    .line 28
    shl-long/2addr v6, v8

    .line 29
    and-long/2addr v6, v4

    .line 30
    and-long/2addr v6, v9

    .line 31
    cmp-long v6, v6, v9

    .line 32
    .line 33
    if-eqz v6, :cond_b

    .line 34
    .line 35
    sub-int v6, v14, v3

    .line 36
    .line 37
    not-int v6, v6

    .line 38
    ushr-int/lit8 v6, v6, 0x1f

    .line 39
    .line 40
    rsub-int/lit8 v6, v6, 0x8

    .line 41
    .line 42
    const/4 v7, 0x0

    .line 43
    :goto_1
    if-ge v7, v6, :cond_a

    .line 44
    .line 45
    and-long v19, v4, v17

    .line 46
    .line 47
    cmp-long v19, v19, v15

    .line 48
    .line 49
    if-gez v19, :cond_9

    .line 50
    .line 51
    shl-int/lit8 v19, v14, 0x3

    .line 52
    .line 53
    move/from16 v20, v8

    .line 54
    .line 55
    add-int v8, v19, v7

    .line 56
    .line 57
    move-wide/from16 v21, v9

    .line 58
    .line 59
    iget-object v9, v1, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 60
    .line 61
    aget-object v9, v9, v8

    .line 62
    .line 63
    iget-object v9, v1, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 64
    .line 65
    aget-object v9, v9, v8

    .line 66
    .line 67
    instance-of v10, v9, Landroidx/collection/r0;

    .line 68
    .line 69
    iget-object v11, v0, Ll2/a0;->j:Landroidx/collection/q0;

    .line 70
    .line 71
    if-eqz v10, :cond_6

    .line 72
    .line 73
    check-cast v9, Landroidx/collection/r0;

    .line 74
    .line 75
    iget-object v10, v9, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 76
    .line 77
    iget-object v13, v9, Landroidx/collection/r0;->a:[J

    .line 78
    .line 79
    move-wide/from16 v23, v15

    .line 80
    .line 81
    array-length v15, v13

    .line 82
    add-int/lit8 v15, v15, -0x2

    .line 83
    .line 84
    if-ltz v15, :cond_4

    .line 85
    .line 86
    move-wide/from16 v25, v4

    .line 87
    .line 88
    move/from16 v16, v12

    .line 89
    .line 90
    const/4 v12, 0x0

    .line 91
    :goto_2
    aget-wide v4, v13, v12

    .line 92
    .line 93
    move-object/from16 v27, v2

    .line 94
    .line 95
    move/from16 v28, v3

    .line 96
    .line 97
    not-long v2, v4

    .line 98
    shl-long v2, v2, v20

    .line 99
    .line 100
    and-long/2addr v2, v4

    .line 101
    and-long v2, v2, v21

    .line 102
    .line 103
    cmp-long v2, v2, v21

    .line 104
    .line 105
    if-eqz v2, :cond_3

    .line 106
    .line 107
    sub-int v2, v12, v15

    .line 108
    .line 109
    not-int v2, v2

    .line 110
    ushr-int/lit8 v2, v2, 0x1f

    .line 111
    .line 112
    rsub-int/lit8 v2, v2, 0x8

    .line 113
    .line 114
    const/4 v3, 0x0

    .line 115
    :goto_3
    if-ge v3, v2, :cond_2

    .line 116
    .line 117
    and-long v29, v4, v17

    .line 118
    .line 119
    cmp-long v29, v29, v23

    .line 120
    .line 121
    if-gez v29, :cond_0

    .line 122
    .line 123
    shl-int/lit8 v29, v12, 0x3

    .line 124
    .line 125
    move/from16 v30, v3

    .line 126
    .line 127
    add-int v3, v29, v30

    .line 128
    .line 129
    aget-object v29, v10, v3

    .line 130
    .line 131
    move-wide/from16 v31, v4

    .line 132
    .line 133
    move-object/from16 v4, v29

    .line 134
    .line 135
    check-cast v4, Ll2/h0;

    .line 136
    .line 137
    invoke-virtual {v11, v4}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 138
    .line 139
    .line 140
    move-result v4

    .line 141
    if-nez v4, :cond_1

    .line 142
    .line 143
    invoke-virtual {v9, v3}, Landroidx/collection/r0;->m(I)V

    .line 144
    .line 145
    .line 146
    goto :goto_4

    .line 147
    :cond_0
    move/from16 v30, v3

    .line 148
    .line 149
    move-wide/from16 v31, v4

    .line 150
    .line 151
    :cond_1
    :goto_4
    shr-long v4, v31, v16

    .line 152
    .line 153
    add-int/lit8 v3, v30, 0x1

    .line 154
    .line 155
    goto :goto_3

    .line 156
    :cond_2
    move/from16 v3, v16

    .line 157
    .line 158
    if-ne v2, v3, :cond_5

    .line 159
    .line 160
    :cond_3
    if-eq v12, v15, :cond_5

    .line 161
    .line 162
    add-int/lit8 v12, v12, 0x1

    .line 163
    .line 164
    move-object/from16 v2, v27

    .line 165
    .line 166
    move/from16 v3, v28

    .line 167
    .line 168
    const/16 v16, 0x8

    .line 169
    .line 170
    goto :goto_2

    .line 171
    :cond_4
    move-object/from16 v27, v2

    .line 172
    .line 173
    move/from16 v28, v3

    .line 174
    .line 175
    move-wide/from16 v25, v4

    .line 176
    .line 177
    :cond_5
    invoke-virtual {v9}, Landroidx/collection/r0;->g()Z

    .line 178
    .line 179
    .line 180
    move-result v2

    .line 181
    goto :goto_5

    .line 182
    :cond_6
    move-object/from16 v27, v2

    .line 183
    .line 184
    move/from16 v28, v3

    .line 185
    .line 186
    move-wide/from16 v25, v4

    .line 187
    .line 188
    move-wide/from16 v23, v15

    .line 189
    .line 190
    const-string v2, "null cannot be cast to non-null type Scope of androidx.compose.runtime.collection.ScopeMap"

    .line 191
    .line 192
    invoke-static {v9, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 193
    .line 194
    .line 195
    check-cast v9, Ll2/h0;

    .line 196
    .line 197
    invoke-virtual {v11, v9}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 198
    .line 199
    .line 200
    move-result v2

    .line 201
    if-nez v2, :cond_7

    .line 202
    .line 203
    const/4 v2, 0x1

    .line 204
    goto :goto_5

    .line 205
    :cond_7
    const/4 v2, 0x0

    .line 206
    :goto_5
    if-eqz v2, :cond_8

    .line 207
    .line 208
    invoke-virtual {v1, v8}, Landroidx/collection/q0;->l(I)Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    :cond_8
    const/16 v3, 0x8

    .line 212
    .line 213
    goto :goto_6

    .line 214
    :cond_9
    move-object/from16 v27, v2

    .line 215
    .line 216
    move/from16 v28, v3

    .line 217
    .line 218
    move-wide/from16 v25, v4

    .line 219
    .line 220
    move/from16 v20, v8

    .line 221
    .line 222
    move-wide/from16 v21, v9

    .line 223
    .line 224
    move-wide/from16 v23, v15

    .line 225
    .line 226
    move v3, v12

    .line 227
    :goto_6
    shr-long v4, v25, v3

    .line 228
    .line 229
    add-int/lit8 v7, v7, 0x1

    .line 230
    .line 231
    move v12, v3

    .line 232
    move/from16 v8, v20

    .line 233
    .line 234
    move-wide/from16 v9, v21

    .line 235
    .line 236
    move-wide/from16 v15, v23

    .line 237
    .line 238
    move-object/from16 v2, v27

    .line 239
    .line 240
    move/from16 v3, v28

    .line 241
    .line 242
    goto/16 :goto_1

    .line 243
    .line 244
    :cond_a
    move-object/from16 v27, v2

    .line 245
    .line 246
    move/from16 v28, v3

    .line 247
    .line 248
    move/from16 v20, v8

    .line 249
    .line 250
    move-wide/from16 v21, v9

    .line 251
    .line 252
    move v3, v12

    .line 253
    move-wide/from16 v23, v15

    .line 254
    .line 255
    if-ne v6, v3, :cond_d

    .line 256
    .line 257
    move/from16 v3, v28

    .line 258
    .line 259
    goto :goto_7

    .line 260
    :cond_b
    move-object/from16 v27, v2

    .line 261
    .line 262
    move/from16 v20, v8

    .line 263
    .line 264
    move-wide/from16 v21, v9

    .line 265
    .line 266
    move-wide/from16 v23, v15

    .line 267
    .line 268
    :goto_7
    if-eq v14, v3, :cond_d

    .line 269
    .line 270
    add-int/lit8 v14, v14, 0x1

    .line 271
    .line 272
    move/from16 v8, v20

    .line 273
    .line 274
    move-wide/from16 v9, v21

    .line 275
    .line 276
    move-wide/from16 v15, v23

    .line 277
    .line 278
    move-object/from16 v2, v27

    .line 279
    .line 280
    const/16 v12, 0x8

    .line 281
    .line 282
    goto/16 :goto_0

    .line 283
    .line 284
    :cond_c
    move/from16 v20, v8

    .line 285
    .line 286
    move-wide/from16 v21, v9

    .line 287
    .line 288
    const-wide/16 v17, 0xff

    .line 289
    .line 290
    const-wide/16 v23, 0x80

    .line 291
    .line 292
    :cond_d
    iget-object v0, v0, Ll2/a0;->l:Landroidx/collection/r0;

    .line 293
    .line 294
    invoke-virtual {v0}, Landroidx/collection/r0;->h()Z

    .line 295
    .line 296
    .line 297
    move-result v1

    .line 298
    if-eqz v1, :cond_13

    .line 299
    .line 300
    iget-object v1, v0, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 301
    .line 302
    iget-object v2, v0, Landroidx/collection/r0;->a:[J

    .line 303
    .line 304
    array-length v3, v2

    .line 305
    add-int/lit8 v3, v3, -0x2

    .line 306
    .line 307
    if-ltz v3, :cond_13

    .line 308
    .line 309
    const/4 v4, 0x0

    .line 310
    :goto_8
    aget-wide v5, v2, v4

    .line 311
    .line 312
    not-long v7, v5

    .line 313
    shl-long v7, v7, v20

    .line 314
    .line 315
    and-long/2addr v7, v5

    .line 316
    and-long v7, v7, v21

    .line 317
    .line 318
    cmp-long v7, v7, v21

    .line 319
    .line 320
    if-eqz v7, :cond_12

    .line 321
    .line 322
    sub-int v7, v4, v3

    .line 323
    .line 324
    not-int v7, v7

    .line 325
    ushr-int/lit8 v7, v7, 0x1f

    .line 326
    .line 327
    const/16 v16, 0x8

    .line 328
    .line 329
    rsub-int/lit8 v12, v7, 0x8

    .line 330
    .line 331
    const/4 v7, 0x0

    .line 332
    :goto_9
    if-ge v7, v12, :cond_11

    .line 333
    .line 334
    and-long v8, v5, v17

    .line 335
    .line 336
    cmp-long v8, v8, v23

    .line 337
    .line 338
    if-gez v8, :cond_e

    .line 339
    .line 340
    const/4 v8, 0x1

    .line 341
    goto :goto_a

    .line 342
    :cond_e
    const/4 v8, 0x0

    .line 343
    :goto_a
    if-eqz v8, :cond_10

    .line 344
    .line 345
    shl-int/lit8 v8, v4, 0x3

    .line 346
    .line 347
    add-int/2addr v8, v7

    .line 348
    aget-object v9, v1, v8

    .line 349
    .line 350
    check-cast v9, Ll2/u1;

    .line 351
    .line 352
    iget-object v9, v9, Ll2/u1;->g:Landroidx/collection/q0;

    .line 353
    .line 354
    if-eqz v9, :cond_f

    .line 355
    .line 356
    const/4 v9, 0x1

    .line 357
    goto :goto_b

    .line 358
    :cond_f
    const/4 v9, 0x0

    .line 359
    :goto_b
    if-nez v9, :cond_10

    .line 360
    .line 361
    invoke-virtual {v0, v8}, Landroidx/collection/r0;->m(I)V

    .line 362
    .line 363
    .line 364
    :cond_10
    const/16 v8, 0x8

    .line 365
    .line 366
    shr-long/2addr v5, v8

    .line 367
    add-int/lit8 v7, v7, 0x1

    .line 368
    .line 369
    goto :goto_9

    .line 370
    :cond_11
    const/16 v8, 0x8

    .line 371
    .line 372
    if-ne v12, v8, :cond_13

    .line 373
    .line 374
    goto :goto_c

    .line 375
    :cond_12
    const/16 v8, 0x8

    .line 376
    .line 377
    :goto_c
    if-eq v4, v3, :cond_13

    .line 378
    .line 379
    add-int/lit8 v4, v4, 0x1

    .line 380
    .line 381
    goto :goto_8

    .line 382
    :cond_13
    return-void
.end method

.method public final i()Z
    .locals 4

    .line 1
    iget-object v0, p0, Ll2/a0;->g:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget v1, p0, Ll2/a0;->z:I

    .line 5
    .line 6
    const/4 v2, 0x0

    .line 7
    const/4 v3, 0x1

    .line 8
    if-ne v1, v3, :cond_0

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    move v3, v2

    .line 12
    :goto_0
    if-eqz v3, :cond_1

    .line 13
    .line 14
    iput v2, p0, Ll2/a0;->z:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 15
    .line 16
    goto :goto_1

    .line 17
    :catchall_0
    move-exception p0

    .line 18
    goto :goto_2

    .line 19
    :cond_1
    :goto_1
    monitor-exit v0

    .line 20
    return v3

    .line 21
    :goto_2
    monitor-exit v0

    .line 22
    throw p0
.end method

.method public final j(Lay0/n;)V
    .locals 5

    .line 1
    :try_start_0
    iget-object v0, p0, Ll2/a0;->g:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 4
    :try_start_1
    invoke-virtual {p0}, Ll2/a0;->m()V

    .line 5
    .line 6
    .line 7
    iget-object v1, p0, Ll2/a0;->q:Landroidx/collection/q0;

    .line 8
    .line 9
    invoke-static {}, Ljp/v1;->b()Landroidx/collection/q0;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    iput-object v2, p0, Ll2/a0;->q:Landroidx/collection/q0;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_3

    .line 14
    .line 15
    :try_start_2
    iget-object v2, p0, Ll2/a0;->y:Ll2/t;

    .line 16
    .line 17
    iget-object v3, p0, Ll2/a0;->s:Lt0/c;

    .line 18
    .line 19
    iget-object v4, v2, Ll2/t;->e:Lm2/a;

    .line 20
    .line 21
    iget-object v4, v4, Lm2/a;->b:Lm2/l0;

    .line 22
    .line 23
    invoke-virtual {v4}, Lm2/l0;->f()Z

    .line 24
    .line 25
    .line 26
    move-result v4

    .line 27
    if-nez v4, :cond_0

    .line 28
    .line 29
    const-string v4, "Expected applyChanges() to have been called"

    .line 30
    .line 31
    invoke-static {v4}, Ll2/v;->c(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    :cond_0
    iput-object v3, v2, Ll2/t;->P:Lt0/c;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 35
    .line 36
    const/4 v3, 0x0

    .line 37
    :try_start_3
    invoke-virtual {v2, v1, p1}, Ll2/t;->o(Landroidx/collection/q0;Lay0/n;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 38
    .line 39
    .line 40
    :try_start_4
    iput-object v3, v2, Ll2/t;->P:Lt0/c;
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 41
    .line 42
    :try_start_5
    monitor-exit v0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 43
    return-void

    .line 44
    :catchall_0
    move-exception p1

    .line 45
    goto :goto_0

    .line 46
    :catchall_1
    move-exception p1

    .line 47
    :try_start_6
    iput-object v3, v2, Ll2/t;->P:Lt0/c;

    .line 48
    .line 49
    throw p1
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 50
    :catchall_2
    move-exception p1

    .line 51
    :try_start_7
    iput-object v1, p0, Ll2/a0;->q:Landroidx/collection/q0;

    .line 52
    .line 53
    throw p1
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_3

    .line 54
    :catchall_3
    move-exception p1

    .line 55
    :try_start_8
    monitor-exit v0

    .line 56
    throw p1
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_0

    .line 57
    :goto_0
    :try_start_9
    iget-object v0, p0, Ll2/a0;->h:Landroidx/collection/t0;

    .line 58
    .line 59
    iget-object v0, v0, Landroidx/collection/t0;->d:Landroidx/collection/r0;

    .line 60
    .line 61
    invoke-virtual {v0}, Landroidx/collection/r0;->g()Z

    .line 62
    .line 63
    .line 64
    move-result v0

    .line 65
    if-nez v0, :cond_1

    .line 66
    .line 67
    iget-object v0, p0, Ll2/a0;->x:Ljp/uf;

    .line 68
    .line 69
    iget-object v1, p0, Ll2/a0;->h:Landroidx/collection/t0;

    .line 70
    .line 71
    iget-object v2, p0, Ll2/a0;->y:Ll2/t;

    .line 72
    .line 73
    invoke-virtual {v2}, Ll2/t;->z()Lw2/b;

    .line 74
    .line 75
    .line 76
    move-result-object v2
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_4

    .line 77
    :try_start_a
    invoke-virtual {v0, v1, v2}, Ljp/uf;->g(Ljava/util/Set;Lw2/b;)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {v0}, Ljp/uf;->b()V
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_5

    .line 81
    .line 82
    .line 83
    :try_start_b
    invoke-virtual {v0}, Ljp/uf;->a()V

    .line 84
    .line 85
    .line 86
    goto :goto_1

    .line 87
    :catchall_4
    move-exception p1

    .line 88
    goto :goto_2

    .line 89
    :catchall_5
    move-exception p1

    .line 90
    invoke-virtual {v0}, Ljp/uf;->a()V

    .line 91
    .line 92
    .line 93
    throw p1

    .line 94
    :cond_1
    :goto_1
    throw p1
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_4

    .line 95
    :goto_2
    invoke-virtual {p0}, Ll2/a0;->a()V

    .line 96
    .line 97
    .line 98
    throw p1
.end method

.method public final k(ZLay0/n;)Ll2/m1;
    .locals 10

    .line 1
    iget-object v0, p0, Ll2/a0;->t:Ll2/m1;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    const-string v0, "A pausable composition is in progress"

    .line 7
    .line 8
    invoke-static {v0}, Ll2/q1;->b(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    :goto_0
    new-instance v1, Ll2/m1;

    .line 12
    .line 13
    iget-object v3, p0, Ll2/a0;->d:Ll2/x;

    .line 14
    .line 15
    iget-object v4, p0, Ll2/a0;->y:Ll2/t;

    .line 16
    .line 17
    iget-object v5, p0, Ll2/a0;->h:Landroidx/collection/t0;

    .line 18
    .line 19
    iget-object v8, p0, Ll2/a0;->e:Leb/j0;

    .line 20
    .line 21
    iget-object v9, p0, Ll2/a0;->g:Ljava/lang/Object;

    .line 22
    .line 23
    move-object v2, p0

    .line 24
    move v7, p1

    .line 25
    move-object v6, p2

    .line 26
    invoke-direct/range {v1 .. v9}, Ll2/m1;-><init>(Ll2/a0;Ll2/x;Ll2/t;Landroidx/collection/t0;Lay0/n;ZLeb/j0;Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    iput-object v1, v2, Ll2/a0;->t:Ll2/m1;

    .line 30
    .line 31
    return-object v1
.end method

.method public final l()V
    .locals 9

    .line 1
    iget-object v0, p0, Ll2/a0;->g:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Ll2/a0;->t:Ll2/m1;

    .line 5
    .line 6
    if-nez v1, :cond_0

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    const-string v1, "Deactivate is not supported while pausable composition is in progress"

    .line 10
    .line 11
    invoke-static {v1}, Ll2/q1;->b(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    :goto_0
    iget-object v1, p0, Ll2/a0;->i:Ll2/f2;

    .line 15
    .line 16
    iget v1, v1, Ll2/f2;->e:I

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    const/4 v3, 0x1

    .line 20
    if-lez v1, :cond_1

    .line 21
    .line 22
    move v1, v3

    .line 23
    goto :goto_1

    .line 24
    :cond_1
    move v1, v2

    .line 25
    :goto_1
    if-nez v1, :cond_2

    .line 26
    .line 27
    iget-object v4, p0, Ll2/a0;->h:Landroidx/collection/t0;

    .line 28
    .line 29
    iget-object v4, v4, Landroidx/collection/t0;->d:Landroidx/collection/r0;

    .line 30
    .line 31
    invoke-virtual {v4}, Landroidx/collection/r0;->g()Z

    .line 32
    .line 33
    .line 34
    move-result v4

    .line 35
    if-nez v4, :cond_4

    .line 36
    .line 37
    goto :goto_2

    .line 38
    :catchall_0
    move-exception p0

    .line 39
    goto/16 :goto_6

    .line 40
    .line 41
    :cond_2
    :goto_2
    const-string v4, "Compose:deactivate"

    .line 42
    .line 43
    invoke-static {v4}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 44
    .line 45
    .line 46
    :try_start_1
    iget-object v4, p0, Ll2/a0;->x:Ljp/uf;

    .line 47
    .line 48
    iget-object v5, p0, Ll2/a0;->h:Landroidx/collection/t0;

    .line 49
    .line 50
    iget-object v6, p0, Ll2/a0;->y:Ll2/t;

    .line 51
    .line 52
    invoke-virtual {v6}, Ll2/t;->z()Lw2/b;

    .line 53
    .line 54
    .line 55
    move-result-object v6
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_3

    .line 56
    :try_start_2
    invoke-virtual {v4, v5, v6}, Ljp/uf;->g(Ljava/util/Set;Lw2/b;)V

    .line 57
    .line 58
    .line 59
    if-eqz v1, :cond_3

    .line 60
    .line 61
    iget-object v1, p0, Ll2/a0;->i:Ll2/f2;

    .line 62
    .line 63
    invoke-virtual {v1}, Ll2/f2;->i()Ll2/i2;

    .line 64
    .line 65
    .line 66
    move-result-object v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 67
    :try_start_3
    iget-object v5, p0, Ll2/a0;->x:Ljp/uf;

    .line 68
    .line 69
    iget v6, v1, Ll2/i2;->t:I

    .line 70
    .line 71
    new-instance v7, Ll2/u;

    .line 72
    .line 73
    const/4 v8, 0x0

    .line 74
    invoke-direct {v7, v8, v5, v1}, Ll2/u;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {v1, v6, v7}, Ll2/i2;->n(ILay0/n;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 78
    .line 79
    .line 80
    :try_start_4
    invoke-virtual {v1, v3}, Ll2/i2;->e(Z)V

    .line 81
    .line 82
    .line 83
    iget-object v1, p0, Ll2/a0;->e:Leb/j0;

    .line 84
    .line 85
    invoke-interface {v1}, Ll2/c;->f()V

    .line 86
    .line 87
    .line 88
    invoke-virtual {v4}, Ljp/uf;->c()V

    .line 89
    .line 90
    .line 91
    goto :goto_3

    .line 92
    :catchall_1
    move-exception p0

    .line 93
    goto :goto_4

    .line 94
    :catchall_2
    move-exception p0

    .line 95
    invoke-virtual {v1, v2}, Ll2/i2;->e(Z)V

    .line 96
    .line 97
    .line 98
    throw p0

    .line 99
    :cond_3
    :goto_3
    invoke-virtual {v4}, Ljp/uf;->b()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 100
    .line 101
    .line 102
    :try_start_5
    invoke-virtual {v4}, Ljp/uf;->a()V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    .line 103
    .line 104
    .line 105
    :try_start_6
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 106
    .line 107
    .line 108
    :cond_4
    iget-object v1, p0, Ll2/a0;->j:Landroidx/collection/q0;

    .line 109
    .line 110
    invoke-virtual {v1}, Landroidx/collection/q0;->a()V

    .line 111
    .line 112
    .line 113
    iget-object v1, p0, Ll2/a0;->m:Landroidx/collection/q0;

    .line 114
    .line 115
    invoke-virtual {v1}, Landroidx/collection/q0;->a()V

    .line 116
    .line 117
    .line 118
    iget-object v1, p0, Ll2/a0;->q:Landroidx/collection/q0;

    .line 119
    .line 120
    invoke-virtual {v1}, Landroidx/collection/q0;->a()V

    .line 121
    .line 122
    .line 123
    iget-object v1, p0, Ll2/a0;->n:Lm2/a;

    .line 124
    .line 125
    iget-object v1, v1, Lm2/a;->b:Lm2/l0;

    .line 126
    .line 127
    invoke-virtual {v1}, Lm2/l0;->d()V

    .line 128
    .line 129
    .line 130
    iget-object v1, p0, Ll2/a0;->o:Lm2/a;

    .line 131
    .line 132
    iget-object v1, v1, Lm2/a;->b:Lm2/l0;

    .line 133
    .line 134
    invoke-virtual {v1}, Lm2/l0;->d()V

    .line 135
    .line 136
    .line 137
    iget-object v1, p0, Ll2/a0;->y:Ll2/t;

    .line 138
    .line 139
    iget-object v2, v1, Ll2/t;->E:Ljava/util/ArrayList;

    .line 140
    .line 141
    invoke-virtual {v2}, Ljava/util/ArrayList;->clear()V

    .line 142
    .line 143
    .line 144
    iget-object v2, v1, Ll2/t;->s:Ljava/util/ArrayList;

    .line 145
    .line 146
    invoke-virtual {v2}, Ljava/util/ArrayList;->clear()V

    .line 147
    .line 148
    .line 149
    iget-object v2, v1, Ll2/t;->e:Lm2/a;

    .line 150
    .line 151
    iget-object v2, v2, Lm2/a;->b:Lm2/l0;

    .line 152
    .line 153
    invoke-virtual {v2}, Lm2/l0;->d()V

    .line 154
    .line 155
    .line 156
    const/4 v2, 0x0

    .line 157
    iput-object v2, v1, Ll2/t;->v:Landroidx/collection/b0;

    .line 158
    .line 159
    iput v3, p0, Ll2/a0;->z:I
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 160
    .line 161
    monitor-exit v0

    .line 162
    return-void

    .line 163
    :catchall_3
    move-exception p0

    .line 164
    goto :goto_5

    .line 165
    :goto_4
    :try_start_7
    invoke-virtual {v4}, Ljp/uf;->a()V

    .line 166
    .line 167
    .line 168
    throw p0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_3

    .line 169
    :goto_5
    :try_start_8
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 170
    .line 171
    .line 172
    throw p0
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_0

    .line 173
    :goto_6
    monitor-exit v0

    .line 174
    throw p0
.end method

.method public final m()V
    .locals 5

    .line 1
    iget-object v0, p0, Ll2/a0;->f:Ljava/util/concurrent/atomic/AtomicReference;

    .line 2
    .line 3
    sget-object v1, Ll2/b;->a:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicReference;->getAndSet(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    if-eqz v2, :cond_3

    .line 10
    .line 11
    invoke-virtual {v2, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-nez v1, :cond_2

    .line 16
    .line 17
    instance-of v1, v2, Ljava/util/Set;

    .line 18
    .line 19
    const/4 v3, 0x1

    .line 20
    if-eqz v1, :cond_0

    .line 21
    .line 22
    check-cast v2, Ljava/util/Set;

    .line 23
    .line 24
    invoke-virtual {p0, v2, v3}, Ll2/a0;->c(Ljava/util/Set;Z)V

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    :cond_0
    instance-of v1, v2, [Ljava/lang/Object;

    .line 29
    .line 30
    if-eqz v1, :cond_1

    .line 31
    .line 32
    check-cast v2, [Ljava/util/Set;

    .line 33
    .line 34
    array-length v0, v2

    .line 35
    const/4 v1, 0x0

    .line 36
    :goto_0
    if-ge v1, v0, :cond_3

    .line 37
    .line 38
    aget-object v4, v2, v1

    .line 39
    .line 40
    invoke-virtual {p0, v4, v3}, Ll2/a0;->c(Ljava/util/Set;Z)V

    .line 41
    .line 42
    .line 43
    add-int/lit8 v1, v1, 0x1

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_1
    new-instance p0, Ljava/lang/StringBuilder;

    .line 47
    .line 48
    const-string v1, "corrupt pendingModifications drain: "

    .line 49
    .line 50
    invoke-direct {p0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    invoke-static {p0}, Ll2/v;->d(Ljava/lang/String;)Ljava/lang/Void;

    .line 61
    .line 62
    .line 63
    new-instance p0, La8/r0;

    .line 64
    .line 65
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 66
    .line 67
    .line 68
    throw p0

    .line 69
    :cond_2
    const-string p0, "pending composition has not been applied"

    .line 70
    .line 71
    invoke-static {p0}, Ll2/v;->d(Ljava/lang/String;)Ljava/lang/Void;

    .line 72
    .line 73
    .line 74
    new-instance p0, La8/r0;

    .line 75
    .line 76
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 77
    .line 78
    .line 79
    throw p0

    .line 80
    :cond_3
    return-void
.end method

.method public final n()V
    .locals 5

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Ll2/a0;->f:Ljava/util/concurrent/atomic/AtomicReference;

    .line 3
    .line 4
    invoke-virtual {v1, v0}, Ljava/util/concurrent/atomic/AtomicReference;->getAndSet(Ljava/lang/Object;)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    sget-object v2, Ll2/b;->a:Ljava/lang/Object;

    .line 9
    .line 10
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    if-nez v2, :cond_3

    .line 15
    .line 16
    instance-of v2, v0, Ljava/util/Set;

    .line 17
    .line 18
    const/4 v3, 0x0

    .line 19
    if-eqz v2, :cond_0

    .line 20
    .line 21
    check-cast v0, Ljava/util/Set;

    .line 22
    .line 23
    invoke-virtual {p0, v0, v3}, Ll2/a0;->c(Ljava/util/Set;Z)V

    .line 24
    .line 25
    .line 26
    return-void

    .line 27
    :cond_0
    instance-of v2, v0, [Ljava/lang/Object;

    .line 28
    .line 29
    if-eqz v2, :cond_1

    .line 30
    .line 31
    check-cast v0, [Ljava/util/Set;

    .line 32
    .line 33
    array-length v1, v0

    .line 34
    move v2, v3

    .line 35
    :goto_0
    if-ge v2, v1, :cond_3

    .line 36
    .line 37
    aget-object v4, v0, v2

    .line 38
    .line 39
    invoke-virtual {p0, v4, v3}, Ll2/a0;->c(Ljava/util/Set;Z)V

    .line 40
    .line 41
    .line 42
    add-int/lit8 v2, v2, 0x1

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_1
    if-nez v0, :cond_2

    .line 46
    .line 47
    const-string p0, "calling recordModificationsOf and applyChanges concurrently is not supported"

    .line 48
    .line 49
    invoke-static {p0}, Ll2/v;->d(Ljava/lang/String;)Ljava/lang/Void;

    .line 50
    .line 51
    .line 52
    new-instance p0, La8/r0;

    .line 53
    .line 54
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 55
    .line 56
    .line 57
    throw p0

    .line 58
    :cond_2
    new-instance p0, Ljava/lang/StringBuilder;

    .line 59
    .line 60
    const-string v0, "corrupt pendingModifications drain: "

    .line 61
    .line 62
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    invoke-static {p0}, Ll2/v;->d(Ljava/lang/String;)Ljava/lang/Void;

    .line 73
    .line 74
    .line 75
    new-instance p0, La8/r0;

    .line 76
    .line 77
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 78
    .line 79
    .line 80
    throw p0

    .line 81
    :cond_3
    return-void
.end method

.method public final o()V
    .locals 5

    .line 1
    sget-object v0, Lmx0/u;->d:Lmx0/u;

    .line 2
    .line 3
    iget-object v1, p0, Ll2/a0;->f:Ljava/util/concurrent/atomic/AtomicReference;

    .line 4
    .line 5
    invoke-virtual {v1, v0}, Ljava/util/concurrent/atomic/AtomicReference;->getAndSet(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sget-object v2, Ll2/b;->a:Ljava/lang/Object;

    .line 10
    .line 11
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    if-nez v2, :cond_3

    .line 16
    .line 17
    if-nez v0, :cond_0

    .line 18
    .line 19
    goto :goto_1

    .line 20
    :cond_0
    instance-of v2, v0, Ljava/util/Set;

    .line 21
    .line 22
    const/4 v3, 0x0

    .line 23
    if-eqz v2, :cond_1

    .line 24
    .line 25
    check-cast v0, Ljava/util/Set;

    .line 26
    .line 27
    invoke-virtual {p0, v0, v3}, Ll2/a0;->c(Ljava/util/Set;Z)V

    .line 28
    .line 29
    .line 30
    return-void

    .line 31
    :cond_1
    instance-of v2, v0, [Ljava/lang/Object;

    .line 32
    .line 33
    if-eqz v2, :cond_2

    .line 34
    .line 35
    check-cast v0, [Ljava/util/Set;

    .line 36
    .line 37
    array-length v1, v0

    .line 38
    move v2, v3

    .line 39
    :goto_0
    if-ge v2, v1, :cond_3

    .line 40
    .line 41
    aget-object v4, v0, v2

    .line 42
    .line 43
    invoke-virtual {p0, v4, v3}, Ll2/a0;->c(Ljava/util/Set;Z)V

    .line 44
    .line 45
    .line 46
    add-int/lit8 v2, v2, 0x1

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_2
    new-instance p0, Ljava/lang/StringBuilder;

    .line 50
    .line 51
    const-string v0, "corrupt pendingModifications drain: "

    .line 52
    .line 53
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    invoke-static {p0}, Ll2/v;->d(Ljava/lang/String;)Ljava/lang/Void;

    .line 64
    .line 65
    .line 66
    new-instance p0, La8/r0;

    .line 67
    .line 68
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 69
    .line 70
    .line 71
    throw p0

    .line 72
    :cond_3
    :goto_1
    return-void
.end method

.method public final p()V
    .locals 2

    .line 1
    iget v0, p0, Ll2/a0;->z:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto :goto_1

    .line 6
    :cond_0
    const/4 v1, 0x1

    .line 7
    if-eq v0, v1, :cond_3

    .line 8
    .line 9
    const/4 v1, 0x2

    .line 10
    if-eq v0, v1, :cond_2

    .line 11
    .line 12
    const/4 v1, 0x3

    .line 13
    if-eq v0, v1, :cond_1

    .line 14
    .line 15
    const-string v0, ""

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_1
    const-string v0, "The composition is disposed"

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_2
    const-string v0, "A previous pausable composition for this composition was cancelled. This composition must be disposed."

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_3
    const-string v0, "The composition should be activated before setting content."

    .line 25
    .line 26
    :goto_0
    invoke-static {v0}, Ll2/q1;->b(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    :goto_1
    iget-object p0, p0, Ll2/a0;->t:Ll2/m1;

    .line 30
    .line 31
    if-nez p0, :cond_4

    .line 32
    .line 33
    return-void

    .line 34
    :cond_4
    const-string p0, "A pausable composition is in progress"

    .line 35
    .line 36
    invoke-static {p0}, Ll2/q1;->b(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    return-void
.end method

.method public final q(Ljava/util/ArrayList;)V
    .locals 3

    .line 1
    iget-object v0, p0, Ll2/a0;->h:Landroidx/collection/t0;

    .line 2
    .line 3
    iget-object v1, p0, Ll2/a0;->y:Ll2/t;

    .line 4
    .line 5
    invoke-interface {p1}, Ljava/util/Collection;->size()I

    .line 6
    .line 7
    .line 8
    move-result v2

    .line 9
    if-gtz v2, :cond_1

    .line 10
    .line 11
    :try_start_0
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 12
    .line 13
    .line 14
    :try_start_1
    invoke-virtual {v1, p1}, Ll2/t;->B(Ljava/util/ArrayList;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 15
    .line 16
    .line 17
    :try_start_2
    invoke-virtual {v1}, Ll2/t;->j()V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :catchall_0
    move-exception p1

    .line 22
    invoke-virtual {v1}, Ll2/t;->a()V

    .line 23
    .line 24
    .line 25
    throw p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 26
    :catchall_1
    move-exception p1

    .line 27
    :try_start_3
    iget-object v2, v0, Landroidx/collection/t0;->d:Landroidx/collection/r0;

    .line 28
    .line 29
    invoke-virtual {v2}, Landroidx/collection/r0;->g()Z

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    if-nez v2, :cond_0

    .line 34
    .line 35
    iget-object v2, p0, Ll2/a0;->x:Ljp/uf;

    .line 36
    .line 37
    invoke-virtual {v1}, Ll2/t;->z()Lw2/b;

    .line 38
    .line 39
    .line 40
    move-result-object v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 41
    :try_start_4
    invoke-virtual {v2, v0, v1}, Ljp/uf;->g(Ljava/util/Set;Lw2/b;)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {v2}, Ljp/uf;->b()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_3

    .line 45
    .line 46
    .line 47
    :try_start_5
    invoke-virtual {v2}, Ljp/uf;->a()V

    .line 48
    .line 49
    .line 50
    goto :goto_0

    .line 51
    :catchall_2
    move-exception p1

    .line 52
    goto :goto_1

    .line 53
    :catchall_3
    move-exception p1

    .line 54
    invoke-virtual {v2}, Ljp/uf;->a()V

    .line 55
    .line 56
    .line 57
    throw p1

    .line 58
    :cond_0
    :goto_0
    throw p1
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 59
    :goto_1
    invoke-virtual {p0}, Ll2/a0;->a()V

    .line 60
    .line 61
    .line 62
    throw p1

    .line 63
    :cond_1
    const/4 p0, 0x0

    .line 64
    invoke-interface {p1, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    check-cast p0, Llx0/l;

    .line 69
    .line 70
    iget-object p0, p0, Llx0/l;->d:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast p0, Ll2/a1;

    .line 73
    .line 74
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 75
    .line 76
    .line 77
    const/4 p0, 0x0

    .line 78
    throw p0
.end method

.method public final r(Ll2/u1;Ljava/lang/Object;)Ll2/s0;
    .locals 2

    .line 1
    iget v0, p1, Ll2/u1;->b:I

    .line 2
    .line 3
    and-int/lit8 v1, v0, 0x2

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    or-int/lit8 v0, v0, 0x4

    .line 8
    .line 9
    iput v0, p1, Ll2/u1;->b:I

    .line 10
    .line 11
    :cond_0
    iget-object v0, p1, Ll2/u1;->c:Ll2/a;

    .line 12
    .line 13
    if-eqz v0, :cond_6

    .line 14
    .line 15
    invoke-virtual {v0}, Ll2/a;->a()Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-nez v1, :cond_1

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_1
    iget-object v1, p0, Ll2/a0;->i:Ll2/f2;

    .line 23
    .line 24
    invoke-virtual {v1, v0}, Ll2/f2;->k(Ll2/a;)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-nez v1, :cond_3

    .line 29
    .line 30
    iget-object v0, p0, Ll2/a0;->g:Ljava/lang/Object;

    .line 31
    .line 32
    monitor-enter v0

    .line 33
    :try_start_0
    iget-object p0, p0, Ll2/a0;->u:Ll2/a0;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 34
    .line 35
    monitor-exit v0

    .line 36
    if-eqz p0, :cond_2

    .line 37
    .line 38
    iget-object p0, p0, Ll2/a0;->y:Ll2/t;

    .line 39
    .line 40
    iget-boolean v0, p0, Ll2/t;->F:Z

    .line 41
    .line 42
    if-eqz v0, :cond_2

    .line 43
    .line 44
    invoke-virtual {p0, p1, p2}, Ll2/t;->e0(Ll2/u1;Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result p0

    .line 48
    if-eqz p0, :cond_2

    .line 49
    .line 50
    sget-object p0, Ll2/s0;->g:Ll2/s0;

    .line 51
    .line 52
    return-object p0

    .line 53
    :cond_2
    sget-object p0, Ll2/s0;->d:Ll2/s0;

    .line 54
    .line 55
    return-object p0

    .line 56
    :catchall_0
    move-exception p0

    .line 57
    monitor-exit v0

    .line 58
    throw p0

    .line 59
    :cond_3
    iget-object v1, p1, Ll2/u1;->d:Lay0/n;

    .line 60
    .line 61
    if-eqz v1, :cond_5

    .line 62
    .line 63
    invoke-virtual {p0, p1, v0, p2}, Ll2/a0;->t(Ll2/u1;Ll2/a;Ljava/lang/Object;)Ll2/s0;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    sget-object p2, Ll2/s0;->d:Ll2/s0;

    .line 68
    .line 69
    if-eq p1, p2, :cond_4

    .line 70
    .line 71
    iget-object p0, p0, Ll2/a0;->w:Lh6/e;

    .line 72
    .line 73
    invoke-virtual {p0}, Lh6/e;->w()V

    .line 74
    .line 75
    .line 76
    :cond_4
    return-object p1

    .line 77
    :cond_5
    sget-object p0, Ll2/s0;->d:Ll2/s0;

    .line 78
    .line 79
    return-object p0

    .line 80
    :cond_6
    :goto_0
    sget-object p0, Ll2/s0;->d:Ll2/s0;

    .line 81
    .line 82
    return-object p0
.end method

.method public final s()V
    .locals 5

    .line 1
    iget-object v0, p0, Ll2/a0;->g:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Ll2/a0;->i:Ll2/f2;

    .line 5
    .line 6
    iget-object p0, p0, Ll2/f2;->f:[Ljava/lang/Object;

    .line 7
    .line 8
    array-length v1, p0

    .line 9
    const/4 v2, 0x0

    .line 10
    :goto_0
    if-ge v2, v1, :cond_2

    .line 11
    .line 12
    aget-object v3, p0, v2

    .line 13
    .line 14
    instance-of v4, v3, Ll2/u1;

    .line 15
    .line 16
    if-eqz v4, :cond_0

    .line 17
    .line 18
    check-cast v3, Ll2/u1;

    .line 19
    .line 20
    goto :goto_1

    .line 21
    :catchall_0
    move-exception p0

    .line 22
    goto :goto_2

    .line 23
    :cond_0
    const/4 v3, 0x0

    .line 24
    :goto_1
    if-eqz v3, :cond_1

    .line 25
    .line 26
    invoke-virtual {v3}, Ll2/u1;->c()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 27
    .line 28
    .line 29
    :cond_1
    add-int/lit8 v2, v2, 0x1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_2
    monitor-exit v0

    .line 33
    return-void

    .line 34
    :goto_2
    monitor-exit v0

    .line 35
    throw p0
.end method

.method public final t(Ll2/u1;Ll2/a;Ljava/lang/Object;)Ll2/s0;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    move-object/from16 v3, p3

    .line 8
    .line 9
    iget-object v4, v0, Ll2/a0;->g:Ljava/lang/Object;

    .line 10
    .line 11
    monitor-enter v4

    .line 12
    :try_start_0
    iget-object v5, v0, Ll2/a0;->u:Ll2/a0;

    .line 13
    .line 14
    const/4 v6, 0x0

    .line 15
    if-eqz v5, :cond_3

    .line 16
    .line 17
    iget-object v7, v0, Ll2/a0;->i:Ll2/f2;

    .line 18
    .line 19
    iget v8, v0, Ll2/a0;->v:I

    .line 20
    .line 21
    iget-boolean v9, v7, Ll2/f2;->j:Z

    .line 22
    .line 23
    if-eqz v9, :cond_0

    .line 24
    .line 25
    const-string v9, "Writer is active"

    .line 26
    .line 27
    invoke-static {v9}, Ll2/v;->c(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    :cond_0
    if-ltz v8, :cond_1

    .line 31
    .line 32
    iget v9, v7, Ll2/f2;->e:I

    .line 33
    .line 34
    if-ge v8, v9, :cond_1

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_1
    const-string v9, "Invalid group index"

    .line 38
    .line 39
    invoke-static {v9}, Ll2/v;->c(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    :goto_0
    invoke-virtual {v7, v2}, Ll2/f2;->k(Ll2/a;)Z

    .line 43
    .line 44
    .line 45
    move-result v9

    .line 46
    if-eqz v9, :cond_2

    .line 47
    .line 48
    iget-object v7, v7, Ll2/f2;->d:[I

    .line 49
    .line 50
    mul-int/lit8 v9, v8, 0x5

    .line 51
    .line 52
    add-int/lit8 v9, v9, 0x3

    .line 53
    .line 54
    aget v7, v7, v9

    .line 55
    .line 56
    add-int/2addr v7, v8

    .line 57
    iget v9, v2, Ll2/a;->a:I

    .line 58
    .line 59
    if-gt v8, v9, :cond_2

    .line 60
    .line 61
    if-ge v9, v7, :cond_2

    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_2
    move-object v5, v6

    .line 65
    :goto_1
    move-object v6, v5

    .line 66
    goto :goto_2

    .line 67
    :catchall_0
    move-exception v0

    .line 68
    goto/16 :goto_7

    .line 69
    .line 70
    :cond_3
    :goto_2
    if-nez v6, :cond_e

    .line 71
    .line 72
    iget-object v5, v0, Ll2/a0;->y:Ll2/t;

    .line 73
    .line 74
    iget-boolean v7, v5, Ll2/t;->F:Z

    .line 75
    .line 76
    if-eqz v7, :cond_4

    .line 77
    .line 78
    invoke-virtual {v5, v1, v3}, Ll2/t;->e0(Ll2/u1;Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v5

    .line 82
    if-eqz v5, :cond_4

    .line 83
    .line 84
    const/4 v5, 0x1

    .line 85
    goto :goto_3

    .line 86
    :cond_4
    const/4 v5, 0x0

    .line 87
    :goto_3
    if-eqz v5, :cond_5

    .line 88
    .line 89
    sget-object v0, Ll2/s0;->g:Ll2/s0;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 90
    .line 91
    monitor-exit v4

    .line 92
    return-object v0

    .line 93
    :cond_5
    if-nez v3, :cond_6

    .line 94
    .line 95
    :try_start_1
    iget-object v5, v0, Ll2/a0;->q:Landroidx/collection/q0;

    .line 96
    .line 97
    sget-object v7, Ll2/x0;->h:Ll2/x0;

    .line 98
    .line 99
    invoke-virtual {v5, v1, v7}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    goto/16 :goto_6

    .line 103
    .line 104
    :cond_6
    instance-of v5, v3, Ll2/h0;

    .line 105
    .line 106
    if-nez v5, :cond_7

    .line 107
    .line 108
    iget-object v5, v0, Ll2/a0;->q:Landroidx/collection/q0;

    .line 109
    .line 110
    sget-object v7, Ll2/x0;->h:Ll2/x0;

    .line 111
    .line 112
    invoke-virtual {v5, v1, v7}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 113
    .line 114
    .line 115
    goto/16 :goto_6

    .line 116
    .line 117
    :cond_7
    iget-object v5, v0, Ll2/a0;->q:Landroidx/collection/q0;

    .line 118
    .line 119
    invoke-virtual {v5, v1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object v5

    .line 123
    if-eqz v5, :cond_d

    .line 124
    .line 125
    instance-of v7, v5, Landroidx/collection/r0;

    .line 126
    .line 127
    if-eqz v7, :cond_c

    .line 128
    .line 129
    check-cast v5, Landroidx/collection/r0;

    .line 130
    .line 131
    iget-object v7, v5, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 132
    .line 133
    iget-object v5, v5, Landroidx/collection/r0;->a:[J

    .line 134
    .line 135
    array-length v9, v5

    .line 136
    add-int/lit8 v9, v9, -0x2

    .line 137
    .line 138
    if-ltz v9, :cond_d

    .line 139
    .line 140
    const/4 v10, 0x0

    .line 141
    :goto_4
    aget-wide v11, v5, v10

    .line 142
    .line 143
    not-long v13, v11

    .line 144
    const/4 v15, 0x7

    .line 145
    shl-long/2addr v13, v15

    .line 146
    and-long/2addr v13, v11

    .line 147
    const-wide v15, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 148
    .line 149
    .line 150
    .line 151
    .line 152
    and-long/2addr v13, v15

    .line 153
    cmp-long v13, v13, v15

    .line 154
    .line 155
    if-eqz v13, :cond_b

    .line 156
    .line 157
    sub-int v13, v10, v9

    .line 158
    .line 159
    not-int v13, v13

    .line 160
    ushr-int/lit8 v13, v13, 0x1f

    .line 161
    .line 162
    const/16 v14, 0x8

    .line 163
    .line 164
    rsub-int/lit8 v13, v13, 0x8

    .line 165
    .line 166
    const/4 v15, 0x0

    .line 167
    :goto_5
    if-ge v15, v13, :cond_a

    .line 168
    .line 169
    const-wide/16 v16, 0xff

    .line 170
    .line 171
    and-long v16, v11, v16

    .line 172
    .line 173
    const-wide/16 v18, 0x80

    .line 174
    .line 175
    cmp-long v16, v16, v18

    .line 176
    .line 177
    if-gez v16, :cond_8

    .line 178
    .line 179
    shl-int/lit8 v16, v10, 0x3

    .line 180
    .line 181
    add-int v16, v16, v15

    .line 182
    .line 183
    aget-object v8, v7, v16

    .line 184
    .line 185
    move/from16 v16, v14

    .line 186
    .line 187
    sget-object v14, Ll2/x0;->h:Ll2/x0;

    .line 188
    .line 189
    if-ne v8, v14, :cond_9

    .line 190
    .line 191
    goto :goto_6

    .line 192
    :cond_8
    move/from16 v16, v14

    .line 193
    .line 194
    :cond_9
    shr-long v11, v11, v16

    .line 195
    .line 196
    add-int/lit8 v15, v15, 0x1

    .line 197
    .line 198
    move/from16 v14, v16

    .line 199
    .line 200
    goto :goto_5

    .line 201
    :cond_a
    move v8, v14

    .line 202
    if-ne v13, v8, :cond_d

    .line 203
    .line 204
    :cond_b
    if-eq v10, v9, :cond_d

    .line 205
    .line 206
    add-int/lit8 v10, v10, 0x1

    .line 207
    .line 208
    goto :goto_4

    .line 209
    :cond_c
    sget-object v7, Ll2/x0;->h:Ll2/x0;

    .line 210
    .line 211
    if-ne v5, v7, :cond_d

    .line 212
    .line 213
    goto :goto_6

    .line 214
    :cond_d
    iget-object v5, v0, Ll2/a0;->q:Landroidx/collection/q0;

    .line 215
    .line 216
    invoke-static {v5, v1, v3}, Ljp/v1;->a(Landroidx/collection/q0;Ljava/lang/Object;Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 217
    .line 218
    .line 219
    :cond_e
    :goto_6
    monitor-exit v4

    .line 220
    if-eqz v6, :cond_f

    .line 221
    .line 222
    invoke-virtual {v6, v1, v2, v3}, Ll2/a0;->t(Ll2/u1;Ll2/a;Ljava/lang/Object;)Ll2/s0;

    .line 223
    .line 224
    .line 225
    move-result-object v0

    .line 226
    return-object v0

    .line 227
    :cond_f
    iget-object v1, v0, Ll2/a0;->d:Ll2/x;

    .line 228
    .line 229
    invoke-virtual {v1, v0}, Ll2/x;->k(Ll2/a0;)V

    .line 230
    .line 231
    .line 232
    iget-object v0, v0, Ll2/a0;->y:Ll2/t;

    .line 233
    .line 234
    iget-boolean v0, v0, Ll2/t;->F:Z

    .line 235
    .line 236
    if-eqz v0, :cond_10

    .line 237
    .line 238
    sget-object v0, Ll2/s0;->f:Ll2/s0;

    .line 239
    .line 240
    return-object v0

    .line 241
    :cond_10
    sget-object v0, Ll2/s0;->e:Ll2/s0;

    .line 242
    .line 243
    return-object v0

    .line 244
    :goto_7
    monitor-exit v4

    .line 245
    throw v0
.end method

.method public final u(Ljava/lang/Object;)V
    .locals 14

    .line 1
    iget-object v0, p0, Ll2/a0;->j:Landroidx/collection/q0;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-eqz v0, :cond_4

    .line 8
    .line 9
    instance-of v1, v0, Landroidx/collection/r0;

    .line 10
    .line 11
    iget-object p0, p0, Ll2/a0;->p:Landroidx/collection/q0;

    .line 12
    .line 13
    if-eqz v1, :cond_3

    .line 14
    .line 15
    check-cast v0, Landroidx/collection/r0;

    .line 16
    .line 17
    iget-object v1, v0, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 18
    .line 19
    iget-object v0, v0, Landroidx/collection/r0;->a:[J

    .line 20
    .line 21
    array-length v2, v0

    .line 22
    add-int/lit8 v2, v2, -0x2

    .line 23
    .line 24
    if-ltz v2, :cond_4

    .line 25
    .line 26
    const/4 v3, 0x0

    .line 27
    move v4, v3

    .line 28
    :goto_0
    aget-wide v5, v0, v4

    .line 29
    .line 30
    not-long v7, v5

    .line 31
    const/4 v9, 0x7

    .line 32
    shl-long/2addr v7, v9

    .line 33
    and-long/2addr v7, v5

    .line 34
    const-wide v9, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 35
    .line 36
    .line 37
    .line 38
    .line 39
    and-long/2addr v7, v9

    .line 40
    cmp-long v7, v7, v9

    .line 41
    .line 42
    if-eqz v7, :cond_2

    .line 43
    .line 44
    sub-int v7, v4, v2

    .line 45
    .line 46
    not-int v7, v7

    .line 47
    ushr-int/lit8 v7, v7, 0x1f

    .line 48
    .line 49
    const/16 v8, 0x8

    .line 50
    .line 51
    rsub-int/lit8 v7, v7, 0x8

    .line 52
    .line 53
    move v9, v3

    .line 54
    :goto_1
    if-ge v9, v7, :cond_1

    .line 55
    .line 56
    const-wide/16 v10, 0xff

    .line 57
    .line 58
    and-long/2addr v10, v5

    .line 59
    const-wide/16 v12, 0x80

    .line 60
    .line 61
    cmp-long v10, v10, v12

    .line 62
    .line 63
    if-gez v10, :cond_0

    .line 64
    .line 65
    shl-int/lit8 v10, v4, 0x3

    .line 66
    .line 67
    add-int/2addr v10, v9

    .line 68
    aget-object v10, v1, v10

    .line 69
    .line 70
    check-cast v10, Ll2/u1;

    .line 71
    .line 72
    invoke-virtual {v10, p1}, Ll2/u1;->d(Ljava/lang/Object;)Ll2/s0;

    .line 73
    .line 74
    .line 75
    move-result-object v11

    .line 76
    sget-object v12, Ll2/s0;->g:Ll2/s0;

    .line 77
    .line 78
    if-ne v11, v12, :cond_0

    .line 79
    .line 80
    invoke-static {p0, p1, v10}, Ljp/v1;->a(Landroidx/collection/q0;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    :cond_0
    shr-long/2addr v5, v8

    .line 84
    add-int/lit8 v9, v9, 0x1

    .line 85
    .line 86
    goto :goto_1

    .line 87
    :cond_1
    if-ne v7, v8, :cond_4

    .line 88
    .line 89
    :cond_2
    if-eq v4, v2, :cond_4

    .line 90
    .line 91
    add-int/lit8 v4, v4, 0x1

    .line 92
    .line 93
    goto :goto_0

    .line 94
    :cond_3
    check-cast v0, Ll2/u1;

    .line 95
    .line 96
    invoke-virtual {v0, p1}, Ll2/u1;->d(Ljava/lang/Object;)Ll2/s0;

    .line 97
    .line 98
    .line 99
    move-result-object v1

    .line 100
    sget-object v2, Ll2/s0;->g:Ll2/s0;

    .line 101
    .line 102
    if-ne v1, v2, :cond_4

    .line 103
    .line 104
    invoke-static {p0, p1, v0}, Ljp/v1;->a(Landroidx/collection/q0;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    :cond_4
    return-void
.end method

.method public final v(Ljava/util/Set;)Z
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    instance-of v2, v1, Ln2/d;

    .line 6
    .line 7
    iget-object v3, v0, Ll2/a0;->m:Landroidx/collection/q0;

    .line 8
    .line 9
    iget-object v0, v0, Ll2/a0;->j:Landroidx/collection/q0;

    .line 10
    .line 11
    const/4 v4, 0x0

    .line 12
    const/4 v5, 0x1

    .line 13
    if-eqz v2, :cond_4

    .line 14
    .line 15
    check-cast v1, Ln2/d;

    .line 16
    .line 17
    iget-object v1, v1, Ln2/d;->d:Landroidx/collection/r0;

    .line 18
    .line 19
    iget-object v2, v1, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 20
    .line 21
    iget-object v1, v1, Landroidx/collection/r0;->a:[J

    .line 22
    .line 23
    array-length v6, v1

    .line 24
    add-int/lit8 v6, v6, -0x2

    .line 25
    .line 26
    if-ltz v6, :cond_7

    .line 27
    .line 28
    move v7, v4

    .line 29
    :goto_0
    aget-wide v8, v1, v7

    .line 30
    .line 31
    not-long v10, v8

    .line 32
    const/4 v12, 0x7

    .line 33
    shl-long/2addr v10, v12

    .line 34
    and-long/2addr v10, v8

    .line 35
    const-wide v12, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 36
    .line 37
    .line 38
    .line 39
    .line 40
    and-long/2addr v10, v12

    .line 41
    cmp-long v10, v10, v12

    .line 42
    .line 43
    if-eqz v10, :cond_3

    .line 44
    .line 45
    sub-int v10, v7, v6

    .line 46
    .line 47
    not-int v10, v10

    .line 48
    ushr-int/lit8 v10, v10, 0x1f

    .line 49
    .line 50
    const/16 v11, 0x8

    .line 51
    .line 52
    rsub-int/lit8 v10, v10, 0x8

    .line 53
    .line 54
    move v12, v4

    .line 55
    :goto_1
    if-ge v12, v10, :cond_2

    .line 56
    .line 57
    const-wide/16 v13, 0xff

    .line 58
    .line 59
    and-long/2addr v13, v8

    .line 60
    const-wide/16 v15, 0x80

    .line 61
    .line 62
    cmp-long v13, v13, v15

    .line 63
    .line 64
    if-gez v13, :cond_1

    .line 65
    .line 66
    shl-int/lit8 v13, v7, 0x3

    .line 67
    .line 68
    add-int/2addr v13, v12

    .line 69
    aget-object v13, v2, v13

    .line 70
    .line 71
    invoke-virtual {v0, v13}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v14

    .line 75
    if-nez v14, :cond_0

    .line 76
    .line 77
    invoke-virtual {v3, v13}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result v13

    .line 81
    if-eqz v13, :cond_1

    .line 82
    .line 83
    :cond_0
    return v5

    .line 84
    :cond_1
    shr-long/2addr v8, v11

    .line 85
    add-int/lit8 v12, v12, 0x1

    .line 86
    .line 87
    goto :goto_1

    .line 88
    :cond_2
    if-ne v10, v11, :cond_7

    .line 89
    .line 90
    :cond_3
    if-eq v7, v6, :cond_7

    .line 91
    .line 92
    add-int/lit8 v7, v7, 0x1

    .line 93
    .line 94
    goto :goto_0

    .line 95
    :cond_4
    check-cast v1, Ljava/lang/Iterable;

    .line 96
    .line 97
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 98
    .line 99
    .line 100
    move-result-object v1

    .line 101
    :cond_5
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 102
    .line 103
    .line 104
    move-result v2

    .line 105
    if-eqz v2, :cond_7

    .line 106
    .line 107
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v2

    .line 111
    invoke-virtual {v0, v2}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    move-result v6

    .line 115
    if-nez v6, :cond_6

    .line 116
    .line 117
    invoke-virtual {v3, v2}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 118
    .line 119
    .line 120
    move-result v2

    .line 121
    if-eqz v2, :cond_5

    .line 122
    .line 123
    :cond_6
    return v5

    .line 124
    :cond_7
    return v4
.end method

.method public final w()Z
    .locals 7

    .line 1
    iget-object v0, p0, Ll2/a0;->g:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Ll2/a0;->t:Ll2/m1;

    .line 5
    .line 6
    const/4 v2, 0x0

    .line 7
    if-eqz v1, :cond_1

    .line 8
    .line 9
    iget-object v3, v1, Ll2/m1;->h:Ljava/util/concurrent/atomic/AtomicReference;

    .line 10
    .line 11
    invoke-virtual {v3}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v3

    .line 15
    sget-object v4, Ll2/n1;->h:Ll2/n1;

    .line 16
    .line 17
    if-ne v3, v4, :cond_0

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    invoke-virtual {v1}, Ll2/m1;->e()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 21
    .line 22
    .line 23
    monitor-exit v0

    .line 24
    return v2

    .line 25
    :catchall_0
    move-exception p0

    .line 26
    goto/16 :goto_6

    .line 27
    .line 28
    :cond_1
    :goto_0
    :try_start_1
    invoke-virtual {p0}, Ll2/a0;->m()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 29
    .line 30
    .line 31
    :try_start_2
    iget-object v1, p0, Ll2/a0;->q:Landroidx/collection/q0;

    .line 32
    .line 33
    invoke-static {}, Ljp/v1;->b()Landroidx/collection/q0;

    .line 34
    .line 35
    .line 36
    move-result-object v3

    .line 37
    iput-object v3, p0, Ll2/a0;->q:Landroidx/collection/q0;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_3

    .line 38
    .line 39
    :try_start_3
    iget-object v3, p0, Ll2/a0;->y:Ll2/t;

    .line 40
    .line 41
    iget-object v4, p0, Ll2/a0;->s:Lt0/c;

    .line 42
    .line 43
    iget-object v5, v3, Ll2/t;->e:Lm2/a;

    .line 44
    .line 45
    iget-object v5, v5, Lm2/a;->b:Lm2/l0;

    .line 46
    .line 47
    invoke-virtual {v5}, Lm2/l0;->f()Z

    .line 48
    .line 49
    .line 50
    move-result v6

    .line 51
    if-nez v6, :cond_2

    .line 52
    .line 53
    const-string v6, "Expected applyChanges() to have been called"

    .line 54
    .line 55
    invoke-static {v6}, Ll2/v;->c(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    :cond_2
    iget v6, v1, Landroidx/collection/q0;->e:I

    .line 59
    .line 60
    if-gtz v6, :cond_3

    .line 61
    .line 62
    iget-object v6, v3, Ll2/t;->s:Ljava/util/ArrayList;

    .line 63
    .line 64
    invoke-virtual {v6}, Ljava/util/ArrayList;->isEmpty()Z

    .line 65
    .line 66
    .line 67
    move-result v6

    .line 68
    if-eqz v6, :cond_3

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_3
    iput-object v4, v3, Ll2/t;->P:Lt0/c;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 72
    .line 73
    const/4 v2, 0x0

    .line 74
    :try_start_4
    invoke-virtual {v3, v1, v2}, Ll2/t;->o(Landroidx/collection/q0;Lay0/n;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 75
    .line 76
    .line 77
    :try_start_5
    iput-object v2, v3, Ll2/t;->P:Lt0/c;

    .line 78
    .line 79
    invoke-virtual {v5}, Lm2/l0;->g()Z

    .line 80
    .line 81
    .line 82
    move-result v2

    .line 83
    :goto_1
    if-nez v2, :cond_4

    .line 84
    .line 85
    invoke-virtual {p0}, Ll2/a0;->n()V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 86
    .line 87
    .line 88
    goto :goto_2

    .line 89
    :catchall_1
    move-exception v2

    .line 90
    goto :goto_3

    .line 91
    :cond_4
    :goto_2
    monitor-exit v0

    .line 92
    return v2

    .line 93
    :catchall_2
    move-exception v4

    .line 94
    :try_start_6
    iput-object v2, v3, Ll2/t;->P:Lt0/c;

    .line 95
    .line 96
    throw v4
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 97
    :goto_3
    :try_start_7
    iput-object v1, p0, Ll2/a0;->q:Landroidx/collection/q0;

    .line 98
    .line 99
    throw v2
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_3

    .line 100
    :catchall_3
    move-exception v1

    .line 101
    :try_start_8
    iget-object v2, p0, Ll2/a0;->h:Landroidx/collection/t0;

    .line 102
    .line 103
    iget-object v2, v2, Landroidx/collection/t0;->d:Landroidx/collection/r0;

    .line 104
    .line 105
    invoke-virtual {v2}, Landroidx/collection/r0;->g()Z

    .line 106
    .line 107
    .line 108
    move-result v2

    .line 109
    if-nez v2, :cond_5

    .line 110
    .line 111
    iget-object v2, p0, Ll2/a0;->x:Ljp/uf;

    .line 112
    .line 113
    iget-object v3, p0, Ll2/a0;->h:Landroidx/collection/t0;

    .line 114
    .line 115
    iget-object v4, p0, Ll2/a0;->y:Ll2/t;

    .line 116
    .line 117
    invoke-virtual {v4}, Ll2/t;->z()Lw2/b;

    .line 118
    .line 119
    .line 120
    move-result-object v4
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_4

    .line 121
    :try_start_9
    invoke-virtual {v2, v3, v4}, Ljp/uf;->g(Ljava/util/Set;Lw2/b;)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {v2}, Ljp/uf;->b()V
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_5

    .line 125
    .line 126
    .line 127
    :try_start_a
    invoke-virtual {v2}, Ljp/uf;->a()V

    .line 128
    .line 129
    .line 130
    goto :goto_4

    .line 131
    :catchall_4
    move-exception v1

    .line 132
    goto :goto_5

    .line 133
    :catchall_5
    move-exception v1

    .line 134
    invoke-virtual {v2}, Ljp/uf;->a()V

    .line 135
    .line 136
    .line 137
    throw v1

    .line 138
    :cond_5
    :goto_4
    throw v1
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_4

    .line 139
    :goto_5
    :try_start_b
    invoke-virtual {p0}, Ll2/a0;->a()V

    .line 140
    .line 141
    .line 142
    throw v1
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_0

    .line 143
    :goto_6
    monitor-exit v0

    .line 144
    throw p0
.end method

.method public final x(Ln2/d;)V
    .locals 4

    .line 1
    :goto_0
    iget-object v0, p0, Ll2/a0;->f:Ljava/util/concurrent/atomic/AtomicReference;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-eqz v0, :cond_3

    .line 8
    .line 9
    sget-object v1, Ll2/b;->a:Ljava/lang/Object;

    .line 10
    .line 11
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-eqz v1, :cond_0

    .line 16
    .line 17
    goto :goto_1

    .line 18
    :cond_0
    instance-of v1, v0, Ljava/util/Set;

    .line 19
    .line 20
    if-eqz v1, :cond_1

    .line 21
    .line 22
    const/4 v1, 0x2

    .line 23
    new-array v1, v1, [Ljava/util/Set;

    .line 24
    .line 25
    const/4 v2, 0x0

    .line 26
    aput-object v0, v1, v2

    .line 27
    .line 28
    const/4 v2, 0x1

    .line 29
    aput-object p1, v1, v2

    .line 30
    .line 31
    goto :goto_2

    .line 32
    :cond_1
    instance-of v1, v0, [Ljava/lang/Object;

    .line 33
    .line 34
    if-eqz v1, :cond_2

    .line 35
    .line 36
    move-object v1, v0

    .line 37
    check-cast v1, [Ljava/util/Set;

    .line 38
    .line 39
    array-length v2, v1

    .line 40
    add-int/lit8 v3, v2, 0x1

    .line 41
    .line 42
    invoke-static {v1, v3}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    aput-object p1, v1, v2

    .line 47
    .line 48
    goto :goto_2

    .line 49
    :cond_2
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    new-instance v0, Ljava/lang/StringBuilder;

    .line 52
    .line 53
    const-string v1, "corrupt pendingModifications: "

    .line 54
    .line 55
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    iget-object p0, p0, Ll2/a0;->f:Ljava/util/concurrent/atomic/AtomicReference;

    .line 59
    .line 60
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    throw p1

    .line 75
    :cond_3
    :goto_1
    move-object v1, p1

    .line 76
    :goto_2
    iget-object v2, p0, Ll2/a0;->f:Ljava/util/concurrent/atomic/AtomicReference;

    .line 77
    .line 78
    :cond_4
    invoke-virtual {v2, v0, v1}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v3

    .line 82
    if-eqz v3, :cond_6

    .line 83
    .line 84
    if-nez v0, :cond_5

    .line 85
    .line 86
    iget-object p1, p0, Ll2/a0;->g:Ljava/lang/Object;

    .line 87
    .line 88
    monitor-enter p1

    .line 89
    :try_start_0
    invoke-virtual {p0}, Ll2/a0;->n()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 90
    .line 91
    .line 92
    monitor-exit p1

    .line 93
    return-void

    .line 94
    :catchall_0
    move-exception p0

    .line 95
    monitor-exit p1

    .line 96
    throw p0

    .line 97
    :cond_5
    return-void

    .line 98
    :cond_6
    invoke-virtual {v2}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v3

    .line 102
    if-eq v3, v0, :cond_4

    .line 103
    .line 104
    goto :goto_0
.end method

.method public final y(Ljava/lang/Object;)V
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, Ll2/a0;->y:Ll2/t;

    .line 6
    .line 7
    iget v3, v2, Ll2/t;->A:I

    .line 8
    .line 9
    if-lez v3, :cond_0

    .line 10
    .line 11
    goto/16 :goto_5

    .line 12
    .line 13
    :cond_0
    invoke-virtual {v2}, Ll2/t;->x()Ll2/u1;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    if-eqz v2, :cond_c

    .line 18
    .line 19
    iget v3, v2, Ll2/u1;->b:I

    .line 20
    .line 21
    const/4 v4, 0x1

    .line 22
    or-int/2addr v3, v4

    .line 23
    iput v3, v2, Ll2/u1;->b:I

    .line 24
    .line 25
    and-int/lit8 v3, v3, 0x20

    .line 26
    .line 27
    if-eqz v3, :cond_2

    .line 28
    .line 29
    :cond_1
    const/4 v3, 0x0

    .line 30
    goto :goto_1

    .line 31
    :cond_2
    iget-object v3, v2, Ll2/u1;->f:Landroidx/collection/h0;

    .line 32
    .line 33
    if-nez v3, :cond_3

    .line 34
    .line 35
    new-instance v3, Landroidx/collection/h0;

    .line 36
    .line 37
    invoke-direct {v3}, Landroidx/collection/h0;-><init>()V

    .line 38
    .line 39
    .line 40
    iput-object v3, v2, Ll2/u1;->f:Landroidx/collection/h0;

    .line 41
    .line 42
    :cond_3
    iget v6, v2, Ll2/u1;->e:I

    .line 43
    .line 44
    invoke-virtual {v3, v1}, Landroidx/collection/h0;->c(Ljava/lang/Object;)I

    .line 45
    .line 46
    .line 47
    move-result v7

    .line 48
    if-gez v7, :cond_4

    .line 49
    .line 50
    not-int v7, v7

    .line 51
    const/4 v8, -0x1

    .line 52
    goto :goto_0

    .line 53
    :cond_4
    iget-object v8, v3, Landroidx/collection/h0;->c:[I

    .line 54
    .line 55
    aget v8, v8, v7

    .line 56
    .line 57
    :goto_0
    iget-object v9, v3, Landroidx/collection/h0;->b:[Ljava/lang/Object;

    .line 58
    .line 59
    aput-object v1, v9, v7

    .line 60
    .line 61
    iget-object v3, v3, Landroidx/collection/h0;->c:[I

    .line 62
    .line 63
    aput v6, v3, v7

    .line 64
    .line 65
    iget v3, v2, Ll2/u1;->e:I

    .line 66
    .line 67
    if-ne v8, v3, :cond_1

    .line 68
    .line 69
    move v3, v4

    .line 70
    :goto_1
    iget-object v6, v0, Ll2/a0;->w:Lh6/e;

    .line 71
    .line 72
    invoke-virtual {v6}, Lh6/e;->w()V

    .line 73
    .line 74
    .line 75
    if-nez v3, :cond_c

    .line 76
    .line 77
    instance-of v3, v1, Lv2/u;

    .line 78
    .line 79
    if-eqz v3, :cond_5

    .line 80
    .line 81
    move-object v3, v1

    .line 82
    check-cast v3, Lv2/u;

    .line 83
    .line 84
    invoke-virtual {v3, v4}, Lv2/u;->b(I)V

    .line 85
    .line 86
    .line 87
    :cond_5
    iget-object v3, v0, Ll2/a0;->j:Landroidx/collection/q0;

    .line 88
    .line 89
    invoke-static {v3, v1, v2}, Ljp/v1;->a(Landroidx/collection/q0;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 90
    .line 91
    .line 92
    instance-of v3, v1, Ll2/h0;

    .line 93
    .line 94
    if-eqz v3, :cond_c

    .line 95
    .line 96
    move-object v3, v1

    .line 97
    check-cast v3, Ll2/h0;

    .line 98
    .line 99
    invoke-virtual {v3}, Ll2/h0;->o()Ll2/g0;

    .line 100
    .line 101
    .line 102
    move-result-object v6

    .line 103
    iget-object v0, v0, Ll2/a0;->m:Landroidx/collection/q0;

    .line 104
    .line 105
    invoke-static {v0, v1}, Ljp/v1;->j(Landroidx/collection/q0;Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    iget-object v7, v6, Ll2/g0;->e:Landroidx/collection/h0;

    .line 109
    .line 110
    iget-object v8, v7, Landroidx/collection/h0;->b:[Ljava/lang/Object;

    .line 111
    .line 112
    iget-object v7, v7, Landroidx/collection/h0;->a:[J

    .line 113
    .line 114
    array-length v9, v7

    .line 115
    add-int/lit8 v9, v9, -0x2

    .line 116
    .line 117
    if-ltz v9, :cond_a

    .line 118
    .line 119
    const/4 v10, 0x0

    .line 120
    :goto_2
    aget-wide v11, v7, v10

    .line 121
    .line 122
    not-long v13, v11

    .line 123
    const/4 v15, 0x7

    .line 124
    shl-long/2addr v13, v15

    .line 125
    and-long/2addr v13, v11

    .line 126
    const-wide v15, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 127
    .line 128
    .line 129
    .line 130
    .line 131
    and-long/2addr v13, v15

    .line 132
    cmp-long v13, v13, v15

    .line 133
    .line 134
    if-eqz v13, :cond_9

    .line 135
    .line 136
    sub-int v13, v10, v9

    .line 137
    .line 138
    not-int v13, v13

    .line 139
    ushr-int/lit8 v13, v13, 0x1f

    .line 140
    .line 141
    const/16 v14, 0x8

    .line 142
    .line 143
    rsub-int/lit8 v13, v13, 0x8

    .line 144
    .line 145
    const/4 v15, 0x0

    .line 146
    :goto_3
    if-ge v15, v13, :cond_8

    .line 147
    .line 148
    const-wide/16 v16, 0xff

    .line 149
    .line 150
    and-long v16, v11, v16

    .line 151
    .line 152
    const-wide/16 v18, 0x80

    .line 153
    .line 154
    cmp-long v16, v16, v18

    .line 155
    .line 156
    if-gez v16, :cond_7

    .line 157
    .line 158
    shl-int/lit8 v16, v10, 0x3

    .line 159
    .line 160
    add-int v16, v16, v15

    .line 161
    .line 162
    aget-object v16, v8, v16

    .line 163
    .line 164
    move-object/from16 v5, v16

    .line 165
    .line 166
    check-cast v5, Lv2/t;

    .line 167
    .line 168
    move/from16 p0, v14

    .line 169
    .line 170
    instance-of v14, v5, Lv2/u;

    .line 171
    .line 172
    if-eqz v14, :cond_6

    .line 173
    .line 174
    move-object v14, v5

    .line 175
    check-cast v14, Lv2/u;

    .line 176
    .line 177
    invoke-virtual {v14, v4}, Lv2/u;->b(I)V

    .line 178
    .line 179
    .line 180
    :cond_6
    invoke-static {v0, v5, v1}, Ljp/v1;->a(Landroidx/collection/q0;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 181
    .line 182
    .line 183
    goto :goto_4

    .line 184
    :cond_7
    move/from16 p0, v14

    .line 185
    .line 186
    :goto_4
    shr-long v11, v11, p0

    .line 187
    .line 188
    add-int/lit8 v15, v15, 0x1

    .line 189
    .line 190
    move/from16 v14, p0

    .line 191
    .line 192
    goto :goto_3

    .line 193
    :cond_8
    move v5, v14

    .line 194
    if-ne v13, v5, :cond_a

    .line 195
    .line 196
    :cond_9
    if-eq v10, v9, :cond_a

    .line 197
    .line 198
    add-int/lit8 v10, v10, 0x1

    .line 199
    .line 200
    goto :goto_2

    .line 201
    :cond_a
    iget-object v0, v6, Ll2/g0;->f:Ljava/lang/Object;

    .line 202
    .line 203
    iget-object v1, v2, Ll2/u1;->g:Landroidx/collection/q0;

    .line 204
    .line 205
    if-nez v1, :cond_b

    .line 206
    .line 207
    new-instance v1, Landroidx/collection/q0;

    .line 208
    .line 209
    invoke-direct {v1}, Landroidx/collection/q0;-><init>()V

    .line 210
    .line 211
    .line 212
    iput-object v1, v2, Ll2/u1;->g:Landroidx/collection/q0;

    .line 213
    .line 214
    :cond_b
    invoke-virtual {v1, v3, v0}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 215
    .line 216
    .line 217
    :cond_c
    :goto_5
    return-void
.end method

.method public final z(Ljava/lang/Object;)V
    .locals 14

    .line 1
    iget-object v0, p0, Ll2/a0;->g:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    invoke-virtual {p0, p1}, Ll2/a0;->u(Ljava/lang/Object;)V

    .line 5
    .line 6
    .line 7
    iget-object v1, p0, Ll2/a0;->m:Landroidx/collection/q0;

    .line 8
    .line 9
    invoke-virtual {v1, p1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    if-eqz p1, :cond_4

    .line 14
    .line 15
    instance-of v1, p1, Landroidx/collection/r0;

    .line 16
    .line 17
    if-eqz v1, :cond_3

    .line 18
    .line 19
    check-cast p1, Landroidx/collection/r0;

    .line 20
    .line 21
    iget-object v1, p1, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 22
    .line 23
    iget-object p1, p1, Landroidx/collection/r0;->a:[J

    .line 24
    .line 25
    array-length v2, p1

    .line 26
    add-int/lit8 v2, v2, -0x2

    .line 27
    .line 28
    if-ltz v2, :cond_4

    .line 29
    .line 30
    const/4 v3, 0x0

    .line 31
    move v4, v3

    .line 32
    :goto_0
    aget-wide v5, p1, v4

    .line 33
    .line 34
    not-long v7, v5

    .line 35
    const/4 v9, 0x7

    .line 36
    shl-long/2addr v7, v9

    .line 37
    and-long/2addr v7, v5

    .line 38
    const-wide v9, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 39
    .line 40
    .line 41
    .line 42
    .line 43
    and-long/2addr v7, v9

    .line 44
    cmp-long v7, v7, v9

    .line 45
    .line 46
    if-eqz v7, :cond_2

    .line 47
    .line 48
    sub-int v7, v4, v2

    .line 49
    .line 50
    not-int v7, v7

    .line 51
    ushr-int/lit8 v7, v7, 0x1f

    .line 52
    .line 53
    const/16 v8, 0x8

    .line 54
    .line 55
    rsub-int/lit8 v7, v7, 0x8

    .line 56
    .line 57
    move v9, v3

    .line 58
    :goto_1
    if-ge v9, v7, :cond_1

    .line 59
    .line 60
    const-wide/16 v10, 0xff

    .line 61
    .line 62
    and-long/2addr v10, v5

    .line 63
    const-wide/16 v12, 0x80

    .line 64
    .line 65
    cmp-long v10, v10, v12

    .line 66
    .line 67
    if-gez v10, :cond_0

    .line 68
    .line 69
    shl-int/lit8 v10, v4, 0x3

    .line 70
    .line 71
    add-int/2addr v10, v9

    .line 72
    aget-object v10, v1, v10

    .line 73
    .line 74
    check-cast v10, Ll2/h0;

    .line 75
    .line 76
    invoke-virtual {p0, v10}, Ll2/a0;->u(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    goto :goto_2

    .line 80
    :catchall_0
    move-exception p0

    .line 81
    goto :goto_3

    .line 82
    :cond_0
    :goto_2
    shr-long/2addr v5, v8

    .line 83
    add-int/lit8 v9, v9, 0x1

    .line 84
    .line 85
    goto :goto_1

    .line 86
    :cond_1
    if-ne v7, v8, :cond_4

    .line 87
    .line 88
    :cond_2
    if-eq v4, v2, :cond_4

    .line 89
    .line 90
    add-int/lit8 v4, v4, 0x1

    .line 91
    .line 92
    goto :goto_0

    .line 93
    :cond_3
    check-cast p1, Ll2/h0;

    .line 94
    .line 95
    invoke-virtual {p0, p1}, Ll2/a0;->u(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 96
    .line 97
    .line 98
    :cond_4
    monitor-exit v0

    .line 99
    return-void

    .line 100
    :goto_3
    monitor-exit v0

    .line 101
    throw p0
.end method
