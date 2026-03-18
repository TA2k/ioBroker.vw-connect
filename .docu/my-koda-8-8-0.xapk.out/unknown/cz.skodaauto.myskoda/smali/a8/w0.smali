.class public final La8/w0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/Object;

.field public final b:Ljava/lang/Object;

.field public final c:[Lh8/y0;

.field public d:Z

.field public e:Z

.field public f:Z

.field public g:La8/x0;

.field public h:Z

.field public final i:[Z

.field public final j:[La8/f;

.field public final k:Lh/w;

.field public final l:Lac/i;

.field public m:La8/w0;

.field public n:Lh8/e1;

.field public o:Lj8/s;

.field public p:J


# direct methods
.method public constructor <init>([La8/f;JLh/w;Lk8/e;Lac/i;La8/x0;Lj8/s;)V
    .locals 7

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, La8/w0;->j:[La8/f;

    .line 5
    .line 6
    iput-wide p2, p0, La8/w0;->p:J

    .line 7
    .line 8
    iput-object p4, p0, La8/w0;->k:Lh/w;

    .line 9
    .line 10
    iput-object p6, p0, La8/w0;->l:Lac/i;

    .line 11
    .line 12
    iget-object p2, p7, La8/x0;->a:Lh8/b0;

    .line 13
    .line 14
    iget-object p3, p2, Lh8/b0;->a:Ljava/lang/Object;

    .line 15
    .line 16
    iput-object p3, p0, La8/w0;->b:Ljava/lang/Object;

    .line 17
    .line 18
    iput-object p7, p0, La8/w0;->g:La8/x0;

    .line 19
    .line 20
    sget-object p3, Lh8/e1;->d:Lh8/e1;

    .line 21
    .line 22
    iput-object p3, p0, La8/w0;->n:Lh8/e1;

    .line 23
    .line 24
    iput-object p8, p0, La8/w0;->o:Lj8/s;

    .line 25
    .line 26
    array-length p3, p1

    .line 27
    new-array p3, p3, [Lh8/y0;

    .line 28
    .line 29
    iput-object p3, p0, La8/w0;->c:[Lh8/y0;

    .line 30
    .line 31
    array-length p1, p1

    .line 32
    new-array p1, p1, [Z

    .line 33
    .line 34
    iput-object p1, p0, La8/w0;->i:[Z

    .line 35
    .line 36
    iget-wide p3, p7, La8/x0;->b:J

    .line 37
    .line 38
    iget-wide v5, p7, La8/x0;->d:J

    .line 39
    .line 40
    iget-boolean p1, p7, La8/x0;->f:Z

    .line 41
    .line 42
    invoke-virtual {p6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 43
    .line 44
    .line 45
    iget-object p7, p2, Lh8/b0;->a:Ljava/lang/Object;

    .line 46
    .line 47
    sget p8, La8/n1;->k:I

    .line 48
    .line 49
    check-cast p7, Landroid/util/Pair;

    .line 50
    .line 51
    iget-object p8, p7, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 52
    .line 53
    iget-object p7, p7, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 54
    .line 55
    invoke-virtual {p2, p7}, Lh8/b0;->a(Ljava/lang/Object;)Lh8/b0;

    .line 56
    .line 57
    .line 58
    move-result-object p2

    .line 59
    iget-object p7, p6, Lac/i;->e:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast p7, Ljava/util/HashMap;

    .line 62
    .line 63
    invoke-virtual {p7, p8}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object p7

    .line 67
    check-cast p7, La8/h1;

    .line 68
    .line 69
    invoke-virtual {p7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 70
    .line 71
    .line 72
    iget-object p8, p6, Lac/i;->h:Ljava/lang/Object;

    .line 73
    .line 74
    check-cast p8, Ljava/util/HashSet;

    .line 75
    .line 76
    invoke-virtual {p8, p7}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    iget-object p8, p6, Lac/i;->g:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast p8, Ljava/util/HashMap;

    .line 82
    .line 83
    invoke-virtual {p8, p7}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object p8

    .line 87
    check-cast p8, La8/g1;

    .line 88
    .line 89
    if-eqz p8, :cond_0

    .line 90
    .line 91
    iget-object v0, p8, La8/g1;->a:Lh8/a;

    .line 92
    .line 93
    iget-object p8, p8, La8/g1;->b:La8/b1;

    .line 94
    .line 95
    invoke-virtual {v0, p8}, Lh8/a;->d(Lh8/c0;)V

    .line 96
    .line 97
    .line 98
    :cond_0
    iget-object p8, p7, La8/h1;->c:Ljava/util/ArrayList;

    .line 99
    .line 100
    invoke-virtual {p8, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    iget-object p8, p7, La8/h1;->a:Lh8/w;

    .line 104
    .line 105
    invoke-virtual {p8, p2, p5, p3, p4}, Lh8/w;->B(Lh8/b0;Lk8/e;J)Lh8/t;

    .line 106
    .line 107
    .line 108
    move-result-object v1

    .line 109
    iget-object p2, p6, Lac/i;->d:Ljava/lang/Object;

    .line 110
    .line 111
    check-cast p2, Ljava/util/IdentityHashMap;

    .line 112
    .line 113
    invoke-virtual {p2, v1, p7}, Ljava/util/IdentityHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    invoke-virtual {p6}, Lac/i;->d()V

    .line 117
    .line 118
    .line 119
    const-wide p2, -0x7fffffffffffffffL    # -4.9E-324

    .line 120
    .line 121
    .line 122
    .line 123
    .line 124
    cmp-long p2, v5, p2

    .line 125
    .line 126
    if-eqz p2, :cond_1

    .line 127
    .line 128
    new-instance v0, Lh8/c;

    .line 129
    .line 130
    xor-int/lit8 v2, p1, 0x1

    .line 131
    .line 132
    const-wide/16 v3, 0x0

    .line 133
    .line 134
    invoke-direct/range {v0 .. v6}, Lh8/c;-><init>(Lh8/z;ZJJ)V

    .line 135
    .line 136
    .line 137
    move-object v1, v0

    .line 138
    :cond_1
    iput-object v1, p0, La8/w0;->a:Ljava/lang/Object;

    .line 139
    .line 140
    return-void
.end method


# virtual methods
.method public final a(Lj8/s;JZ[Z)J
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    move v3, v2

    .line 7
    :goto_0
    iget v4, v1, Lj8/s;->a:I

    .line 8
    .line 9
    const/4 v5, 0x1

    .line 10
    if-ge v3, v4, :cond_1

    .line 11
    .line 12
    if-nez p4, :cond_0

    .line 13
    .line 14
    iget-object v4, v0, La8/w0;->o:Lj8/s;

    .line 15
    .line 16
    invoke-virtual {v1, v4, v3}, Lj8/s;->a(Lj8/s;I)Z

    .line 17
    .line 18
    .line 19
    move-result v4

    .line 20
    if-eqz v4, :cond_0

    .line 21
    .line 22
    goto :goto_1

    .line 23
    :cond_0
    move v5, v2

    .line 24
    :goto_1
    iget-object v4, v0, La8/w0;->i:[Z

    .line 25
    .line 26
    aput-boolean v5, v4, v3

    .line 27
    .line 28
    add-int/lit8 v3, v3, 0x1

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_1
    move v3, v2

    .line 32
    :goto_2
    iget-object v4, v0, La8/w0;->j:[La8/f;

    .line 33
    .line 34
    array-length v6, v4

    .line 35
    const/4 v7, -0x2

    .line 36
    iget-object v8, v0, La8/w0;->c:[Lh8/y0;

    .line 37
    .line 38
    if-ge v3, v6, :cond_3

    .line 39
    .line 40
    aget-object v4, v4, v3

    .line 41
    .line 42
    iget v4, v4, La8/f;->e:I

    .line 43
    .line 44
    if-ne v4, v7, :cond_2

    .line 45
    .line 46
    const/4 v4, 0x0

    .line 47
    aput-object v4, v8, v3

    .line 48
    .line 49
    :cond_2
    add-int/lit8 v3, v3, 0x1

    .line 50
    .line 51
    goto :goto_2

    .line 52
    :cond_3
    invoke-virtual {v0}, La8/w0;->b()V

    .line 53
    .line 54
    .line 55
    iput-object v1, v0, La8/w0;->o:Lj8/s;

    .line 56
    .line 57
    invoke-virtual {v0}, La8/w0;->c()V

    .line 58
    .line 59
    .line 60
    iget-object v10, v1, Lj8/s;->c:[Lj8/q;

    .line 61
    .line 62
    iget-object v11, v0, La8/w0;->i:[Z

    .line 63
    .line 64
    iget-object v12, v0, La8/w0;->c:[Lh8/y0;

    .line 65
    .line 66
    iget-object v9, v0, La8/w0;->a:Ljava/lang/Object;

    .line 67
    .line 68
    move-wide/from16 v14, p2

    .line 69
    .line 70
    move-object/from16 v13, p5

    .line 71
    .line 72
    invoke-interface/range {v9 .. v15}, Lh8/z;->o([Lj8/q;[Z[Lh8/y0;[ZJ)J

    .line 73
    .line 74
    .line 75
    move-result-wide v9

    .line 76
    move v3, v2

    .line 77
    :goto_3
    array-length v6, v4

    .line 78
    if-ge v3, v6, :cond_5

    .line 79
    .line 80
    aget-object v6, v4, v3

    .line 81
    .line 82
    iget v6, v6, La8/f;->e:I

    .line 83
    .line 84
    if-ne v6, v7, :cond_4

    .line 85
    .line 86
    iget-object v6, v0, La8/w0;->o:Lj8/s;

    .line 87
    .line 88
    invoke-virtual {v6, v3}, Lj8/s;->b(I)Z

    .line 89
    .line 90
    .line 91
    move-result v6

    .line 92
    if-eqz v6, :cond_4

    .line 93
    .line 94
    new-instance v6, Lwe0/b;

    .line 95
    .line 96
    const/4 v11, 0x6

    .line 97
    invoke-direct {v6, v11}, Lwe0/b;-><init>(I)V

    .line 98
    .line 99
    .line 100
    aput-object v6, v8, v3

    .line 101
    .line 102
    :cond_4
    add-int/lit8 v3, v3, 0x1

    .line 103
    .line 104
    goto :goto_3

    .line 105
    :cond_5
    iput-boolean v2, v0, La8/w0;->f:Z

    .line 106
    .line 107
    move v3, v2

    .line 108
    :goto_4
    array-length v6, v8

    .line 109
    if-ge v3, v6, :cond_9

    .line 110
    .line 111
    aget-object v6, v8, v3

    .line 112
    .line 113
    if-eqz v6, :cond_6

    .line 114
    .line 115
    invoke-virtual {v1, v3}, Lj8/s;->b(I)Z

    .line 116
    .line 117
    .line 118
    move-result v6

    .line 119
    invoke-static {v6}, Lw7/a;->j(Z)V

    .line 120
    .line 121
    .line 122
    aget-object v6, v4, v3

    .line 123
    .line 124
    iget v6, v6, La8/f;->e:I

    .line 125
    .line 126
    if-eq v6, v7, :cond_8

    .line 127
    .line 128
    iput-boolean v5, v0, La8/w0;->f:Z

    .line 129
    .line 130
    goto :goto_6

    .line 131
    :cond_6
    iget-object v6, v1, Lj8/s;->c:[Lj8/q;

    .line 132
    .line 133
    aget-object v6, v6, v3

    .line 134
    .line 135
    if-nez v6, :cond_7

    .line 136
    .line 137
    move v6, v5

    .line 138
    goto :goto_5

    .line 139
    :cond_7
    move v6, v2

    .line 140
    :goto_5
    invoke-static {v6}, Lw7/a;->j(Z)V

    .line 141
    .line 142
    .line 143
    :cond_8
    :goto_6
    add-int/lit8 v3, v3, 0x1

    .line 144
    .line 145
    goto :goto_4

    .line 146
    :cond_9
    return-wide v9
.end method

.method public final b()V
    .locals 3

    .line 1
    iget-object v0, p0, La8/w0;->m:La8/w0;

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    :goto_0
    iget-object v1, p0, La8/w0;->o:Lj8/s;

    .line 7
    .line 8
    iget v2, v1, Lj8/s;->a:I

    .line 9
    .line 10
    if-ge v0, v2, :cond_1

    .line 11
    .line 12
    invoke-virtual {v1, v0}, Lj8/s;->b(I)Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    iget-object v2, p0, La8/w0;->o:Lj8/s;

    .line 17
    .line 18
    iget-object v2, v2, Lj8/s;->c:[Lj8/q;

    .line 19
    .line 20
    aget-object v2, v2, v0

    .line 21
    .line 22
    if-eqz v1, :cond_0

    .line 23
    .line 24
    if-eqz v2, :cond_0

    .line 25
    .line 26
    invoke-interface {v2}, Lj8/q;->c()V

    .line 27
    .line 28
    .line 29
    :cond_0
    add-int/lit8 v0, v0, 0x1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_1
    return-void
.end method

.method public final c()V
    .locals 3

    .line 1
    iget-object v0, p0, La8/w0;->m:La8/w0;

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    :goto_0
    iget-object v1, p0, La8/w0;->o:Lj8/s;

    .line 7
    .line 8
    iget v2, v1, Lj8/s;->a:I

    .line 9
    .line 10
    if-ge v0, v2, :cond_1

    .line 11
    .line 12
    invoke-virtual {v1, v0}, Lj8/s;->b(I)Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    iget-object v2, p0, La8/w0;->o:Lj8/s;

    .line 17
    .line 18
    iget-object v2, v2, Lj8/s;->c:[Lj8/q;

    .line 19
    .line 20
    aget-object v2, v2, v0

    .line 21
    .line 22
    if-eqz v1, :cond_0

    .line 23
    .line 24
    if-eqz v2, :cond_0

    .line 25
    .line 26
    invoke-interface {v2}, Lj8/q;->i()V

    .line 27
    .line 28
    .line 29
    :cond_0
    add-int/lit8 v0, v0, 0x1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_1
    return-void
.end method

.method public final d()J
    .locals 5

    .line 1
    iget-boolean v0, p0, La8/w0;->e:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, La8/w0;->g:La8/x0;

    .line 6
    .line 7
    iget-wide v0, p0, La8/x0;->b:J

    .line 8
    .line 9
    return-wide v0

    .line 10
    :cond_0
    iget-boolean v0, p0, La8/w0;->f:Z

    .line 11
    .line 12
    const-wide/high16 v1, -0x8000000000000000L

    .line 13
    .line 14
    if-eqz v0, :cond_1

    .line 15
    .line 16
    iget-object v0, p0, La8/w0;->a:Ljava/lang/Object;

    .line 17
    .line 18
    invoke-interface {v0}, Lh8/z0;->r()J

    .line 19
    .line 20
    .line 21
    move-result-wide v3

    .line 22
    goto :goto_0

    .line 23
    :cond_1
    move-wide v3, v1

    .line 24
    :goto_0
    cmp-long v0, v3, v1

    .line 25
    .line 26
    if-nez v0, :cond_2

    .line 27
    .line 28
    iget-object p0, p0, La8/w0;->g:La8/x0;

    .line 29
    .line 30
    iget-wide v0, p0, La8/x0;->e:J

    .line 31
    .line 32
    return-wide v0

    .line 33
    :cond_2
    return-wide v3
.end method

.method public final e()J
    .locals 4

    .line 1
    iget-object v0, p0, La8/w0;->g:La8/x0;

    .line 2
    .line 3
    iget-wide v0, v0, La8/x0;->b:J

    .line 4
    .line 5
    iget-wide v2, p0, La8/w0;->p:J

    .line 6
    .line 7
    add-long/2addr v0, v2

    .line 8
    return-wide v0
.end method

.method public final f(FLt7/p0;Z)V
    .locals 7

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, La8/w0;->e:Z

    .line 3
    .line 4
    iget-object v0, p0, La8/w0;->a:Ljava/lang/Object;

    .line 5
    .line 6
    invoke-interface {v0}, Lh8/z;->n()Lh8/e1;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    iput-object v0, p0, La8/w0;->n:Lh8/e1;

    .line 11
    .line 12
    invoke-virtual {p0, p1, p2, p3}, La8/w0;->j(FLt7/p0;Z)Lj8/s;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    iget-object p1, p0, La8/w0;->g:La8/x0;

    .line 17
    .line 18
    iget-wide p2, p1, La8/x0;->b:J

    .line 19
    .line 20
    iget-wide v0, p1, La8/x0;->e:J

    .line 21
    .line 22
    const-wide v3, -0x7fffffffffffffffL    # -4.9E-324

    .line 23
    .line 24
    .line 25
    .line 26
    .line 27
    cmp-long p1, v0, v3

    .line 28
    .line 29
    if-eqz p1, :cond_0

    .line 30
    .line 31
    cmp-long p1, p2, v0

    .line 32
    .line 33
    if-ltz p1, :cond_0

    .line 34
    .line 35
    const-wide/16 p1, 0x1

    .line 36
    .line 37
    sub-long/2addr v0, p1

    .line 38
    const-wide/16 p1, 0x0

    .line 39
    .line 40
    invoke-static {p1, p2, v0, v1}, Ljava/lang/Math;->max(JJ)J

    .line 41
    .line 42
    .line 43
    move-result-wide p2

    .line 44
    :cond_0
    move-wide v3, p2

    .line 45
    iget-object p1, p0, La8/w0;->j:[La8/f;

    .line 46
    .line 47
    array-length p1, p1

    .line 48
    new-array v6, p1, [Z

    .line 49
    .line 50
    const/4 v5, 0x0

    .line 51
    move-object v1, p0

    .line 52
    invoke-virtual/range {v1 .. v6}, La8/w0;->a(Lj8/s;JZ[Z)J

    .line 53
    .line 54
    .line 55
    move-result-wide p0

    .line 56
    iget-wide p2, v1, La8/w0;->p:J

    .line 57
    .line 58
    iget-object v0, v1, La8/w0;->g:La8/x0;

    .line 59
    .line 60
    iget-wide v2, v0, La8/x0;->b:J

    .line 61
    .line 62
    sub-long/2addr v2, p0

    .line 63
    add-long/2addr v2, p2

    .line 64
    iput-wide v2, v1, La8/w0;->p:J

    .line 65
    .line 66
    invoke-virtual {v0, p0, p1}, La8/x0;->b(J)La8/x0;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    iput-object p0, v1, La8/w0;->g:La8/x0;

    .line 71
    .line 72
    return-void
.end method

.method public final g()Z
    .locals 4

    .line 1
    iget-boolean v0, p0, La8/w0;->e:Z

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    iget-boolean v0, p0, La8/w0;->f:Z

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, La8/w0;->a:Ljava/lang/Object;

    .line 10
    .line 11
    invoke-interface {p0}, Lh8/z0;->r()J

    .line 12
    .line 13
    .line 14
    move-result-wide v0

    .line 15
    const-wide/high16 v2, -0x8000000000000000L

    .line 16
    .line 17
    cmp-long p0, v0, v2

    .line 18
    .line 19
    if-nez p0, :cond_1

    .line 20
    .line 21
    :cond_0
    const/4 p0, 0x1

    .line 22
    return p0

    .line 23
    :cond_1
    const/4 p0, 0x0

    .line 24
    return p0
.end method

.method public final h()Z
    .locals 4

    .line 1
    iget-boolean v0, p0, La8/w0;->e:Z

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    invoke-virtual {p0}, La8/w0;->g()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0}, La8/w0;->d()J

    .line 12
    .line 13
    .line 14
    move-result-wide v0

    .line 15
    iget-object p0, p0, La8/w0;->g:La8/x0;

    .line 16
    .line 17
    iget-wide v2, p0, La8/x0;->b:J

    .line 18
    .line 19
    sub-long/2addr v0, v2

    .line 20
    const-wide v2, -0x7fffffffffffffffL    # -4.9E-324

    .line 21
    .line 22
    .line 23
    .line 24
    .line 25
    cmp-long p0, v0, v2

    .line 26
    .line 27
    if-ltz p0, :cond_1

    .line 28
    .line 29
    :cond_0
    const/4 p0, 0x1

    .line 30
    return p0

    .line 31
    :cond_1
    const/4 p0, 0x0

    .line 32
    return p0
.end method

.method public final i()V
    .locals 2

    .line 1
    invoke-virtual {p0}, La8/w0;->b()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, La8/w0;->a:Ljava/lang/Object;

    .line 5
    .line 6
    :try_start_0
    instance-of v1, v0, Lh8/c;
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 7
    .line 8
    iget-object p0, p0, La8/w0;->l:Lac/i;

    .line 9
    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    :try_start_1
    check-cast v0, Lh8/c;

    .line 13
    .line 14
    iget-object v0, v0, Lh8/c;->d:Lh8/z;

    .line 15
    .line 16
    invoke-virtual {p0, v0}, Lac/i;->j(Lh8/z;)V

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    :cond_0
    invoke-virtual {p0, v0}, Lac/i;->j(Lh8/z;)V
    :try_end_1
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_0

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :catch_0
    move-exception p0

    .line 25
    const-string v0, "MediaPeriodHolder"

    .line 26
    .line 27
    const-string v1, "Period release failed."

    .line 28
    .line 29
    invoke-static {v0, v1, p0}, Lw7/a;->p(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 30
    .line 31
    .line 32
    return-void
.end method

.method public final j(FLt7/p0;Z)Lj8/s;
    .locals 31

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, La8/w0;->k:Lh/w;

    .line 4
    .line 5
    iget-object v2, v0, La8/w0;->j:[La8/f;

    .line 6
    .line 7
    iget-object v3, v0, La8/w0;->n:Lh8/e1;

    .line 8
    .line 9
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    array-length v4, v2

    .line 13
    const/4 v5, 0x1

    .line 14
    add-int/2addr v4, v5

    .line 15
    new-array v4, v4, [I

    .line 16
    .line 17
    array-length v6, v2

    .line 18
    add-int/2addr v6, v5

    .line 19
    new-array v7, v6, [[Lt7/q0;

    .line 20
    .line 21
    array-length v8, v2

    .line 22
    add-int/2addr v8, v5

    .line 23
    new-array v13, v8, [[[I

    .line 24
    .line 25
    const/4 v9, 0x0

    .line 26
    :goto_0
    if-ge v9, v6, :cond_0

    .line 27
    .line 28
    iget v10, v3, Lh8/e1;->a:I

    .line 29
    .line 30
    new-array v11, v10, [Lt7/q0;

    .line 31
    .line 32
    aput-object v11, v7, v9

    .line 33
    .line 34
    new-array v10, v10, [[I

    .line 35
    .line 36
    aput-object v10, v13, v9

    .line 37
    .line 38
    add-int/lit8 v9, v9, 0x1

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    array-length v6, v2

    .line 42
    new-array v12, v6, [I

    .line 43
    .line 44
    const/4 v9, 0x0

    .line 45
    :goto_1
    if-ge v9, v6, :cond_1

    .line 46
    .line 47
    aget-object v10, v2, v9

    .line 48
    .line 49
    invoke-virtual {v10}, La8/f;->C()I

    .line 50
    .line 51
    .line 52
    move-result v10

    .line 53
    aput v10, v12, v9

    .line 54
    .line 55
    add-int/lit8 v9, v9, 0x1

    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_1
    const/4 v6, 0x0

    .line 59
    :goto_2
    iget v9, v3, Lh8/e1;->a:I

    .line 60
    .line 61
    if-ge v6, v9, :cond_a

    .line 62
    .line 63
    invoke-virtual {v3, v6}, Lh8/e1;->a(I)Lt7/q0;

    .line 64
    .line 65
    .line 66
    move-result-object v9

    .line 67
    iget v10, v9, Lt7/q0;->c:I

    .line 68
    .line 69
    const/4 v11, 0x5

    .line 70
    if-ne v10, v11, :cond_2

    .line 71
    .line 72
    move v10, v5

    .line 73
    goto :goto_3

    .line 74
    :cond_2
    const/4 v10, 0x0

    .line 75
    :goto_3
    array-length v11, v2

    .line 76
    move/from16 v16, v5

    .line 77
    .line 78
    const/16 p2, 0x0

    .line 79
    .line 80
    const/4 v8, 0x0

    .line 81
    const/4 v14, 0x0

    .line 82
    const/16 v17, 0x7

    .line 83
    .line 84
    :goto_4
    array-length v15, v2

    .line 85
    if-ge v14, v15, :cond_7

    .line 86
    .line 87
    aget-object v15, v2, v14

    .line 88
    .line 89
    move-object/from16 v19, v1

    .line 90
    .line 91
    move-object/from16 v20, v3

    .line 92
    .line 93
    move/from16 v18, v5

    .line 94
    .line 95
    move/from16 v1, p2

    .line 96
    .line 97
    move v5, v1

    .line 98
    :goto_5
    iget v3, v9, Lt7/q0;->a:I

    .line 99
    .line 100
    if-ge v5, v3, :cond_3

    .line 101
    .line 102
    iget-object v3, v9, Lt7/q0;->d:[Lt7/o;

    .line 103
    .line 104
    aget-object v3, v3, v5

    .line 105
    .line 106
    invoke-virtual {v15, v3}, La8/f;->B(Lt7/o;)I

    .line 107
    .line 108
    .line 109
    move-result v3

    .line 110
    and-int/lit8 v3, v3, 0x7

    .line 111
    .line 112
    invoke-static {v1, v3}, Ljava/lang/Math;->max(II)I

    .line 113
    .line 114
    .line 115
    move-result v1

    .line 116
    add-int/lit8 v5, v5, 0x1

    .line 117
    .line 118
    goto :goto_5

    .line 119
    :cond_3
    aget v3, v4, v14

    .line 120
    .line 121
    if-nez v3, :cond_4

    .line 122
    .line 123
    move/from16 v3, v18

    .line 124
    .line 125
    goto :goto_6

    .line 126
    :cond_4
    move/from16 v3, p2

    .line 127
    .line 128
    :goto_6
    if-gt v1, v8, :cond_5

    .line 129
    .line 130
    if-ne v1, v8, :cond_6

    .line 131
    .line 132
    if-eqz v10, :cond_6

    .line 133
    .line 134
    if-nez v16, :cond_6

    .line 135
    .line 136
    if-eqz v3, :cond_6

    .line 137
    .line 138
    :cond_5
    move v8, v1

    .line 139
    move/from16 v16, v3

    .line 140
    .line 141
    move v11, v14

    .line 142
    :cond_6
    add-int/lit8 v14, v14, 0x1

    .line 143
    .line 144
    move/from16 v5, v18

    .line 145
    .line 146
    move-object/from16 v1, v19

    .line 147
    .line 148
    move-object/from16 v3, v20

    .line 149
    .line 150
    goto :goto_4

    .line 151
    :cond_7
    move-object/from16 v19, v1

    .line 152
    .line 153
    move-object/from16 v20, v3

    .line 154
    .line 155
    move/from16 v18, v5

    .line 156
    .line 157
    array-length v1, v2

    .line 158
    if-ne v11, v1, :cond_8

    .line 159
    .line 160
    iget v1, v9, Lt7/q0;->a:I

    .line 161
    .line 162
    new-array v1, v1, [I

    .line 163
    .line 164
    goto :goto_8

    .line 165
    :cond_8
    aget-object v1, v2, v11

    .line 166
    .line 167
    iget v3, v9, Lt7/q0;->a:I

    .line 168
    .line 169
    new-array v3, v3, [I

    .line 170
    .line 171
    move/from16 v5, p2

    .line 172
    .line 173
    :goto_7
    iget v8, v9, Lt7/q0;->a:I

    .line 174
    .line 175
    if-ge v5, v8, :cond_9

    .line 176
    .line 177
    iget-object v8, v9, Lt7/q0;->d:[Lt7/o;

    .line 178
    .line 179
    aget-object v8, v8, v5

    .line 180
    .line 181
    invoke-virtual {v1, v8}, La8/f;->B(Lt7/o;)I

    .line 182
    .line 183
    .line 184
    move-result v8

    .line 185
    aput v8, v3, v5

    .line 186
    .line 187
    add-int/lit8 v5, v5, 0x1

    .line 188
    .line 189
    goto :goto_7

    .line 190
    :cond_9
    move-object v1, v3

    .line 191
    :goto_8
    aget v3, v4, v11

    .line 192
    .line 193
    aget-object v5, v7, v11

    .line 194
    .line 195
    aput-object v9, v5, v3

    .line 196
    .line 197
    aget-object v5, v13, v11

    .line 198
    .line 199
    aput-object v1, v5, v3

    .line 200
    .line 201
    add-int/lit8 v3, v3, 0x1

    .line 202
    .line 203
    aput v3, v4, v11

    .line 204
    .line 205
    add-int/lit8 v6, v6, 0x1

    .line 206
    .line 207
    move/from16 v5, v18

    .line 208
    .line 209
    move-object/from16 v1, v19

    .line 210
    .line 211
    move-object/from16 v3, v20

    .line 212
    .line 213
    goto/16 :goto_2

    .line 214
    .line 215
    :cond_a
    move-object/from16 v19, v1

    .line 216
    .line 217
    move/from16 v18, v5

    .line 218
    .line 219
    const/16 p2, 0x0

    .line 220
    .line 221
    const/16 v17, 0x7

    .line 222
    .line 223
    array-length v1, v2

    .line 224
    new-array v11, v1, [Lh8/e1;

    .line 225
    .line 226
    array-length v1, v2

    .line 227
    new-array v1, v1, [Ljava/lang/String;

    .line 228
    .line 229
    array-length v3, v2

    .line 230
    new-array v10, v3, [I

    .line 231
    .line 232
    move/from16 v3, p2

    .line 233
    .line 234
    :goto_9
    array-length v5, v2

    .line 235
    if-ge v3, v5, :cond_b

    .line 236
    .line 237
    aget v5, v4, v3

    .line 238
    .line 239
    new-instance v6, Lh8/e1;

    .line 240
    .line 241
    aget-object v8, v7, v3

    .line 242
    .line 243
    invoke-static {v5, v8}, Lw7/w;->F(I[Ljava/lang/Object;)[Ljava/lang/Object;

    .line 244
    .line 245
    .line 246
    move-result-object v8

    .line 247
    check-cast v8, [Lt7/q0;

    .line 248
    .line 249
    invoke-direct {v6, v8}, Lh8/e1;-><init>([Lt7/q0;)V

    .line 250
    .line 251
    .line 252
    aput-object v6, v11, v3

    .line 253
    .line 254
    aget-object v6, v13, v3

    .line 255
    .line 256
    invoke-static {v5, v6}, Lw7/w;->F(I[Ljava/lang/Object;)[Ljava/lang/Object;

    .line 257
    .line 258
    .line 259
    move-result-object v5

    .line 260
    check-cast v5, [[I

    .line 261
    .line 262
    aput-object v5, v13, v3

    .line 263
    .line 264
    aget-object v5, v2, v3

    .line 265
    .line 266
    invoke-virtual {v5}, La8/f;->k()Ljava/lang/String;

    .line 267
    .line 268
    .line 269
    move-result-object v5

    .line 270
    aput-object v5, v1, v3

    .line 271
    .line 272
    aget-object v5, v2, v3

    .line 273
    .line 274
    iget v5, v5, La8/f;->e:I

    .line 275
    .line 276
    aput v5, v10, v3

    .line 277
    .line 278
    add-int/lit8 v3, v3, 0x1

    .line 279
    .line 280
    goto :goto_9

    .line 281
    :cond_b
    array-length v1, v2

    .line 282
    aget v1, v4, v1

    .line 283
    .line 284
    new-instance v14, Lh8/e1;

    .line 285
    .line 286
    array-length v2, v2

    .line 287
    aget-object v2, v7, v2

    .line 288
    .line 289
    invoke-static {v1, v2}, Lw7/w;->F(I[Ljava/lang/Object;)[Ljava/lang/Object;

    .line 290
    .line 291
    .line 292
    move-result-object v1

    .line 293
    check-cast v1, [Lt7/q0;

    .line 294
    .line 295
    invoke-direct {v14, v1}, Lh8/e1;-><init>([Lt7/q0;)V

    .line 296
    .line 297
    .line 298
    new-instance v9, Lj8/r;

    .line 299
    .line 300
    invoke-direct/range {v9 .. v14}, Lj8/r;-><init>([I[Lh8/e1;[I[[[ILh8/e1;)V

    .line 301
    .line 302
    .line 303
    move-object/from16 v1, v19

    .line 304
    .line 305
    check-cast v1, Lj8/o;

    .line 306
    .line 307
    iget-object v2, v1, Lj8/o;->d:Ljava/lang/Object;

    .line 308
    .line 309
    monitor-enter v2

    .line 310
    :try_start_0
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 311
    .line 312
    .line 313
    move-result-object v3

    .line 314
    iput-object v3, v1, Lj8/o;->h:Ljava/lang/Thread;

    .line 315
    .line 316
    iget-object v3, v1, Lj8/o;->g:Lj8/i;

    .line 317
    .line 318
    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 319
    iget-object v2, v1, Lj8/o;->k:Ljava/lang/Boolean;

    .line 320
    .line 321
    if-nez v2, :cond_c

    .line 322
    .line 323
    iget-object v2, v1, Lj8/o;->e:Landroid/content/Context;

    .line 324
    .line 325
    if-eqz v2, :cond_c

    .line 326
    .line 327
    invoke-static {v2}, Lw7/w;->C(Landroid/content/Context;)Z

    .line 328
    .line 329
    .line 330
    move-result v2

    .line 331
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 332
    .line 333
    .line 334
    move-result-object v2

    .line 335
    iput-object v2, v1, Lj8/o;->k:Ljava/lang/Boolean;

    .line 336
    .line 337
    :cond_c
    iget-boolean v2, v3, Lj8/i;->y:Z

    .line 338
    .line 339
    if-eqz v2, :cond_d

    .line 340
    .line 341
    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 342
    .line 343
    const/16 v4, 0x20

    .line 344
    .line 345
    if-lt v2, v4, :cond_d

    .line 346
    .line 347
    iget-object v2, v1, Lj8/o;->i:La8/b;

    .line 348
    .line 349
    if-nez v2, :cond_d

    .line 350
    .line 351
    new-instance v2, La8/b;

    .line 352
    .line 353
    iget-object v4, v1, Lj8/o;->e:Landroid/content/Context;

    .line 354
    .line 355
    iget-object v5, v1, Lj8/o;->k:Ljava/lang/Boolean;

    .line 356
    .line 357
    invoke-direct {v2, v4, v1, v5}, La8/b;-><init>(Landroid/content/Context;Lj8/o;Ljava/lang/Boolean;)V

    .line 358
    .line 359
    .line 360
    iput-object v2, v1, Lj8/o;->i:La8/b;

    .line 361
    .line 362
    :cond_d
    iget v2, v9, Lj8/r;->a:I

    .line 363
    .line 364
    iget-object v4, v1, Lj8/o;->e:Landroid/content/Context;

    .line 365
    .line 366
    new-array v5, v2, [Lj8/p;

    .line 367
    .line 368
    move/from16 v6, p2

    .line 369
    .line 370
    :goto_a
    iget v7, v9, Lj8/r;->a:I

    .line 371
    .line 372
    const/4 v8, 0x2

    .line 373
    if-ge v6, v7, :cond_f

    .line 374
    .line 375
    aget v7, v10, v6

    .line 376
    .line 377
    if-ne v8, v7, :cond_e

    .line 378
    .line 379
    aget-object v7, v11, v6

    .line 380
    .line 381
    iget v7, v7, Lh8/e1;->a:I

    .line 382
    .line 383
    if-lez v7, :cond_e

    .line 384
    .line 385
    move/from16 v6, v18

    .line 386
    .line 387
    goto :goto_b

    .line 388
    :cond_e
    add-int/lit8 v6, v6, 0x1

    .line 389
    .line 390
    goto :goto_a

    .line 391
    :cond_f
    move/from16 v6, p2

    .line 392
    .line 393
    :goto_b
    new-instance v7, Lj8/c;

    .line 394
    .line 395
    invoke-direct {v7, v6, v1, v3, v12}, Lj8/c;-><init>(ZLjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 396
    .line 397
    .line 398
    new-instance v6, Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 399
    .line 400
    const/16 v14, 0x8

    .line 401
    .line 402
    invoke-direct {v6, v14}, Lcom/salesforce/marketingcloud/analytics/piwama/m;-><init>(I)V

    .line 403
    .line 404
    .line 405
    move/from16 v15, v18

    .line 406
    .line 407
    invoke-static {v15, v9, v13, v7, v6}, Lj8/o;->v(ILj8/r;[[[ILj8/l;Ljava/util/Comparator;)Landroid/util/Pair;

    .line 408
    .line 409
    .line 410
    move-result-object v6

    .line 411
    if-eqz v6, :cond_10

    .line 412
    .line 413
    iget-object v7, v6, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 414
    .line 415
    check-cast v7, Ljava/lang/Integer;

    .line 416
    .line 417
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 418
    .line 419
    .line 420
    move-result v7

    .line 421
    iget-object v15, v6, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 422
    .line 423
    check-cast v15, Lj8/p;

    .line 424
    .line 425
    aput-object v15, v5, v7

    .line 426
    .line 427
    :cond_10
    if-nez v6, :cond_11

    .line 428
    .line 429
    const/4 v6, 0x0

    .line 430
    goto :goto_c

    .line 431
    :cond_11
    iget-object v6, v6, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 432
    .line 433
    check-cast v6, Lj8/p;

    .line 434
    .line 435
    iget-object v15, v6, Lj8/p;->a:Lt7/q0;

    .line 436
    .line 437
    iget-object v6, v6, Lj8/p;->b:[I

    .line 438
    .line 439
    aget v6, v6, p2

    .line 440
    .line 441
    iget-object v15, v15, Lt7/q0;->d:[Lt7/o;

    .line 442
    .line 443
    aget-object v6, v15, v6

    .line 444
    .line 445
    iget-object v6, v6, Lt7/o;->d:Ljava/lang/String;

    .line 446
    .line 447
    :goto_c
    iget-object v15, v3, Lt7/u0;->o:Lt7/s0;

    .line 448
    .line 449
    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 450
    .line 451
    .line 452
    iget-boolean v15, v3, Lt7/u0;->g:Z

    .line 453
    .line 454
    if-eqz v15, :cond_12

    .line 455
    .line 456
    if-eqz v4, :cond_12

    .line 457
    .line 458
    invoke-static {v4}, Lw7/w;->o(Landroid/content/Context;)Landroid/graphics/Point;

    .line 459
    .line 460
    .line 461
    move-result-object v15

    .line 462
    :goto_d
    const/16 v16, 0x0

    .line 463
    .line 464
    goto :goto_e

    .line 465
    :cond_12
    const/4 v15, 0x0

    .line 466
    goto :goto_d

    .line 467
    :goto_e
    new-instance v7, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;

    .line 468
    .line 469
    invoke-direct {v7, v3, v6, v12, v15}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 470
    .line 471
    .line 472
    new-instance v12, Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 473
    .line 474
    move/from16 v15, v17

    .line 475
    .line 476
    invoke-direct {v12, v15}, Lcom/salesforce/marketingcloud/analytics/piwama/m;-><init>(I)V

    .line 477
    .line 478
    .line 479
    invoke-static {v8, v9, v13, v7, v12}, Lj8/o;->v(ILj8/r;[[[ILj8/l;Ljava/util/Comparator;)Landroid/util/Pair;

    .line 480
    .line 481
    .line 482
    move-result-object v7

    .line 483
    const/4 v12, 0x4

    .line 484
    if-nez v7, :cond_13

    .line 485
    .line 486
    new-instance v15, Lgr/k;

    .line 487
    .line 488
    invoke-direct {v15, v3, v14}, Lgr/k;-><init>(Ljava/lang/Object;I)V

    .line 489
    .line 490
    .line 491
    new-instance v8, Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 492
    .line 493
    const/4 v14, 0x6

    .line 494
    invoke-direct {v8, v14}, Lcom/salesforce/marketingcloud/analytics/piwama/m;-><init>(I)V

    .line 495
    .line 496
    .line 497
    invoke-static {v12, v9, v13, v15, v8}, Lj8/o;->v(ILj8/r;[[[ILj8/l;Ljava/util/Comparator;)Landroid/util/Pair;

    .line 498
    .line 499
    .line 500
    move-result-object v8

    .line 501
    goto :goto_f

    .line 502
    :cond_13
    move-object/from16 v8, v16

    .line 503
    .line 504
    :goto_f
    if-eqz v8, :cond_14

    .line 505
    .line 506
    iget-object v7, v8, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 507
    .line 508
    check-cast v7, Ljava/lang/Integer;

    .line 509
    .line 510
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 511
    .line 512
    .line 513
    move-result v7

    .line 514
    iget-object v8, v8, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 515
    .line 516
    check-cast v8, Lj8/p;

    .line 517
    .line 518
    aput-object v8, v5, v7

    .line 519
    .line 520
    goto :goto_10

    .line 521
    :cond_14
    if-eqz v7, :cond_15

    .line 522
    .line 523
    iget-object v8, v7, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 524
    .line 525
    check-cast v8, Ljava/lang/Integer;

    .line 526
    .line 527
    invoke-virtual {v8}, Ljava/lang/Integer;->intValue()I

    .line 528
    .line 529
    .line 530
    move-result v8

    .line 531
    iget-object v7, v7, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 532
    .line 533
    check-cast v7, Lj8/p;

    .line 534
    .line 535
    aput-object v7, v5, v8

    .line 536
    .line 537
    :cond_15
    :goto_10
    iget-boolean v7, v3, Lt7/u0;->q:Z

    .line 538
    .line 539
    if-eqz v7, :cond_19

    .line 540
    .line 541
    if-nez v4, :cond_16

    .line 542
    .line 543
    goto :goto_11

    .line 544
    :cond_16
    const-string v7, "captioning"

    .line 545
    .line 546
    invoke-virtual {v4, v7}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 547
    .line 548
    .line 549
    move-result-object v4

    .line 550
    check-cast v4, Landroid/view/accessibility/CaptioningManager;

    .line 551
    .line 552
    if-eqz v4, :cond_19

    .line 553
    .line 554
    invoke-virtual {v4}, Landroid/view/accessibility/CaptioningManager;->isEnabled()Z

    .line 555
    .line 556
    .line 557
    move-result v7

    .line 558
    if-nez v7, :cond_17

    .line 559
    .line 560
    goto :goto_11

    .line 561
    :cond_17
    invoke-virtual {v4}, Landroid/view/accessibility/CaptioningManager;->getLocale()Ljava/util/Locale;

    .line 562
    .line 563
    .line 564
    move-result-object v4

    .line 565
    if-nez v4, :cond_18

    .line 566
    .line 567
    goto :goto_11

    .line 568
    :cond_18
    sget-object v7, Lw7/w;->a:Ljava/lang/String;

    .line 569
    .line 570
    invoke-virtual {v4}, Ljava/util/Locale;->toLanguageTag()Ljava/lang/String;

    .line 571
    .line 572
    .line 573
    move-result-object v4

    .line 574
    goto :goto_12

    .line 575
    :cond_19
    :goto_11
    move-object/from16 v4, v16

    .line 576
    .line 577
    :goto_12
    new-instance v7, Lbb/i;

    .line 578
    .line 579
    const/16 v8, 0x8

    .line 580
    .line 581
    invoke-direct {v7, v3, v6, v4, v8}, Lbb/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 582
    .line 583
    .line 584
    new-instance v4, Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 585
    .line 586
    const/16 v6, 0x9

    .line 587
    .line 588
    invoke-direct {v4, v6}, Lcom/salesforce/marketingcloud/analytics/piwama/m;-><init>(I)V

    .line 589
    .line 590
    .line 591
    const/4 v6, 0x3

    .line 592
    invoke-static {v6, v9, v13, v7, v4}, Lj8/o;->v(ILj8/r;[[[ILj8/l;Ljava/util/Comparator;)Landroid/util/Pair;

    .line 593
    .line 594
    .line 595
    move-result-object v4

    .line 596
    if-eqz v4, :cond_1a

    .line 597
    .line 598
    iget-object v7, v4, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 599
    .line 600
    check-cast v7, Ljava/lang/Integer;

    .line 601
    .line 602
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 603
    .line 604
    .line 605
    move-result v7

    .line 606
    iget-object v4, v4, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 607
    .line 608
    check-cast v4, Lj8/p;

    .line 609
    .line 610
    aput-object v4, v5, v7

    .line 611
    .line 612
    :cond_1a
    move/from16 v4, p2

    .line 613
    .line 614
    :goto_13
    if-ge v4, v2, :cond_22

    .line 615
    .line 616
    aget v7, v10, v4

    .line 617
    .line 618
    const/4 v8, 0x2

    .line 619
    if-eq v7, v8, :cond_21

    .line 620
    .line 621
    const/4 v15, 0x1

    .line 622
    if-eq v7, v15, :cond_21

    .line 623
    .line 624
    if-eq v7, v6, :cond_21

    .line 625
    .line 626
    if-eq v7, v12, :cond_21

    .line 627
    .line 628
    aget-object v7, v11, v4

    .line 629
    .line 630
    aget-object v8, v13, v4

    .line 631
    .line 632
    move/from16 v14, p2

    .line 633
    .line 634
    move v15, v14

    .line 635
    move-object/from16 v6, v16

    .line 636
    .line 637
    move-object/from16 v21, v6

    .line 638
    .line 639
    :goto_14
    iget v12, v7, Lh8/e1;->a:I

    .line 640
    .line 641
    if-ge v14, v12, :cond_1f

    .line 642
    .line 643
    invoke-virtual {v7, v14}, Lh8/e1;->a(I)Lt7/q0;

    .line 644
    .line 645
    .line 646
    move-result-object v12

    .line 647
    aget-object v22, v8, v14

    .line 648
    .line 649
    move/from16 v23, v4

    .line 650
    .line 651
    move-object/from16 v24, v7

    .line 652
    .line 653
    move-object/from16 v4, v21

    .line 654
    .line 655
    move/from16 v21, v15

    .line 656
    .line 657
    move-object v15, v6

    .line 658
    move/from16 v6, p2

    .line 659
    .line 660
    :goto_15
    iget v7, v12, Lt7/q0;->a:I

    .line 661
    .line 662
    if-ge v6, v7, :cond_1e

    .line 663
    .line 664
    aget v7, v22, v6

    .line 665
    .line 666
    move/from16 v25, v6

    .line 667
    .line 668
    iget-boolean v6, v3, Lj8/i;->z:Z

    .line 669
    .line 670
    invoke-static {v7, v6}, La8/f;->n(IZ)Z

    .line 671
    .line 672
    .line 673
    move-result v6

    .line 674
    if-eqz v6, :cond_1c

    .line 675
    .line 676
    iget-object v6, v12, Lt7/q0;->d:[Lt7/o;

    .line 677
    .line 678
    aget-object v6, v6, v25

    .line 679
    .line 680
    new-instance v7, Lj8/g;

    .line 681
    .line 682
    move-object/from16 v26, v8

    .line 683
    .line 684
    aget v8, v22, v25

    .line 685
    .line 686
    invoke-direct {v7, v6, v8}, Lj8/g;-><init>(Lt7/o;I)V

    .line 687
    .line 688
    .line 689
    if-eqz v4, :cond_1b

    .line 690
    .line 691
    sget-object v6, Lhr/z;->a:Lhr/x;

    .line 692
    .line 693
    iget-boolean v8, v7, Lj8/g;->e:Z

    .line 694
    .line 695
    move-object/from16 v27, v10

    .line 696
    .line 697
    iget-boolean v10, v4, Lj8/g;->e:Z

    .line 698
    .line 699
    invoke-virtual {v6, v8, v10}, Lhr/x;->c(ZZ)Lhr/z;

    .line 700
    .line 701
    .line 702
    move-result-object v6

    .line 703
    iget-boolean v8, v7, Lj8/g;->d:Z

    .line 704
    .line 705
    iget-boolean v10, v4, Lj8/g;->d:Z

    .line 706
    .line 707
    invoke-virtual {v6, v8, v10}, Lhr/z;->c(ZZ)Lhr/z;

    .line 708
    .line 709
    .line 710
    move-result-object v6

    .line 711
    invoke-virtual {v6}, Lhr/z;->e()I

    .line 712
    .line 713
    .line 714
    move-result v6

    .line 715
    if-lez v6, :cond_1d

    .line 716
    .line 717
    goto :goto_16

    .line 718
    :cond_1b
    move-object/from16 v27, v10

    .line 719
    .line 720
    :goto_16
    move-object v4, v7

    .line 721
    move-object v15, v12

    .line 722
    move/from16 v21, v25

    .line 723
    .line 724
    goto :goto_17

    .line 725
    :cond_1c
    move-object/from16 v26, v8

    .line 726
    .line 727
    move-object/from16 v27, v10

    .line 728
    .line 729
    :cond_1d
    :goto_17
    add-int/lit8 v6, v25, 0x1

    .line 730
    .line 731
    move-object/from16 v8, v26

    .line 732
    .line 733
    move-object/from16 v10, v27

    .line 734
    .line 735
    goto :goto_15

    .line 736
    :cond_1e
    move-object/from16 v26, v8

    .line 737
    .line 738
    move-object/from16 v27, v10

    .line 739
    .line 740
    add-int/lit8 v14, v14, 0x1

    .line 741
    .line 742
    move-object v6, v15

    .line 743
    move/from16 v15, v21

    .line 744
    .line 745
    move-object/from16 v7, v24

    .line 746
    .line 747
    move-object/from16 v21, v4

    .line 748
    .line 749
    move/from16 v4, v23

    .line 750
    .line 751
    goto :goto_14

    .line 752
    :cond_1f
    move/from16 v23, v4

    .line 753
    .line 754
    move-object/from16 v27, v10

    .line 755
    .line 756
    if-nez v6, :cond_20

    .line 757
    .line 758
    move-object/from16 v4, v16

    .line 759
    .line 760
    goto :goto_18

    .line 761
    :cond_20
    new-instance v4, Lj8/p;

    .line 762
    .line 763
    filled-new-array {v15}, [I

    .line 764
    .line 765
    .line 766
    move-result-object v7

    .line 767
    move/from16 v8, p2

    .line 768
    .line 769
    invoke-direct {v4, v8, v6, v7}, Lj8/p;-><init>(ILt7/q0;[I)V

    .line 770
    .line 771
    .line 772
    :goto_18
    aput-object v4, v5, v23

    .line 773
    .line 774
    goto :goto_19

    .line 775
    :cond_21
    move/from16 v23, v4

    .line 776
    .line 777
    move-object/from16 v27, v10

    .line 778
    .line 779
    :goto_19
    add-int/lit8 v4, v23, 0x1

    .line 780
    .line 781
    move-object/from16 v10, v27

    .line 782
    .line 783
    const/16 p2, 0x0

    .line 784
    .line 785
    const/4 v6, 0x3

    .line 786
    const/4 v12, 0x4

    .line 787
    goto/16 :goto_13

    .line 788
    .line 789
    :cond_22
    iget v4, v9, Lj8/r;->a:I

    .line 790
    .line 791
    iget-object v6, v9, Lj8/r;->c:[Lh8/e1;

    .line 792
    .line 793
    new-instance v7, Ljava/util/HashMap;

    .line 794
    .line 795
    invoke-direct {v7}, Ljava/util/HashMap;-><init>()V

    .line 796
    .line 797
    .line 798
    const/4 v8, 0x0

    .line 799
    :goto_1a
    if-ge v8, v4, :cond_23

    .line 800
    .line 801
    aget-object v10, v6, v8

    .line 802
    .line 803
    invoke-static {v10, v3, v7}, Lj8/o;->q(Lh8/e1;Lj8/i;Ljava/util/HashMap;)V

    .line 804
    .line 805
    .line 806
    add-int/lit8 v8, v8, 0x1

    .line 807
    .line 808
    goto :goto_1a

    .line 809
    :cond_23
    iget-object v8, v9, Lj8/r;->f:Lh8/e1;

    .line 810
    .line 811
    invoke-static {v8, v3, v7}, Lj8/o;->q(Lh8/e1;Lj8/i;Ljava/util/HashMap;)V

    .line 812
    .line 813
    .line 814
    const/4 v8, 0x0

    .line 815
    :goto_1b
    const/4 v10, -0x1

    .line 816
    if-ge v8, v4, :cond_27

    .line 817
    .line 818
    iget-object v11, v9, Lj8/r;->b:[I

    .line 819
    .line 820
    aget v11, v11, v8

    .line 821
    .line 822
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 823
    .line 824
    .line 825
    move-result-object v11

    .line 826
    invoke-virtual {v7, v11}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 827
    .line 828
    .line 829
    move-result-object v11

    .line 830
    check-cast v11, Lt7/r0;

    .line 831
    .line 832
    if-nez v11, :cond_24

    .line 833
    .line 834
    goto :goto_1e

    .line 835
    :cond_24
    iget-object v12, v11, Lt7/r0;->a:Lt7/q0;

    .line 836
    .line 837
    iget-object v11, v11, Lt7/r0;->b:Lhr/h0;

    .line 838
    .line 839
    invoke-virtual {v11}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 840
    .line 841
    .line 842
    move-result v13

    .line 843
    if-nez v13, :cond_26

    .line 844
    .line 845
    aget-object v13, v6, v8

    .line 846
    .line 847
    iget-object v13, v13, Lh8/e1;->b:Lhr/x0;

    .line 848
    .line 849
    invoke-virtual {v13, v12}, Lhr/h0;->indexOf(Ljava/lang/Object;)I

    .line 850
    .line 851
    .line 852
    move-result v13

    .line 853
    if-ltz v13, :cond_25

    .line 854
    .line 855
    goto :goto_1c

    .line 856
    :cond_25
    move v13, v10

    .line 857
    :goto_1c
    if-eq v13, v10, :cond_26

    .line 858
    .line 859
    new-instance v10, Lj8/p;

    .line 860
    .line 861
    invoke-static {v11}, Llp/de;->f(Ljava/util/Collection;)[I

    .line 862
    .line 863
    .line 864
    move-result-object v11

    .line 865
    const/4 v13, 0x0

    .line 866
    invoke-direct {v10, v13, v12, v11}, Lj8/p;-><init>(ILt7/q0;[I)V

    .line 867
    .line 868
    .line 869
    goto :goto_1d

    .line 870
    :cond_26
    move-object/from16 v10, v16

    .line 871
    .line 872
    :goto_1d
    aput-object v10, v5, v8

    .line 873
    .line 874
    :goto_1e
    add-int/lit8 v8, v8, 0x1

    .line 875
    .line 876
    goto :goto_1b

    .line 877
    :cond_27
    iget v4, v9, Lj8/r;->a:I

    .line 878
    .line 879
    const/4 v6, 0x0

    .line 880
    :goto_1f
    if-ge v6, v4, :cond_2b

    .line 881
    .line 882
    iget-object v7, v9, Lj8/r;->c:[Lh8/e1;

    .line 883
    .line 884
    aget-object v7, v7, v6

    .line 885
    .line 886
    iget-object v8, v3, Lj8/i;->B:Landroid/util/SparseArray;

    .line 887
    .line 888
    invoke-virtual {v8, v6}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 889
    .line 890
    .line 891
    move-result-object v8

    .line 892
    check-cast v8, Ljava/util/Map;

    .line 893
    .line 894
    if-eqz v8, :cond_2a

    .line 895
    .line 896
    invoke-interface {v8, v7}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 897
    .line 898
    .line 899
    move-result v8

    .line 900
    if-eqz v8, :cond_2a

    .line 901
    .line 902
    iget-object v8, v3, Lj8/i;->B:Landroid/util/SparseArray;

    .line 903
    .line 904
    invoke-virtual {v8, v6}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 905
    .line 906
    .line 907
    move-result-object v8

    .line 908
    check-cast v8, Ljava/util/Map;

    .line 909
    .line 910
    if-eqz v8, :cond_29

    .line 911
    .line 912
    invoke-interface {v8, v7}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 913
    .line 914
    .line 915
    move-result-object v7

    .line 916
    if-nez v7, :cond_28

    .line 917
    .line 918
    goto :goto_20

    .line 919
    :cond_28
    new-instance v0, Ljava/lang/ClassCastException;

    .line 920
    .line 921
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 922
    .line 923
    .line 924
    throw v0

    .line 925
    :cond_29
    :goto_20
    aput-object v16, v5, v6

    .line 926
    .line 927
    :cond_2a
    add-int/lit8 v6, v6, 0x1

    .line 928
    .line 929
    goto :goto_1f

    .line 930
    :cond_2b
    const/4 v4, 0x0

    .line 931
    :goto_21
    if-ge v4, v2, :cond_2e

    .line 932
    .line 933
    iget-object v6, v9, Lj8/r;->b:[I

    .line 934
    .line 935
    aget v6, v6, v4

    .line 936
    .line 937
    iget-object v7, v3, Lj8/i;->C:Landroid/util/SparseBooleanArray;

    .line 938
    .line 939
    invoke-virtual {v7, v4}, Landroid/util/SparseBooleanArray;->get(I)Z

    .line 940
    .line 941
    .line 942
    move-result v7

    .line 943
    if-nez v7, :cond_2c

    .line 944
    .line 945
    iget-object v7, v3, Lt7/u0;->t:Lhr/k0;

    .line 946
    .line 947
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 948
    .line 949
    .line 950
    move-result-object v6

    .line 951
    invoke-virtual {v7, v6}, Lhr/c0;->contains(Ljava/lang/Object;)Z

    .line 952
    .line 953
    .line 954
    move-result v6

    .line 955
    if-eqz v6, :cond_2d

    .line 956
    .line 957
    :cond_2c
    aput-object v16, v5, v4

    .line 958
    .line 959
    :cond_2d
    add-int/lit8 v4, v4, 0x1

    .line 960
    .line 961
    goto :goto_21

    .line 962
    :cond_2e
    iget-object v4, v1, Lj8/o;->f:Lst/b;

    .line 963
    .line 964
    iget-object v1, v1, Lh/w;->c:Ljava/lang/Object;

    .line 965
    .line 966
    check-cast v1, Lk8/d;

    .line 967
    .line 968
    invoke-static {v1}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 969
    .line 970
    .line 971
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 972
    .line 973
    .line 974
    new-instance v1, Ljava/util/ArrayList;

    .line 975
    .line 976
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 977
    .line 978
    .line 979
    const/4 v4, 0x0

    .line 980
    :goto_22
    array-length v6, v5

    .line 981
    const-wide/16 v7, 0x0

    .line 982
    .line 983
    if-ge v4, v6, :cond_30

    .line 984
    .line 985
    aget-object v6, v5, v4

    .line 986
    .line 987
    if-eqz v6, :cond_2f

    .line 988
    .line 989
    iget-object v6, v6, Lj8/p;->b:[I

    .line 990
    .line 991
    array-length v6, v6

    .line 992
    const/4 v15, 0x1

    .line 993
    if-le v6, v15, :cond_2f

    .line 994
    .line 995
    invoke-static {}, Lhr/h0;->o()Lhr/e0;

    .line 996
    .line 997
    .line 998
    move-result-object v6

    .line 999
    new-instance v11, Lj8/a;

    .line 1000
    .line 1001
    invoke-direct {v11, v7, v8, v7, v8}, Lj8/a;-><init>(JJ)V

    .line 1002
    .line 1003
    .line 1004
    invoke-virtual {v6, v11}, Lhr/b0;->a(Ljava/lang/Object;)V

    .line 1005
    .line 1006
    .line 1007
    invoke-virtual {v1, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1008
    .line 1009
    .line 1010
    move-object/from16 v6, v16

    .line 1011
    .line 1012
    goto :goto_23

    .line 1013
    :cond_2f
    move-object/from16 v6, v16

    .line 1014
    .line 1015
    invoke-virtual {v1, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1016
    .line 1017
    .line 1018
    :goto_23
    add-int/lit8 v4, v4, 0x1

    .line 1019
    .line 1020
    move-object/from16 v16, v6

    .line 1021
    .line 1022
    goto :goto_22

    .line 1023
    :cond_30
    move-object/from16 v6, v16

    .line 1024
    .line 1025
    array-length v4, v5

    .line 1026
    new-array v11, v4, [[J

    .line 1027
    .line 1028
    const/4 v12, 0x0

    .line 1029
    :goto_24
    array-length v13, v5

    .line 1030
    if-ge v12, v13, :cond_34

    .line 1031
    .line 1032
    aget-object v13, v5, v12

    .line 1033
    .line 1034
    if-nez v13, :cond_31

    .line 1035
    .line 1036
    const/4 v6, 0x0

    .line 1037
    new-array v13, v6, [J

    .line 1038
    .line 1039
    aput-object v13, v11, v12

    .line 1040
    .line 1041
    goto :goto_26

    .line 1042
    :cond_31
    iget-object v6, v13, Lj8/p;->b:[I

    .line 1043
    .line 1044
    array-length v7, v6

    .line 1045
    new-array v7, v7, [J

    .line 1046
    .line 1047
    aput-object v7, v11, v12

    .line 1048
    .line 1049
    const/4 v7, 0x0

    .line 1050
    :goto_25
    array-length v8, v6

    .line 1051
    if-ge v7, v8, :cond_33

    .line 1052
    .line 1053
    iget-object v8, v13, Lj8/p;->a:Lt7/q0;

    .line 1054
    .line 1055
    aget v22, v6, v7

    .line 1056
    .line 1057
    iget-object v8, v8, Lt7/q0;->d:[Lt7/o;

    .line 1058
    .line 1059
    aget-object v8, v8, v22

    .line 1060
    .line 1061
    iget v8, v8, Lt7/o;->j:I

    .line 1062
    .line 1063
    const-wide/16 v22, -0x1

    .line 1064
    .line 1065
    int-to-long v14, v8

    .line 1066
    aget-object v8, v11, v12

    .line 1067
    .line 1068
    cmp-long v24, v14, v22

    .line 1069
    .line 1070
    if-nez v24, :cond_32

    .line 1071
    .line 1072
    const-wide/16 v14, 0x0

    .line 1073
    .line 1074
    :cond_32
    aput-wide v14, v8, v7

    .line 1075
    .line 1076
    add-int/lit8 v7, v7, 0x1

    .line 1077
    .line 1078
    goto :goto_25

    .line 1079
    :cond_33
    aget-object v6, v11, v12

    .line 1080
    .line 1081
    invoke-static {v6}, Ljava/util/Arrays;->sort([J)V

    .line 1082
    .line 1083
    .line 1084
    :goto_26
    add-int/lit8 v12, v12, 0x1

    .line 1085
    .line 1086
    const/4 v6, 0x0

    .line 1087
    const-wide/16 v7, 0x0

    .line 1088
    .line 1089
    goto :goto_24

    .line 1090
    :cond_34
    const-wide/16 v22, -0x1

    .line 1091
    .line 1092
    new-array v6, v4, [I

    .line 1093
    .line 1094
    new-array v7, v4, [J

    .line 1095
    .line 1096
    const/4 v8, 0x0

    .line 1097
    :goto_27
    if-ge v8, v4, :cond_36

    .line 1098
    .line 1099
    aget-object v12, v11, v8

    .line 1100
    .line 1101
    array-length v13, v12

    .line 1102
    if-nez v13, :cond_35

    .line 1103
    .line 1104
    const-wide/16 v14, 0x0

    .line 1105
    .line 1106
    goto :goto_28

    .line 1107
    :cond_35
    const/4 v13, 0x0

    .line 1108
    aget-wide v14, v12, v13

    .line 1109
    .line 1110
    :goto_28
    aput-wide v14, v7, v8

    .line 1111
    .line 1112
    add-int/lit8 v8, v8, 0x1

    .line 1113
    .line 1114
    goto :goto_27

    .line 1115
    :cond_36
    invoke-static {v1, v7}, Lj8/b;->m(Ljava/util/ArrayList;[J)V

    .line 1116
    .line 1117
    .line 1118
    const-string v8, "expectedValuesPerKey"

    .line 1119
    .line 1120
    const/4 v12, 0x2

    .line 1121
    invoke-static {v12, v8}, Lhr/q;->c(ILjava/lang/String;)V

    .line 1122
    .line 1123
    .line 1124
    new-instance v8, Ljava/util/TreeMap;

    .line 1125
    .line 1126
    sget-object v12, Lhr/v0;->e:Lhr/v0;

    .line 1127
    .line 1128
    invoke-direct {v8, v12}, Ljava/util/TreeMap;-><init>(Ljava/util/Comparator;)V

    .line 1129
    .line 1130
    .line 1131
    new-instance v12, Lhr/s0;

    .line 1132
    .line 1133
    invoke-direct {v12}, Lhr/s0;-><init>()V

    .line 1134
    .line 1135
    .line 1136
    new-instance v13, Lhr/t0;

    .line 1137
    .line 1138
    invoke-direct {v13}, Ljava/lang/Object;-><init>()V

    .line 1139
    .line 1140
    .line 1141
    invoke-interface {v8}, Ljava/util/Map;->isEmpty()Z

    .line 1142
    .line 1143
    .line 1144
    move-result v14

    .line 1145
    if-eqz v14, :cond_65

    .line 1146
    .line 1147
    iput-object v8, v13, Lhr/t0;->g:Ljava/util/Map;

    .line 1148
    .line 1149
    iput-object v12, v13, Lhr/t0;->i:Lhr/s0;

    .line 1150
    .line 1151
    const/4 v8, 0x0

    .line 1152
    :goto_29
    if-ge v8, v4, :cond_3f

    .line 1153
    .line 1154
    aget-object v12, v11, v8

    .line 1155
    .line 1156
    array-length v14, v12

    .line 1157
    const/4 v15, 0x1

    .line 1158
    if-gt v14, v15, :cond_37

    .line 1159
    .line 1160
    move/from16 v20, v4

    .line 1161
    .line 1162
    move-object/from16 v21, v11

    .line 1163
    .line 1164
    :goto_2a
    move-object/from16 v26, v6

    .line 1165
    .line 1166
    move/from16 v27, v8

    .line 1167
    .line 1168
    goto/16 :goto_31

    .line 1169
    .line 1170
    :cond_37
    array-length v12, v12

    .line 1171
    new-array v14, v12, [D

    .line 1172
    .line 1173
    const/4 v15, 0x0

    .line 1174
    :goto_2b
    aget-object v10, v11, v8

    .line 1175
    .line 1176
    move/from16 v20, v4

    .line 1177
    .line 1178
    array-length v4, v10

    .line 1179
    const-wide/16 v24, 0x0

    .line 1180
    .line 1181
    if-ge v15, v4, :cond_39

    .line 1182
    .line 1183
    move-object v4, v11

    .line 1184
    aget-wide v10, v10, v15

    .line 1185
    .line 1186
    cmp-long v21, v10, v22

    .line 1187
    .line 1188
    if-nez v21, :cond_38

    .line 1189
    .line 1190
    goto :goto_2c

    .line 1191
    :cond_38
    long-to-double v10, v10

    .line 1192
    invoke-static {v10, v11}, Ljava/lang/Math;->log(D)D

    .line 1193
    .line 1194
    .line 1195
    move-result-wide v24

    .line 1196
    :goto_2c
    aput-wide v24, v14, v15

    .line 1197
    .line 1198
    add-int/lit8 v15, v15, 0x1

    .line 1199
    .line 1200
    move-object v11, v4

    .line 1201
    move/from16 v4, v20

    .line 1202
    .line 1203
    goto :goto_2b

    .line 1204
    :cond_39
    move-object v4, v11

    .line 1205
    add-int/lit8 v12, v12, -0x1

    .line 1206
    .line 1207
    aget-wide v10, v14, v12

    .line 1208
    .line 1209
    const/4 v15, 0x0

    .line 1210
    aget-wide v26, v14, v15

    .line 1211
    .line 1212
    sub-double v10, v10, v26

    .line 1213
    .line 1214
    const/4 v15, 0x0

    .line 1215
    :goto_2d
    if-ge v15, v12, :cond_3e

    .line 1216
    .line 1217
    aget-wide v26, v14, v15

    .line 1218
    .line 1219
    add-int/lit8 v15, v15, 0x1

    .line 1220
    .line 1221
    aget-wide v28, v14, v15

    .line 1222
    .line 1223
    add-double v26, v26, v28

    .line 1224
    .line 1225
    const-wide/high16 v28, 0x3fe0000000000000L    # 0.5

    .line 1226
    .line 1227
    mul-double v26, v26, v28

    .line 1228
    .line 1229
    cmpl-double v21, v10, v24

    .line 1230
    .line 1231
    if-nez v21, :cond_3a

    .line 1232
    .line 1233
    const-wide/high16 v26, 0x3ff0000000000000L    # 1.0

    .line 1234
    .line 1235
    :goto_2e
    move-object/from16 v21, v4

    .line 1236
    .line 1237
    goto :goto_2f

    .line 1238
    :cond_3a
    const/16 v21, 0x0

    .line 1239
    .line 1240
    aget-wide v28, v14, v21

    .line 1241
    .line 1242
    sub-double v26, v26, v28

    .line 1243
    .line 1244
    div-double v26, v26, v10

    .line 1245
    .line 1246
    goto :goto_2e

    .line 1247
    :goto_2f
    invoke-static/range {v26 .. v27}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 1248
    .line 1249
    .line 1250
    move-result-object v4

    .line 1251
    move-object/from16 v26, v6

    .line 1252
    .line 1253
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1254
    .line 1255
    .line 1256
    move-result-object v6

    .line 1257
    move/from16 v27, v8

    .line 1258
    .line 1259
    iget-object v8, v13, Lhr/t0;->g:Ljava/util/Map;

    .line 1260
    .line 1261
    invoke-interface {v8, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1262
    .line 1263
    .line 1264
    move-result-object v28

    .line 1265
    move-wide/from16 v29, v10

    .line 1266
    .line 1267
    move-object/from16 v10, v28

    .line 1268
    .line 1269
    check-cast v10, Ljava/util/Collection;

    .line 1270
    .line 1271
    if-nez v10, :cond_3c

    .line 1272
    .line 1273
    iget-object v10, v13, Lhr/t0;->i:Lhr/s0;

    .line 1274
    .line 1275
    invoke-virtual {v10}, Lhr/s0;->get()Ljava/lang/Object;

    .line 1276
    .line 1277
    .line 1278
    move-result-object v10

    .line 1279
    check-cast v10, Ljava/util/List;

    .line 1280
    .line 1281
    check-cast v10, Ljava/util/List;

    .line 1282
    .line 1283
    invoke-interface {v10, v6}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 1284
    .line 1285
    .line 1286
    move-result v6

    .line 1287
    if-eqz v6, :cond_3b

    .line 1288
    .line 1289
    iget v6, v13, Lhr/t0;->h:I

    .line 1290
    .line 1291
    const/16 v18, 0x1

    .line 1292
    .line 1293
    add-int/lit8 v6, v6, 0x1

    .line 1294
    .line 1295
    iput v6, v13, Lhr/t0;->h:I

    .line 1296
    .line 1297
    invoke-interface {v8, v4, v10}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1298
    .line 1299
    .line 1300
    goto :goto_30

    .line 1301
    :cond_3b
    new-instance v0, Ljava/lang/AssertionError;

    .line 1302
    .line 1303
    const-string v1, "New Collection violated the Collection spec"

    .line 1304
    .line 1305
    invoke-direct {v0, v1}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    .line 1306
    .line 1307
    .line 1308
    throw v0

    .line 1309
    :cond_3c
    const/16 v18, 0x1

    .line 1310
    .line 1311
    invoke-interface {v10, v6}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 1312
    .line 1313
    .line 1314
    move-result v4

    .line 1315
    if-eqz v4, :cond_3d

    .line 1316
    .line 1317
    iget v4, v13, Lhr/t0;->h:I

    .line 1318
    .line 1319
    add-int/lit8 v4, v4, 0x1

    .line 1320
    .line 1321
    iput v4, v13, Lhr/t0;->h:I

    .line 1322
    .line 1323
    :cond_3d
    :goto_30
    move-object/from16 v4, v21

    .line 1324
    .line 1325
    move-object/from16 v6, v26

    .line 1326
    .line 1327
    move/from16 v8, v27

    .line 1328
    .line 1329
    move-wide/from16 v10, v29

    .line 1330
    .line 1331
    goto :goto_2d

    .line 1332
    :cond_3e
    move-object/from16 v21, v4

    .line 1333
    .line 1334
    goto/16 :goto_2a

    .line 1335
    .line 1336
    :goto_31
    add-int/lit8 v8, v27, 0x1

    .line 1337
    .line 1338
    move/from16 v4, v20

    .line 1339
    .line 1340
    move-object/from16 v11, v21

    .line 1341
    .line 1342
    move-object/from16 v6, v26

    .line 1343
    .line 1344
    const/4 v10, -0x1

    .line 1345
    goto/16 :goto_29

    .line 1346
    .line 1347
    :cond_3f
    move-object/from16 v26, v6

    .line 1348
    .line 1349
    move-object/from16 v21, v11

    .line 1350
    .line 1351
    iget-object v4, v13, Lhr/o;->e:Lhr/n;

    .line 1352
    .line 1353
    if-nez v4, :cond_40

    .line 1354
    .line 1355
    new-instance v4, Lhr/n;

    .line 1356
    .line 1357
    const/4 v15, 0x0

    .line 1358
    invoke-direct {v4, v15, v13}, Lhr/n;-><init>(ILjava/io/Serializable;)V

    .line 1359
    .line 1360
    .line 1361
    iput-object v4, v13, Lhr/o;->e:Lhr/n;

    .line 1362
    .line 1363
    :cond_40
    invoke-static {v4}, Lhr/h0;->p(Ljava/util/Collection;)Lhr/h0;

    .line 1364
    .line 1365
    .line 1366
    move-result-object v4

    .line 1367
    const/4 v6, 0x0

    .line 1368
    :goto_32
    invoke-virtual {v4}, Ljava/util/AbstractCollection;->size()I

    .line 1369
    .line 1370
    .line 1371
    move-result v8

    .line 1372
    if-ge v6, v8, :cond_41

    .line 1373
    .line 1374
    invoke-interface {v4, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1375
    .line 1376
    .line 1377
    move-result-object v8

    .line 1378
    check-cast v8, Ljava/lang/Integer;

    .line 1379
    .line 1380
    invoke-virtual {v8}, Ljava/lang/Integer;->intValue()I

    .line 1381
    .line 1382
    .line 1383
    move-result v8

    .line 1384
    aget v10, v26, v8

    .line 1385
    .line 1386
    const/16 v18, 0x1

    .line 1387
    .line 1388
    add-int/lit8 v10, v10, 0x1

    .line 1389
    .line 1390
    aput v10, v26, v8

    .line 1391
    .line 1392
    aget-object v11, v21, v8

    .line 1393
    .line 1394
    aget-wide v10, v11, v10

    .line 1395
    .line 1396
    aput-wide v10, v7, v8

    .line 1397
    .line 1398
    invoke-static {v1, v7}, Lj8/b;->m(Ljava/util/ArrayList;[J)V

    .line 1399
    .line 1400
    .line 1401
    add-int/lit8 v6, v6, 0x1

    .line 1402
    .line 1403
    goto :goto_32

    .line 1404
    :cond_41
    const/4 v4, 0x0

    .line 1405
    :goto_33
    array-length v6, v5

    .line 1406
    if-ge v4, v6, :cond_43

    .line 1407
    .line 1408
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1409
    .line 1410
    .line 1411
    move-result-object v6

    .line 1412
    if-eqz v6, :cond_42

    .line 1413
    .line 1414
    aget-wide v10, v7, v4

    .line 1415
    .line 1416
    const-wide/16 v12, 0x2

    .line 1417
    .line 1418
    mul-long/2addr v10, v12

    .line 1419
    aput-wide v10, v7, v4

    .line 1420
    .line 1421
    :cond_42
    add-int/lit8 v4, v4, 0x1

    .line 1422
    .line 1423
    goto :goto_33

    .line 1424
    :cond_43
    invoke-static {v1, v7}, Lj8/b;->m(Ljava/util/ArrayList;[J)V

    .line 1425
    .line 1426
    .line 1427
    invoke-static {}, Lhr/h0;->o()Lhr/e0;

    .line 1428
    .line 1429
    .line 1430
    move-result-object v4

    .line 1431
    const/4 v6, 0x0

    .line 1432
    :goto_34
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 1433
    .line 1434
    .line 1435
    move-result v7

    .line 1436
    if-ge v6, v7, :cond_45

    .line 1437
    .line 1438
    invoke-virtual {v1, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1439
    .line 1440
    .line 1441
    move-result-object v7

    .line 1442
    check-cast v7, Lhr/e0;

    .line 1443
    .line 1444
    if-nez v7, :cond_44

    .line 1445
    .line 1446
    sget-object v7, Lhr/x0;->h:Lhr/x0;

    .line 1447
    .line 1448
    goto :goto_35

    .line 1449
    :cond_44
    invoke-virtual {v7}, Lhr/e0;->i()Lhr/x0;

    .line 1450
    .line 1451
    .line 1452
    move-result-object v7

    .line 1453
    :goto_35
    invoke-virtual {v4, v7}, Lhr/b0;->a(Ljava/lang/Object;)V

    .line 1454
    .line 1455
    .line 1456
    add-int/lit8 v6, v6, 0x1

    .line 1457
    .line 1458
    goto :goto_34

    .line 1459
    :cond_45
    invoke-virtual {v4}, Lhr/e0;->i()Lhr/x0;

    .line 1460
    .line 1461
    .line 1462
    move-result-object v1

    .line 1463
    array-length v4, v5

    .line 1464
    new-array v4, v4, [Lj8/q;

    .line 1465
    .line 1466
    const/4 v8, 0x0

    .line 1467
    :goto_36
    array-length v6, v5

    .line 1468
    if-ge v8, v6, :cond_4a

    .line 1469
    .line 1470
    aget-object v6, v5, v8

    .line 1471
    .line 1472
    if-eqz v6, :cond_49

    .line 1473
    .line 1474
    iget-object v7, v6, Lj8/p;->a:Lt7/q0;

    .line 1475
    .line 1476
    iget-object v6, v6, Lj8/p;->b:[I

    .line 1477
    .line 1478
    array-length v10, v6

    .line 1479
    if-nez v10, :cond_46

    .line 1480
    .line 1481
    goto :goto_38

    .line 1482
    :cond_46
    array-length v10, v6

    .line 1483
    const/4 v15, 0x1

    .line 1484
    if-ne v10, v15, :cond_47

    .line 1485
    .line 1486
    new-instance v10, Lj8/b;

    .line 1487
    .line 1488
    const/4 v13, 0x0

    .line 1489
    aget v6, v6, v13

    .line 1490
    .line 1491
    filled-new-array {v6}, [I

    .line 1492
    .line 1493
    .line 1494
    move-result-object v6

    .line 1495
    invoke-direct {v10, v15, v7, v6}, Lj8/b;-><init>(ILt7/q0;[I)V

    .line 1496
    .line 1497
    .line 1498
    goto :goto_37

    .line 1499
    :cond_47
    const/4 v13, 0x0

    .line 1500
    invoke-virtual {v1, v8}, Lhr/x0;->get(I)Ljava/lang/Object;

    .line 1501
    .line 1502
    .line 1503
    move-result-object v10

    .line 1504
    check-cast v10, Lhr/h0;

    .line 1505
    .line 1506
    new-instance v11, Lj8/b;

    .line 1507
    .line 1508
    const/16 v12, 0x2710

    .line 1509
    .line 1510
    int-to-long v14, v12

    .line 1511
    const/16 v12, 0x61a8

    .line 1512
    .line 1513
    move-wide/from16 v20, v14

    .line 1514
    .line 1515
    int-to-long v14, v12

    .line 1516
    invoke-direct {v11, v13, v7, v6}, Lj8/b;-><init>(ILt7/q0;[I)V

    .line 1517
    .line 1518
    .line 1519
    cmp-long v6, v14, v20

    .line 1520
    .line 1521
    if-gez v6, :cond_48

    .line 1522
    .line 1523
    const-string v6, "AdaptiveTrackSelection"

    .line 1524
    .line 1525
    const-string v7, "Adjusting minDurationToRetainAfterDiscardMs to be at least minDurationForQualityIncreaseMs"

    .line 1526
    .line 1527
    invoke-static {v6, v7}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 1528
    .line 1529
    .line 1530
    :cond_48
    invoke-static {v10}, Lhr/h0;->p(Ljava/util/Collection;)Lhr/h0;

    .line 1531
    .line 1532
    .line 1533
    move-object v10, v11

    .line 1534
    :goto_37
    aput-object v10, v4, v8

    .line 1535
    .line 1536
    :cond_49
    :goto_38
    add-int/lit8 v8, v8, 0x1

    .line 1537
    .line 1538
    goto :goto_36

    .line 1539
    :cond_4a
    new-array v1, v2, [La8/o1;

    .line 1540
    .line 1541
    const/4 v8, 0x0

    .line 1542
    :goto_39
    const/4 v5, -0x2

    .line 1543
    if-ge v8, v2, :cond_4e

    .line 1544
    .line 1545
    iget-object v6, v9, Lj8/r;->b:[I

    .line 1546
    .line 1547
    aget v6, v6, v8

    .line 1548
    .line 1549
    iget-object v7, v3, Lj8/i;->C:Landroid/util/SparseBooleanArray;

    .line 1550
    .line 1551
    invoke-virtual {v7, v8}, Landroid/util/SparseBooleanArray;->get(I)Z

    .line 1552
    .line 1553
    .line 1554
    move-result v7

    .line 1555
    if-nez v7, :cond_4d

    .line 1556
    .line 1557
    iget-object v7, v3, Lt7/u0;->t:Lhr/k0;

    .line 1558
    .line 1559
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1560
    .line 1561
    .line 1562
    move-result-object v6

    .line 1563
    invoke-virtual {v7, v6}, Lhr/c0;->contains(Ljava/lang/Object;)Z

    .line 1564
    .line 1565
    .line 1566
    move-result v6

    .line 1567
    if-eqz v6, :cond_4b

    .line 1568
    .line 1569
    goto :goto_3a

    .line 1570
    :cond_4b
    iget-object v6, v9, Lj8/r;->b:[I

    .line 1571
    .line 1572
    aget v6, v6, v8

    .line 1573
    .line 1574
    if-eq v6, v5, :cond_4c

    .line 1575
    .line 1576
    aget-object v5, v4, v8

    .line 1577
    .line 1578
    if-eqz v5, :cond_4d

    .line 1579
    .line 1580
    :cond_4c
    sget-object v5, La8/o1;->c:La8/o1;

    .line 1581
    .line 1582
    goto :goto_3b

    .line 1583
    :cond_4d
    :goto_3a
    const/4 v5, 0x0

    .line 1584
    :goto_3b
    aput-object v5, v1, v8

    .line 1585
    .line 1586
    add-int/lit8 v8, v8, 0x1

    .line 1587
    .line 1588
    goto :goto_39

    .line 1589
    :cond_4e
    iget-object v2, v3, Lt7/u0;->o:Lt7/s0;

    .line 1590
    .line 1591
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1592
    .line 1593
    .line 1594
    invoke-static {v1, v4}, Landroid/util/Pair;->create(Ljava/lang/Object;Ljava/lang/Object;)Landroid/util/Pair;

    .line 1595
    .line 1596
    .line 1597
    move-result-object v1

    .line 1598
    iget-object v2, v1, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 1599
    .line 1600
    check-cast v2, [Lj8/q;

    .line 1601
    .line 1602
    array-length v3, v2

    .line 1603
    new-array v3, v3, [Ljava/util/List;

    .line 1604
    .line 1605
    const/4 v8, 0x0

    .line 1606
    :goto_3c
    array-length v4, v2

    .line 1607
    if-ge v8, v4, :cond_50

    .line 1608
    .line 1609
    aget-object v4, v2, v8

    .line 1610
    .line 1611
    if-eqz v4, :cond_4f

    .line 1612
    .line 1613
    invoke-static {v4}, Lhr/h0;->u(Ljava/lang/Object;)Lhr/x0;

    .line 1614
    .line 1615
    .line 1616
    move-result-object v4

    .line 1617
    goto :goto_3d

    .line 1618
    :cond_4f
    sget-object v4, Lhr/h0;->e:Lhr/f0;

    .line 1619
    .line 1620
    sget-object v4, Lhr/x0;->h:Lhr/x0;

    .line 1621
    .line 1622
    :goto_3d
    aput-object v4, v3, v8

    .line 1623
    .line 1624
    add-int/lit8 v8, v8, 0x1

    .line 1625
    .line 1626
    goto :goto_3c

    .line 1627
    :cond_50
    new-instance v2, Lhr/e0;

    .line 1628
    .line 1629
    const/4 v4, 0x4

    .line 1630
    invoke-direct {v2, v4}, Lhr/b0;-><init>(I)V

    .line 1631
    .line 1632
    .line 1633
    const/4 v8, 0x0

    .line 1634
    :goto_3e
    iget v4, v9, Lj8/r;->a:I

    .line 1635
    .line 1636
    iget-object v6, v9, Lj8/r;->c:[Lh8/e1;

    .line 1637
    .line 1638
    if-ge v8, v4, :cond_5c

    .line 1639
    .line 1640
    aget-object v4, v6, v8

    .line 1641
    .line 1642
    aget-object v7, v3, v8

    .line 1643
    .line 1644
    const/4 v10, 0x0

    .line 1645
    :goto_3f
    iget v11, v4, Lh8/e1;->a:I

    .line 1646
    .line 1647
    if-ge v10, v11, :cond_5b

    .line 1648
    .line 1649
    invoke-virtual {v4, v10}, Lh8/e1;->a(I)Lt7/q0;

    .line 1650
    .line 1651
    .line 1652
    move-result-object v11

    .line 1653
    aget-object v12, v6, v8

    .line 1654
    .line 1655
    invoke-virtual {v12, v10}, Lh8/e1;->a(I)Lt7/q0;

    .line 1656
    .line 1657
    .line 1658
    move-result-object v12

    .line 1659
    iget v12, v12, Lt7/q0;->a:I

    .line 1660
    .line 1661
    new-array v13, v12, [I

    .line 1662
    .line 1663
    const/4 v14, 0x0

    .line 1664
    const/4 v15, 0x0

    .line 1665
    :goto_40
    if-ge v14, v12, :cond_52

    .line 1666
    .line 1667
    iget-object v5, v9, Lj8/r;->e:[[[I

    .line 1668
    .line 1669
    aget-object v5, v5, v8

    .line 1670
    .line 1671
    aget-object v5, v5, v10

    .line 1672
    .line 1673
    aget v5, v5, v14

    .line 1674
    .line 1675
    const/16 v17, 0x7

    .line 1676
    .line 1677
    and-int/lit8 v5, v5, 0x7

    .line 1678
    .line 1679
    move-object/from16 v21, v3

    .line 1680
    .line 1681
    const/4 v3, 0x4

    .line 1682
    if-eq v5, v3, :cond_51

    .line 1683
    .line 1684
    goto :goto_41

    .line 1685
    :cond_51
    add-int/lit8 v5, v15, 0x1

    .line 1686
    .line 1687
    aput v14, v13, v15

    .line 1688
    .line 1689
    move v15, v5

    .line 1690
    :goto_41
    add-int/lit8 v14, v14, 0x1

    .line 1691
    .line 1692
    move-object/from16 v3, v21

    .line 1693
    .line 1694
    const/4 v5, -0x2

    .line 1695
    goto :goto_40

    .line 1696
    :cond_52
    move-object/from16 v21, v3

    .line 1697
    .line 1698
    const/4 v3, 0x4

    .line 1699
    invoke-static {v13, v15}, Ljava/util/Arrays;->copyOf([II)[I

    .line 1700
    .line 1701
    .line 1702
    move-result-object v5

    .line 1703
    const/16 v12, 0x10

    .line 1704
    .line 1705
    move-object/from16 v22, v4

    .line 1706
    .line 1707
    move v15, v12

    .line 1708
    const/4 v3, 0x0

    .line 1709
    const/4 v12, 0x0

    .line 1710
    const/4 v13, 0x0

    .line 1711
    const/4 v14, 0x0

    .line 1712
    :goto_42
    array-length v4, v5

    .line 1713
    if-ge v12, v4, :cond_54

    .line 1714
    .line 1715
    aget v4, v5, v12

    .line 1716
    .line 1717
    move/from16 v23, v4

    .line 1718
    .line 1719
    aget-object v4, v6, v8

    .line 1720
    .line 1721
    invoke-virtual {v4, v10}, Lh8/e1;->a(I)Lt7/q0;

    .line 1722
    .line 1723
    .line 1724
    move-result-object v4

    .line 1725
    iget-object v4, v4, Lt7/q0;->d:[Lt7/o;

    .line 1726
    .line 1727
    aget-object v4, v4, v23

    .line 1728
    .line 1729
    iget-object v4, v4, Lt7/o;->n:Ljava/lang/String;

    .line 1730
    .line 1731
    add-int/lit8 v23, v14, 0x1

    .line 1732
    .line 1733
    if-nez v14, :cond_53

    .line 1734
    .line 1735
    move-object v3, v4

    .line 1736
    const/16 v18, 0x1

    .line 1737
    .line 1738
    goto :goto_43

    .line 1739
    :cond_53
    invoke-static {v3, v4}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1740
    .line 1741
    .line 1742
    move-result v4

    .line 1743
    const/16 v18, 0x1

    .line 1744
    .line 1745
    xor-int/lit8 v4, v4, 0x1

    .line 1746
    .line 1747
    or-int/2addr v4, v13

    .line 1748
    move v13, v4

    .line 1749
    :goto_43
    iget-object v4, v9, Lj8/r;->e:[[[I

    .line 1750
    .line 1751
    aget-object v4, v4, v8

    .line 1752
    .line 1753
    aget-object v4, v4, v10

    .line 1754
    .line 1755
    aget v4, v4, v12

    .line 1756
    .line 1757
    and-int/lit8 v4, v4, 0x18

    .line 1758
    .line 1759
    invoke-static {v15, v4}, Ljava/lang/Math;->min(II)I

    .line 1760
    .line 1761
    .line 1762
    move-result v15

    .line 1763
    add-int/lit8 v12, v12, 0x1

    .line 1764
    .line 1765
    move/from16 v14, v23

    .line 1766
    .line 1767
    goto :goto_42

    .line 1768
    :cond_54
    const/16 v18, 0x1

    .line 1769
    .line 1770
    if-eqz v13, :cond_55

    .line 1771
    .line 1772
    iget-object v3, v9, Lj8/r;->d:[I

    .line 1773
    .line 1774
    aget v3, v3, v8

    .line 1775
    .line 1776
    invoke-static {v15, v3}, Ljava/lang/Math;->min(II)I

    .line 1777
    .line 1778
    .line 1779
    move-result v15

    .line 1780
    :cond_55
    if-eqz v15, :cond_56

    .line 1781
    .line 1782
    move/from16 v15, v18

    .line 1783
    .line 1784
    goto :goto_44

    .line 1785
    :cond_56
    const/4 v15, 0x0

    .line 1786
    :goto_44
    iget v3, v11, Lt7/q0;->a:I

    .line 1787
    .line 1788
    new-array v4, v3, [I

    .line 1789
    .line 1790
    new-array v3, v3, [Z

    .line 1791
    .line 1792
    const/4 v5, 0x0

    .line 1793
    :goto_45
    iget v12, v11, Lt7/q0;->a:I

    .line 1794
    .line 1795
    if-ge v5, v12, :cond_5a

    .line 1796
    .line 1797
    iget-object v12, v9, Lj8/r;->e:[[[I

    .line 1798
    .line 1799
    aget-object v12, v12, v8

    .line 1800
    .line 1801
    aget-object v12, v12, v10

    .line 1802
    .line 1803
    aget v12, v12, v5

    .line 1804
    .line 1805
    const/16 v17, 0x7

    .line 1806
    .line 1807
    and-int/lit8 v12, v12, 0x7

    .line 1808
    .line 1809
    aput v12, v4, v5

    .line 1810
    .line 1811
    const/4 v12, 0x0

    .line 1812
    :goto_46
    invoke-interface {v7}, Ljava/util/List;->size()I

    .line 1813
    .line 1814
    .line 1815
    move-result v13

    .line 1816
    if-ge v12, v13, :cond_59

    .line 1817
    .line 1818
    invoke-interface {v7, v12}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1819
    .line 1820
    .line 1821
    move-result-object v13

    .line 1822
    check-cast v13, Lj8/q;

    .line 1823
    .line 1824
    invoke-interface {v13}, Lj8/q;->g()Lt7/q0;

    .line 1825
    .line 1826
    .line 1827
    move-result-object v14

    .line 1828
    invoke-virtual {v14, v11}, Lt7/q0;->equals(Ljava/lang/Object;)Z

    .line 1829
    .line 1830
    .line 1831
    move-result v14

    .line 1832
    if-eqz v14, :cond_57

    .line 1833
    .line 1834
    invoke-interface {v13, v5}, Lj8/q;->f(I)I

    .line 1835
    .line 1836
    .line 1837
    move-result v13

    .line 1838
    const/4 v14, -0x1

    .line 1839
    if-eq v13, v14, :cond_58

    .line 1840
    .line 1841
    move/from16 v12, v18

    .line 1842
    .line 1843
    goto :goto_47

    .line 1844
    :cond_57
    const/4 v14, -0x1

    .line 1845
    :cond_58
    add-int/lit8 v12, v12, 0x1

    .line 1846
    .line 1847
    goto :goto_46

    .line 1848
    :cond_59
    const/4 v14, -0x1

    .line 1849
    const/4 v12, 0x0

    .line 1850
    :goto_47
    aput-boolean v12, v3, v5

    .line 1851
    .line 1852
    add-int/lit8 v5, v5, 0x1

    .line 1853
    .line 1854
    goto :goto_45

    .line 1855
    :cond_5a
    const/4 v14, -0x1

    .line 1856
    const/16 v17, 0x7

    .line 1857
    .line 1858
    new-instance v5, Lt7/v0;

    .line 1859
    .line 1860
    invoke-direct {v5, v11, v15, v4, v3}, Lt7/v0;-><init>(Lt7/q0;Z[I[Z)V

    .line 1861
    .line 1862
    .line 1863
    invoke-virtual {v2, v5}, Lhr/b0;->a(Ljava/lang/Object;)V

    .line 1864
    .line 1865
    .line 1866
    add-int/lit8 v10, v10, 0x1

    .line 1867
    .line 1868
    move-object/from16 v3, v21

    .line 1869
    .line 1870
    move-object/from16 v4, v22

    .line 1871
    .line 1872
    const/4 v5, -0x2

    .line 1873
    goto/16 :goto_3f

    .line 1874
    .line 1875
    :cond_5b
    move-object/from16 v21, v3

    .line 1876
    .line 1877
    const/4 v14, -0x1

    .line 1878
    const/16 v17, 0x7

    .line 1879
    .line 1880
    const/16 v18, 0x1

    .line 1881
    .line 1882
    add-int/lit8 v8, v8, 0x1

    .line 1883
    .line 1884
    const/4 v5, -0x2

    .line 1885
    goto/16 :goto_3e

    .line 1886
    .line 1887
    :cond_5c
    const/16 v18, 0x1

    .line 1888
    .line 1889
    iget-object v3, v9, Lj8/r;->f:Lh8/e1;

    .line 1890
    .line 1891
    const/4 v8, 0x0

    .line 1892
    :goto_48
    iget v4, v3, Lh8/e1;->a:I

    .line 1893
    .line 1894
    if-ge v8, v4, :cond_5d

    .line 1895
    .line 1896
    invoke-virtual {v3, v8}, Lh8/e1;->a(I)Lt7/q0;

    .line 1897
    .line 1898
    .line 1899
    move-result-object v4

    .line 1900
    iget v5, v4, Lt7/q0;->a:I

    .line 1901
    .line 1902
    new-array v5, v5, [I

    .line 1903
    .line 1904
    const/4 v13, 0x0

    .line 1905
    invoke-static {v5, v13}, Ljava/util/Arrays;->fill([II)V

    .line 1906
    .line 1907
    .line 1908
    iget v6, v4, Lt7/q0;->a:I

    .line 1909
    .line 1910
    new-array v6, v6, [Z

    .line 1911
    .line 1912
    new-instance v7, Lt7/v0;

    .line 1913
    .line 1914
    invoke-direct {v7, v4, v13, v5, v6}, Lt7/v0;-><init>(Lt7/q0;Z[I[Z)V

    .line 1915
    .line 1916
    .line 1917
    invoke-virtual {v2, v7}, Lhr/b0;->a(Ljava/lang/Object;)V

    .line 1918
    .line 1919
    .line 1920
    add-int/lit8 v8, v8, 0x1

    .line 1921
    .line 1922
    goto :goto_48

    .line 1923
    :cond_5d
    const/4 v13, 0x0

    .line 1924
    new-instance v3, Lt7/w0;

    .line 1925
    .line 1926
    invoke-virtual {v2}, Lhr/e0;->i()Lhr/x0;

    .line 1927
    .line 1928
    .line 1929
    move-result-object v2

    .line 1930
    invoke-direct {v3, v2}, Lt7/w0;-><init>(Lhr/x0;)V

    .line 1931
    .line 1932
    .line 1933
    new-instance v2, Lj8/s;

    .line 1934
    .line 1935
    iget-object v4, v1, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 1936
    .line 1937
    check-cast v4, [La8/o1;

    .line 1938
    .line 1939
    iget-object v1, v1, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 1940
    .line 1941
    check-cast v1, [Lj8/q;

    .line 1942
    .line 1943
    invoke-direct {v2, v4, v1, v3, v9}, Lj8/s;-><init>([La8/o1;[Lj8/q;Lt7/w0;Ljava/lang/Object;)V

    .line 1944
    .line 1945
    .line 1946
    move v8, v13

    .line 1947
    :goto_49
    iget v1, v2, Lj8/s;->a:I

    .line 1948
    .line 1949
    if-ge v8, v1, :cond_62

    .line 1950
    .line 1951
    invoke-virtual {v2, v8}, Lj8/s;->b(I)Z

    .line 1952
    .line 1953
    .line 1954
    move-result v1

    .line 1955
    if-eqz v1, :cond_60

    .line 1956
    .line 1957
    iget-object v1, v2, Lj8/s;->c:[Lj8/q;

    .line 1958
    .line 1959
    aget-object v1, v1, v8

    .line 1960
    .line 1961
    if-nez v1, :cond_5f

    .line 1962
    .line 1963
    iget-object v1, v0, La8/w0;->j:[La8/f;

    .line 1964
    .line 1965
    aget-object v1, v1, v8

    .line 1966
    .line 1967
    iget v1, v1, La8/f;->e:I

    .line 1968
    .line 1969
    const/4 v3, -0x2

    .line 1970
    if-ne v1, v3, :cond_5e

    .line 1971
    .line 1972
    goto :goto_4a

    .line 1973
    :cond_5e
    move v15, v13

    .line 1974
    goto :goto_4b

    .line 1975
    :cond_5f
    const/4 v3, -0x2

    .line 1976
    :goto_4a
    move/from16 v15, v18

    .line 1977
    .line 1978
    :goto_4b
    invoke-static {v15}, Lw7/a;->j(Z)V

    .line 1979
    .line 1980
    .line 1981
    goto :goto_4d

    .line 1982
    :cond_60
    const/4 v3, -0x2

    .line 1983
    iget-object v1, v2, Lj8/s;->c:[Lj8/q;

    .line 1984
    .line 1985
    aget-object v1, v1, v8

    .line 1986
    .line 1987
    if-nez v1, :cond_61

    .line 1988
    .line 1989
    move/from16 v15, v18

    .line 1990
    .line 1991
    goto :goto_4c

    .line 1992
    :cond_61
    move v15, v13

    .line 1993
    :goto_4c
    invoke-static {v15}, Lw7/a;->j(Z)V

    .line 1994
    .line 1995
    .line 1996
    :goto_4d
    add-int/lit8 v8, v8, 0x1

    .line 1997
    .line 1998
    goto :goto_49

    .line 1999
    :cond_62
    iget-object v0, v2, Lj8/s;->c:[Lj8/q;

    .line 2000
    .line 2001
    array-length v1, v0

    .line 2002
    move v8, v13

    .line 2003
    :goto_4e
    if-ge v8, v1, :cond_64

    .line 2004
    .line 2005
    aget-object v3, v0, v8

    .line 2006
    .line 2007
    move/from16 v4, p1

    .line 2008
    .line 2009
    if-eqz v3, :cond_63

    .line 2010
    .line 2011
    invoke-interface {v3, v4}, Lj8/q;->d(F)V

    .line 2012
    .line 2013
    .line 2014
    move/from16 v5, p3

    .line 2015
    .line 2016
    invoke-interface {v3, v5}, Lj8/q;->h(Z)V

    .line 2017
    .line 2018
    .line 2019
    goto :goto_4f

    .line 2020
    :cond_63
    move/from16 v5, p3

    .line 2021
    .line 2022
    :goto_4f
    add-int/lit8 v8, v8, 0x1

    .line 2023
    .line 2024
    goto :goto_4e

    .line 2025
    :cond_64
    return-object v2

    .line 2026
    :cond_65
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 2027
    .line 2028
    invoke-direct {v0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 2029
    .line 2030
    .line 2031
    throw v0

    .line 2032
    :catchall_0
    move-exception v0

    .line 2033
    :try_start_1
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 2034
    throw v0
.end method

.method public final k()V
    .locals 5

    .line 1
    iget-object v0, p0, La8/w0;->a:Ljava/lang/Object;

    .line 2
    .line 3
    instance-of v1, v0, Lh8/c;

    .line 4
    .line 5
    if-eqz v1, :cond_1

    .line 6
    .line 7
    iget-object p0, p0, La8/w0;->g:La8/x0;

    .line 8
    .line 9
    iget-wide v1, p0, La8/x0;->d:J

    .line 10
    .line 11
    const-wide v3, -0x7fffffffffffffffL    # -4.9E-324

    .line 12
    .line 13
    .line 14
    .line 15
    .line 16
    cmp-long p0, v1, v3

    .line 17
    .line 18
    if-nez p0, :cond_0

    .line 19
    .line 20
    const-wide/high16 v1, -0x8000000000000000L

    .line 21
    .line 22
    :cond_0
    check-cast v0, Lh8/c;

    .line 23
    .line 24
    const-wide/16 v3, 0x0

    .line 25
    .line 26
    iput-wide v3, v0, Lh8/c;->h:J

    .line 27
    .line 28
    iput-wide v1, v0, Lh8/c;->i:J

    .line 29
    .line 30
    :cond_1
    return-void
.end method
