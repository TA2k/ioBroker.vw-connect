.class public final Lh8/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh8/z;
.implements Lh8/y;


# instance fields
.field public final d:Lh8/z;

.field public e:Lh8/y;

.field public f:[Lh8/b;

.field public g:J

.field public h:J

.field public i:J

.field public j:Lh8/f;


# direct methods
.method public constructor <init>(Lh8/z;ZJJ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh8/c;->d:Lh8/z;

    .line 5
    .line 6
    const/4 p1, 0x0

    .line 7
    new-array p1, p1, [Lh8/b;

    .line 8
    .line 9
    iput-object p1, p0, Lh8/c;->f:[Lh8/b;

    .line 10
    .line 11
    if-eqz p2, :cond_0

    .line 12
    .line 13
    move-wide p1, p3

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    const-wide p1, -0x7fffffffffffffffL    # -4.9E-324

    .line 16
    .line 17
    .line 18
    .line 19
    .line 20
    :goto_0
    iput-wide p1, p0, Lh8/c;->g:J

    .line 21
    .line 22
    iput-wide p3, p0, Lh8/c;->h:J

    .line 23
    .line 24
    iput-wide p5, p0, Lh8/c;->i:J

    .line 25
    .line 26
    return-void
.end method


# virtual methods
.method public final a()J
    .locals 6

    .line 1
    iget-object v0, p0, Lh8/c;->d:Lh8/z;

    .line 2
    .line 3
    invoke-interface {v0}, Lh8/z0;->a()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    const-wide/high16 v2, -0x8000000000000000L

    .line 8
    .line 9
    cmp-long v4, v0, v2

    .line 10
    .line 11
    if-eqz v4, :cond_1

    .line 12
    .line 13
    iget-wide v4, p0, Lh8/c;->i:J

    .line 14
    .line 15
    cmp-long p0, v4, v2

    .line 16
    .line 17
    if-eqz p0, :cond_0

    .line 18
    .line 19
    cmp-long p0, v0, v4

    .line 20
    .line 21
    if-ltz p0, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    return-wide v0

    .line 25
    :cond_1
    :goto_0
    return-wide v2
.end method

.method public final b(JLa8/r1;)J
    .locals 9

    .line 1
    iget-wide v0, p0, Lh8/c;->h:J

    .line 2
    .line 3
    cmp-long v2, p1, v0

    .line 4
    .line 5
    if-nez v2, :cond_0

    .line 6
    .line 7
    return-wide v0

    .line 8
    :cond_0
    iget-wide v3, p3, La8/r1;->a:J

    .line 9
    .line 10
    const-wide/16 v5, 0x0

    .line 11
    .line 12
    sub-long v7, p1, v0

    .line 13
    .line 14
    invoke-static/range {v3 .. v8}, Lw7/w;->h(JJJ)J

    .line 15
    .line 16
    .line 17
    move-result-wide v0

    .line 18
    iget-wide v2, p3, La8/r1;->b:J

    .line 19
    .line 20
    iget-wide v4, p0, Lh8/c;->i:J

    .line 21
    .line 22
    const-wide/high16 v6, -0x8000000000000000L

    .line 23
    .line 24
    cmp-long v6, v4, v6

    .line 25
    .line 26
    if-nez v6, :cond_1

    .line 27
    .line 28
    const-wide v4, 0x7fffffffffffffffL

    .line 29
    .line 30
    .line 31
    .line 32
    .line 33
    :goto_0
    move-wide v6, v4

    .line 34
    goto :goto_1

    .line 35
    :cond_1
    sub-long/2addr v4, p1

    .line 36
    goto :goto_0

    .line 37
    :goto_1
    const-wide/16 v4, 0x0

    .line 38
    .line 39
    invoke-static/range {v2 .. v7}, Lw7/w;->h(JJJ)J

    .line 40
    .line 41
    .line 42
    move-result-wide v2

    .line 43
    iget-wide v4, p3, La8/r1;->a:J

    .line 44
    .line 45
    cmp-long v4, v0, v4

    .line 46
    .line 47
    if-nez v4, :cond_2

    .line 48
    .line 49
    iget-wide v4, p3, La8/r1;->b:J

    .line 50
    .line 51
    cmp-long v4, v2, v4

    .line 52
    .line 53
    if-nez v4, :cond_2

    .line 54
    .line 55
    goto :goto_2

    .line 56
    :cond_2
    new-instance p3, La8/r1;

    .line 57
    .line 58
    invoke-direct {p3, v0, v1, v2, v3}, La8/r1;-><init>(JJ)V

    .line 59
    .line 60
    .line 61
    :goto_2
    iget-object p0, p0, Lh8/c;->d:Lh8/z;

    .line 62
    .line 63
    invoke-interface {p0, p1, p2, p3}, Lh8/z;->b(JLa8/r1;)J

    .line 64
    .line 65
    .line 66
    move-result-wide p0

    .line 67
    return-wide p0
.end method

.method public final c(Lh8/z;)V
    .locals 0

    .line 1
    iget-object p1, p0, Lh8/c;->j:Lh8/f;

    .line 2
    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iget-object p1, p0, Lh8/c;->e:Lh8/y;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    invoke-interface {p1, p0}, Lh8/y;->c(Lh8/z;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public final d(J)J
    .locals 5

    .line 1
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 2
    .line 3
    .line 4
    .line 5
    .line 6
    iput-wide v0, p0, Lh8/c;->g:J

    .line 7
    .line 8
    iget-object v0, p0, Lh8/c;->f:[Lh8/b;

    .line 9
    .line 10
    array-length v1, v0

    .line 11
    const/4 v2, 0x0

    .line 12
    move v3, v2

    .line 13
    :goto_0
    if-ge v3, v1, :cond_1

    .line 14
    .line 15
    aget-object v4, v0, v3

    .line 16
    .line 17
    if-eqz v4, :cond_0

    .line 18
    .line 19
    iput-boolean v2, v4, Lh8/b;->e:Z

    .line 20
    .line 21
    :cond_0
    add-int/lit8 v3, v3, 0x1

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_1
    iget-object v0, p0, Lh8/c;->d:Lh8/z;

    .line 25
    .line 26
    invoke-interface {v0, p1, p2}, Lh8/z;->d(J)J

    .line 27
    .line 28
    .line 29
    move-result-wide p1

    .line 30
    iget-wide v0, p0, Lh8/c;->h:J

    .line 31
    .line 32
    iget-wide v2, p0, Lh8/c;->i:J

    .line 33
    .line 34
    invoke-static {p1, p2, v0, v1}, Ljava/lang/Math;->max(JJ)J

    .line 35
    .line 36
    .line 37
    move-result-wide p0

    .line 38
    const-wide/high16 v0, -0x8000000000000000L

    .line 39
    .line 40
    cmp-long p2, v2, v0

    .line 41
    .line 42
    if-eqz p2, :cond_2

    .line 43
    .line 44
    invoke-static {p0, p1, v2, v3}, Ljava/lang/Math;->min(JJ)J

    .line 45
    .line 46
    .line 47
    move-result-wide p0

    .line 48
    :cond_2
    return-wide p0
.end method

.method public final e()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lh8/c;->d:Lh8/z;

    .line 2
    .line 3
    invoke-interface {p0}, Lh8/z0;->e()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final f(Lh8/z0;)V
    .locals 0

    .line 1
    check-cast p1, Lh8/z;

    .line 2
    .line 3
    iget-object p1, p0, Lh8/c;->e:Lh8/y;

    .line 4
    .line 5
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    invoke-interface {p1, p0}, Lh8/y;->f(Lh8/z0;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final g()J
    .locals 7

    .line 1
    invoke-virtual {p0}, Lh8/c;->i()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const-wide v1, -0x7fffffffffffffffL    # -4.9E-324

    .line 6
    .line 7
    .line 8
    .line 9
    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    iget-wide v3, p0, Lh8/c;->g:J

    .line 13
    .line 14
    iput-wide v1, p0, Lh8/c;->g:J

    .line 15
    .line 16
    invoke-virtual {p0}, Lh8/c;->g()J

    .line 17
    .line 18
    .line 19
    move-result-wide v5

    .line 20
    cmp-long p0, v5, v1

    .line 21
    .line 22
    if-eqz p0, :cond_0

    .line 23
    .line 24
    return-wide v5

    .line 25
    :cond_0
    return-wide v3

    .line 26
    :cond_1
    iget-object v0, p0, Lh8/c;->d:Lh8/z;

    .line 27
    .line 28
    invoke-interface {v0}, Lh8/z;->g()J

    .line 29
    .line 30
    .line 31
    move-result-wide v3

    .line 32
    cmp-long v0, v3, v1

    .line 33
    .line 34
    if-nez v0, :cond_2

    .line 35
    .line 36
    return-wide v1

    .line 37
    :cond_2
    iget-wide v0, p0, Lh8/c;->h:J

    .line 38
    .line 39
    iget-wide v5, p0, Lh8/c;->i:J

    .line 40
    .line 41
    invoke-static {v3, v4, v0, v1}, Ljava/lang/Math;->max(JJ)J

    .line 42
    .line 43
    .line 44
    move-result-wide v0

    .line 45
    const-wide/high16 v2, -0x8000000000000000L

    .line 46
    .line 47
    cmp-long p0, v5, v2

    .line 48
    .line 49
    if-eqz p0, :cond_3

    .line 50
    .line 51
    invoke-static {v0, v1, v5, v6}, Ljava/lang/Math;->min(JJ)J

    .line 52
    .line 53
    .line 54
    move-result-wide v0

    .line 55
    :cond_3
    return-wide v0
.end method

.method public final h(Lh8/y;J)V
    .locals 0

    .line 1
    iput-object p1, p0, Lh8/c;->e:Lh8/y;

    .line 2
    .line 3
    iget-object p1, p0, Lh8/c;->d:Lh8/z;

    .line 4
    .line 5
    invoke-interface {p1, p0, p2, p3}, Lh8/z;->h(Lh8/y;J)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final i()Z
    .locals 4

    .line 1
    iget-wide v0, p0, Lh8/c;->g:J

    .line 2
    .line 3
    const-wide v2, -0x7fffffffffffffffL    # -4.9E-324

    .line 4
    .line 5
    .line 6
    .line 7
    .line 8
    cmp-long p0, v0, v2

    .line 9
    .line 10
    if-eqz p0, :cond_0

    .line 11
    .line 12
    const/4 p0, 0x1

    .line 13
    return p0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    return p0
.end method

.method public final k()V
    .locals 1

    .line 1
    iget-object v0, p0, Lh8/c;->j:Lh8/f;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lh8/c;->d:Lh8/z;

    .line 6
    .line 7
    invoke-interface {p0}, Lh8/z;->k()V

    .line 8
    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    throw v0
.end method

.method public final l(J)V
    .locals 0

    .line 1
    iget-object p0, p0, Lh8/c;->d:Lh8/z;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2}, Lh8/z;->l(J)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final n()Lh8/e1;
    .locals 0

    .line 1
    iget-object p0, p0, Lh8/c;->d:Lh8/z;

    .line 2
    .line 3
    invoke-interface {p0}, Lh8/z;->n()Lh8/e1;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final o([Lj8/q;[Z[Lh8/y0;[ZJ)J
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v8, p3

    .line 4
    .line 5
    array-length v1, v8

    .line 6
    new-array v1, v1, [Lh8/b;

    .line 7
    .line 8
    iput-object v1, v0, Lh8/c;->f:[Lh8/b;

    .line 9
    .line 10
    array-length v1, v8

    .line 11
    new-array v4, v1, [Lh8/y0;

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    :goto_0
    array-length v2, v8

    .line 15
    if-ge v1, v2, :cond_1

    .line 16
    .line 17
    iget-object v2, v0, Lh8/c;->f:[Lh8/b;

    .line 18
    .line 19
    aget-object v3, v8, v1

    .line 20
    .line 21
    check-cast v3, Lh8/b;

    .line 22
    .line 23
    aput-object v3, v2, v1

    .line 24
    .line 25
    if-eqz v3, :cond_0

    .line 26
    .line 27
    iget-object v10, v3, Lh8/b;->d:Lh8/y0;

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_0
    const/4 v10, 0x0

    .line 31
    :goto_1
    aput-object v10, v4, v1

    .line 32
    .line 33
    add-int/lit8 v1, v1, 0x1

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    iget-object v1, v0, Lh8/c;->d:Lh8/z;

    .line 37
    .line 38
    move-object/from16 v2, p1

    .line 39
    .line 40
    move-object/from16 v3, p2

    .line 41
    .line 42
    move-object/from16 v5, p4

    .line 43
    .line 44
    move-wide/from16 v6, p5

    .line 45
    .line 46
    invoke-interface/range {v1 .. v7}, Lh8/z;->o([Lj8/q;[Z[Lh8/y0;[ZJ)J

    .line 47
    .line 48
    .line 49
    move-result-wide v11

    .line 50
    iget-wide v13, v0, Lh8/c;->i:J

    .line 51
    .line 52
    const/4 v3, 0x0

    .line 53
    invoke-static {v11, v12, v6, v7}, Ljava/lang/Math;->max(JJ)J

    .line 54
    .line 55
    .line 56
    move-result-wide v9

    .line 57
    const-wide/high16 v15, -0x8000000000000000L

    .line 58
    .line 59
    cmp-long v5, v13, v15

    .line 60
    .line 61
    if-eqz v5, :cond_2

    .line 62
    .line 63
    invoke-static {v9, v10, v13, v14}, Ljava/lang/Math;->min(JJ)J

    .line 64
    .line 65
    .line 66
    move-result-wide v9

    .line 67
    :cond_2
    invoke-virtual {v0}, Lh8/c;->i()Z

    .line 68
    .line 69
    .line 70
    move-result v5

    .line 71
    if-eqz v5, :cond_5

    .line 72
    .line 73
    cmp-long v5, v11, v6

    .line 74
    .line 75
    if-gez v5, :cond_3

    .line 76
    .line 77
    goto :goto_3

    .line 78
    :cond_3
    const-wide/16 v5, 0x0

    .line 79
    .line 80
    cmp-long v5, v11, v5

    .line 81
    .line 82
    if-eqz v5, :cond_5

    .line 83
    .line 84
    array-length v5, v2

    .line 85
    const/4 v6, 0x0

    .line 86
    :goto_2
    if-ge v6, v5, :cond_5

    .line 87
    .line 88
    aget-object v7, v2, v6

    .line 89
    .line 90
    if-eqz v7, :cond_4

    .line 91
    .line 92
    invoke-interface {v7}, Lj8/q;->k()Lt7/o;

    .line 93
    .line 94
    .line 95
    move-result-object v7

    .line 96
    iget-object v11, v7, Lt7/o;->n:Ljava/lang/String;

    .line 97
    .line 98
    iget-object v7, v7, Lt7/o;->k:Ljava/lang/String;

    .line 99
    .line 100
    invoke-static {v11, v7}, Lt7/d0;->a(Ljava/lang/String;Ljava/lang/String;)Z

    .line 101
    .line 102
    .line 103
    move-result v7

    .line 104
    if-nez v7, :cond_4

    .line 105
    .line 106
    :goto_3
    move-wide v5, v9

    .line 107
    goto :goto_4

    .line 108
    :cond_4
    add-int/lit8 v6, v6, 0x1

    .line 109
    .line 110
    goto :goto_2

    .line 111
    :cond_5
    const-wide v5, -0x7fffffffffffffffL    # -4.9E-324

    .line 112
    .line 113
    .line 114
    .line 115
    .line 116
    :goto_4
    iput-wide v5, v0, Lh8/c;->g:J

    .line 117
    .line 118
    const/4 v1, 0x0

    .line 119
    :goto_5
    array-length v2, v8

    .line 120
    if-ge v1, v2, :cond_9

    .line 121
    .line 122
    aget-object v2, v4, v1

    .line 123
    .line 124
    if-nez v2, :cond_6

    .line 125
    .line 126
    iget-object v2, v0, Lh8/c;->f:[Lh8/b;

    .line 127
    .line 128
    aput-object v3, v2, v1

    .line 129
    .line 130
    goto :goto_6

    .line 131
    :cond_6
    iget-object v5, v0, Lh8/c;->f:[Lh8/b;

    .line 132
    .line 133
    aget-object v6, v5, v1

    .line 134
    .line 135
    if-eqz v6, :cond_7

    .line 136
    .line 137
    iget-object v6, v6, Lh8/b;->d:Lh8/y0;

    .line 138
    .line 139
    if-eq v6, v2, :cond_8

    .line 140
    .line 141
    :cond_7
    new-instance v6, Lh8/b;

    .line 142
    .line 143
    invoke-direct {v6, v0, v2}, Lh8/b;-><init>(Lh8/c;Lh8/y0;)V

    .line 144
    .line 145
    .line 146
    aput-object v6, v5, v1

    .line 147
    .line 148
    :cond_8
    :goto_6
    iget-object v2, v0, Lh8/c;->f:[Lh8/b;

    .line 149
    .line 150
    aget-object v2, v2, v1

    .line 151
    .line 152
    aput-object v2, v8, v1

    .line 153
    .line 154
    add-int/lit8 v1, v1, 0x1

    .line 155
    .line 156
    goto :goto_5

    .line 157
    :cond_9
    return-wide v9
.end method

.method public final p(La8/u0;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lh8/c;->d:Lh8/z;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lh8/z0;->p(La8/u0;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final r()J
    .locals 6

    .line 1
    iget-object v0, p0, Lh8/c;->d:Lh8/z;

    .line 2
    .line 3
    invoke-interface {v0}, Lh8/z0;->r()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    const-wide/high16 v2, -0x8000000000000000L

    .line 8
    .line 9
    cmp-long v4, v0, v2

    .line 10
    .line 11
    if-eqz v4, :cond_1

    .line 12
    .line 13
    iget-wide v4, p0, Lh8/c;->i:J

    .line 14
    .line 15
    cmp-long p0, v4, v2

    .line 16
    .line 17
    if-eqz p0, :cond_0

    .line 18
    .line 19
    cmp-long p0, v0, v4

    .line 20
    .line 21
    if-ltz p0, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    return-wide v0

    .line 25
    :cond_1
    :goto_0
    return-wide v2
.end method

.method public final s(J)V
    .locals 0

    .line 1
    iget-object p0, p0, Lh8/c;->d:Lh8/z;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2}, Lh8/z0;->s(J)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
