.class public final Lp11/k;
.super Lq11/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lp11/m;

.field public final i:I

.field public final j:I


# direct methods
.method public constructor <init>(Lp11/m;)V
    .locals 3

    .line 1
    sget-object v0, Ln11/b;->n:Ln11/b;

    .line 2
    .line 3
    const-wide v1, 0x9cbebd50L

    .line 4
    .line 5
    .line 6
    .line 7
    .line 8
    invoke-direct {p0, v0, v1, v2}, Lq11/f;-><init>(Ln11/b;J)V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lp11/k;->h:Lp11/m;

    .line 12
    .line 13
    const/16 p1, 0xc

    .line 14
    .line 15
    iput p1, p0, Lp11/k;->i:I

    .line 16
    .line 17
    const/4 p1, 0x2

    .line 18
    iput p1, p0, Lp11/k;->j:I

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final a(IJ)J
    .locals 9

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    return-wide p2

    .line 4
    :cond_0
    iget-object v0, p0, Lp11/k;->h:Lp11/m;

    .line 5
    .line 6
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    invoke-static {p2, p3}, Lp11/e;->S(J)I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    int-to-long v1, v1

    .line 14
    invoke-virtual {v0, p2, p3}, Lp11/e;->X(J)I

    .line 15
    .line 16
    .line 17
    move-result v3

    .line 18
    invoke-virtual {v0, v3, p2, p3}, Lp11/g;->c0(IJ)I

    .line 19
    .line 20
    .line 21
    move-result v4

    .line 22
    add-int/lit8 v5, v4, -0x1

    .line 23
    .line 24
    add-int v6, v5, p1

    .line 25
    .line 26
    iget p0, p0, Lp11/k;->i:I

    .line 27
    .line 28
    if-lez v4, :cond_1

    .line 29
    .line 30
    if-gez v6, :cond_1

    .line 31
    .line 32
    add-int/lit8 v6, v3, 0x1

    .line 33
    .line 34
    sub-int/2addr p1, p0

    .line 35
    add-int/2addr p1, v5

    .line 36
    move v8, v6

    .line 37
    move v6, p1

    .line 38
    move p1, v8

    .line 39
    goto :goto_0

    .line 40
    :cond_1
    move p1, v3

    .line 41
    :goto_0
    const/4 v5, 0x1

    .line 42
    if-ltz v6, :cond_2

    .line 43
    .line 44
    div-int v7, v6, p0

    .line 45
    .line 46
    add-int/2addr v7, p1

    .line 47
    rem-int/2addr v6, p0

    .line 48
    add-int/2addr v6, v5

    .line 49
    goto :goto_1

    .line 50
    :cond_2
    div-int v7, v6, p0

    .line 51
    .line 52
    add-int/2addr v7, p1

    .line 53
    add-int/lit8 p1, v7, -0x1

    .line 54
    .line 55
    invoke-static {v6}, Ljava/lang/Math;->abs(I)I

    .line 56
    .line 57
    .line 58
    move-result v6

    .line 59
    rem-int/2addr v6, p0

    .line 60
    if-nez v6, :cond_3

    .line 61
    .line 62
    move v6, p0

    .line 63
    :cond_3
    sub-int/2addr p0, v6

    .line 64
    add-int/lit8 v6, p0, 0x1

    .line 65
    .line 66
    if-ne v6, v5, :cond_4

    .line 67
    .line 68
    goto :goto_1

    .line 69
    :cond_4
    move v7, p1

    .line 70
    :goto_1
    invoke-virtual {v0, p2, p3, v3, v4}, Lp11/e;->P(JII)I

    .line 71
    .line 72
    .line 73
    move-result p0

    .line 74
    invoke-virtual {v0, v7, v6}, Lp11/g;->b0(II)I

    .line 75
    .line 76
    .line 77
    move-result p1

    .line 78
    if-le p0, p1, :cond_5

    .line 79
    .line 80
    move p0, p1

    .line 81
    :cond_5
    invoke-virtual {v0, v7, v6, p0}, Lp11/e;->Z(III)J

    .line 82
    .line 83
    .line 84
    move-result-wide p0

    .line 85
    add-long/2addr p0, v1

    .line 86
    return-wide p0
.end method

.method public final b(J)I
    .locals 1

    .line 1
    iget-object p0, p0, Lp11/k;->h:Lp11/m;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lp11/e;->X(J)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    invoke-virtual {p0, v0, p1, p2}, Lp11/g;->c0(IJ)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method public final c(ILjava/util/Locale;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p2}, Lp11/j;->b(Ljava/util/Locale;)Lp11/j;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p0, p0, Lp11/j;->e:[Ljava/lang/String;

    .line 6
    .line 7
    aget-object p0, p0, p1

    .line 8
    .line 9
    return-object p0
.end method

.method public final f(ILjava/util/Locale;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p2}, Lp11/j;->b(Ljava/util/Locale;)Lp11/j;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p0, p0, Lp11/j;->d:[Ljava/lang/String;

    .line 6
    .line 7
    aget-object p0, p0, p1

    .line 8
    .line 9
    return-object p0
.end method

.method public final j()Ln11/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lp11/k;->h:Lp11/m;

    .line 2
    .line 3
    iget-object p0, p0, Lp11/b;->k:Ln11/g;

    .line 4
    .line 5
    return-object p0
.end method

.method public final k(Ljava/util/Locale;)I
    .locals 0

    .line 1
    invoke-static {p1}, Lp11/j;->b(Ljava/util/Locale;)Lp11/j;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget p0, p0, Lp11/j;->l:I

    .line 6
    .line 7
    return p0
.end method

.method public final l()I
    .locals 0

    .line 1
    iget p0, p0, Lp11/k;->i:I

    .line 2
    .line 3
    return p0
.end method

.method public final o()I
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final p()Ln11/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lp11/k;->h:Lp11/m;

    .line 2
    .line 3
    iget-object p0, p0, Lp11/b;->o:Ln11/g;

    .line 4
    .line 5
    return-object p0
.end method

.method public final r(J)Z
    .locals 3

    .line 1
    iget-object v0, p0, Lp11/k;->h:Lp11/m;

    .line 2
    .line 3
    invoke-virtual {v0, p1, p2}, Lp11/e;->X(J)I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    invoke-virtual {v0, v1}, Lp11/m;->a0(I)Z

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    if-eqz v2, :cond_0

    .line 12
    .line 13
    invoke-virtual {v0, v1, p1, p2}, Lp11/g;->c0(IJ)I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    iget p0, p0, Lp11/k;->j:I

    .line 18
    .line 19
    if-ne p1, p0, :cond_0

    .line 20
    .line 21
    const/4 p0, 0x1

    .line 22
    return p0

    .line 23
    :cond_0
    const/4 p0, 0x0

    .line 24
    return p0
.end method

.method public final t(J)J
    .locals 2

    .line 1
    invoke-virtual {p0, p1, p2}, Lp11/k;->u(J)J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    sub-long/2addr p1, v0

    .line 6
    return-wide p1
.end method

.method public final u(J)J
    .locals 3

    .line 1
    iget-object p0, p0, Lp11/k;->h:Lp11/m;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lp11/e;->X(J)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    invoke-virtual {p0, v0, p1, p2}, Lp11/g;->c0(IJ)I

    .line 8
    .line 9
    .line 10
    move-result p1

    .line 11
    invoke-virtual {p0, v0}, Lp11/e;->Y(I)J

    .line 12
    .line 13
    .line 14
    move-result-wide v1

    .line 15
    invoke-virtual {p0, v0, p1}, Lp11/g;->T(II)J

    .line 16
    .line 17
    .line 18
    move-result-wide p0

    .line 19
    add-long/2addr p0, v1

    .line 20
    return-wide p0
.end method

.method public final v(IJ)J
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    iget v1, p0, Lp11/k;->i:I

    .line 3
    .line 4
    invoke-static {p0, p1, v0, v1}, Ljp/je;->g(Ln11/a;III)V

    .line 5
    .line 6
    .line 7
    iget-object p0, p0, Lp11/k;->h:Lp11/m;

    .line 8
    .line 9
    invoke-virtual {p0, p2, p3}, Lp11/e;->X(J)I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    invoke-virtual {p0, v0, p2, p3}, Lp11/g;->c0(IJ)I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    invoke-virtual {p0, p2, p3, v0, v1}, Lp11/e;->P(JII)I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    invoke-virtual {p0, v0, p1}, Lp11/g;->b0(II)I

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-le v1, v2, :cond_0

    .line 26
    .line 27
    move v1, v2

    .line 28
    :cond_0
    invoke-virtual {p0, v0, p1, v1}, Lp11/e;->Z(III)J

    .line 29
    .line 30
    .line 31
    move-result-wide p0

    .line 32
    invoke-static {p2, p3}, Lp11/e;->S(J)I

    .line 33
    .line 34
    .line 35
    move-result p2

    .line 36
    int-to-long p2, p2

    .line 37
    add-long/2addr p0, p2

    .line 38
    return-wide p0
.end method

.method public final y(Ljava/lang/String;Ljava/util/Locale;)I
    .locals 0

    .line 1
    invoke-static {p2}, Lp11/j;->b(Ljava/util/Locale;)Lp11/j;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p0, p0, Lp11/j;->i:Ljava/util/TreeMap;

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Ljava/util/TreeMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    check-cast p0, Ljava/lang/Integer;

    .line 12
    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    :cond_0
    new-instance p0, Ln11/i;

    .line 21
    .line 22
    sget-object p2, Ln11/b;->n:Ln11/b;

    .line 23
    .line 24
    invoke-direct {p0, p2, p1}, Ln11/i;-><init>(Ln11/b;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    throw p0
.end method

.method public final z(JJ)J
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-wide/from16 v1, p1

    .line 4
    .line 5
    move-wide/from16 v3, p3

    .line 6
    .line 7
    long-to-int v5, v3

    .line 8
    int-to-long v6, v5

    .line 9
    cmp-long v6, v6, v3

    .line 10
    .line 11
    if-nez v6, :cond_0

    .line 12
    .line 13
    invoke-virtual {v0, v5, v1, v2}, Lp11/k;->a(IJ)J

    .line 14
    .line 15
    .line 16
    move-result-wide v0

    .line 17
    return-wide v0

    .line 18
    :cond_0
    iget-object v5, v0, Lp11/k;->h:Lp11/m;

    .line 19
    .line 20
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    invoke-static {v1, v2}, Lp11/e;->S(J)I

    .line 24
    .line 25
    .line 26
    move-result v6

    .line 27
    int-to-long v6, v6

    .line 28
    invoke-virtual {v5, v1, v2}, Lp11/e;->X(J)I

    .line 29
    .line 30
    .line 31
    move-result v8

    .line 32
    invoke-virtual {v5, v8, v1, v2}, Lp11/g;->c0(IJ)I

    .line 33
    .line 34
    .line 35
    move-result v9

    .line 36
    add-int/lit8 v10, v9, -0x1

    .line 37
    .line 38
    int-to-long v10, v10

    .line 39
    add-long/2addr v10, v3

    .line 40
    const-wide/16 v12, 0x0

    .line 41
    .line 42
    cmp-long v12, v10, v12

    .line 43
    .line 44
    iget v0, v0, Lp11/k;->i:I

    .line 45
    .line 46
    if-ltz v12, :cond_1

    .line 47
    .line 48
    const-wide/16 v15, 0x1

    .line 49
    .line 50
    int-to-long v13, v8

    .line 51
    move-wide/from16 v17, v6

    .line 52
    .line 53
    int-to-long v6, v0

    .line 54
    div-long v19, v10, v6

    .line 55
    .line 56
    add-long v19, v19, v13

    .line 57
    .line 58
    rem-long/2addr v10, v6

    .line 59
    add-long/2addr v10, v15

    .line 60
    :goto_0
    move-wide/from16 v6, v19

    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_1
    move-wide/from16 v17, v6

    .line 64
    .line 65
    const-wide/16 v15, 0x1

    .line 66
    .line 67
    int-to-long v6, v8

    .line 68
    int-to-long v12, v0

    .line 69
    div-long v19, v10, v12

    .line 70
    .line 71
    add-long v19, v19, v6

    .line 72
    .line 73
    sub-long v6, v19, v15

    .line 74
    .line 75
    invoke-static {v10, v11}, Ljava/lang/Math;->abs(J)J

    .line 76
    .line 77
    .line 78
    move-result-wide v10

    .line 79
    rem-long/2addr v10, v12

    .line 80
    long-to-int v10, v10

    .line 81
    if-nez v10, :cond_2

    .line 82
    .line 83
    move v10, v0

    .line 84
    :cond_2
    sub-int/2addr v0, v10

    .line 85
    add-int/lit8 v0, v0, 0x1

    .line 86
    .line 87
    int-to-long v10, v0

    .line 88
    cmp-long v0, v10, v15

    .line 89
    .line 90
    if-nez v0, :cond_3

    .line 91
    .line 92
    goto :goto_0

    .line 93
    :cond_3
    :goto_1
    const v0, -0x116bc36e

    .line 94
    .line 95
    .line 96
    int-to-long v12, v0

    .line 97
    cmp-long v0, v6, v12

    .line 98
    .line 99
    if-ltz v0, :cond_5

    .line 100
    .line 101
    const v0, 0x116bd2d1

    .line 102
    .line 103
    .line 104
    int-to-long v12, v0

    .line 105
    cmp-long v0, v6, v12

    .line 106
    .line 107
    if-gtz v0, :cond_5

    .line 108
    .line 109
    long-to-int v0, v6

    .line 110
    long-to-int v3, v10

    .line 111
    invoke-virtual {v5, v1, v2, v8, v9}, Lp11/e;->P(JII)I

    .line 112
    .line 113
    .line 114
    move-result v1

    .line 115
    invoke-virtual {v5, v0, v3}, Lp11/g;->b0(II)I

    .line 116
    .line 117
    .line 118
    move-result v2

    .line 119
    if-le v1, v2, :cond_4

    .line 120
    .line 121
    move v1, v2

    .line 122
    :cond_4
    invoke-virtual {v5, v0, v3, v1}, Lp11/e;->Z(III)J

    .line 123
    .line 124
    .line 125
    move-result-wide v0

    .line 126
    add-long v0, v0, v17

    .line 127
    .line 128
    return-wide v0

    .line 129
    :cond_5
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 130
    .line 131
    const-string v1, "Magnitude of add amount is too large: "

    .line 132
    .line 133
    invoke-static {v3, v4, v1}, Lp3/m;->f(JLjava/lang/String;)Ljava/lang/String;

    .line 134
    .line 135
    .line 136
    move-result-object v1

    .line 137
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 138
    .line 139
    .line 140
    throw v0
.end method
