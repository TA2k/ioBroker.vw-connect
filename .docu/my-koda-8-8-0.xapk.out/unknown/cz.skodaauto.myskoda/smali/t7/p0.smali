.class public abstract Lt7/p0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lt7/m0;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lt7/m0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lt7/p0;->a:Lt7/m0;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    invoke-static {v0}, Lw7/w;->z(I)V

    .line 10
    .line 11
    .line 12
    const/4 v0, 0x1

    .line 13
    invoke-static {v0}, Lw7/w;->z(I)V

    .line 14
    .line 15
    .line 16
    const/4 v0, 0x2

    .line 17
    invoke-static {v0}, Lw7/w;->z(I)V

    .line 18
    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public a(Z)I
    .locals 0

    .line 1
    invoke-virtual {p0}, Lt7/p0;->p()Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    const/4 p0, -0x1

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 p0, 0x0

    .line 10
    return p0
.end method

.method public abstract b(Ljava/lang/Object;)I
.end method

.method public c(Z)I
    .locals 0

    .line 1
    invoke-virtual {p0}, Lt7/p0;->p()Z

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    const/4 p0, -0x1

    .line 8
    return p0

    .line 9
    :cond_0
    invoke-virtual {p0}, Lt7/p0;->o()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    add-int/lit8 p0, p0, -0x1

    .line 14
    .line 15
    return p0
.end method

.method public final d(ILt7/n0;Lt7/o0;IZ)I
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, p1, p2, v0}, Lt7/p0;->f(ILt7/n0;Z)Lt7/n0;

    .line 3
    .line 4
    .line 5
    move-result-object p2

    .line 6
    iget p2, p2, Lt7/n0;->c:I

    .line 7
    .line 8
    const-wide/16 v0, 0x0

    .line 9
    .line 10
    invoke-virtual {p0, p2, p3, v0, v1}, Lt7/p0;->m(ILt7/o0;J)Lt7/o0;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    iget v2, v2, Lt7/o0;->n:I

    .line 15
    .line 16
    if-ne v2, p1, :cond_1

    .line 17
    .line 18
    invoke-virtual {p0, p2, p4, p5}, Lt7/p0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result p1

    .line 22
    const/4 p2, -0x1

    .line 23
    if-ne p1, p2, :cond_0

    .line 24
    .line 25
    return p2

    .line 26
    :cond_0
    invoke-virtual {p0, p1, p3, v0, v1}, Lt7/p0;->m(ILt7/o0;J)Lt7/o0;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    iget p0, p0, Lt7/o0;->m:I

    .line 31
    .line 32
    return p0

    .line 33
    :cond_1
    add-int/lit8 p1, p1, 0x1

    .line 34
    .line 35
    return p1
.end method

.method public e(IIZ)I
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    if-eqz p2, :cond_3

    .line 3
    .line 4
    if-eq p2, v0, :cond_2

    .line 5
    .line 6
    const/4 v1, 0x2

    .line 7
    if-ne p2, v1, :cond_1

    .line 8
    .line 9
    invoke-virtual {p0, p3}, Lt7/p0;->c(Z)I

    .line 10
    .line 11
    .line 12
    move-result p2

    .line 13
    if-ne p1, p2, :cond_0

    .line 14
    .line 15
    invoke-virtual {p0, p3}, Lt7/p0;->a(Z)I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    :cond_0
    add-int/2addr p1, v0

    .line 21
    return p1

    .line 22
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 23
    .line 24
    invoke-direct {p0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 25
    .line 26
    .line 27
    throw p0

    .line 28
    :cond_2
    return p1

    .line 29
    :cond_3
    invoke-virtual {p0, p3}, Lt7/p0;->c(Z)I

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    if-ne p1, p0, :cond_4

    .line 34
    .line 35
    const/4 p0, -0x1

    .line 36
    return p0

    .line 37
    :cond_4
    add-int/2addr p1, v0

    .line 38
    return p1
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 10

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    goto/16 :goto_3

    .line 5
    .line 6
    :cond_0
    instance-of v1, p1, Lt7/p0;

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    if-nez v1, :cond_1

    .line 10
    .line 11
    goto/16 :goto_4

    .line 12
    .line 13
    :cond_1
    check-cast p1, Lt7/p0;

    .line 14
    .line 15
    invoke-virtual {p1}, Lt7/p0;->o()I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    invoke-virtual {p0}, Lt7/p0;->o()I

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    if-ne v1, v3, :cond_b

    .line 24
    .line 25
    invoke-virtual {p1}, Lt7/p0;->h()I

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    invoke-virtual {p0}, Lt7/p0;->h()I

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    if-eq v1, v3, :cond_2

    .line 34
    .line 35
    goto/16 :goto_4

    .line 36
    .line 37
    :cond_2
    new-instance v1, Lt7/o0;

    .line 38
    .line 39
    invoke-direct {v1}, Lt7/o0;-><init>()V

    .line 40
    .line 41
    .line 42
    new-instance v3, Lt7/n0;

    .line 43
    .line 44
    invoke-direct {v3}, Lt7/n0;-><init>()V

    .line 45
    .line 46
    .line 47
    new-instance v4, Lt7/o0;

    .line 48
    .line 49
    invoke-direct {v4}, Lt7/o0;-><init>()V

    .line 50
    .line 51
    .line 52
    new-instance v5, Lt7/n0;

    .line 53
    .line 54
    invoke-direct {v5}, Lt7/n0;-><init>()V

    .line 55
    .line 56
    .line 57
    move v6, v2

    .line 58
    :goto_0
    invoke-virtual {p0}, Lt7/p0;->o()I

    .line 59
    .line 60
    .line 61
    move-result v7

    .line 62
    if-ge v6, v7, :cond_4

    .line 63
    .line 64
    const-wide/16 v7, 0x0

    .line 65
    .line 66
    invoke-virtual {p0, v6, v1, v7, v8}, Lt7/p0;->m(ILt7/o0;J)Lt7/o0;

    .line 67
    .line 68
    .line 69
    move-result-object v9

    .line 70
    invoke-virtual {p1, v6, v4, v7, v8}, Lt7/p0;->m(ILt7/o0;J)Lt7/o0;

    .line 71
    .line 72
    .line 73
    move-result-object v7

    .line 74
    invoke-virtual {v9, v7}, Lt7/o0;->equals(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result v7

    .line 78
    if-nez v7, :cond_3

    .line 79
    .line 80
    goto :goto_4

    .line 81
    :cond_3
    add-int/lit8 v6, v6, 0x1

    .line 82
    .line 83
    goto :goto_0

    .line 84
    :cond_4
    move v1, v2

    .line 85
    :goto_1
    invoke-virtual {p0}, Lt7/p0;->h()I

    .line 86
    .line 87
    .line 88
    move-result v4

    .line 89
    if-ge v1, v4, :cond_6

    .line 90
    .line 91
    invoke-virtual {p0, v1, v3, v0}, Lt7/p0;->f(ILt7/n0;Z)Lt7/n0;

    .line 92
    .line 93
    .line 94
    move-result-object v4

    .line 95
    invoke-virtual {p1, v1, v5, v0}, Lt7/p0;->f(ILt7/n0;Z)Lt7/n0;

    .line 96
    .line 97
    .line 98
    move-result-object v6

    .line 99
    invoke-virtual {v4, v6}, Lt7/n0;->equals(Ljava/lang/Object;)Z

    .line 100
    .line 101
    .line 102
    move-result v4

    .line 103
    if-nez v4, :cond_5

    .line 104
    .line 105
    goto :goto_4

    .line 106
    :cond_5
    add-int/lit8 v1, v1, 0x1

    .line 107
    .line 108
    goto :goto_1

    .line 109
    :cond_6
    invoke-virtual {p0, v0}, Lt7/p0;->a(Z)I

    .line 110
    .line 111
    .line 112
    move-result v1

    .line 113
    invoke-virtual {p1, v0}, Lt7/p0;->a(Z)I

    .line 114
    .line 115
    .line 116
    move-result v3

    .line 117
    if-eq v1, v3, :cond_7

    .line 118
    .line 119
    goto :goto_4

    .line 120
    :cond_7
    invoke-virtual {p0, v0}, Lt7/p0;->c(Z)I

    .line 121
    .line 122
    .line 123
    move-result v3

    .line 124
    invoke-virtual {p1, v0}, Lt7/p0;->c(Z)I

    .line 125
    .line 126
    .line 127
    move-result v4

    .line 128
    if-eq v3, v4, :cond_8

    .line 129
    .line 130
    goto :goto_4

    .line 131
    :cond_8
    :goto_2
    if-eq v1, v3, :cond_a

    .line 132
    .line 133
    invoke-virtual {p0, v1, v2, v0}, Lt7/p0;->e(IIZ)I

    .line 134
    .line 135
    .line 136
    move-result v4

    .line 137
    invoke-virtual {p1, v1, v2, v0}, Lt7/p0;->e(IIZ)I

    .line 138
    .line 139
    .line 140
    move-result v1

    .line 141
    if-eq v4, v1, :cond_9

    .line 142
    .line 143
    goto :goto_4

    .line 144
    :cond_9
    move v1, v4

    .line 145
    goto :goto_2

    .line 146
    :cond_a
    :goto_3
    return v0

    .line 147
    :cond_b
    :goto_4
    return v2
.end method

.method public abstract f(ILt7/n0;Z)Lt7/n0;
.end method

.method public g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;
    .locals 1

    .line 1
    invoke-virtual {p0, p1}, Lt7/p0;->b(Ljava/lang/Object;)I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    const/4 v0, 0x1

    .line 6
    invoke-virtual {p0, p1, p2, v0}, Lt7/p0;->f(ILt7/n0;Z)Lt7/n0;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method

.method public abstract h()I
.end method

.method public hashCode()I
    .locals 7

    .line 1
    new-instance v0, Lt7/o0;

    .line 2
    .line 3
    invoke-direct {v0}, Lt7/o0;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lt7/n0;

    .line 7
    .line 8
    invoke-direct {v1}, Lt7/n0;-><init>()V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Lt7/p0;->o()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    add-int/lit16 v2, v2, 0xd9

    .line 16
    .line 17
    const/4 v3, 0x0

    .line 18
    move v4, v3

    .line 19
    :goto_0
    invoke-virtual {p0}, Lt7/p0;->o()I

    .line 20
    .line 21
    .line 22
    move-result v5

    .line 23
    if-ge v4, v5, :cond_0

    .line 24
    .line 25
    mul-int/lit8 v2, v2, 0x1f

    .line 26
    .line 27
    const-wide/16 v5, 0x0

    .line 28
    .line 29
    invoke-virtual {p0, v4, v0, v5, v6}, Lt7/p0;->m(ILt7/o0;J)Lt7/o0;

    .line 30
    .line 31
    .line 32
    move-result-object v5

    .line 33
    invoke-virtual {v5}, Lt7/o0;->hashCode()I

    .line 34
    .line 35
    .line 36
    move-result v5

    .line 37
    add-int/2addr v2, v5

    .line 38
    add-int/lit8 v4, v4, 0x1

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    mul-int/lit8 v2, v2, 0x1f

    .line 42
    .line 43
    invoke-virtual {p0}, Lt7/p0;->h()I

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    add-int/2addr v0, v2

    .line 48
    move v2, v3

    .line 49
    :goto_1
    invoke-virtual {p0}, Lt7/p0;->h()I

    .line 50
    .line 51
    .line 52
    move-result v4

    .line 53
    const/4 v5, 0x1

    .line 54
    if-ge v2, v4, :cond_1

    .line 55
    .line 56
    mul-int/lit8 v0, v0, 0x1f

    .line 57
    .line 58
    invoke-virtual {p0, v2, v1, v5}, Lt7/p0;->f(ILt7/n0;Z)Lt7/n0;

    .line 59
    .line 60
    .line 61
    move-result-object v4

    .line 62
    invoke-virtual {v4}, Lt7/n0;->hashCode()I

    .line 63
    .line 64
    .line 65
    move-result v4

    .line 66
    add-int/2addr v0, v4

    .line 67
    add-int/lit8 v2, v2, 0x1

    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_1
    invoke-virtual {p0, v5}, Lt7/p0;->a(Z)I

    .line 71
    .line 72
    .line 73
    move-result v1

    .line 74
    :goto_2
    const/4 v2, -0x1

    .line 75
    if-eq v1, v2, :cond_2

    .line 76
    .line 77
    mul-int/lit8 v0, v0, 0x1f

    .line 78
    .line 79
    add-int/2addr v0, v1

    .line 80
    invoke-virtual {p0, v1, v3, v5}, Lt7/p0;->e(IIZ)I

    .line 81
    .line 82
    .line 83
    move-result v1

    .line 84
    goto :goto_2

    .line 85
    :cond_2
    return v0
.end method

.method public final i(Lt7/o0;Lt7/n0;IJ)Landroid/util/Pair;
    .locals 8

    .line 1
    const-wide/16 v6, 0x0

    .line 2
    .line 3
    move-object v0, p0

    .line 4
    move-object v1, p1

    .line 5
    move-object v2, p2

    .line 6
    move v3, p3

    .line 7
    move-wide v4, p4

    .line 8
    invoke-virtual/range {v0 .. v7}, Lt7/p0;->j(Lt7/o0;Lt7/n0;IJJ)Landroid/util/Pair;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    return-object p0
.end method

.method public final j(Lt7/o0;Lt7/n0;IJJ)Landroid/util/Pair;
    .locals 4

    .line 1
    invoke-virtual {p0}, Lt7/p0;->o()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-static {p3, v0}, Lw7/a;->g(II)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, p3, p1, p6, p7}, Lt7/p0;->m(ILt7/o0;J)Lt7/o0;

    .line 9
    .line 10
    .line 11
    const-wide p6, -0x7fffffffffffffffL    # -4.9E-324

    .line 12
    .line 13
    .line 14
    .line 15
    .line 16
    cmp-long p3, p4, p6

    .line 17
    .line 18
    if-nez p3, :cond_0

    .line 19
    .line 20
    iget-wide p4, p1, Lt7/o0;->k:J

    .line 21
    .line 22
    cmp-long p3, p4, p6

    .line 23
    .line 24
    if-nez p3, :cond_0

    .line 25
    .line 26
    const/4 p0, 0x0

    .line 27
    return-object p0

    .line 28
    :cond_0
    iget p3, p1, Lt7/o0;->m:I

    .line 29
    .line 30
    const/4 v0, 0x0

    .line 31
    invoke-virtual {p0, p3, p2, v0}, Lt7/p0;->f(ILt7/n0;Z)Lt7/n0;

    .line 32
    .line 33
    .line 34
    :goto_0
    iget v1, p1, Lt7/o0;->n:I

    .line 35
    .line 36
    if-ge p3, v1, :cond_1

    .line 37
    .line 38
    iget-wide v1, p2, Lt7/n0;->e:J

    .line 39
    .line 40
    cmp-long v1, v1, p4

    .line 41
    .line 42
    if-eqz v1, :cond_1

    .line 43
    .line 44
    add-int/lit8 v1, p3, 0x1

    .line 45
    .line 46
    invoke-virtual {p0, v1, p2, v0}, Lt7/p0;->f(ILt7/n0;Z)Lt7/n0;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    iget-wide v2, v2, Lt7/n0;->e:J

    .line 51
    .line 52
    cmp-long v2, v2, p4

    .line 53
    .line 54
    if-gtz v2, :cond_1

    .line 55
    .line 56
    move p3, v1

    .line 57
    goto :goto_0

    .line 58
    :cond_1
    const/4 p1, 0x1

    .line 59
    invoke-virtual {p0, p3, p2, p1}, Lt7/p0;->f(ILt7/n0;Z)Lt7/n0;

    .line 60
    .line 61
    .line 62
    iget-wide p0, p2, Lt7/n0;->e:J

    .line 63
    .line 64
    sub-long/2addr p4, p0

    .line 65
    iget-wide p0, p2, Lt7/n0;->d:J

    .line 66
    .line 67
    cmp-long p3, p0, p6

    .line 68
    .line 69
    if-eqz p3, :cond_2

    .line 70
    .line 71
    const-wide/16 p6, 0x1

    .line 72
    .line 73
    sub-long/2addr p0, p6

    .line 74
    invoke-static {p4, p5, p0, p1}, Ljava/lang/Math;->min(JJ)J

    .line 75
    .line 76
    .line 77
    move-result-wide p4

    .line 78
    :cond_2
    const-wide/16 p0, 0x0

    .line 79
    .line 80
    invoke-static {p0, p1, p4, p5}, Ljava/lang/Math;->max(JJ)J

    .line 81
    .line 82
    .line 83
    move-result-wide p0

    .line 84
    iget-object p2, p2, Lt7/n0;->b:Ljava/lang/Object;

    .line 85
    .line 86
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 87
    .line 88
    .line 89
    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    invoke-static {p2, p0}, Landroid/util/Pair;->create(Ljava/lang/Object;Ljava/lang/Object;)Landroid/util/Pair;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    return-object p0
.end method

.method public k(IIZ)I
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    if-eqz p2, :cond_3

    .line 3
    .line 4
    if-eq p2, v0, :cond_2

    .line 5
    .line 6
    const/4 v1, 0x2

    .line 7
    if-ne p2, v1, :cond_1

    .line 8
    .line 9
    invoke-virtual {p0, p3}, Lt7/p0;->a(Z)I

    .line 10
    .line 11
    .line 12
    move-result p2

    .line 13
    if-ne p1, p2, :cond_0

    .line 14
    .line 15
    invoke-virtual {p0, p3}, Lt7/p0;->c(Z)I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    :cond_0
    sub-int/2addr p1, v0

    .line 21
    return p1

    .line 22
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 23
    .line 24
    invoke-direct {p0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 25
    .line 26
    .line 27
    throw p0

    .line 28
    :cond_2
    return p1

    .line 29
    :cond_3
    invoke-virtual {p0, p3}, Lt7/p0;->a(Z)I

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    if-ne p1, p0, :cond_4

    .line 34
    .line 35
    const/4 p0, -0x1

    .line 36
    return p0

    .line 37
    :cond_4
    sub-int/2addr p1, v0

    .line 38
    return p1
.end method

.method public abstract l(I)Ljava/lang/Object;
.end method

.method public abstract m(ILt7/o0;J)Lt7/o0;
.end method

.method public final n(ILt7/o0;)V
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2, v0, v1}, Lt7/p0;->m(ILt7/o0;J)Lt7/o0;

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public abstract o()I
.end method

.method public final p()Z
    .locals 0

    .line 1
    invoke-virtual {p0}, Lt7/p0;->o()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 p0, 0x0

    .line 10
    return p0
.end method
