.class public final Landroidx/collection/q0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:[J

.field public b:[Ljava/lang/Object;

.field public c:[Ljava/lang/Object;

.field public d:I

.field public e:I

.field public f:I


# direct methods
.method public synthetic constructor <init>()V
    .locals 1

    const/4 v0, 0x6

    .line 8
    invoke-direct {p0, v0}, Landroidx/collection/q0;-><init>(I)V

    return-void
.end method

.method public constructor <init>(I)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    sget-object v0, Landroidx/collection/y0;->a:[J

    iput-object v0, p0, Landroidx/collection/q0;->a:[J

    .line 3
    sget-object v0, La1/a;->c:[Ljava/lang/Object;

    iput-object v0, p0, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 4
    iput-object v0, p0, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    if-ltz p1, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    if-eqz v0, :cond_1

    .line 5
    invoke-static {p1}, Landroidx/collection/y0;->d(I)I

    move-result p1

    invoke-virtual {p0, p1}, Landroidx/collection/q0;->h(I)V

    return-void

    .line 6
    :cond_1
    const-string p0, "Capacity must be a positive value."

    .line 7
    invoke-static {p0}, La1/a;->c(Ljava/lang/String;)V

    const/4 p0, 0x0

    throw p0
.end method


# virtual methods
.method public final a()V
    .locals 10

    .line 1
    const/4 v0, 0x0

    .line 2
    iput v0, p0, Landroidx/collection/q0;->e:I

    .line 3
    .line 4
    iget-object v1, p0, Landroidx/collection/q0;->a:[J

    .line 5
    .line 6
    sget-object v2, Landroidx/collection/y0;->a:[J

    .line 7
    .line 8
    if-eq v1, v2, :cond_0

    .line 9
    .line 10
    const-wide v2, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 11
    .line 12
    .line 13
    .line 14
    .line 15
    invoke-static {v2, v3, v1}, Lmx0/n;->r(J[J)V

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Landroidx/collection/q0;->a:[J

    .line 19
    .line 20
    iget v2, p0, Landroidx/collection/q0;->d:I

    .line 21
    .line 22
    shr-int/lit8 v3, v2, 0x3

    .line 23
    .line 24
    and-int/lit8 v2, v2, 0x7

    .line 25
    .line 26
    shl-int/lit8 v2, v2, 0x3

    .line 27
    .line 28
    aget-wide v4, v1, v3

    .line 29
    .line 30
    const-wide/16 v6, 0xff

    .line 31
    .line 32
    shl-long/2addr v6, v2

    .line 33
    not-long v8, v6

    .line 34
    and-long/2addr v4, v8

    .line 35
    or-long/2addr v4, v6

    .line 36
    aput-wide v4, v1, v3

    .line 37
    .line 38
    :cond_0
    iget-object v1, p0, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 39
    .line 40
    iget v2, p0, Landroidx/collection/q0;->d:I

    .line 41
    .line 42
    const/4 v3, 0x0

    .line 43
    invoke-static {v0, v2, v3, v1}, Lmx0/n;->q(IILjava/lang/Object;[Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    iget-object v1, p0, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 47
    .line 48
    iget v2, p0, Landroidx/collection/q0;->d:I

    .line 49
    .line 50
    invoke-static {v0, v2, v3, v1}, Lmx0/n;->q(IILjava/lang/Object;[Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    iget v0, p0, Landroidx/collection/q0;->d:I

    .line 54
    .line 55
    invoke-static {v0}, Landroidx/collection/y0;->a(I)I

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    iget v1, p0, Landroidx/collection/q0;->e:I

    .line 60
    .line 61
    sub-int/2addr v0, v1

    .line 62
    iput v0, p0, Landroidx/collection/q0;->f:I

    .line 63
    .line 64
    return-void
.end method

.method public final b(Ljava/lang/Object;)Z
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 9
    .line 10
    .line 11
    move-result v3

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move v3, v2

    .line 14
    :goto_0
    const v4, -0x3361d2af    # -8.2930312E7f

    .line 15
    .line 16
    .line 17
    mul-int/2addr v3, v4

    .line 18
    shl-int/lit8 v4, v3, 0x10

    .line 19
    .line 20
    xor-int/2addr v3, v4

    .line 21
    and-int/lit8 v4, v3, 0x7f

    .line 22
    .line 23
    iget v5, v0, Landroidx/collection/q0;->d:I

    .line 24
    .line 25
    ushr-int/lit8 v3, v3, 0x7

    .line 26
    .line 27
    and-int/2addr v3, v5

    .line 28
    move v6, v2

    .line 29
    :goto_1
    iget-object v7, v0, Landroidx/collection/q0;->a:[J

    .line 30
    .line 31
    shr-int/lit8 v8, v3, 0x3

    .line 32
    .line 33
    and-int/lit8 v9, v3, 0x7

    .line 34
    .line 35
    shl-int/lit8 v9, v9, 0x3

    .line 36
    .line 37
    aget-wide v10, v7, v8

    .line 38
    .line 39
    ushr-long/2addr v10, v9

    .line 40
    const/4 v12, 0x1

    .line 41
    add-int/2addr v8, v12

    .line 42
    aget-wide v7, v7, v8

    .line 43
    .line 44
    rsub-int/lit8 v13, v9, 0x40

    .line 45
    .line 46
    shl-long/2addr v7, v13

    .line 47
    int-to-long v13, v9

    .line 48
    neg-long v13, v13

    .line 49
    const/16 v9, 0x3f

    .line 50
    .line 51
    shr-long/2addr v13, v9

    .line 52
    and-long/2addr v7, v13

    .line 53
    or-long/2addr v7, v10

    .line 54
    int-to-long v9, v4

    .line 55
    const-wide v13, 0x101010101010101L

    .line 56
    .line 57
    .line 58
    .line 59
    .line 60
    mul-long/2addr v9, v13

    .line 61
    xor-long/2addr v9, v7

    .line 62
    sub-long v13, v9, v13

    .line 63
    .line 64
    not-long v9, v9

    .line 65
    and-long/2addr v9, v13

    .line 66
    const-wide v13, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 67
    .line 68
    .line 69
    .line 70
    .line 71
    and-long/2addr v9, v13

    .line 72
    :goto_2
    const-wide/16 v15, 0x0

    .line 73
    .line 74
    cmp-long v11, v9, v15

    .line 75
    .line 76
    if-eqz v11, :cond_2

    .line 77
    .line 78
    invoke-static {v9, v10}, Ljava/lang/Long;->numberOfTrailingZeros(J)I

    .line 79
    .line 80
    .line 81
    move-result v11

    .line 82
    shr-int/lit8 v11, v11, 0x3

    .line 83
    .line 84
    add-int/2addr v11, v3

    .line 85
    and-int/2addr v11, v5

    .line 86
    iget-object v15, v0, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 87
    .line 88
    aget-object v15, v15, v11

    .line 89
    .line 90
    invoke-static {v15, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result v15

    .line 94
    if-eqz v15, :cond_1

    .line 95
    .line 96
    goto :goto_3

    .line 97
    :cond_1
    const-wide/16 v15, 0x1

    .line 98
    .line 99
    sub-long v15, v9, v15

    .line 100
    .line 101
    and-long/2addr v9, v15

    .line 102
    goto :goto_2

    .line 103
    :cond_2
    not-long v9, v7

    .line 104
    const/4 v11, 0x6

    .line 105
    shl-long/2addr v9, v11

    .line 106
    and-long/2addr v7, v9

    .line 107
    and-long/2addr v7, v13

    .line 108
    cmp-long v7, v7, v15

    .line 109
    .line 110
    if-eqz v7, :cond_4

    .line 111
    .line 112
    const/4 v11, -0x1

    .line 113
    :goto_3
    if-ltz v11, :cond_3

    .line 114
    .line 115
    return v12

    .line 116
    :cond_3
    return v2

    .line 117
    :cond_4
    add-int/lit8 v6, v6, 0x8

    .line 118
    .line 119
    add-int/2addr v3, v6

    .line 120
    and-int/2addr v3, v5

    .line 121
    goto :goto_1
.end method

.method public final c(Ljava/lang/Object;)Z
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 9
    .line 10
    .line 11
    move-result v3

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move v3, v2

    .line 14
    :goto_0
    const v4, -0x3361d2af    # -8.2930312E7f

    .line 15
    .line 16
    .line 17
    mul-int/2addr v3, v4

    .line 18
    shl-int/lit8 v4, v3, 0x10

    .line 19
    .line 20
    xor-int/2addr v3, v4

    .line 21
    and-int/lit8 v4, v3, 0x7f

    .line 22
    .line 23
    iget v5, v0, Landroidx/collection/q0;->d:I

    .line 24
    .line 25
    ushr-int/lit8 v3, v3, 0x7

    .line 26
    .line 27
    and-int/2addr v3, v5

    .line 28
    move v6, v2

    .line 29
    :goto_1
    iget-object v7, v0, Landroidx/collection/q0;->a:[J

    .line 30
    .line 31
    shr-int/lit8 v8, v3, 0x3

    .line 32
    .line 33
    and-int/lit8 v9, v3, 0x7

    .line 34
    .line 35
    shl-int/lit8 v9, v9, 0x3

    .line 36
    .line 37
    aget-wide v10, v7, v8

    .line 38
    .line 39
    ushr-long/2addr v10, v9

    .line 40
    const/4 v12, 0x1

    .line 41
    add-int/2addr v8, v12

    .line 42
    aget-wide v7, v7, v8

    .line 43
    .line 44
    rsub-int/lit8 v13, v9, 0x40

    .line 45
    .line 46
    shl-long/2addr v7, v13

    .line 47
    int-to-long v13, v9

    .line 48
    neg-long v13, v13

    .line 49
    const/16 v9, 0x3f

    .line 50
    .line 51
    shr-long/2addr v13, v9

    .line 52
    and-long/2addr v7, v13

    .line 53
    or-long/2addr v7, v10

    .line 54
    int-to-long v9, v4

    .line 55
    const-wide v13, 0x101010101010101L

    .line 56
    .line 57
    .line 58
    .line 59
    .line 60
    mul-long/2addr v9, v13

    .line 61
    xor-long/2addr v9, v7

    .line 62
    sub-long v13, v9, v13

    .line 63
    .line 64
    not-long v9, v9

    .line 65
    and-long/2addr v9, v13

    .line 66
    const-wide v13, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 67
    .line 68
    .line 69
    .line 70
    .line 71
    and-long/2addr v9, v13

    .line 72
    :goto_2
    const-wide/16 v15, 0x0

    .line 73
    .line 74
    cmp-long v11, v9, v15

    .line 75
    .line 76
    if-eqz v11, :cond_2

    .line 77
    .line 78
    invoke-static {v9, v10}, Ljava/lang/Long;->numberOfTrailingZeros(J)I

    .line 79
    .line 80
    .line 81
    move-result v11

    .line 82
    shr-int/lit8 v11, v11, 0x3

    .line 83
    .line 84
    add-int/2addr v11, v3

    .line 85
    and-int/2addr v11, v5

    .line 86
    iget-object v15, v0, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 87
    .line 88
    aget-object v15, v15, v11

    .line 89
    .line 90
    invoke-static {v15, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result v15

    .line 94
    if-eqz v15, :cond_1

    .line 95
    .line 96
    goto :goto_3

    .line 97
    :cond_1
    const-wide/16 v15, 0x1

    .line 98
    .line 99
    sub-long v15, v9, v15

    .line 100
    .line 101
    and-long/2addr v9, v15

    .line 102
    goto :goto_2

    .line 103
    :cond_2
    not-long v9, v7

    .line 104
    const/4 v11, 0x6

    .line 105
    shl-long/2addr v9, v11

    .line 106
    and-long/2addr v7, v9

    .line 107
    and-long/2addr v7, v13

    .line 108
    cmp-long v7, v7, v15

    .line 109
    .line 110
    if-eqz v7, :cond_4

    .line 111
    .line 112
    const/4 v11, -0x1

    .line 113
    :goto_3
    if-ltz v11, :cond_3

    .line 114
    .line 115
    return v12

    .line 116
    :cond_3
    return v2

    .line 117
    :cond_4
    add-int/lit8 v6, v6, 0x8

    .line 118
    .line 119
    add-int/2addr v3, v6

    .line 120
    and-int/2addr v3, v5

    .line 121
    goto :goto_1
.end method

.method public final d(Ljava/lang/Object;)Z
    .locals 13

    .line 1
    iget-object v0, p0, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 2
    .line 3
    iget-object p0, p0, Landroidx/collection/q0;->a:[J

    .line 4
    .line 5
    array-length v1, p0

    .line 6
    add-int/lit8 v1, v1, -0x2

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    if-ltz v1, :cond_3

    .line 10
    .line 11
    move v3, v2

    .line 12
    :goto_0
    aget-wide v4, p0, v3

    .line 13
    .line 14
    not-long v6, v4

    .line 15
    const/4 v8, 0x7

    .line 16
    shl-long/2addr v6, v8

    .line 17
    and-long/2addr v6, v4

    .line 18
    const-wide v8, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 19
    .line 20
    .line 21
    .line 22
    .line 23
    and-long/2addr v6, v8

    .line 24
    cmp-long v6, v6, v8

    .line 25
    .line 26
    if-eqz v6, :cond_2

    .line 27
    .line 28
    sub-int v6, v3, v1

    .line 29
    .line 30
    not-int v6, v6

    .line 31
    ushr-int/lit8 v6, v6, 0x1f

    .line 32
    .line 33
    const/16 v7, 0x8

    .line 34
    .line 35
    rsub-int/lit8 v6, v6, 0x8

    .line 36
    .line 37
    move v8, v2

    .line 38
    :goto_1
    if-ge v8, v6, :cond_1

    .line 39
    .line 40
    const-wide/16 v9, 0xff

    .line 41
    .line 42
    and-long/2addr v9, v4

    .line 43
    const-wide/16 v11, 0x80

    .line 44
    .line 45
    cmp-long v9, v9, v11

    .line 46
    .line 47
    if-gez v9, :cond_0

    .line 48
    .line 49
    shl-int/lit8 v9, v3, 0x3

    .line 50
    .line 51
    add-int/2addr v9, v8

    .line 52
    aget-object v9, v0, v9

    .line 53
    .line 54
    invoke-static {p1, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v9

    .line 58
    if-eqz v9, :cond_0

    .line 59
    .line 60
    const/4 p0, 0x1

    .line 61
    return p0

    .line 62
    :cond_0
    shr-long/2addr v4, v7

    .line 63
    add-int/lit8 v8, v8, 0x1

    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_1
    if-ne v6, v7, :cond_3

    .line 67
    .line 68
    :cond_2
    if-eq v3, v1, :cond_3

    .line 69
    .line 70
    add-int/lit8 v3, v3, 0x1

    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_3
    return v2
.end method

.method public final e(I)I
    .locals 9

    .line 1
    iget v0, p0, Landroidx/collection/q0;->d:I

    .line 2
    .line 3
    and-int/2addr p1, v0

    .line 4
    const/4 v1, 0x0

    .line 5
    :goto_0
    iget-object v2, p0, Landroidx/collection/q0;->a:[J

    .line 6
    .line 7
    shr-int/lit8 v3, p1, 0x3

    .line 8
    .line 9
    and-int/lit8 v4, p1, 0x7

    .line 10
    .line 11
    shl-int/lit8 v4, v4, 0x3

    .line 12
    .line 13
    aget-wide v5, v2, v3

    .line 14
    .line 15
    ushr-long/2addr v5, v4

    .line 16
    add-int/lit8 v3, v3, 0x1

    .line 17
    .line 18
    aget-wide v2, v2, v3

    .line 19
    .line 20
    rsub-int/lit8 v7, v4, 0x40

    .line 21
    .line 22
    shl-long/2addr v2, v7

    .line 23
    int-to-long v7, v4

    .line 24
    neg-long v7, v7

    .line 25
    const/16 v4, 0x3f

    .line 26
    .line 27
    shr-long/2addr v7, v4

    .line 28
    and-long/2addr v2, v7

    .line 29
    or-long/2addr v2, v5

    .line 30
    not-long v4, v2

    .line 31
    const/4 v6, 0x7

    .line 32
    shl-long/2addr v4, v6

    .line 33
    and-long/2addr v2, v4

    .line 34
    const-wide v4, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 35
    .line 36
    .line 37
    .line 38
    .line 39
    and-long/2addr v2, v4

    .line 40
    const-wide/16 v4, 0x0

    .line 41
    .line 42
    cmp-long v4, v2, v4

    .line 43
    .line 44
    if-eqz v4, :cond_0

    .line 45
    .line 46
    invoke-static {v2, v3}, Ljava/lang/Long;->numberOfTrailingZeros(J)I

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    shr-int/lit8 p0, p0, 0x3

    .line 51
    .line 52
    add-int/2addr p1, p0

    .line 53
    and-int p0, p1, v0

    .line 54
    .line 55
    return p0

    .line 56
    :cond_0
    add-int/lit8 v1, v1, 0x8

    .line 57
    .line 58
    add-int/2addr p1, v1

    .line 59
    and-int/2addr p1, v0

    .line 60
    goto :goto_0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    if-ne v1, v0, :cond_0

    .line 7
    .line 8
    return v2

    .line 9
    :cond_0
    instance-of v3, v1, Landroidx/collection/q0;

    .line 10
    .line 11
    const/4 v4, 0x0

    .line 12
    if-nez v3, :cond_1

    .line 13
    .line 14
    return v4

    .line 15
    :cond_1
    check-cast v1, Landroidx/collection/q0;

    .line 16
    .line 17
    iget v3, v1, Landroidx/collection/q0;->e:I

    .line 18
    .line 19
    iget v5, v0, Landroidx/collection/q0;->e:I

    .line 20
    .line 21
    if-eq v3, v5, :cond_2

    .line 22
    .line 23
    return v4

    .line 24
    :cond_2
    iget-object v3, v0, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 25
    .line 26
    iget-object v5, v0, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 27
    .line 28
    iget-object v0, v0, Landroidx/collection/q0;->a:[J

    .line 29
    .line 30
    array-length v6, v0

    .line 31
    add-int/lit8 v6, v6, -0x2

    .line 32
    .line 33
    if-ltz v6, :cond_8

    .line 34
    .line 35
    move v7, v4

    .line 36
    :goto_0
    aget-wide v8, v0, v7

    .line 37
    .line 38
    not-long v10, v8

    .line 39
    const/4 v12, 0x7

    .line 40
    shl-long/2addr v10, v12

    .line 41
    and-long/2addr v10, v8

    .line 42
    const-wide v12, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 43
    .line 44
    .line 45
    .line 46
    .line 47
    and-long/2addr v10, v12

    .line 48
    cmp-long v10, v10, v12

    .line 49
    .line 50
    if-eqz v10, :cond_7

    .line 51
    .line 52
    sub-int v10, v7, v6

    .line 53
    .line 54
    not-int v10, v10

    .line 55
    ushr-int/lit8 v10, v10, 0x1f

    .line 56
    .line 57
    const/16 v11, 0x8

    .line 58
    .line 59
    rsub-int/lit8 v10, v10, 0x8

    .line 60
    .line 61
    move v12, v4

    .line 62
    :goto_1
    if-ge v12, v10, :cond_6

    .line 63
    .line 64
    const-wide/16 v13, 0xff

    .line 65
    .line 66
    and-long/2addr v13, v8

    .line 67
    const-wide/16 v15, 0x80

    .line 68
    .line 69
    cmp-long v13, v13, v15

    .line 70
    .line 71
    if-gez v13, :cond_5

    .line 72
    .line 73
    shl-int/lit8 v13, v7, 0x3

    .line 74
    .line 75
    add-int/2addr v13, v12

    .line 76
    aget-object v14, v3, v13

    .line 77
    .line 78
    aget-object v13, v5, v13

    .line 79
    .line 80
    if-nez v13, :cond_4

    .line 81
    .line 82
    invoke-virtual {v1, v14}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v13

    .line 86
    if-nez v13, :cond_3

    .line 87
    .line 88
    invoke-virtual {v1, v14}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    move-result v13

    .line 92
    if-nez v13, :cond_5

    .line 93
    .line 94
    :cond_3
    return v4

    .line 95
    :cond_4
    invoke-virtual {v1, v14}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v14

    .line 99
    invoke-virtual {v13, v14}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 100
    .line 101
    .line 102
    move-result v13

    .line 103
    if-nez v13, :cond_5

    .line 104
    .line 105
    return v4

    .line 106
    :cond_5
    shr-long/2addr v8, v11

    .line 107
    add-int/lit8 v12, v12, 0x1

    .line 108
    .line 109
    goto :goto_1

    .line 110
    :cond_6
    if-ne v10, v11, :cond_8

    .line 111
    .line 112
    :cond_7
    if-eq v7, v6, :cond_8

    .line 113
    .line 114
    add-int/lit8 v7, v7, 0x1

    .line 115
    .line 116
    goto :goto_0

    .line 117
    :cond_8
    return v2
.end method

.method public final f(Ljava/lang/Object;)I
    .locals 31

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 8
    .line 9
    .line 10
    move-result v3

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 v3, 0x0

    .line 13
    :goto_0
    const v4, -0x3361d2af    # -8.2930312E7f

    .line 14
    .line 15
    .line 16
    mul-int/2addr v3, v4

    .line 17
    shl-int/lit8 v5, v3, 0x10

    .line 18
    .line 19
    xor-int/2addr v3, v5

    .line 20
    ushr-int/lit8 v5, v3, 0x7

    .line 21
    .line 22
    and-int/lit8 v3, v3, 0x7f

    .line 23
    .line 24
    iget v6, v0, Landroidx/collection/q0;->d:I

    .line 25
    .line 26
    and-int v7, v5, v6

    .line 27
    .line 28
    const/4 v8, 0x0

    .line 29
    :goto_1
    iget-object v9, v0, Landroidx/collection/q0;->a:[J

    .line 30
    .line 31
    shr-int/lit8 v10, v7, 0x3

    .line 32
    .line 33
    and-int/lit8 v11, v7, 0x7

    .line 34
    .line 35
    shl-int/lit8 v11, v11, 0x3

    .line 36
    .line 37
    aget-wide v12, v9, v10

    .line 38
    .line 39
    ushr-long/2addr v12, v11

    .line 40
    const/4 v14, 0x1

    .line 41
    add-int/2addr v10, v14

    .line 42
    aget-wide v9, v9, v10

    .line 43
    .line 44
    rsub-int/lit8 v15, v11, 0x40

    .line 45
    .line 46
    shl-long/2addr v9, v15

    .line 47
    move/from16 v16, v14

    .line 48
    .line 49
    int-to-long v14, v11

    .line 50
    neg-long v14, v14

    .line 51
    const/16 v11, 0x3f

    .line 52
    .line 53
    shr-long/2addr v14, v11

    .line 54
    and-long/2addr v9, v14

    .line 55
    or-long/2addr v9, v12

    .line 56
    int-to-long v11, v3

    .line 57
    const-wide v13, 0x101010101010101L

    .line 58
    .line 59
    .line 60
    .line 61
    .line 62
    mul-long v17, v11, v13

    .line 63
    .line 64
    move/from16 v19, v3

    .line 65
    .line 66
    const/4 v15, 0x0

    .line 67
    xor-long v2, v9, v17

    .line 68
    .line 69
    sub-long v13, v2, v13

    .line 70
    .line 71
    not-long v2, v2

    .line 72
    and-long/2addr v2, v13

    .line 73
    const-wide v13, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 74
    .line 75
    .line 76
    .line 77
    .line 78
    and-long/2addr v2, v13

    .line 79
    :goto_2
    const-wide/16 v17, 0x0

    .line 80
    .line 81
    cmp-long v20, v2, v17

    .line 82
    .line 83
    if-eqz v20, :cond_2

    .line 84
    .line 85
    invoke-static {v2, v3}, Ljava/lang/Long;->numberOfTrailingZeros(J)I

    .line 86
    .line 87
    .line 88
    move-result v17

    .line 89
    shr-int/lit8 v17, v17, 0x3

    .line 90
    .line 91
    add-int v17, v7, v17

    .line 92
    .line 93
    and-int v17, v17, v6

    .line 94
    .line 95
    move/from16 v20, v4

    .line 96
    .line 97
    iget-object v4, v0, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 98
    .line 99
    aget-object v4, v4, v17

    .line 100
    .line 101
    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    move-result v4

    .line 105
    if-eqz v4, :cond_1

    .line 106
    .line 107
    return v17

    .line 108
    :cond_1
    const-wide/16 v17, 0x1

    .line 109
    .line 110
    sub-long v17, v2, v17

    .line 111
    .line 112
    and-long v2, v2, v17

    .line 113
    .line 114
    move/from16 v4, v20

    .line 115
    .line 116
    goto :goto_2

    .line 117
    :cond_2
    move/from16 v20, v4

    .line 118
    .line 119
    not-long v2, v9

    .line 120
    const/4 v4, 0x6

    .line 121
    shl-long/2addr v2, v4

    .line 122
    and-long/2addr v2, v9

    .line 123
    and-long/2addr v2, v13

    .line 124
    cmp-long v2, v2, v17

    .line 125
    .line 126
    const/16 v3, 0x8

    .line 127
    .line 128
    if-eqz v2, :cond_12

    .line 129
    .line 130
    invoke-virtual {v0, v5}, Landroidx/collection/q0;->e(I)I

    .line 131
    .line 132
    .line 133
    move-result v1

    .line 134
    iget v2, v0, Landroidx/collection/q0;->f:I

    .line 135
    .line 136
    const-wide/16 v8, 0xff

    .line 137
    .line 138
    if-nez v2, :cond_3

    .line 139
    .line 140
    iget-object v2, v0, Landroidx/collection/q0;->a:[J

    .line 141
    .line 142
    shr-int/lit8 v10, v1, 0x3

    .line 143
    .line 144
    aget-wide v17, v2, v10

    .line 145
    .line 146
    and-int/lit8 v2, v1, 0x7

    .line 147
    .line 148
    shl-int/lit8 v2, v2, 0x3

    .line 149
    .line 150
    shr-long v17, v17, v2

    .line 151
    .line 152
    and-long v17, v17, v8

    .line 153
    .line 154
    const-wide/16 v21, 0xfe

    .line 155
    .line 156
    cmp-long v2, v17, v21

    .line 157
    .line 158
    if-nez v2, :cond_4

    .line 159
    .line 160
    :cond_3
    move-wide/from16 v25, v8

    .line 161
    .line 162
    move-wide/from16 v23, v11

    .line 163
    .line 164
    const/16 p1, 0x7

    .line 165
    .line 166
    const-wide/16 v18, 0x80

    .line 167
    .line 168
    goto/16 :goto_e

    .line 169
    .line 170
    :cond_4
    iget v1, v0, Landroidx/collection/q0;->d:I

    .line 171
    .line 172
    if-le v1, v3, :cond_d

    .line 173
    .line 174
    iget v2, v0, Landroidx/collection/q0;->e:I

    .line 175
    .line 176
    move v10, v3

    .line 177
    const/16 p1, 0x7

    .line 178
    .line 179
    int-to-long v3, v2

    .line 180
    const-wide/16 v17, 0x20

    .line 181
    .line 182
    mul-long v3, v3, v17

    .line 183
    .line 184
    int-to-long v1, v1

    .line 185
    const-wide/16 v17, 0x19

    .line 186
    .line 187
    mul-long v1, v1, v17

    .line 188
    .line 189
    invoke-static {v3, v4, v1, v2}, Ljava/lang/Long;->compareUnsigned(JJ)I

    .line 190
    .line 191
    .line 192
    move-result v1

    .line 193
    if-gtz v1, :cond_c

    .line 194
    .line 195
    iget-object v1, v0, Landroidx/collection/q0;->a:[J

    .line 196
    .line 197
    iget v2, v0, Landroidx/collection/q0;->d:I

    .line 198
    .line 199
    iget-object v3, v0, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 200
    .line 201
    iget-object v4, v0, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 202
    .line 203
    add-int/lit8 v17, v2, 0x7

    .line 204
    .line 205
    const-wide/16 v18, 0x80

    .line 206
    .line 207
    shr-int/lit8 v6, v17, 0x3

    .line 208
    .line 209
    move v7, v15

    .line 210
    :goto_3
    if-ge v7, v6, :cond_5

    .line 211
    .line 212
    aget-wide v23, v1, v7

    .line 213
    .line 214
    move-wide/from16 v25, v8

    .line 215
    .line 216
    and-long v8, v23, v13

    .line 217
    .line 218
    move-wide/from16 v23, v11

    .line 219
    .line 220
    move v12, v10

    .line 221
    not-long v10, v8

    .line 222
    ushr-long v8, v8, p1

    .line 223
    .line 224
    add-long/2addr v10, v8

    .line 225
    const-wide v8, -0x101010101010102L

    .line 226
    .line 227
    .line 228
    .line 229
    .line 230
    and-long/2addr v8, v10

    .line 231
    aput-wide v8, v1, v7

    .line 232
    .line 233
    add-int/lit8 v7, v7, 0x1

    .line 234
    .line 235
    move v10, v12

    .line 236
    move-wide/from16 v11, v23

    .line 237
    .line 238
    move-wide/from16 v8, v25

    .line 239
    .line 240
    goto :goto_3

    .line 241
    :cond_5
    move-wide/from16 v25, v8

    .line 242
    .line 243
    move-wide/from16 v23, v11

    .line 244
    .line 245
    move v12, v10

    .line 246
    invoke-static {v1}, Lmx0/n;->A([J)I

    .line 247
    .line 248
    .line 249
    move-result v6

    .line 250
    add-int/lit8 v7, v6, -0x1

    .line 251
    .line 252
    aget-wide v8, v1, v7

    .line 253
    .line 254
    const-wide v10, 0xffffffffffffffL

    .line 255
    .line 256
    .line 257
    .line 258
    .line 259
    and-long/2addr v8, v10

    .line 260
    const-wide/high16 v10, -0x100000000000000L

    .line 261
    .line 262
    or-long/2addr v8, v10

    .line 263
    aput-wide v8, v1, v7

    .line 264
    .line 265
    aget-wide v7, v1, v15

    .line 266
    .line 267
    aput-wide v7, v1, v6

    .line 268
    .line 269
    move v6, v15

    .line 270
    :goto_4
    if-eq v6, v2, :cond_b

    .line 271
    .line 272
    shr-int/lit8 v7, v6, 0x3

    .line 273
    .line 274
    aget-wide v8, v1, v7

    .line 275
    .line 276
    and-int/lit8 v10, v6, 0x7

    .line 277
    .line 278
    shl-int/lit8 v10, v10, 0x3

    .line 279
    .line 280
    shr-long/2addr v8, v10

    .line 281
    and-long v8, v8, v25

    .line 282
    .line 283
    cmp-long v11, v8, v18

    .line 284
    .line 285
    if-nez v11, :cond_6

    .line 286
    .line 287
    :goto_5
    add-int/lit8 v6, v6, 0x1

    .line 288
    .line 289
    goto :goto_4

    .line 290
    :cond_6
    cmp-long v8, v8, v21

    .line 291
    .line 292
    if-eqz v8, :cond_7

    .line 293
    .line 294
    goto :goto_5

    .line 295
    :cond_7
    aget-object v8, v3, v6

    .line 296
    .line 297
    if-eqz v8, :cond_8

    .line 298
    .line 299
    invoke-virtual {v8}, Ljava/lang/Object;->hashCode()I

    .line 300
    .line 301
    .line 302
    move-result v8

    .line 303
    goto :goto_6

    .line 304
    :cond_8
    move v8, v15

    .line 305
    :goto_6
    mul-int v8, v8, v20

    .line 306
    .line 307
    shl-int/lit8 v9, v8, 0x10

    .line 308
    .line 309
    xor-int/2addr v8, v9

    .line 310
    ushr-int/lit8 v9, v8, 0x7

    .line 311
    .line 312
    invoke-virtual {v0, v9}, Landroidx/collection/q0;->e(I)I

    .line 313
    .line 314
    .line 315
    move-result v11

    .line 316
    and-int/2addr v9, v2

    .line 317
    sub-int v13, v11, v9

    .line 318
    .line 319
    and-int/2addr v13, v2

    .line 320
    div-int/2addr v13, v12

    .line 321
    sub-int v9, v6, v9

    .line 322
    .line 323
    and-int/2addr v9, v2

    .line 324
    div-int/2addr v9, v12

    .line 325
    if-ne v13, v9, :cond_9

    .line 326
    .line 327
    and-int/lit8 v8, v8, 0x7f

    .line 328
    .line 329
    int-to-long v8, v8

    .line 330
    aget-wide v13, v1, v7

    .line 331
    .line 332
    move/from16 v17, v12

    .line 333
    .line 334
    move-wide/from16 v27, v13

    .line 335
    .line 336
    shl-long v12, v25, v10

    .line 337
    .line 338
    not-long v11, v12

    .line 339
    and-long v11, v27, v11

    .line 340
    .line 341
    shl-long/2addr v8, v10

    .line 342
    or-long/2addr v8, v11

    .line 343
    aput-wide v8, v1, v7

    .line 344
    .line 345
    array-length v7, v1

    .line 346
    add-int/lit8 v7, v7, -0x1

    .line 347
    .line 348
    aget-wide v8, v1, v15

    .line 349
    .line 350
    aput-wide v8, v1, v7

    .line 351
    .line 352
    add-int/lit8 v6, v6, 0x1

    .line 353
    .line 354
    move/from16 v12, v17

    .line 355
    .line 356
    goto :goto_4

    .line 357
    :cond_9
    move/from16 v17, v12

    .line 358
    .line 359
    shr-int/lit8 v9, v11, 0x3

    .line 360
    .line 361
    aget-wide v12, v1, v9

    .line 362
    .line 363
    and-int/lit8 v14, v11, 0x7

    .line 364
    .line 365
    shl-int/lit8 v14, v14, 0x3

    .line 366
    .line 367
    shr-long v27, v12, v14

    .line 368
    .line 369
    and-long v27, v27, v25

    .line 370
    .line 371
    cmp-long v27, v27, v18

    .line 372
    .line 373
    if-nez v27, :cond_a

    .line 374
    .line 375
    and-int/lit8 v8, v8, 0x7f

    .line 376
    .line 377
    move/from16 v27, v2

    .line 378
    .line 379
    move-object/from16 v28, v3

    .line 380
    .line 381
    int-to-long v2, v8

    .line 382
    move-wide/from16 v29, v2

    .line 383
    .line 384
    shl-long v2, v25, v14

    .line 385
    .line 386
    not-long v2, v2

    .line 387
    and-long/2addr v2, v12

    .line 388
    shl-long v12, v29, v14

    .line 389
    .line 390
    or-long/2addr v2, v12

    .line 391
    aput-wide v2, v1, v9

    .line 392
    .line 393
    aget-wide v2, v1, v7

    .line 394
    .line 395
    shl-long v8, v25, v10

    .line 396
    .line 397
    not-long v8, v8

    .line 398
    and-long/2addr v2, v8

    .line 399
    shl-long v8, v18, v10

    .line 400
    .line 401
    or-long/2addr v2, v8

    .line 402
    aput-wide v2, v1, v7

    .line 403
    .line 404
    aget-object v2, v28, v6

    .line 405
    .line 406
    aput-object v2, v28, v11

    .line 407
    .line 408
    const/4 v2, 0x0

    .line 409
    aput-object v2, v28, v6

    .line 410
    .line 411
    aget-object v3, v4, v6

    .line 412
    .line 413
    aput-object v3, v4, v11

    .line 414
    .line 415
    aput-object v2, v4, v6

    .line 416
    .line 417
    goto :goto_7

    .line 418
    :cond_a
    move/from16 v27, v2

    .line 419
    .line 420
    move-object/from16 v28, v3

    .line 421
    .line 422
    and-int/lit8 v2, v8, 0x7f

    .line 423
    .line 424
    int-to-long v2, v2

    .line 425
    shl-long v7, v25, v14

    .line 426
    .line 427
    not-long v7, v7

    .line 428
    and-long/2addr v7, v12

    .line 429
    shl-long/2addr v2, v14

    .line 430
    or-long/2addr v2, v7

    .line 431
    aput-wide v2, v1, v9

    .line 432
    .line 433
    aget-object v2, v28, v11

    .line 434
    .line 435
    aget-object v3, v28, v6

    .line 436
    .line 437
    aput-object v3, v28, v11

    .line 438
    .line 439
    aput-object v2, v28, v6

    .line 440
    .line 441
    aget-object v2, v4, v11

    .line 442
    .line 443
    aget-object v3, v4, v6

    .line 444
    .line 445
    aput-object v3, v4, v11

    .line 446
    .line 447
    aput-object v2, v4, v6

    .line 448
    .line 449
    add-int/lit8 v6, v6, -0x1

    .line 450
    .line 451
    :goto_7
    array-length v2, v1

    .line 452
    add-int/lit8 v2, v2, -0x1

    .line 453
    .line 454
    aget-wide v7, v1, v15

    .line 455
    .line 456
    aput-wide v7, v1, v2

    .line 457
    .line 458
    add-int/lit8 v6, v6, 0x1

    .line 459
    .line 460
    move/from16 v12, v17

    .line 461
    .line 462
    move/from16 v2, v27

    .line 463
    .line 464
    move-object/from16 v3, v28

    .line 465
    .line 466
    goto/16 :goto_4

    .line 467
    .line 468
    :cond_b
    iget v1, v0, Landroidx/collection/q0;->d:I

    .line 469
    .line 470
    invoke-static {v1}, Landroidx/collection/y0;->a(I)I

    .line 471
    .line 472
    .line 473
    move-result v1

    .line 474
    iget v2, v0, Landroidx/collection/q0;->e:I

    .line 475
    .line 476
    sub-int/2addr v1, v2

    .line 477
    iput v1, v0, Landroidx/collection/q0;->f:I

    .line 478
    .line 479
    goto/16 :goto_d

    .line 480
    .line 481
    :cond_c
    :goto_8
    move-wide/from16 v25, v8

    .line 482
    .line 483
    move-wide/from16 v23, v11

    .line 484
    .line 485
    const-wide/16 v18, 0x80

    .line 486
    .line 487
    goto :goto_9

    .line 488
    :cond_d
    const/16 p1, 0x7

    .line 489
    .line 490
    goto :goto_8

    .line 491
    :goto_9
    iget v1, v0, Landroidx/collection/q0;->d:I

    .line 492
    .line 493
    invoke-static {v1}, Landroidx/collection/y0;->b(I)I

    .line 494
    .line 495
    .line 496
    move-result v1

    .line 497
    iget-object v2, v0, Landroidx/collection/q0;->a:[J

    .line 498
    .line 499
    iget-object v3, v0, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 500
    .line 501
    iget-object v4, v0, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 502
    .line 503
    iget v6, v0, Landroidx/collection/q0;->d:I

    .line 504
    .line 505
    invoke-virtual {v0, v1}, Landroidx/collection/q0;->h(I)V

    .line 506
    .line 507
    .line 508
    iget-object v1, v0, Landroidx/collection/q0;->a:[J

    .line 509
    .line 510
    iget-object v7, v0, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 511
    .line 512
    iget-object v8, v0, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 513
    .line 514
    iget v9, v0, Landroidx/collection/q0;->d:I

    .line 515
    .line 516
    move v10, v15

    .line 517
    :goto_a
    if-ge v10, v6, :cond_10

    .line 518
    .line 519
    shr-int/lit8 v11, v10, 0x3

    .line 520
    .line 521
    aget-wide v11, v2, v11

    .line 522
    .line 523
    and-int/lit8 v13, v10, 0x7

    .line 524
    .line 525
    shl-int/lit8 v13, v13, 0x3

    .line 526
    .line 527
    shr-long/2addr v11, v13

    .line 528
    and-long v11, v11, v25

    .line 529
    .line 530
    cmp-long v11, v11, v18

    .line 531
    .line 532
    if-gez v11, :cond_f

    .line 533
    .line 534
    aget-object v11, v3, v10

    .line 535
    .line 536
    if-eqz v11, :cond_e

    .line 537
    .line 538
    invoke-virtual {v11}, Ljava/lang/Object;->hashCode()I

    .line 539
    .line 540
    .line 541
    move-result v12

    .line 542
    goto :goto_b

    .line 543
    :cond_e
    move v12, v15

    .line 544
    :goto_b
    mul-int v12, v12, v20

    .line 545
    .line 546
    shl-int/lit8 v13, v12, 0x10

    .line 547
    .line 548
    xor-int/2addr v12, v13

    .line 549
    ushr-int/lit8 v13, v12, 0x7

    .line 550
    .line 551
    invoke-virtual {v0, v13}, Landroidx/collection/q0;->e(I)I

    .line 552
    .line 553
    .line 554
    move-result v13

    .line 555
    and-int/lit8 v12, v12, 0x7f

    .line 556
    .line 557
    move-object/from16 v17, v1

    .line 558
    .line 559
    move-object v14, v2

    .line 560
    int-to-long v1, v12

    .line 561
    shr-int/lit8 v12, v13, 0x3

    .line 562
    .line 563
    and-int/lit8 v21, v13, 0x7

    .line 564
    .line 565
    shl-int/lit8 v21, v21, 0x3

    .line 566
    .line 567
    aget-wide v27, v17, v12

    .line 568
    .line 569
    move-wide/from16 v29, v1

    .line 570
    .line 571
    shl-long v1, v25, v21

    .line 572
    .line 573
    not-long v1, v1

    .line 574
    and-long v1, v27, v1

    .line 575
    .line 576
    shl-long v21, v29, v21

    .line 577
    .line 578
    or-long v1, v1, v21

    .line 579
    .line 580
    aput-wide v1, v17, v12

    .line 581
    .line 582
    add-int/lit8 v12, v13, -0x7

    .line 583
    .line 584
    and-int/2addr v12, v9

    .line 585
    and-int/lit8 v21, v9, 0x7

    .line 586
    .line 587
    add-int v12, v12, v21

    .line 588
    .line 589
    shr-int/lit8 v12, v12, 0x3

    .line 590
    .line 591
    aput-wide v1, v17, v12

    .line 592
    .line 593
    aput-object v11, v7, v13

    .line 594
    .line 595
    aget-object v1, v4, v10

    .line 596
    .line 597
    aput-object v1, v8, v13

    .line 598
    .line 599
    goto :goto_c

    .line 600
    :cond_f
    move-object/from16 v17, v1

    .line 601
    .line 602
    move-object v14, v2

    .line 603
    :goto_c
    add-int/lit8 v10, v10, 0x1

    .line 604
    .line 605
    move-object v2, v14

    .line 606
    move-object/from16 v1, v17

    .line 607
    .line 608
    goto :goto_a

    .line 609
    :cond_10
    :goto_d
    invoke-virtual {v0, v5}, Landroidx/collection/q0;->e(I)I

    .line 610
    .line 611
    .line 612
    move-result v1

    .line 613
    :goto_e
    iget v2, v0, Landroidx/collection/q0;->e:I

    .line 614
    .line 615
    add-int/lit8 v2, v2, 0x1

    .line 616
    .line 617
    iput v2, v0, Landroidx/collection/q0;->e:I

    .line 618
    .line 619
    iget v2, v0, Landroidx/collection/q0;->f:I

    .line 620
    .line 621
    iget-object v3, v0, Landroidx/collection/q0;->a:[J

    .line 622
    .line 623
    shr-int/lit8 v4, v1, 0x3

    .line 624
    .line 625
    aget-wide v5, v3, v4

    .line 626
    .line 627
    and-int/lit8 v7, v1, 0x7

    .line 628
    .line 629
    shl-int/lit8 v7, v7, 0x3

    .line 630
    .line 631
    shr-long v8, v5, v7

    .line 632
    .line 633
    and-long v8, v8, v25

    .line 634
    .line 635
    cmp-long v8, v8, v18

    .line 636
    .line 637
    if-nez v8, :cond_11

    .line 638
    .line 639
    move/from16 v15, v16

    .line 640
    .line 641
    :cond_11
    sub-int/2addr v2, v15

    .line 642
    iput v2, v0, Landroidx/collection/q0;->f:I

    .line 643
    .line 644
    iget v0, v0, Landroidx/collection/q0;->d:I

    .line 645
    .line 646
    shl-long v8, v25, v7

    .line 647
    .line 648
    not-long v8, v8

    .line 649
    and-long/2addr v5, v8

    .line 650
    shl-long v7, v23, v7

    .line 651
    .line 652
    or-long/2addr v5, v7

    .line 653
    aput-wide v5, v3, v4

    .line 654
    .line 655
    add-int/lit8 v2, v1, -0x7

    .line 656
    .line 657
    and-int/2addr v2, v0

    .line 658
    and-int/lit8 v0, v0, 0x7

    .line 659
    .line 660
    add-int/2addr v2, v0

    .line 661
    shr-int/lit8 v0, v2, 0x3

    .line 662
    .line 663
    aput-wide v5, v3, v0

    .line 664
    .line 665
    not-int v0, v1

    .line 666
    return v0

    .line 667
    :cond_12
    move/from16 v17, v3

    .line 668
    .line 669
    add-int/lit8 v8, v8, 0x8

    .line 670
    .line 671
    add-int/2addr v7, v8

    .line 672
    and-int/2addr v7, v6

    .line 673
    move/from16 v3, v19

    .line 674
    .line 675
    move/from16 v4, v20

    .line 676
    .line 677
    goto/16 :goto_1
.end method

.method public final g(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p1, :cond_0

    .line 3
    .line 4
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move v1, v0

    .line 10
    :goto_0
    const v2, -0x3361d2af    # -8.2930312E7f

    .line 11
    .line 12
    .line 13
    mul-int/2addr v1, v2

    .line 14
    shl-int/lit8 v2, v1, 0x10

    .line 15
    .line 16
    xor-int/2addr v1, v2

    .line 17
    and-int/lit8 v2, v1, 0x7f

    .line 18
    .line 19
    iget v3, p0, Landroidx/collection/q0;->d:I

    .line 20
    .line 21
    ushr-int/lit8 v1, v1, 0x7

    .line 22
    .line 23
    :goto_1
    and-int/2addr v1, v3

    .line 24
    iget-object v4, p0, Landroidx/collection/q0;->a:[J

    .line 25
    .line 26
    shr-int/lit8 v5, v1, 0x3

    .line 27
    .line 28
    and-int/lit8 v6, v1, 0x7

    .line 29
    .line 30
    shl-int/lit8 v6, v6, 0x3

    .line 31
    .line 32
    aget-wide v7, v4, v5

    .line 33
    .line 34
    ushr-long/2addr v7, v6

    .line 35
    add-int/lit8 v5, v5, 0x1

    .line 36
    .line 37
    aget-wide v4, v4, v5

    .line 38
    .line 39
    rsub-int/lit8 v9, v6, 0x40

    .line 40
    .line 41
    shl-long/2addr v4, v9

    .line 42
    int-to-long v9, v6

    .line 43
    neg-long v9, v9

    .line 44
    const/16 v6, 0x3f

    .line 45
    .line 46
    shr-long/2addr v9, v6

    .line 47
    and-long/2addr v4, v9

    .line 48
    or-long/2addr v4, v7

    .line 49
    int-to-long v6, v2

    .line 50
    const-wide v8, 0x101010101010101L

    .line 51
    .line 52
    .line 53
    .line 54
    .line 55
    mul-long/2addr v6, v8

    .line 56
    xor-long/2addr v6, v4

    .line 57
    sub-long v8, v6, v8

    .line 58
    .line 59
    not-long v6, v6

    .line 60
    and-long/2addr v6, v8

    .line 61
    const-wide v8, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 62
    .line 63
    .line 64
    .line 65
    .line 66
    and-long/2addr v6, v8

    .line 67
    :goto_2
    const-wide/16 v10, 0x0

    .line 68
    .line 69
    cmp-long v12, v6, v10

    .line 70
    .line 71
    if-eqz v12, :cond_2

    .line 72
    .line 73
    invoke-static {v6, v7}, Ljava/lang/Long;->numberOfTrailingZeros(J)I

    .line 74
    .line 75
    .line 76
    move-result v10

    .line 77
    shr-int/lit8 v10, v10, 0x3

    .line 78
    .line 79
    add-int/2addr v10, v1

    .line 80
    and-int/2addr v10, v3

    .line 81
    iget-object v11, p0, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 82
    .line 83
    aget-object v11, v11, v10

    .line 84
    .line 85
    invoke-static {v11, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v11

    .line 89
    if-eqz v11, :cond_1

    .line 90
    .line 91
    goto :goto_3

    .line 92
    :cond_1
    const-wide/16 v10, 0x1

    .line 93
    .line 94
    sub-long v10, v6, v10

    .line 95
    .line 96
    and-long/2addr v6, v10

    .line 97
    goto :goto_2

    .line 98
    :cond_2
    not-long v6, v4

    .line 99
    const/4 v12, 0x6

    .line 100
    shl-long/2addr v6, v12

    .line 101
    and-long/2addr v4, v6

    .line 102
    and-long/2addr v4, v8

    .line 103
    cmp-long v4, v4, v10

    .line 104
    .line 105
    if-eqz v4, :cond_4

    .line 106
    .line 107
    const/4 v10, -0x1

    .line 108
    :goto_3
    if-ltz v10, :cond_3

    .line 109
    .line 110
    iget-object p0, p0, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 111
    .line 112
    aget-object p0, p0, v10

    .line 113
    .line 114
    return-object p0

    .line 115
    :cond_3
    const/4 p0, 0x0

    .line 116
    return-object p0

    .line 117
    :cond_4
    add-int/lit8 v0, v0, 0x8

    .line 118
    .line 119
    add-int/2addr v1, v0

    .line 120
    goto :goto_1
.end method

.method public final h(I)V
    .locals 9

    .line 1
    if-lez p1, :cond_0

    .line 2
    .line 3
    invoke-static {p1}, Landroidx/collection/y0;->c(I)I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    const/4 v0, 0x7

    .line 8
    invoke-static {v0, p1}, Ljava/lang/Math;->max(II)I

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 p1, 0x0

    .line 14
    :goto_0
    iput p1, p0, Landroidx/collection/q0;->d:I

    .line 15
    .line 16
    if-nez p1, :cond_1

    .line 17
    .line 18
    sget-object v0, Landroidx/collection/y0;->a:[J

    .line 19
    .line 20
    goto :goto_1

    .line 21
    :cond_1
    add-int/lit8 v0, p1, 0xf

    .line 22
    .line 23
    and-int/lit8 v0, v0, -0x8

    .line 24
    .line 25
    shr-int/lit8 v0, v0, 0x3

    .line 26
    .line 27
    new-array v0, v0, [J

    .line 28
    .line 29
    const-wide v1, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 30
    .line 31
    .line 32
    .line 33
    .line 34
    invoke-static {v1, v2, v0}, Lmx0/n;->r(J[J)V

    .line 35
    .line 36
    .line 37
    shr-int/lit8 v1, p1, 0x3

    .line 38
    .line 39
    and-int/lit8 v2, p1, 0x7

    .line 40
    .line 41
    shl-int/lit8 v2, v2, 0x3

    .line 42
    .line 43
    aget-wide v3, v0, v1

    .line 44
    .line 45
    const-wide/16 v5, 0xff

    .line 46
    .line 47
    shl-long/2addr v5, v2

    .line 48
    not-long v7, v5

    .line 49
    and-long v2, v3, v7

    .line 50
    .line 51
    or-long/2addr v2, v5

    .line 52
    aput-wide v2, v0, v1

    .line 53
    .line 54
    :goto_1
    iput-object v0, p0, Landroidx/collection/q0;->a:[J

    .line 55
    .line 56
    iget v0, p0, Landroidx/collection/q0;->d:I

    .line 57
    .line 58
    invoke-static {v0}, Landroidx/collection/y0;->a(I)I

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    iget v1, p0, Landroidx/collection/q0;->e:I

    .line 63
    .line 64
    sub-int/2addr v0, v1

    .line 65
    iput v0, p0, Landroidx/collection/q0;->f:I

    .line 66
    .line 67
    sget-object v0, La1/a;->c:[Ljava/lang/Object;

    .line 68
    .line 69
    if-nez p1, :cond_2

    .line 70
    .line 71
    move-object v1, v0

    .line 72
    goto :goto_2

    .line 73
    :cond_2
    new-array v1, p1, [Ljava/lang/Object;

    .line 74
    .line 75
    :goto_2
    iput-object v1, p0, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 76
    .line 77
    if-nez p1, :cond_3

    .line 78
    .line 79
    goto :goto_3

    .line 80
    :cond_3
    new-array v0, p1, [Ljava/lang/Object;

    .line 81
    .line 82
    :goto_3
    iput-object v0, p0, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 83
    .line 84
    return-void
.end method

.method public final hashCode()I
    .locals 15

    .line 1
    iget-object v0, p0, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 2
    .line 3
    iget-object v1, p0, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 4
    .line 5
    iget-object p0, p0, Landroidx/collection/q0;->a:[J

    .line 6
    .line 7
    array-length v2, p0

    .line 8
    add-int/lit8 v2, v2, -0x2

    .line 9
    .line 10
    const/4 v3, 0x0

    .line 11
    if-ltz v2, :cond_7

    .line 12
    .line 13
    move v4, v3

    .line 14
    move v5, v4

    .line 15
    :goto_0
    aget-wide v6, p0, v4

    .line 16
    .line 17
    not-long v8, v6

    .line 18
    const/4 v10, 0x7

    .line 19
    shl-long/2addr v8, v10

    .line 20
    and-long/2addr v8, v6

    .line 21
    const-wide v10, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 22
    .line 23
    .line 24
    .line 25
    .line 26
    and-long/2addr v8, v10

    .line 27
    cmp-long v8, v8, v10

    .line 28
    .line 29
    if-eqz v8, :cond_5

    .line 30
    .line 31
    sub-int v8, v4, v2

    .line 32
    .line 33
    not-int v8, v8

    .line 34
    ushr-int/lit8 v8, v8, 0x1f

    .line 35
    .line 36
    const/16 v9, 0x8

    .line 37
    .line 38
    rsub-int/lit8 v8, v8, 0x8

    .line 39
    .line 40
    move v10, v3

    .line 41
    :goto_1
    if-ge v10, v8, :cond_3

    .line 42
    .line 43
    const-wide/16 v11, 0xff

    .line 44
    .line 45
    and-long/2addr v11, v6

    .line 46
    const-wide/16 v13, 0x80

    .line 47
    .line 48
    cmp-long v11, v11, v13

    .line 49
    .line 50
    if-gez v11, :cond_2

    .line 51
    .line 52
    shl-int/lit8 v11, v4, 0x3

    .line 53
    .line 54
    add-int/2addr v11, v10

    .line 55
    aget-object v12, v0, v11

    .line 56
    .line 57
    aget-object v11, v1, v11

    .line 58
    .line 59
    if-eqz v12, :cond_0

    .line 60
    .line 61
    invoke-virtual {v12}, Ljava/lang/Object;->hashCode()I

    .line 62
    .line 63
    .line 64
    move-result v12

    .line 65
    goto :goto_2

    .line 66
    :cond_0
    move v12, v3

    .line 67
    :goto_2
    if-eqz v11, :cond_1

    .line 68
    .line 69
    invoke-virtual {v11}, Ljava/lang/Object;->hashCode()I

    .line 70
    .line 71
    .line 72
    move-result v11

    .line 73
    goto :goto_3

    .line 74
    :cond_1
    move v11, v3

    .line 75
    :goto_3
    xor-int/2addr v11, v12

    .line 76
    add-int/2addr v5, v11

    .line 77
    :cond_2
    shr-long/2addr v6, v9

    .line 78
    add-int/lit8 v10, v10, 0x1

    .line 79
    .line 80
    goto :goto_1

    .line 81
    :cond_3
    if-ne v8, v9, :cond_4

    .line 82
    .line 83
    goto :goto_4

    .line 84
    :cond_4
    return v5

    .line 85
    :cond_5
    :goto_4
    if-eq v4, v2, :cond_6

    .line 86
    .line 87
    add-int/lit8 v4, v4, 0x1

    .line 88
    .line 89
    goto :goto_0

    .line 90
    :cond_6
    return v5

    .line 91
    :cond_7
    return v3
.end method

.method public final i()Z
    .locals 0

    .line 1
    iget p0, p0, Landroidx/collection/q0;->e:I

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public final j()Z
    .locals 0

    .line 1
    iget p0, p0, Landroidx/collection/q0;->e:I

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public final k(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p1, :cond_0

    .line 3
    .line 4
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move v1, v0

    .line 10
    :goto_0
    const v2, -0x3361d2af    # -8.2930312E7f

    .line 11
    .line 12
    .line 13
    mul-int/2addr v1, v2

    .line 14
    shl-int/lit8 v2, v1, 0x10

    .line 15
    .line 16
    xor-int/2addr v1, v2

    .line 17
    and-int/lit8 v2, v1, 0x7f

    .line 18
    .line 19
    iget v3, p0, Landroidx/collection/q0;->d:I

    .line 20
    .line 21
    ushr-int/lit8 v1, v1, 0x7

    .line 22
    .line 23
    :goto_1
    and-int/2addr v1, v3

    .line 24
    iget-object v4, p0, Landroidx/collection/q0;->a:[J

    .line 25
    .line 26
    shr-int/lit8 v5, v1, 0x3

    .line 27
    .line 28
    and-int/lit8 v6, v1, 0x7

    .line 29
    .line 30
    shl-int/lit8 v6, v6, 0x3

    .line 31
    .line 32
    aget-wide v7, v4, v5

    .line 33
    .line 34
    ushr-long/2addr v7, v6

    .line 35
    add-int/lit8 v5, v5, 0x1

    .line 36
    .line 37
    aget-wide v4, v4, v5

    .line 38
    .line 39
    rsub-int/lit8 v9, v6, 0x40

    .line 40
    .line 41
    shl-long/2addr v4, v9

    .line 42
    int-to-long v9, v6

    .line 43
    neg-long v9, v9

    .line 44
    const/16 v6, 0x3f

    .line 45
    .line 46
    shr-long/2addr v9, v6

    .line 47
    and-long/2addr v4, v9

    .line 48
    or-long/2addr v4, v7

    .line 49
    int-to-long v6, v2

    .line 50
    const-wide v8, 0x101010101010101L

    .line 51
    .line 52
    .line 53
    .line 54
    .line 55
    mul-long/2addr v6, v8

    .line 56
    xor-long/2addr v6, v4

    .line 57
    sub-long v8, v6, v8

    .line 58
    .line 59
    not-long v6, v6

    .line 60
    and-long/2addr v6, v8

    .line 61
    const-wide v8, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 62
    .line 63
    .line 64
    .line 65
    .line 66
    and-long/2addr v6, v8

    .line 67
    :goto_2
    const-wide/16 v10, 0x0

    .line 68
    .line 69
    cmp-long v12, v6, v10

    .line 70
    .line 71
    if-eqz v12, :cond_2

    .line 72
    .line 73
    invoke-static {v6, v7}, Ljava/lang/Long;->numberOfTrailingZeros(J)I

    .line 74
    .line 75
    .line 76
    move-result v10

    .line 77
    shr-int/lit8 v10, v10, 0x3

    .line 78
    .line 79
    add-int/2addr v10, v1

    .line 80
    and-int/2addr v10, v3

    .line 81
    iget-object v11, p0, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 82
    .line 83
    aget-object v11, v11, v10

    .line 84
    .line 85
    invoke-static {v11, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v11

    .line 89
    if-eqz v11, :cond_1

    .line 90
    .line 91
    goto :goto_3

    .line 92
    :cond_1
    const-wide/16 v10, 0x1

    .line 93
    .line 94
    sub-long v10, v6, v10

    .line 95
    .line 96
    and-long/2addr v6, v10

    .line 97
    goto :goto_2

    .line 98
    :cond_2
    not-long v6, v4

    .line 99
    const/4 v12, 0x6

    .line 100
    shl-long/2addr v6, v12

    .line 101
    and-long/2addr v4, v6

    .line 102
    and-long/2addr v4, v8

    .line 103
    cmp-long v4, v4, v10

    .line 104
    .line 105
    if-eqz v4, :cond_4

    .line 106
    .line 107
    const/4 v10, -0x1

    .line 108
    :goto_3
    if-ltz v10, :cond_3

    .line 109
    .line 110
    invoke-virtual {p0, v10}, Landroidx/collection/q0;->l(I)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    return-object p0

    .line 115
    :cond_3
    const/4 p0, 0x0

    .line 116
    return-object p0

    .line 117
    :cond_4
    add-int/lit8 v0, v0, 0x8

    .line 118
    .line 119
    add-int/2addr v1, v0

    .line 120
    goto :goto_1
.end method

.method public final l(I)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Landroidx/collection/q0;->e:I

    .line 2
    .line 3
    add-int/lit8 v0, v0, -0x1

    .line 4
    .line 5
    iput v0, p0, Landroidx/collection/q0;->e:I

    .line 6
    .line 7
    iget-object v0, p0, Landroidx/collection/q0;->a:[J

    .line 8
    .line 9
    iget v1, p0, Landroidx/collection/q0;->d:I

    .line 10
    .line 11
    shr-int/lit8 v2, p1, 0x3

    .line 12
    .line 13
    and-int/lit8 v3, p1, 0x7

    .line 14
    .line 15
    shl-int/lit8 v3, v3, 0x3

    .line 16
    .line 17
    aget-wide v4, v0, v2

    .line 18
    .line 19
    const-wide/16 v6, 0xff

    .line 20
    .line 21
    shl-long/2addr v6, v3

    .line 22
    not-long v6, v6

    .line 23
    and-long/2addr v4, v6

    .line 24
    const-wide/16 v6, 0xfe

    .line 25
    .line 26
    shl-long/2addr v6, v3

    .line 27
    or-long v3, v4, v6

    .line 28
    .line 29
    aput-wide v3, v0, v2

    .line 30
    .line 31
    add-int/lit8 v2, p1, -0x7

    .line 32
    .line 33
    and-int/2addr v2, v1

    .line 34
    and-int/lit8 v1, v1, 0x7

    .line 35
    .line 36
    add-int/2addr v2, v1

    .line 37
    shr-int/lit8 v1, v2, 0x3

    .line 38
    .line 39
    aput-wide v3, v0, v1

    .line 40
    .line 41
    iget-object v0, p0, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 42
    .line 43
    const/4 v1, 0x0

    .line 44
    aput-object v1, v0, p1

    .line 45
    .line 46
    iget-object p0, p0, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 47
    .line 48
    aget-object v0, p0, p1

    .line 49
    .line 50
    aput-object v1, p0, p1

    .line 51
    .line 52
    return-object v0
.end method

.method public final m(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 2

    .line 1
    invoke-virtual {p0, p1}, Landroidx/collection/q0;->f(Ljava/lang/Object;)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-gez v0, :cond_0

    .line 6
    .line 7
    not-int v0, v0

    .line 8
    :cond_0
    iget-object v1, p0, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 9
    .line 10
    aput-object p1, v1, v0

    .line 11
    .line 12
    iget-object p0, p0, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 13
    .line 14
    aput-object p2, p0, v0

    .line 15
    .line 16
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    invoke-virtual {v0}, Landroidx/collection/q0;->i()Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    const-string v0, "{}"

    .line 10
    .line 11
    return-object v0

    .line 12
    :cond_0
    new-instance v1, Ljava/lang/StringBuilder;

    .line 13
    .line 14
    const-string v2, "{"

    .line 15
    .line 16
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    iget-object v2, v0, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 20
    .line 21
    iget-object v3, v0, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 22
    .line 23
    iget-object v4, v0, Landroidx/collection/q0;->a:[J

    .line 24
    .line 25
    array-length v5, v4

    .line 26
    add-int/lit8 v5, v5, -0x2

    .line 27
    .line 28
    if-ltz v5, :cond_6

    .line 29
    .line 30
    const/4 v6, 0x0

    .line 31
    move v7, v6

    .line 32
    move v8, v7

    .line 33
    :goto_0
    aget-wide v9, v4, v7

    .line 34
    .line 35
    not-long v11, v9

    .line 36
    const/4 v13, 0x7

    .line 37
    shl-long/2addr v11, v13

    .line 38
    and-long/2addr v11, v9

    .line 39
    const-wide v13, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 40
    .line 41
    .line 42
    .line 43
    .line 44
    and-long/2addr v11, v13

    .line 45
    cmp-long v11, v11, v13

    .line 46
    .line 47
    if-eqz v11, :cond_5

    .line 48
    .line 49
    sub-int v11, v7, v5

    .line 50
    .line 51
    not-int v11, v11

    .line 52
    ushr-int/lit8 v11, v11, 0x1f

    .line 53
    .line 54
    const/16 v12, 0x8

    .line 55
    .line 56
    rsub-int/lit8 v11, v11, 0x8

    .line 57
    .line 58
    move v13, v6

    .line 59
    :goto_1
    if-ge v13, v11, :cond_4

    .line 60
    .line 61
    const-wide/16 v14, 0xff

    .line 62
    .line 63
    and-long/2addr v14, v9

    .line 64
    const-wide/16 v16, 0x80

    .line 65
    .line 66
    cmp-long v14, v14, v16

    .line 67
    .line 68
    if-gez v14, :cond_3

    .line 69
    .line 70
    shl-int/lit8 v14, v7, 0x3

    .line 71
    .line 72
    add-int/2addr v14, v13

    .line 73
    aget-object v15, v2, v14

    .line 74
    .line 75
    aget-object v14, v3, v14

    .line 76
    .line 77
    const-string v16, "(this)"

    .line 78
    .line 79
    if-ne v15, v0, :cond_1

    .line 80
    .line 81
    move-object/from16 v15, v16

    .line 82
    .line 83
    :cond_1
    invoke-virtual {v1, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    const-string v15, "="

    .line 87
    .line 88
    invoke-virtual {v1, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    if-ne v14, v0, :cond_2

    .line 92
    .line 93
    move-object/from16 v14, v16

    .line 94
    .line 95
    :cond_2
    invoke-virtual {v1, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    add-int/lit8 v8, v8, 0x1

    .line 99
    .line 100
    iget v14, v0, Landroidx/collection/q0;->e:I

    .line 101
    .line 102
    if-ge v8, v14, :cond_3

    .line 103
    .line 104
    const-string v14, ", "

    .line 105
    .line 106
    invoke-virtual {v1, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    :cond_3
    shr-long/2addr v9, v12

    .line 110
    add-int/lit8 v13, v13, 0x1

    .line 111
    .line 112
    goto :goto_1

    .line 113
    :cond_4
    if-ne v11, v12, :cond_6

    .line 114
    .line 115
    :cond_5
    if-eq v7, v5, :cond_6

    .line 116
    .line 117
    add-int/lit8 v7, v7, 0x1

    .line 118
    .line 119
    goto :goto_0

    .line 120
    :cond_6
    const/16 v0, 0x7d

    .line 121
    .line 122
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 123
    .line 124
    .line 125
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object v0

    .line 129
    const-string v1, "toString(...)"

    .line 130
    .line 131
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    return-object v0
.end method
