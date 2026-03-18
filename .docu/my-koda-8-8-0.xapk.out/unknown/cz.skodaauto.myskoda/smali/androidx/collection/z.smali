.class public final Landroidx/collection/z;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:[J

.field public b:[I

.field public c:[I

.field public d:I

.field public e:I

.field public f:I


# direct methods
.method public synthetic constructor <init>()V
    .locals 1

    const/4 v0, 0x6

    .line 9
    invoke-direct {p0, v0}, Landroidx/collection/z;-><init>(I)V

    return-void
.end method

.method public constructor <init>(I)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    sget-object v0, Landroidx/collection/y0;->a:[J

    iput-object v0, p0, Landroidx/collection/z;->a:[J

    .line 3
    sget-object v0, Landroidx/collection/r;->a:[I

    .line 4
    iput-object v0, p0, Landroidx/collection/z;->b:[I

    .line 5
    iput-object v0, p0, Landroidx/collection/z;->c:[I

    if-ltz p1, :cond_0

    .line 6
    invoke-static {p1}, Landroidx/collection/y0;->d(I)I

    move-result p1

    invoke-virtual {p0, p1}, Landroidx/collection/z;->e(I)V

    return-void

    .line 7
    :cond_0
    const-string p0, "Capacity must be a positive value."

    .line 8
    invoke-static {p0}, La1/a;->c(Ljava/lang/String;)V

    const/4 p0, 0x0

    throw p0
.end method


# virtual methods
.method public final a()V
    .locals 9

    .line 1
    const/4 v0, 0x0

    .line 2
    iput v0, p0, Landroidx/collection/z;->e:I

    .line 3
    .line 4
    iget-object v0, p0, Landroidx/collection/z;->a:[J

    .line 5
    .line 6
    sget-object v1, Landroidx/collection/y0;->a:[J

    .line 7
    .line 8
    if-eq v0, v1, :cond_0

    .line 9
    .line 10
    const-wide v1, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 11
    .line 12
    .line 13
    .line 14
    .line 15
    invoke-static {v1, v2, v0}, Lmx0/n;->r(J[J)V

    .line 16
    .line 17
    .line 18
    iget-object v0, p0, Landroidx/collection/z;->a:[J

    .line 19
    .line 20
    iget v1, p0, Landroidx/collection/z;->d:I

    .line 21
    .line 22
    shr-int/lit8 v2, v1, 0x3

    .line 23
    .line 24
    and-int/lit8 v1, v1, 0x7

    .line 25
    .line 26
    shl-int/lit8 v1, v1, 0x3

    .line 27
    .line 28
    aget-wide v3, v0, v2

    .line 29
    .line 30
    const-wide/16 v5, 0xff

    .line 31
    .line 32
    shl-long/2addr v5, v1

    .line 33
    not-long v7, v5

    .line 34
    and-long/2addr v3, v7

    .line 35
    or-long/2addr v3, v5

    .line 36
    aput-wide v3, v0, v2

    .line 37
    .line 38
    :cond_0
    iget v0, p0, Landroidx/collection/z;->d:I

    .line 39
    .line 40
    invoke-static {v0}, Landroidx/collection/y0;->a(I)I

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    iget v1, p0, Landroidx/collection/z;->e:I

    .line 45
    .line 46
    sub-int/2addr v0, v1

    .line 47
    iput v0, p0, Landroidx/collection/z;->f:I

    .line 48
    .line 49
    return-void
.end method

.method public final b(I)I
    .locals 9

    .line 1
    iget v0, p0, Landroidx/collection/z;->d:I

    .line 2
    .line 3
    and-int/2addr p1, v0

    .line 4
    const/4 v1, 0x0

    .line 5
    :goto_0
    iget-object v2, p0, Landroidx/collection/z;->a:[J

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

.method public final c(I)I
    .locals 13

    .line 1
    invoke-static {p1}, Ljava/lang/Integer;->hashCode(I)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const v1, -0x3361d2af    # -8.2930312E7f

    .line 6
    .line 7
    .line 8
    mul-int/2addr v0, v1

    .line 9
    shl-int/lit8 v1, v0, 0x10

    .line 10
    .line 11
    xor-int/2addr v0, v1

    .line 12
    and-int/lit8 v1, v0, 0x7f

    .line 13
    .line 14
    iget v2, p0, Landroidx/collection/z;->d:I

    .line 15
    .line 16
    ushr-int/lit8 v0, v0, 0x7

    .line 17
    .line 18
    and-int/2addr v0, v2

    .line 19
    const/4 v3, 0x0

    .line 20
    :goto_0
    iget-object v4, p0, Landroidx/collection/z;->a:[J

    .line 21
    .line 22
    shr-int/lit8 v5, v0, 0x3

    .line 23
    .line 24
    and-int/lit8 v6, v0, 0x7

    .line 25
    .line 26
    shl-int/lit8 v6, v6, 0x3

    .line 27
    .line 28
    aget-wide v7, v4, v5

    .line 29
    .line 30
    ushr-long/2addr v7, v6

    .line 31
    add-int/lit8 v5, v5, 0x1

    .line 32
    .line 33
    aget-wide v4, v4, v5

    .line 34
    .line 35
    rsub-int/lit8 v9, v6, 0x40

    .line 36
    .line 37
    shl-long/2addr v4, v9

    .line 38
    int-to-long v9, v6

    .line 39
    neg-long v9, v9

    .line 40
    const/16 v6, 0x3f

    .line 41
    .line 42
    shr-long/2addr v9, v6

    .line 43
    and-long/2addr v4, v9

    .line 44
    or-long/2addr v4, v7

    .line 45
    int-to-long v6, v1

    .line 46
    const-wide v8, 0x101010101010101L

    .line 47
    .line 48
    .line 49
    .line 50
    .line 51
    mul-long/2addr v6, v8

    .line 52
    xor-long/2addr v6, v4

    .line 53
    sub-long v8, v6, v8

    .line 54
    .line 55
    not-long v6, v6

    .line 56
    and-long/2addr v6, v8

    .line 57
    const-wide v8, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 58
    .line 59
    .line 60
    .line 61
    .line 62
    and-long/2addr v6, v8

    .line 63
    :goto_1
    const-wide/16 v10, 0x0

    .line 64
    .line 65
    cmp-long v12, v6, v10

    .line 66
    .line 67
    if-eqz v12, :cond_1

    .line 68
    .line 69
    invoke-static {v6, v7}, Ljava/lang/Long;->numberOfTrailingZeros(J)I

    .line 70
    .line 71
    .line 72
    move-result v10

    .line 73
    shr-int/lit8 v10, v10, 0x3

    .line 74
    .line 75
    add-int/2addr v10, v0

    .line 76
    and-int/2addr v10, v2

    .line 77
    iget-object v11, p0, Landroidx/collection/z;->b:[I

    .line 78
    .line 79
    aget v11, v11, v10

    .line 80
    .line 81
    if-ne v11, p1, :cond_0

    .line 82
    .line 83
    return v10

    .line 84
    :cond_0
    const-wide/16 v10, 0x1

    .line 85
    .line 86
    sub-long v10, v6, v10

    .line 87
    .line 88
    and-long/2addr v6, v10

    .line 89
    goto :goto_1

    .line 90
    :cond_1
    not-long v6, v4

    .line 91
    const/4 v12, 0x6

    .line 92
    shl-long/2addr v6, v12

    .line 93
    and-long/2addr v4, v6

    .line 94
    and-long/2addr v4, v8

    .line 95
    cmp-long v4, v4, v10

    .line 96
    .line 97
    if-eqz v4, :cond_2

    .line 98
    .line 99
    const/4 p0, -0x1

    .line 100
    return p0

    .line 101
    :cond_2
    add-int/lit8 v3, v3, 0x8

    .line 102
    .line 103
    add-int/2addr v0, v3

    .line 104
    and-int/2addr v0, v2

    .line 105
    goto :goto_0
.end method

.method public final d(I)I
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Landroidx/collection/z;->c(I)I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    if-ltz p1, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Landroidx/collection/z;->c:[I

    .line 8
    .line 9
    aget p0, p0, p1

    .line 10
    .line 11
    return p0

    .line 12
    :cond_0
    const/4 p0, -0x1

    .line 13
    return p0
.end method

.method public final e(I)V
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
    iput p1, p0, Landroidx/collection/z;->d:I

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
    :goto_1
    iput-object v0, p0, Landroidx/collection/z;->a:[J

    .line 38
    .line 39
    shr-int/lit8 v1, p1, 0x3

    .line 40
    .line 41
    and-int/lit8 v2, p1, 0x7

    .line 42
    .line 43
    shl-int/lit8 v2, v2, 0x3

    .line 44
    .line 45
    aget-wide v3, v0, v1

    .line 46
    .line 47
    const-wide/16 v5, 0xff

    .line 48
    .line 49
    shl-long/2addr v5, v2

    .line 50
    not-long v7, v5

    .line 51
    and-long v2, v3, v7

    .line 52
    .line 53
    or-long/2addr v2, v5

    .line 54
    aput-wide v2, v0, v1

    .line 55
    .line 56
    iget v0, p0, Landroidx/collection/z;->d:I

    .line 57
    .line 58
    invoke-static {v0}, Landroidx/collection/y0;->a(I)I

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    iget v1, p0, Landroidx/collection/z;->e:I

    .line 63
    .line 64
    sub-int/2addr v0, v1

    .line 65
    iput v0, p0, Landroidx/collection/z;->f:I

    .line 66
    .line 67
    new-array v0, p1, [I

    .line 68
    .line 69
    iput-object v0, p0, Landroidx/collection/z;->b:[I

    .line 70
    .line 71
    new-array p1, p1, [I

    .line 72
    .line 73
    iput-object p1, p0, Landroidx/collection/z;->c:[I

    .line 74
    .line 75
    return-void
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
    instance-of v3, v1, Landroidx/collection/z;

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
    check-cast v1, Landroidx/collection/z;

    .line 16
    .line 17
    iget v3, v1, Landroidx/collection/z;->e:I

    .line 18
    .line 19
    iget v5, v0, Landroidx/collection/z;->e:I

    .line 20
    .line 21
    if-eq v3, v5, :cond_2

    .line 22
    .line 23
    return v4

    .line 24
    :cond_2
    iget-object v3, v0, Landroidx/collection/z;->b:[I

    .line 25
    .line 26
    iget-object v5, v0, Landroidx/collection/z;->c:[I

    .line 27
    .line 28
    iget-object v0, v0, Landroidx/collection/z;->a:[J

    .line 29
    .line 30
    array-length v6, v0

    .line 31
    add-int/lit8 v6, v6, -0x2

    .line 32
    .line 33
    if-ltz v6, :cond_7

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
    if-eqz v10, :cond_6

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
    if-ge v12, v10, :cond_5

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
    if-gez v13, :cond_4

    .line 72
    .line 73
    shl-int/lit8 v13, v7, 0x3

    .line 74
    .line 75
    add-int/2addr v13, v12

    .line 76
    aget v14, v3, v13

    .line 77
    .line 78
    aget v13, v5, v13

    .line 79
    .line 80
    invoke-virtual {v1, v14}, Landroidx/collection/z;->c(I)I

    .line 81
    .line 82
    .line 83
    move-result v14

    .line 84
    if-ltz v14, :cond_3

    .line 85
    .line 86
    iget-object v15, v1, Landroidx/collection/z;->c:[I

    .line 87
    .line 88
    aget v14, v15, v14

    .line 89
    .line 90
    if-eq v13, v14, :cond_4

    .line 91
    .line 92
    :cond_3
    return v4

    .line 93
    :cond_4
    shr-long/2addr v8, v11

    .line 94
    add-int/lit8 v12, v12, 0x1

    .line 95
    .line 96
    goto :goto_1

    .line 97
    :cond_5
    if-ne v10, v11, :cond_7

    .line 98
    .line 99
    :cond_6
    if-eq v7, v6, :cond_7

    .line 100
    .line 101
    add-int/lit8 v7, v7, 0x1

    .line 102
    .line 103
    goto :goto_0

    .line 104
    :cond_7
    return v2
.end method

.method public final f(II)V
    .locals 37

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    invoke-static {v1}, Ljava/lang/Integer;->hashCode(I)I

    .line 6
    .line 7
    .line 8
    move-result v2

    .line 9
    const v3, -0x3361d2af    # -8.2930312E7f

    .line 10
    .line 11
    .line 12
    mul-int/2addr v2, v3

    .line 13
    shl-int/lit8 v4, v2, 0x10

    .line 14
    .line 15
    xor-int/2addr v2, v4

    .line 16
    ushr-int/lit8 v4, v2, 0x7

    .line 17
    .line 18
    and-int/lit8 v2, v2, 0x7f

    .line 19
    .line 20
    iget v5, v0, Landroidx/collection/z;->d:I

    .line 21
    .line 22
    and-int v6, v4, v5

    .line 23
    .line 24
    const/4 v8, 0x0

    .line 25
    :goto_0
    iget-object v9, v0, Landroidx/collection/z;->a:[J

    .line 26
    .line 27
    shr-int/lit8 v10, v6, 0x3

    .line 28
    .line 29
    and-int/lit8 v11, v6, 0x7

    .line 30
    .line 31
    shl-int/lit8 v11, v11, 0x3

    .line 32
    .line 33
    aget-wide v12, v9, v10

    .line 34
    .line 35
    ushr-long/2addr v12, v11

    .line 36
    const/4 v14, 0x1

    .line 37
    add-int/2addr v10, v14

    .line 38
    aget-wide v9, v9, v10

    .line 39
    .line 40
    rsub-int/lit8 v15, v11, 0x40

    .line 41
    .line 42
    shl-long/2addr v9, v15

    .line 43
    move/from16 v16, v8

    .line 44
    .line 45
    const/4 v15, 0x0

    .line 46
    int-to-long v7, v11

    .line 47
    neg-long v7, v7

    .line 48
    const/16 v11, 0x3f

    .line 49
    .line 50
    shr-long/2addr v7, v11

    .line 51
    and-long/2addr v7, v9

    .line 52
    or-long/2addr v7, v12

    .line 53
    int-to-long v9, v2

    .line 54
    const-wide v11, 0x101010101010101L

    .line 55
    .line 56
    .line 57
    .line 58
    .line 59
    mul-long v17, v9, v11

    .line 60
    .line 61
    move-wide/from16 v19, v11

    .line 62
    .line 63
    xor-long v11, v7, v17

    .line 64
    .line 65
    sub-long v17, v11, v19

    .line 66
    .line 67
    not-long v11, v11

    .line 68
    and-long v11, v17, v11

    .line 69
    .line 70
    const-wide v17, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 71
    .line 72
    .line 73
    .line 74
    .line 75
    and-long v11, v11, v17

    .line 76
    .line 77
    :goto_1
    const-wide/16 v19, 0x0

    .line 78
    .line 79
    cmp-long v13, v11, v19

    .line 80
    .line 81
    if-eqz v13, :cond_1

    .line 82
    .line 83
    invoke-static {v11, v12}, Ljava/lang/Long;->numberOfTrailingZeros(J)I

    .line 84
    .line 85
    .line 86
    move-result v13

    .line 87
    shr-int/lit8 v13, v13, 0x3

    .line 88
    .line 89
    add-int/2addr v13, v6

    .line 90
    and-int/2addr v13, v5

    .line 91
    move/from16 v21, v3

    .line 92
    .line 93
    iget-object v3, v0, Landroidx/collection/z;->b:[I

    .line 94
    .line 95
    aget v3, v3, v13

    .line 96
    .line 97
    if-ne v3, v1, :cond_0

    .line 98
    .line 99
    goto/16 :goto_c

    .line 100
    .line 101
    :cond_0
    const-wide/16 v19, 0x1

    .line 102
    .line 103
    sub-long v19, v11, v19

    .line 104
    .line 105
    and-long v11, v11, v19

    .line 106
    .line 107
    move/from16 v3, v21

    .line 108
    .line 109
    goto :goto_1

    .line 110
    :cond_1
    move/from16 v21, v3

    .line 111
    .line 112
    not-long v11, v7

    .line 113
    const/4 v3, 0x6

    .line 114
    shl-long/2addr v11, v3

    .line 115
    and-long/2addr v7, v11

    .line 116
    and-long v7, v7, v17

    .line 117
    .line 118
    cmp-long v3, v7, v19

    .line 119
    .line 120
    const/16 v7, 0x8

    .line 121
    .line 122
    if-eqz v3, :cond_10

    .line 123
    .line 124
    invoke-virtual {v0, v4}, Landroidx/collection/z;->b(I)I

    .line 125
    .line 126
    .line 127
    move-result v2

    .line 128
    iget v3, v0, Landroidx/collection/z;->f:I

    .line 129
    .line 130
    const-wide/16 v11, 0xff

    .line 131
    .line 132
    if-nez v3, :cond_2

    .line 133
    .line 134
    iget-object v3, v0, Landroidx/collection/z;->a:[J

    .line 135
    .line 136
    shr-int/lit8 v13, v2, 0x3

    .line 137
    .line 138
    aget-wide v19, v3, v13

    .line 139
    .line 140
    and-int/lit8 v3, v2, 0x7

    .line 141
    .line 142
    shl-int/lit8 v3, v3, 0x3

    .line 143
    .line 144
    shr-long v19, v19, v3

    .line 145
    .line 146
    and-long v19, v19, v11

    .line 147
    .line 148
    const-wide/16 v22, 0xfe

    .line 149
    .line 150
    cmp-long v3, v19, v22

    .line 151
    .line 152
    if-nez v3, :cond_3

    .line 153
    .line 154
    :cond_2
    move-wide/from16 v27, v9

    .line 155
    .line 156
    move-wide/from16 v25, v11

    .line 157
    .line 158
    move/from16 v18, v14

    .line 159
    .line 160
    move/from16 v32, v15

    .line 161
    .line 162
    const-wide/16 v19, 0x80

    .line 163
    .line 164
    const/16 v29, 0x7

    .line 165
    .line 166
    goto/16 :goto_b

    .line 167
    .line 168
    :cond_3
    iget v2, v0, Landroidx/collection/z;->d:I

    .line 169
    .line 170
    if-le v2, v7, :cond_b

    .line 171
    .line 172
    iget v3, v0, Landroidx/collection/z;->e:I

    .line 173
    .line 174
    const-wide/16 v19, 0x80

    .line 175
    .line 176
    int-to-long v5, v3

    .line 177
    const-wide/16 v24, 0x20

    .line 178
    .line 179
    mul-long v5, v5, v24

    .line 180
    .line 181
    int-to-long v2, v2

    .line 182
    const-wide/16 v24, 0x19

    .line 183
    .line 184
    mul-long v2, v2, v24

    .line 185
    .line 186
    invoke-static {v5, v6, v2, v3}, Ljava/lang/Long;->compareUnsigned(JJ)I

    .line 187
    .line 188
    .line 189
    move-result v2

    .line 190
    if-gtz v2, :cond_a

    .line 191
    .line 192
    iget-object v2, v0, Landroidx/collection/z;->a:[J

    .line 193
    .line 194
    iget v3, v0, Landroidx/collection/z;->d:I

    .line 195
    .line 196
    iget-object v5, v0, Landroidx/collection/z;->b:[I

    .line 197
    .line 198
    iget-object v6, v0, Landroidx/collection/z;->c:[I

    .line 199
    .line 200
    add-int/lit8 v13, v3, 0x7

    .line 201
    .line 202
    shr-int/lit8 v13, v13, 0x3

    .line 203
    .line 204
    move/from16 v24, v7

    .line 205
    .line 206
    move v7, v15

    .line 207
    :goto_2
    if-ge v7, v13, :cond_4

    .line 208
    .line 209
    aget-wide v25, v2, v7

    .line 210
    .line 211
    move-wide/from16 v27, v9

    .line 212
    .line 213
    const/4 v10, 0x7

    .line 214
    and-long v8, v25, v17

    .line 215
    .line 216
    move-wide/from16 v25, v11

    .line 217
    .line 218
    move v12, v10

    .line 219
    not-long v10, v8

    .line 220
    ushr-long/2addr v8, v12

    .line 221
    add-long/2addr v10, v8

    .line 222
    const-wide v8, -0x101010101010102L

    .line 223
    .line 224
    .line 225
    .line 226
    .line 227
    and-long/2addr v8, v10

    .line 228
    aput-wide v8, v2, v7

    .line 229
    .line 230
    add-int/lit8 v7, v7, 0x1

    .line 231
    .line 232
    move-wide/from16 v11, v25

    .line 233
    .line 234
    move-wide/from16 v9, v27

    .line 235
    .line 236
    goto :goto_2

    .line 237
    :cond_4
    move-wide/from16 v27, v9

    .line 238
    .line 239
    move-wide/from16 v25, v11

    .line 240
    .line 241
    const/4 v12, 0x7

    .line 242
    invoke-static {v2}, Lmx0/n;->A([J)I

    .line 243
    .line 244
    .line 245
    move-result v7

    .line 246
    add-int/lit8 v8, v7, -0x1

    .line 247
    .line 248
    aget-wide v9, v2, v8

    .line 249
    .line 250
    const-wide v16, 0xffffffffffffffL

    .line 251
    .line 252
    .line 253
    .line 254
    .line 255
    and-long v9, v9, v16

    .line 256
    .line 257
    const-wide/high16 v29, -0x100000000000000L

    .line 258
    .line 259
    or-long v9, v9, v29

    .line 260
    .line 261
    aput-wide v9, v2, v8

    .line 262
    .line 263
    aget-wide v8, v2, v15

    .line 264
    .line 265
    aput-wide v8, v2, v7

    .line 266
    .line 267
    move v7, v15

    .line 268
    :goto_3
    if-eq v7, v3, :cond_9

    .line 269
    .line 270
    shr-int/lit8 v8, v7, 0x3

    .line 271
    .line 272
    aget-wide v9, v2, v8

    .line 273
    .line 274
    and-int/lit8 v11, v7, 0x7

    .line 275
    .line 276
    shl-int/lit8 v11, v11, 0x3

    .line 277
    .line 278
    shr-long/2addr v9, v11

    .line 279
    and-long v9, v9, v25

    .line 280
    .line 281
    cmp-long v13, v9, v19

    .line 282
    .line 283
    if-nez v13, :cond_5

    .line 284
    .line 285
    :goto_4
    add-int/lit8 v7, v7, 0x1

    .line 286
    .line 287
    goto :goto_3

    .line 288
    :cond_5
    cmp-long v9, v9, v22

    .line 289
    .line 290
    if-eqz v9, :cond_6

    .line 291
    .line 292
    goto :goto_4

    .line 293
    :cond_6
    aget v9, v5, v7

    .line 294
    .line 295
    invoke-static {v9}, Ljava/lang/Integer;->hashCode(I)I

    .line 296
    .line 297
    .line 298
    move-result v9

    .line 299
    mul-int v9, v9, v21

    .line 300
    .line 301
    shl-int/lit8 v10, v9, 0x10

    .line 302
    .line 303
    xor-int/2addr v9, v10

    .line 304
    ushr-int/lit8 v10, v9, 0x7

    .line 305
    .line 306
    invoke-virtual {v0, v10}, Landroidx/collection/z;->b(I)I

    .line 307
    .line 308
    .line 309
    move-result v13

    .line 310
    and-int/2addr v10, v3

    .line 311
    sub-int v18, v13, v10

    .line 312
    .line 313
    and-int v18, v18, v3

    .line 314
    .line 315
    move/from16 v29, v12

    .line 316
    .line 317
    div-int/lit8 v12, v18, 0x8

    .line 318
    .line 319
    sub-int v10, v7, v10

    .line 320
    .line 321
    and-int/2addr v10, v3

    .line 322
    div-int/lit8 v10, v10, 0x8

    .line 323
    .line 324
    const-wide/high16 v30, -0x8000000000000000L

    .line 325
    .line 326
    if-ne v12, v10, :cond_7

    .line 327
    .line 328
    and-int/lit8 v9, v9, 0x7f

    .line 329
    .line 330
    int-to-long v9, v9

    .line 331
    aget-wide v12, v2, v8

    .line 332
    .line 333
    move/from16 v18, v14

    .line 334
    .line 335
    move/from16 v32, v15

    .line 336
    .line 337
    shl-long v14, v25, v11

    .line 338
    .line 339
    not-long v14, v14

    .line 340
    and-long/2addr v12, v14

    .line 341
    shl-long/2addr v9, v11

    .line 342
    or-long/2addr v9, v12

    .line 343
    aput-wide v9, v2, v8

    .line 344
    .line 345
    array-length v8, v2

    .line 346
    add-int/lit8 v8, v8, -0x1

    .line 347
    .line 348
    aget-wide v9, v2, v32

    .line 349
    .line 350
    and-long v9, v9, v16

    .line 351
    .line 352
    or-long v9, v9, v30

    .line 353
    .line 354
    aput-wide v9, v2, v8

    .line 355
    .line 356
    add-int/lit8 v7, v7, 0x1

    .line 357
    .line 358
    move/from16 v14, v18

    .line 359
    .line 360
    move/from16 v12, v29

    .line 361
    .line 362
    move/from16 v15, v32

    .line 363
    .line 364
    goto :goto_3

    .line 365
    :cond_7
    move/from16 v18, v14

    .line 366
    .line 367
    move/from16 v32, v15

    .line 368
    .line 369
    shr-int/lit8 v10, v13, 0x3

    .line 370
    .line 371
    aget-wide v14, v2, v10

    .line 372
    .line 373
    and-int/lit8 v12, v13, 0x7

    .line 374
    .line 375
    shl-int/lit8 v12, v12, 0x3

    .line 376
    .line 377
    shr-long v33, v14, v12

    .line 378
    .line 379
    and-long v33, v33, v25

    .line 380
    .line 381
    cmp-long v33, v33, v19

    .line 382
    .line 383
    if-nez v33, :cond_8

    .line 384
    .line 385
    and-int/lit8 v9, v9, 0x7f

    .line 386
    .line 387
    move-object/from16 v33, v5

    .line 388
    .line 389
    move-object/from16 v34, v6

    .line 390
    .line 391
    int-to-long v5, v9

    .line 392
    move-wide/from16 v35, v5

    .line 393
    .line 394
    shl-long v5, v25, v12

    .line 395
    .line 396
    not-long v5, v5

    .line 397
    and-long/2addr v5, v14

    .line 398
    shl-long v14, v35, v12

    .line 399
    .line 400
    or-long/2addr v5, v14

    .line 401
    aput-wide v5, v2, v10

    .line 402
    .line 403
    aget-wide v5, v2, v8

    .line 404
    .line 405
    shl-long v9, v25, v11

    .line 406
    .line 407
    not-long v9, v9

    .line 408
    and-long/2addr v5, v9

    .line 409
    shl-long v9, v19, v11

    .line 410
    .line 411
    or-long/2addr v5, v9

    .line 412
    aput-wide v5, v2, v8

    .line 413
    .line 414
    aget v5, v33, v7

    .line 415
    .line 416
    aput v5, v33, v13

    .line 417
    .line 418
    aput v32, v33, v7

    .line 419
    .line 420
    aget v5, v34, v7

    .line 421
    .line 422
    aput v5, v34, v13

    .line 423
    .line 424
    aput v32, v34, v7

    .line 425
    .line 426
    goto :goto_5

    .line 427
    :cond_8
    move-object/from16 v33, v5

    .line 428
    .line 429
    move-object/from16 v34, v6

    .line 430
    .line 431
    and-int/lit8 v5, v9, 0x7f

    .line 432
    .line 433
    int-to-long v5, v5

    .line 434
    shl-long v8, v25, v12

    .line 435
    .line 436
    not-long v8, v8

    .line 437
    and-long/2addr v8, v14

    .line 438
    shl-long/2addr v5, v12

    .line 439
    or-long/2addr v5, v8

    .line 440
    aput-wide v5, v2, v10

    .line 441
    .line 442
    aget v5, v33, v13

    .line 443
    .line 444
    aget v6, v33, v7

    .line 445
    .line 446
    aput v6, v33, v13

    .line 447
    .line 448
    aput v5, v33, v7

    .line 449
    .line 450
    aget v5, v34, v13

    .line 451
    .line 452
    aget v6, v34, v7

    .line 453
    .line 454
    aput v6, v34, v13

    .line 455
    .line 456
    aput v5, v34, v7

    .line 457
    .line 458
    add-int/lit8 v7, v7, -0x1

    .line 459
    .line 460
    :goto_5
    array-length v5, v2

    .line 461
    add-int/lit8 v5, v5, -0x1

    .line 462
    .line 463
    aget-wide v8, v2, v32

    .line 464
    .line 465
    and-long v8, v8, v16

    .line 466
    .line 467
    or-long v8, v8, v30

    .line 468
    .line 469
    aput-wide v8, v2, v5

    .line 470
    .line 471
    add-int/lit8 v7, v7, 0x1

    .line 472
    .line 473
    move/from16 v14, v18

    .line 474
    .line 475
    move/from16 v12, v29

    .line 476
    .line 477
    move/from16 v15, v32

    .line 478
    .line 479
    move-object/from16 v5, v33

    .line 480
    .line 481
    move-object/from16 v6, v34

    .line 482
    .line 483
    goto/16 :goto_3

    .line 484
    .line 485
    :cond_9
    move/from16 v29, v12

    .line 486
    .line 487
    move/from16 v18, v14

    .line 488
    .line 489
    move/from16 v32, v15

    .line 490
    .line 491
    iget v2, v0, Landroidx/collection/z;->d:I

    .line 492
    .line 493
    invoke-static {v2}, Landroidx/collection/y0;->a(I)I

    .line 494
    .line 495
    .line 496
    move-result v2

    .line 497
    iget v3, v0, Landroidx/collection/z;->e:I

    .line 498
    .line 499
    sub-int/2addr v2, v3

    .line 500
    iput v2, v0, Landroidx/collection/z;->f:I

    .line 501
    .line 502
    goto/16 :goto_a

    .line 503
    .line 504
    :cond_a
    :goto_6
    move-wide/from16 v27, v9

    .line 505
    .line 506
    move-wide/from16 v25, v11

    .line 507
    .line 508
    move/from16 v18, v14

    .line 509
    .line 510
    move/from16 v32, v15

    .line 511
    .line 512
    const/16 v29, 0x7

    .line 513
    .line 514
    goto :goto_7

    .line 515
    :cond_b
    const-wide/16 v19, 0x80

    .line 516
    .line 517
    goto :goto_6

    .line 518
    :goto_7
    iget v2, v0, Landroidx/collection/z;->d:I

    .line 519
    .line 520
    invoke-static {v2}, Landroidx/collection/y0;->b(I)I

    .line 521
    .line 522
    .line 523
    move-result v2

    .line 524
    iget-object v3, v0, Landroidx/collection/z;->a:[J

    .line 525
    .line 526
    iget-object v5, v0, Landroidx/collection/z;->b:[I

    .line 527
    .line 528
    iget-object v6, v0, Landroidx/collection/z;->c:[I

    .line 529
    .line 530
    iget v7, v0, Landroidx/collection/z;->d:I

    .line 531
    .line 532
    invoke-virtual {v0, v2}, Landroidx/collection/z;->e(I)V

    .line 533
    .line 534
    .line 535
    iget-object v2, v0, Landroidx/collection/z;->a:[J

    .line 536
    .line 537
    iget-object v8, v0, Landroidx/collection/z;->b:[I

    .line 538
    .line 539
    iget-object v9, v0, Landroidx/collection/z;->c:[I

    .line 540
    .line 541
    iget v10, v0, Landroidx/collection/z;->d:I

    .line 542
    .line 543
    move/from16 v11, v32

    .line 544
    .line 545
    :goto_8
    if-ge v11, v7, :cond_d

    .line 546
    .line 547
    shr-int/lit8 v12, v11, 0x3

    .line 548
    .line 549
    aget-wide v12, v3, v12

    .line 550
    .line 551
    and-int/lit8 v14, v11, 0x7

    .line 552
    .line 553
    shl-int/lit8 v14, v14, 0x3

    .line 554
    .line 555
    shr-long/2addr v12, v14

    .line 556
    and-long v12, v12, v25

    .line 557
    .line 558
    cmp-long v12, v12, v19

    .line 559
    .line 560
    if-gez v12, :cond_c

    .line 561
    .line 562
    aget v12, v5, v11

    .line 563
    .line 564
    invoke-static {v12}, Ljava/lang/Integer;->hashCode(I)I

    .line 565
    .line 566
    .line 567
    move-result v13

    .line 568
    mul-int v13, v13, v21

    .line 569
    .line 570
    shl-int/lit8 v14, v13, 0x10

    .line 571
    .line 572
    xor-int/2addr v13, v14

    .line 573
    ushr-int/lit8 v14, v13, 0x7

    .line 574
    .line 575
    invoke-virtual {v0, v14}, Landroidx/collection/z;->b(I)I

    .line 576
    .line 577
    .line 578
    move-result v14

    .line 579
    and-int/lit8 v13, v13, 0x7f

    .line 580
    .line 581
    move-object v15, v2

    .line 582
    int-to-long v1, v13

    .line 583
    shr-int/lit8 v13, v14, 0x3

    .line 584
    .line 585
    and-int/lit8 v16, v14, 0x7

    .line 586
    .line 587
    shl-int/lit8 v16, v16, 0x3

    .line 588
    .line 589
    aget-wide v22, v15, v13

    .line 590
    .line 591
    move-wide/from16 v30, v1

    .line 592
    .line 593
    shl-long v1, v25, v16

    .line 594
    .line 595
    not-long v1, v1

    .line 596
    and-long v1, v22, v1

    .line 597
    .line 598
    shl-long v16, v30, v16

    .line 599
    .line 600
    or-long v1, v1, v16

    .line 601
    .line 602
    aput-wide v1, v15, v13

    .line 603
    .line 604
    add-int/lit8 v13, v14, -0x7

    .line 605
    .line 606
    and-int/2addr v13, v10

    .line 607
    and-int/lit8 v16, v10, 0x7

    .line 608
    .line 609
    add-int v13, v13, v16

    .line 610
    .line 611
    shr-int/lit8 v13, v13, 0x3

    .line 612
    .line 613
    aput-wide v1, v15, v13

    .line 614
    .line 615
    aput v12, v8, v14

    .line 616
    .line 617
    aget v1, v6, v11

    .line 618
    .line 619
    aput v1, v9, v14

    .line 620
    .line 621
    goto :goto_9

    .line 622
    :cond_c
    move-object v15, v2

    .line 623
    :goto_9
    add-int/lit8 v11, v11, 0x1

    .line 624
    .line 625
    move/from16 v1, p1

    .line 626
    .line 627
    move-object v2, v15

    .line 628
    goto :goto_8

    .line 629
    :cond_d
    :goto_a
    invoke-virtual {v0, v4}, Landroidx/collection/z;->b(I)I

    .line 630
    .line 631
    .line 632
    move-result v2

    .line 633
    :goto_b
    iget v1, v0, Landroidx/collection/z;->e:I

    .line 634
    .line 635
    add-int/lit8 v1, v1, 0x1

    .line 636
    .line 637
    iput v1, v0, Landroidx/collection/z;->e:I

    .line 638
    .line 639
    iget v1, v0, Landroidx/collection/z;->f:I

    .line 640
    .line 641
    iget-object v3, v0, Landroidx/collection/z;->a:[J

    .line 642
    .line 643
    shr-int/lit8 v4, v2, 0x3

    .line 644
    .line 645
    aget-wide v5, v3, v4

    .line 646
    .line 647
    and-int/lit8 v7, v2, 0x7

    .line 648
    .line 649
    shl-int/lit8 v7, v7, 0x3

    .line 650
    .line 651
    shr-long v8, v5, v7

    .line 652
    .line 653
    and-long v8, v8, v25

    .line 654
    .line 655
    cmp-long v8, v8, v19

    .line 656
    .line 657
    if-nez v8, :cond_e

    .line 658
    .line 659
    move/from16 v32, v18

    .line 660
    .line 661
    :cond_e
    sub-int v1, v1, v32

    .line 662
    .line 663
    iput v1, v0, Landroidx/collection/z;->f:I

    .line 664
    .line 665
    iget v1, v0, Landroidx/collection/z;->d:I

    .line 666
    .line 667
    shl-long v8, v25, v7

    .line 668
    .line 669
    not-long v8, v8

    .line 670
    and-long/2addr v5, v8

    .line 671
    shl-long v7, v27, v7

    .line 672
    .line 673
    or-long/2addr v5, v7

    .line 674
    aput-wide v5, v3, v4

    .line 675
    .line 676
    add-int/lit8 v4, v2, -0x7

    .line 677
    .line 678
    and-int/2addr v4, v1

    .line 679
    and-int/lit8 v1, v1, 0x7

    .line 680
    .line 681
    add-int/2addr v4, v1

    .line 682
    shr-int/lit8 v1, v4, 0x3

    .line 683
    .line 684
    aput-wide v5, v3, v1

    .line 685
    .line 686
    not-int v13, v2

    .line 687
    :goto_c
    if-gez v13, :cond_f

    .line 688
    .line 689
    not-int v13, v13

    .line 690
    :cond_f
    iget-object v1, v0, Landroidx/collection/z;->b:[I

    .line 691
    .line 692
    aput p1, v1, v13

    .line 693
    .line 694
    iget-object v0, v0, Landroidx/collection/z;->c:[I

    .line 695
    .line 696
    aput p2, v0, v13

    .line 697
    .line 698
    return-void

    .line 699
    :cond_10
    move/from16 v24, v7

    .line 700
    .line 701
    move/from16 v32, v15

    .line 702
    .line 703
    add-int/lit8 v8, v16, 0x8

    .line 704
    .line 705
    add-int/2addr v6, v8

    .line 706
    and-int/2addr v6, v5

    .line 707
    move/from16 v1, p1

    .line 708
    .line 709
    move/from16 v3, v21

    .line 710
    .line 711
    goto/16 :goto_0
.end method

.method public final hashCode()I
    .locals 15

    .line 1
    iget-object v0, p0, Landroidx/collection/z;->b:[I

    .line 2
    .line 3
    iget-object v1, p0, Landroidx/collection/z;->c:[I

    .line 4
    .line 5
    iget-object p0, p0, Landroidx/collection/z;->a:[J

    .line 6
    .line 7
    array-length v2, p0

    .line 8
    add-int/lit8 v2, v2, -0x2

    .line 9
    .line 10
    const/4 v3, 0x0

    .line 11
    if-ltz v2, :cond_5

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
    if-eqz v8, :cond_3

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
    if-ge v10, v8, :cond_1

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
    if-gez v11, :cond_0

    .line 51
    .line 52
    shl-int/lit8 v11, v4, 0x3

    .line 53
    .line 54
    add-int/2addr v11, v10

    .line 55
    aget v12, v0, v11

    .line 56
    .line 57
    aget v11, v1, v11

    .line 58
    .line 59
    invoke-static {v12}, Ljava/lang/Integer;->hashCode(I)I

    .line 60
    .line 61
    .line 62
    move-result v12

    .line 63
    invoke-static {v11}, Ljava/lang/Integer;->hashCode(I)I

    .line 64
    .line 65
    .line 66
    move-result v11

    .line 67
    xor-int/2addr v11, v12

    .line 68
    add-int/2addr v5, v11

    .line 69
    :cond_0
    shr-long/2addr v6, v9

    .line 70
    add-int/lit8 v10, v10, 0x1

    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_1
    if-ne v8, v9, :cond_2

    .line 74
    .line 75
    goto :goto_2

    .line 76
    :cond_2
    return v5

    .line 77
    :cond_3
    :goto_2
    if-eq v4, v2, :cond_4

    .line 78
    .line 79
    add-int/lit8 v4, v4, 0x1

    .line 80
    .line 81
    goto :goto_0

    .line 82
    :cond_4
    return v5

    .line 83
    :cond_5
    return v3
.end method

.method public final toString()Ljava/lang/String;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Landroidx/collection/z;->e:I

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    const-string v0, "{}"

    .line 8
    .line 9
    return-object v0

    .line 10
    :cond_0
    new-instance v1, Ljava/lang/StringBuilder;

    .line 11
    .line 12
    const-string v2, "{"

    .line 13
    .line 14
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    iget-object v2, v0, Landroidx/collection/z;->b:[I

    .line 18
    .line 19
    iget-object v3, v0, Landroidx/collection/z;->c:[I

    .line 20
    .line 21
    iget-object v4, v0, Landroidx/collection/z;->a:[J

    .line 22
    .line 23
    array-length v5, v4

    .line 24
    add-int/lit8 v5, v5, -0x2

    .line 25
    .line 26
    if-ltz v5, :cond_4

    .line 27
    .line 28
    const/4 v6, 0x0

    .line 29
    move v7, v6

    .line 30
    move v8, v7

    .line 31
    :goto_0
    aget-wide v9, v4, v7

    .line 32
    .line 33
    not-long v11, v9

    .line 34
    const/4 v13, 0x7

    .line 35
    shl-long/2addr v11, v13

    .line 36
    and-long/2addr v11, v9

    .line 37
    const-wide v13, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 38
    .line 39
    .line 40
    .line 41
    .line 42
    and-long/2addr v11, v13

    .line 43
    cmp-long v11, v11, v13

    .line 44
    .line 45
    if-eqz v11, :cond_3

    .line 46
    .line 47
    sub-int v11, v7, v5

    .line 48
    .line 49
    not-int v11, v11

    .line 50
    ushr-int/lit8 v11, v11, 0x1f

    .line 51
    .line 52
    const/16 v12, 0x8

    .line 53
    .line 54
    rsub-int/lit8 v11, v11, 0x8

    .line 55
    .line 56
    move v13, v6

    .line 57
    :goto_1
    if-ge v13, v11, :cond_2

    .line 58
    .line 59
    const-wide/16 v14, 0xff

    .line 60
    .line 61
    and-long/2addr v14, v9

    .line 62
    const-wide/16 v16, 0x80

    .line 63
    .line 64
    cmp-long v14, v14, v16

    .line 65
    .line 66
    if-gez v14, :cond_1

    .line 67
    .line 68
    shl-int/lit8 v14, v7, 0x3

    .line 69
    .line 70
    add-int/2addr v14, v13

    .line 71
    aget v15, v2, v14

    .line 72
    .line 73
    aget v14, v3, v14

    .line 74
    .line 75
    invoke-virtual {v1, v15}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    const-string v15, "="

    .line 79
    .line 80
    invoke-virtual {v1, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    invoke-virtual {v1, v14}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    add-int/lit8 v8, v8, 0x1

    .line 87
    .line 88
    iget v14, v0, Landroidx/collection/z;->e:I

    .line 89
    .line 90
    if-ge v8, v14, :cond_1

    .line 91
    .line 92
    const-string v14, ", "

    .line 93
    .line 94
    invoke-virtual {v1, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    :cond_1
    shr-long/2addr v9, v12

    .line 98
    add-int/lit8 v13, v13, 0x1

    .line 99
    .line 100
    goto :goto_1

    .line 101
    :cond_2
    if-ne v11, v12, :cond_4

    .line 102
    .line 103
    :cond_3
    if-eq v7, v5, :cond_4

    .line 104
    .line 105
    add-int/lit8 v7, v7, 0x1

    .line 106
    .line 107
    goto :goto_0

    .line 108
    :cond_4
    const/16 v0, 0x7d

    .line 109
    .line 110
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object v0

    .line 117
    const-string v1, "toString(...)"

    .line 118
    .line 119
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    return-object v0
.end method
