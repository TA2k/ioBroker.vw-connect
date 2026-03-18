.class public abstract Lp11/g;
.super Lp11/e;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final r1:[I

.field public static final s1:[I

.field public static final t1:[J

.field public static final u1:[J


# direct methods
.method static constructor <clinit>()V
    .locals 9

    .line 1
    const/16 v0, 0xc

    .line 2
    .line 3
    new-array v1, v0, [I

    .line 4
    .line 5
    fill-array-data v1, :array_0

    .line 6
    .line 7
    .line 8
    sput-object v1, Lp11/g;->r1:[I

    .line 9
    .line 10
    new-array v1, v0, [I

    .line 11
    .line 12
    fill-array-data v1, :array_1

    .line 13
    .line 14
    .line 15
    sput-object v1, Lp11/g;->s1:[I

    .line 16
    .line 17
    new-array v1, v0, [J

    .line 18
    .line 19
    sput-object v1, Lp11/g;->t1:[J

    .line 20
    .line 21
    new-array v0, v0, [J

    .line 22
    .line 23
    sput-object v0, Lp11/g;->u1:[J

    .line 24
    .line 25
    const-wide/16 v0, 0x0

    .line 26
    .line 27
    const/4 v2, 0x0

    .line 28
    move v4, v2

    .line 29
    move-wide v2, v0

    .line 30
    :goto_0
    const/16 v5, 0xb

    .line 31
    .line 32
    if-ge v4, v5, :cond_0

    .line 33
    .line 34
    sget-object v5, Lp11/g;->r1:[I

    .line 35
    .line 36
    aget v5, v5, v4

    .line 37
    .line 38
    int-to-long v5, v5

    .line 39
    const-wide/32 v7, 0x5265c00

    .line 40
    .line 41
    .line 42
    mul-long/2addr v5, v7

    .line 43
    add-long/2addr v0, v5

    .line 44
    sget-object v5, Lp11/g;->t1:[J

    .line 45
    .line 46
    add-int/lit8 v6, v4, 0x1

    .line 47
    .line 48
    aput-wide v0, v5, v6

    .line 49
    .line 50
    sget-object v5, Lp11/g;->s1:[I

    .line 51
    .line 52
    aget v4, v5, v4

    .line 53
    .line 54
    int-to-long v4, v4

    .line 55
    mul-long/2addr v4, v7

    .line 56
    add-long/2addr v2, v4

    .line 57
    sget-object v4, Lp11/g;->u1:[J

    .line 58
    .line 59
    aput-wide v2, v4, v6

    .line 60
    .line 61
    move v4, v6

    .line 62
    goto :goto_0

    .line 63
    :cond_0
    return-void

    .line 64
    nop

    .line 65
    :array_0
    .array-data 4
        0x1f
        0x1c
        0x1f
        0x1e
        0x1f
        0x1e
        0x1f
        0x1f
        0x1e
        0x1f
        0x1e
        0x1f
    .end array-data

    .line 66
    .line 67
    .line 68
    .line 69
    .line 70
    .line 71
    .line 72
    .line 73
    .line 74
    .line 75
    .line 76
    .line 77
    .line 78
    .line 79
    .line 80
    .line 81
    .line 82
    .line 83
    .line 84
    .line 85
    :array_1
    .array-data 4
        0x1f
        0x1d
        0x1f
        0x1e
        0x1f
        0x1e
        0x1f
        0x1f
        0x1e
        0x1f
        0x1e
        0x1f
    .end array-data
.end method


# virtual methods
.method public final T(II)J
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lp11/e;->a0(I)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    sget-object p0, Lp11/g;->u1:[J

    .line 8
    .line 9
    add-int/lit8 p2, p2, -0x1

    .line 10
    .line 11
    aget-wide p0, p0, p2

    .line 12
    .line 13
    return-wide p0

    .line 14
    :cond_0
    sget-object p0, Lp11/g;->t1:[J

    .line 15
    .line 16
    add-int/lit8 p2, p2, -0x1

    .line 17
    .line 18
    aget-wide p0, p0, p2

    .line 19
    .line 20
    return-wide p0
.end method

.method public final b0(II)I
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lp11/e;->a0(I)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    sget-object p0, Lp11/g;->s1:[I

    .line 8
    .line 9
    add-int/lit8 p2, p2, -0x1

    .line 10
    .line 11
    aget p0, p0, p2

    .line 12
    .line 13
    return p0

    .line 14
    :cond_0
    sget-object p0, Lp11/g;->r1:[I

    .line 15
    .line 16
    add-int/lit8 p2, p2, -0x1

    .line 17
    .line 18
    aget p0, p0, p2

    .line 19
    .line 20
    return p0
.end method

.method public final c0(IJ)I
    .locals 2

    .line 1
    invoke-virtual {p0, p1}, Lp11/e;->Y(I)J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    sub-long/2addr p2, v0

    .line 6
    const/16 v0, 0xa

    .line 7
    .line 8
    shr-long/2addr p2, v0

    .line 9
    long-to-int p2, p2

    .line 10
    invoke-virtual {p0, p1}, Lp11/e;->a0(I)Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    const p1, 0x27e949

    .line 15
    .line 16
    .line 17
    if-eqz p0, :cond_7

    .line 18
    .line 19
    const p0, 0xea515a

    .line 20
    .line 21
    .line 22
    if-ge p2, p0, :cond_3

    .line 23
    .line 24
    const p0, 0x7528ad

    .line 25
    .line 26
    .line 27
    if-ge p2, p0, :cond_1

    .line 28
    .line 29
    if-ge p2, p1, :cond_0

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    const p0, 0x4d3f64

    .line 33
    .line 34
    .line 35
    if-ge p2, p0, :cond_9

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_1
    const p0, 0x9bc85f

    .line 39
    .line 40
    .line 41
    if-ge p2, p0, :cond_2

    .line 42
    .line 43
    goto :goto_2

    .line 44
    :cond_2
    const p0, 0xc3b1a8

    .line 45
    .line 46
    .line 47
    if-ge p2, p0, :cond_c

    .line 48
    .line 49
    goto :goto_3

    .line 50
    :cond_3
    const p0, 0x160c39e

    .line 51
    .line 52
    .line 53
    if-ge p2, p0, :cond_5

    .line 54
    .line 55
    const p0, 0x1123aa3

    .line 56
    .line 57
    .line 58
    if-ge p2, p0, :cond_4

    .line 59
    .line 60
    goto :goto_4

    .line 61
    :cond_4
    const p0, 0x13a23ec

    .line 62
    .line 63
    .line 64
    if-ge p2, p0, :cond_f

    .line 65
    .line 66
    goto :goto_5

    .line 67
    :cond_5
    const p0, 0x188ace7

    .line 68
    .line 69
    .line 70
    if-ge p2, p0, :cond_6

    .line 71
    .line 72
    goto :goto_6

    .line 73
    :cond_6
    const p0, 0x1af4c99

    .line 74
    .line 75
    .line 76
    if-ge p2, p0, :cond_12

    .line 77
    .line 78
    goto :goto_7

    .line 79
    :cond_7
    const p0, 0xe907c3

    .line 80
    .line 81
    .line 82
    if-ge p2, p0, :cond_d

    .line 83
    .line 84
    const p0, 0x73df16

    .line 85
    .line 86
    .line 87
    if-ge p2, p0, :cond_a

    .line 88
    .line 89
    if-ge p2, p1, :cond_8

    .line 90
    .line 91
    :goto_0
    const/4 p0, 0x1

    .line 92
    return p0

    .line 93
    :cond_8
    const p0, 0x4bf5cd

    .line 94
    .line 95
    .line 96
    if-ge p2, p0, :cond_9

    .line 97
    .line 98
    :goto_1
    const/4 p0, 0x2

    .line 99
    return p0

    .line 100
    :cond_9
    const/4 p0, 0x3

    .line 101
    return p0

    .line 102
    :cond_a
    const p0, 0x9a7ec8

    .line 103
    .line 104
    .line 105
    if-ge p2, p0, :cond_b

    .line 106
    .line 107
    :goto_2
    const/4 p0, 0x4

    .line 108
    return p0

    .line 109
    :cond_b
    const p0, 0xc26811

    .line 110
    .line 111
    .line 112
    if-ge p2, p0, :cond_c

    .line 113
    .line 114
    :goto_3
    const/4 p0, 0x5

    .line 115
    return p0

    .line 116
    :cond_c
    const/4 p0, 0x6

    .line 117
    return p0

    .line 118
    :cond_d
    const p0, 0x15f7a07

    .line 119
    .line 120
    .line 121
    if-ge p2, p0, :cond_10

    .line 122
    .line 123
    const p0, 0x110f10c

    .line 124
    .line 125
    .line 126
    if-ge p2, p0, :cond_e

    .line 127
    .line 128
    :goto_4
    const/4 p0, 0x7

    .line 129
    return p0

    .line 130
    :cond_e
    const p0, 0x138da55

    .line 131
    .line 132
    .line 133
    if-ge p2, p0, :cond_f

    .line 134
    .line 135
    :goto_5
    const/16 p0, 0x8

    .line 136
    .line 137
    return p0

    .line 138
    :cond_f
    const/16 p0, 0x9

    .line 139
    .line 140
    return p0

    .line 141
    :cond_10
    const p0, 0x1876350

    .line 142
    .line 143
    .line 144
    if-ge p2, p0, :cond_11

    .line 145
    .line 146
    :goto_6
    return v0

    .line 147
    :cond_11
    const p0, 0x1ae0302

    .line 148
    .line 149
    .line 150
    if-ge p2, p0, :cond_12

    .line 151
    .line 152
    :goto_7
    const/16 p0, 0xb

    .line 153
    .line 154
    return p0

    .line 155
    :cond_12
    const/16 p0, 0xc

    .line 156
    .line 157
    return p0
.end method

.method public final d0(J)Z
    .locals 2

    .line 1
    iget-object v0, p0, Lp11/b;->D:Ln11/a;

    .line 2
    .line 3
    invoke-virtual {v0, p1, p2}, Ln11/a;->b(J)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1d

    .line 8
    .line 9
    if-ne v0, v1, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, Lp11/b;->I:Ln11/a;

    .line 12
    .line 13
    invoke-virtual {p0, p1, p2}, Ln11/a;->r(J)Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    if-eqz p0, :cond_0

    .line 18
    .line 19
    const/4 p0, 0x1

    .line 20
    return p0

    .line 21
    :cond_0
    const/4 p0, 0x0

    .line 22
    return p0
.end method

.method public final e0(IJ)J
    .locals 5

    .line 1
    invoke-virtual {p0, p2, p3}, Lp11/e;->X(J)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p0, v0}, Lp11/e;->Y(I)J

    .line 6
    .line 7
    .line 8
    move-result-wide v1

    .line 9
    sub-long v1, p2, v1

    .line 10
    .line 11
    const-wide/32 v3, 0x5265c00

    .line 12
    .line 13
    .line 14
    div-long/2addr v1, v3

    .line 15
    long-to-int v1, v1

    .line 16
    add-int/lit8 v2, v1, 0x1

    .line 17
    .line 18
    invoke-static {p2, p3}, Lp11/e;->S(J)I

    .line 19
    .line 20
    .line 21
    move-result p2

    .line 22
    const/16 p3, 0x3b

    .line 23
    .line 24
    if-le v2, p3, :cond_1

    .line 25
    .line 26
    invoke-virtual {p0, v0}, Lp11/e;->a0(I)Z

    .line 27
    .line 28
    .line 29
    move-result p3

    .line 30
    if-eqz p3, :cond_0

    .line 31
    .line 32
    invoke-virtual {p0, p1}, Lp11/e;->a0(I)Z

    .line 33
    .line 34
    .line 35
    move-result p3

    .line 36
    if-nez p3, :cond_1

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    invoke-virtual {p0, p1}, Lp11/e;->a0(I)Z

    .line 40
    .line 41
    .line 42
    move-result p3

    .line 43
    if-eqz p3, :cond_1

    .line 44
    .line 45
    add-int/lit8 v1, v1, 0x2

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_1
    move v1, v2

    .line 49
    :goto_0
    const/4 p3, 0x1

    .line 50
    invoke-virtual {p0, p1, p3, v1}, Lp11/e;->Z(III)J

    .line 51
    .line 52
    .line 53
    move-result-wide p0

    .line 54
    int-to-long p2, p2

    .line 55
    add-long/2addr p0, p2

    .line 56
    return-wide p0
.end method
