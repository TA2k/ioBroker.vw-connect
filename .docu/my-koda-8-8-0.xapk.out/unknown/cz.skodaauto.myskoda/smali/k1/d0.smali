.class public final Lk1/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:I

.field public final b:Lk1/g0;

.field public final c:J

.field public final d:I

.field public final e:I


# direct methods
.method public constructor <init>(ILk1/g0;JII)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lk1/d0;->a:I

    .line 5
    .line 6
    iput-object p2, p0, Lk1/d0;->b:Lk1/g0;

    .line 7
    .line 8
    iput-wide p3, p0, Lk1/d0;->c:J

    .line 9
    .line 10
    iput p5, p0, Lk1/d0;->d:I

    .line 11
    .line 12
    iput p6, p0, Lk1/d0;->e:I

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a(Lk1/c0;ZIIII)Lk1/d;
    .locals 0

    .line 1
    iget-boolean p1, p1, Lk1/c0;->b:Z

    .line 2
    .line 3
    if-nez p1, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    iget-object p0, p0, Lk1/d0;->b:Lk1/g0;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    sget-object p0, Lk1/f0;->d:Lk1/f0;

    .line 12
    .line 13
    :goto_0
    const/4 p0, 0x0

    .line 14
    return-object p0
.end method

.method public final b(ZIJLandroidx/collection/n;IIIZZ)Lk1/c0;
    .locals 14

    .line 1
    move/from16 v0, p2

    .line 2
    .line 3
    move-object/from16 v1, p5

    .line 4
    .line 5
    move/from16 v2, p6

    .line 6
    .line 7
    move/from16 v3, p8

    .line 8
    .line 9
    add-int v7, p7, v3

    .line 10
    .line 11
    const/4 v11, 0x1

    .line 12
    if-nez v1, :cond_0

    .line 13
    .line 14
    new-instance p0, Lk1/c0;

    .line 15
    .line 16
    invoke-direct {p0, v11, v11}, Lk1/c0;-><init>(ZZ)V

    .line 17
    .line 18
    .line 19
    return-object p0

    .line 20
    :cond_0
    iget-wide v4, v1, Landroidx/collection/n;->a:J

    .line 21
    .line 22
    iget-object v1, p0, Lk1/d0;->b:Lk1/g0;

    .line 23
    .line 24
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 25
    .line 26
    .line 27
    sget-object v1, Lk1/f0;->d:Lk1/f0;

    .line 28
    .line 29
    sget-object v1, Lk1/f0;->d:Lk1/f0;

    .line 30
    .line 31
    const v1, 0x7fffffff

    .line 32
    .line 33
    .line 34
    if-lt v2, v1, :cond_1

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_1
    const-wide v8, 0xffffffffL

    .line 38
    .line 39
    .line 40
    .line 41
    .line 42
    and-long v12, p3, v8

    .line 43
    .line 44
    long-to-int v1, v12

    .line 45
    and-long v12, v4, v8

    .line 46
    .line 47
    long-to-int v6, v12

    .line 48
    sub-int/2addr v1, v6

    .line 49
    if-gez v1, :cond_2

    .line 50
    .line 51
    :goto_0
    new-instance p0, Lk1/c0;

    .line 52
    .line 53
    invoke-direct {p0, v11, v11}, Lk1/c0;-><init>(ZZ)V

    .line 54
    .line 55
    .line 56
    return-object p0

    .line 57
    :cond_2
    if-nez v0, :cond_3

    .line 58
    .line 59
    goto :goto_2

    .line 60
    :cond_3
    iget v1, p0, Lk1/d0;->a:I

    .line 61
    .line 62
    const/16 v6, 0x20

    .line 63
    .line 64
    if-lt v0, v1, :cond_4

    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_4
    shr-long v0, p3, v6

    .line 68
    .line 69
    long-to-int v0, v0

    .line 70
    shr-long v12, v4, v6

    .line 71
    .line 72
    long-to-int v1, v12

    .line 73
    sub-int/2addr v0, v1

    .line 74
    if-gez v0, :cond_6

    .line 75
    .line 76
    :goto_1
    if-eqz p9, :cond_5

    .line 77
    .line 78
    new-instance p0, Lk1/c0;

    .line 79
    .line 80
    invoke-direct {p0, v11, v11}, Lk1/c0;-><init>(ZZ)V

    .line 81
    .line 82
    .line 83
    return-object p0

    .line 84
    :cond_5
    iget-wide v0, p0, Lk1/d0;->c:J

    .line 85
    .line 86
    invoke-static {v0, v1}, Lt4/a;->h(J)I

    .line 87
    .line 88
    .line 89
    move-result v0

    .line 90
    and-long v12, p3, v8

    .line 91
    .line 92
    long-to-int v1, v12

    .line 93
    iget v10, p0, Lk1/d0;->e:I

    .line 94
    .line 95
    sub-int/2addr v1, v10

    .line 96
    sub-int/2addr v1, v3

    .line 97
    invoke-static {v0, v1}, Landroidx/collection/n;->a(II)J

    .line 98
    .line 99
    .line 100
    move-result-wide v0

    .line 101
    shr-long v12, v4, v6

    .line 102
    .line 103
    long-to-int v3, v12

    .line 104
    iget v6, p0, Lk1/d0;->d:I

    .line 105
    .line 106
    sub-int/2addr v3, v6

    .line 107
    and-long/2addr v4, v8

    .line 108
    long-to-int v4, v4

    .line 109
    invoke-static {v3, v4}, Landroidx/collection/n;->a(II)J

    .line 110
    .line 111
    .line 112
    move-result-wide v3

    .line 113
    new-instance v5, Landroidx/collection/n;

    .line 114
    .line 115
    invoke-direct {v5, v3, v4}, Landroidx/collection/n;-><init>(J)V

    .line 116
    .line 117
    .line 118
    add-int/lit8 v6, v2, 0x1

    .line 119
    .line 120
    const/4 v9, 0x1

    .line 121
    const/4 v10, 0x0

    .line 122
    const/4 v2, 0x0

    .line 123
    const/4 v8, 0x0

    .line 124
    move-wide v3, v0

    .line 125
    move-object v0, p0

    .line 126
    move v1, p1

    .line 127
    invoke-virtual/range {v0 .. v10}, Lk1/d0;->b(ZIJLandroidx/collection/n;IIIZZ)Lk1/c0;

    .line 128
    .line 129
    .line 130
    move-result-object p0

    .line 131
    new-instance p1, Lk1/c0;

    .line 132
    .line 133
    iget-boolean p0, p0, Lk1/c0;->b:Z

    .line 134
    .line 135
    invoke-direct {p1, v11, p0}, Lk1/c0;-><init>(ZZ)V

    .line 136
    .line 137
    .line 138
    return-object p1

    .line 139
    :cond_6
    :goto_2
    and-long p0, v4, v8

    .line 140
    .line 141
    long-to-int p0, p0

    .line 142
    invoke-static {v3, p0}, Ljava/lang/Math;->max(II)I

    .line 143
    .line 144
    .line 145
    new-instance p0, Lk1/c0;

    .line 146
    .line 147
    const/4 p1, 0x0

    .line 148
    invoke-direct {p0, p1, p1}, Lk1/c0;-><init>(ZZ)V

    .line 149
    .line 150
    .line 151
    return-object p0
.end method
