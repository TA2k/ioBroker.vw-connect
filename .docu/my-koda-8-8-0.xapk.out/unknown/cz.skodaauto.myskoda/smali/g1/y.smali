.class public final Lg1/y;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/l;
.implements Lv3/x;


# instance fields
.field public A:Z

.field public r:Lg1/w1;

.field public final s:Lg1/u2;

.field public t:Z

.field public u:Lg1/u;

.field public final v:Lg1/r;

.field public w:Lt3/y;

.field public x:Z

.field public y:Z

.field public z:J


# direct methods
.method public constructor <init>(Lg1/w1;Lg1/u2;ZLg1/u;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lx2/r;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lg1/y;->r:Lg1/w1;

    .line 5
    .line 6
    iput-object p2, p0, Lg1/y;->s:Lg1/u2;

    .line 7
    .line 8
    iput-boolean p3, p0, Lg1/y;->t:Z

    .line 9
    .line 10
    iput-object p4, p0, Lg1/y;->u:Lg1/u;

    .line 11
    .line 12
    new-instance p1, Lg1/r;

    .line 13
    .line 14
    const/4 p2, 0x0

    .line 15
    invoke-direct {p1, p2}, Lg1/r;-><init>(I)V

    .line 16
    .line 17
    .line 18
    iput-object p1, p0, Lg1/y;->v:Lg1/r;

    .line 19
    .line 20
    const-wide/16 p1, 0x0

    .line 21
    .line 22
    iput-wide p1, p0, Lg1/y;->z:J

    .line 23
    .line 24
    return-void
.end method

.method public static final X0(Lg1/y;Lg1/u;)F
    .locals 14

    .line 1
    iget-wide v0, p0, Lg1/y;->z:J

    .line 2
    .line 3
    const-wide/16 v2, 0x0

    .line 4
    .line 5
    invoke-static {v0, v1, v2, v3}, Lt4/l;->a(JJ)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    goto/16 :goto_4

    .line 12
    .line 13
    :cond_0
    iget-object v0, p0, Lg1/y;->v:Lg1/r;

    .line 14
    .line 15
    iget-object v0, v0, Lg1/r;->a:Ln2/b;

    .line 16
    .line 17
    iget v1, v0, Ln2/b;->f:I

    .line 18
    .line 19
    const/4 v2, 0x1

    .line 20
    sub-int/2addr v1, v2

    .line 21
    iget-object v0, v0, Ln2/b;->d:[Ljava/lang/Object;

    .line 22
    .line 23
    array-length v3, v0

    .line 24
    const/16 v4, 0x20

    .line 25
    .line 26
    const-wide v5, 0xffffffffL

    .line 27
    .line 28
    .line 29
    .line 30
    .line 31
    const/4 v7, 0x0

    .line 32
    if-ge v1, v3, :cond_5

    .line 33
    .line 34
    move-object v3, v7

    .line 35
    :goto_0
    if-ltz v1, :cond_6

    .line 36
    .line 37
    aget-object v8, v0, v1

    .line 38
    .line 39
    check-cast v8, Lg1/x;

    .line 40
    .line 41
    iget-object v8, v8, Lg1/x;->a:Lq1/d;

    .line 42
    .line 43
    invoke-virtual {v8}, Lq1/d;->invoke()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v8

    .line 47
    check-cast v8, Ld3/c;

    .line 48
    .line 49
    if-eqz v8, :cond_4

    .line 50
    .line 51
    invoke-virtual {v8}, Ld3/c;->c()J

    .line 52
    .line 53
    .line 54
    move-result-wide v9

    .line 55
    iget-wide v11, p0, Lg1/y;->z:J

    .line 56
    .line 57
    invoke-static {v11, v12}, Lkp/f9;->c(J)J

    .line 58
    .line 59
    .line 60
    move-result-wide v11

    .line 61
    iget-object v13, p0, Lg1/y;->r:Lg1/w1;

    .line 62
    .line 63
    invoke-virtual {v13}, Ljava/lang/Enum;->ordinal()I

    .line 64
    .line 65
    .line 66
    move-result v13

    .line 67
    if-eqz v13, :cond_2

    .line 68
    .line 69
    if-ne v13, v2, :cond_1

    .line 70
    .line 71
    shr-long/2addr v9, v4

    .line 72
    long-to-int v9, v9

    .line 73
    invoke-static {v9}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 74
    .line 75
    .line 76
    move-result v9

    .line 77
    shr-long v10, v11, v4

    .line 78
    .line 79
    long-to-int v10, v10

    .line 80
    invoke-static {v10}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 81
    .line 82
    .line 83
    move-result v10

    .line 84
    invoke-static {v9, v10}, Ljava/lang/Float;->compare(FF)I

    .line 85
    .line 86
    .line 87
    move-result v9

    .line 88
    goto :goto_1

    .line 89
    :cond_1
    new-instance p0, La8/r0;

    .line 90
    .line 91
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 92
    .line 93
    .line 94
    throw p0

    .line 95
    :cond_2
    and-long/2addr v9, v5

    .line 96
    long-to-int v9, v9

    .line 97
    invoke-static {v9}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 98
    .line 99
    .line 100
    move-result v9

    .line 101
    and-long v10, v11, v5

    .line 102
    .line 103
    long-to-int v10, v10

    .line 104
    invoke-static {v10}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 105
    .line 106
    .line 107
    move-result v10

    .line 108
    invoke-static {v9, v10}, Ljava/lang/Float;->compare(FF)I

    .line 109
    .line 110
    .line 111
    move-result v9

    .line 112
    :goto_1
    if-gtz v9, :cond_3

    .line 113
    .line 114
    move-object v3, v8

    .line 115
    goto :goto_2

    .line 116
    :cond_3
    if-nez v3, :cond_6

    .line 117
    .line 118
    move-object v3, v8

    .line 119
    goto :goto_3

    .line 120
    :cond_4
    :goto_2
    add-int/lit8 v1, v1, -0x1

    .line 121
    .line 122
    goto :goto_0

    .line 123
    :cond_5
    move-object v3, v7

    .line 124
    :cond_6
    :goto_3
    if-nez v3, :cond_9

    .line 125
    .line 126
    iget-boolean v0, p0, Lg1/y;->x:Z

    .line 127
    .line 128
    if-eqz v0, :cond_7

    .line 129
    .line 130
    invoke-virtual {p0}, Lg1/y;->Y0()Ld3/c;

    .line 131
    .line 132
    .line 133
    move-result-object v7

    .line 134
    :cond_7
    if-nez v7, :cond_8

    .line 135
    .line 136
    :goto_4
    const/4 p0, 0x0

    .line 137
    return p0

    .line 138
    :cond_8
    move-object v3, v7

    .line 139
    :cond_9
    iget-wide v0, p0, Lg1/y;->z:J

    .line 140
    .line 141
    invoke-static {v0, v1}, Lkp/f9;->c(J)J

    .line 142
    .line 143
    .line 144
    move-result-wide v0

    .line 145
    iget-object p0, p0, Lg1/y;->r:Lg1/w1;

    .line 146
    .line 147
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 148
    .line 149
    .line 150
    move-result p0

    .line 151
    if-eqz p0, :cond_b

    .line 152
    .line 153
    if-ne p0, v2, :cond_a

    .line 154
    .line 155
    iget p0, v3, Ld3/c;->a:F

    .line 156
    .line 157
    iget v2, v3, Ld3/c;->c:F

    .line 158
    .line 159
    sub-float/2addr v2, p0

    .line 160
    shr-long/2addr v0, v4

    .line 161
    long-to-int v0, v0

    .line 162
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 163
    .line 164
    .line 165
    move-result v0

    .line 166
    invoke-interface {p1, p0, v2, v0}, Lg1/u;->a(FFF)F

    .line 167
    .line 168
    .line 169
    move-result p0

    .line 170
    return p0

    .line 171
    :cond_a
    new-instance p0, La8/r0;

    .line 172
    .line 173
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 174
    .line 175
    .line 176
    throw p0

    .line 177
    :cond_b
    iget p0, v3, Ld3/c;->b:F

    .line 178
    .line 179
    iget v2, v3, Ld3/c;->d:F

    .line 180
    .line 181
    sub-float/2addr v2, p0

    .line 182
    and-long/2addr v0, v5

    .line 183
    long-to-int v0, v0

    .line 184
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 185
    .line 186
    .line 187
    move-result v0

    .line 188
    invoke-interface {p1, p0, v2, v0}, Lg1/u;->a(FFF)F

    .line 189
    .line 190
    .line 191
    move-result p0

    .line 192
    return p0
.end method


# virtual methods
.method public final M0()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final Y0()Ld3/c;
    .locals 3

    .line 1
    iget-boolean v0, p0, Lx2/r;->q:Z

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    goto :goto_1

    .line 7
    :cond_0
    invoke-static {p0}, Lv3/f;->w(Lv3/m;)Lv3/f1;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iget-object p0, p0, Lg1/y;->w:Lt3/y;

    .line 12
    .line 13
    if-eqz p0, :cond_3

    .line 14
    .line 15
    invoke-interface {p0}, Lt3/y;->g()Z

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    if-eqz v2, :cond_1

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_1
    move-object p0, v1

    .line 23
    :goto_0
    if-nez p0, :cond_2

    .line 24
    .line 25
    goto :goto_1

    .line 26
    :cond_2
    const/4 v1, 0x0

    .line 27
    invoke-virtual {v0, p0, v1}, Lv3/f1;->P(Lt3/y;Z)Ld3/c;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0

    .line 32
    :cond_3
    :goto_1
    return-object v1
.end method

.method public final Z0(Ld3/c;J)Z
    .locals 2

    .line 1
    invoke-virtual {p0, p1, p2, p3}, Lg1/y;->b1(Ld3/c;J)J

    .line 2
    .line 3
    .line 4
    move-result-wide p0

    .line 5
    const/16 p2, 0x20

    .line 6
    .line 7
    shr-long p2, p0, p2

    .line 8
    .line 9
    long-to-int p2, p2

    .line 10
    invoke-static {p2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    invoke-static {p2}, Ljava/lang/Math;->abs(F)F

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    const/high16 p3, 0x3f000000    # 0.5f

    .line 19
    .line 20
    cmpg-float p2, p2, p3

    .line 21
    .line 22
    if-gtz p2, :cond_0

    .line 23
    .line 24
    const-wide v0, 0xffffffffL

    .line 25
    .line 26
    .line 27
    .line 28
    .line 29
    and-long/2addr p0, v0

    .line 30
    long-to-int p0, p0

    .line 31
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    .line 36
    .line 37
    .line 38
    move-result p0

    .line 39
    cmpg-float p0, p0, p3

    .line 40
    .line 41
    if-gtz p0, :cond_0

    .line 42
    .line 43
    const/4 p0, 0x1

    .line 44
    return p0

    .line 45
    :cond_0
    const/4 p0, 0x0

    .line 46
    return p0
.end method

.method public final a1()V
    .locals 8

    .line 1
    iget-object v0, p0, Lg1/y;->u:Lg1/u;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    sget-object v0, Lg1/w;->a:Ll2/e0;

    .line 6
    .line 7
    invoke-static {p0, v0}, Lv3/f;->i(Lv3/l;Ll2/s1;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    check-cast v0, Lg1/u;

    .line 12
    .line 13
    :cond_0
    move-object v5, v0

    .line 14
    iget-boolean v0, p0, Lg1/y;->A:Z

    .line 15
    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    const-string v0, "launchAnimation called when previous animation was running"

    .line 19
    .line 20
    invoke-static {v0}, Lj1/b;->c(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    :cond_1
    new-instance v4, Lg1/l3;

    .line 24
    .line 25
    iget-object v0, p0, Lg1/y;->u:Lg1/u;

    .line 26
    .line 27
    if-nez v0, :cond_2

    .line 28
    .line 29
    sget-object v0, Lg1/w;->a:Ll2/e0;

    .line 30
    .line 31
    invoke-static {p0, v0}, Lv3/f;->i(Lv3/l;Ll2/s1;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    check-cast v0, Lg1/u;

    .line 36
    .line 37
    :cond_2
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 38
    .line 39
    .line 40
    sget-object v0, Lg1/u;->a:Lg1/t;

    .line 41
    .line 42
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 43
    .line 44
    .line 45
    sget-object v0, Lg1/t;->b:Lc1/f1;

    .line 46
    .line 47
    invoke-direct {v4, v0}, Lg1/l3;-><init>(Lc1/j;)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {p0}, Lx2/r;->L0()Lvy0/b0;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    sget-object v7, Lvy0/c0;->g:Lvy0/c0;

    .line 55
    .line 56
    new-instance v1, La7/k;

    .line 57
    .line 58
    const/16 v2, 0x16

    .line 59
    .line 60
    const/4 v6, 0x0

    .line 61
    move-object v3, p0

    .line 62
    invoke-direct/range {v1 .. v6}, La7/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 63
    .line 64
    .line 65
    const/4 p0, 0x1

    .line 66
    invoke-static {v0, v6, v7, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 67
    .line 68
    .line 69
    return-void
.end method

.method public final b1(Ld3/c;J)J
    .locals 6

    .line 1
    invoke-static {p2, p3}, Lkp/f9;->c(J)J

    .line 2
    .line 3
    .line 4
    move-result-wide p2

    .line 5
    iget-object v0, p0, Lg1/y;->r:Lg1/w1;

    .line 6
    .line 7
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    const/4 v1, 0x0

    .line 12
    const-wide v2, 0xffffffffL

    .line 13
    .line 14
    .line 15
    .line 16
    .line 17
    const/16 v4, 0x20

    .line 18
    .line 19
    if-eqz v0, :cond_2

    .line 20
    .line 21
    const/4 v5, 0x1

    .line 22
    if-ne v0, v5, :cond_1

    .line 23
    .line 24
    iget-object v0, p0, Lg1/y;->u:Lg1/u;

    .line 25
    .line 26
    if-nez v0, :cond_0

    .line 27
    .line 28
    sget-object v0, Lg1/w;->a:Ll2/e0;

    .line 29
    .line 30
    invoke-static {p0, v0}, Lv3/f;->i(Lv3/l;Ll2/s1;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    move-object v0, p0

    .line 35
    check-cast v0, Lg1/u;

    .line 36
    .line 37
    :cond_0
    iget p0, p1, Ld3/c;->a:F

    .line 38
    .line 39
    iget p1, p1, Ld3/c;->c:F

    .line 40
    .line 41
    sub-float/2addr p1, p0

    .line 42
    shr-long/2addr p2, v4

    .line 43
    long-to-int p2, p2

    .line 44
    invoke-static {p2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 45
    .line 46
    .line 47
    move-result p2

    .line 48
    invoke-interface {v0, p0, p1, p2}, Lg1/u;->a(FFF)F

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 53
    .line 54
    .line 55
    move-result p0

    .line 56
    int-to-long p0, p0

    .line 57
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 58
    .line 59
    .line 60
    move-result p2

    .line 61
    int-to-long p2, p2

    .line 62
    shl-long/2addr p0, v4

    .line 63
    and-long/2addr p2, v2

    .line 64
    :goto_0
    or-long/2addr p0, p2

    .line 65
    return-wide p0

    .line 66
    :cond_1
    new-instance p0, La8/r0;

    .line 67
    .line 68
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 69
    .line 70
    .line 71
    throw p0

    .line 72
    :cond_2
    iget-object v0, p0, Lg1/y;->u:Lg1/u;

    .line 73
    .line 74
    if-nez v0, :cond_3

    .line 75
    .line 76
    sget-object v0, Lg1/w;->a:Ll2/e0;

    .line 77
    .line 78
    invoke-static {p0, v0}, Lv3/f;->i(Lv3/l;Ll2/s1;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    move-object v0, p0

    .line 83
    check-cast v0, Lg1/u;

    .line 84
    .line 85
    :cond_3
    iget p0, p1, Ld3/c;->b:F

    .line 86
    .line 87
    iget p1, p1, Ld3/c;->d:F

    .line 88
    .line 89
    sub-float/2addr p1, p0

    .line 90
    and-long/2addr p2, v2

    .line 91
    long-to-int p2, p2

    .line 92
    invoke-static {p2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 93
    .line 94
    .line 95
    move-result p2

    .line 96
    invoke-interface {v0, p0, p1, p2}, Lg1/u;->a(FFF)F

    .line 97
    .line 98
    .line 99
    move-result p0

    .line 100
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 101
    .line 102
    .line 103
    move-result p1

    .line 104
    int-to-long p1, p1

    .line 105
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 106
    .line 107
    .line 108
    move-result p0

    .line 109
    int-to-long v0, p0

    .line 110
    shl-long p0, p1, v4

    .line 111
    .line 112
    and-long p2, v0, v2

    .line 113
    .line 114
    goto :goto_0
.end method

.method public final h(J)V
    .locals 6

    .line 1
    iget-wide v0, p0, Lg1/y;->z:J

    .line 2
    .line 3
    iput-wide p1, p0, Lg1/y;->z:J

    .line 4
    .line 5
    iget-object v2, p0, Lg1/y;->r:Lg1/w1;

    .line 6
    .line 7
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    const/4 v3, 0x1

    .line 12
    if-eqz v2, :cond_1

    .line 13
    .line 14
    if-ne v2, v3, :cond_0

    .line 15
    .line 16
    const/16 v2, 0x20

    .line 17
    .line 18
    shr-long/2addr p1, v2

    .line 19
    long-to-int p1, p1

    .line 20
    shr-long v4, v0, v2

    .line 21
    .line 22
    long-to-int p2, v4

    .line 23
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->g(II)I

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    new-instance p0, La8/r0;

    .line 29
    .line 30
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 31
    .line 32
    .line 33
    throw p0

    .line 34
    :cond_1
    const-wide v4, 0xffffffffL

    .line 35
    .line 36
    .line 37
    .line 38
    .line 39
    and-long/2addr p1, v4

    .line 40
    long-to-int p1, p1

    .line 41
    and-long/2addr v4, v0

    .line 42
    long-to-int p2, v4

    .line 43
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->g(II)I

    .line 44
    .line 45
    .line 46
    move-result p1

    .line 47
    :goto_0
    if-ltz p1, :cond_2

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_2
    iget-boolean p1, p0, Lg1/y;->A:Z

    .line 51
    .line 52
    if-nez p1, :cond_5

    .line 53
    .line 54
    iget-boolean p1, p0, Lg1/y;->x:Z

    .line 55
    .line 56
    if-eqz p1, :cond_3

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_3
    invoke-virtual {p0}, Lg1/y;->Y0()Ld3/c;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    if-nez p1, :cond_4

    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_4
    invoke-virtual {p0, p1, v0, v1}, Lg1/y;->Z0(Ld3/c;J)Z

    .line 67
    .line 68
    .line 69
    move-result p1

    .line 70
    if-eqz p1, :cond_5

    .line 71
    .line 72
    iput-boolean v3, p0, Lg1/y;->y:Z

    .line 73
    .line 74
    :cond_5
    :goto_1
    return-void
.end method
