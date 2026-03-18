.class public abstract Llp/qe;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lay0/a;Ll2/o;I)V
    .locals 10

    .line 1
    const-string v0, "onClick"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    move-object v6, p1

    .line 7
    check-cast v6, Ll2/t;

    .line 8
    .line 9
    const p1, 0x3e68e3e1

    .line 10
    .line 11
    .line 12
    invoke-virtual {v6, p1}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    and-int/lit8 p1, p2, 0x6

    .line 16
    .line 17
    const/4 v0, 0x2

    .line 18
    if-nez p1, :cond_1

    .line 19
    .line 20
    invoke-virtual {v6, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result p1

    .line 24
    if-eqz p1, :cond_0

    .line 25
    .line 26
    const/4 p1, 0x4

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    move p1, v0

    .line 29
    :goto_0
    or-int/2addr p1, p2

    .line 30
    goto :goto_1

    .line 31
    :cond_1
    move p1, p2

    .line 32
    :goto_1
    and-int/lit8 v1, p1, 0x3

    .line 33
    .line 34
    const/4 v2, 0x1

    .line 35
    if-eq v1, v0, :cond_2

    .line 36
    .line 37
    move v0, v2

    .line 38
    goto :goto_2

    .line 39
    :cond_2
    const/4 v0, 0x0

    .line 40
    :goto_2
    and-int/2addr p1, v2

    .line 41
    invoke-virtual {v6, p1, v0}, Ll2/t;->O(IZ)Z

    .line 42
    .line 43
    .line 44
    move-result p1

    .line 45
    if-eqz p1, :cond_3

    .line 46
    .line 47
    invoke-static {p0, v6}, Lzb/b;->B(Lay0/a;Ll2/o;)Lay0/a;

    .line 48
    .line 49
    .line 50
    move-result-object v3

    .line 51
    new-instance p1, Lxf0/i2;

    .line 52
    .line 53
    const/4 v0, 0x7

    .line 54
    invoke-direct {p1, v0}, Lxf0/i2;-><init>(I)V

    .line 55
    .line 56
    .line 57
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 58
    .line 59
    invoke-static {v0, p1}, Lx2/a;->a(Lx2/s;Lay0/o;)Lx2/s;

    .line 60
    .line 61
    .line 62
    move-result-object v7

    .line 63
    const p1, 0x7f12080a

    .line 64
    .line 65
    .line 66
    invoke-static {v6, p1}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v5

    .line 70
    const/4 v1, 0x0

    .line 71
    const/16 v2, 0x38

    .line 72
    .line 73
    const/4 v4, 0x0

    .line 74
    const/4 v8, 0x0

    .line 75
    const/4 v9, 0x0

    .line 76
    invoke-static/range {v1 .. v9}, Li91/j0;->X(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;ZZ)V

    .line 77
    .line 78
    .line 79
    goto :goto_3

    .line 80
    :cond_3
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 81
    .line 82
    .line 83
    :goto_3
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 84
    .line 85
    .line 86
    move-result-object p1

    .line 87
    if-eqz p1, :cond_4

    .line 88
    .line 89
    new-instance v0, Lcz/s;

    .line 90
    .line 91
    const/16 v1, 0x17

    .line 92
    .line 93
    invoke-direct {v0, p0, p2, v1}, Lcz/s;-><init>(Lay0/a;II)V

    .line 94
    .line 95
    .line 96
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 97
    .line 98
    :cond_4
    return-void
.end method

.method public static final b(Lgh/a;Lay0/a;Lay0/a;Ll2/o;I)V
    .locals 7

    .line 1
    const-string v0, "onStartClick"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "onStopClick"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    check-cast p3, Ll2/t;

    .line 12
    .line 13
    const v0, 0x6f9474bf

    .line 14
    .line 15
    .line 16
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    invoke-virtual {p3, v0}, Ll2/t;->e(I)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    const/4 v1, 0x2

    .line 28
    const/4 v2, 0x4

    .line 29
    if-eqz v0, :cond_0

    .line 30
    .line 31
    move v0, v2

    .line 32
    goto :goto_0

    .line 33
    :cond_0
    move v0, v1

    .line 34
    :goto_0
    or-int/2addr v0, p4

    .line 35
    invoke-virtual {p3, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    if-eqz v3, :cond_1

    .line 40
    .line 41
    const/16 v3, 0x20

    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_1
    const/16 v3, 0x10

    .line 45
    .line 46
    :goto_1
    or-int/2addr v0, v3

    .line 47
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result v3

    .line 51
    if-eqz v3, :cond_2

    .line 52
    .line 53
    const/16 v3, 0x100

    .line 54
    .line 55
    goto :goto_2

    .line 56
    :cond_2
    const/16 v3, 0x80

    .line 57
    .line 58
    :goto_2
    or-int/2addr v0, v3

    .line 59
    and-int/lit16 v3, v0, 0x93

    .line 60
    .line 61
    const/16 v4, 0x92

    .line 62
    .line 63
    const/4 v5, 0x1

    .line 64
    const/4 v6, 0x0

    .line 65
    if-eq v3, v4, :cond_3

    .line 66
    .line 67
    move v3, v5

    .line 68
    goto :goto_3

    .line 69
    :cond_3
    move v3, v6

    .line 70
    :goto_3
    and-int/lit8 v4, v0, 0x1

    .line 71
    .line 72
    invoke-virtual {p3, v4, v3}, Ll2/t;->O(IZ)Z

    .line 73
    .line 74
    .line 75
    move-result v3

    .line 76
    if-eqz v3, :cond_a

    .line 77
    .line 78
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 79
    .line 80
    .line 81
    move-result v3

    .line 82
    const/4 v4, 0x3

    .line 83
    if-eqz v3, :cond_9

    .line 84
    .line 85
    if-eq v3, v5, :cond_7

    .line 86
    .line 87
    if-eq v3, v1, :cond_6

    .line 88
    .line 89
    if-eq v3, v4, :cond_5

    .line 90
    .line 91
    if-ne v3, v2, :cond_4

    .line 92
    .line 93
    goto :goto_4

    .line 94
    :cond_4
    const p0, -0x23b5ac7b

    .line 95
    .line 96
    .line 97
    invoke-static {p0, p3, v6}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    throw p0

    .line 102
    :cond_5
    const v0, -0x23b58ce6

    .line 103
    .line 104
    .line 105
    invoke-virtual {p3, v0}, Ll2/t;->Y(I)V

    .line 106
    .line 107
    .line 108
    invoke-static {p3, v6}, Llp/qe;->c(Ll2/o;I)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {p3, v6}, Ll2/t;->q(Z)V

    .line 112
    .line 113
    .line 114
    goto :goto_6

    .line 115
    :cond_6
    const v0, -0x23b59312

    .line 116
    .line 117
    .line 118
    invoke-virtual {p3, v0}, Ll2/t;->Y(I)V

    .line 119
    .line 120
    .line 121
    invoke-static {p3, v6}, Llp/qe;->e(Ll2/o;I)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {p3, v6}, Ll2/t;->q(Z)V

    .line 125
    .line 126
    .line 127
    goto :goto_6

    .line 128
    :cond_7
    :goto_4
    const v1, -0x23b59dbe

    .line 129
    .line 130
    .line 131
    invoke-virtual {p3, v1}, Ll2/t;->Y(I)V

    .line 132
    .line 133
    .line 134
    sget-object v1, Lgh/a;->e:Lgh/a;

    .line 135
    .line 136
    if-ne p0, v1, :cond_8

    .line 137
    .line 138
    goto :goto_5

    .line 139
    :cond_8
    move v5, v6

    .line 140
    :goto_5
    shr-int/2addr v0, v4

    .line 141
    and-int/lit8 v0, v0, 0x70

    .line 142
    .line 143
    invoke-static {v5, p2, p3, v0}, Llp/qe;->d(ZLay0/a;Ll2/o;I)V

    .line 144
    .line 145
    .line 146
    invoke-virtual {p3, v6}, Ll2/t;->q(Z)V

    .line 147
    .line 148
    .line 149
    goto :goto_6

    .line 150
    :cond_9
    const v1, -0x23b5a7bc

    .line 151
    .line 152
    .line 153
    invoke-virtual {p3, v1}, Ll2/t;->Y(I)V

    .line 154
    .line 155
    .line 156
    shr-int/2addr v0, v4

    .line 157
    and-int/lit8 v0, v0, 0xe

    .line 158
    .line 159
    invoke-static {p1, p3, v0}, Llp/qe;->a(Lay0/a;Ll2/o;I)V

    .line 160
    .line 161
    .line 162
    invoke-virtual {p3, v6}, Ll2/t;->q(Z)V

    .line 163
    .line 164
    .line 165
    goto :goto_6

    .line 166
    :cond_a
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 167
    .line 168
    .line 169
    :goto_6
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 170
    .line 171
    .line 172
    move-result-object p3

    .line 173
    if-eqz p3, :cond_b

    .line 174
    .line 175
    new-instance v0, Luj/j0;

    .line 176
    .line 177
    const/16 v2, 0x13

    .line 178
    .line 179
    move-object v3, p0

    .line 180
    move-object v4, p1

    .line 181
    move-object v5, p2

    .line 182
    move v1, p4

    .line 183
    invoke-direct/range {v0 .. v5}, Luj/j0;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 184
    .line 185
    .line 186
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 187
    .line 188
    :cond_b
    return-void
.end method

.method public static final c(Ll2/o;I)V
    .locals 9

    .line 1
    move-object v5, p0

    .line 2
    check-cast v5, Ll2/t;

    .line 3
    .line 4
    const p0, -0x44ea33dc

    .line 5
    .line 6
    .line 7
    invoke-virtual {v5, p0}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    if-eqz p1, :cond_0

    .line 11
    .line 12
    const/4 p0, 0x1

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    :goto_0
    and-int/lit8 v0, p1, 0x1

    .line 16
    .line 17
    invoke-virtual {v5, v0, p0}, Ll2/t;->O(IZ)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    if-eqz p0, :cond_2

    .line 22
    .line 23
    new-instance p0, Lxf0/i2;

    .line 24
    .line 25
    const/4 v0, 0x7

    .line 26
    invoke-direct {p0, v0}, Lxf0/i2;-><init>(I)V

    .line 27
    .line 28
    .line 29
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 30
    .line 31
    invoke-static {v0, p0}, Lx2/a;->a(Lx2/s;Lay0/o;)Lx2/s;

    .line 32
    .line 33
    .line 34
    move-result-object v6

    .line 35
    const p0, 0x7f12080a

    .line 36
    .line 37
    .line 38
    invoke-static {v5, p0}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v4

    .line 42
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 47
    .line 48
    if-ne p0, v0, :cond_1

    .line 49
    .line 50
    new-instance p0, Lz81/g;

    .line 51
    .line 52
    const/4 v0, 0x2

    .line 53
    invoke-direct {p0, v0}, Lz81/g;-><init>(I)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {v5, p0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    :cond_1
    move-object v2, p0

    .line 60
    check-cast v2, Lay0/a;

    .line 61
    .line 62
    const/16 v0, 0x6030

    .line 63
    .line 64
    const/16 v1, 0x28

    .line 65
    .line 66
    const/4 v3, 0x0

    .line 67
    const/4 v7, 0x0

    .line 68
    const/4 v8, 0x0

    .line 69
    invoke-static/range {v0 .. v8}, Li91/j0;->X(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;ZZ)V

    .line 70
    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_2
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 74
    .line 75
    .line 76
    :goto_1
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    if-eqz p0, :cond_3

    .line 81
    .line 82
    new-instance v0, Lxj/h;

    .line 83
    .line 84
    const/4 v1, 0x5

    .line 85
    invoke-direct {v0, p1, v1}, Lxj/h;-><init>(II)V

    .line 86
    .line 87
    .line 88
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 89
    .line 90
    :cond_3
    return-void
.end method

.method public static final d(ZLay0/a;Ll2/o;I)V
    .locals 8

    .line 1
    const-string v0, "onClick"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    move-object v5, p2

    .line 7
    check-cast v5, Ll2/t;

    .line 8
    .line 9
    const p2, -0x2f57870e

    .line 10
    .line 11
    .line 12
    invoke-virtual {v5, p2}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    and-int/lit8 p2, p3, 0x6

    .line 16
    .line 17
    if-nez p2, :cond_1

    .line 18
    .line 19
    invoke-virtual {v5, p0}, Ll2/t;->h(Z)Z

    .line 20
    .line 21
    .line 22
    move-result p2

    .line 23
    if-eqz p2, :cond_0

    .line 24
    .line 25
    const/4 p2, 0x4

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 p2, 0x2

    .line 28
    :goto_0
    or-int/2addr p2, p3

    .line 29
    goto :goto_1

    .line 30
    :cond_1
    move p2, p3

    .line 31
    :goto_1
    and-int/lit8 v0, p3, 0x30

    .line 32
    .line 33
    if-nez v0, :cond_3

    .line 34
    .line 35
    invoke-virtual {v5, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    if-eqz v0, :cond_2

    .line 40
    .line 41
    const/16 v0, 0x20

    .line 42
    .line 43
    goto :goto_2

    .line 44
    :cond_2
    const/16 v0, 0x10

    .line 45
    .line 46
    :goto_2
    or-int/2addr p2, v0

    .line 47
    :cond_3
    and-int/lit8 v0, p2, 0x13

    .line 48
    .line 49
    const/16 v1, 0x12

    .line 50
    .line 51
    if-eq v0, v1, :cond_4

    .line 52
    .line 53
    const/4 v0, 0x1

    .line 54
    goto :goto_3

    .line 55
    :cond_4
    const/4 v0, 0x0

    .line 56
    :goto_3
    and-int/lit8 v1, p2, 0x1

    .line 57
    .line 58
    invoke-virtual {v5, v1, v0}, Ll2/t;->O(IZ)Z

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    if-eqz v0, :cond_5

    .line 63
    .line 64
    invoke-static {p1, v5}, Lzb/b;->B(Lay0/a;Ll2/o;)Lay0/a;

    .line 65
    .line 66
    .line 67
    move-result-object v3

    .line 68
    new-instance v0, Lxf0/i2;

    .line 69
    .line 70
    const/4 v1, 0x7

    .line 71
    invoke-direct {v0, v1}, Lxf0/i2;-><init>(I)V

    .line 72
    .line 73
    .line 74
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 75
    .line 76
    invoke-static {v1, v0}, Lx2/a;->a(Lx2/s;Lay0/o;)Lx2/s;

    .line 77
    .line 78
    .line 79
    move-result-object v6

    .line 80
    const v0, 0x7f12082c

    .line 81
    .line 82
    .line 83
    invoke-static {v5, v0}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object v4

    .line 87
    shl-int/lit8 p2, p2, 0xc

    .line 88
    .line 89
    const v0, 0xe000

    .line 90
    .line 91
    .line 92
    and-int v1, p2, v0

    .line 93
    .line 94
    const/16 v2, 0x28

    .line 95
    .line 96
    move v7, p0

    .line 97
    invoke-static/range {v1 .. v7}, Li91/j0;->P(IILay0/a;Ljava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 98
    .line 99
    .line 100
    goto :goto_4

    .line 101
    :cond_5
    move v7, p0

    .line 102
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 103
    .line 104
    .line 105
    :goto_4
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    if-eqz p0, :cond_6

    .line 110
    .line 111
    new-instance p2, Li2/r;

    .line 112
    .line 113
    const/4 v0, 0x5

    .line 114
    invoke-direct {p2, v7, p1, p3, v0}, Li2/r;-><init>(ZLay0/a;II)V

    .line 115
    .line 116
    .line 117
    iput-object p2, p0, Ll2/u1;->d:Lay0/n;

    .line 118
    .line 119
    :cond_6
    return-void
.end method

.method public static final e(Ll2/o;I)V
    .locals 9

    .line 1
    move-object v5, p0

    .line 2
    check-cast v5, Ll2/t;

    .line 3
    .line 4
    const p0, 0x7e0402d

    .line 5
    .line 6
    .line 7
    invoke-virtual {v5, p0}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    if-eqz p1, :cond_0

    .line 11
    .line 12
    const/4 p0, 0x1

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    :goto_0
    and-int/lit8 v0, p1, 0x1

    .line 16
    .line 17
    invoke-virtual {v5, v0, p0}, Ll2/t;->O(IZ)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    if-eqz p0, :cond_2

    .line 22
    .line 23
    new-instance p0, Lxf0/i2;

    .line 24
    .line 25
    const/4 v0, 0x7

    .line 26
    invoke-direct {p0, v0}, Lxf0/i2;-><init>(I)V

    .line 27
    .line 28
    .line 29
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 30
    .line 31
    invoke-static {v0, p0}, Lx2/a;->a(Lx2/s;Lay0/o;)Lx2/s;

    .line 32
    .line 33
    .line 34
    move-result-object v6

    .line 35
    const p0, 0x7f12082d

    .line 36
    .line 37
    .line 38
    invoke-static {v5, p0}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v4

    .line 42
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 47
    .line 48
    if-ne p0, v0, :cond_1

    .line 49
    .line 50
    new-instance p0, Lz81/g;

    .line 51
    .line 52
    const/4 v0, 0x2

    .line 53
    invoke-direct {p0, v0}, Lz81/g;-><init>(I)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {v5, p0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    :cond_1
    move-object v2, p0

    .line 60
    check-cast v2, Lay0/a;

    .line 61
    .line 62
    const/16 v0, 0x6030

    .line 63
    .line 64
    const/16 v1, 0x28

    .line 65
    .line 66
    const/4 v3, 0x0

    .line 67
    const/4 v7, 0x0

    .line 68
    const/4 v8, 0x0

    .line 69
    invoke-static/range {v0 .. v8}, Li91/j0;->X(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;ZZ)V

    .line 70
    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_2
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 74
    .line 75
    .line 76
    :goto_1
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    if-eqz p0, :cond_3

    .line 81
    .line 82
    new-instance v0, Lxj/h;

    .line 83
    .line 84
    const/4 v1, 0x6

    .line 85
    invoke-direct {v0, p1, v1}, Lxj/h;-><init>(II)V

    .line 86
    .line 87
    .line 88
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 89
    .line 90
    :cond_3
    return-void
.end method

.method public static final f(Ll4/v;)Landroid/view/inputmethod/ExtractedText;
    .locals 4

    .line 1
    new-instance v0, Landroid/view/inputmethod/ExtractedText;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/view/inputmethod/ExtractedText;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Ll4/v;->a:Lg4/g;

    .line 7
    .line 8
    iget-object v1, v1, Lg4/g;->e:Ljava/lang/String;

    .line 9
    .line 10
    iput-object v1, v0, Landroid/view/inputmethod/ExtractedText;->text:Ljava/lang/CharSequence;

    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    iput v2, v0, Landroid/view/inputmethod/ExtractedText;->startOffset:I

    .line 14
    .line 15
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    iput v1, v0, Landroid/view/inputmethod/ExtractedText;->partialEndOffset:I

    .line 20
    .line 21
    const/4 v1, -0x1

    .line 22
    iput v1, v0, Landroid/view/inputmethod/ExtractedText;->partialStartOffset:I

    .line 23
    .line 24
    iget-wide v1, p0, Ll4/v;->b:J

    .line 25
    .line 26
    invoke-static {v1, v2}, Lg4/o0;->f(J)I

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    iput v3, v0, Landroid/view/inputmethod/ExtractedText;->selectionStart:I

    .line 31
    .line 32
    invoke-static {v1, v2}, Lg4/o0;->e(J)I

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    iput v1, v0, Landroid/view/inputmethod/ExtractedText;->selectionEnd:I

    .line 37
    .line 38
    iget-object p0, p0, Ll4/v;->a:Lg4/g;

    .line 39
    .line 40
    iget-object p0, p0, Lg4/g;->e:Ljava/lang/String;

    .line 41
    .line 42
    const/16 v1, 0xa

    .line 43
    .line 44
    invoke-static {p0, v1}, Lly0/p;->B(Ljava/lang/CharSequence;C)Z

    .line 45
    .line 46
    .line 47
    move-result p0

    .line 48
    xor-int/lit8 p0, p0, 0x1

    .line 49
    .line 50
    iput p0, v0, Landroid/view/inputmethod/ExtractedText;->flags:I

    .line 51
    .line 52
    return-object v0
.end method
