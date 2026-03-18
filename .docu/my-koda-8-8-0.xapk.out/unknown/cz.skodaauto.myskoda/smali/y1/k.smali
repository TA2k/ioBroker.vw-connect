.class public abstract Ly1/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lx4/w;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lx4/w;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    const/16 v2, 0xe

    .line 5
    .line 6
    invoke-direct {v0, v2, v1}, Lx4/w;-><init>(IZ)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Ly1/k;->a:Lx4/w;

    .line 10
    .line 11
    return-void
.end method

.method public static final a(Lw1/g;Lw1/c;Ll2/o;I)V
    .locals 6

    .line 1
    move-object v3, p2

    .line 2
    check-cast v3, Ll2/t;

    .line 3
    .line 4
    const p2, 0x71816bae

    .line 5
    .line 6
    .line 7
    invoke-virtual {v3, p2}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    invoke-virtual {v3, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    const/4 v0, 0x4

    .line 15
    if-eqz p2, :cond_0

    .line 16
    .line 17
    move p2, v0

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    const/4 p2, 0x2

    .line 20
    :goto_0
    or-int/2addr p2, p3

    .line 21
    invoke-virtual {v3, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-eqz v1, :cond_1

    .line 26
    .line 27
    const/16 v1, 0x20

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_1
    const/16 v1, 0x10

    .line 31
    .line 32
    :goto_1
    or-int/2addr p2, v1

    .line 33
    and-int/lit8 v1, p2, 0x13

    .line 34
    .line 35
    const/16 v2, 0x12

    .line 36
    .line 37
    const/4 v4, 0x0

    .line 38
    const/4 v5, 0x1

    .line 39
    if-eq v1, v2, :cond_2

    .line 40
    .line 41
    move v1, v5

    .line 42
    goto :goto_2

    .line 43
    :cond_2
    move v1, v4

    .line 44
    :goto_2
    and-int/lit8 v2, p2, 0x1

    .line 45
    .line 46
    invoke-virtual {v3, v2, v1}, Ll2/t;->O(IZ)Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-eqz v1, :cond_6

    .line 51
    .line 52
    const v1, -0x3c2b2dd8

    .line 53
    .line 54
    .line 55
    invoke-virtual {v3, v1}, Ll2/t;->Y(I)V

    .line 56
    .line 57
    .line 58
    sget-object v1, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 59
    .line 60
    invoke-virtual {v3, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    check-cast v1, Landroid/content/Context;

    .line 65
    .line 66
    invoke-virtual {v3, v4}, Ll2/t;->q(Z)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {v3, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    move-result v2

    .line 73
    and-int/lit8 p2, p2, 0xe

    .line 74
    .line 75
    if-eq p2, v0, :cond_3

    .line 76
    .line 77
    goto :goto_3

    .line 78
    :cond_3
    move v4, v5

    .line 79
    :goto_3
    or-int p2, v2, v4

    .line 80
    .line 81
    invoke-virtual {v3, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 82
    .line 83
    .line 84
    move-result v0

    .line 85
    or-int/2addr p2, v0

    .line 86
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v0

    .line 90
    if-nez p2, :cond_4

    .line 91
    .line 92
    sget-object p2, Ll2/n;->a:Ll2/x0;

    .line 93
    .line 94
    if-ne v0, p2, :cond_5

    .line 95
    .line 96
    :cond_4
    new-instance v0, Lxc/b;

    .line 97
    .line 98
    const/4 p2, 0x3

    .line 99
    invoke-direct {v0, p1, v1, p0, p2}, Lxc/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v3, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    :cond_5
    move-object v2, v0

    .line 106
    check-cast v2, Lay0/k;

    .line 107
    .line 108
    const/4 v4, 0x0

    .line 109
    const/4 v5, 0x3

    .line 110
    const/4 v0, 0x0

    .line 111
    const/4 v1, 0x0

    .line 112
    invoke-static/range {v0 .. v5}, Lf1/g;->b(Lx2/s;Lf1/c;Lay0/k;Ll2/o;II)V

    .line 113
    .line 114
    .line 115
    goto :goto_4

    .line 116
    :cond_6
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 117
    .line 118
    .line 119
    :goto_4
    invoke-virtual {v3}, Ll2/t;->s()Ll2/u1;

    .line 120
    .line 121
    .line 122
    move-result-object p2

    .line 123
    if-eqz p2, :cond_7

    .line 124
    .line 125
    new-instance v0, Lx40/n;

    .line 126
    .line 127
    const/16 v1, 0xc

    .line 128
    .line 129
    invoke-direct {v0, p3, v1, p0, p1}, Lx40/n;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 130
    .line 131
    .line 132
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 133
    .line 134
    :cond_7
    return-void
.end method

.method public static final b(IJLl2/o;I)V
    .locals 20

    .line 1
    move-wide/from16 v1, p1

    .line 2
    .line 3
    move-object/from16 v0, p3

    .line 4
    .line 5
    check-cast v0, Ll2/t;

    .line 6
    .line 7
    const v3, -0x49eca00d

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    and-int/lit8 v3, p4, 0x6

    .line 14
    .line 15
    const/4 v4, 0x4

    .line 16
    if-nez v3, :cond_1

    .line 17
    .line 18
    move/from16 v3, p0

    .line 19
    .line 20
    invoke-virtual {v0, v3}, Ll2/t;->e(I)Z

    .line 21
    .line 22
    .line 23
    move-result v5

    .line 24
    if-eqz v5, :cond_0

    .line 25
    .line 26
    move v5, v4

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 v5, 0x2

    .line 29
    :goto_0
    or-int v5, p4, v5

    .line 30
    .line 31
    goto :goto_1

    .line 32
    :cond_1
    move/from16 v3, p0

    .line 33
    .line 34
    move/from16 v5, p4

    .line 35
    .line 36
    :goto_1
    and-int/lit8 v6, p4, 0x30

    .line 37
    .line 38
    const/16 v7, 0x20

    .line 39
    .line 40
    if-nez v6, :cond_3

    .line 41
    .line 42
    invoke-virtual {v0, v1, v2}, Ll2/t;->f(J)Z

    .line 43
    .line 44
    .line 45
    move-result v6

    .line 46
    if-eqz v6, :cond_2

    .line 47
    .line 48
    move v6, v7

    .line 49
    goto :goto_2

    .line 50
    :cond_2
    const/16 v6, 0x10

    .line 51
    .line 52
    :goto_2
    or-int/2addr v5, v6

    .line 53
    :cond_3
    and-int/lit8 v6, v5, 0x13

    .line 54
    .line 55
    const/16 v8, 0x12

    .line 56
    .line 57
    const/4 v9, 0x1

    .line 58
    const/4 v10, 0x0

    .line 59
    if-eq v6, v8, :cond_4

    .line 60
    .line 61
    move v6, v9

    .line 62
    goto :goto_3

    .line 63
    :cond_4
    move v6, v10

    .line 64
    :goto_3
    and-int/lit8 v8, v5, 0x1

    .line 65
    .line 66
    invoke-virtual {v0, v8, v6}, Ll2/t;->O(IZ)Z

    .line 67
    .line 68
    .line 69
    move-result v6

    .line 70
    if-eqz v6, :cond_d

    .line 71
    .line 72
    sget-object v6, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 73
    .line 74
    invoke-virtual {v0, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v6

    .line 78
    check-cast v6, Landroid/content/Context;

    .line 79
    .line 80
    invoke-virtual {v0, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    move-result v8

    .line 84
    and-int/lit8 v11, v5, 0xe

    .line 85
    .line 86
    if-ne v11, v4, :cond_5

    .line 87
    .line 88
    move v4, v9

    .line 89
    goto :goto_4

    .line 90
    :cond_5
    move v4, v10

    .line 91
    :goto_4
    or-int/2addr v4, v8

    .line 92
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v8

    .line 96
    const/4 v11, -0x1

    .line 97
    sget-object v12, Ll2/n;->a:Ll2/x0;

    .line 98
    .line 99
    if-nez v4, :cond_6

    .line 100
    .line 101
    if-ne v8, v12, :cond_7

    .line 102
    .line 103
    :cond_6
    filled-new-array {v3}, [I

    .line 104
    .line 105
    .line 106
    move-result-object v4

    .line 107
    invoke-virtual {v6, v4}, Landroid/content/Context;->obtainStyledAttributes([I)Landroid/content/res/TypedArray;

    .line 108
    .line 109
    .line 110
    move-result-object v4

    .line 111
    invoke-virtual {v4, v10, v11}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 112
    .line 113
    .line 114
    move-result v4

    .line 115
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 116
    .line 117
    .line 118
    move-result-object v8

    .line 119
    invoke-virtual {v0, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    :cond_7
    check-cast v8, Ljava/lang/Number;

    .line 123
    .line 124
    invoke-virtual {v8}, Ljava/lang/Number;->intValue()I

    .line 125
    .line 126
    .line 127
    move-result v4

    .line 128
    if-ne v4, v11, :cond_8

    .line 129
    .line 130
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 131
    .line 132
    .line 133
    move-result-object v6

    .line 134
    if-eqz v6, :cond_e

    .line 135
    .line 136
    new-instance v0, Ly1/j;

    .line 137
    .line 138
    const/4 v5, 0x0

    .line 139
    move/from16 v4, p4

    .line 140
    .line 141
    invoke-direct/range {v0 .. v5}, Ly1/j;-><init>(JIII)V

    .line 142
    .line 143
    .line 144
    :goto_5
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 145
    .line 146
    return-void

    .line 147
    :cond_8
    invoke-static {v4, v10, v0}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 148
    .line 149
    .line 150
    move-result-object v14

    .line 151
    and-int/lit8 v3, v5, 0x70

    .line 152
    .line 153
    if-ne v3, v7, :cond_9

    .line 154
    .line 155
    goto :goto_6

    .line 156
    :cond_9
    move v9, v10

    .line 157
    :goto_6
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object v3

    .line 161
    if-nez v9, :cond_a

    .line 162
    .line 163
    if-ne v3, v12, :cond_c

    .line 164
    .line 165
    :cond_a
    const-wide/16 v3, 0x10

    .line 166
    .line 167
    cmp-long v3, v1, v3

    .line 168
    .line 169
    if-nez v3, :cond_b

    .line 170
    .line 171
    const/4 v3, 0x0

    .line 172
    goto :goto_7

    .line 173
    :cond_b
    new-instance v3, Le3/m;

    .line 174
    .line 175
    const/4 v4, 0x5

    .line 176
    invoke-direct {v3, v1, v2, v4}, Le3/m;-><init>(JI)V

    .line 177
    .line 178
    .line 179
    :goto_7
    invoke-virtual {v0, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 180
    .line 181
    .line 182
    :cond_c
    move-object/from16 v18, v3

    .line 183
    .line 184
    check-cast v18, Le3/m;

    .line 185
    .line 186
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 187
    .line 188
    sget v4, Lf1/f;->j:F

    .line 189
    .line 190
    invoke-static {v3, v4}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 191
    .line 192
    .line 193
    move-result-object v13

    .line 194
    const/16 v17, 0x0

    .line 195
    .line 196
    const/16 v19, 0x16

    .line 197
    .line 198
    const/4 v15, 0x0

    .line 199
    sget-object v16, Lt3/j;->b:Lt3/x0;

    .line 200
    .line 201
    invoke-static/range {v13 .. v19}, Landroidx/compose/ui/draw/a;->d(Lx2/s;Li3/c;Lx2/e;Lt3/k;FLe3/m;I)Lx2/s;

    .line 202
    .line 203
    .line 204
    move-result-object v3

    .line 205
    invoke-static {v3, v0, v10}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 206
    .line 207
    .line 208
    goto :goto_8

    .line 209
    :cond_d
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 210
    .line 211
    .line 212
    :goto_8
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 213
    .line 214
    .line 215
    move-result-object v6

    .line 216
    if-eqz v6, :cond_e

    .line 217
    .line 218
    new-instance v0, Ly1/j;

    .line 219
    .line 220
    const/4 v5, 0x1

    .line 221
    move/from16 v3, p0

    .line 222
    .line 223
    move/from16 v4, p4

    .line 224
    .line 225
    invoke-direct/range {v0 .. v5}, Ly1/j;-><init>(JIII)V

    .line 226
    .line 227
    .line 228
    goto :goto_5

    .line 229
    :cond_e
    return-void
.end method

.method public static final c(Lw1/g;La2/k;Lay0/a;Ll2/o;I)V
    .locals 9

    .line 1
    move-object v4, p3

    .line 2
    check-cast v4, Ll2/t;

    .line 3
    .line 4
    const p3, -0x799dedcc

    .line 5
    .line 6
    .line 7
    invoke-virtual {v4, p3}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    and-int/lit8 p3, p4, 0x6

    .line 11
    .line 12
    const/4 v0, 0x4

    .line 13
    if-nez p3, :cond_2

    .line 14
    .line 15
    and-int/lit8 p3, p4, 0x8

    .line 16
    .line 17
    if-nez p3, :cond_0

    .line 18
    .line 19
    invoke-virtual {v4, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result p3

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    invoke-virtual {v4, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result p3

    .line 28
    :goto_0
    if-eqz p3, :cond_1

    .line 29
    .line 30
    move p3, v0

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    const/4 p3, 0x2

    .line 33
    :goto_1
    or-int/2addr p3, p4

    .line 34
    goto :goto_2

    .line 35
    :cond_2
    move p3, p4

    .line 36
    :goto_2
    and-int/lit8 v1, p4, 0x30

    .line 37
    .line 38
    const/16 v2, 0x20

    .line 39
    .line 40
    if-nez v1, :cond_5

    .line 41
    .line 42
    and-int/lit8 v1, p4, 0x40

    .line 43
    .line 44
    if-nez v1, :cond_3

    .line 45
    .line 46
    invoke-virtual {v4, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    goto :goto_3

    .line 51
    :cond_3
    invoke-virtual {v4, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    :goto_3
    if-eqz v1, :cond_4

    .line 56
    .line 57
    move v1, v2

    .line 58
    goto :goto_4

    .line 59
    :cond_4
    const/16 v1, 0x10

    .line 60
    .line 61
    :goto_4
    or-int/2addr p3, v1

    .line 62
    :cond_5
    and-int/lit16 v1, p4, 0x180

    .line 63
    .line 64
    if-nez v1, :cond_7

    .line 65
    .line 66
    invoke-virtual {v4, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result v1

    .line 70
    if-eqz v1, :cond_6

    .line 71
    .line 72
    const/16 v1, 0x100

    .line 73
    .line 74
    goto :goto_5

    .line 75
    :cond_6
    const/16 v1, 0x80

    .line 76
    .line 77
    :goto_5
    or-int/2addr p3, v1

    .line 78
    :cond_7
    and-int/lit16 v1, p3, 0x93

    .line 79
    .line 80
    const/16 v3, 0x92

    .line 81
    .line 82
    const/4 v5, 0x0

    .line 83
    const/4 v6, 0x1

    .line 84
    if-eq v1, v3, :cond_8

    .line 85
    .line 86
    move v1, v6

    .line 87
    goto :goto_6

    .line 88
    :cond_8
    move v1, v5

    .line 89
    :goto_6
    and-int/lit8 v3, p3, 0x1

    .line 90
    .line 91
    invoke-virtual {v4, v3, v1}, Ll2/t;->O(IZ)Z

    .line 92
    .line 93
    .line 94
    move-result v1

    .line 95
    if-eqz v1, :cond_11

    .line 96
    .line 97
    and-int/lit8 v1, p3, 0x70

    .line 98
    .line 99
    if-eq v1, v2, :cond_a

    .line 100
    .line 101
    and-int/lit8 v1, p3, 0x40

    .line 102
    .line 103
    if-eqz v1, :cond_9

    .line 104
    .line 105
    invoke-virtual {v4, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    move-result v1

    .line 109
    if-eqz v1, :cond_9

    .line 110
    .line 111
    goto :goto_7

    .line 112
    :cond_9
    move v1, v5

    .line 113
    goto :goto_8

    .line 114
    :cond_a
    :goto_7
    move v1, v6

    .line 115
    :goto_8
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v2

    .line 119
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 120
    .line 121
    if-nez v1, :cond_b

    .line 122
    .line 123
    if-ne v2, v3, :cond_c

    .line 124
    .line 125
    :cond_b
    new-instance v2, Ly1/m;

    .line 126
    .line 127
    new-instance v1, La0/j;

    .line 128
    .line 129
    new-instance v7, Lvu/d;

    .line 130
    .line 131
    const/16 v8, 0x15

    .line 132
    .line 133
    invoke-direct {v7, v8, p1, p2}, Lvu/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    const/16 v8, 0x13

    .line 137
    .line 138
    invoke-direct {v1, v7, v8}, La0/j;-><init>(Ljava/lang/Object;I)V

    .line 139
    .line 140
    .line 141
    invoke-direct {v2, v1}, Ly1/m;-><init>(La0/j;)V

    .line 142
    .line 143
    .line 144
    invoke-virtual {v4, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 145
    .line 146
    .line 147
    :cond_c
    check-cast v2, Ly1/m;

    .line 148
    .line 149
    and-int/lit8 v1, p3, 0xe

    .line 150
    .line 151
    if-eq v1, v0, :cond_d

    .line 152
    .line 153
    and-int/lit8 p3, p3, 0x8

    .line 154
    .line 155
    if-eqz p3, :cond_e

    .line 156
    .line 157
    invoke-virtual {v4, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 158
    .line 159
    .line 160
    move-result p3

    .line 161
    if-eqz p3, :cond_e

    .line 162
    .line 163
    :cond_d
    move v5, v6

    .line 164
    :cond_e
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object p3

    .line 168
    if-nez v5, :cond_f

    .line 169
    .line 170
    if-ne p3, v3, :cond_10

    .line 171
    .line 172
    :cond_f
    new-instance p3, Ly1/i;

    .line 173
    .line 174
    const/4 v0, 0x0

    .line 175
    invoke-direct {p3, p0, v0}, Ly1/i;-><init>(Ljava/lang/Object;I)V

    .line 176
    .line 177
    .line 178
    invoke-virtual {v4, p3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 179
    .line 180
    .line 181
    :cond_10
    move-object v1, p3

    .line 182
    check-cast v1, Lay0/a;

    .line 183
    .line 184
    new-instance p3, Laa/p;

    .line 185
    .line 186
    const/16 v0, 0x12

    .line 187
    .line 188
    invoke-direct {p3, v0, p1, p0}, Laa/p;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 189
    .line 190
    .line 191
    const v0, 0x4e63add6    # 9.5495514E8f

    .line 192
    .line 193
    .line 194
    invoke-static {v0, v4, p3}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 195
    .line 196
    .line 197
    move-result-object v3

    .line 198
    const/16 v5, 0xd80

    .line 199
    .line 200
    const/4 v6, 0x0

    .line 201
    move-object v0, v2

    .line 202
    sget-object v2, Ly1/k;->a:Lx4/w;

    .line 203
    .line 204
    invoke-static/range {v0 .. v6}, Lx4/i;->a(Lx4/v;Lay0/a;Lx4/w;Lt2/b;Ll2/o;II)V

    .line 205
    .line 206
    .line 207
    goto :goto_9

    .line 208
    :cond_11
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 209
    .line 210
    .line 211
    :goto_9
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 212
    .line 213
    .line 214
    move-result-object p3

    .line 215
    if-eqz p3, :cond_12

    .line 216
    .line 217
    new-instance v0, Lxk0/g0;

    .line 218
    .line 219
    const/4 v2, 0x1

    .line 220
    move-object v3, p0

    .line 221
    move-object v4, p1

    .line 222
    move-object v5, p2

    .line 223
    move v1, p4

    .line 224
    invoke-direct/range {v0 .. v5}, Lxk0/g0;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 225
    .line 226
    .line 227
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 228
    .line 229
    :cond_12
    return-void
.end method

.method public static final d(Lx2/s;Lt2/b;Ll2/o;I)V
    .locals 3

    .line 1
    check-cast p2, Ll2/t;

    .line 2
    .line 3
    const v0, 0x52f9d6eb

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p3, 0x6

    .line 10
    .line 11
    if-nez v0, :cond_1

    .line 12
    .line 13
    invoke-virtual {p2, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    const/4 v0, 0x4

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v0, 0x2

    .line 22
    :goto_0
    or-int/2addr v0, p3

    .line 23
    goto :goto_1

    .line 24
    :cond_1
    move v0, p3

    .line 25
    :goto_1
    and-int/lit8 v1, p3, 0x30

    .line 26
    .line 27
    if-nez v1, :cond_3

    .line 28
    .line 29
    invoke-virtual {p2, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_2

    .line 34
    .line 35
    const/16 v1, 0x20

    .line 36
    .line 37
    goto :goto_2

    .line 38
    :cond_2
    const/16 v1, 0x10

    .line 39
    .line 40
    :goto_2
    or-int/2addr v0, v1

    .line 41
    :cond_3
    and-int/lit8 v1, v0, 0x13

    .line 42
    .line 43
    const/16 v2, 0x12

    .line 44
    .line 45
    if-eq v1, v2, :cond_4

    .line 46
    .line 47
    const/4 v1, 0x1

    .line 48
    goto :goto_3

    .line 49
    :cond_4
    const/4 v1, 0x0

    .line 50
    :goto_3
    and-int/lit8 v2, v0, 0x1

    .line 51
    .line 52
    invoke-virtual {p2, v2, v1}, Ll2/t;->O(IZ)Z

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    if-eqz v1, :cond_5

    .line 57
    .line 58
    sget-object v1, La2/n;->a:Ll2/e0;

    .line 59
    .line 60
    sget-object v2, Ly1/h;->a:Lt2/b;

    .line 61
    .line 62
    and-int/lit8 v2, v0, 0xe

    .line 63
    .line 64
    or-int/lit16 v2, v2, 0x1b0

    .line 65
    .line 66
    shl-int/lit8 v0, v0, 0x6

    .line 67
    .line 68
    and-int/lit16 v0, v0, 0x1c00

    .line 69
    .line 70
    or-int/2addr v0, v2

    .line 71
    invoke-static {p0, v1, p1, p2, v0}, Lb0/c;->b(Lx2/s;Ll2/s1;Lt2/b;Ll2/o;I)V

    .line 72
    .line 73
    .line 74
    goto :goto_4

    .line 75
    :cond_5
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 76
    .line 77
    .line 78
    :goto_4
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 79
    .line 80
    .line 81
    move-result-object p2

    .line 82
    if-eqz p2, :cond_6

    .line 83
    .line 84
    new-instance v0, Lew/a;

    .line 85
    .line 86
    const/4 v1, 0x5

    .line 87
    invoke-direct {v0, p0, p1, p3, v1}, Lew/a;-><init>(Lx2/s;Lt2/b;II)V

    .line 88
    .line 89
    .line 90
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 91
    .line 92
    :cond_6
    return-void
.end method
