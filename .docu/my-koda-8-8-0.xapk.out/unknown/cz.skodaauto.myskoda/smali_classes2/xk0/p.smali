.class public abstract Lxk0/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x7a

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Lxk0/p;->a:F

    .line 5
    .line 6
    return-void
.end method

.method public static final a(ILjava/util/List;Lay0/a;Ll2/o;I)V
    .locals 4

    .line 1
    check-cast p3, Ll2/t;

    .line 2
    .line 3
    const v0, 0x68b1cf93

    .line 4
    .line 5
    .line 6
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p4, 0x6

    .line 10
    .line 11
    if-nez v0, :cond_1

    .line 12
    .line 13
    invoke-virtual {p3, p0}, Ll2/t;->e(I)Z

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
    or-int/2addr v0, p4

    .line 23
    goto :goto_1

    .line 24
    :cond_1
    move v0, p4

    .line 25
    :goto_1
    and-int/lit8 v1, p4, 0x30

    .line 26
    .line 27
    if-nez v1, :cond_3

    .line 28
    .line 29
    invoke-virtual {p3, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

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
    and-int/lit16 v1, p4, 0x180

    .line 42
    .line 43
    if-nez v1, :cond_5

    .line 44
    .line 45
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    if-eqz v1, :cond_4

    .line 50
    .line 51
    const/16 v1, 0x100

    .line 52
    .line 53
    goto :goto_3

    .line 54
    :cond_4
    const/16 v1, 0x80

    .line 55
    .line 56
    :goto_3
    or-int/2addr v0, v1

    .line 57
    :cond_5
    and-int/lit16 v1, v0, 0x93

    .line 58
    .line 59
    const/16 v2, 0x92

    .line 60
    .line 61
    const/4 v3, 0x1

    .line 62
    if-eq v1, v2, :cond_6

    .line 63
    .line 64
    move v1, v3

    .line 65
    goto :goto_4

    .line 66
    :cond_6
    const/4 v1, 0x0

    .line 67
    :goto_4
    and-int/lit8 v2, v0, 0x1

    .line 68
    .line 69
    invoke-virtual {p3, v2, v1}, Ll2/t;->O(IZ)Z

    .line 70
    .line 71
    .line 72
    move-result v1

    .line 73
    if-eqz v1, :cond_7

    .line 74
    .line 75
    new-instance v1, Lx4/p;

    .line 76
    .line 77
    invoke-direct {v1, v3}, Lx4/p;-><init>(I)V

    .line 78
    .line 79
    .line 80
    new-instance v2, Lsm0/b;

    .line 81
    .line 82
    invoke-direct {v2, p0, p1, p2}, Lsm0/b;-><init>(ILjava/util/List;Lay0/a;)V

    .line 83
    .line 84
    .line 85
    const v3, -0x2d87e016

    .line 86
    .line 87
    .line 88
    invoke-static {v3, p3, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 89
    .line 90
    .line 91
    move-result-object v2

    .line 92
    shr-int/lit8 v0, v0, 0x6

    .line 93
    .line 94
    and-int/lit8 v0, v0, 0xe

    .line 95
    .line 96
    or-int/lit16 v0, v0, 0x1b0

    .line 97
    .line 98
    invoke-static {p2, v1, v2, p3, v0}, Llp/ge;->a(Lay0/a;Lx4/p;Lt2/b;Ll2/o;I)V

    .line 99
    .line 100
    .line 101
    goto :goto_5

    .line 102
    :cond_7
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 103
    .line 104
    .line 105
    :goto_5
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 106
    .line 107
    .line 108
    move-result-object p3

    .line 109
    if-eqz p3, :cond_8

    .line 110
    .line 111
    new-instance v0, Lck/h;

    .line 112
    .line 113
    invoke-direct {v0, p0, p4, p2, p1}, Lck/h;-><init>(IILay0/a;Ljava/util/List;)V

    .line 114
    .line 115
    .line 116
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 117
    .line 118
    :cond_8
    return-void
.end method

.method public static final b(Ljava/util/List;Lx2/s;Ll2/o;I)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p3

    .line 4
    .line 5
    const-string v2, "images"

    .line 6
    .line 7
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    move-object/from16 v12, p2

    .line 11
    .line 12
    check-cast v12, Ll2/t;

    .line 13
    .line 14
    const v2, -0x39b706b7

    .line 15
    .line 16
    .line 17
    invoke-virtual {v12, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v12, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    const/4 v3, 0x2

    .line 25
    if-eqz v2, :cond_0

    .line 26
    .line 27
    const/4 v2, 0x4

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    move v2, v3

    .line 30
    :goto_0
    or-int/2addr v2, v1

    .line 31
    or-int/lit8 v2, v2, 0x30

    .line 32
    .line 33
    and-int/lit8 v4, v2, 0x13

    .line 34
    .line 35
    const/16 v5, 0x12

    .line 36
    .line 37
    const/4 v15, 0x0

    .line 38
    if-eq v4, v5, :cond_1

    .line 39
    .line 40
    const/4 v4, 0x1

    .line 41
    goto :goto_1

    .line 42
    :cond_1
    move v4, v15

    .line 43
    :goto_1
    and-int/lit8 v5, v2, 0x1

    .line 44
    .line 45
    invoke-virtual {v12, v5, v4}, Ll2/t;->O(IZ)Z

    .line 46
    .line 47
    .line 48
    move-result v4

    .line 49
    if-eqz v4, :cond_8

    .line 50
    .line 51
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v4

    .line 55
    sget-object v5, Ll2/n;->a:Ll2/x0;

    .line 56
    .line 57
    if-ne v4, v5, :cond_2

    .line 58
    .line 59
    const/4 v4, 0x0

    .line 60
    invoke-static {v4}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 61
    .line 62
    .line 63
    move-result-object v4

    .line 64
    invoke-virtual {v12, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    :cond_2
    check-cast v4, Ll2/b1;

    .line 68
    .line 69
    sget-object v6, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->a:Ll2/e0;

    .line 70
    .line 71
    invoke-virtual {v12, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v6

    .line 75
    check-cast v6, Landroid/content/res/Configuration;

    .line 76
    .line 77
    iget v6, v6, Landroid/content/res/Configuration;->smallestScreenWidthDp:I

    .line 78
    .line 79
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v7

    .line 83
    check-cast v7, Ljava/lang/Integer;

    .line 84
    .line 85
    if-nez v7, :cond_3

    .line 86
    .line 87
    const v2, -0x59f2a9c1

    .line 88
    .line 89
    .line 90
    invoke-virtual {v12, v2}, Ll2/t;->Y(I)V

    .line 91
    .line 92
    .line 93
    :goto_2
    invoke-virtual {v12, v15}, Ll2/t;->q(Z)V

    .line 94
    .line 95
    .line 96
    goto :goto_3

    .line 97
    :cond_3
    const v8, -0x59f2a9c0

    .line 98
    .line 99
    .line 100
    invoke-virtual {v12, v8}, Ll2/t;->Y(I)V

    .line 101
    .line 102
    .line 103
    invoke-virtual {v7}, Ljava/lang/Number;->intValue()I

    .line 104
    .line 105
    .line 106
    move-result v7

    .line 107
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v8

    .line 111
    if-ne v8, v5, :cond_4

    .line 112
    .line 113
    new-instance v8, Lio0/f;

    .line 114
    .line 115
    const/16 v9, 0x1b

    .line 116
    .line 117
    invoke-direct {v8, v4, v9}, Lio0/f;-><init>(Ll2/b1;I)V

    .line 118
    .line 119
    .line 120
    invoke-virtual {v12, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 121
    .line 122
    .line 123
    :cond_4
    check-cast v8, Lay0/a;

    .line 124
    .line 125
    shl-int/lit8 v2, v2, 0x3

    .line 126
    .line 127
    and-int/lit8 v2, v2, 0x70

    .line 128
    .line 129
    or-int/lit16 v2, v2, 0x180

    .line 130
    .line 131
    invoke-static {v7, v0, v8, v12, v2}, Lxk0/p;->a(ILjava/util/List;Lay0/a;Ll2/o;I)V

    .line 132
    .line 133
    .line 134
    goto :goto_2

    .line 135
    :goto_3
    move-object v2, v0

    .line 136
    check-cast v2, Ljava/util/Collection;

    .line 137
    .line 138
    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    .line 139
    .line 140
    .line 141
    move-result v2

    .line 142
    sget-object v7, Lx2/p;->b:Lx2/p;

    .line 143
    .line 144
    if-nez v2, :cond_7

    .line 145
    .line 146
    const v2, -0x59ef6aaf

    .line 147
    .line 148
    .line 149
    invoke-virtual {v12, v2}, Ll2/t;->Y(I)V

    .line 150
    .line 151
    .line 152
    sget-object v2, Lk1/j;->a:Lk1/c;

    .line 153
    .line 154
    sget-object v2, Lj91/a;->a:Ll2/u2;

    .line 155
    .line 156
    invoke-virtual {v12, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v8

    .line 160
    check-cast v8, Lj91/c;

    .line 161
    .line 162
    iget v8, v8, Lj91/c;->c:F

    .line 163
    .line 164
    invoke-static {v8}, Lk1/j;->g(F)Lk1/h;

    .line 165
    .line 166
    .line 167
    move-result-object v8

    .line 168
    invoke-virtual {v12, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 169
    .line 170
    .line 171
    move-result-object v2

    .line 172
    check-cast v2, Lj91/c;

    .line 173
    .line 174
    iget v2, v2, Lj91/c;->j:F

    .line 175
    .line 176
    const/4 v9, 0x0

    .line 177
    invoke-static {v2, v9, v3}, Landroidx/compose/foundation/layout/a;->a(FFI)Lk1/a1;

    .line 178
    .line 179
    .line 180
    move-result-object v2

    .line 181
    const/high16 v3, 0x3f800000    # 1.0f

    .line 182
    .line 183
    invoke-static {v7, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 184
    .line 185
    .line 186
    move-result-object v3

    .line 187
    invoke-virtual {v12, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 188
    .line 189
    .line 190
    move-result v9

    .line 191
    invoke-virtual {v12, v6}, Ll2/t;->e(I)Z

    .line 192
    .line 193
    .line 194
    move-result v10

    .line 195
    or-int/2addr v9, v10

    .line 196
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 197
    .line 198
    .line 199
    move-result-object v10

    .line 200
    if-nez v9, :cond_5

    .line 201
    .line 202
    if-ne v10, v5, :cond_6

    .line 203
    .line 204
    :cond_5
    new-instance v10, Le1/i1;

    .line 205
    .line 206
    invoke-direct {v10, v0, v4, v6}, Le1/i1;-><init>(Ljava/util/List;Ll2/b1;I)V

    .line 207
    .line 208
    .line 209
    invoke-virtual {v12, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 210
    .line 211
    .line 212
    :cond_6
    move-object v11, v10

    .line 213
    check-cast v11, Lay0/k;

    .line 214
    .line 215
    const/4 v13, 0x0

    .line 216
    const/16 v14, 0x1ea

    .line 217
    .line 218
    const/4 v4, 0x0

    .line 219
    move-object v5, v7

    .line 220
    const/4 v7, 0x0

    .line 221
    move-object v6, v8

    .line 222
    const/4 v8, 0x0

    .line 223
    const/4 v9, 0x0

    .line 224
    const/4 v10, 0x0

    .line 225
    move-object/from16 v16, v5

    .line 226
    .line 227
    move-object v5, v2

    .line 228
    move-object/from16 v2, v16

    .line 229
    .line 230
    invoke-static/range {v3 .. v14}, La/a;->b(Lx2/s;Lm1/t;Lk1/z0;Lk1/g;Lx2/i;Lg1/j1;ZLe1/j;Lay0/k;Ll2/o;II)V

    .line 231
    .line 232
    .line 233
    :goto_4
    invoke-virtual {v12, v15}, Ll2/t;->q(Z)V

    .line 234
    .line 235
    .line 236
    goto :goto_5

    .line 237
    :cond_7
    move-object v2, v7

    .line 238
    const v3, -0x5a110de7

    .line 239
    .line 240
    .line 241
    invoke-virtual {v12, v3}, Ll2/t;->Y(I)V

    .line 242
    .line 243
    .line 244
    goto :goto_4

    .line 245
    :cond_8
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 246
    .line 247
    .line 248
    move-object/from16 v2, p1

    .line 249
    .line 250
    :goto_5
    invoke-virtual {v12}, Ll2/t;->s()Ll2/u1;

    .line 251
    .line 252
    .line 253
    move-result-object v3

    .line 254
    if-eqz v3, :cond_9

    .line 255
    .line 256
    new-instance v4, Lx40/n;

    .line 257
    .line 258
    const/16 v5, 0x9

    .line 259
    .line 260
    invoke-direct {v4, v1, v5, v0, v2}, Lx40/n;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 261
    .line 262
    .line 263
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 264
    .line 265
    :cond_9
    return-void
.end method
