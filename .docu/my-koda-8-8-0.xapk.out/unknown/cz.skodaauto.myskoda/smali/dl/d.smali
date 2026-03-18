.class public abstract Ldl/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F

.field public static final c:Lnm0/b;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const/16 v0, 0xd8

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Ldl/d;->a:F

    .line 5
    .line 6
    const/16 v0, 0x8

    .line 7
    .line 8
    int-to-float v0, v0

    .line 9
    sput v0, Ldl/d;->b:F

    .line 10
    .line 11
    new-instance v0, Lnm0/b;

    .line 12
    .line 13
    const/4 v1, 0x4

    .line 14
    invoke-direct {v0, v1}, Lnm0/b;-><init>(I)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Ldl/d;->c:Lnm0/b;

    .line 18
    .line 19
    return-void
.end method

.method public static final a(Landroidx/compose/foundation/layout/HorizontalAlignElement;Lay0/a;Ll2/o;I)V
    .locals 9

    .line 1
    move-object v7, p2

    .line 2
    check-cast v7, Ll2/t;

    .line 3
    .line 4
    const v1, 0x15ee7b20

    .line 5
    .line 6
    .line 7
    invoke-virtual {v7, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    invoke-virtual {v7, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-eqz v1, :cond_0

    .line 15
    .line 16
    const/4 v1, 0x4

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 v1, 0x2

    .line 19
    :goto_0
    or-int/2addr v1, p3

    .line 20
    invoke-virtual {v7, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    if-eqz v2, :cond_1

    .line 25
    .line 26
    const/16 v2, 0x20

    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_1
    const/16 v2, 0x10

    .line 30
    .line 31
    :goto_1
    or-int v8, v1, v2

    .line 32
    .line 33
    and-int/lit8 v1, v8, 0x13

    .line 34
    .line 35
    const/16 v2, 0x12

    .line 36
    .line 37
    if-eq v1, v2, :cond_2

    .line 38
    .line 39
    const/4 v1, 0x1

    .line 40
    goto :goto_2

    .line 41
    :cond_2
    const/4 v1, 0x0

    .line 42
    :goto_2
    and-int/lit8 v2, v8, 0x1

    .line 43
    .line 44
    invoke-virtual {v7, v2, v1}, Ll2/t;->O(IZ)Z

    .line 45
    .line 46
    .line 47
    move-result v1

    .line 48
    if-eqz v1, :cond_3

    .line 49
    .line 50
    sget-object v1, Lj91/a;->a:Ll2/u2;

    .line 51
    .line 52
    invoke-virtual {v7, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v2

    .line 56
    check-cast v2, Lj91/c;

    .line 57
    .line 58
    iget v2, v2, Lj91/c;->g:F

    .line 59
    .line 60
    invoke-virtual {v7, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    check-cast v1, Lj91/c;

    .line 65
    .line 66
    iget v1, v1, Lj91/c;->d:F

    .line 67
    .line 68
    const/4 v4, 0x0

    .line 69
    const/16 v5, 0xc

    .line 70
    .line 71
    const/4 v3, 0x0

    .line 72
    move-object v0, p0

    .line 73
    invoke-static/range {v0 .. v5}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    sget-object v5, Ldl/a;->a:Lt2/b;

    .line 78
    .line 79
    shr-int/lit8 v0, v8, 0x3

    .line 80
    .line 81
    and-int/lit8 v0, v0, 0xe

    .line 82
    .line 83
    const/high16 v2, 0x180000

    .line 84
    .line 85
    or-int/2addr v0, v2

    .line 86
    const/16 v8, 0x3c

    .line 87
    .line 88
    const/4 v2, 0x0

    .line 89
    const/4 v3, 0x0

    .line 90
    const/4 v4, 0x0

    .line 91
    move-object v6, v7

    .line 92
    move v7, v0

    .line 93
    move-object v0, p1

    .line 94
    invoke-static/range {v0 .. v8}, Lh2/r;->l(Lay0/a;Lx2/s;ZLh2/d5;Le3/n0;Lay0/n;Ll2/o;II)V

    .line 95
    .line 96
    .line 97
    goto :goto_3

    .line 98
    :cond_3
    move-object v6, v7

    .line 99
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 100
    .line 101
    .line 102
    :goto_3
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 103
    .line 104
    .line 105
    move-result-object v1

    .line 106
    if-eqz v1, :cond_4

    .line 107
    .line 108
    new-instance v2, Ld90/m;

    .line 109
    .line 110
    const/4 v3, 0x4

    .line 111
    invoke-direct {v2, p3, v3, p0, p1}, Ld90/m;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 112
    .line 113
    .line 114
    iput-object v2, v1, Ll2/u1;->d:Lay0/n;

    .line 115
    .line 116
    :cond_4
    return-void
.end method

.method public static final b(Ll2/o;I)V
    .locals 24

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    check-cast v1, Ll2/t;

    .line 4
    .line 5
    const v2, 0x367401c2

    .line 6
    .line 7
    .line 8
    invoke-virtual {v1, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 9
    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    const/4 v3, 0x1

    .line 13
    if-eqz p1, :cond_0

    .line 14
    .line 15
    move v4, v3

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    move v4, v2

    .line 18
    :goto_0
    and-int/lit8 v5, p1, 0x1

    .line 19
    .line 20
    invoke-virtual {v1, v5, v4}, Ll2/t;->O(IZ)Z

    .line 21
    .line 22
    .line 23
    move-result v4

    .line 24
    if-eqz v4, :cond_4

    .line 25
    .line 26
    invoke-static {v1}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 27
    .line 28
    .line 29
    move-result-object v4

    .line 30
    iget v4, v4, Lj91/c;->c:F

    .line 31
    .line 32
    invoke-static {v1}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 33
    .line 34
    .line 35
    move-result-object v5

    .line 36
    iget v5, v5, Lj91/c;->g:F

    .line 37
    .line 38
    sget-object v6, Lx2/p;->b:Lx2/p;

    .line 39
    .line 40
    invoke-static {v6, v4, v5}, Landroidx/compose/foundation/layout/a;->n(Lx2/s;FF)Lx2/s;

    .line 41
    .line 42
    .line 43
    move-result-object v4

    .line 44
    invoke-static {v1}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 45
    .line 46
    .line 47
    move-result-object v5

    .line 48
    iget v5, v5, Lj91/c;->h:F

    .line 49
    .line 50
    invoke-static {v4, v5}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 51
    .line 52
    .line 53
    move-result-object v4

    .line 54
    const/high16 v5, 0x3f800000    # 1.0f

    .line 55
    .line 56
    invoke-static {v4, v5}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 57
    .line 58
    .line 59
    move-result-object v4

    .line 60
    invoke-static {v1}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 61
    .line 62
    .line 63
    move-result-object v5

    .line 64
    invoke-virtual {v5}, Lj91/e;->b()J

    .line 65
    .line 66
    .line 67
    move-result-wide v5

    .line 68
    invoke-static {v1}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 69
    .line 70
    .line 71
    move-result-object v7

    .line 72
    iget v7, v7, Lj91/c;->b:F

    .line 73
    .line 74
    invoke-static {v7}, Ls1/f;->b(F)Ls1/e;

    .line 75
    .line 76
    .line 77
    move-result-object v7

    .line 78
    invoke-static {v4, v5, v6, v7}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 79
    .line 80
    .line 81
    move-result-object v4

    .line 82
    invoke-static {v1}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 83
    .line 84
    .line 85
    move-result-object v5

    .line 86
    iget v5, v5, Lj91/c;->d:F

    .line 87
    .line 88
    const/4 v6, 0x2

    .line 89
    const/4 v7, 0x0

    .line 90
    invoke-static {v4, v5, v7, v6}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 91
    .line 92
    .line 93
    move-result-object v4

    .line 94
    sget-object v5, Lx2/c;->g:Lx2/j;

    .line 95
    .line 96
    invoke-static {v5, v2}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 97
    .line 98
    .line 99
    move-result-object v2

    .line 100
    iget-wide v5, v1, Ll2/t;->T:J

    .line 101
    .line 102
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 103
    .line 104
    .line 105
    move-result v5

    .line 106
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 107
    .line 108
    .line 109
    move-result-object v6

    .line 110
    invoke-static {v1, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 111
    .line 112
    .line 113
    move-result-object v4

    .line 114
    sget-object v7, Lv3/k;->m1:Lv3/j;

    .line 115
    .line 116
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 117
    .line 118
    .line 119
    sget-object v7, Lv3/j;->b:Lv3/i;

    .line 120
    .line 121
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 122
    .line 123
    .line 124
    iget-boolean v8, v1, Ll2/t;->S:Z

    .line 125
    .line 126
    if-eqz v8, :cond_1

    .line 127
    .line 128
    invoke-virtual {v1, v7}, Ll2/t;->l(Lay0/a;)V

    .line 129
    .line 130
    .line 131
    goto :goto_1

    .line 132
    :cond_1
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 133
    .line 134
    .line 135
    :goto_1
    sget-object v7, Lv3/j;->g:Lv3/h;

    .line 136
    .line 137
    invoke-static {v7, v2, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 138
    .line 139
    .line 140
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 141
    .line 142
    invoke-static {v2, v6, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 143
    .line 144
    .line 145
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 146
    .line 147
    iget-boolean v6, v1, Ll2/t;->S:Z

    .line 148
    .line 149
    if-nez v6, :cond_2

    .line 150
    .line 151
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object v6

    .line 155
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 156
    .line 157
    .line 158
    move-result-object v7

    .line 159
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 160
    .line 161
    .line 162
    move-result v6

    .line 163
    if-nez v6, :cond_3

    .line 164
    .line 165
    :cond_2
    invoke-static {v5, v1, v5, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 166
    .line 167
    .line 168
    :cond_3
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 169
    .line 170
    invoke-static {v2, v4, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 171
    .line 172
    .line 173
    const v2, 0x7f120bd0

    .line 174
    .line 175
    .line 176
    invoke-static {v1, v2}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 177
    .line 178
    .line 179
    move-result-object v2

    .line 180
    invoke-static {v1}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 181
    .line 182
    .line 183
    move-result-object v4

    .line 184
    invoke-virtual {v4}, Lj91/f;->e()Lg4/p0;

    .line 185
    .line 186
    .line 187
    move-result-object v4

    .line 188
    invoke-static {v1}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 189
    .line 190
    .line 191
    move-result-object v5

    .line 192
    invoke-virtual {v5}, Lj91/e;->q()J

    .line 193
    .line 194
    .line 195
    move-result-wide v5

    .line 196
    const/16 v21, 0x0

    .line 197
    .line 198
    const v22, 0xfff4

    .line 199
    .line 200
    .line 201
    move v7, v3

    .line 202
    const/4 v3, 0x0

    .line 203
    move-object/from16 v19, v1

    .line 204
    .line 205
    move-object v1, v2

    .line 206
    move-object v2, v4

    .line 207
    move-wide v4, v5

    .line 208
    move v8, v7

    .line 209
    const-wide/16 v6, 0x0

    .line 210
    .line 211
    move v9, v8

    .line 212
    const/4 v8, 0x0

    .line 213
    move v11, v9

    .line 214
    const-wide/16 v9, 0x0

    .line 215
    .line 216
    move v12, v11

    .line 217
    const/4 v11, 0x0

    .line 218
    move v13, v12

    .line 219
    const/4 v12, 0x0

    .line 220
    move v15, v13

    .line 221
    const-wide/16 v13, 0x0

    .line 222
    .line 223
    move/from16 v16, v15

    .line 224
    .line 225
    const/4 v15, 0x0

    .line 226
    move/from16 v17, v16

    .line 227
    .line 228
    const/16 v16, 0x0

    .line 229
    .line 230
    move/from16 v18, v17

    .line 231
    .line 232
    const/16 v17, 0x0

    .line 233
    .line 234
    move/from16 v20, v18

    .line 235
    .line 236
    const/16 v18, 0x0

    .line 237
    .line 238
    move/from16 v23, v20

    .line 239
    .line 240
    const/16 v20, 0x0

    .line 241
    .line 242
    move/from16 v0, v23

    .line 243
    .line 244
    invoke-static/range {v1 .. v22}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 245
    .line 246
    .line 247
    move-object/from16 v1, v19

    .line 248
    .line 249
    invoke-virtual {v1, v0}, Ll2/t;->q(Z)V

    .line 250
    .line 251
    .line 252
    goto :goto_2

    .line 253
    :cond_4
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 254
    .line 255
    .line 256
    :goto_2
    invoke-virtual {v1}, Ll2/t;->s()Ll2/u1;

    .line 257
    .line 258
    .line 259
    move-result-object v0

    .line 260
    if-eqz v0, :cond_5

    .line 261
    .line 262
    new-instance v1, Ld80/m;

    .line 263
    .line 264
    const/16 v2, 0x14

    .line 265
    .line 266
    move/from16 v3, p1

    .line 267
    .line 268
    invoke-direct {v1, v3, v2}, Ld80/m;-><init>(II)V

    .line 269
    .line 270
    .line 271
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 272
    .line 273
    :cond_5
    return-void
.end method

.method public static final c(Ll2/o;I)V
    .locals 6

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    const v0, 0x210ee13c

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    if-eqz p1, :cond_0

    .line 10
    .line 11
    const/4 v0, 0x1

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 v0, 0x0

    .line 14
    :goto_0
    and-int/lit8 v1, p1, 0x1

    .line 15
    .line 16
    invoke-virtual {p0, v1, v0}, Ll2/t;->O(IZ)Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-eqz v0, :cond_1

    .line 21
    .line 22
    const/16 v0, 0x14

    .line 23
    .line 24
    int-to-float v0, v0

    .line 25
    sget-wide v1, Le3/s;->e:J

    .line 26
    .line 27
    sget v3, Ldl/d;->a:F

    .line 28
    .line 29
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 30
    .line 31
    invoke-static {v4, v3}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 32
    .line 33
    .line 34
    move-result-object v3

    .line 35
    new-instance v4, Ldl/c;

    .line 36
    .line 37
    const/4 v5, 0x0

    .line 38
    invoke-direct {v4, v1, v2, v5, v0}, Ldl/c;-><init>(JIF)V

    .line 39
    .line 40
    .line 41
    invoke-static {v3, v4}, Landroidx/compose/ui/draw/a;->a(Lx2/s;Lay0/k;)Lx2/s;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    invoke-static {p0, v0}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 46
    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_1
    invoke-virtual {p0}, Ll2/t;->R()V

    .line 50
    .line 51
    .line 52
    :goto_1
    invoke-virtual {p0}, Ll2/t;->s()Ll2/u1;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    if-eqz p0, :cond_2

    .line 57
    .line 58
    new-instance v0, Ld80/m;

    .line 59
    .line 60
    const/16 v1, 0x15

    .line 61
    .line 62
    invoke-direct {v0, p1, v1}, Ld80/m;-><init>(II)V

    .line 63
    .line 64
    .line 65
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 66
    .line 67
    :cond_2
    return-void
.end method

.method public static final d(Lrh/h;Lay0/a;Lay0/k;Lay0/a;Ll2/o;I)V
    .locals 10

    .line 1
    const-string v0, "scannerState"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "onManualCodeClick"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "onResult"

    .line 12
    .line 13
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "onDeniedSettings"

    .line 17
    .line 18
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    move-object v8, p4

    .line 22
    check-cast v8, Ll2/t;

    .line 23
    .line 24
    const v0, 0x313cdb13

    .line 25
    .line 26
    .line 27
    invoke-virtual {v8, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v8, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-eqz v0, :cond_0

    .line 35
    .line 36
    const/4 v0, 0x4

    .line 37
    goto :goto_0

    .line 38
    :cond_0
    const/4 v0, 0x2

    .line 39
    :goto_0
    or-int/2addr v0, p5

    .line 40
    invoke-virtual {v8, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    if-eqz v1, :cond_1

    .line 45
    .line 46
    const/16 v1, 0x20

    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_1
    const/16 v1, 0x10

    .line 50
    .line 51
    :goto_1
    or-int/2addr v0, v1

    .line 52
    invoke-virtual {v8, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    if-eqz v1, :cond_2

    .line 57
    .line 58
    const/16 v1, 0x100

    .line 59
    .line 60
    goto :goto_2

    .line 61
    :cond_2
    const/16 v1, 0x80

    .line 62
    .line 63
    :goto_2
    or-int/2addr v0, v1

    .line 64
    invoke-virtual {v8, p3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v1

    .line 68
    if-eqz v1, :cond_3

    .line 69
    .line 70
    const/16 v1, 0x800

    .line 71
    .line 72
    goto :goto_3

    .line 73
    :cond_3
    const/16 v1, 0x400

    .line 74
    .line 75
    :goto_3
    or-int/2addr v0, v1

    .line 76
    and-int/lit16 v1, v0, 0x493

    .line 77
    .line 78
    const/16 v2, 0x492

    .line 79
    .line 80
    const/4 v4, 0x0

    .line 81
    const/4 v5, 0x1

    .line 82
    if-eq v1, v2, :cond_4

    .line 83
    .line 84
    move v1, v5

    .line 85
    goto :goto_4

    .line 86
    :cond_4
    move v1, v4

    .line 87
    :goto_4
    and-int/lit8 v2, v0, 0x1

    .line 88
    .line 89
    invoke-virtual {v8, v2, v1}, Ll2/t;->O(IZ)Z

    .line 90
    .line 91
    .line 92
    move-result v1

    .line 93
    if-eqz v1, :cond_9

    .line 94
    .line 95
    invoke-static {v8}, Ljp/gf;->b(Ll2/o;)Lqb/c;

    .line 96
    .line 97
    .line 98
    move-result-object v1

    .line 99
    sget-object v2, Lqb/a;->e:Lqb/a;

    .line 100
    .line 101
    invoke-virtual {v8, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    move-result v2

    .line 105
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v6

    .line 109
    sget-object v7, Ll2/n;->a:Ll2/x0;

    .line 110
    .line 111
    if-nez v2, :cond_5

    .line 112
    .line 113
    if-ne v6, v7, :cond_6

    .line 114
    .line 115
    :cond_5
    new-instance v6, Ldl/b;

    .line 116
    .line 117
    invoke-direct {v6, v1, v4}, Ldl/b;-><init>(Lqb/c;I)V

    .line 118
    .line 119
    .line 120
    invoke-virtual {v8, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 121
    .line 122
    .line 123
    :cond_6
    move-object v4, v6

    .line 124
    check-cast v4, Lay0/a;

    .line 125
    .line 126
    invoke-virtual {v8, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 127
    .line 128
    .line 129
    move-result v2

    .line 130
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v6

    .line 134
    if-nez v2, :cond_7

    .line 135
    .line 136
    if-ne v6, v7, :cond_8

    .line 137
    .line 138
    :cond_7
    new-instance v6, Ldl/b;

    .line 139
    .line 140
    invoke-direct {v6, v1, v5}, Ldl/b;-><init>(Lqb/c;I)V

    .line 141
    .line 142
    .line 143
    invoke-virtual {v8, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 144
    .line 145
    .line 146
    :cond_8
    move-object v5, v6

    .line 147
    check-cast v5, Lay0/a;

    .line 148
    .line 149
    new-instance v1, Lal/d;

    .line 150
    .line 151
    const/16 v2, 0x19

    .line 152
    .line 153
    invoke-direct {v1, v2, p1, p0}, Lal/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    const v2, 0xb8ad331

    .line 157
    .line 158
    .line 159
    invoke-static {v2, v8, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 160
    .line 161
    .line 162
    move-result-object v7

    .line 163
    shr-int/lit8 v1, v0, 0x3

    .line 164
    .line 165
    and-int/lit8 v1, v1, 0x70

    .line 166
    .line 167
    const v2, 0x6000006

    .line 168
    .line 169
    .line 170
    or-int/2addr v1, v2

    .line 171
    const v2, 0xe000

    .line 172
    .line 173
    .line 174
    shl-int/lit8 v0, v0, 0x3

    .line 175
    .line 176
    and-int/2addr v0, v2

    .line 177
    or-int v9, v1, v0

    .line 178
    .line 179
    const/4 v1, 0x0

    .line 180
    const/4 v2, 0x0

    .line 181
    const/4 v6, 0x0

    .line 182
    move-object v0, p2

    .line 183
    move-object v3, p3

    .line 184
    invoke-static/range {v0 .. v9}, Ljp/ff;->a(Lay0/k;Lx2/s;Lqb/c;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lt2/b;Ll2/o;I)V

    .line 185
    .line 186
    .line 187
    goto :goto_5

    .line 188
    :cond_9
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 189
    .line 190
    .line 191
    :goto_5
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 192
    .line 193
    .line 194
    move-result-object v7

    .line 195
    if-eqz v7, :cond_a

    .line 196
    .line 197
    new-instance v0, Laj0/b;

    .line 198
    .line 199
    const/16 v6, 0xa

    .line 200
    .line 201
    move-object v1, p0

    .line 202
    move-object v2, p1

    .line 203
    move-object v3, p2

    .line 204
    move-object v4, p3

    .line 205
    move v5, p5

    .line 206
    invoke-direct/range {v0 .. v6}, Laj0/b;-><init>(Ljava/lang/Object;Lay0/a;Lay0/k;Llx0/e;II)V

    .line 207
    .line 208
    .line 209
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 210
    .line 211
    :cond_a
    return-void
.end method

.method public static final e(Lg3/d;FFJ)V
    .locals 15

    .line 1
    move/from16 v0, p1

    .line 2
    .line 3
    invoke-static {}, Le3/l;->a()Le3/i;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    const/4 v2, 0x0

    .line 8
    invoke-virtual {v1, v0, v2}, Le3/i;->h(FF)V

    .line 9
    .line 10
    .line 11
    iget-object v3, v1, Le3/i;->b:Landroid/graphics/RectF;

    .line 12
    .line 13
    if-nez v3, :cond_0

    .line 14
    .line 15
    new-instance v3, Landroid/graphics/RectF;

    .line 16
    .line 17
    invoke-direct {v3}, Landroid/graphics/RectF;-><init>()V

    .line 18
    .line 19
    .line 20
    iput-object v3, v1, Le3/i;->b:Landroid/graphics/RectF;

    .line 21
    .line 22
    :cond_0
    iget-object v3, v1, Le3/i;->b:Landroid/graphics/RectF;

    .line 23
    .line 24
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    move/from16 v4, p2

    .line 28
    .line 29
    invoke-virtual {v3, v2, v2, v4, v4}, Landroid/graphics/RectF;->set(FFFF)V

    .line 30
    .line 31
    .line 32
    iget-object v3, v1, Le3/i;->a:Landroid/graphics/Path;

    .line 33
    .line 34
    iget-object v4, v1, Le3/i;->b:Landroid/graphics/RectF;

    .line 35
    .line 36
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    const/high16 v5, 0x43870000    # 270.0f

    .line 40
    .line 41
    const/high16 v6, -0x3d4c0000    # -90.0f

    .line 42
    .line 43
    const/4 v7, 0x0

    .line 44
    invoke-virtual {v3, v4, v5, v6, v7}, Landroid/graphics/Path;->arcTo(Landroid/graphics/RectF;FFZ)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {v1, v2, v0}, Le3/i;->g(FF)V

    .line 48
    .line 49
    .line 50
    new-instance v5, Lg3/h;

    .line 51
    .line 52
    const/4 v0, 0x3

    .line 53
    int-to-float v0, v0

    .line 54
    invoke-interface {p0, v0}, Lt4/c;->w0(F)F

    .line 55
    .line 56
    .line 57
    move-result v9

    .line 58
    const/4 v13, 0x0

    .line 59
    const/16 v14, 0x12

    .line 60
    .line 61
    const/4 v10, 0x0

    .line 62
    const/4 v11, 0x1

    .line 63
    const/4 v12, 0x0

    .line 64
    move-object v8, v5

    .line 65
    invoke-direct/range {v8 .. v14}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 66
    .line 67
    .line 68
    const/16 v6, 0x34

    .line 69
    .line 70
    const/4 v4, 0x0

    .line 71
    move-object v0, p0

    .line 72
    move-wide/from16 v2, p3

    .line 73
    .line 74
    invoke-static/range {v0 .. v6}, Lg3/d;->K0(Lg3/d;Le3/i;JFLg3/e;I)V

    .line 75
    .line 76
    .line 77
    return-void
.end method
