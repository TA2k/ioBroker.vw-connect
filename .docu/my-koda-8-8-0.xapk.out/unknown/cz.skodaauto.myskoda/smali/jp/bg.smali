.class public abstract Ljp/bg;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(IILl2/o;)V
    .locals 9

    .line 1
    move-object v5, p2

    .line 2
    check-cast v5, Ll2/t;

    .line 3
    .line 4
    const p2, 0x1c149e43

    .line 5
    .line 6
    .line 7
    invoke-virtual {v5, p2}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    and-int/lit8 p2, p1, 0x6

    .line 11
    .line 12
    const/4 v0, 0x2

    .line 13
    if-nez p2, :cond_1

    .line 14
    .line 15
    invoke-virtual {v5, p0}, Ll2/t;->e(I)Z

    .line 16
    .line 17
    .line 18
    move-result p2

    .line 19
    if-eqz p2, :cond_0

    .line 20
    .line 21
    const/4 p2, 0x4

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    move p2, v0

    .line 24
    :goto_0
    or-int/2addr p2, p1

    .line 25
    goto :goto_1

    .line 26
    :cond_1
    move p2, p1

    .line 27
    :goto_1
    and-int/lit8 v1, p2, 0x3

    .line 28
    .line 29
    const/4 v2, 0x1

    .line 30
    const/4 v8, 0x0

    .line 31
    if-eq v1, v0, :cond_2

    .line 32
    .line 33
    move v1, v2

    .line 34
    goto :goto_2

    .line 35
    :cond_2
    move v1, v8

    .line 36
    :goto_2
    and-int/2addr p2, v2

    .line 37
    invoke-virtual {v5, p2, v1}, Ll2/t;->O(IZ)Z

    .line 38
    .line 39
    .line 40
    move-result p2

    .line 41
    if-eqz p2, :cond_8

    .line 42
    .line 43
    if-eqz p0, :cond_6

    .line 44
    .line 45
    if-eq p0, v2, :cond_5

    .line 46
    .line 47
    if-eq p0, v0, :cond_4

    .line 48
    .line 49
    const/4 p2, 0x3

    .line 50
    if-eq p0, p2, :cond_3

    .line 51
    .line 52
    const/4 p2, 0x0

    .line 53
    goto :goto_3

    .line 54
    :cond_3
    const p2, 0x7f0805d7

    .line 55
    .line 56
    .line 57
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 58
    .line 59
    .line 60
    move-result-object p2

    .line 61
    goto :goto_3

    .line 62
    :cond_4
    const p2, 0x7f0805d6

    .line 63
    .line 64
    .line 65
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 66
    .line 67
    .line 68
    move-result-object p2

    .line 69
    goto :goto_3

    .line 70
    :cond_5
    const p2, 0x7f0805d5

    .line 71
    .line 72
    .line 73
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 74
    .line 75
    .line 76
    move-result-object p2

    .line 77
    goto :goto_3

    .line 78
    :cond_6
    const p2, 0x7f0805d4

    .line 79
    .line 80
    .line 81
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 82
    .line 83
    .line 84
    move-result-object p2

    .line 85
    :goto_3
    if-nez p2, :cond_7

    .line 86
    .line 87
    const p2, -0x3c9e5112

    .line 88
    .line 89
    .line 90
    invoke-virtual {v5, p2}, Ll2/t;->Y(I)V

    .line 91
    .line 92
    .line 93
    :goto_4
    invoke-virtual {v5, v8}, Ll2/t;->q(Z)V

    .line 94
    .line 95
    .line 96
    goto :goto_5

    .line 97
    :cond_7
    const v0, -0x3c9e5111

    .line 98
    .line 99
    .line 100
    invoke-virtual {v5, v0}, Ll2/t;->Y(I)V

    .line 101
    .line 102
    .line 103
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 104
    .line 105
    .line 106
    move-result p2

    .line 107
    invoke-static {p2, v8, v5}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 108
    .line 109
    .line 110
    move-result-object v0

    .line 111
    sget-object p2, Lj91/j;->a:Ll2/u2;

    .line 112
    .line 113
    invoke-virtual {v5, p2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object p2

    .line 117
    check-cast p2, Lj91/f;

    .line 118
    .line 119
    invoke-virtual {p2}, Lj91/f;->i()Lg4/p0;

    .line 120
    .line 121
    .line 122
    move-result-object p2

    .line 123
    invoke-virtual {p2}, Lg4/p0;->b()J

    .line 124
    .line 125
    .line 126
    move-result-wide v3

    .line 127
    const/16 v6, 0x30

    .line 128
    .line 129
    const/4 v7, 0x4

    .line 130
    const/4 v1, 0x0

    .line 131
    const/4 v2, 0x0

    .line 132
    invoke-static/range {v0 .. v7}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 133
    .line 134
    .line 135
    goto :goto_4

    .line 136
    :cond_8
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 137
    .line 138
    .line 139
    :goto_5
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 140
    .line 141
    .line 142
    move-result-object p2

    .line 143
    if-eqz p2, :cond_9

    .line 144
    .line 145
    new-instance v0, Ld90/i;

    .line 146
    .line 147
    const/4 v1, 0x0

    .line 148
    invoke-direct {v0, p0, p1, v1}, Ld90/i;-><init>(III)V

    .line 149
    .line 150
    .line 151
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 152
    .line 153
    :cond_9
    return-void
.end method

.method public static final b(Lb90/d;ILl2/o;I)V
    .locals 25

    .line 1
    move/from16 v0, p1

    .line 2
    .line 3
    move/from16 v1, p3

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    check-cast v2, Ll2/t;

    .line 8
    .line 9
    const v3, -0x6b8297de

    .line 10
    .line 11
    .line 12
    invoke-virtual {v2, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    invoke-virtual/range {p0 .. p0}, Ljava/lang/Enum;->ordinal()I

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    invoke-virtual {v2, v3}, Ll2/t;->e(I)Z

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    const/4 v4, 0x2

    .line 24
    if-eqz v3, :cond_0

    .line 25
    .line 26
    const/4 v3, 0x4

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    move v3, v4

    .line 29
    :goto_0
    or-int/2addr v3, v1

    .line 30
    invoke-virtual {v2, v0}, Ll2/t;->e(I)Z

    .line 31
    .line 32
    .line 33
    move-result v5

    .line 34
    if-eqz v5, :cond_1

    .line 35
    .line 36
    const/16 v5, 0x20

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_1
    const/16 v5, 0x10

    .line 40
    .line 41
    :goto_1
    or-int/2addr v3, v5

    .line 42
    and-int/lit8 v5, v3, 0x13

    .line 43
    .line 44
    const/16 v6, 0x12

    .line 45
    .line 46
    const/4 v7, 0x0

    .line 47
    const/4 v8, 0x1

    .line 48
    if-eq v5, v6, :cond_2

    .line 49
    .line 50
    move v5, v8

    .line 51
    goto :goto_2

    .line 52
    :cond_2
    move v5, v7

    .line 53
    :goto_2
    and-int/lit8 v6, v3, 0x1

    .line 54
    .line 55
    invoke-virtual {v2, v6, v5}, Ll2/t;->O(IZ)Z

    .line 56
    .line 57
    .line 58
    move-result v5

    .line 59
    if-eqz v5, :cond_a

    .line 60
    .line 61
    sget-object v5, Lx2/c;->n:Lx2/i;

    .line 62
    .line 63
    sget-object v6, Lk1/j;->a:Lk1/c;

    .line 64
    .line 65
    const/16 v9, 0x30

    .line 66
    .line 67
    invoke-static {v6, v5, v2, v9}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 68
    .line 69
    .line 70
    move-result-object v5

    .line 71
    iget-wide v9, v2, Ll2/t;->T:J

    .line 72
    .line 73
    invoke-static {v9, v10}, Ljava/lang/Long;->hashCode(J)I

    .line 74
    .line 75
    .line 76
    move-result v6

    .line 77
    invoke-virtual {v2}, Ll2/t;->m()Ll2/p1;

    .line 78
    .line 79
    .line 80
    move-result-object v9

    .line 81
    sget-object v10, Lx2/p;->b:Lx2/p;

    .line 82
    .line 83
    invoke-static {v2, v10}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 84
    .line 85
    .line 86
    move-result-object v11

    .line 87
    sget-object v12, Lv3/k;->m1:Lv3/j;

    .line 88
    .line 89
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 90
    .line 91
    .line 92
    sget-object v12, Lv3/j;->b:Lv3/i;

    .line 93
    .line 94
    invoke-virtual {v2}, Ll2/t;->c0()V

    .line 95
    .line 96
    .line 97
    iget-boolean v13, v2, Ll2/t;->S:Z

    .line 98
    .line 99
    if-eqz v13, :cond_3

    .line 100
    .line 101
    invoke-virtual {v2, v12}, Ll2/t;->l(Lay0/a;)V

    .line 102
    .line 103
    .line 104
    goto :goto_3

    .line 105
    :cond_3
    invoke-virtual {v2}, Ll2/t;->m0()V

    .line 106
    .line 107
    .line 108
    :goto_3
    sget-object v12, Lv3/j;->g:Lv3/h;

    .line 109
    .line 110
    invoke-static {v12, v5, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 111
    .line 112
    .line 113
    sget-object v5, Lv3/j;->f:Lv3/h;

    .line 114
    .line 115
    invoke-static {v5, v9, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 116
    .line 117
    .line 118
    sget-object v5, Lv3/j;->j:Lv3/h;

    .line 119
    .line 120
    iget-boolean v9, v2, Ll2/t;->S:Z

    .line 121
    .line 122
    if-nez v9, :cond_4

    .line 123
    .line 124
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v9

    .line 128
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 129
    .line 130
    .line 131
    move-result-object v12

    .line 132
    invoke-static {v9, v12}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    move-result v9

    .line 136
    if-nez v9, :cond_5

    .line 137
    .line 138
    :cond_4
    invoke-static {v6, v2, v6, v5}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 139
    .line 140
    .line 141
    :cond_5
    sget-object v5, Lv3/j;->d:Lv3/h;

    .line 142
    .line 143
    invoke-static {v5, v11, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 144
    .line 145
    .line 146
    const/4 v5, 0x3

    .line 147
    shr-int/2addr v3, v5

    .line 148
    and-int/lit8 v3, v3, 0xe

    .line 149
    .line 150
    invoke-static {v0, v3, v2}, Ljp/bg;->a(IILl2/o;)V

    .line 151
    .line 152
    .line 153
    sget-object v3, Lj91/a;->a:Ll2/u2;

    .line 154
    .line 155
    invoke-virtual {v2, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object v3

    .line 159
    check-cast v3, Lj91/c;

    .line 160
    .line 161
    iget v3, v3, Lj91/c;->c:F

    .line 162
    .line 163
    invoke-static {v10, v3}, Landroidx/compose/foundation/layout/d;->r(Lx2/s;F)Lx2/s;

    .line 164
    .line 165
    .line 166
    move-result-object v3

    .line 167
    invoke-static {v2, v3}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 168
    .line 169
    .line 170
    invoke-virtual/range {p0 .. p0}, Ljava/lang/Enum;->ordinal()I

    .line 171
    .line 172
    .line 173
    move-result v3

    .line 174
    if-eqz v3, :cond_9

    .line 175
    .line 176
    if-eq v3, v8, :cond_8

    .line 177
    .line 178
    if-eq v3, v4, :cond_7

    .line 179
    .line 180
    if-eq v3, v5, :cond_6

    .line 181
    .line 182
    const v3, -0x227c6ddf

    .line 183
    .line 184
    .line 185
    invoke-virtual {v2, v3}, Ll2/t;->Y(I)V

    .line 186
    .line 187
    .line 188
    invoke-virtual {v2, v7}, Ll2/t;->q(Z)V

    .line 189
    .line 190
    .line 191
    const-string v3, ""

    .line 192
    .line 193
    goto :goto_4

    .line 194
    :cond_6
    const v3, -0x95ee369

    .line 195
    .line 196
    .line 197
    const v4, 0x7f1212c3

    .line 198
    .line 199
    .line 200
    invoke-static {v3, v4, v2, v2, v7}, Lvj/b;->g(IILl2/t;Ll2/t;Z)Ljava/lang/String;

    .line 201
    .line 202
    .line 203
    move-result-object v3

    .line 204
    goto :goto_4

    .line 205
    :cond_7
    const v3, -0x95eef68

    .line 206
    .line 207
    .line 208
    const v4, 0x7f1212c4

    .line 209
    .line 210
    .line 211
    invoke-static {v3, v4, v2, v2, v7}, Lvj/b;->g(IILl2/t;Ll2/t;Z)Ljava/lang/String;

    .line 212
    .line 213
    .line 214
    move-result-object v3

    .line 215
    goto :goto_4

    .line 216
    :cond_8
    const v3, -0x95efc28

    .line 217
    .line 218
    .line 219
    const v4, 0x7f1212c5

    .line 220
    .line 221
    .line 222
    invoke-static {v3, v4, v2, v2, v7}, Lvj/b;->g(IILl2/t;Ll2/t;Z)Ljava/lang/String;

    .line 223
    .line 224
    .line 225
    move-result-object v3

    .line 226
    goto :goto_4

    .line 227
    :cond_9
    const v3, -0x95f07eb

    .line 228
    .line 229
    .line 230
    const v4, 0x7f1212c6

    .line 231
    .line 232
    .line 233
    invoke-static {v3, v4, v2, v2, v7}, Lvj/b;->g(IILl2/t;Ll2/t;Z)Ljava/lang/String;

    .line 234
    .line 235
    .line 236
    move-result-object v3

    .line 237
    :goto_4
    sget-object v4, Lj91/j;->a:Ll2/u2;

    .line 238
    .line 239
    invoke-virtual {v2, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 240
    .line 241
    .line 242
    move-result-object v4

    .line 243
    check-cast v4, Lj91/f;

    .line 244
    .line 245
    invoke-virtual {v4}, Lj91/f;->b()Lg4/p0;

    .line 246
    .line 247
    .line 248
    move-result-object v4

    .line 249
    const/16 v22, 0x0

    .line 250
    .line 251
    const v23, 0xfffc

    .line 252
    .line 253
    .line 254
    move-object/from16 v20, v2

    .line 255
    .line 256
    move-object v2, v3

    .line 257
    move-object v3, v4

    .line 258
    const/4 v4, 0x0

    .line 259
    const-wide/16 v5, 0x0

    .line 260
    .line 261
    move v9, v8

    .line 262
    const-wide/16 v7, 0x0

    .line 263
    .line 264
    move v10, v9

    .line 265
    const/4 v9, 0x0

    .line 266
    move v12, v10

    .line 267
    const-wide/16 v10, 0x0

    .line 268
    .line 269
    move v13, v12

    .line 270
    const/4 v12, 0x0

    .line 271
    move v14, v13

    .line 272
    const/4 v13, 0x0

    .line 273
    move/from16 v16, v14

    .line 274
    .line 275
    const-wide/16 v14, 0x0

    .line 276
    .line 277
    move/from16 v17, v16

    .line 278
    .line 279
    const/16 v16, 0x0

    .line 280
    .line 281
    move/from16 v18, v17

    .line 282
    .line 283
    const/16 v17, 0x0

    .line 284
    .line 285
    move/from16 v19, v18

    .line 286
    .line 287
    const/16 v18, 0x0

    .line 288
    .line 289
    move/from16 v21, v19

    .line 290
    .line 291
    const/16 v19, 0x0

    .line 292
    .line 293
    move/from16 v24, v21

    .line 294
    .line 295
    const/16 v21, 0x0

    .line 296
    .line 297
    move/from16 v0, v24

    .line 298
    .line 299
    invoke-static/range {v2 .. v23}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 300
    .line 301
    .line 302
    move-object/from16 v2, v20

    .line 303
    .line 304
    invoke-virtual {v2, v0}, Ll2/t;->q(Z)V

    .line 305
    .line 306
    .line 307
    goto :goto_5

    .line 308
    :cond_a
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 309
    .line 310
    .line 311
    :goto_5
    invoke-virtual {v2}, Ll2/t;->s()Ll2/u1;

    .line 312
    .line 313
    .line 314
    move-result-object v0

    .line 315
    if-eqz v0, :cond_b

    .line 316
    .line 317
    new-instance v2, Ld90/h;

    .line 318
    .line 319
    const/4 v3, 0x0

    .line 320
    move-object/from16 v4, p0

    .line 321
    .line 322
    move/from16 v5, p1

    .line 323
    .line 324
    invoke-direct {v2, v4, v5, v1, v3}, Ld90/h;-><init>(Ljava/lang/Object;III)V

    .line 325
    .line 326
    .line 327
    iput-object v2, v0, Ll2/u1;->d:Lay0/n;

    .line 328
    .line 329
    :cond_b
    return-void
.end method

.method public static final c(Ll2/o;I)V
    .locals 14

    .line 1
    move-object v4, p0

    .line 2
    check-cast v4, Ll2/t;

    .line 3
    .line 4
    const p0, 0x629278cd

    .line 5
    .line 6
    .line 7
    invoke-virtual {v4, p0}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    const/4 p0, 0x1

    .line 11
    const/4 v0, 0x0

    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    move v1, p0

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    move v1, v0

    .line 17
    :goto_0
    and-int/lit8 v2, p1, 0x1

    .line 18
    .line 19
    invoke-virtual {v4, v2, v1}, Ll2/t;->O(IZ)Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_c

    .line 24
    .line 25
    const v1, -0x6040e0aa

    .line 26
    .line 27
    .line 28
    invoke-virtual {v4, v1}, Ll2/t;->Y(I)V

    .line 29
    .line 30
    .line 31
    invoke-static {v4}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    if-eqz v1, :cond_b

    .line 36
    .line 37
    invoke-static {v1}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 38
    .line 39
    .line 40
    move-result-object v8

    .line 41
    invoke-static {v4}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 42
    .line 43
    .line 44
    move-result-object v10

    .line 45
    const-class v2, Lc90/c0;

    .line 46
    .line 47
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 48
    .line 49
    invoke-virtual {v3, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 50
    .line 51
    .line 52
    move-result-object v5

    .line 53
    invoke-interface {v1}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 54
    .line 55
    .line 56
    move-result-object v6

    .line 57
    const/4 v7, 0x0

    .line 58
    const/4 v9, 0x0

    .line 59
    const/4 v11, 0x0

    .line 60
    invoke-static/range {v5 .. v11}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    invoke-virtual {v4, v0}, Ll2/t;->q(Z)V

    .line 65
    .line 66
    .line 67
    check-cast v1, Lql0/j;

    .line 68
    .line 69
    invoke-static {v1, v4, v0, p0}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 70
    .line 71
    .line 72
    move-object v7, v1

    .line 73
    check-cast v7, Lc90/c0;

    .line 74
    .line 75
    iget-object v0, v7, Lql0/j;->g:Lyy0/l1;

    .line 76
    .line 77
    const/4 v1, 0x0

    .line 78
    invoke-static {v0, v1, v4, p0}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    move-object v0, p0

    .line 87
    check-cast v0, Lc90/z;

    .line 88
    .line 89
    invoke-virtual {v4, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result p0

    .line 93
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    sget-object v13, Ll2/n;->a:Ll2/x0;

    .line 98
    .line 99
    if-nez p0, :cond_1

    .line 100
    .line 101
    if-ne v1, v13, :cond_2

    .line 102
    .line 103
    :cond_1
    new-instance v5, Ld80/l;

    .line 104
    .line 105
    const/4 v11, 0x0

    .line 106
    const/16 v12, 0x18

    .line 107
    .line 108
    const/4 v6, 0x0

    .line 109
    const-class v8, Lc90/c0;

    .line 110
    .line 111
    const-string v9, "onBack"

    .line 112
    .line 113
    const-string v10, "onBack()V"

    .line 114
    .line 115
    invoke-direct/range {v5 .. v12}, Ld80/l;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 116
    .line 117
    .line 118
    invoke-virtual {v4, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    move-object v1, v5

    .line 122
    :cond_2
    check-cast v1, Lhy0/g;

    .line 123
    .line 124
    check-cast v1, Lay0/a;

    .line 125
    .line 126
    invoke-virtual {v4, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 127
    .line 128
    .line 129
    move-result p0

    .line 130
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v2

    .line 134
    if-nez p0, :cond_3

    .line 135
    .line 136
    if-ne v2, v13, :cond_4

    .line 137
    .line 138
    :cond_3
    new-instance v5, Ld80/l;

    .line 139
    .line 140
    const/4 v11, 0x0

    .line 141
    const/16 v12, 0x19

    .line 142
    .line 143
    const/4 v6, 0x0

    .line 144
    const-class v8, Lc90/c0;

    .line 145
    .line 146
    const-string v9, "onBookNow"

    .line 147
    .line 148
    const-string v10, "onBookNow()V"

    .line 149
    .line 150
    invoke-direct/range {v5 .. v12}, Ld80/l;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 151
    .line 152
    .line 153
    invoke-virtual {v4, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    move-object v2, v5

    .line 157
    :cond_4
    check-cast v2, Lhy0/g;

    .line 158
    .line 159
    check-cast v2, Lay0/a;

    .line 160
    .line 161
    invoke-virtual {v4, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 162
    .line 163
    .line 164
    move-result p0

    .line 165
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object v3

    .line 169
    if-nez p0, :cond_5

    .line 170
    .line 171
    if-ne v3, v13, :cond_6

    .line 172
    .line 173
    :cond_5
    new-instance v5, Lcz/j;

    .line 174
    .line 175
    const/4 v11, 0x0

    .line 176
    const/16 v12, 0xd

    .line 177
    .line 178
    const/4 v6, 0x1

    .line 179
    const-class v8, Lc90/c0;

    .line 180
    .line 181
    const-string v9, "onErrorConsumed"

    .line 182
    .line 183
    const-string v10, "onErrorConsumed(Lcz/skodaauto/myskoda/library/mvvm/presentation/AbstractViewModel$State$Error$Type;)V"

    .line 184
    .line 185
    invoke-direct/range {v5 .. v12}, Lcz/j;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 186
    .line 187
    .line 188
    invoke-virtual {v4, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 189
    .line 190
    .line 191
    move-object v3, v5

    .line 192
    :cond_6
    check-cast v3, Lhy0/g;

    .line 193
    .line 194
    check-cast v3, Lay0/k;

    .line 195
    .line 196
    const/4 v5, 0x0

    .line 197
    invoke-static/range {v0 .. v5}, Ljp/bg;->d(Lc90/z;Lay0/a;Lay0/a;Lay0/k;Ll2/o;I)V

    .line 198
    .line 199
    .line 200
    invoke-virtual {v4, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 201
    .line 202
    .line 203
    move-result p0

    .line 204
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    move-result-object v0

    .line 208
    if-nez p0, :cond_7

    .line 209
    .line 210
    if-ne v0, v13, :cond_8

    .line 211
    .line 212
    :cond_7
    new-instance v5, Ld80/l;

    .line 213
    .line 214
    const/4 v11, 0x0

    .line 215
    const/16 v12, 0x1a

    .line 216
    .line 217
    const/4 v6, 0x0

    .line 218
    const-class v8, Lc90/c0;

    .line 219
    .line 220
    const-string v9, "onStart"

    .line 221
    .line 222
    const-string v10, "onStart()V"

    .line 223
    .line 224
    invoke-direct/range {v5 .. v12}, Ld80/l;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 225
    .line 226
    .line 227
    invoke-virtual {v4, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 228
    .line 229
    .line 230
    move-object v0, v5

    .line 231
    :cond_8
    check-cast v0, Lhy0/g;

    .line 232
    .line 233
    move-object v2, v0

    .line 234
    check-cast v2, Lay0/a;

    .line 235
    .line 236
    invoke-virtual {v4, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 237
    .line 238
    .line 239
    move-result p0

    .line 240
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 241
    .line 242
    .line 243
    move-result-object v0

    .line 244
    if-nez p0, :cond_9

    .line 245
    .line 246
    if-ne v0, v13, :cond_a

    .line 247
    .line 248
    :cond_9
    new-instance v5, Ld80/l;

    .line 249
    .line 250
    const/4 v11, 0x0

    .line 251
    const/16 v12, 0x1b

    .line 252
    .line 253
    const/4 v6, 0x0

    .line 254
    const-class v8, Lc90/c0;

    .line 255
    .line 256
    const-string v9, "onStop"

    .line 257
    .line 258
    const-string v10, "onStop()V"

    .line 259
    .line 260
    invoke-direct/range {v5 .. v12}, Ld80/l;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 261
    .line 262
    .line 263
    invoke-virtual {v4, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 264
    .line 265
    .line 266
    move-object v0, v5

    .line 267
    :cond_a
    check-cast v0, Lhy0/g;

    .line 268
    .line 269
    move-object v5, v0

    .line 270
    check-cast v5, Lay0/a;

    .line 271
    .line 272
    const/4 v8, 0x0

    .line 273
    const/16 v9, 0xdb

    .line 274
    .line 275
    const/4 v0, 0x0

    .line 276
    const/4 v1, 0x0

    .line 277
    const/4 v3, 0x0

    .line 278
    move-object v7, v4

    .line 279
    const/4 v4, 0x0

    .line 280
    const/4 v6, 0x0

    .line 281
    invoke-static/range {v0 .. v9}, Lxf0/i0;->z(Landroidx/lifecycle/x;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 282
    .line 283
    .line 284
    move-object v4, v7

    .line 285
    goto :goto_1

    .line 286
    :cond_b
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 287
    .line 288
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 289
    .line 290
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 291
    .line 292
    .line 293
    throw p0

    .line 294
    :cond_c
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 295
    .line 296
    .line 297
    :goto_1
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 298
    .line 299
    .line 300
    move-result-object p0

    .line 301
    if-eqz p0, :cond_d

    .line 302
    .line 303
    new-instance v0, Ld80/m;

    .line 304
    .line 305
    const/4 v1, 0x7

    .line 306
    invoke-direct {v0, p1, v1}, Ld80/m;-><init>(II)V

    .line 307
    .line 308
    .line 309
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 310
    .line 311
    :cond_d
    return-void
.end method

.method public static final d(Lc90/z;Lay0/a;Lay0/a;Lay0/k;Ll2/o;I)V
    .locals 19

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v3, p2

    .line 6
    .line 7
    move-object/from16 v7, p4

    .line 8
    .line 9
    check-cast v7, Ll2/t;

    .line 10
    .line 11
    const v0, 0x2a0fb72f

    .line 12
    .line 13
    .line 14
    invoke-virtual {v7, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v7, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-eqz v0, :cond_0

    .line 22
    .line 23
    const/4 v0, 0x4

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 v0, 0x2

    .line 26
    :goto_0
    or-int v0, p5, v0

    .line 27
    .line 28
    invoke-virtual {v7, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v4

    .line 32
    const/16 v5, 0x20

    .line 33
    .line 34
    if-eqz v4, :cond_1

    .line 35
    .line 36
    move v4, v5

    .line 37
    goto :goto_1

    .line 38
    :cond_1
    const/16 v4, 0x10

    .line 39
    .line 40
    :goto_1
    or-int/2addr v0, v4

    .line 41
    invoke-virtual {v7, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v4

    .line 45
    if-eqz v4, :cond_2

    .line 46
    .line 47
    const/16 v4, 0x100

    .line 48
    .line 49
    goto :goto_2

    .line 50
    :cond_2
    const/16 v4, 0x80

    .line 51
    .line 52
    :goto_2
    or-int/2addr v0, v4

    .line 53
    move-object/from16 v4, p3

    .line 54
    .line 55
    invoke-virtual {v7, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result v6

    .line 59
    if-eqz v6, :cond_3

    .line 60
    .line 61
    const/16 v6, 0x800

    .line 62
    .line 63
    goto :goto_3

    .line 64
    :cond_3
    const/16 v6, 0x400

    .line 65
    .line 66
    :goto_3
    or-int/2addr v0, v6

    .line 67
    and-int/lit16 v6, v0, 0x493

    .line 68
    .line 69
    const/16 v8, 0x492

    .line 70
    .line 71
    const/4 v10, 0x0

    .line 72
    const/4 v9, 0x1

    .line 73
    if-eq v6, v8, :cond_4

    .line 74
    .line 75
    move v6, v9

    .line 76
    goto :goto_4

    .line 77
    :cond_4
    move v6, v10

    .line 78
    :goto_4
    and-int/lit8 v8, v0, 0x1

    .line 79
    .line 80
    invoke-virtual {v7, v8, v6}, Ll2/t;->O(IZ)Z

    .line 81
    .line 82
    .line 83
    move-result v6

    .line 84
    if-eqz v6, :cond_9

    .line 85
    .line 86
    and-int/lit8 v6, v0, 0x70

    .line 87
    .line 88
    invoke-static {v10, v2, v7, v6, v9}, Ljp/tb;->a(ZLay0/a;Ll2/o;II)V

    .line 89
    .line 90
    .line 91
    iget-object v4, v1, Lc90/z;->b:Lql0/g;

    .line 92
    .line 93
    if-nez v4, :cond_5

    .line 94
    .line 95
    const v0, -0x4525b670

    .line 96
    .line 97
    .line 98
    invoke-virtual {v7, v0}, Ll2/t;->Y(I)V

    .line 99
    .line 100
    .line 101
    invoke-virtual {v7, v10}, Ll2/t;->q(Z)V

    .line 102
    .line 103
    .line 104
    new-instance v0, Lb60/d;

    .line 105
    .line 106
    const/16 v4, 0xe

    .line 107
    .line 108
    invoke-direct {v0, v3, v4}, Lb60/d;-><init>(Lay0/a;I)V

    .line 109
    .line 110
    .line 111
    const v4, 0x357f4c4a

    .line 112
    .line 113
    .line 114
    invoke-static {v4, v7, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 115
    .line 116
    .line 117
    move-result-object v6

    .line 118
    new-instance v0, Lal/d;

    .line 119
    .line 120
    const/16 v4, 0x16

    .line 121
    .line 122
    invoke-direct {v0, v4, v1, v2}, Lal/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 123
    .line 124
    .line 125
    const v4, 0x79566340

    .line 126
    .line 127
    .line 128
    invoke-static {v4, v7, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 129
    .line 130
    .line 131
    move-result-object v15

    .line 132
    const v17, 0x30000180

    .line 133
    .line 134
    .line 135
    const/16 v18, 0x1fb

    .line 136
    .line 137
    const/4 v4, 0x0

    .line 138
    const/4 v5, 0x0

    .line 139
    move-object/from16 v16, v7

    .line 140
    .line 141
    const/4 v7, 0x0

    .line 142
    const/4 v8, 0x0

    .line 143
    const/4 v9, 0x0

    .line 144
    const-wide/16 v10, 0x0

    .line 145
    .line 146
    const-wide/16 v12, 0x0

    .line 147
    .line 148
    const/4 v14, 0x0

    .line 149
    invoke-static/range {v4 .. v18}, Lh2/c8;->a(Lx2/s;Lay0/n;Lay0/n;Lay0/n;Lay0/n;IJJLk1/q1;Lay0/o;Ll2/o;II)V

    .line 150
    .line 151
    .line 152
    move-object/from16 v7, v16

    .line 153
    .line 154
    goto :goto_7

    .line 155
    :cond_5
    const v8, -0x4525b66f

    .line 156
    .line 157
    .line 158
    invoke-virtual {v7, v8}, Ll2/t;->Y(I)V

    .line 159
    .line 160
    .line 161
    if-ne v6, v5, :cond_6

    .line 162
    .line 163
    goto :goto_5

    .line 164
    :cond_6
    move v9, v10

    .line 165
    :goto_5
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object v5

    .line 169
    if-nez v9, :cond_7

    .line 170
    .line 171
    sget-object v6, Ll2/n;->a:Ll2/x0;

    .line 172
    .line 173
    if-ne v5, v6, :cond_8

    .line 174
    .line 175
    :cond_7
    new-instance v5, Laj0/c;

    .line 176
    .line 177
    const/16 v6, 0xf

    .line 178
    .line 179
    invoke-direct {v5, v2, v6}, Laj0/c;-><init>(Lay0/a;I)V

    .line 180
    .line 181
    .line 182
    invoke-virtual {v7, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 183
    .line 184
    .line 185
    :cond_8
    move-object v6, v5

    .line 186
    check-cast v6, Lay0/k;

    .line 187
    .line 188
    shr-int/lit8 v0, v0, 0x6

    .line 189
    .line 190
    and-int/lit8 v8, v0, 0x70

    .line 191
    .line 192
    const/4 v9, 0x0

    .line 193
    move-object/from16 v5, p3

    .line 194
    .line 195
    invoke-static/range {v4 .. v9}, Lyg0/a;->a(Lql0/g;Lay0/k;Lay0/k;Ll2/o;II)V

    .line 196
    .line 197
    .line 198
    invoke-virtual {v7, v10}, Ll2/t;->q(Z)V

    .line 199
    .line 200
    .line 201
    invoke-virtual {v7}, Ll2/t;->s()Ll2/u1;

    .line 202
    .line 203
    .line 204
    move-result-object v7

    .line 205
    if-eqz v7, :cond_a

    .line 206
    .line 207
    new-instance v0, Ld90/g;

    .line 208
    .line 209
    const/4 v6, 0x0

    .line 210
    move-object/from16 v4, p3

    .line 211
    .line 212
    move/from16 v5, p5

    .line 213
    .line 214
    invoke-direct/range {v0 .. v6}, Ld90/g;-><init>(Lc90/z;Lay0/a;Lay0/a;Lay0/k;II)V

    .line 215
    .line 216
    .line 217
    :goto_6
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 218
    .line 219
    return-void

    .line 220
    :cond_9
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 221
    .line 222
    .line 223
    :goto_7
    invoke-virtual {v7}, Ll2/t;->s()Ll2/u1;

    .line 224
    .line 225
    .line 226
    move-result-object v7

    .line 227
    if-eqz v7, :cond_a

    .line 228
    .line 229
    new-instance v0, Ld90/g;

    .line 230
    .line 231
    const/4 v6, 0x1

    .line 232
    move-object/from16 v1, p0

    .line 233
    .line 234
    move-object/from16 v2, p1

    .line 235
    .line 236
    move-object/from16 v3, p2

    .line 237
    .line 238
    move-object/from16 v4, p3

    .line 239
    .line 240
    move/from16 v5, p5

    .line 241
    .line 242
    invoke-direct/range {v0 .. v6}, Ld90/g;-><init>(Lc90/z;Lay0/a;Lay0/a;Lay0/k;II)V

    .line 243
    .line 244
    .line 245
    goto :goto_6

    .line 246
    :cond_a
    return-void
.end method

.method public static final e(Lqp0/g;)Lqp0/g;
    .locals 8

    .line 1
    const/4 v0, -0x1

    .line 2
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 3
    .line 4
    .line 5
    move-result-object v1

    .line 6
    iget-object v2, p0, Lqp0/g;->a:Ljava/util/List;

    .line 7
    .line 8
    iget-object v3, p0, Lqp0/g;->b:Ljava/lang/Integer;

    .line 9
    .line 10
    iget-boolean v4, p0, Lqp0/g;->c:Z

    .line 11
    .line 12
    move-object v5, v2

    .line 13
    check-cast v5, Ljava/lang/Iterable;

    .line 14
    .line 15
    new-instance v6, Ljava/util/ArrayList;

    .line 16
    .line 17
    const/16 v7, 0xa

    .line 18
    .line 19
    invoke-static {v5, v7}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 20
    .line 21
    .line 22
    move-result v7

    .line 23
    invoke-direct {v6, v7}, Ljava/util/ArrayList;-><init>(I)V

    .line 24
    .line 25
    .line 26
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 27
    .line 28
    .line 29
    move-result-object v5

    .line 30
    :goto_0
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 31
    .line 32
    .line 33
    move-result v7

    .line 34
    if-eqz v7, :cond_0

    .line 35
    .line 36
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v7

    .line 40
    check-cast v7, Llx0/l;

    .line 41
    .line 42
    iget-object v7, v7, Llx0/l;->e:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v7, Lqp0/b0;

    .line 45
    .line 46
    invoke-virtual {v6, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_0
    if-nez v4, :cond_3

    .line 51
    .line 52
    invoke-static {v6}, Ljp/eg;->k(Ljava/util/List;)Z

    .line 53
    .line 54
    .line 55
    move-result v5

    .line 56
    if-nez v5, :cond_1

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_1
    if-eqz v3, :cond_2

    .line 60
    .line 61
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 62
    .line 63
    .line 64
    move-result v5

    .line 65
    invoke-static {v5, v6}, Ljp/eg;->i(ILjava/util/List;)Z

    .line 66
    .line 67
    .line 68
    move-result v5

    .line 69
    if-nez v5, :cond_2

    .line 70
    .line 71
    sget-object p0, Lqp0/g;->d:Lqp0/b0;

    .line 72
    .line 73
    goto :goto_2

    .line 74
    :cond_2
    return-object p0

    .line 75
    :cond_3
    :goto_1
    sget-object p0, Lqp0/g;->e:Lqp0/b0;

    .line 76
    .line 77
    :goto_2
    invoke-virtual {v6}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 78
    .line 79
    .line 80
    move-result-object v5

    .line 81
    :cond_4
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 82
    .line 83
    .line 84
    move-result v6

    .line 85
    if-eqz v6, :cond_5

    .line 86
    .line 87
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v6

    .line 91
    move-object v7, v6

    .line 92
    check-cast v7, Lqp0/b0;

    .line 93
    .line 94
    invoke-static {v7}, Ljp/eg;->e(Lqp0/b0;)Z

    .line 95
    .line 96
    .line 97
    move-result v7

    .line 98
    if-eqz v7, :cond_4

    .line 99
    .line 100
    goto :goto_3

    .line 101
    :cond_5
    const/4 v6, 0x0

    .line 102
    :goto_3
    check-cast v6, Lqp0/b0;

    .line 103
    .line 104
    if-nez v6, :cond_6

    .line 105
    .line 106
    check-cast v2, Ljava/util/Collection;

    .line 107
    .line 108
    invoke-static {v2}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 109
    .line 110
    .line 111
    move-result-object v0

    .line 112
    new-instance v2, Llx0/l;

    .line 113
    .line 114
    invoke-direct {v2, v1, p0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 118
    .line 119
    .line 120
    invoke-static {v0}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    new-instance v0, Lqp0/g;

    .line 125
    .line 126
    invoke-direct {v0, p0, v3, v4}, Lqp0/g;-><init>(Ljava/util/List;Ljava/lang/Integer;Z)V

    .line 127
    .line 128
    .line 129
    return-object v0

    .line 130
    :cond_6
    const-string v5, "waypoint"

    .line 131
    .line 132
    invoke-static {p0, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    check-cast v2, Ljava/util/Collection;

    .line 136
    .line 137
    invoke-static {v2}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 138
    .line 139
    .line 140
    move-result-object v2

    .line 141
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 142
    .line 143
    .line 144
    move-result-object v5

    .line 145
    const/4 v6, 0x0

    .line 146
    :goto_4
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 147
    .line 148
    .line 149
    move-result v7

    .line 150
    if-eqz v7, :cond_8

    .line 151
    .line 152
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v7

    .line 156
    check-cast v7, Llx0/l;

    .line 157
    .line 158
    iget-object v7, v7, Llx0/l;->d:Ljava/lang/Object;

    .line 159
    .line 160
    check-cast v7, Ljava/lang/Number;

    .line 161
    .line 162
    invoke-virtual {v7}, Ljava/lang/Number;->intValue()I

    .line 163
    .line 164
    .line 165
    move-result v7

    .line 166
    if-ne v7, v0, :cond_7

    .line 167
    .line 168
    goto :goto_5

    .line 169
    :cond_7
    add-int/lit8 v6, v6, 0x1

    .line 170
    .line 171
    goto :goto_4

    .line 172
    :cond_8
    move v6, v0

    .line 173
    :goto_5
    if-eq v6, v0, :cond_9

    .line 174
    .line 175
    new-instance v0, Llx0/l;

    .line 176
    .line 177
    invoke-direct {v0, v1, p0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 178
    .line 179
    .line 180
    invoke-virtual {v2, v6, v0}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    :cond_9
    invoke-static {v2}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 184
    .line 185
    .line 186
    move-result-object p0

    .line 187
    new-instance v0, Lqp0/g;

    .line 188
    .line 189
    invoke-direct {v0, p0, v3, v4}, Lqp0/g;-><init>(Ljava/util/List;Ljava/lang/Integer;Z)V

    .line 190
    .line 191
    .line 192
    return-object v0
.end method
