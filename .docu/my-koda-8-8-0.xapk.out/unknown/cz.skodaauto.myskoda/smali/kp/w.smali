.class public abstract Lkp/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(ZLr4/j;Le2/w0;Ll2/o;I)V
    .locals 16

    .line 1
    move/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v10, p2

    .line 4
    .line 5
    move/from16 v11, p4

    .line 6
    .line 7
    move-object/from16 v8, p3

    .line 8
    .line 9
    check-cast v8, Ll2/t;

    .line 10
    .line 11
    const v0, -0x50245748

    .line 12
    .line 13
    .line 14
    invoke-virtual {v8, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    and-int/lit8 v0, v11, 0x6

    .line 18
    .line 19
    const/4 v2, 0x4

    .line 20
    if-nez v0, :cond_1

    .line 21
    .line 22
    invoke-virtual {v8, v1}, Ll2/t;->h(Z)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-eqz v0, :cond_0

    .line 27
    .line 28
    move v0, v2

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const/4 v0, 0x2

    .line 31
    :goto_0
    or-int/2addr v0, v11

    .line 32
    goto :goto_1

    .line 33
    :cond_1
    move v0, v11

    .line 34
    :goto_1
    and-int/lit8 v3, v11, 0x30

    .line 35
    .line 36
    const/16 v4, 0x20

    .line 37
    .line 38
    if-nez v3, :cond_3

    .line 39
    .line 40
    invoke-virtual/range {p1 .. p1}, Ljava/lang/Enum;->ordinal()I

    .line 41
    .line 42
    .line 43
    move-result v3

    .line 44
    invoke-virtual {v8, v3}, Ll2/t;->e(I)Z

    .line 45
    .line 46
    .line 47
    move-result v3

    .line 48
    if-eqz v3, :cond_2

    .line 49
    .line 50
    move v3, v4

    .line 51
    goto :goto_2

    .line 52
    :cond_2
    const/16 v3, 0x10

    .line 53
    .line 54
    :goto_2
    or-int/2addr v0, v3

    .line 55
    :cond_3
    and-int/lit16 v3, v11, 0x180

    .line 56
    .line 57
    if-nez v3, :cond_5

    .line 58
    .line 59
    invoke-virtual {v8, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v3

    .line 63
    if-eqz v3, :cond_4

    .line 64
    .line 65
    const/16 v3, 0x100

    .line 66
    .line 67
    goto :goto_3

    .line 68
    :cond_4
    const/16 v3, 0x80

    .line 69
    .line 70
    :goto_3
    or-int/2addr v0, v3

    .line 71
    :cond_5
    and-int/lit16 v3, v0, 0x93

    .line 72
    .line 73
    const/16 v5, 0x92

    .line 74
    .line 75
    const/4 v6, 0x0

    .line 76
    const/4 v7, 0x1

    .line 77
    if-eq v3, v5, :cond_6

    .line 78
    .line 79
    move v3, v7

    .line 80
    goto :goto_4

    .line 81
    :cond_6
    move v3, v6

    .line 82
    :goto_4
    and-int/lit8 v5, v0, 0x1

    .line 83
    .line 84
    invoke-virtual {v8, v5, v3}, Ll2/t;->O(IZ)Z

    .line 85
    .line 86
    .line 87
    move-result v3

    .line 88
    if-eqz v3, :cond_13

    .line 89
    .line 90
    and-int/lit8 v3, v0, 0xe

    .line 91
    .line 92
    if-ne v3, v2, :cond_7

    .line 93
    .line 94
    move v5, v7

    .line 95
    goto :goto_5

    .line 96
    :cond_7
    move v5, v6

    .line 97
    :goto_5
    invoke-virtual {v8, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result v9

    .line 101
    or-int/2addr v5, v9

    .line 102
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v9

    .line 106
    sget-object v12, Ll2/n;->a:Ll2/x0;

    .line 107
    .line 108
    if-nez v5, :cond_8

    .line 109
    .line 110
    if-ne v9, v12, :cond_9

    .line 111
    .line 112
    :cond_8
    new-instance v9, Le2/s0;

    .line 113
    .line 114
    invoke-direct {v9, v10, v1}, Le2/s0;-><init>(Le2/w0;Z)V

    .line 115
    .line 116
    .line 117
    invoke-virtual {v8, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 118
    .line 119
    .line 120
    :cond_9
    check-cast v9, Lt1/w0;

    .line 121
    .line 122
    invoke-virtual {v8, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 123
    .line 124
    .line 125
    move-result v5

    .line 126
    if-ne v3, v2, :cond_a

    .line 127
    .line 128
    move v2, v7

    .line 129
    goto :goto_6

    .line 130
    :cond_a
    move v2, v6

    .line 131
    :goto_6
    or-int/2addr v2, v5

    .line 132
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v3

    .line 136
    if-nez v2, :cond_b

    .line 137
    .line 138
    if-ne v3, v12, :cond_c

    .line 139
    .line 140
    :cond_b
    new-instance v3, Le2/y0;

    .line 141
    .line 142
    invoke-direct {v3, v10, v1}, Le2/y0;-><init>(Le2/w0;Z)V

    .line 143
    .line 144
    .line 145
    invoke-virtual {v8, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 146
    .line 147
    .line 148
    :cond_c
    check-cast v3, Le2/l;

    .line 149
    .line 150
    invoke-virtual {v10}, Le2/w0;->m()Ll4/v;

    .line 151
    .line 152
    .line 153
    move-result-object v2

    .line 154
    iget-wide v13, v2, Ll4/v;->b:J

    .line 155
    .line 156
    invoke-static {v13, v14}, Lg4/o0;->g(J)Z

    .line 157
    .line 158
    .line 159
    move-result v2

    .line 160
    if-eqz v1, :cond_d

    .line 161
    .line 162
    invoke-virtual {v10}, Le2/w0;->m()Ll4/v;

    .line 163
    .line 164
    .line 165
    move-result-object v5

    .line 166
    iget-wide v13, v5, Ll4/v;->b:J

    .line 167
    .line 168
    shr-long v4, v13, v4

    .line 169
    .line 170
    :goto_7
    long-to-int v4, v4

    .line 171
    goto :goto_8

    .line 172
    :cond_d
    invoke-virtual {v10}, Le2/w0;->m()Ll4/v;

    .line 173
    .line 174
    .line 175
    move-result-object v4

    .line 176
    iget-wide v4, v4, Ll4/v;->b:J

    .line 177
    .line 178
    const-wide v13, 0xffffffffL

    .line 179
    .line 180
    .line 181
    .line 182
    .line 183
    and-long/2addr v4, v13

    .line 184
    goto :goto_7

    .line 185
    :goto_8
    iget-object v5, v10, Le2/w0;->d:Lt1/p0;

    .line 186
    .line 187
    const/4 v13, 0x0

    .line 188
    if-eqz v5, :cond_10

    .line 189
    .line 190
    invoke-virtual {v5}, Lt1/p0;->d()Lt1/j1;

    .line 191
    .line 192
    .line 193
    move-result-object v5

    .line 194
    if-eqz v5, :cond_10

    .line 195
    .line 196
    iget-object v5, v5, Lt1/j1;->a:Lg4/l0;

    .line 197
    .line 198
    if-ltz v4, :cond_10

    .line 199
    .line 200
    iget-object v14, v5, Lg4/l0;->a:Lg4/k0;

    .line 201
    .line 202
    iget-object v5, v5, Lg4/l0;->b:Lg4/o;

    .line 203
    .line 204
    iget-object v14, v14, Lg4/k0;->a:Lg4/g;

    .line 205
    .line 206
    iget-object v14, v14, Lg4/g;->e:Ljava/lang/String;

    .line 207
    .line 208
    invoke-virtual {v14}, Ljava/lang/String;->length()I

    .line 209
    .line 210
    .line 211
    move-result v14

    .line 212
    if-nez v14, :cond_e

    .line 213
    .line 214
    goto :goto_9

    .line 215
    :cond_e
    invoke-virtual {v5, v4}, Lg4/o;->d(I)I

    .line 216
    .line 217
    .line 218
    move-result v14

    .line 219
    iget v15, v5, Lg4/o;->b:I

    .line 220
    .line 221
    sub-int/2addr v15, v7

    .line 222
    move/from16 p3, v7

    .line 223
    .line 224
    iget v7, v5, Lg4/o;->f:I

    .line 225
    .line 226
    add-int/lit8 v7, v7, -0x1

    .line 227
    .line 228
    invoke-static {v15, v7}, Ljava/lang/Math;->min(II)I

    .line 229
    .line 230
    .line 231
    move-result v7

    .line 232
    invoke-static {v14, v7}, Ljava/lang/Math;->min(II)I

    .line 233
    .line 234
    .line 235
    move-result v7

    .line 236
    invoke-virtual {v5, v7, v6}, Lg4/o;->c(IZ)I

    .line 237
    .line 238
    .line 239
    move-result v6

    .line 240
    if-le v4, v6, :cond_f

    .line 241
    .line 242
    goto :goto_9

    .line 243
    :cond_f
    invoke-virtual {v5, v7}, Lg4/o;->m(I)V

    .line 244
    .line 245
    .line 246
    iget-object v4, v5, Lg4/o;->h:Ljava/util/ArrayList;

    .line 247
    .line 248
    invoke-static {v7, v4}, Lg4/f0;->e(ILjava/util/List;)I

    .line 249
    .line 250
    .line 251
    move-result v5

    .line 252
    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 253
    .line 254
    .line 255
    move-result-object v4

    .line 256
    check-cast v4, Lg4/q;

    .line 257
    .line 258
    iget-object v5, v4, Lg4/q;->a:Lg4/a;

    .line 259
    .line 260
    iget v4, v4, Lg4/q;->d:I

    .line 261
    .line 262
    sub-int/2addr v7, v4

    .line 263
    iget-object v4, v5, Lg4/a;->d:Lh4/j;

    .line 264
    .line 265
    invoke-virtual {v4, v7}, Lh4/j;->e(I)F

    .line 266
    .line 267
    .line 268
    move-result v5

    .line 269
    invoke-virtual {v4, v7}, Lh4/j;->g(I)F

    .line 270
    .line 271
    .line 272
    move-result v4

    .line 273
    sub-float v13, v5, v4

    .line 274
    .line 275
    :cond_10
    :goto_9
    move v6, v13

    .line 276
    invoke-virtual {v8, v9}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 277
    .line 278
    .line 279
    move-result v4

    .line 280
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 281
    .line 282
    .line 283
    move-result-object v5

    .line 284
    if-nez v4, :cond_11

    .line 285
    .line 286
    if-ne v5, v12, :cond_12

    .line 287
    .line 288
    :cond_11
    new-instance v5, Lb2/b;

    .line 289
    .line 290
    const/4 v4, 0x4

    .line 291
    invoke-direct {v5, v9, v4}, Lb2/b;-><init>(Ljava/lang/Object;I)V

    .line 292
    .line 293
    .line 294
    invoke-virtual {v8, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 295
    .line 296
    .line 297
    :cond_12
    check-cast v5, Landroidx/compose/ui/input/pointer/PointerInputEventHandler;

    .line 298
    .line 299
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 300
    .line 301
    invoke-static {v4, v9, v5}, Lp3/f0;->b(Lx2/s;Ljava/lang/Object;Landroidx/compose/ui/input/pointer/PointerInputEventHandler;)Lx2/s;

    .line 302
    .line 303
    .line 304
    move-result-object v7

    .line 305
    shl-int/lit8 v0, v0, 0x3

    .line 306
    .line 307
    and-int/lit16 v9, v0, 0x3f0

    .line 308
    .line 309
    const-wide/16 v4, 0x0

    .line 310
    .line 311
    move-object v0, v3

    .line 312
    move v3, v2

    .line 313
    move-object/from16 v2, p1

    .line 314
    .line 315
    invoke-static/range {v0 .. v9}, Lkp/o;->b(Le2/l;ZLr4/j;ZJFLx2/s;Ll2/o;I)V

    .line 316
    .line 317
    .line 318
    goto :goto_a

    .line 319
    :cond_13
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 320
    .line 321
    .line 322
    :goto_a
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 323
    .line 324
    .line 325
    move-result-object v6

    .line 326
    if-eqz v6, :cond_14

    .line 327
    .line 328
    new-instance v0, Le2/x0;

    .line 329
    .line 330
    const/4 v5, 0x0

    .line 331
    move/from16 v1, p0

    .line 332
    .line 333
    move-object/from16 v2, p1

    .line 334
    .line 335
    move-object v3, v10

    .line 336
    move v4, v11

    .line 337
    invoke-direct/range {v0 .. v5}, Le2/x0;-><init>(ZLjava/lang/Object;Ljava/lang/Object;II)V

    .line 338
    .line 339
    .line 340
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 341
    .line 342
    :cond_14
    return-void
.end method

.method public static final b(Landroid/view/View;)Lra/f;
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :goto_0
    const/4 v0, 0x0

    .line 7
    if-eqz p0, :cond_3

    .line 8
    .line 9
    const v1, 0x7f0a0304

    .line 10
    .line 11
    .line 12
    invoke-virtual {p0, v1}, Landroid/view/View;->getTag(I)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    instance-of v2, v1, Lra/f;

    .line 17
    .line 18
    if-eqz v2, :cond_0

    .line 19
    .line 20
    check-cast v1, Lra/f;

    .line 21
    .line 22
    goto :goto_1

    .line 23
    :cond_0
    move-object v1, v0

    .line 24
    :goto_1
    if-eqz v1, :cond_1

    .line 25
    .line 26
    return-object v1

    .line 27
    :cond_1
    invoke-static {p0}, Lkp/o8;->b(Landroid/view/View;)Landroid/view/ViewParent;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    instance-of v1, p0, Landroid/view/View;

    .line 32
    .line 33
    if-eqz v1, :cond_2

    .line 34
    .line 35
    check-cast p0, Landroid/view/View;

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_2
    move-object p0, v0

    .line 39
    goto :goto_0

    .line 40
    :cond_3
    return-object v0
.end method

.method public static final c(Le2/w0;Z)Z
    .locals 5

    .line 1
    iget-object v0, p0, Le2/w0;->d:Lt1/p0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0}, Lt1/p0;->c()Lt3/y;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-static {v0}, Lkp/u;->b(Lt3/y;)Ld3/c;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-virtual {p0, p1}, Le2/w0;->k(Z)J

    .line 16
    .line 17
    .line 18
    move-result-wide p0

    .line 19
    iget v1, v0, Ld3/c;->a:F

    .line 20
    .line 21
    iget v2, v0, Ld3/c;->c:F

    .line 22
    .line 23
    const/16 v3, 0x20

    .line 24
    .line 25
    shr-long v3, p0, v3

    .line 26
    .line 27
    long-to-int v3, v3

    .line 28
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 29
    .line 30
    .line 31
    move-result v3

    .line 32
    cmpg-float v1, v1, v3

    .line 33
    .line 34
    if-gtz v1, :cond_0

    .line 35
    .line 36
    cmpg-float v1, v3, v2

    .line 37
    .line 38
    if-gtz v1, :cond_0

    .line 39
    .line 40
    iget v1, v0, Ld3/c;->b:F

    .line 41
    .line 42
    iget v0, v0, Ld3/c;->d:F

    .line 43
    .line 44
    const-wide v2, 0xffffffffL

    .line 45
    .line 46
    .line 47
    .line 48
    .line 49
    and-long/2addr p0, v2

    .line 50
    long-to-int p0, p0

    .line 51
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 52
    .line 53
    .line 54
    move-result p0

    .line 55
    cmpg-float p1, v1, p0

    .line 56
    .line 57
    if-gtz p1, :cond_0

    .line 58
    .line 59
    cmpg-float p0, p0, v0

    .line 60
    .line 61
    if-gtz p0, :cond_0

    .line 62
    .line 63
    const/4 p0, 0x1

    .line 64
    return p0

    .line 65
    :cond_0
    const/4 p0, 0x0

    .line 66
    return p0
.end method

.method public static final d(Landroid/view/View;Lra/f;)V
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const v0, 0x7f0a0304

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0, v0, p1}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method
