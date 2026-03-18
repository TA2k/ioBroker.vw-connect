.class public abstract Ljp/ra;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/lang/String;Ll2/o;I)V
    .locals 3

    .line 1
    check-cast p1, Ll2/t;

    .line 2
    .line 3
    const v0, -0x1b32e506

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p1, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const/4 v1, 0x2

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    const/4 v0, 0x4

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move v0, v1

    .line 19
    :goto_0
    or-int/2addr v0, p2

    .line 20
    and-int/lit8 v2, v0, 0x3

    .line 21
    .line 22
    if-eq v2, v1, :cond_1

    .line 23
    .line 24
    const/4 v1, 0x1

    .line 25
    goto :goto_1

    .line 26
    :cond_1
    const/4 v1, 0x0

    .line 27
    :goto_1
    and-int/lit8 v2, v0, 0x1

    .line 28
    .line 29
    invoke-virtual {p1, v2, v1}, Ll2/t;->O(IZ)Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_2

    .line 34
    .line 35
    const v1, 0x7f120b0c

    .line 36
    .line 37
    .line 38
    invoke-static {p1, v1}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    shl-int/lit8 v0, v0, 0x3

    .line 43
    .line 44
    and-int/lit8 v0, v0, 0x70

    .line 45
    .line 46
    or-int/lit16 v0, v0, 0x180

    .line 47
    .line 48
    const-string v2, "remotestop_authorization_charging_time"

    .line 49
    .line 50
    invoke-static {v1, p0, v2, p1, v0}, Ljp/ra;->b(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ll2/o;I)V

    .line 51
    .line 52
    .line 53
    goto :goto_2

    .line 54
    :cond_2
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 55
    .line 56
    .line 57
    :goto_2
    invoke-virtual {p1}, Ll2/t;->s()Ll2/u1;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    if-eqz p1, :cond_3

    .line 62
    .line 63
    new-instance v0, Ll20/d;

    .line 64
    .line 65
    const/16 v1, 0xf

    .line 66
    .line 67
    invoke-direct {v0, p0, p2, v1}, Ll20/d;-><init>(Ljava/lang/String;II)V

    .line 68
    .line 69
    .line 70
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 71
    .line 72
    :cond_3
    return-void
.end method

.method public static final b(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ll2/o;I)V
    .locals 32

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    move/from16 v3, p4

    .line 8
    .line 9
    move-object/from16 v4, p3

    .line 10
    .line 11
    check-cast v4, Ll2/t;

    .line 12
    .line 13
    const v5, -0x5ca95350

    .line 14
    .line 15
    .line 16
    invoke-virtual {v4, v5}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    and-int/lit8 v5, v3, 0x6

    .line 20
    .line 21
    if-nez v5, :cond_1

    .line 22
    .line 23
    invoke-virtual {v4, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v5

    .line 27
    if-eqz v5, :cond_0

    .line 28
    .line 29
    const/4 v5, 0x4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v5, 0x2

    .line 32
    :goto_0
    or-int/2addr v5, v3

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    move v5, v3

    .line 35
    :goto_1
    and-int/lit8 v6, v3, 0x30

    .line 36
    .line 37
    if-nez v6, :cond_3

    .line 38
    .line 39
    invoke-virtual {v4, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v6

    .line 43
    if-eqz v6, :cond_2

    .line 44
    .line 45
    const/16 v6, 0x20

    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_2
    const/16 v6, 0x10

    .line 49
    .line 50
    :goto_2
    or-int/2addr v5, v6

    .line 51
    :cond_3
    and-int/lit16 v6, v3, 0x180

    .line 52
    .line 53
    if-nez v6, :cond_5

    .line 54
    .line 55
    invoke-virtual {v4, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result v6

    .line 59
    if-eqz v6, :cond_4

    .line 60
    .line 61
    const/16 v6, 0x100

    .line 62
    .line 63
    goto :goto_3

    .line 64
    :cond_4
    const/16 v6, 0x80

    .line 65
    .line 66
    :goto_3
    or-int/2addr v5, v6

    .line 67
    :cond_5
    and-int/lit16 v6, v5, 0x93

    .line 68
    .line 69
    const/16 v7, 0x92

    .line 70
    .line 71
    const/4 v8, 0x1

    .line 72
    if-eq v6, v7, :cond_6

    .line 73
    .line 74
    move v6, v8

    .line 75
    goto :goto_4

    .line 76
    :cond_6
    const/4 v6, 0x0

    .line 77
    :goto_4
    and-int/lit8 v7, v5, 0x1

    .line 78
    .line 79
    invoke-virtual {v4, v7, v6}, Ll2/t;->O(IZ)Z

    .line 80
    .line 81
    .line 82
    move-result v6

    .line 83
    if-eqz v6, :cond_a

    .line 84
    .line 85
    sget-object v6, Lj91/a;->a:Ll2/u2;

    .line 86
    .line 87
    invoke-virtual {v4, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v7

    .line 91
    check-cast v7, Lj91/c;

    .line 92
    .line 93
    iget v7, v7, Lj91/c;->f:F

    .line 94
    .line 95
    sget-object v9, Lx2/p;->b:Lx2/p;

    .line 96
    .line 97
    const/4 v10, 0x0

    .line 98
    invoke-static {v9, v10, v7, v8}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 99
    .line 100
    .line 101
    move-result-object v7

    .line 102
    invoke-static {v7, v2}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 103
    .line 104
    .line 105
    move-result-object v7

    .line 106
    const/high16 v10, 0x3f800000    # 1.0f

    .line 107
    .line 108
    invoke-static {v7, v10}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 109
    .line 110
    .line 111
    move-result-object v7

    .line 112
    sget-object v10, Lk1/j;->g:Lk1/f;

    .line 113
    .line 114
    sget-object v11, Lx2/c;->m:Lx2/i;

    .line 115
    .line 116
    const/4 v12, 0x6

    .line 117
    invoke-static {v10, v11, v4, v12}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 118
    .line 119
    .line 120
    move-result-object v10

    .line 121
    iget-wide v11, v4, Ll2/t;->T:J

    .line 122
    .line 123
    invoke-static {v11, v12}, Ljava/lang/Long;->hashCode(J)I

    .line 124
    .line 125
    .line 126
    move-result v11

    .line 127
    invoke-virtual {v4}, Ll2/t;->m()Ll2/p1;

    .line 128
    .line 129
    .line 130
    move-result-object v12

    .line 131
    invoke-static {v4, v7}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 132
    .line 133
    .line 134
    move-result-object v7

    .line 135
    sget-object v13, Lv3/k;->m1:Lv3/j;

    .line 136
    .line 137
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 138
    .line 139
    .line 140
    sget-object v13, Lv3/j;->b:Lv3/i;

    .line 141
    .line 142
    invoke-virtual {v4}, Ll2/t;->c0()V

    .line 143
    .line 144
    .line 145
    iget-boolean v14, v4, Ll2/t;->S:Z

    .line 146
    .line 147
    if-eqz v14, :cond_7

    .line 148
    .line 149
    invoke-virtual {v4, v13}, Ll2/t;->l(Lay0/a;)V

    .line 150
    .line 151
    .line 152
    goto :goto_5

    .line 153
    :cond_7
    invoke-virtual {v4}, Ll2/t;->m0()V

    .line 154
    .line 155
    .line 156
    :goto_5
    sget-object v13, Lv3/j;->g:Lv3/h;

    .line 157
    .line 158
    invoke-static {v13, v10, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 159
    .line 160
    .line 161
    sget-object v10, Lv3/j;->f:Lv3/h;

    .line 162
    .line 163
    invoke-static {v10, v12, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 164
    .line 165
    .line 166
    sget-object v10, Lv3/j;->j:Lv3/h;

    .line 167
    .line 168
    iget-boolean v12, v4, Ll2/t;->S:Z

    .line 169
    .line 170
    if-nez v12, :cond_8

    .line 171
    .line 172
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object v12

    .line 176
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 177
    .line 178
    .line 179
    move-result-object v13

    .line 180
    invoke-static {v12, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 181
    .line 182
    .line 183
    move-result v12

    .line 184
    if-nez v12, :cond_9

    .line 185
    .line 186
    :cond_8
    invoke-static {v11, v4, v11, v10}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 187
    .line 188
    .line 189
    :cond_9
    sget-object v10, Lv3/j;->d:Lv3/h;

    .line 190
    .line 191
    invoke-static {v10, v7, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 192
    .line 193
    .line 194
    sget-object v7, Lj91/j;->a:Ll2/u2;

    .line 195
    .line 196
    invoke-virtual {v4, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 197
    .line 198
    .line 199
    move-result-object v10

    .line 200
    check-cast v10, Lj91/f;

    .line 201
    .line 202
    invoke-virtual {v10}, Lj91/f;->b()Lg4/p0;

    .line 203
    .line 204
    .line 205
    move-result-object v10

    .line 206
    sget-object v11, Lj91/h;->a:Ll2/u2;

    .line 207
    .line 208
    invoke-virtual {v4, v11}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    move-result-object v12

    .line 212
    check-cast v12, Lj91/e;

    .line 213
    .line 214
    invoke-virtual {v12}, Lj91/e;->q()J

    .line 215
    .line 216
    .line 217
    move-result-wide v12

    .line 218
    and-int/lit8 v19, v5, 0xe

    .line 219
    .line 220
    const/16 v20, 0x0

    .line 221
    .line 222
    const v21, 0xfff4

    .line 223
    .line 224
    .line 225
    const/4 v2, 0x0

    .line 226
    move v14, v5

    .line 227
    move-object v15, v6

    .line 228
    const-wide/16 v5, 0x0

    .line 229
    .line 230
    move-object/from16 v16, v7

    .line 231
    .line 232
    const/4 v7, 0x0

    .line 233
    move/from16 v17, v8

    .line 234
    .line 235
    move-object/from16 v18, v9

    .line 236
    .line 237
    const-wide/16 v8, 0x0

    .line 238
    .line 239
    move-object v1, v10

    .line 240
    const/4 v10, 0x0

    .line 241
    move-object/from16 v22, v11

    .line 242
    .line 243
    const/4 v11, 0x0

    .line 244
    move-object/from16 v23, v18

    .line 245
    .line 246
    move-object/from16 v18, v4

    .line 247
    .line 248
    move-wide v3, v12

    .line 249
    const-wide/16 v12, 0x0

    .line 250
    .line 251
    move/from16 v24, v14

    .line 252
    .line 253
    const/4 v14, 0x0

    .line 254
    move-object/from16 v25, v15

    .line 255
    .line 256
    const/4 v15, 0x0

    .line 257
    move-object/from16 v26, v16

    .line 258
    .line 259
    const/16 v16, 0x0

    .line 260
    .line 261
    move/from16 v27, v17

    .line 262
    .line 263
    const/16 v17, 0x0

    .line 264
    .line 265
    move-object/from16 v30, v22

    .line 266
    .line 267
    move-object/from16 v31, v23

    .line 268
    .line 269
    move-object/from16 v28, v25

    .line 270
    .line 271
    move-object/from16 v29, v26

    .line 272
    .line 273
    invoke-static/range {v0 .. v21}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 274
    .line 275
    .line 276
    move-object/from16 v0, v18

    .line 277
    .line 278
    move-object/from16 v15, v28

    .line 279
    .line 280
    invoke-virtual {v0, v15}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 281
    .line 282
    .line 283
    move-result-object v1

    .line 284
    check-cast v1, Lj91/c;

    .line 285
    .line 286
    iget v1, v1, Lj91/c;->c:F

    .line 287
    .line 288
    move-object/from16 v2, v31

    .line 289
    .line 290
    invoke-static {v2, v1}, Landroidx/compose/foundation/layout/d;->r(Lx2/s;F)Lx2/s;

    .line 291
    .line 292
    .line 293
    move-result-object v1

    .line 294
    invoke-static {v0, v1}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 295
    .line 296
    .line 297
    move-object/from16 v1, v29

    .line 298
    .line 299
    invoke-virtual {v0, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 300
    .line 301
    .line 302
    move-result-object v1

    .line 303
    check-cast v1, Lj91/f;

    .line 304
    .line 305
    invoke-virtual {v1}, Lj91/f;->a()Lg4/p0;

    .line 306
    .line 307
    .line 308
    move-result-object v1

    .line 309
    move-object/from16 v2, v30

    .line 310
    .line 311
    invoke-virtual {v0, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 312
    .line 313
    .line 314
    move-result-object v2

    .line 315
    check-cast v2, Lj91/e;

    .line 316
    .line 317
    invoke-virtual {v2}, Lj91/e;->q()J

    .line 318
    .line 319
    .line 320
    move-result-wide v3

    .line 321
    shr-int/lit8 v2, v24, 0x3

    .line 322
    .line 323
    and-int/lit8 v19, v2, 0xe

    .line 324
    .line 325
    const/4 v2, 0x0

    .line 326
    const/4 v15, 0x0

    .line 327
    move-object/from16 v0, p1

    .line 328
    .line 329
    invoke-static/range {v0 .. v21}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 330
    .line 331
    .line 332
    move-object/from16 v1, v18

    .line 333
    .line 334
    const/4 v2, 0x1

    .line 335
    invoke-virtual {v1, v2}, Ll2/t;->q(Z)V

    .line 336
    .line 337
    .line 338
    goto :goto_6

    .line 339
    :cond_a
    move-object v0, v1

    .line 340
    move-object v1, v4

    .line 341
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 342
    .line 343
    .line 344
    :goto_6
    invoke-virtual {v1}, Ll2/t;->s()Ll2/u1;

    .line 345
    .line 346
    .line 347
    move-result-object v1

    .line 348
    if-eqz v1, :cond_b

    .line 349
    .line 350
    new-instance v2, Lak/j;

    .line 351
    .line 352
    move-object/from16 v3, p0

    .line 353
    .line 354
    move-object/from16 v4, p2

    .line 355
    .line 356
    move/from16 v5, p4

    .line 357
    .line 358
    invoke-direct {v2, v5, v3, v0, v4}, Lak/j;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 359
    .line 360
    .line 361
    iput-object v2, v1, Ll2/u1;->d:Lay0/n;

    .line 362
    .line 363
    :cond_b
    return-void
.end method

.method public static final c(Llc/l;Lay0/k;Ll2/o;I)V
    .locals 8

    .line 1
    move-object v5, p2

    .line 2
    check-cast v5, Ll2/t;

    .line 3
    .line 4
    const p2, 0x2ddaca43

    .line 5
    .line 6
    .line 7
    invoke-virtual {v5, p2}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    invoke-virtual {v5, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    if-eqz p2, :cond_0

    .line 15
    .line 16
    const/4 p2, 0x4

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 p2, 0x2

    .line 19
    :goto_0
    or-int/2addr p2, p3

    .line 20
    invoke-virtual {v5, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    const/16 v1, 0x20

    .line 25
    .line 26
    if-eqz v0, :cond_1

    .line 27
    .line 28
    move v0, v1

    .line 29
    goto :goto_1

    .line 30
    :cond_1
    const/16 v0, 0x10

    .line 31
    .line 32
    :goto_1
    or-int/2addr p2, v0

    .line 33
    and-int/lit8 v0, p2, 0x13

    .line 34
    .line 35
    const/16 v2, 0x12

    .line 36
    .line 37
    const/4 v3, 0x0

    .line 38
    const/4 v4, 0x1

    .line 39
    if-eq v0, v2, :cond_2

    .line 40
    .line 41
    move v0, v4

    .line 42
    goto :goto_2

    .line 43
    :cond_2
    move v0, v3

    .line 44
    :goto_2
    and-int/lit8 v2, p2, 0x1

    .line 45
    .line 46
    invoke-virtual {v5, v2, v0}, Ll2/t;->O(IZ)Z

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    if-eqz v0, :cond_6

    .line 51
    .line 52
    and-int/lit8 v0, p2, 0x70

    .line 53
    .line 54
    if-ne v0, v1, :cond_3

    .line 55
    .line 56
    move v3, v4

    .line 57
    :cond_3
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    if-nez v3, :cond_4

    .line 62
    .line 63
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 64
    .line 65
    if-ne v0, v1, :cond_5

    .line 66
    .line 67
    :cond_4
    new-instance v0, Llk/f;

    .line 68
    .line 69
    const/16 v1, 0x1d

    .line 70
    .line 71
    invoke-direct {v0, v1, p1}, Llk/f;-><init>(ILay0/k;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {v5, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    :cond_5
    move-object v4, v0

    .line 78
    check-cast v4, Lay0/a;

    .line 79
    .line 80
    shl-int/lit8 p2, p2, 0x3

    .line 81
    .line 82
    and-int/lit8 p2, p2, 0x70

    .line 83
    .line 84
    const/4 v0, 0x6

    .line 85
    or-int v6, v0, p2

    .line 86
    .line 87
    const/16 v7, 0xc

    .line 88
    .line 89
    const-string v0, "remotestop_authorization"

    .line 90
    .line 91
    const/4 v2, 0x0

    .line 92
    const/4 v3, 0x0

    .line 93
    move-object v1, p0

    .line 94
    invoke-static/range {v0 .. v7}, Ldk/h;->c(Ljava/lang/String;Llc/l;Ljava/lang/String;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 95
    .line 96
    .line 97
    goto :goto_3

    .line 98
    :cond_6
    move-object v1, p0

    .line 99
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 100
    .line 101
    .line 102
    :goto_3
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    if-eqz p0, :cond_7

    .line 107
    .line 108
    new-instance p2, Ll2/u;

    .line 109
    .line 110
    const/16 v0, 0x19

    .line 111
    .line 112
    invoke-direct {p2, p3, v0, v1, p1}, Ll2/u;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 113
    .line 114
    .line 115
    iput-object p2, p0, Ll2/u1;->d:Lay0/n;

    .line 116
    .line 117
    :cond_7
    return-void
.end method

.method public static final d(Ll2/o;I)V
    .locals 10

    .line 1
    move-object v7, p0

    .line 2
    check-cast v7, Ll2/t;

    .line 3
    .line 4
    const p0, 0x7fb2b62e

    .line 5
    .line 6
    .line 7
    invoke-virtual {v7, p0}, Ll2/t;->a0(I)Ll2/t;

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
    invoke-virtual {v7, v0, p0}, Ll2/t;->O(IZ)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    if-eqz p0, :cond_1

    .line 22
    .line 23
    sget-object p0, Lx2/p;->b:Lx2/p;

    .line 24
    .line 25
    const/high16 v0, 0x3f800000    # 1.0f

    .line 26
    .line 27
    invoke-static {p0, v0}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    sget-object p0, Lj91/h;->a:Ll2/u2;

    .line 32
    .line 33
    invoke-virtual {v7, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    check-cast v1, Lj91/e;

    .line 38
    .line 39
    invoke-virtual {v1}, Lj91/e;->e()J

    .line 40
    .line 41
    .line 42
    move-result-wide v1

    .line 43
    invoke-virtual {v7, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    check-cast p0, Lj91/e;

    .line 48
    .line 49
    invoke-virtual {p0}, Lj91/e;->b()J

    .line 50
    .line 51
    .line 52
    move-result-wide v3

    .line 53
    const/4 v8, 0x6

    .line 54
    const/16 v9, 0x18

    .line 55
    .line 56
    const/4 v5, 0x0

    .line 57
    const/4 v6, 0x0

    .line 58
    invoke-static/range {v0 .. v9}, Lh2/n7;->d(Lx2/s;JJIFLl2/o;II)V

    .line 59
    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_1
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 63
    .line 64
    .line 65
    :goto_1
    invoke-virtual {v7}, Ll2/t;->s()Ll2/u1;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    if-eqz p0, :cond_2

    .line 70
    .line 71
    new-instance v0, Lnc0/l;

    .line 72
    .line 73
    const/4 v1, 0x6

    .line 74
    invoke-direct {v0, p1, v1}, Lnc0/l;-><init>(II)V

    .line 75
    .line 76
    .line 77
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 78
    .line 79
    :cond_2
    return-void
.end method

.method public static final e(Lig/a;ZLay0/a;Ll2/o;I)V
    .locals 18

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v3, p2

    .line 6
    .line 7
    move-object/from16 v7, p3

    .line 8
    .line 9
    check-cast v7, Ll2/t;

    .line 10
    .line 11
    const v0, 0x686238a5

    .line 12
    .line 13
    .line 14
    invoke-virtual {v7, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v7, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

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
    or-int v0, p4, v0

    .line 27
    .line 28
    invoke-virtual {v7, v2}, Ll2/t;->h(Z)Z

    .line 29
    .line 30
    .line 31
    move-result v4

    .line 32
    if-eqz v4, :cond_1

    .line 33
    .line 34
    const/16 v4, 0x20

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_1
    const/16 v4, 0x10

    .line 38
    .line 39
    :goto_1
    or-int/2addr v0, v4

    .line 40
    invoke-virtual {v7, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v4

    .line 44
    if-eqz v4, :cond_2

    .line 45
    .line 46
    const/16 v4, 0x100

    .line 47
    .line 48
    goto :goto_2

    .line 49
    :cond_2
    const/16 v4, 0x80

    .line 50
    .line 51
    :goto_2
    or-int/2addr v0, v4

    .line 52
    and-int/lit16 v4, v0, 0x93

    .line 53
    .line 54
    const/16 v5, 0x92

    .line 55
    .line 56
    const/4 v14, 0x1

    .line 57
    const/4 v15, 0x0

    .line 58
    if-eq v4, v5, :cond_3

    .line 59
    .line 60
    move v4, v14

    .line 61
    goto :goto_3

    .line 62
    :cond_3
    move v4, v15

    .line 63
    :goto_3
    and-int/lit8 v5, v0, 0x1

    .line 64
    .line 65
    invoke-virtual {v7, v5, v4}, Ll2/t;->O(IZ)Z

    .line 66
    .line 67
    .line 68
    move-result v4

    .line 69
    if-eqz v4, :cond_12

    .line 70
    .line 71
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v4

    .line 75
    sget-object v11, Ll2/n;->a:Ll2/x0;

    .line 76
    .line 77
    if-ne v4, v11, :cond_4

    .line 78
    .line 79
    sget-object v4, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 80
    .line 81
    invoke-static {v4}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 82
    .line 83
    .line 84
    move-result-object v4

    .line 85
    invoke-virtual {v7, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    :cond_4
    move-object v12, v4

    .line 89
    check-cast v12, Ll2/b1;

    .line 90
    .line 91
    sget-object v4, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 92
    .line 93
    invoke-static {v15, v14, v7}, Lkp/n;->b(IILl2/o;)Le1/n1;

    .line 94
    .line 95
    .line 96
    move-result-object v5

    .line 97
    const/16 v6, 0xe

    .line 98
    .line 99
    invoke-static {v4, v5, v6}, Lkp/n;->d(Lx2/s;Le1/n1;I)Lx2/s;

    .line 100
    .line 101
    .line 102
    move-result-object v4

    .line 103
    sget-object v5, Lk1/j;->c:Lk1/e;

    .line 104
    .line 105
    sget-object v6, Lx2/c;->p:Lx2/h;

    .line 106
    .line 107
    invoke-static {v5, v6, v7, v15}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 108
    .line 109
    .line 110
    move-result-object v8

    .line 111
    iget-wide v13, v7, Ll2/t;->T:J

    .line 112
    .line 113
    invoke-static {v13, v14}, Ljava/lang/Long;->hashCode(J)I

    .line 114
    .line 115
    .line 116
    move-result v9

    .line 117
    invoke-virtual {v7}, Ll2/t;->m()Ll2/p1;

    .line 118
    .line 119
    .line 120
    move-result-object v13

    .line 121
    invoke-static {v7, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 122
    .line 123
    .line 124
    move-result-object v4

    .line 125
    sget-object v14, Lv3/k;->m1:Lv3/j;

    .line 126
    .line 127
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 128
    .line 129
    .line 130
    sget-object v14, Lv3/j;->b:Lv3/i;

    .line 131
    .line 132
    invoke-virtual {v7}, Ll2/t;->c0()V

    .line 133
    .line 134
    .line 135
    iget-boolean v15, v7, Ll2/t;->S:Z

    .line 136
    .line 137
    if-eqz v15, :cond_5

    .line 138
    .line 139
    invoke-virtual {v7, v14}, Ll2/t;->l(Lay0/a;)V

    .line 140
    .line 141
    .line 142
    goto :goto_4

    .line 143
    :cond_5
    invoke-virtual {v7}, Ll2/t;->m0()V

    .line 144
    .line 145
    .line 146
    :goto_4
    sget-object v15, Lv3/j;->g:Lv3/h;

    .line 147
    .line 148
    invoke-static {v15, v8, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 149
    .line 150
    .line 151
    sget-object v8, Lv3/j;->f:Lv3/h;

    .line 152
    .line 153
    invoke-static {v8, v13, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 154
    .line 155
    .line 156
    sget-object v13, Lv3/j;->j:Lv3/h;

    .line 157
    .line 158
    iget-boolean v10, v7, Ll2/t;->S:Z

    .line 159
    .line 160
    if-nez v10, :cond_6

    .line 161
    .line 162
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object v10

    .line 166
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 167
    .line 168
    .line 169
    move-result-object v2

    .line 170
    invoke-static {v10, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 171
    .line 172
    .line 173
    move-result v2

    .line 174
    if-nez v2, :cond_7

    .line 175
    .line 176
    :cond_6
    invoke-static {v9, v7, v9, v13}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 177
    .line 178
    .line 179
    :cond_7
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 180
    .line 181
    invoke-static {v2, v4, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 182
    .line 183
    .line 184
    sget-object v10, Lj91/a;->a:Ll2/u2;

    .line 185
    .line 186
    invoke-virtual {v7, v10}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 187
    .line 188
    .line 189
    move-result-object v4

    .line 190
    check-cast v4, Lj91/c;

    .line 191
    .line 192
    iget v4, v4, Lj91/c;->j:F

    .line 193
    .line 194
    sget-object v9, Lx2/p;->b:Lx2/p;

    .line 195
    .line 196
    const/4 v3, 0x0

    .line 197
    move/from16 v16, v0

    .line 198
    .line 199
    const/4 v0, 0x2

    .line 200
    invoke-static {v9, v4, v3, v0}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 201
    .line 202
    .line 203
    move-result-object v4

    .line 204
    const/4 v0, 0x0

    .line 205
    invoke-static {v5, v6, v7, v0}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 206
    .line 207
    .line 208
    move-result-object v5

    .line 209
    move-object v6, v4

    .line 210
    iget-wide v3, v7, Ll2/t;->T:J

    .line 211
    .line 212
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 213
    .line 214
    .line 215
    move-result v3

    .line 216
    invoke-virtual {v7}, Ll2/t;->m()Ll2/p1;

    .line 217
    .line 218
    .line 219
    move-result-object v4

    .line 220
    invoke-static {v7, v6}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 221
    .line 222
    .line 223
    move-result-object v6

    .line 224
    invoke-virtual {v7}, Ll2/t;->c0()V

    .line 225
    .line 226
    .line 227
    iget-boolean v0, v7, Ll2/t;->S:Z

    .line 228
    .line 229
    if-eqz v0, :cond_8

    .line 230
    .line 231
    invoke-virtual {v7, v14}, Ll2/t;->l(Lay0/a;)V

    .line 232
    .line 233
    .line 234
    goto :goto_5

    .line 235
    :cond_8
    invoke-virtual {v7}, Ll2/t;->m0()V

    .line 236
    .line 237
    .line 238
    :goto_5
    invoke-static {v15, v5, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 239
    .line 240
    .line 241
    invoke-static {v8, v4, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 242
    .line 243
    .line 244
    iget-boolean v0, v7, Ll2/t;->S:Z

    .line 245
    .line 246
    if-nez v0, :cond_9

    .line 247
    .line 248
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 249
    .line 250
    .line 251
    move-result-object v0

    .line 252
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 253
    .line 254
    .line 255
    move-result-object v4

    .line 256
    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 257
    .line 258
    .line 259
    move-result v0

    .line 260
    if-nez v0, :cond_a

    .line 261
    .line 262
    :cond_9
    invoke-static {v3, v7, v3, v13}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 263
    .line 264
    .line 265
    :cond_a
    invoke-static {v2, v6, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 266
    .line 267
    .line 268
    const-string v0, "remotestop_authorization_elli_header"

    .line 269
    .line 270
    invoke-static {v9, v0}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 271
    .line 272
    .line 273
    move-result-object v4

    .line 274
    const/4 v8, 0x6

    .line 275
    move-object v0, v9

    .line 276
    const/4 v9, 0x6

    .line 277
    const/4 v5, 0x0

    .line 278
    const/4 v6, 0x0

    .line 279
    invoke-static/range {v4 .. v9}, Ldk/c;->b(Lx2/s;Lg4/p0;Ljava/lang/String;Ll2/o;II)V

    .line 280
    .line 281
    .line 282
    invoke-virtual {v7, v10}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 283
    .line 284
    .line 285
    move-result-object v2

    .line 286
    check-cast v2, Lj91/c;

    .line 287
    .line 288
    iget v2, v2, Lj91/c;->f:F

    .line 289
    .line 290
    invoke-static {v0, v2}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 291
    .line 292
    .line 293
    move-result-object v2

    .line 294
    invoke-static {v7, v2}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 295
    .line 296
    .line 297
    const/4 v2, 0x0

    .line 298
    invoke-static {v7, v2}, Ljp/ra;->d(Ll2/o;I)V

    .line 299
    .line 300
    .line 301
    invoke-virtual {v7, v10}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 302
    .line 303
    .line 304
    move-result-object v3

    .line 305
    check-cast v3, Lj91/c;

    .line 306
    .line 307
    iget v3, v3, Lj91/c;->f:F

    .line 308
    .line 309
    invoke-static {v0, v3}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 310
    .line 311
    .line 312
    move-result-object v3

    .line 313
    invoke-static {v7, v3}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 314
    .line 315
    .line 316
    iget-object v3, v1, Lig/a;->a:Ljava/lang/String;

    .line 317
    .line 318
    invoke-static {v3, v7, v2}, Ljp/ra;->f(Ljava/lang/String;Ll2/o;I)V

    .line 319
    .line 320
    .line 321
    sget-object v3, Lj91/h;->a:Ll2/u2;

    .line 322
    .line 323
    invoke-virtual {v7, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 324
    .line 325
    .line 326
    move-result-object v3

    .line 327
    check-cast v3, Lj91/e;

    .line 328
    .line 329
    invoke-virtual {v3}, Lj91/e;->r()J

    .line 330
    .line 331
    .line 332
    move-result-wide v3

    .line 333
    const/4 v13, 0x1

    .line 334
    int-to-float v5, v13

    .line 335
    move-object v8, v7

    .line 336
    move-wide v6, v3

    .line 337
    const/4 v4, 0x0

    .line 338
    const/16 v9, 0x30

    .line 339
    .line 340
    invoke-static/range {v4 .. v9}, Lh2/r;->g(Lx2/s;FJLl2/o;I)V

    .line 341
    .line 342
    .line 343
    move-object v7, v8

    .line 344
    iget-object v3, v1, Lig/a;->b:Ljava/lang/String;

    .line 345
    .line 346
    invoke-static {v3, v7, v2}, Ljp/ra;->a(Ljava/lang/String;Ll2/o;I)V

    .line 347
    .line 348
    .line 349
    invoke-virtual {v7, v13}, Ll2/t;->q(Z)V

    .line 350
    .line 351
    .line 352
    const/high16 v2, 0x3f800000    # 1.0f

    .line 353
    .line 354
    float-to-double v3, v2

    .line 355
    const-wide/16 v5, 0x0

    .line 356
    .line 357
    cmpl-double v3, v3, v5

    .line 358
    .line 359
    if-lez v3, :cond_b

    .line 360
    .line 361
    goto :goto_6

    .line 362
    :cond_b
    const-string v3, "invalid weight; must be greater than zero"

    .line 363
    .line 364
    invoke-static {v3}, Ll1/a;->a(Ljava/lang/String;)V

    .line 365
    .line 366
    .line 367
    :goto_6
    new-instance v3, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 368
    .line 369
    invoke-direct {v3, v2, v13}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 370
    .line 371
    .line 372
    invoke-static {v7, v3}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 373
    .line 374
    .line 375
    const v2, 0x7f120b11

    .line 376
    .line 377
    .line 378
    invoke-static {v7, v2}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 379
    .line 380
    .line 381
    move-result-object v8

    .line 382
    xor-int/lit8 v2, p1, 0x1

    .line 383
    .line 384
    const/16 v3, 0x48

    .line 385
    .line 386
    int-to-float v3, v3

    .line 387
    const/4 v4, 0x0

    .line 388
    const/4 v5, 0x2

    .line 389
    invoke-static {v0, v3, v4, v5}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 390
    .line 391
    .line 392
    move-result-object v3

    .line 393
    const-string v4, "remotestop_authorization_cta"

    .line 394
    .line 395
    invoke-static {v3, v4}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 396
    .line 397
    .line 398
    move-result-object v3

    .line 399
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 400
    .line 401
    .line 402
    move-result-object v4

    .line 403
    if-ne v4, v11, :cond_c

    .line 404
    .line 405
    new-instance v4, Lio0/f;

    .line 406
    .line 407
    const/4 v5, 0x6

    .line 408
    invoke-direct {v4, v12, v5}, Lio0/f;-><init>(Ll2/b1;I)V

    .line 409
    .line 410
    .line 411
    invoke-virtual {v7, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 412
    .line 413
    .line 414
    :cond_c
    move-object v6, v4

    .line 415
    check-cast v6, Lay0/a;

    .line 416
    .line 417
    const v4, 0x301b0

    .line 418
    .line 419
    .line 420
    const/16 v5, 0x8

    .line 421
    .line 422
    move-object v9, v7

    .line 423
    const/4 v7, 0x0

    .line 424
    move-object v13, v12

    .line 425
    const/4 v12, 0x1

    .line 426
    move-object/from16 v17, v11

    .line 427
    .line 428
    move v11, v2

    .line 429
    move-object v2, v10

    .line 430
    move-object v10, v3

    .line 431
    move-object/from16 v3, v17

    .line 432
    .line 433
    invoke-static/range {v4 .. v12}, Li91/j0;->f0(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;ZZ)V

    .line 434
    .line 435
    .line 436
    move-object v7, v9

    .line 437
    invoke-interface {v13}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 438
    .line 439
    .line 440
    move-result-object v4

    .line 441
    check-cast v4, Ljava/lang/Boolean;

    .line 442
    .line 443
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 444
    .line 445
    .line 446
    move-result v4

    .line 447
    if-eqz v4, :cond_11

    .line 448
    .line 449
    const v4, -0x56e04e1d

    .line 450
    .line 451
    .line 452
    invoke-virtual {v7, v4}, Ll2/t;->Y(I)V

    .line 453
    .line 454
    .line 455
    invoke-interface {v13}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 456
    .line 457
    .line 458
    move-result-object v4

    .line 459
    check-cast v4, Ljava/lang/Boolean;

    .line 460
    .line 461
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 462
    .line 463
    .line 464
    move-result v4

    .line 465
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 466
    .line 467
    .line 468
    move-result-object v5

    .line 469
    if-ne v5, v3, :cond_d

    .line 470
    .line 471
    new-instance v5, Lio0/f;

    .line 472
    .line 473
    const/4 v6, 0x7

    .line 474
    invoke-direct {v5, v13, v6}, Lio0/f;-><init>(Ll2/b1;I)V

    .line 475
    .line 476
    .line 477
    invoke-virtual {v7, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 478
    .line 479
    .line 480
    :cond_d
    check-cast v5, Lay0/a;

    .line 481
    .line 482
    move/from16 v6, v16

    .line 483
    .line 484
    and-int/lit16 v6, v6, 0x380

    .line 485
    .line 486
    const/16 v8, 0x100

    .line 487
    .line 488
    if-ne v6, v8, :cond_e

    .line 489
    .line 490
    const/4 v6, 0x1

    .line 491
    goto :goto_7

    .line 492
    :cond_e
    const/4 v6, 0x0

    .line 493
    :goto_7
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 494
    .line 495
    .line 496
    move-result-object v8

    .line 497
    if-nez v6, :cond_10

    .line 498
    .line 499
    if-ne v8, v3, :cond_f

    .line 500
    .line 501
    goto :goto_8

    .line 502
    :cond_f
    move-object/from16 v6, p2

    .line 503
    .line 504
    goto :goto_9

    .line 505
    :cond_10
    :goto_8
    new-instance v8, Lb71/h;

    .line 506
    .line 507
    const/16 v3, 0xc

    .line 508
    .line 509
    move-object/from16 v6, p2

    .line 510
    .line 511
    invoke-direct {v8, v3, v6, v13}, Lb71/h;-><init>(ILay0/a;Ll2/b1;)V

    .line 512
    .line 513
    .line 514
    invoke-virtual {v7, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 515
    .line 516
    .line 517
    :goto_9
    check-cast v8, Lay0/a;

    .line 518
    .line 519
    const/16 v3, 0x30

    .line 520
    .line 521
    invoke-static {v3, v5, v8, v7, v4}, Ljp/ra;->h(ILay0/a;Lay0/a;Ll2/o;Z)V

    .line 522
    .line 523
    .line 524
    const/4 v3, 0x0

    .line 525
    :goto_a
    invoke-virtual {v7, v3}, Ll2/t;->q(Z)V

    .line 526
    .line 527
    .line 528
    goto :goto_b

    .line 529
    :cond_11
    move-object/from16 v6, p2

    .line 530
    .line 531
    const/4 v3, 0x0

    .line 532
    const v4, -0x574896ed

    .line 533
    .line 534
    .line 535
    invoke-virtual {v7, v4}, Ll2/t;->Y(I)V

    .line 536
    .line 537
    .line 538
    goto :goto_a

    .line 539
    :goto_b
    invoke-virtual {v7, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 540
    .line 541
    .line 542
    move-result-object v2

    .line 543
    check-cast v2, Lj91/c;

    .line 544
    .line 545
    iget v2, v2, Lj91/c;->f:F

    .line 546
    .line 547
    const/4 v13, 0x1

    .line 548
    invoke-static {v0, v2, v7, v13}, Lvj/b;->z(Lx2/p;FLl2/t;Z)V

    .line 549
    .line 550
    .line 551
    goto :goto_c

    .line 552
    :cond_12
    move-object v6, v3

    .line 553
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 554
    .line 555
    .line 556
    :goto_c
    invoke-virtual {v7}, Ll2/t;->s()Ll2/u1;

    .line 557
    .line 558
    .line 559
    move-result-object v7

    .line 560
    if-eqz v7, :cond_13

    .line 561
    .line 562
    new-instance v0, La71/l0;

    .line 563
    .line 564
    const/4 v5, 0x7

    .line 565
    move/from16 v2, p1

    .line 566
    .line 567
    move/from16 v4, p4

    .line 568
    .line 569
    move-object v3, v6

    .line 570
    invoke-direct/range {v0 .. v5}, La71/l0;-><init>(Ljava/lang/Object;ZLjava/lang/Object;II)V

    .line 571
    .line 572
    .line 573
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 574
    .line 575
    :cond_13
    return-void
.end method

.method public static final f(Ljava/lang/String;Ll2/o;I)V
    .locals 3

    .line 1
    check-cast p1, Ll2/t;

    .line 2
    .line 3
    const v0, -0x6ef19359

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p1, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const/4 v1, 0x2

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    const/4 v0, 0x4

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move v0, v1

    .line 19
    :goto_0
    or-int/2addr v0, p2

    .line 20
    and-int/lit8 v2, v0, 0x3

    .line 21
    .line 22
    if-eq v2, v1, :cond_1

    .line 23
    .line 24
    const/4 v1, 0x1

    .line 25
    goto :goto_1

    .line 26
    :cond_1
    const/4 v1, 0x0

    .line 27
    :goto_1
    and-int/lit8 v2, v0, 0x1

    .line 28
    .line 29
    invoke-virtual {p1, v2, v1}, Ll2/t;->O(IZ)Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_2

    .line 34
    .line 35
    const v1, 0x7f120b0d

    .line 36
    .line 37
    .line 38
    invoke-static {p1, v1}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    shl-int/lit8 v0, v0, 0x3

    .line 43
    .line 44
    and-int/lit8 v0, v0, 0x70

    .line 45
    .line 46
    or-int/lit16 v0, v0, 0x180

    .line 47
    .line 48
    const-string v2, "remotestop_authorization_session_started"

    .line 49
    .line 50
    invoke-static {v1, p0, v2, p1, v0}, Ljp/ra;->b(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ll2/o;I)V

    .line 51
    .line 52
    .line 53
    goto :goto_2

    .line 54
    :cond_2
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 55
    .line 56
    .line 57
    :goto_2
    invoke-virtual {p1}, Ll2/t;->s()Ll2/u1;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    if-eqz p1, :cond_3

    .line 62
    .line 63
    new-instance v0, Ll20/d;

    .line 64
    .line 65
    const/16 v1, 0xe

    .line 66
    .line 67
    invoke-direct {v0, p0, p2, v1}, Ll20/d;-><init>(Ljava/lang/String;II)V

    .line 68
    .line 69
    .line 70
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 71
    .line 72
    :cond_3
    return-void
.end method

.method public static final g(Lig/e;Lay0/k;Ll2/o;I)V
    .locals 12

    .line 1
    const-string v0, "uiState"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lig/e;->c:Llc/l;

    .line 7
    .line 8
    const-string v1, "event"

    .line 9
    .line 10
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    move-object v6, p2

    .line 14
    check-cast v6, Ll2/t;

    .line 15
    .line 16
    const p2, 0x707f32df

    .line 17
    .line 18
    .line 19
    invoke-virtual {v6, p2}, Ll2/t;->a0(I)Ll2/t;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v6, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result p2

    .line 26
    const/4 v1, 0x2

    .line 27
    if-eqz p2, :cond_0

    .line 28
    .line 29
    const/4 p2, 0x4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    move p2, v1

    .line 32
    :goto_0
    or-int/2addr p2, p3

    .line 33
    invoke-virtual {v6, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    const/16 v9, 0x20

    .line 38
    .line 39
    if-eqz v2, :cond_1

    .line 40
    .line 41
    move v2, v9

    .line 42
    goto :goto_1

    .line 43
    :cond_1
    const/16 v2, 0x10

    .line 44
    .line 45
    :goto_1
    or-int/2addr p2, v2

    .line 46
    and-int/lit8 v2, p2, 0x13

    .line 47
    .line 48
    const/16 v3, 0x12

    .line 49
    .line 50
    const/4 v10, 0x1

    .line 51
    const/4 v11, 0x0

    .line 52
    if-eq v2, v3, :cond_2

    .line 53
    .line 54
    move v2, v10

    .line 55
    goto :goto_2

    .line 56
    :cond_2
    move v2, v11

    .line 57
    :goto_2
    and-int/lit8 v3, p2, 0x1

    .line 58
    .line 59
    invoke-virtual {v6, v3, v2}, Ll2/t;->O(IZ)Z

    .line 60
    .line 61
    .line 62
    move-result v2

    .line 63
    if-eqz v2, :cond_b

    .line 64
    .line 65
    sget-object v2, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 66
    .line 67
    sget-object v3, Lj91/h;->a:Ll2/u2;

    .line 68
    .line 69
    invoke-virtual {v6, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v3

    .line 73
    check-cast v3, Lj91/e;

    .line 74
    .line 75
    invoke-virtual {v3}, Lj91/e;->b()J

    .line 76
    .line 77
    .line 78
    move-result-wide v3

    .line 79
    sget-object v5, Le3/j0;->a:Le3/i0;

    .line 80
    .line 81
    invoke-static {v2, v3, v4, v5}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 82
    .line 83
    .line 84
    move-result-object v2

    .line 85
    sget-object v3, Lk1/j;->c:Lk1/e;

    .line 86
    .line 87
    sget-object v4, Lx2/c;->p:Lx2/h;

    .line 88
    .line 89
    invoke-static {v3, v4, v6, v11}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 90
    .line 91
    .line 92
    move-result-object v3

    .line 93
    iget-wide v4, v6, Ll2/t;->T:J

    .line 94
    .line 95
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 96
    .line 97
    .line 98
    move-result v4

    .line 99
    invoke-virtual {v6}, Ll2/t;->m()Ll2/p1;

    .line 100
    .line 101
    .line 102
    move-result-object v5

    .line 103
    invoke-static {v6, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 104
    .line 105
    .line 106
    move-result-object v2

    .line 107
    sget-object v7, Lv3/k;->m1:Lv3/j;

    .line 108
    .line 109
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 110
    .line 111
    .line 112
    sget-object v7, Lv3/j;->b:Lv3/i;

    .line 113
    .line 114
    invoke-virtual {v6}, Ll2/t;->c0()V

    .line 115
    .line 116
    .line 117
    iget-boolean v8, v6, Ll2/t;->S:Z

    .line 118
    .line 119
    if-eqz v8, :cond_3

    .line 120
    .line 121
    invoke-virtual {v6, v7}, Ll2/t;->l(Lay0/a;)V

    .line 122
    .line 123
    .line 124
    goto :goto_3

    .line 125
    :cond_3
    invoke-virtual {v6}, Ll2/t;->m0()V

    .line 126
    .line 127
    .line 128
    :goto_3
    sget-object v7, Lv3/j;->g:Lv3/h;

    .line 129
    .line 130
    invoke-static {v7, v3, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 131
    .line 132
    .line 133
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 134
    .line 135
    invoke-static {v3, v5, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 136
    .line 137
    .line 138
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 139
    .line 140
    iget-boolean v5, v6, Ll2/t;->S:Z

    .line 141
    .line 142
    if-nez v5, :cond_4

    .line 143
    .line 144
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v5

    .line 148
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 149
    .line 150
    .line 151
    move-result-object v7

    .line 152
    invoke-static {v5, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 153
    .line 154
    .line 155
    move-result v5

    .line 156
    if-nez v5, :cond_5

    .line 157
    .line 158
    :cond_4
    invoke-static {v4, v6, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 159
    .line 160
    .line 161
    :cond_5
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 162
    .line 163
    invoke-static {v3, v2, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 164
    .line 165
    .line 166
    iget-object v2, p0, Lig/e;->a:Ljava/lang/String;

    .line 167
    .line 168
    new-instance v4, Li91/w2;

    .line 169
    .line 170
    invoke-static {v6}, Lzb/b;->r(Ll2/o;)Lay0/a;

    .line 171
    .line 172
    .line 173
    move-result-object v3

    .line 174
    invoke-direct {v4, v3, v1}, Li91/w2;-><init>(Lay0/a;I)V

    .line 175
    .line 176
    .line 177
    const/4 v7, 0x0

    .line 178
    const/16 v8, 0xa

    .line 179
    .line 180
    const/4 v3, 0x0

    .line 181
    const/4 v5, 0x0

    .line 182
    invoke-static/range {v2 .. v8}, Ldk/l;->a(Ljava/lang/String;Lx2/s;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;Ll2/o;II)V

    .line 183
    .line 184
    .line 185
    sget-object v1, Lj91/a;->a:Ll2/u2;

    .line 186
    .line 187
    invoke-virtual {v6, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object v1

    .line 191
    check-cast v1, Lj91/c;

    .line 192
    .line 193
    iget v1, v1, Lj91/c;->g:F

    .line 194
    .line 195
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 196
    .line 197
    invoke-static {v2, v1}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 198
    .line 199
    .line 200
    move-result-object v1

    .line 201
    invoke-static {v6, v1}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 202
    .line 203
    .line 204
    iget-boolean v1, p0, Lig/e;->d:Z

    .line 205
    .line 206
    if-eqz v1, :cond_6

    .line 207
    .line 208
    const p2, 0xe958a97

    .line 209
    .line 210
    .line 211
    invoke-virtual {v6, p2}, Ll2/t;->Y(I)V

    .line 212
    .line 213
    .line 214
    invoke-static {v11, v10, v6, v11}, Ldk/b;->e(IILl2/o;Z)V

    .line 215
    .line 216
    .line 217
    invoke-virtual {v6, v11}, Ll2/t;->q(Z)V

    .line 218
    .line 219
    .line 220
    goto :goto_5

    .line 221
    :cond_6
    if-eqz v0, :cond_7

    .line 222
    .line 223
    const v1, 0xe95913c

    .line 224
    .line 225
    .line 226
    invoke-virtual {v6, v1}, Ll2/t;->Y(I)V

    .line 227
    .line 228
    .line 229
    and-int/lit8 p2, p2, 0x70

    .line 230
    .line 231
    invoke-static {v0, p1, v6, p2}, Ljp/ra;->c(Llc/l;Lay0/k;Ll2/o;I)V

    .line 232
    .line 233
    .line 234
    invoke-virtual {v6, v11}, Ll2/t;->q(Z)V

    .line 235
    .line 236
    .line 237
    goto :goto_5

    .line 238
    :cond_7
    const v0, 0xe959ae9

    .line 239
    .line 240
    .line 241
    invoke-virtual {v6, v0}, Ll2/t;->Y(I)V

    .line 242
    .line 243
    .line 244
    iget-object v0, p0, Lig/e;->b:Lig/a;

    .line 245
    .line 246
    iget-boolean v1, p0, Lig/e;->e:Z

    .line 247
    .line 248
    and-int/lit8 p2, p2, 0x70

    .line 249
    .line 250
    if-ne p2, v9, :cond_8

    .line 251
    .line 252
    move p2, v10

    .line 253
    goto :goto_4

    .line 254
    :cond_8
    move p2, v11

    .line 255
    :goto_4
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 256
    .line 257
    .line 258
    move-result-object v2

    .line 259
    if-nez p2, :cond_9

    .line 260
    .line 261
    sget-object p2, Ll2/n;->a:Ll2/x0;

    .line 262
    .line 263
    if-ne v2, p2, :cond_a

    .line 264
    .line 265
    :cond_9
    new-instance v2, Llk/f;

    .line 266
    .line 267
    const/16 p2, 0x1c

    .line 268
    .line 269
    invoke-direct {v2, p2, p1}, Llk/f;-><init>(ILay0/k;)V

    .line 270
    .line 271
    .line 272
    invoke-virtual {v6, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 273
    .line 274
    .line 275
    :cond_a
    check-cast v2, Lay0/a;

    .line 276
    .line 277
    invoke-static {v0, v1, v2, v6, v11}, Ljp/ra;->e(Lig/a;ZLay0/a;Ll2/o;I)V

    .line 278
    .line 279
    .line 280
    invoke-virtual {v6, v11}, Ll2/t;->q(Z)V

    .line 281
    .line 282
    .line 283
    :goto_5
    invoke-virtual {v6, v10}, Ll2/t;->q(Z)V

    .line 284
    .line 285
    .line 286
    goto :goto_6

    .line 287
    :cond_b
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 288
    .line 289
    .line 290
    :goto_6
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 291
    .line 292
    .line 293
    move-result-object p2

    .line 294
    if-eqz p2, :cond_c

    .line 295
    .line 296
    new-instance v0, Ll2/u;

    .line 297
    .line 298
    const/16 v1, 0x18

    .line 299
    .line 300
    invoke-direct {v0, p3, v1, p0, p1}, Ll2/u;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 301
    .line 302
    .line 303
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 304
    .line 305
    :cond_c
    return-void
.end method

.method public static final h(ILay0/a;Lay0/a;Ll2/o;Z)V
    .locals 20

    .line 1
    move/from16 v1, p4

    .line 2
    .line 3
    move-object/from16 v0, p3

    .line 4
    .line 5
    check-cast v0, Ll2/t;

    .line 6
    .line 7
    const v2, -0xde409a    # -2.149995E38f

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v0, v1}, Ll2/t;->h(Z)Z

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    if-eqz v2, :cond_0

    .line 18
    .line 19
    const/4 v2, 0x4

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v2, 0x2

    .line 22
    :goto_0
    or-int v2, p0, v2

    .line 23
    .line 24
    move-object/from16 v3, p2

    .line 25
    .line 26
    invoke-virtual {v0, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v4

    .line 30
    if-eqz v4, :cond_1

    .line 31
    .line 32
    const/16 v4, 0x100

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_1
    const/16 v4, 0x80

    .line 36
    .line 37
    :goto_1
    or-int/2addr v2, v4

    .line 38
    and-int/lit16 v4, v2, 0x93

    .line 39
    .line 40
    const/16 v5, 0x92

    .line 41
    .line 42
    const/4 v6, 0x0

    .line 43
    if-eq v4, v5, :cond_2

    .line 44
    .line 45
    const/4 v4, 0x1

    .line 46
    goto :goto_2

    .line 47
    :cond_2
    move v4, v6

    .line 48
    :goto_2
    and-int/lit8 v5, v2, 0x1

    .line 49
    .line 50
    invoke-virtual {v0, v5, v4}, Ll2/t;->O(IZ)Z

    .line 51
    .line 52
    .line 53
    move-result v4

    .line 54
    if-eqz v4, :cond_4

    .line 55
    .line 56
    if-eqz v1, :cond_3

    .line 57
    .line 58
    const v4, -0x7bd96e5

    .line 59
    .line 60
    .line 61
    invoke-virtual {v0, v4}, Ll2/t;->Y(I)V

    .line 62
    .line 63
    .line 64
    const v4, 0x7f120b10

    .line 65
    .line 66
    .line 67
    invoke-static {v0, v4}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v4

    .line 71
    const v5, 0x7f120b0f

    .line 72
    .line 73
    .line 74
    invoke-static {v0, v5}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object v5

    .line 78
    const v7, 0x7f120b0e

    .line 79
    .line 80
    .line 81
    invoke-static {v0, v7}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v7

    .line 85
    const v8, 0x7f120931

    .line 86
    .line 87
    .line 88
    invoke-static {v0, v8}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object v8

    .line 92
    shl-int/lit8 v2, v2, 0x9

    .line 93
    .line 94
    const/high16 v9, 0x70000

    .line 95
    .line 96
    and-int/2addr v2, v9

    .line 97
    const v9, 0xc00180

    .line 98
    .line 99
    .line 100
    or-int v17, v2, v9

    .line 101
    .line 102
    const/16 v18, 0xc00

    .line 103
    .line 104
    const/16 v19, 0x1f10

    .line 105
    .line 106
    move v2, v6

    .line 107
    const/4 v6, 0x0

    .line 108
    const/4 v10, 0x0

    .line 109
    const/4 v11, 0x0

    .line 110
    const/4 v12, 0x0

    .line 111
    const/4 v13, 0x0

    .line 112
    const/4 v14, 0x0

    .line 113
    const-string v15, "remotestop_authorization_stop_charging_dialog"

    .line 114
    .line 115
    move-object/from16 v9, p1

    .line 116
    .line 117
    move-object/from16 v16, v7

    .line 118
    .line 119
    move-object v7, v3

    .line 120
    move-object v3, v5

    .line 121
    move-object/from16 v5, v16

    .line 122
    .line 123
    move-object/from16 v16, v0

    .line 124
    .line 125
    move v0, v2

    .line 126
    move-object v2, v4

    .line 127
    move-object/from16 v4, p1

    .line 128
    .line 129
    invoke-static/range {v2 .. v19}, Li91/j0;->d(Ljava/lang/String;Ljava/lang/String;Lay0/a;Ljava/lang/String;Lx2/s;Lay0/a;Ljava/lang/String;Lay0/a;Lx4/p;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ll2/o;III)V

    .line 130
    .line 131
    .line 132
    move-object/from16 v2, v16

    .line 133
    .line 134
    :goto_3
    invoke-virtual {v2, v0}, Ll2/t;->q(Z)V

    .line 135
    .line 136
    .line 137
    goto :goto_4

    .line 138
    :cond_3
    move-object v2, v0

    .line 139
    move v0, v6

    .line 140
    const v3, -0x82e6384

    .line 141
    .line 142
    .line 143
    invoke-virtual {v2, v3}, Ll2/t;->Y(I)V

    .line 144
    .line 145
    .line 146
    goto :goto_3

    .line 147
    :cond_4
    move-object v2, v0

    .line 148
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 149
    .line 150
    .line 151
    :goto_4
    invoke-virtual {v2}, Ll2/t;->s()Ll2/u1;

    .line 152
    .line 153
    .line 154
    move-result-object v6

    .line 155
    if-eqz v6, :cond_5

    .line 156
    .line 157
    new-instance v0, La71/p;

    .line 158
    .line 159
    const/4 v5, 0x2

    .line 160
    move/from16 v4, p0

    .line 161
    .line 162
    move-object/from16 v2, p1

    .line 163
    .line 164
    move-object/from16 v3, p2

    .line 165
    .line 166
    invoke-direct/range {v0 .. v5}, La71/p;-><init>(ZLay0/a;Lay0/a;II)V

    .line 167
    .line 168
    .line 169
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 170
    .line 171
    :cond_5
    return-void
.end method

.method public static final i(Ly1/i;Lzg/h;Lai/a;Lxh/e;Lzb/d;Lzg/c1;Ll2/o;I)V
    .locals 24

    .line 1
    move-object/from16 v2, p1

    .line 2
    .line 3
    move-object/from16 v3, p2

    .line 4
    .line 5
    move-object/from16 v8, p6

    .line 6
    .line 7
    check-cast v8, Ll2/t;

    .line 8
    .line 9
    const v0, 0x75b7d9aa

    .line 10
    .line 11
    .line 12
    invoke-virtual {v8, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    move-object/from16 v1, p0

    .line 16
    .line 17
    invoke-virtual {v8, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    const/4 v4, 0x4

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    move v0, v4

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 v0, 0x2

    .line 27
    :goto_0
    or-int v0, p7, v0

    .line 28
    .line 29
    invoke-virtual {v8, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v5

    .line 33
    if-eqz v5, :cond_1

    .line 34
    .line 35
    const/16 v5, 0x20

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_1
    const/16 v5, 0x10

    .line 39
    .line 40
    :goto_1
    or-int/2addr v0, v5

    .line 41
    invoke-virtual {v8, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v5

    .line 45
    if-eqz v5, :cond_2

    .line 46
    .line 47
    const/16 v5, 0x100

    .line 48
    .line 49
    goto :goto_2

    .line 50
    :cond_2
    const/16 v5, 0x80

    .line 51
    .line 52
    :goto_2
    or-int/2addr v0, v5

    .line 53
    move-object/from16 v5, p3

    .line 54
    .line 55
    invoke-virtual {v8, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result v6

    .line 59
    const/16 v7, 0x800

    .line 60
    .line 61
    if-eqz v6, :cond_3

    .line 62
    .line 63
    move v6, v7

    .line 64
    goto :goto_3

    .line 65
    :cond_3
    const/16 v6, 0x400

    .line 66
    .line 67
    :goto_3
    or-int/2addr v0, v6

    .line 68
    move-object/from16 v6, p4

    .line 69
    .line 70
    invoke-virtual {v8, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    move-result v9

    .line 74
    const/16 v10, 0x4000

    .line 75
    .line 76
    if-eqz v9, :cond_4

    .line 77
    .line 78
    move v9, v10

    .line 79
    goto :goto_4

    .line 80
    :cond_4
    const/16 v9, 0x2000

    .line 81
    .line 82
    :goto_4
    or-int/2addr v0, v9

    .line 83
    move-object/from16 v9, p5

    .line 84
    .line 85
    invoke-virtual {v8, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v11

    .line 89
    const/high16 v12, 0x20000

    .line 90
    .line 91
    if-eqz v11, :cond_5

    .line 92
    .line 93
    move v11, v12

    .line 94
    goto :goto_5

    .line 95
    :cond_5
    const/high16 v11, 0x10000

    .line 96
    .line 97
    :goto_5
    or-int/2addr v0, v11

    .line 98
    const v11, 0x12493

    .line 99
    .line 100
    .line 101
    and-int/2addr v11, v0

    .line 102
    const v13, 0x12492

    .line 103
    .line 104
    .line 105
    const/4 v14, 0x1

    .line 106
    const/4 v15, 0x0

    .line 107
    if-eq v11, v13, :cond_6

    .line 108
    .line 109
    move v11, v14

    .line 110
    goto :goto_6

    .line 111
    :cond_6
    move v11, v15

    .line 112
    :goto_6
    and-int/lit8 v13, v0, 0x1

    .line 113
    .line 114
    invoke-virtual {v8, v13, v11}, Ll2/t;->O(IZ)Z

    .line 115
    .line 116
    .line 117
    move-result v11

    .line 118
    if-eqz v11, :cond_12

    .line 119
    .line 120
    and-int/lit8 v11, v0, 0xe

    .line 121
    .line 122
    if-ne v11, v4, :cond_7

    .line 123
    .line 124
    move v4, v14

    .line 125
    goto :goto_7

    .line 126
    :cond_7
    move v4, v15

    .line 127
    :goto_7
    invoke-virtual {v8, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 128
    .line 129
    .line 130
    move-result v11

    .line 131
    or-int/2addr v4, v11

    .line 132
    invoke-virtual {v8, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    move-result v11

    .line 136
    or-int/2addr v4, v11

    .line 137
    and-int/lit16 v11, v0, 0x1c00

    .line 138
    .line 139
    if-ne v11, v7, :cond_8

    .line 140
    .line 141
    move v7, v14

    .line 142
    goto :goto_8

    .line 143
    :cond_8
    move v7, v15

    .line 144
    :goto_8
    or-int/2addr v4, v7

    .line 145
    const v7, 0xe000

    .line 146
    .line 147
    .line 148
    and-int/2addr v7, v0

    .line 149
    if-ne v7, v10, :cond_9

    .line 150
    .line 151
    move v7, v14

    .line 152
    goto :goto_9

    .line 153
    :cond_9
    move v7, v15

    .line 154
    :goto_9
    or-int/2addr v4, v7

    .line 155
    const/high16 v7, 0x70000

    .line 156
    .line 157
    and-int/2addr v0, v7

    .line 158
    if-ne v0, v12, :cond_a

    .line 159
    .line 160
    goto :goto_a

    .line 161
    :cond_a
    move v14, v15

    .line 162
    :goto_a
    or-int v0, v4, v14

    .line 163
    .line 164
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object v4

    .line 168
    sget-object v10, Ll2/n;->a:Ll2/x0;

    .line 169
    .line 170
    if-nez v0, :cond_b

    .line 171
    .line 172
    if-ne v4, v10, :cond_c

    .line 173
    .line 174
    :cond_b
    new-instance v0, Lbi/a;

    .line 175
    .line 176
    const/4 v7, 0x0

    .line 177
    move-object v4, v5

    .line 178
    move-object v5, v6

    .line 179
    move-object v6, v9

    .line 180
    invoke-direct/range {v0 .. v7}, Lbi/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 181
    .line 182
    .line 183
    invoke-virtual {v8, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 184
    .line 185
    .line 186
    move-object v4, v0

    .line 187
    :cond_c
    check-cast v4, Lay0/k;

    .line 188
    .line 189
    sget-object v0, Lw3/q1;->a:Ll2/u2;

    .line 190
    .line 191
    invoke-virtual {v8, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    move-result-object v0

    .line 195
    check-cast v0, Ljava/lang/Boolean;

    .line 196
    .line 197
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 198
    .line 199
    .line 200
    move-result v0

    .line 201
    if-eqz v0, :cond_d

    .line 202
    .line 203
    const v0, -0x105bcaaa

    .line 204
    .line 205
    .line 206
    invoke-virtual {v8, v0}, Ll2/t;->Y(I)V

    .line 207
    .line 208
    .line 209
    invoke-virtual {v8, v15}, Ll2/t;->q(Z)V

    .line 210
    .line 211
    .line 212
    const/4 v0, 0x0

    .line 213
    goto :goto_b

    .line 214
    :cond_d
    const v0, 0x31054eee

    .line 215
    .line 216
    .line 217
    invoke-virtual {v8, v0}, Ll2/t;->Y(I)V

    .line 218
    .line 219
    .line 220
    sget-object v0, Lzb/x;->a:Ll2/u2;

    .line 221
    .line 222
    invoke-virtual {v8, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 223
    .line 224
    .line 225
    move-result-object v0

    .line 226
    check-cast v0, Lhi/a;

    .line 227
    .line 228
    invoke-virtual {v8, v15}, Ll2/t;->q(Z)V

    .line 229
    .line 230
    .line 231
    :goto_b
    new-instance v3, Laf/a;

    .line 232
    .line 233
    const/4 v1, 0x4

    .line 234
    invoke-direct {v3, v0, v4, v1}, Laf/a;-><init>(Lhi/a;Lay0/k;I)V

    .line 235
    .line 236
    .line 237
    invoke-static {v8}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 238
    .line 239
    .line 240
    move-result-object v1

    .line 241
    if-eqz v1, :cond_11

    .line 242
    .line 243
    instance-of v0, v1, Landroidx/lifecycle/k;

    .line 244
    .line 245
    if-eqz v0, :cond_e

    .line 246
    .line 247
    move-object v0, v1

    .line 248
    check-cast v0, Landroidx/lifecycle/k;

    .line 249
    .line 250
    invoke-interface {v0}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 251
    .line 252
    .line 253
    move-result-object v0

    .line 254
    :goto_c
    move-object v4, v0

    .line 255
    goto :goto_d

    .line 256
    :cond_e
    sget-object v0, Lp7/a;->b:Lp7/a;

    .line 257
    .line 258
    goto :goto_c

    .line 259
    :goto_d
    const-class v0, Lbi/g;

    .line 260
    .line 261
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 262
    .line 263
    invoke-virtual {v2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 264
    .line 265
    .line 266
    move-result-object v0

    .line 267
    const/4 v2, 0x0

    .line 268
    move-object v5, v8

    .line 269
    invoke-static/range {v0 .. v5}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 270
    .line 271
    .line 272
    move-result-object v0

    .line 273
    check-cast v0, Lbi/g;

    .line 274
    .line 275
    invoke-static {v5}, Leh/a;->b(Ll2/o;)Leh/n;

    .line 276
    .line 277
    .line 278
    move-result-object v1

    .line 279
    iget-object v2, v0, Lbi/g;->j:Lyy0/l1;

    .line 280
    .line 281
    invoke-static {v2, v5}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 282
    .line 283
    .line 284
    move-result-object v2

    .line 285
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 286
    .line 287
    .line 288
    move-result-object v2

    .line 289
    check-cast v2, Lbi/f;

    .line 290
    .line 291
    invoke-virtual {v5, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 292
    .line 293
    .line 294
    move-result v3

    .line 295
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 296
    .line 297
    .line 298
    move-result-object v4

    .line 299
    if-nez v3, :cond_f

    .line 300
    .line 301
    if-ne v4, v10, :cond_10

    .line 302
    .line 303
    :cond_f
    new-instance v16, Laf/b;

    .line 304
    .line 305
    const/16 v22, 0x0

    .line 306
    .line 307
    const/16 v23, 0x8

    .line 308
    .line 309
    const/16 v17, 0x1

    .line 310
    .line 311
    const-class v19, Lbi/g;

    .line 312
    .line 313
    const-string v20, "onUiEvent"

    .line 314
    .line 315
    const-string v21, "onUiEvent(Lcariad/charging/multicharge/kitten/wallboxes/presentation/pvcharging/WallboxPVChargingUiEvent;)V"

    .line 316
    .line 317
    move-object/from16 v18, v0

    .line 318
    .line 319
    invoke-direct/range {v16 .. v23}, Laf/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 320
    .line 321
    .line 322
    move-object/from16 v4, v16

    .line 323
    .line 324
    invoke-virtual {v5, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 325
    .line 326
    .line 327
    :cond_10
    check-cast v4, Lhy0/g;

    .line 328
    .line 329
    check-cast v4, Lay0/k;

    .line 330
    .line 331
    invoke-interface {v1, v2, v4, v5, v15}, Leh/n;->a0(Lbi/f;Lay0/k;Ll2/o;I)V

    .line 332
    .line 333
    .line 334
    goto :goto_e

    .line 335
    :cond_11
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 336
    .line 337
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 338
    .line 339
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 340
    .line 341
    .line 342
    throw v0

    .line 343
    :cond_12
    move-object v5, v8

    .line 344
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 345
    .line 346
    .line 347
    :goto_e
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 348
    .line 349
    .line 350
    move-result-object v9

    .line 351
    if-eqz v9, :cond_13

    .line 352
    .line 353
    new-instance v0, Lb41/a;

    .line 354
    .line 355
    const/16 v8, 0x9

    .line 356
    .line 357
    move-object/from16 v1, p0

    .line 358
    .line 359
    move-object/from16 v2, p1

    .line 360
    .line 361
    move-object/from16 v3, p2

    .line 362
    .line 363
    move-object/from16 v4, p3

    .line 364
    .line 365
    move-object/from16 v5, p4

    .line 366
    .line 367
    move-object/from16 v6, p5

    .line 368
    .line 369
    move/from16 v7, p7

    .line 370
    .line 371
    invoke-direct/range {v0 .. v8}, Lb41/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    .line 372
    .line 373
    .line 374
    iput-object v0, v9, Ll2/u1;->d:Lay0/n;

    .line 375
    .line 376
    :cond_13
    return-void
.end method
