.class public abstract Lkp/q7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lx2/s;ZZLay0/a;Lay0/a;Ll2/o;I)V
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    move/from16 v12, p2

    .line 6
    .line 7
    move-object/from16 v13, p3

    .line 8
    .line 9
    move-object/from16 v14, p4

    .line 10
    .line 11
    const-string v2, "modifier"

    .line 12
    .line 13
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v2, "onTouchDown"

    .line 17
    .line 18
    invoke-static {v13, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v2, "onTouchUp"

    .line 22
    .line 23
    invoke-static {v14, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    move-object/from16 v10, p5

    .line 27
    .line 28
    check-cast v10, Ll2/t;

    .line 29
    .line 30
    const v2, -0x59872ee2

    .line 31
    .line 32
    .line 33
    invoke-virtual {v10, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 34
    .line 35
    .line 36
    invoke-virtual {v10, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result v2

    .line 40
    if-eqz v2, :cond_0

    .line 41
    .line 42
    const/4 v2, 0x4

    .line 43
    goto :goto_0

    .line 44
    :cond_0
    const/4 v2, 0x2

    .line 45
    :goto_0
    or-int v2, p6, v2

    .line 46
    .line 47
    invoke-virtual {v10, v1}, Ll2/t;->h(Z)Z

    .line 48
    .line 49
    .line 50
    move-result v3

    .line 51
    if-eqz v3, :cond_1

    .line 52
    .line 53
    const/16 v3, 0x20

    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_1
    const/16 v3, 0x10

    .line 57
    .line 58
    :goto_1
    or-int/2addr v2, v3

    .line 59
    invoke-virtual {v10, v12}, Ll2/t;->h(Z)Z

    .line 60
    .line 61
    .line 62
    move-result v3

    .line 63
    if-eqz v3, :cond_2

    .line 64
    .line 65
    const/16 v3, 0x100

    .line 66
    .line 67
    goto :goto_2

    .line 68
    :cond_2
    const/16 v3, 0x80

    .line 69
    .line 70
    :goto_2
    or-int/2addr v2, v3

    .line 71
    invoke-virtual {v10, v13}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v3

    .line 75
    if-eqz v3, :cond_3

    .line 76
    .line 77
    const/16 v3, 0x800

    .line 78
    .line 79
    goto :goto_3

    .line 80
    :cond_3
    const/16 v3, 0x400

    .line 81
    .line 82
    :goto_3
    or-int/2addr v2, v3

    .line 83
    invoke-virtual {v10, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    move-result v3

    .line 87
    if-eqz v3, :cond_4

    .line 88
    .line 89
    const/16 v3, 0x4000

    .line 90
    .line 91
    goto :goto_4

    .line 92
    :cond_4
    const/16 v3, 0x2000

    .line 93
    .line 94
    :goto_4
    or-int/2addr v2, v3

    .line 95
    and-int/lit16 v3, v2, 0x2493

    .line 96
    .line 97
    const/16 v4, 0x2492

    .line 98
    .line 99
    const/4 v5, 0x0

    .line 100
    if-eq v3, v4, :cond_5

    .line 101
    .line 102
    const/4 v3, 0x1

    .line 103
    goto :goto_5

    .line 104
    :cond_5
    move v3, v5

    .line 105
    :goto_5
    and-int/lit8 v4, v2, 0x1

    .line 106
    .line 107
    invoke-virtual {v10, v4, v3}, Ll2/t;->O(IZ)Z

    .line 108
    .line 109
    .line 110
    move-result v3

    .line 111
    if-eqz v3, :cond_11

    .line 112
    .line 113
    sget-object v3, Lh71/m;->a:Ll2/u2;

    .line 114
    .line 115
    invoke-virtual {v10, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v3

    .line 119
    check-cast v3, Lh71/l;

    .line 120
    .line 121
    iget-object v3, v3, Lh71/l;->c:Lh71/f;

    .line 122
    .line 123
    iget-object v3, v3, Lh71/f;->f:Lh71/w;

    .line 124
    .line 125
    if-eqz v12, :cond_6

    .line 126
    .line 127
    const v4, -0x7a648e51

    .line 128
    .line 129
    .line 130
    invoke-virtual {v10, v4}, Ll2/t;->Y(I)V

    .line 131
    .line 132
    .line 133
    sget-object v4, Lh71/q;->a:Ll2/e0;

    .line 134
    .line 135
    invoke-virtual {v10, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object v4

    .line 139
    check-cast v4, Lh71/p;

    .line 140
    .line 141
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 142
    .line 143
    .line 144
    invoke-virtual {v10, v5}, Ll2/t;->q(Z)V

    .line 145
    .line 146
    .line 147
    const v4, 0x7f0805c2

    .line 148
    .line 149
    .line 150
    goto :goto_6

    .line 151
    :cond_6
    const v4, -0x7a63aac8

    .line 152
    .line 153
    .line 154
    invoke-virtual {v10, v4}, Ll2/t;->Y(I)V

    .line 155
    .line 156
    .line 157
    sget-object v4, Lh71/q;->a:Ll2/e0;

    .line 158
    .line 159
    invoke-virtual {v10, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    move-result-object v4

    .line 163
    check-cast v4, Lh71/p;

    .line 164
    .line 165
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 166
    .line 167
    .line 168
    invoke-virtual {v10, v5}, Ll2/t;->q(Z)V

    .line 169
    .line 170
    .line 171
    const v4, 0x7f0805b6

    .line 172
    .line 173
    .line 174
    :goto_6
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object v6

    .line 178
    sget-object v7, Ll2/n;->a:Ll2/x0;

    .line 179
    .line 180
    if-ne v6, v7, :cond_7

    .line 181
    .line 182
    sget-object v6, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 183
    .line 184
    invoke-static {v6}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 185
    .line 186
    .line 187
    move-result-object v6

    .line 188
    invoke-virtual {v10, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 189
    .line 190
    .line 191
    :cond_7
    check-cast v6, Ll2/b1;

    .line 192
    .line 193
    iget-object v8, v3, Lh71/w;->c:Lh71/d;

    .line 194
    .line 195
    invoke-interface {v6}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    move-result-object v16

    .line 199
    check-cast v16, Ljava/lang/Boolean;

    .line 200
    .line 201
    invoke-virtual/range {v16 .. v16}, Ljava/lang/Boolean;->booleanValue()Z

    .line 202
    .line 203
    .line 204
    move-result v5

    .line 205
    and-int/lit8 v16, v2, 0x70

    .line 206
    .line 207
    invoke-virtual {v8, v5, v1}, Lh71/d;->a(ZZ)J

    .line 208
    .line 209
    .line 210
    move-result-wide v11

    .line 211
    iget-object v5, v3, Lh71/w;->b:Lh71/d;

    .line 212
    .line 213
    invoke-interface {v6}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 214
    .line 215
    .line 216
    move-result-object v8

    .line 217
    check-cast v8, Ljava/lang/Boolean;

    .line 218
    .line 219
    invoke-virtual {v8}, Ljava/lang/Boolean;->booleanValue()Z

    .line 220
    .line 221
    .line 222
    move-result v8

    .line 223
    invoke-virtual {v5, v8, v1}, Lh71/d;->a(ZZ)J

    .line 224
    .line 225
    .line 226
    move-result-wide v17

    .line 227
    move-object v5, v7

    .line 228
    const/4 v7, 0x0

    .line 229
    const/4 v8, 0x2

    .line 230
    move-object/from16 v19, v5

    .line 231
    .line 232
    const/4 v5, 0x0

    .line 233
    move-object v15, v3

    .line 234
    move v9, v4

    .line 235
    move-wide/from16 v3, v17

    .line 236
    .line 237
    move-object/from16 v20, v19

    .line 238
    .line 239
    move-object/from16 v18, v6

    .line 240
    .line 241
    move-object v6, v10

    .line 242
    const/4 v10, 0x0

    .line 243
    invoke-static/range {v3 .. v8}, Lkp/f0;->c(JLay0/k;Ll2/o;II)Le71/b;

    .line 244
    .line 245
    .line 246
    move-result-object v3

    .line 247
    invoke-interface/range {v18 .. v18}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    move-result-object v4

    .line 251
    check-cast v4, Ljava/lang/Boolean;

    .line 252
    .line 253
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 254
    .line 255
    .line 256
    move-result v4

    .line 257
    new-instance v5, Le71/g;

    .line 258
    .line 259
    invoke-static {v9, v10, v6}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 260
    .line 261
    .line 262
    move-result-object v7

    .line 263
    invoke-direct {v5, v3, v7, v11, v12}, Le71/g;-><init>(Le71/b;Li3/c;J)V

    .line 264
    .line 265
    .line 266
    iget-object v3, v15, Lh71/w;->d:Lh71/x;

    .line 267
    .line 268
    and-int/lit16 v7, v2, 0x1c00

    .line 269
    .line 270
    const/16 v8, 0x800

    .line 271
    .line 272
    if-ne v7, v8, :cond_8

    .line 273
    .line 274
    const/4 v7, 0x1

    .line 275
    goto :goto_7

    .line 276
    :cond_8
    move v7, v10

    .line 277
    :goto_7
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 278
    .line 279
    .line 280
    move-result-object v8

    .line 281
    if-nez v7, :cond_a

    .line 282
    .line 283
    move-object/from16 v7, v20

    .line 284
    .line 285
    if-ne v8, v7, :cond_9

    .line 286
    .line 287
    goto :goto_8

    .line 288
    :cond_9
    move-object/from16 v11, v18

    .line 289
    .line 290
    goto :goto_9

    .line 291
    :cond_a
    move-object/from16 v7, v20

    .line 292
    .line 293
    :goto_8
    new-instance v8, Lb71/h;

    .line 294
    .line 295
    const/4 v9, 0x1

    .line 296
    move-object/from16 v11, v18

    .line 297
    .line 298
    invoke-direct {v8, v9, v13, v11}, Lb71/h;-><init>(ILay0/a;Ll2/b1;)V

    .line 299
    .line 300
    .line 301
    invoke-virtual {v6, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 302
    .line 303
    .line 304
    :goto_9
    check-cast v8, Lay0/a;

    .line 305
    .line 306
    const v9, 0xe000

    .line 307
    .line 308
    .line 309
    and-int/2addr v9, v2

    .line 310
    const/16 v12, 0x4000

    .line 311
    .line 312
    if-ne v9, v12, :cond_b

    .line 313
    .line 314
    const/4 v12, 0x1

    .line 315
    goto :goto_a

    .line 316
    :cond_b
    move v12, v10

    .line 317
    :goto_a
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 318
    .line 319
    .line 320
    move-result-object v15

    .line 321
    if-nez v12, :cond_c

    .line 322
    .line 323
    if-ne v15, v7, :cond_d

    .line 324
    .line 325
    :cond_c
    new-instance v15, Lb71/h;

    .line 326
    .line 327
    const/4 v12, 0x2

    .line 328
    invoke-direct {v15, v12, v14, v11}, Lb71/h;-><init>(ILay0/a;Ll2/b1;)V

    .line 329
    .line 330
    .line 331
    invoke-virtual {v6, v15}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 332
    .line 333
    .line 334
    :cond_d
    check-cast v15, Lay0/a;

    .line 335
    .line 336
    const/16 v12, 0x4000

    .line 337
    .line 338
    if-ne v9, v12, :cond_e

    .line 339
    .line 340
    const/4 v10, 0x1

    .line 341
    :cond_e
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 342
    .line 343
    .line 344
    move-result-object v9

    .line 345
    if-nez v10, :cond_f

    .line 346
    .line 347
    if-ne v9, v7, :cond_10

    .line 348
    .line 349
    :cond_f
    new-instance v9, Lb71/h;

    .line 350
    .line 351
    const/4 v7, 0x3

    .line 352
    invoke-direct {v9, v7, v14, v11}, Lb71/h;-><init>(ILay0/a;Ll2/b1;)V

    .line 353
    .line 354
    .line 355
    invoke-virtual {v6, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 356
    .line 357
    .line 358
    :cond_10
    check-cast v9, Lay0/a;

    .line 359
    .line 360
    and-int/lit8 v2, v2, 0xe

    .line 361
    .line 362
    const/high16 v7, 0x1b0000

    .line 363
    .line 364
    or-int/2addr v2, v7

    .line 365
    or-int v11, v2, v16

    .line 366
    .line 367
    move-object v2, v5

    .line 368
    const/4 v5, 0x0

    .line 369
    move-object v10, v6

    .line 370
    const/high16 v6, 0x3e800000    # 0.25f

    .line 371
    .line 372
    move-object v7, v8

    .line 373
    move-object v8, v15

    .line 374
    invoke-static/range {v0 .. v11}, Lkp/j0;->a(Lx2/s;ZLe71/g;Lh71/x;ZLjava/lang/Float;FLay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 375
    .line 376
    .line 377
    goto :goto_b

    .line 378
    :cond_11
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 379
    .line 380
    .line 381
    :goto_b
    invoke-virtual {v10}, Ll2/t;->s()Ll2/u1;

    .line 382
    .line 383
    .line 384
    move-result-object v7

    .line 385
    if-eqz v7, :cond_12

    .line 386
    .line 387
    new-instance v0, Lf71/a;

    .line 388
    .line 389
    move-object/from16 v1, p0

    .line 390
    .line 391
    move/from16 v2, p1

    .line 392
    .line 393
    move/from16 v3, p2

    .line 394
    .line 395
    move/from16 v6, p6

    .line 396
    .line 397
    move-object v4, v13

    .line 398
    move-object v5, v14

    .line 399
    invoke-direct/range {v0 .. v6}, Lf71/a;-><init>(Lx2/s;ZZLay0/a;Lay0/a;I)V

    .line 400
    .line 401
    .line 402
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 403
    .line 404
    :cond_12
    return-void
.end method

.method public static final b(Lss0/j;ZZ)Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lss0/j;->a:Ljava/time/LocalDate;

    .line 7
    .line 8
    iget-object p0, p0, Lss0/j;->b:Ljava/time/LocalDate;

    .line 9
    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    if-nez p0, :cond_0

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    const/4 v1, 0x1

    .line 16
    if-eqz v0, :cond_2

    .line 17
    .line 18
    if-eqz p0, :cond_2

    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/time/LocalDate;->getYear()I

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    invoke-virtual {p0}, Ljava/time/LocalDate;->getYear()I

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    const-string v4, " \u2013 "

    .line 29
    .line 30
    if-ne v2, v3, :cond_1

    .line 31
    .line 32
    const/4 v2, 0x0

    .line 33
    invoke-static {v0, p1, v2, p2}, Lkp/r7;->b(Ljava/time/LocalDate;ZZZ)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    invoke-static {p0, p1, v1, p2}, Lkp/r7;->b(Ljava/time/LocalDate;ZZZ)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-static {v0, v4, p0}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    return-object p0

    .line 46
    :cond_1
    invoke-static {v0, p1, v1, p2}, Lkp/r7;->b(Ljava/time/LocalDate;ZZZ)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    invoke-static {p0, p1, v1, p2}, Lkp/r7;->b(Ljava/time/LocalDate;ZZZ)Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    invoke-static {v0, v4, p0}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    return-object p0

    .line 59
    :cond_2
    if-nez v0, :cond_3

    .line 60
    .line 61
    if-eqz p0, :cond_3

    .line 62
    .line 63
    invoke-static {p0, p1, v1, p2}, Lkp/r7;->b(Ljava/time/LocalDate;ZZZ)Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    return-object p0

    .line 68
    :cond_3
    if-eqz v0, :cond_5

    .line 69
    .line 70
    invoke-static {v0, p1, v1, p2}, Lkp/r7;->b(Ljava/time/LocalDate;ZZZ)Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    if-nez p0, :cond_4

    .line 75
    .line 76
    goto :goto_0

    .line 77
    :cond_4
    return-object p0

    .line 78
    :cond_5
    :goto_0
    const-string p0, ""

    .line 79
    .line 80
    return-object p0
.end method
