.class public abstract Lz61/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lx2/s;ZZLay0/a;Lay0/a;Lay0/a;Ll2/o;I)V
    .locals 17

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move/from16 v3, p2

    .line 4
    .line 5
    move-object/from16 v9, p6

    .line 6
    .line 7
    check-cast v9, Ll2/t;

    .line 8
    .line 9
    const v0, -0x2aebdc77

    .line 10
    .line 11
    .line 12
    invoke-virtual {v9, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v9, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    const/4 v0, 0x4

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    const/4 v0, 0x2

    .line 24
    :goto_0
    or-int v0, p7, v0

    .line 25
    .line 26
    move/from16 v12, p1

    .line 27
    .line 28
    invoke-virtual {v9, v12}, Ll2/t;->h(Z)Z

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
    invoke-virtual {v9, v3}, Ll2/t;->h(Z)Z

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
    move-object/from16 v13, p3

    .line 53
    .line 54
    invoke-virtual {v9, v13}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v4

    .line 58
    if-eqz v4, :cond_3

    .line 59
    .line 60
    const/16 v4, 0x800

    .line 61
    .line 62
    goto :goto_3

    .line 63
    :cond_3
    const/16 v4, 0x400

    .line 64
    .line 65
    :goto_3
    or-int/2addr v0, v4

    .line 66
    move-object/from16 v14, p4

    .line 67
    .line 68
    invoke-virtual {v9, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v4

    .line 72
    if-eqz v4, :cond_4

    .line 73
    .line 74
    const/16 v4, 0x4000

    .line 75
    .line 76
    goto :goto_4

    .line 77
    :cond_4
    const/16 v4, 0x2000

    .line 78
    .line 79
    :goto_4
    or-int/2addr v0, v4

    .line 80
    move-object/from16 v15, p5

    .line 81
    .line 82
    invoke-virtual {v9, v15}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 83
    .line 84
    .line 85
    move-result v4

    .line 86
    if-eqz v4, :cond_5

    .line 87
    .line 88
    const/high16 v4, 0x20000

    .line 89
    .line 90
    goto :goto_5

    .line 91
    :cond_5
    const/high16 v4, 0x10000

    .line 92
    .line 93
    :goto_5
    or-int/2addr v0, v4

    .line 94
    const v4, 0x12493

    .line 95
    .line 96
    .line 97
    and-int/2addr v4, v0

    .line 98
    const v5, 0x12492

    .line 99
    .line 100
    .line 101
    const/4 v7, 0x0

    .line 102
    if-eq v4, v5, :cond_6

    .line 103
    .line 104
    const/4 v4, 0x1

    .line 105
    goto :goto_6

    .line 106
    :cond_6
    move v4, v7

    .line 107
    :goto_6
    and-int/lit8 v5, v0, 0x1

    .line 108
    .line 109
    invoke-virtual {v9, v5, v4}, Ll2/t;->O(IZ)Z

    .line 110
    .line 111
    .line 112
    move-result v4

    .line 113
    if-eqz v4, :cond_b

    .line 114
    .line 115
    sget-object v4, Lx2/c;->d:Lx2/j;

    .line 116
    .line 117
    invoke-static {v4, v7}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 118
    .line 119
    .line 120
    move-result-object v4

    .line 121
    iget-wide v10, v9, Ll2/t;->T:J

    .line 122
    .line 123
    invoke-static {v10, v11}, Ljava/lang/Long;->hashCode(J)I

    .line 124
    .line 125
    .line 126
    move-result v5

    .line 127
    invoke-virtual {v9}, Ll2/t;->m()Ll2/p1;

    .line 128
    .line 129
    .line 130
    move-result-object v8

    .line 131
    sget-object v10, Lx2/p;->b:Lx2/p;

    .line 132
    .line 133
    invoke-static {v9, v10}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 134
    .line 135
    .line 136
    move-result-object v10

    .line 137
    sget-object v11, Lv3/k;->m1:Lv3/j;

    .line 138
    .line 139
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 140
    .line 141
    .line 142
    sget-object v11, Lv3/j;->b:Lv3/i;

    .line 143
    .line 144
    invoke-virtual {v9}, Ll2/t;->c0()V

    .line 145
    .line 146
    .line 147
    iget-boolean v6, v9, Ll2/t;->S:Z

    .line 148
    .line 149
    if-eqz v6, :cond_7

    .line 150
    .line 151
    invoke-virtual {v9, v11}, Ll2/t;->l(Lay0/a;)V

    .line 152
    .line 153
    .line 154
    goto :goto_7

    .line 155
    :cond_7
    invoke-virtual {v9}, Ll2/t;->m0()V

    .line 156
    .line 157
    .line 158
    :goto_7
    sget-object v6, Lv3/j;->g:Lv3/h;

    .line 159
    .line 160
    invoke-static {v6, v4, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 161
    .line 162
    .line 163
    sget-object v4, Lv3/j;->f:Lv3/h;

    .line 164
    .line 165
    invoke-static {v4, v8, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 166
    .line 167
    .line 168
    sget-object v4, Lv3/j;->j:Lv3/h;

    .line 169
    .line 170
    iget-boolean v6, v9, Ll2/t;->S:Z

    .line 171
    .line 172
    if-nez v6, :cond_8

    .line 173
    .line 174
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object v6

    .line 178
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 179
    .line 180
    .line 181
    move-result-object v8

    .line 182
    invoke-static {v6, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 183
    .line 184
    .line 185
    move-result v6

    .line 186
    if-nez v6, :cond_9

    .line 187
    .line 188
    :cond_8
    invoke-static {v5, v9, v5, v4}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 189
    .line 190
    .line 191
    :cond_9
    sget-object v4, Lv3/j;->d:Lv3/h;

    .line 192
    .line 193
    invoke-static {v4, v10, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 194
    .line 195
    .line 196
    if-nez v3, :cond_a

    .line 197
    .line 198
    const v4, -0x42f389d8

    .line 199
    .line 200
    .line 201
    invoke-virtual {v9, v4}, Ll2/t;->Y(I)V

    .line 202
    .line 203
    .line 204
    const-string v4, "drive_activation_park_in_button_hint_tooltip"

    .line 205
    .line 206
    invoke-static {v4, v9}, Ly61/a;->a(Ljava/lang/String;Ll2/o;)Ljava/lang/String;

    .line 207
    .line 208
    .line 209
    move-result-object v5

    .line 210
    sget-object v6, Lh71/a;->d:Lh71/a;

    .line 211
    .line 212
    move v4, v7

    .line 213
    sget-object v7, Lg71/a;->e:Lg71/a;

    .line 214
    .line 215
    const/16 v10, 0xd86

    .line 216
    .line 217
    const/16 v11, 0x10

    .line 218
    .line 219
    move v8, v4

    .line 220
    const/4 v4, 0x0

    .line 221
    move/from16 v16, v8

    .line 222
    .line 223
    const/4 v8, 0x0

    .line 224
    move/from16 v2, v16

    .line 225
    .line 226
    invoke-static/range {v4 .. v11}, Lkp/q8;->b(Ljava/lang/String;Ljava/lang/String;Lh71/a;Lg71/a;FLl2/o;II)V

    .line 227
    .line 228
    .line 229
    :goto_8
    invoke-virtual {v9, v2}, Ll2/t;->q(Z)V

    .line 230
    .line 231
    .line 232
    goto :goto_9

    .line 233
    :cond_a
    move v2, v7

    .line 234
    const v4, -0x437581ed    # -0.01690582f

    .line 235
    .line 236
    .line 237
    invoke-virtual {v9, v4}, Ll2/t;->Y(I)V

    .line 238
    .line 239
    .line 240
    goto :goto_8

    .line 241
    :goto_9
    const/high16 v2, 0x3f800000    # 1.0f

    .line 242
    .line 243
    invoke-static {v1, v2}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 244
    .line 245
    .line 246
    move-result-object v2

    .line 247
    sget-object v4, Lh71/u;->a:Ll2/u2;

    .line 248
    .line 249
    invoke-virtual {v9, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 250
    .line 251
    .line 252
    move-result-object v4

    .line 253
    check-cast v4, Lh71/t;

    .line 254
    .line 255
    iget v4, v4, Lh71/t;->e:F

    .line 256
    .line 257
    const/4 v5, 0x0

    .line 258
    const/4 v6, 0x2

    .line 259
    invoke-static {v2, v4, v5, v6}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 260
    .line 261
    .line 262
    move-result-object v2

    .line 263
    const-string v4, "drive_activation_park_in_button_text"

    .line 264
    .line 265
    invoke-static {v4, v9}, Ly61/a;->a(Ljava/lang/String;Ll2/o;)Ljava/lang/String;

    .line 266
    .line 267
    .line 268
    move-result-object v4

    .line 269
    sget-object v5, Lh71/m;->a:Ll2/u2;

    .line 270
    .line 271
    invoke-virtual {v9, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 272
    .line 273
    .line 274
    move-result-object v5

    .line 275
    check-cast v5, Lh71/l;

    .line 276
    .line 277
    iget-object v5, v5, Lh71/l;->c:Lh71/f;

    .line 278
    .line 279
    iget-object v6, v5, Lh71/f;->b:Lh71/w;

    .line 280
    .line 281
    shl-int/lit8 v5, v0, 0x6

    .line 282
    .line 283
    const v7, 0xfc00

    .line 284
    .line 285
    .line 286
    and-int/2addr v5, v7

    .line 287
    shl-int/lit8 v0, v0, 0xc

    .line 288
    .line 289
    const/high16 v7, 0x1c00000

    .line 290
    .line 291
    and-int/2addr v7, v0

    .line 292
    or-int/2addr v5, v7

    .line 293
    const/high16 v7, 0xe000000

    .line 294
    .line 295
    and-int/2addr v7, v0

    .line 296
    or-int/2addr v5, v7

    .line 297
    const/high16 v7, 0x70000000

    .line 298
    .line 299
    and-int/2addr v0, v7

    .line 300
    or-int/2addr v0, v5

    .line 301
    const/16 v13, 0x42

    .line 302
    .line 303
    const/4 v7, 0x0

    .line 304
    move-object/from16 v8, p3

    .line 305
    .line 306
    move v5, v3

    .line 307
    move-object v3, v4

    .line 308
    move-object v11, v9

    .line 309
    move v4, v12

    .line 310
    move-object v9, v14

    .line 311
    move-object v10, v15

    .line 312
    move v12, v0

    .line 313
    invoke-static/range {v2 .. v13}, Lkp/h0;->b(Lx2/s;Ljava/lang/String;ZZLh71/w;Le71/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 314
    .line 315
    .line 316
    move-object v9, v11

    .line 317
    const/4 v0, 0x1

    .line 318
    invoke-virtual {v9, v0}, Ll2/t;->q(Z)V

    .line 319
    .line 320
    .line 321
    goto :goto_a

    .line 322
    :cond_b
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 323
    .line 324
    .line 325
    :goto_a
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 326
    .line 327
    .line 328
    move-result-object v8

    .line 329
    if-eqz v8, :cond_c

    .line 330
    .line 331
    new-instance v0, Ldk/a;

    .line 332
    .line 333
    move/from16 v2, p1

    .line 334
    .line 335
    move/from16 v3, p2

    .line 336
    .line 337
    move-object/from16 v4, p3

    .line 338
    .line 339
    move-object/from16 v5, p4

    .line 340
    .line 341
    move-object/from16 v6, p5

    .line 342
    .line 343
    move/from16 v7, p7

    .line 344
    .line 345
    invoke-direct/range {v0 .. v7}, Ldk/a;-><init>(Lx2/s;ZZLay0/a;Lay0/a;Lay0/a;I)V

    .line 346
    .line 347
    .line 348
    iput-object v0, v8, Ll2/u1;->d:Lay0/n;

    .line 349
    .line 350
    :cond_c
    return-void
.end method

.method public static final b(Landroidx/compose/foundation/layout/LayoutWeightElement;ZLtechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;ZJLay0/a;Lay0/a;Ll2/o;I)V
    .locals 21

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v3, p2

    .line 4
    .line 5
    move-object/from16 v7, p6

    .line 6
    .line 7
    move-object/from16 v8, p7

    .line 8
    .line 9
    move-object/from16 v14, p8

    .line 10
    .line 11
    check-cast v14, Ll2/t;

    .line 12
    .line 13
    const v0, -0x5dd7f6f5

    .line 14
    .line 15
    .line 16
    invoke-virtual {v14, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    invoke-virtual {v14, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    const/4 v0, 0x4

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 v0, 0x2

    .line 28
    :goto_0
    or-int v0, p9, v0

    .line 29
    .line 30
    move/from16 v10, p1

    .line 31
    .line 32
    invoke-virtual {v14, v10}, Ll2/t;->h(Z)Z

    .line 33
    .line 34
    .line 35
    move-result v2

    .line 36
    if-eqz v2, :cond_1

    .line 37
    .line 38
    const/16 v2, 0x20

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_1
    const/16 v2, 0x10

    .line 42
    .line 43
    :goto_1
    or-int/2addr v0, v2

    .line 44
    invoke-virtual {v14, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    if-eqz v2, :cond_2

    .line 49
    .line 50
    const/16 v2, 0x100

    .line 51
    .line 52
    goto :goto_2

    .line 53
    :cond_2
    const/16 v2, 0x80

    .line 54
    .line 55
    :goto_2
    or-int/2addr v0, v2

    .line 56
    move/from16 v11, p3

    .line 57
    .line 58
    invoke-virtual {v14, v11}, Ll2/t;->h(Z)Z

    .line 59
    .line 60
    .line 61
    move-result v2

    .line 62
    if-eqz v2, :cond_3

    .line 63
    .line 64
    const/16 v2, 0x800

    .line 65
    .line 66
    goto :goto_3

    .line 67
    :cond_3
    const/16 v2, 0x400

    .line 68
    .line 69
    :goto_3
    or-int/2addr v0, v2

    .line 70
    move-wide/from16 v12, p4

    .line 71
    .line 72
    invoke-virtual {v14, v12, v13}, Ll2/t;->f(J)Z

    .line 73
    .line 74
    .line 75
    move-result v2

    .line 76
    if-eqz v2, :cond_4

    .line 77
    .line 78
    const/16 v2, 0x4000

    .line 79
    .line 80
    goto :goto_4

    .line 81
    :cond_4
    const/16 v2, 0x2000

    .line 82
    .line 83
    :goto_4
    or-int/2addr v0, v2

    .line 84
    invoke-virtual {v14, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 85
    .line 86
    .line 87
    move-result v2

    .line 88
    if-eqz v2, :cond_5

    .line 89
    .line 90
    const/high16 v2, 0x20000

    .line 91
    .line 92
    goto :goto_5

    .line 93
    :cond_5
    const/high16 v2, 0x10000

    .line 94
    .line 95
    :goto_5
    or-int/2addr v0, v2

    .line 96
    invoke-virtual {v14, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result v2

    .line 100
    if-eqz v2, :cond_6

    .line 101
    .line 102
    const/high16 v2, 0x100000

    .line 103
    .line 104
    goto :goto_6

    .line 105
    :cond_6
    const/high16 v2, 0x80000

    .line 106
    .line 107
    :goto_6
    or-int/2addr v0, v2

    .line 108
    const v2, 0x92493

    .line 109
    .line 110
    .line 111
    and-int/2addr v2, v0

    .line 112
    const v6, 0x92492

    .line 113
    .line 114
    .line 115
    const/4 v15, 0x0

    .line 116
    if-eq v2, v6, :cond_7

    .line 117
    .line 118
    const/4 v2, 0x1

    .line 119
    goto :goto_7

    .line 120
    :cond_7
    move v2, v15

    .line 121
    :goto_7
    and-int/lit8 v6, v0, 0x1

    .line 122
    .line 123
    invoke-virtual {v14, v6, v2}, Ll2/t;->O(IZ)Z

    .line 124
    .line 125
    .line 126
    move-result v2

    .line 127
    if-eqz v2, :cond_17

    .line 128
    .line 129
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object v2

    .line 133
    sget-object v6, Ll2/n;->a:Ll2/x0;

    .line 134
    .line 135
    if-ne v2, v6, :cond_8

    .line 136
    .line 137
    sget-object v2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 138
    .line 139
    invoke-static {v2}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 140
    .line 141
    .line 142
    move-result-object v2

    .line 143
    invoke-virtual {v14, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 144
    .line 145
    .line 146
    :cond_8
    check-cast v2, Ll2/b1;

    .line 147
    .line 148
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object v5

    .line 152
    if-ne v5, v6, :cond_9

    .line 153
    .line 154
    sget-object v5, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 155
    .line 156
    invoke-static {v5}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 157
    .line 158
    .line 159
    move-result-object v5

    .line 160
    invoke-virtual {v14, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 161
    .line 162
    .line 163
    :cond_9
    check-cast v5, Ll2/b1;

    .line 164
    .line 165
    invoke-virtual {v14, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 166
    .line 167
    .line 168
    move-result v16

    .line 169
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object v4

    .line 173
    if-nez v16, :cond_a

    .line 174
    .line 175
    if-ne v4, v6, :cond_b

    .line 176
    .line 177
    :cond_a
    new-instance v4, Lz61/g;

    .line 178
    .line 179
    const/4 v9, 0x0

    .line 180
    invoke-direct {v4, v3, v2, v9}, Lz61/g;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;Ll2/b1;Lkotlin/coroutines/Continuation;)V

    .line 181
    .line 182
    .line 183
    invoke-virtual {v14, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 184
    .line 185
    .line 186
    :cond_b
    check-cast v4, Lay0/n;

    .line 187
    .line 188
    invoke-static {v4, v3, v14}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 189
    .line 190
    .line 191
    sget-object v4, Lx2/c;->d:Lx2/j;

    .line 192
    .line 193
    invoke-static {v4, v15}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 194
    .line 195
    .line 196
    move-result-object v4

    .line 197
    move-object/from16 v18, v2

    .line 198
    .line 199
    iget-wide v2, v14, Ll2/t;->T:J

    .line 200
    .line 201
    invoke-static {v2, v3}, Ljava/lang/Long;->hashCode(J)I

    .line 202
    .line 203
    .line 204
    move-result v2

    .line 205
    invoke-virtual {v14}, Ll2/t;->m()Ll2/p1;

    .line 206
    .line 207
    .line 208
    move-result-object v3

    .line 209
    invoke-static {v14, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 210
    .line 211
    .line 212
    move-result-object v9

    .line 213
    sget-object v19, Lv3/k;->m1:Lv3/j;

    .line 214
    .line 215
    invoke-virtual/range {v19 .. v19}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 216
    .line 217
    .line 218
    sget-object v15, Lv3/j;->b:Lv3/i;

    .line 219
    .line 220
    invoke-virtual {v14}, Ll2/t;->c0()V

    .line 221
    .line 222
    .line 223
    move/from16 v20, v0

    .line 224
    .line 225
    iget-boolean v0, v14, Ll2/t;->S:Z

    .line 226
    .line 227
    if-eqz v0, :cond_c

    .line 228
    .line 229
    invoke-virtual {v14, v15}, Ll2/t;->l(Lay0/a;)V

    .line 230
    .line 231
    .line 232
    goto :goto_8

    .line 233
    :cond_c
    invoke-virtual {v14}, Ll2/t;->m0()V

    .line 234
    .line 235
    .line 236
    :goto_8
    sget-object v0, Lv3/j;->g:Lv3/h;

    .line 237
    .line 238
    invoke-static {v0, v4, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 239
    .line 240
    .line 241
    sget-object v0, Lv3/j;->f:Lv3/h;

    .line 242
    .line 243
    invoke-static {v0, v3, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 244
    .line 245
    .line 246
    sget-object v0, Lv3/j;->j:Lv3/h;

    .line 247
    .line 248
    iget-boolean v3, v14, Ll2/t;->S:Z

    .line 249
    .line 250
    if-nez v3, :cond_d

    .line 251
    .line 252
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 253
    .line 254
    .line 255
    move-result-object v3

    .line 256
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 257
    .line 258
    .line 259
    move-result-object v4

    .line 260
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 261
    .line 262
    .line 263
    move-result v3

    .line 264
    if-nez v3, :cond_e

    .line 265
    .line 266
    :cond_d
    invoke-static {v2, v14, v2, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 267
    .line 268
    .line 269
    :cond_e
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 270
    .line 271
    invoke-static {v0, v9, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 272
    .line 273
    .line 274
    sget-object v0, Lh71/u;->a:Ll2/u2;

    .line 275
    .line 276
    invoke-virtual {v14, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 277
    .line 278
    .line 279
    move-result-object v2

    .line 280
    check-cast v2, Lh71/t;

    .line 281
    .line 282
    iget v2, v2, Lh71/t;->j:F

    .line 283
    .line 284
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 285
    .line 286
    invoke-static {v3, v2}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 287
    .line 288
    .line 289
    move-result-object v2

    .line 290
    const/high16 v3, 0x3f800000    # 1.0f

    .line 291
    .line 292
    const/4 v4, 0x1

    .line 293
    invoke-static {v2, v3, v4}, Landroidx/compose/foundation/layout/a;->d(Lx2/s;FZ)Lx2/s;

    .line 294
    .line 295
    .line 296
    move-result-object v2

    .line 297
    sget-object v3, Lx2/c;->k:Lx2/j;

    .line 298
    .line 299
    sget-object v9, Landroidx/compose/foundation/layout/b;->a:Landroidx/compose/foundation/layout/b;

    .line 300
    .line 301
    invoke-virtual {v9, v2, v3}, Landroidx/compose/foundation/layout/b;->a(Lx2/s;Lx2/e;)Lx2/s;

    .line 302
    .line 303
    .line 304
    move-result-object v9

    .line 305
    const/high16 v2, 0x70000

    .line 306
    .line 307
    and-int v2, v20, v2

    .line 308
    .line 309
    const/high16 v3, 0x20000

    .line 310
    .line 311
    if-ne v2, v3, :cond_f

    .line 312
    .line 313
    move v2, v4

    .line 314
    goto :goto_9

    .line 315
    :cond_f
    const/4 v2, 0x0

    .line 316
    :goto_9
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 317
    .line 318
    .line 319
    move-result-object v3

    .line 320
    if-nez v2, :cond_10

    .line 321
    .line 322
    if-ne v3, v6, :cond_11

    .line 323
    .line 324
    :cond_10
    new-instance v3, Lb71/h;

    .line 325
    .line 326
    const/16 v2, 0xd

    .line 327
    .line 328
    invoke-direct {v3, v2, v7, v5}, Lb71/h;-><init>(ILay0/a;Ll2/b1;)V

    .line 329
    .line 330
    .line 331
    invoke-virtual {v14, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 332
    .line 333
    .line 334
    :cond_11
    check-cast v3, Lay0/a;

    .line 335
    .line 336
    const/high16 v2, 0x380000

    .line 337
    .line 338
    and-int v2, v20, v2

    .line 339
    .line 340
    const/high16 v15, 0x100000

    .line 341
    .line 342
    if-ne v2, v15, :cond_12

    .line 343
    .line 344
    move v2, v4

    .line 345
    goto :goto_a

    .line 346
    :cond_12
    const/4 v2, 0x0

    .line 347
    :goto_a
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 348
    .line 349
    .line 350
    move-result-object v15

    .line 351
    if-nez v2, :cond_13

    .line 352
    .line 353
    if-ne v15, v6, :cond_14

    .line 354
    .line 355
    :cond_13
    new-instance v15, Lxf0/e2;

    .line 356
    .line 357
    const/16 v2, 0x9

    .line 358
    .line 359
    invoke-direct {v15, v8, v2}, Lxf0/e2;-><init>(Lay0/a;I)V

    .line 360
    .line 361
    .line 362
    invoke-virtual {v14, v15}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 363
    .line 364
    .line 365
    :cond_14
    check-cast v15, Lay0/a;

    .line 366
    .line 367
    and-int/lit8 v2, v20, 0x70

    .line 368
    .line 369
    shr-int/lit8 v6, v20, 0x3

    .line 370
    .line 371
    and-int/lit16 v4, v6, 0x380

    .line 372
    .line 373
    or-int/2addr v2, v4

    .line 374
    and-int/lit16 v4, v6, 0x1c00

    .line 375
    .line 376
    or-int v17, v2, v4

    .line 377
    .line 378
    move-object/from16 v16, v14

    .line 379
    .line 380
    const/4 v2, 0x0

    .line 381
    const/4 v4, 0x1

    .line 382
    move-object v14, v3

    .line 383
    invoke-static/range {v9 .. v17}, Lf71/f;->a(Lx2/s;ZZJLay0/a;Lay0/a;Ll2/o;I)V

    .line 384
    .line 385
    .line 386
    move-object/from16 v14, v16

    .line 387
    .line 388
    invoke-interface/range {v18 .. v18}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 389
    .line 390
    .line 391
    move-result-object v3

    .line 392
    check-cast v3, Ljava/lang/Boolean;

    .line 393
    .line 394
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 395
    .line 396
    .line 397
    move-result v3

    .line 398
    const v6, 0x76bcb3b1

    .line 399
    .line 400
    .line 401
    if-eqz v3, :cond_15

    .line 402
    .line 403
    const v3, 0x775e10e3

    .line 404
    .line 405
    .line 406
    invoke-virtual {v14, v3}, Ll2/t;->Y(I)V

    .line 407
    .line 408
    .line 409
    const-string v3, "drive_activation_motor_start_hint_title"

    .line 410
    .line 411
    invoke-static {v3, v14}, Ly61/a;->a(Ljava/lang/String;Ll2/o;)Ljava/lang/String;

    .line 412
    .line 413
    .line 414
    move-result-object v9

    .line 415
    const-string v3, "drive_activation_motor_start_hint_description"

    .line 416
    .line 417
    invoke-static {v3, v14}, Ly61/a;->a(Ljava/lang/String;Ll2/o;)Ljava/lang/String;

    .line 418
    .line 419
    .line 420
    move-result-object v10

    .line 421
    sget-object v11, Lh71/a;->d:Lh71/a;

    .line 422
    .line 423
    sget-object v12, Lg71/a;->e:Lg71/a;

    .line 424
    .line 425
    invoke-virtual {v14, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 426
    .line 427
    .line 428
    move-result-object v3

    .line 429
    check-cast v3, Lh71/t;

    .line 430
    .line 431
    iget v3, v3, Lh71/t;->c:F

    .line 432
    .line 433
    neg-float v13, v3

    .line 434
    const/16 v15, 0xd80

    .line 435
    .line 436
    const/16 v16, 0x0

    .line 437
    .line 438
    invoke-static/range {v9 .. v16}, Lkp/q8;->b(Ljava/lang/String;Ljava/lang/String;Lh71/a;Lg71/a;FLl2/o;II)V

    .line 439
    .line 440
    .line 441
    :goto_b
    invoke-virtual {v14, v2}, Ll2/t;->q(Z)V

    .line 442
    .line 443
    .line 444
    goto :goto_c

    .line 445
    :cond_15
    invoke-virtual {v14, v6}, Ll2/t;->Y(I)V

    .line 446
    .line 447
    .line 448
    goto :goto_b

    .line 449
    :goto_c
    invoke-interface {v5}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 450
    .line 451
    .line 452
    move-result-object v3

    .line 453
    check-cast v3, Ljava/lang/Boolean;

    .line 454
    .line 455
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 456
    .line 457
    .line 458
    move-result v3

    .line 459
    if-eqz v3, :cond_16

    .line 460
    .line 461
    const v3, 0x7765158e

    .line 462
    .line 463
    .line 464
    invoke-virtual {v14, v3}, Ll2/t;->Y(I)V

    .line 465
    .line 466
    .line 467
    const-string v3, "drive_activation_start_process_hint"

    .line 468
    .line 469
    invoke-static {v3, v14}, Ly61/a;->a(Ljava/lang/String;Ll2/o;)Ljava/lang/String;

    .line 470
    .line 471
    .line 472
    move-result-object v10

    .line 473
    sget-object v11, Lh71/a;->d:Lh71/a;

    .line 474
    .line 475
    sget-object v12, Lg71/a;->e:Lg71/a;

    .line 476
    .line 477
    invoke-virtual {v14, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 478
    .line 479
    .line 480
    move-result-object v0

    .line 481
    check-cast v0, Lh71/t;

    .line 482
    .line 483
    iget v0, v0, Lh71/t;->c:F

    .line 484
    .line 485
    neg-float v13, v0

    .line 486
    const/16 v15, 0xd86

    .line 487
    .line 488
    const/16 v16, 0x0

    .line 489
    .line 490
    const/4 v9, 0x0

    .line 491
    invoke-static/range {v9 .. v16}, Lkp/q8;->b(Ljava/lang/String;Ljava/lang/String;Lh71/a;Lg71/a;FLl2/o;II)V

    .line 492
    .line 493
    .line 494
    :goto_d
    invoke-virtual {v14, v2}, Ll2/t;->q(Z)V

    .line 495
    .line 496
    .line 497
    goto :goto_e

    .line 498
    :cond_16
    invoke-virtual {v14, v6}, Ll2/t;->Y(I)V

    .line 499
    .line 500
    .line 501
    goto :goto_d

    .line 502
    :goto_e
    invoke-virtual {v14, v4}, Ll2/t;->q(Z)V

    .line 503
    .line 504
    .line 505
    goto :goto_f

    .line 506
    :cond_17
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 507
    .line 508
    .line 509
    :goto_f
    invoke-virtual {v14}, Ll2/t;->s()Ll2/u1;

    .line 510
    .line 511
    .line 512
    move-result-object v10

    .line 513
    if-eqz v10, :cond_18

    .line 514
    .line 515
    new-instance v0, Lz61/f;

    .line 516
    .line 517
    move/from16 v2, p1

    .line 518
    .line 519
    move-object/from16 v3, p2

    .line 520
    .line 521
    move/from16 v4, p3

    .line 522
    .line 523
    move-wide/from16 v5, p4

    .line 524
    .line 525
    move/from16 v9, p9

    .line 526
    .line 527
    invoke-direct/range {v0 .. v9}, Lz61/f;-><init>(Landroidx/compose/foundation/layout/LayoutWeightElement;ZLtechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;ZJLay0/a;Lay0/a;I)V

    .line 528
    .line 529
    .line 530
    iput-object v0, v10, Ll2/u1;->d:Lay0/n;

    .line 531
    .line 532
    :cond_18
    return-void
.end method

.method public static final c(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveActivationViewModel;Ll2/o;I)V
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v3, p1

    .line 4
    .line 5
    move/from16 v14, p3

    .line 6
    .line 7
    const-string v1, "modifier"

    .line 8
    .line 9
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v1, "viewModel"

    .line 13
    .line 14
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    move-object/from16 v12, p2

    .line 18
    .line 19
    check-cast v12, Ll2/t;

    .line 20
    .line 21
    const v1, 0x3bf89876

    .line 22
    .line 23
    .line 24
    invoke-virtual {v12, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v12, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    if-eqz v1, :cond_0

    .line 32
    .line 33
    const/4 v1, 0x4

    .line 34
    goto :goto_0

    .line 35
    :cond_0
    const/4 v1, 0x2

    .line 36
    :goto_0
    or-int/2addr v1, v14

    .line 37
    invoke-virtual {v12, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    if-eqz v2, :cond_1

    .line 42
    .line 43
    const/16 v2, 0x20

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_1
    const/16 v2, 0x10

    .line 47
    .line 48
    :goto_1
    or-int v9, v1, v2

    .line 49
    .line 50
    and-int/lit8 v1, v9, 0x13

    .line 51
    .line 52
    const/16 v2, 0x12

    .line 53
    .line 54
    const/4 v4, 0x1

    .line 55
    const/4 v5, 0x0

    .line 56
    if-eq v1, v2, :cond_2

    .line 57
    .line 58
    move v1, v4

    .line 59
    goto :goto_2

    .line 60
    :cond_2
    move v1, v5

    .line 61
    :goto_2
    and-int/lit8 v2, v9, 0x1

    .line 62
    .line 63
    invoke-virtual {v12, v2, v1}, Ll2/t;->O(IZ)Z

    .line 64
    .line 65
    .line 66
    move-result v1

    .line 67
    if-eqz v1, :cond_b

    .line 68
    .line 69
    invoke-interface {v3}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveActivationViewModel;->getParkingManeuverStatus()Lyy0/a2;

    .line 70
    .line 71
    .line 72
    move-result-object v1

    .line 73
    invoke-static {v1, v12}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    invoke-interface {v3}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveActivationViewModel;->isDriveActivationActionAllowed()Lyy0/a2;

    .line 78
    .line 79
    .line 80
    move-result-object v2

    .line 81
    invoke-static {v2, v12}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 82
    .line 83
    .line 84
    move-result-object v2

    .line 85
    invoke-interface {v3}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveActivationViewModel;->isElectricalVehicle()Lyy0/a2;

    .line 86
    .line 87
    .line 88
    move-result-object v6

    .line 89
    invoke-static {v6, v12}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 90
    .line 91
    .line 92
    move-result-object v6

    .line 93
    invoke-interface {v3}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveActivationViewModel;->getError()Lyy0/a2;

    .line 94
    .line 95
    .line 96
    move-result-object v7

    .line 97
    invoke-static {v7, v12}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 98
    .line 99
    .line 100
    move-result-object v7

    .line 101
    invoke-interface {v3}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveActivationViewModel;->isWaitingForResponse()Lyy0/a2;

    .line 102
    .line 103
    .line 104
    move-result-object v8

    .line 105
    invoke-static {v8, v12}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 106
    .line 107
    .line 108
    move-result-object v8

    .line 109
    invoke-interface {v3}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveActivationViewModel;->getPressTimeThreshold()Lyy0/a2;

    .line 110
    .line 111
    .line 112
    move-result-object v10

    .line 113
    invoke-static {v10, v12}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 114
    .line 115
    .line 116
    move-result-object v10

    .line 117
    invoke-interface {v3}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveActivationViewModel;->isClosable()Lyy0/a2;

    .line 118
    .line 119
    .line 120
    move-result-object v11

    .line 121
    invoke-static {v11, v12}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 122
    .line 123
    .line 124
    move-result-object v11

    .line 125
    invoke-interface {v7}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v13

    .line 129
    check-cast v13, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 130
    .line 131
    sget-object v15, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$DriveActivationThresholdNotReached;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$DriveActivationThresholdNotReached;

    .line 132
    .line 133
    invoke-static {v13, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 134
    .line 135
    .line 136
    move-result v13

    .line 137
    if-nez v13, :cond_3

    .line 138
    .line 139
    const v13, -0x199e0866

    .line 140
    .line 141
    .line 142
    invoke-virtual {v12, v13}, Ll2/t;->Y(I)V

    .line 143
    .line 144
    .line 145
    invoke-interface {v7}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object v13

    .line 149
    check-cast v13, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 150
    .line 151
    invoke-static {v13, v12, v5}, La71/b;->m(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;Ll2/o;I)V

    .line 152
    .line 153
    .line 154
    :goto_3
    invoke-virtual {v12, v5}, Ll2/t;->q(Z)V

    .line 155
    .line 156
    .line 157
    goto :goto_4

    .line 158
    :cond_3
    const v13, -0x19d4f8f4

    .line 159
    .line 160
    .line 161
    invoke-virtual {v12, v13}, Ll2/t;->Y(I)V

    .line 162
    .line 163
    .line 164
    goto :goto_3

    .line 165
    :goto_4
    invoke-interface {v7}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object v7

    .line 169
    move-object v13, v7

    .line 170
    check-cast v13, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 171
    .line 172
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object v1

    .line 176
    check-cast v1, Ls71/h;

    .line 177
    .line 178
    sget-object v7, Ls71/h;->e:Ls71/h;

    .line 179
    .line 180
    if-ne v1, v7, :cond_4

    .line 181
    .line 182
    move v15, v4

    .line 183
    goto :goto_5

    .line 184
    :cond_4
    move v15, v5

    .line 185
    :goto_5
    invoke-interface {v6}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object v1

    .line 189
    check-cast v1, Ljava/lang/Boolean;

    .line 190
    .line 191
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 192
    .line 193
    .line 194
    move-result v16

    .line 195
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    move-result-object v1

    .line 199
    check-cast v1, Ljava/lang/Boolean;

    .line 200
    .line 201
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 202
    .line 203
    .line 204
    move-result v17

    .line 205
    invoke-interface {v10}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object v1

    .line 209
    check-cast v1, Lmy0/c;

    .line 210
    .line 211
    iget-wide v1, v1, Lmy0/c;->d:J

    .line 212
    .line 213
    invoke-interface {v8}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 214
    .line 215
    .line 216
    move-result-object v4

    .line 217
    check-cast v4, Ljava/lang/Boolean;

    .line 218
    .line 219
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 220
    .line 221
    .line 222
    move-result v10

    .line 223
    invoke-virtual {v12, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 224
    .line 225
    .line 226
    move-result v4

    .line 227
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 228
    .line 229
    .line 230
    move-result-object v5

    .line 231
    sget-object v6, Ll2/n;->a:Ll2/x0;

    .line 232
    .line 233
    if-nez v4, :cond_5

    .line 234
    .line 235
    if-ne v5, v6, :cond_6

    .line 236
    .line 237
    :cond_5
    move-wide v7, v1

    .line 238
    goto :goto_6

    .line 239
    :cond_6
    move-wide/from16 v18, v1

    .line 240
    .line 241
    move-object v0, v6

    .line 242
    goto :goto_7

    .line 243
    :goto_6
    new-instance v1, Lz20/j;

    .line 244
    .line 245
    move-wide v4, v7

    .line 246
    const/4 v7, 0x0

    .line 247
    const/16 v8, 0xb

    .line 248
    .line 249
    const/4 v2, 0x0

    .line 250
    move-wide/from16 v18, v4

    .line 251
    .line 252
    const-class v4, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveActivationViewModel;

    .line 253
    .line 254
    const-string v5, "startActivation"

    .line 255
    .line 256
    move-object/from16 v20, v6

    .line 257
    .line 258
    const-string v6, "startActivation()V"

    .line 259
    .line 260
    move-object/from16 v0, v20

    .line 261
    .line 262
    invoke-direct/range {v1 .. v8}, Lz20/j;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 263
    .line 264
    .line 265
    invoke-virtual {v12, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 266
    .line 267
    .line 268
    move-object v5, v1

    .line 269
    :goto_7
    move-object/from16 v20, v5

    .line 270
    .line 271
    check-cast v20, Lhy0/g;

    .line 272
    .line 273
    invoke-virtual {v12, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 274
    .line 275
    .line 276
    move-result v1

    .line 277
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 278
    .line 279
    .line 280
    move-result-object v2

    .line 281
    if-nez v1, :cond_7

    .line 282
    .line 283
    if-ne v2, v0, :cond_8

    .line 284
    .line 285
    :cond_7
    new-instance v1, Lz20/j;

    .line 286
    .line 287
    const/4 v7, 0x0

    .line 288
    const/16 v8, 0xc

    .line 289
    .line 290
    const/4 v2, 0x0

    .line 291
    const-class v4, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveActivationViewModel;

    .line 292
    .line 293
    const-string v5, "stopActivation"

    .line 294
    .line 295
    const-string v6, "stopActivation()V"

    .line 296
    .line 297
    invoke-direct/range {v1 .. v8}, Lz20/j;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 298
    .line 299
    .line 300
    invoke-virtual {v12, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 301
    .line 302
    .line 303
    move-object v2, v1

    .line 304
    :cond_8
    move-object/from16 v21, v2

    .line 305
    .line 306
    check-cast v21, Lhy0/g;

    .line 307
    .line 308
    invoke-virtual {v12, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 309
    .line 310
    .line 311
    move-result v1

    .line 312
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 313
    .line 314
    .line 315
    move-result-object v2

    .line 316
    if-nez v1, :cond_9

    .line 317
    .line 318
    if-ne v2, v0, :cond_a

    .line 319
    .line 320
    :cond_9
    new-instance v1, Lz20/j;

    .line 321
    .line 322
    const/4 v7, 0x0

    .line 323
    const/16 v8, 0xd

    .line 324
    .line 325
    const/4 v2, 0x0

    .line 326
    const-class v4, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveActivationViewModel;

    .line 327
    .line 328
    const-string v5, "closeRPAModule"

    .line 329
    .line 330
    const-string v6, "closeRPAModule()V"

    .line 331
    .line 332
    invoke-direct/range {v1 .. v8}, Lz20/j;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 333
    .line 334
    .line 335
    invoke-virtual {v12, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 336
    .line 337
    .line 338
    move-object v2, v1

    .line 339
    :cond_a
    check-cast v2, Lhy0/g;

    .line 340
    .line 341
    invoke-interface {v11}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 342
    .line 343
    .line 344
    move-result-object v0

    .line 345
    check-cast v0, Ljava/lang/Boolean;

    .line 346
    .line 347
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 348
    .line 349
    .line 350
    move-result v6

    .line 351
    check-cast v20, Lay0/a;

    .line 352
    .line 353
    check-cast v21, Lay0/a;

    .line 354
    .line 355
    move-object v11, v2

    .line 356
    check-cast v11, Lay0/a;

    .line 357
    .line 358
    and-int/lit8 v0, v9, 0xe

    .line 359
    .line 360
    move v5, v10

    .line 361
    move-object v1, v13

    .line 362
    move v2, v15

    .line 363
    move/from16 v3, v16

    .line 364
    .line 365
    move/from16 v4, v17

    .line 366
    .line 367
    move-wide/from16 v7, v18

    .line 368
    .line 369
    move-object/from16 v9, v20

    .line 370
    .line 371
    move-object/from16 v10, v21

    .line 372
    .line 373
    move-object/from16 v15, p1

    .line 374
    .line 375
    move v13, v0

    .line 376
    move-object/from16 v0, p0

    .line 377
    .line 378
    invoke-static/range {v0 .. v13}, Lz61/h;->d(Lx2/s;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;ZZZZZJLay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 379
    .line 380
    .line 381
    goto :goto_8

    .line 382
    :cond_b
    move-object v15, v3

    .line 383
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 384
    .line 385
    .line 386
    :goto_8
    invoke-virtual {v12}, Ll2/t;->s()Ll2/u1;

    .line 387
    .line 388
    .line 389
    move-result-object v1

    .line 390
    if-eqz v1, :cond_c

    .line 391
    .line 392
    new-instance v2, Ly61/f;

    .line 393
    .line 394
    invoke-direct {v2, v0, v15, v14}, Ly61/f;-><init>(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveActivationViewModel;I)V

    .line 395
    .line 396
    .line 397
    iput-object v2, v1, Ll2/u1;->d:Lay0/n;

    .line 398
    .line 399
    :cond_c
    return-void
.end method

.method public static final d(Lx2/s;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;ZZZZZJLay0/a;Lay0/a;Lay0/a;Ll2/o;I)V
    .locals 19

    move/from16 v3, p2

    .line 1
    move-object/from16 v11, p12

    check-cast v11, Ll2/t;

    const v0, 0x43c1cca7

    invoke-virtual {v11, v0}, Ll2/t;->a0(I)Ll2/t;

    move-object/from16 v10, p0

    invoke-virtual {v11, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v0

    const/4 v1, 0x4

    if-eqz v0, :cond_0

    move v0, v1

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int v0, p13, v0

    move-object/from16 v6, p1

    invoke-virtual {v11, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_1

    const/16 v4, 0x20

    goto :goto_1

    :cond_1
    const/16 v4, 0x10

    :goto_1
    or-int/2addr v0, v4

    invoke-virtual {v11, v3}, Ll2/t;->h(Z)Z

    move-result v4

    if-eqz v4, :cond_2

    const/16 v4, 0x100

    goto :goto_2

    :cond_2
    const/16 v4, 0x80

    :goto_2
    or-int/2addr v0, v4

    move/from16 v4, p3

    invoke-virtual {v11, v4}, Ll2/t;->h(Z)Z

    move-result v5

    if-eqz v5, :cond_3

    const/16 v5, 0x800

    goto :goto_3

    :cond_3
    const/16 v5, 0x400

    :goto_3
    or-int/2addr v0, v5

    move/from16 v5, p4

    invoke-virtual {v11, v5}, Ll2/t;->h(Z)Z

    move-result v7

    if-eqz v7, :cond_4

    const/16 v7, 0x4000

    goto :goto_4

    :cond_4
    const/16 v7, 0x2000

    :goto_4
    or-int/2addr v0, v7

    move/from16 v7, p5

    invoke-virtual {v11, v7}, Ll2/t;->h(Z)Z

    move-result v8

    if-eqz v8, :cond_5

    const/high16 v8, 0x20000

    goto :goto_5

    :cond_5
    const/high16 v8, 0x10000

    :goto_5
    or-int/2addr v0, v8

    move/from16 v12, p6

    invoke-virtual {v11, v12}, Ll2/t;->h(Z)Z

    move-result v8

    if-eqz v8, :cond_6

    const/high16 v8, 0x100000

    goto :goto_6

    :cond_6
    const/high16 v8, 0x80000

    :goto_6
    or-int/2addr v0, v8

    move-wide/from16 v8, p7

    invoke-virtual {v11, v8, v9}, Ll2/t;->f(J)Z

    move-result v13

    if-eqz v13, :cond_7

    const/high16 v13, 0x800000

    goto :goto_7

    :cond_7
    const/high16 v13, 0x400000

    :goto_7
    or-int/2addr v0, v13

    move-object/from16 v13, p9

    invoke-virtual {v11, v13}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_8

    const/high16 v14, 0x4000000

    goto :goto_8

    :cond_8
    const/high16 v14, 0x2000000

    :goto_8
    or-int/2addr v0, v14

    move-object/from16 v14, p10

    invoke-virtual {v11, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v15

    if-eqz v15, :cond_9

    const/high16 v15, 0x20000000

    goto :goto_9

    :cond_9
    const/high16 v15, 0x10000000

    :goto_9
    or-int/2addr v15, v0

    move-object/from16 v0, p11

    invoke-virtual {v11, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v16

    if-eqz v16, :cond_a

    move/from16 v16, v1

    goto :goto_a

    :cond_a
    const/16 v16, 0x2

    :goto_a
    const v1, 0x12492493

    and-int/2addr v1, v15

    const v2, 0x12492492

    if-ne v1, v2, :cond_c

    and-int/lit8 v1, v16, 0x3

    const/4 v2, 0x2

    if-eq v1, v2, :cond_b

    goto :goto_b

    :cond_b
    const/4 v1, 0x0

    goto :goto_c

    :cond_c
    :goto_b
    const/4 v1, 0x1

    :goto_c
    and-int/lit8 v2, v15, 0x1

    invoke-virtual {v11, v2, v1}, Ll2/t;->O(IZ)Z

    move-result v1

    if-eqz v1, :cond_e

    .line 2
    const-string v1, "drive_activation_top_bar_title"

    invoke-static {v1, v11}, Ly61/a;->a(Ljava/lang/String;Ll2/o;)Ljava/lang/String;

    move-result-object v17

    .line 3
    sget-object v1, Lh71/a;->d:Lh71/a;

    if-eqz v3, :cond_d

    .line 4
    const-string v1, "drive_activation_title_park_in"

    goto :goto_d

    .line 5
    :cond_d
    const-string v1, "drive_activation_title_pull_out"

    .line 6
    :goto_d
    invoke-static {v1, v11}, Ly61/a;->a(Ljava/lang/String;Ll2/o;)Ljava/lang/String;

    move-result-object v18

    .line 7
    new-instance v0, Lz61/b;

    move v1, v3

    move v2, v5

    move v3, v7

    move-wide v7, v8

    move-object v5, v14

    move v9, v4

    move-object v4, v13

    invoke-direct/range {v0 .. v9}, Lz61/b;-><init>(ZZZLay0/a;Lay0/a;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;JZ)V

    const v1, 0x29c54d5d

    invoke-static {v1, v11, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    move-result-object v6

    and-int/lit8 v0, v15, 0xe

    const v1, 0x6c30180

    or-int/2addr v0, v1

    shr-int/lit8 v1, v15, 0x9

    and-int/lit16 v1, v1, 0x1c00

    or-int/2addr v0, v1

    shl-int/lit8 v1, v16, 0x6

    and-int/lit16 v13, v1, 0x380

    const/16 v14, 0xe40

    const/4 v4, 0x1

    const/4 v5, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    move v2, v12

    move-object/from16 v1, v17

    move-object/from16 v3, v18

    move v12, v0

    move-object v0, v10

    move-object/from16 v10, p11

    .line 8
    invoke-static/range {v0 .. v14}, Lc71/a;->b(Lx2/s;Ljava/lang/String;ZLjava/lang/String;ZZLay0/o;Lay0/o;Lk1/i;Lx2/d;Lay0/a;Ll2/o;III)V

    goto :goto_e

    .line 9
    :cond_e
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 10
    :goto_e
    invoke-virtual {v11}, Ll2/t;->s()Ll2/u1;

    move-result-object v14

    if-eqz v14, :cond_f

    new-instance v0, Lz61/c;

    move-object/from16 v1, p0

    move-object/from16 v2, p1

    move/from16 v3, p2

    move/from16 v4, p3

    move/from16 v5, p4

    move/from16 v6, p5

    move/from16 v7, p6

    move-wide/from16 v8, p7

    move-object/from16 v10, p9

    move-object/from16 v11, p10

    move-object/from16 v12, p11

    move/from16 v13, p13

    invoke-direct/range {v0 .. v13}, Lz61/c;-><init>(Lx2/s;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;ZZZZZJLay0/a;Lay0/a;Lay0/a;I)V

    .line 11
    iput-object v0, v14, Ll2/u1;->d:Lay0/n;

    :cond_f
    return-void
.end method
