.class public abstract Luz/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F

.field public static final c:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x20

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Luz/g;->a:F

    .line 5
    .line 6
    sput v0, Luz/g;->b:F

    .line 7
    .line 8
    const/16 v0, 0x14

    .line 9
    .line 10
    int-to-float v0, v0

    .line 11
    sput v0, Luz/g;->c:F

    .line 12
    .line 13
    return-void
.end method

.method public static final a(Lx2/s;Ll2/o;I)V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p2

    .line 4
    .line 5
    move-object/from16 v7, p1

    .line 6
    .line 7
    check-cast v7, Ll2/t;

    .line 8
    .line 9
    const v2, 0x772b7a68

    .line 10
    .line 11
    .line 12
    invoke-virtual {v7, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    and-int/lit8 v2, v1, 0x6

    .line 16
    .line 17
    const/4 v3, 0x2

    .line 18
    if-nez v2, :cond_1

    .line 19
    .line 20
    invoke-virtual {v7, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    if-eqz v2, :cond_0

    .line 25
    .line 26
    const/4 v2, 0x4

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    move v2, v3

    .line 29
    :goto_0
    or-int/2addr v2, v1

    .line 30
    goto :goto_1

    .line 31
    :cond_1
    move v2, v1

    .line 32
    :goto_1
    and-int/lit8 v4, v2, 0x3

    .line 33
    .line 34
    const/4 v5, 0x0

    .line 35
    const/4 v6, 0x1

    .line 36
    if-eq v4, v3, :cond_2

    .line 37
    .line 38
    move v3, v6

    .line 39
    goto :goto_2

    .line 40
    :cond_2
    move v3, v5

    .line 41
    :goto_2
    and-int/lit8 v4, v2, 0x1

    .line 42
    .line 43
    invoke-virtual {v7, v4, v3}, Ll2/t;->O(IZ)Z

    .line 44
    .line 45
    .line 46
    move-result v3

    .line 47
    if-eqz v3, :cond_c

    .line 48
    .line 49
    invoke-static {v7}, Lxf0/y1;->F(Ll2/o;)Z

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    if-eqz v3, :cond_3

    .line 54
    .line 55
    const v3, -0x136525c9

    .line 56
    .line 57
    .line 58
    invoke-virtual {v7, v3}, Ll2/t;->Y(I)V

    .line 59
    .line 60
    .line 61
    and-int/lit8 v2, v2, 0xe

    .line 62
    .line 63
    invoke-static {v0, v7, v2}, Luz/g;->c(Lx2/s;Ll2/o;I)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v7, v5}, Ll2/t;->q(Z)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {v7}, Ll2/t;->s()Ll2/u1;

    .line 70
    .line 71
    .line 72
    move-result-object v2

    .line 73
    if-eqz v2, :cond_d

    .line 74
    .line 75
    new-instance v3, Ln70/d0;

    .line 76
    .line 77
    const/16 v4, 0x12

    .line 78
    .line 79
    const/4 v5, 0x0

    .line 80
    invoke-direct {v3, v0, v1, v4, v5}, Ln70/d0;-><init>(Lx2/s;IIB)V

    .line 81
    .line 82
    .line 83
    :goto_3
    iput-object v3, v2, Ll2/u1;->d:Lay0/n;

    .line 84
    .line 85
    return-void

    .line 86
    :cond_3
    const v2, -0x1395a1c6

    .line 87
    .line 88
    .line 89
    const v3, -0x6040e0aa

    .line 90
    .line 91
    .line 92
    invoke-static {v2, v3, v7, v7, v5}, Lvj/b;->c(IILl2/t;Ll2/t;Z)Landroidx/lifecycle/i1;

    .line 93
    .line 94
    .line 95
    move-result-object v2

    .line 96
    if-eqz v2, :cond_b

    .line 97
    .line 98
    invoke-static {v2}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 99
    .line 100
    .line 101
    move-result-object v11

    .line 102
    invoke-static {v7}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 103
    .line 104
    .line 105
    move-result-object v13

    .line 106
    const-class v3, Ltz/s;

    .line 107
    .line 108
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 109
    .line 110
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 111
    .line 112
    .line 113
    move-result-object v8

    .line 114
    invoke-interface {v2}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 115
    .line 116
    .line 117
    move-result-object v9

    .line 118
    const/4 v10, 0x0

    .line 119
    const/4 v12, 0x0

    .line 120
    const/4 v14, 0x0

    .line 121
    invoke-static/range {v8 .. v14}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 122
    .line 123
    .line 124
    move-result-object v2

    .line 125
    invoke-virtual {v7, v5}, Ll2/t;->q(Z)V

    .line 126
    .line 127
    .line 128
    check-cast v2, Lql0/j;

    .line 129
    .line 130
    invoke-static {v2, v7, v5, v6}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 131
    .line 132
    .line 133
    move-object v10, v2

    .line 134
    check-cast v10, Ltz/s;

    .line 135
    .line 136
    iget-object v2, v10, Lql0/j;->g:Lyy0/l1;

    .line 137
    .line 138
    const/4 v3, 0x0

    .line 139
    invoke-static {v2, v3, v7, v6}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 140
    .line 141
    .line 142
    move-result-object v2

    .line 143
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object v3

    .line 147
    check-cast v3, Ltz/i;

    .line 148
    .line 149
    invoke-virtual {v7, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 150
    .line 151
    .line 152
    move-result v4

    .line 153
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 154
    .line 155
    .line 156
    move-result-object v6

    .line 157
    sget-object v8, Ll2/n;->a:Ll2/x0;

    .line 158
    .line 159
    if-nez v4, :cond_4

    .line 160
    .line 161
    if-ne v6, v8, :cond_5

    .line 162
    .line 163
    :cond_4
    move-object v4, v8

    .line 164
    goto :goto_4

    .line 165
    :cond_5
    move-object v4, v8

    .line 166
    goto :goto_5

    .line 167
    :goto_4
    new-instance v8, Lt90/c;

    .line 168
    .line 169
    const/4 v14, 0x0

    .line 170
    const/16 v15, 0xd

    .line 171
    .line 172
    const/4 v9, 0x0

    .line 173
    const-class v11, Ltz/s;

    .line 174
    .line 175
    const-string v12, "onOpenBatteryCharging"

    .line 176
    .line 177
    const-string v13, "onOpenBatteryCharging()V"

    .line 178
    .line 179
    invoke-direct/range {v8 .. v15}, Lt90/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 180
    .line 181
    .line 182
    invoke-virtual {v7, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 183
    .line 184
    .line 185
    move-object v6, v8

    .line 186
    :goto_5
    check-cast v6, Lhy0/g;

    .line 187
    .line 188
    invoke-virtual {v7, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 189
    .line 190
    .line 191
    move-result v8

    .line 192
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object v9

    .line 196
    if-nez v8, :cond_6

    .line 197
    .line 198
    if-ne v9, v4, :cond_7

    .line 199
    .line 200
    :cond_6
    new-instance v8, Lt90/c;

    .line 201
    .line 202
    const/4 v14, 0x0

    .line 203
    const/16 v15, 0xe

    .line 204
    .line 205
    const/4 v9, 0x0

    .line 206
    const-class v11, Ltz/s;

    .line 207
    .line 208
    const-string v12, "onOpenChargingProfilesDetail"

    .line 209
    .line 210
    const-string v13, "onOpenChargingProfilesDetail()V"

    .line 211
    .line 212
    invoke-direct/range {v8 .. v15}, Lt90/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 213
    .line 214
    .line 215
    invoke-virtual {v7, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 216
    .line 217
    .line 218
    move-object v9, v8

    .line 219
    :cond_7
    move-object/from16 v16, v9

    .line 220
    .line 221
    check-cast v16, Lhy0/g;

    .line 222
    .line 223
    invoke-virtual {v7, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 224
    .line 225
    .line 226
    move-result v8

    .line 227
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 228
    .line 229
    .line 230
    move-result-object v9

    .line 231
    if-nez v8, :cond_8

    .line 232
    .line 233
    if-ne v9, v4, :cond_9

    .line 234
    .line 235
    :cond_8
    new-instance v8, Lt90/c;

    .line 236
    .line 237
    const/4 v14, 0x0

    .line 238
    const/16 v15, 0xf

    .line 239
    .line 240
    const/4 v9, 0x0

    .line 241
    const-class v11, Ltz/s;

    .line 242
    .line 243
    const-string v12, "onOpenPreferredCharging"

    .line 244
    .line 245
    const-string v13, "onOpenPreferredCharging()V"

    .line 246
    .line 247
    invoke-direct/range {v8 .. v15}, Lt90/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 248
    .line 249
    .line 250
    invoke-virtual {v7, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 251
    .line 252
    .line 253
    move-object v9, v8

    .line 254
    :cond_9
    check-cast v9, Lhy0/g;

    .line 255
    .line 256
    const v4, 0x5a36ca74

    .line 257
    .line 258
    .line 259
    invoke-virtual {v7, v4}, Ll2/t;->Y(I)V

    .line 260
    .line 261
    .line 262
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 263
    .line 264
    .line 265
    move-result-object v4

    .line 266
    check-cast v4, Ltz/i;

    .line 267
    .line 268
    iget-boolean v4, v4, Ltz/i;->g:Z

    .line 269
    .line 270
    if-eqz v4, :cond_a

    .line 271
    .line 272
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 273
    .line 274
    .line 275
    move-result-object v2

    .line 276
    check-cast v2, Ltz/i;

    .line 277
    .line 278
    iget-boolean v2, v2, Ltz/i;->h:Z

    .line 279
    .line 280
    if-eqz v2, :cond_a

    .line 281
    .line 282
    const v2, -0x2a8d5526

    .line 283
    .line 284
    .line 285
    invoke-virtual {v7, v2}, Ll2/t;->Y(I)V

    .line 286
    .line 287
    .line 288
    sget-object v2, Lj91/h;->a:Ll2/u2;

    .line 289
    .line 290
    invoke-virtual {v7, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 291
    .line 292
    .line 293
    move-result-object v2

    .line 294
    check-cast v2, Lj91/e;

    .line 295
    .line 296
    invoke-virtual {v2}, Lj91/e;->a()J

    .line 297
    .line 298
    .line 299
    move-result-wide v10

    .line 300
    invoke-static {v10, v11, v0}, Lxf0/y1;->w(JLx2/s;)Lx2/s;

    .line 301
    .line 302
    .line 303
    move-result-object v2

    .line 304
    invoke-virtual {v7, v5}, Ll2/t;->q(Z)V

    .line 305
    .line 306
    .line 307
    goto :goto_6

    .line 308
    :cond_a
    const v2, -0x2a8c14fa

    .line 309
    .line 310
    .line 311
    invoke-virtual {v7, v2}, Ll2/t;->Y(I)V

    .line 312
    .line 313
    .line 314
    invoke-virtual {v7, v5}, Ll2/t;->q(Z)V

    .line 315
    .line 316
    .line 317
    move-object v2, v0

    .line 318
    :goto_6
    invoke-virtual {v7, v5}, Ll2/t;->q(Z)V

    .line 319
    .line 320
    .line 321
    move-object v4, v6

    .line 322
    check-cast v4, Lay0/a;

    .line 323
    .line 324
    move-object/from16 v5, v16

    .line 325
    .line 326
    check-cast v5, Lay0/a;

    .line 327
    .line 328
    move-object v6, v9

    .line 329
    check-cast v6, Lay0/a;

    .line 330
    .line 331
    const/4 v8, 0x0

    .line 332
    const/4 v9, 0x0

    .line 333
    move-object/from16 v17, v3

    .line 334
    .line 335
    move-object v3, v2

    .line 336
    move-object/from16 v2, v17

    .line 337
    .line 338
    invoke-static/range {v2 .. v9}, Luz/g;->b(Ltz/i;Lx2/s;Lay0/a;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 339
    .line 340
    .line 341
    goto :goto_7

    .line 342
    :cond_b
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 343
    .line 344
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 345
    .line 346
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 347
    .line 348
    .line 349
    throw v0

    .line 350
    :cond_c
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 351
    .line 352
    .line 353
    :goto_7
    invoke-virtual {v7}, Ll2/t;->s()Ll2/u1;

    .line 354
    .line 355
    .line 356
    move-result-object v2

    .line 357
    if-eqz v2, :cond_d

    .line 358
    .line 359
    new-instance v3, Ln70/d0;

    .line 360
    .line 361
    const/16 v4, 0x13

    .line 362
    .line 363
    const/4 v5, 0x0

    .line 364
    invoke-direct {v3, v0, v1, v4, v5}, Ln70/d0;-><init>(Lx2/s;IIB)V

    .line 365
    .line 366
    .line 367
    goto/16 :goto_3

    .line 368
    .line 369
    :cond_d
    return-void
.end method

.method public static final b(Ltz/i;Lx2/s;Lay0/a;Lay0/a;Lay0/a;Ll2/o;II)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v4, p5

    .line 4
    .line 5
    check-cast v4, Ll2/t;

    .line 6
    .line 7
    const v1, -0x7443a677

    .line 8
    .line 9
    .line 10
    invoke-virtual {v4, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v4, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    const/4 v2, 0x2

    .line 18
    const/4 v3, 0x4

    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    move v1, v3

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    move v1, v2

    .line 24
    :goto_0
    or-int v1, p6, v1

    .line 25
    .line 26
    move-object/from16 v5, p1

    .line 27
    .line 28
    invoke-virtual {v4, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v6

    .line 32
    if-eqz v6, :cond_1

    .line 33
    .line 34
    const/16 v6, 0x20

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_1
    const/16 v6, 0x10

    .line 38
    .line 39
    :goto_1
    or-int/2addr v1, v6

    .line 40
    and-int/lit8 v6, p7, 0x4

    .line 41
    .line 42
    if-eqz v6, :cond_2

    .line 43
    .line 44
    or-int/lit16 v1, v1, 0x180

    .line 45
    .line 46
    move-object/from16 v7, p2

    .line 47
    .line 48
    goto :goto_3

    .line 49
    :cond_2
    move-object/from16 v7, p2

    .line 50
    .line 51
    invoke-virtual {v4, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result v8

    .line 55
    if-eqz v8, :cond_3

    .line 56
    .line 57
    const/16 v8, 0x100

    .line 58
    .line 59
    goto :goto_2

    .line 60
    :cond_3
    const/16 v8, 0x80

    .line 61
    .line 62
    :goto_2
    or-int/2addr v1, v8

    .line 63
    :goto_3
    and-int/lit8 v8, p7, 0x8

    .line 64
    .line 65
    if-eqz v8, :cond_4

    .line 66
    .line 67
    or-int/lit16 v1, v1, 0xc00

    .line 68
    .line 69
    move-object/from16 v9, p3

    .line 70
    .line 71
    goto :goto_5

    .line 72
    :cond_4
    move-object/from16 v9, p3

    .line 73
    .line 74
    invoke-virtual {v4, v9}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result v10

    .line 78
    if-eqz v10, :cond_5

    .line 79
    .line 80
    const/16 v10, 0x800

    .line 81
    .line 82
    goto :goto_4

    .line 83
    :cond_5
    const/16 v10, 0x400

    .line 84
    .line 85
    :goto_4
    or-int/2addr v1, v10

    .line 86
    :goto_5
    and-int/lit8 v10, p7, 0x10

    .line 87
    .line 88
    if-eqz v10, :cond_6

    .line 89
    .line 90
    or-int/lit16 v1, v1, 0x6000

    .line 91
    .line 92
    move-object/from16 v11, p4

    .line 93
    .line 94
    goto :goto_7

    .line 95
    :cond_6
    move-object/from16 v11, p4

    .line 96
    .line 97
    invoke-virtual {v4, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result v12

    .line 101
    if-eqz v12, :cond_7

    .line 102
    .line 103
    const/16 v12, 0x4000

    .line 104
    .line 105
    goto :goto_6

    .line 106
    :cond_7
    const/16 v12, 0x2000

    .line 107
    .line 108
    :goto_6
    or-int/2addr v1, v12

    .line 109
    :goto_7
    and-int/lit16 v12, v1, 0x2493

    .line 110
    .line 111
    const/16 v13, 0x2492

    .line 112
    .line 113
    const/4 v14, 0x1

    .line 114
    const/4 v15, 0x0

    .line 115
    if-eq v12, v13, :cond_8

    .line 116
    .line 117
    move v12, v14

    .line 118
    goto :goto_8

    .line 119
    :cond_8
    move v12, v15

    .line 120
    :goto_8
    and-int/lit8 v13, v1, 0x1

    .line 121
    .line 122
    invoke-virtual {v4, v13, v12}, Ll2/t;->O(IZ)Z

    .line 123
    .line 124
    .line 125
    move-result v12

    .line 126
    if-eqz v12, :cond_15

    .line 127
    .line 128
    sget-object v12, Ll2/n;->a:Ll2/x0;

    .line 129
    .line 130
    if-eqz v6, :cond_a

    .line 131
    .line 132
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v6

    .line 136
    if-ne v6, v12, :cond_9

    .line 137
    .line 138
    new-instance v6, Lu41/u;

    .line 139
    .line 140
    const/16 v7, 0x11

    .line 141
    .line 142
    invoke-direct {v6, v7}, Lu41/u;-><init>(I)V

    .line 143
    .line 144
    .line 145
    invoke-virtual {v4, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 146
    .line 147
    .line 148
    :cond_9
    check-cast v6, Lay0/a;

    .line 149
    .line 150
    move-object/from16 v16, v6

    .line 151
    .line 152
    move v6, v1

    .line 153
    move-object/from16 v1, v16

    .line 154
    .line 155
    goto :goto_9

    .line 156
    :cond_a
    move v6, v1

    .line 157
    move-object v1, v7

    .line 158
    :goto_9
    if-eqz v8, :cond_c

    .line 159
    .line 160
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object v7

    .line 164
    if-ne v7, v12, :cond_b

    .line 165
    .line 166
    new-instance v7, Lu41/u;

    .line 167
    .line 168
    const/16 v8, 0x11

    .line 169
    .line 170
    invoke-direct {v7, v8}, Lu41/u;-><init>(I)V

    .line 171
    .line 172
    .line 173
    invoke-virtual {v4, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 174
    .line 175
    .line 176
    :cond_b
    check-cast v7, Lay0/a;

    .line 177
    .line 178
    move-object v9, v7

    .line 179
    :cond_c
    if-eqz v10, :cond_e

    .line 180
    .line 181
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object v7

    .line 185
    if-ne v7, v12, :cond_d

    .line 186
    .line 187
    new-instance v7, Lu41/u;

    .line 188
    .line 189
    const/16 v8, 0x11

    .line 190
    .line 191
    invoke-direct {v7, v8}, Lu41/u;-><init>(I)V

    .line 192
    .line 193
    .line 194
    invoke-virtual {v4, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 195
    .line 196
    .line 197
    :cond_d
    check-cast v7, Lay0/a;

    .line 198
    .line 199
    move-object v11, v7

    .line 200
    :cond_e
    iget-object v7, v0, Ltz/i;->e:Llf0/i;

    .line 201
    .line 202
    invoke-virtual {v7}, Ljava/lang/Enum;->ordinal()I

    .line 203
    .line 204
    .line 205
    move-result v7

    .line 206
    const v8, 0x7f1204ad

    .line 207
    .line 208
    .line 209
    if-eqz v7, :cond_14

    .line 210
    .line 211
    const v10, 0xe000

    .line 212
    .line 213
    .line 214
    if-eq v7, v14, :cond_13

    .line 215
    .line 216
    if-eq v7, v2, :cond_12

    .line 217
    .line 218
    const/4 v2, 0x3

    .line 219
    if-eq v7, v2, :cond_11

    .line 220
    .line 221
    if-eq v7, v3, :cond_10

    .line 222
    .line 223
    const/4 v2, 0x5

    .line 224
    if-ne v7, v2, :cond_f

    .line 225
    .line 226
    const v2, -0x71f38276

    .line 227
    .line 228
    .line 229
    invoke-virtual {v4, v2}, Ll2/t;->Y(I)V

    .line 230
    .line 231
    .line 232
    and-int/lit8 v2, v6, 0xe

    .line 233
    .line 234
    shr-int/lit8 v3, v6, 0x3

    .line 235
    .line 236
    and-int/lit8 v7, v3, 0x70

    .line 237
    .line 238
    or-int/2addr v2, v7

    .line 239
    and-int/lit16 v7, v3, 0x380

    .line 240
    .line 241
    or-int/2addr v2, v7

    .line 242
    and-int/lit16 v3, v3, 0x1c00

    .line 243
    .line 244
    or-int/2addr v2, v3

    .line 245
    shl-int/lit8 v3, v6, 0x9

    .line 246
    .line 247
    and-int/2addr v3, v10

    .line 248
    or-int v6, v2, v3

    .line 249
    .line 250
    move-object v2, v5

    .line 251
    move-object v5, v4

    .line 252
    move-object v4, v2

    .line 253
    move-object v2, v9

    .line 254
    move-object v3, v11

    .line 255
    invoke-static/range {v0 .. v6}, Luz/g;->e(Ltz/i;Lay0/a;Lay0/a;Lay0/a;Lx2/s;Ll2/o;I)V

    .line 256
    .line 257
    .line 258
    move-object v4, v5

    .line 259
    move-object v2, v1

    .line 260
    invoke-virtual {v4, v15}, Ll2/t;->q(Z)V

    .line 261
    .line 262
    .line 263
    :goto_a
    move-object v7, v2

    .line 264
    goto/16 :goto_b

    .line 265
    .line 266
    :cond_f
    const v0, -0x71f3bfc1

    .line 267
    .line 268
    .line 269
    invoke-static {v0, v4, v15}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 270
    .line 271
    .line 272
    move-result-object v0

    .line 273
    throw v0

    .line 274
    :cond_10
    move-object v2, v1

    .line 275
    const v0, 0x338facf6

    .line 276
    .line 277
    .line 278
    invoke-virtual {v4, v0}, Ll2/t;->Y(I)V

    .line 279
    .line 280
    .line 281
    invoke-virtual {v4, v15}, Ll2/t;->q(Z)V

    .line 282
    .line 283
    .line 284
    goto :goto_a

    .line 285
    :cond_11
    move-object v2, v1

    .line 286
    const v0, 0x337f4131

    .line 287
    .line 288
    .line 289
    invoke-virtual {v4, v0}, Ll2/t;->Y(I)V

    .line 290
    .line 291
    .line 292
    invoke-static {v4, v8}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 293
    .line 294
    .line 295
    move-result-object v3

    .line 296
    and-int/lit8 v0, v6, 0x70

    .line 297
    .line 298
    or-int/lit16 v0, v0, 0xc00

    .line 299
    .line 300
    shl-int/lit8 v1, v6, 0x6

    .line 301
    .line 302
    and-int/2addr v1, v10

    .line 303
    or-int/2addr v0, v1

    .line 304
    const/4 v1, 0x4

    .line 305
    const/4 v6, 0x0

    .line 306
    move-object/from16 v5, p1

    .line 307
    .line 308
    invoke-static/range {v0 .. v6}, Lxf0/i0;->y(IILay0/a;Ljava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 309
    .line 310
    .line 311
    invoke-virtual {v4, v15}, Ll2/t;->q(Z)V

    .line 312
    .line 313
    .line 314
    goto :goto_a

    .line 315
    :cond_12
    move-object v2, v1

    .line 316
    const v0, 0x338bab4c

    .line 317
    .line 318
    .line 319
    invoke-virtual {v4, v0}, Ll2/t;->Y(I)V

    .line 320
    .line 321
    .line 322
    invoke-static {v4, v8}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 323
    .line 324
    .line 325
    move-result-object v3

    .line 326
    and-int/lit8 v0, v6, 0x70

    .line 327
    .line 328
    or-int/lit16 v0, v0, 0xc00

    .line 329
    .line 330
    shl-int/lit8 v1, v6, 0x6

    .line 331
    .line 332
    and-int/2addr v1, v10

    .line 333
    or-int/2addr v0, v1

    .line 334
    const/4 v1, 0x4

    .line 335
    const/4 v6, 0x0

    .line 336
    move-object/from16 v5, p1

    .line 337
    .line 338
    invoke-static/range {v0 .. v6}, Lxf0/i0;->m(IILay0/a;Ljava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 339
    .line 340
    .line 341
    invoke-virtual {v4, v15}, Ll2/t;->q(Z)V

    .line 342
    .line 343
    .line 344
    goto :goto_a

    .line 345
    :cond_13
    move-object v2, v1

    .line 346
    const v0, 0x3387854e

    .line 347
    .line 348
    .line 349
    invoke-virtual {v4, v0}, Ll2/t;->Y(I)V

    .line 350
    .line 351
    .line 352
    invoke-static {v4, v8}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 353
    .line 354
    .line 355
    move-result-object v3

    .line 356
    and-int/lit8 v0, v6, 0x70

    .line 357
    .line 358
    or-int/lit16 v0, v0, 0xc00

    .line 359
    .line 360
    shl-int/lit8 v1, v6, 0x6

    .line 361
    .line 362
    and-int/2addr v1, v10

    .line 363
    or-int/2addr v0, v1

    .line 364
    const/4 v1, 0x4

    .line 365
    const/4 v6, 0x0

    .line 366
    move-object/from16 v5, p1

    .line 367
    .line 368
    invoke-static/range {v0 .. v6}, Lxf0/i0;->E(IILay0/a;Ljava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 369
    .line 370
    .line 371
    move-object v7, v2

    .line 372
    invoke-virtual {v4, v15}, Ll2/t;->q(Z)V

    .line 373
    .line 374
    .line 375
    goto :goto_b

    .line 376
    :cond_14
    move-object v7, v1

    .line 377
    const v0, 0x337c01e2

    .line 378
    .line 379
    .line 380
    invoke-virtual {v4, v0}, Ll2/t;->Y(I)V

    .line 381
    .line 382
    .line 383
    invoke-static {v4, v8}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 384
    .line 385
    .line 386
    move-result-object v2

    .line 387
    and-int/lit8 v0, v6, 0x70

    .line 388
    .line 389
    or-int/lit16 v0, v0, 0x180

    .line 390
    .line 391
    const/4 v1, 0x0

    .line 392
    const/4 v5, 0x0

    .line 393
    move-object v3, v4

    .line 394
    move-object/from16 v4, p1

    .line 395
    .line 396
    invoke-static/range {v0 .. v5}, Lxf0/i0;->u(IILjava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 397
    .line 398
    .line 399
    move-object v4, v3

    .line 400
    invoke-virtual {v4, v15}, Ll2/t;->q(Z)V

    .line 401
    .line 402
    .line 403
    :goto_b
    move-object v0, v4

    .line 404
    move-object v3, v7

    .line 405
    move-object v4, v9

    .line 406
    move-object v5, v11

    .line 407
    goto :goto_c

    .line 408
    :cond_15
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 409
    .line 410
    .line 411
    goto :goto_b

    .line 412
    :goto_c
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 413
    .line 414
    .line 415
    move-result-object v8

    .line 416
    if-eqz v8, :cond_16

    .line 417
    .line 418
    new-instance v0, Luz/d;

    .line 419
    .line 420
    move-object/from16 v1, p0

    .line 421
    .line 422
    move-object/from16 v2, p1

    .line 423
    .line 424
    move/from16 v6, p6

    .line 425
    .line 426
    move/from16 v7, p7

    .line 427
    .line 428
    invoke-direct/range {v0 .. v7}, Luz/d;-><init>(Ltz/i;Lx2/s;Lay0/a;Lay0/a;Lay0/a;II)V

    .line 429
    .line 430
    .line 431
    iput-object v0, v8, Ll2/u1;->d:Lay0/n;

    .line 432
    .line 433
    :cond_16
    return-void
.end method

.method public static final c(Lx2/s;Ll2/o;I)V
    .locals 5

    .line 1
    check-cast p1, Ll2/t;

    .line 2
    .line 3
    const v0, -0x64579cb0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p2, 0x6

    .line 10
    .line 11
    const/4 v1, 0x2

    .line 12
    if-nez v0, :cond_1

    .line 13
    .line 14
    invoke-virtual {p1, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    const/4 v0, 0x4

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    move v0, v1

    .line 23
    :goto_0
    or-int/2addr v0, p2

    .line 24
    goto :goto_1

    .line 25
    :cond_1
    move v0, p2

    .line 26
    :goto_1
    and-int/lit8 v2, v0, 0x3

    .line 27
    .line 28
    const/4 v3, 0x0

    .line 29
    const/4 v4, 0x1

    .line 30
    if-eq v2, v1, :cond_2

    .line 31
    .line 32
    move v1, v4

    .line 33
    goto :goto_2

    .line 34
    :cond_2
    move v1, v3

    .line 35
    :goto_2
    and-int/2addr v0, v4

    .line 36
    invoke-virtual {p1, v0, v1}, Ll2/t;->O(IZ)Z

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    if-eqz v0, :cond_3

    .line 41
    .line 42
    new-instance v0, Luz/e;

    .line 43
    .line 44
    const/4 v1, 0x0

    .line 45
    invoke-direct {v0, p0, v1}, Luz/e;-><init>(Lx2/s;I)V

    .line 46
    .line 47
    .line 48
    const v1, -0x12a8d4ff

    .line 49
    .line 50
    .line 51
    invoke-static {v1, p1, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    const/16 v1, 0x36

    .line 56
    .line 57
    invoke-static {v3, v0, p1, v1, v3}, Lxf0/y1;->i(ZLay0/n;Ll2/o;II)V

    .line 58
    .line 59
    .line 60
    goto :goto_3

    .line 61
    :cond_3
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 62
    .line 63
    .line 64
    :goto_3
    invoke-virtual {p1}, Ll2/t;->s()Ll2/u1;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    if-eqz p1, :cond_4

    .line 69
    .line 70
    new-instance v0, Ln70/d0;

    .line 71
    .line 72
    const/16 v1, 0x14

    .line 73
    .line 74
    const/4 v2, 0x0

    .line 75
    invoke-direct {v0, p0, p2, v1, v2}, Ln70/d0;-><init>(Lx2/s;IIB)V

    .line 76
    .line 77
    .line 78
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 79
    .line 80
    :cond_4
    return-void
.end method

.method public static final d(Ltz/e;ZZLl2/o;II)V
    .locals 19

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move/from16 v2, p1

    .line 4
    .line 5
    iget-object v0, v1, Ltz/e;->b:Ltz/d;

    .line 6
    .line 7
    move-object/from16 v8, p3

    .line 8
    .line 9
    check-cast v8, Ll2/t;

    .line 10
    .line 11
    const v3, -0x3eb5e8eb

    .line 12
    .line 13
    .line 14
    invoke-virtual {v8, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v8, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    const/4 v4, 0x2

    .line 22
    if-eqz v3, :cond_0

    .line 23
    .line 24
    const/4 v3, 0x4

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    move v3, v4

    .line 27
    :goto_0
    or-int v3, p4, v3

    .line 28
    .line 29
    invoke-virtual {v8, v2}, Ll2/t;->h(Z)Z

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
    or-int/2addr v3, v5

    .line 41
    and-int/lit8 v5, p5, 0x4

    .line 42
    .line 43
    if-eqz v5, :cond_2

    .line 44
    .line 45
    or-int/lit16 v3, v3, 0x180

    .line 46
    .line 47
    move/from16 v6, p2

    .line 48
    .line 49
    goto :goto_3

    .line 50
    :cond_2
    move/from16 v6, p2

    .line 51
    .line 52
    invoke-virtual {v8, v6}, Ll2/t;->h(Z)Z

    .line 53
    .line 54
    .line 55
    move-result v7

    .line 56
    if-eqz v7, :cond_3

    .line 57
    .line 58
    const/16 v7, 0x100

    .line 59
    .line 60
    goto :goto_2

    .line 61
    :cond_3
    const/16 v7, 0x80

    .line 62
    .line 63
    :goto_2
    or-int/2addr v3, v7

    .line 64
    :goto_3
    and-int/lit16 v7, v3, 0x93

    .line 65
    .line 66
    const/16 v9, 0x92

    .line 67
    .line 68
    const/4 v10, 0x1

    .line 69
    const/4 v11, 0x0

    .line 70
    if-eq v7, v9, :cond_4

    .line 71
    .line 72
    move v7, v10

    .line 73
    goto :goto_4

    .line 74
    :cond_4
    move v7, v11

    .line 75
    :goto_4
    and-int/2addr v3, v10

    .line 76
    invoke-virtual {v8, v3, v7}, Ll2/t;->O(IZ)Z

    .line 77
    .line 78
    .line 79
    move-result v3

    .line 80
    if-eqz v3, :cond_17

    .line 81
    .line 82
    if-eqz v5, :cond_5

    .line 83
    .line 84
    move v12, v11

    .line 85
    goto :goto_5

    .line 86
    :cond_5
    move v12, v6

    .line 87
    :goto_5
    if-nez v0, :cond_6

    .line 88
    .line 89
    const v0, 0x4cf6b55a    # 1.29346256E8f

    .line 90
    .line 91
    .line 92
    invoke-virtual {v8, v0}, Ll2/t;->Y(I)V

    .line 93
    .line 94
    .line 95
    :goto_6
    invoke-virtual {v8, v11}, Ll2/t;->q(Z)V

    .line 96
    .line 97
    .line 98
    goto/16 :goto_a

    .line 99
    .line 100
    :cond_6
    const v3, 0x4cf6b55b    # 1.29346264E8f

    .line 101
    .line 102
    .line 103
    invoke-virtual {v8, v3}, Ll2/t;->Y(I)V

    .line 104
    .line 105
    .line 106
    const v3, 0x7f0802b4

    .line 107
    .line 108
    .line 109
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 110
    .line 111
    .line 112
    move-result-object v3

    .line 113
    if-eqz v12, :cond_7

    .line 114
    .line 115
    const v0, 0x7f0802cd

    .line 116
    .line 117
    .line 118
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 119
    .line 120
    .line 121
    move-result-object v0

    .line 122
    sget-object v3, Lsz/a;->e:Lsz/a;

    .line 123
    .line 124
    new-instance v5, Llx0/l;

    .line 125
    .line 126
    invoke-direct {v5, v0, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    goto/16 :goto_7

    .line 130
    .line 131
    :cond_7
    if-eqz v2, :cond_8

    .line 132
    .line 133
    const v0, 0x7f0802ca

    .line 134
    .line 135
    .line 136
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 137
    .line 138
    .line 139
    move-result-object v0

    .line 140
    sget-object v3, Lsz/a;->e:Lsz/a;

    .line 141
    .line 142
    new-instance v5, Llx0/l;

    .line 143
    .line 144
    invoke-direct {v5, v0, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 145
    .line 146
    .line 147
    goto/16 :goto_7

    .line 148
    .line 149
    :cond_8
    sget-object v5, Ltz/d;->d:Ltz/d;

    .line 150
    .line 151
    if-ne v0, v5, :cond_9

    .line 152
    .line 153
    sget-object v0, Lsz/a;->d:Lsz/a;

    .line 154
    .line 155
    new-instance v5, Llx0/l;

    .line 156
    .line 157
    invoke-direct {v5, v3, v0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 158
    .line 159
    .line 160
    goto/16 :goto_7

    .line 161
    .line 162
    :cond_9
    sget-object v5, Ltz/d;->e:Ltz/d;

    .line 163
    .line 164
    if-ne v0, v5, :cond_a

    .line 165
    .line 166
    const v0, 0x7f08042d

    .line 167
    .line 168
    .line 169
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 170
    .line 171
    .line 172
    move-result-object v0

    .line 173
    sget-object v3, Lsz/a;->f:Lsz/a;

    .line 174
    .line 175
    new-instance v5, Llx0/l;

    .line 176
    .line 177
    invoke-direct {v5, v0, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 178
    .line 179
    .line 180
    goto/16 :goto_7

    .line 181
    .line 182
    :cond_a
    sget-object v5, Ltz/d;->f:Ltz/d;

    .line 183
    .line 184
    if-ne v0, v5, :cond_b

    .line 185
    .line 186
    const v0, 0x7f080431

    .line 187
    .line 188
    .line 189
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 190
    .line 191
    .line 192
    move-result-object v0

    .line 193
    sget-object v3, Lsz/a;->f:Lsz/a;

    .line 194
    .line 195
    new-instance v5, Llx0/l;

    .line 196
    .line 197
    invoke-direct {v5, v0, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 198
    .line 199
    .line 200
    goto/16 :goto_7

    .line 201
    .line 202
    :cond_b
    sget-object v5, Ltz/d;->g:Ltz/d;

    .line 203
    .line 204
    if-ne v0, v5, :cond_c

    .line 205
    .line 206
    const v0, 0x7f080433

    .line 207
    .line 208
    .line 209
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 210
    .line 211
    .line 212
    move-result-object v0

    .line 213
    sget-object v3, Lsz/a;->f:Lsz/a;

    .line 214
    .line 215
    new-instance v5, Llx0/l;

    .line 216
    .line 217
    invoke-direct {v5, v0, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 218
    .line 219
    .line 220
    goto/16 :goto_7

    .line 221
    .line 222
    :cond_c
    sget-object v5, Ltz/d;->h:Ltz/d;

    .line 223
    .line 224
    if-ne v0, v5, :cond_d

    .line 225
    .line 226
    const v0, 0x7f080435

    .line 227
    .line 228
    .line 229
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 230
    .line 231
    .line 232
    move-result-object v0

    .line 233
    sget-object v3, Lsz/a;->f:Lsz/a;

    .line 234
    .line 235
    new-instance v5, Llx0/l;

    .line 236
    .line 237
    invoke-direct {v5, v0, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 238
    .line 239
    .line 240
    goto/16 :goto_7

    .line 241
    .line 242
    :cond_d
    sget-object v5, Ltz/d;->i:Ltz/d;

    .line 243
    .line 244
    if-ne v0, v5, :cond_e

    .line 245
    .line 246
    const v0, 0x7f080437

    .line 247
    .line 248
    .line 249
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 250
    .line 251
    .line 252
    move-result-object v0

    .line 253
    sget-object v3, Lsz/a;->f:Lsz/a;

    .line 254
    .line 255
    new-instance v5, Llx0/l;

    .line 256
    .line 257
    invoke-direct {v5, v0, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 258
    .line 259
    .line 260
    goto :goto_7

    .line 261
    :cond_e
    sget-object v5, Ltz/d;->j:Ltz/d;

    .line 262
    .line 263
    if-ne v0, v5, :cond_f

    .line 264
    .line 265
    const v0, 0x7f080439

    .line 266
    .line 267
    .line 268
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 269
    .line 270
    .line 271
    move-result-object v0

    .line 272
    sget-object v3, Lsz/a;->f:Lsz/a;

    .line 273
    .line 274
    new-instance v5, Llx0/l;

    .line 275
    .line 276
    invoke-direct {v5, v0, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 277
    .line 278
    .line 279
    goto :goto_7

    .line 280
    :cond_f
    sget-object v5, Ltz/d;->k:Ltz/d;

    .line 281
    .line 282
    if-ne v0, v5, :cond_10

    .line 283
    .line 284
    const v0, 0x7f08043b

    .line 285
    .line 286
    .line 287
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 288
    .line 289
    .line 290
    move-result-object v0

    .line 291
    sget-object v3, Lsz/a;->f:Lsz/a;

    .line 292
    .line 293
    new-instance v5, Llx0/l;

    .line 294
    .line 295
    invoke-direct {v5, v0, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 296
    .line 297
    .line 298
    goto :goto_7

    .line 299
    :cond_10
    sget-object v5, Ltz/d;->l:Ltz/d;

    .line 300
    .line 301
    if-ne v0, v5, :cond_11

    .line 302
    .line 303
    const v0, 0x7f08043d

    .line 304
    .line 305
    .line 306
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 307
    .line 308
    .line 309
    move-result-object v0

    .line 310
    sget-object v3, Lsz/a;->f:Lsz/a;

    .line 311
    .line 312
    new-instance v5, Llx0/l;

    .line 313
    .line 314
    invoke-direct {v5, v0, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 315
    .line 316
    .line 317
    goto :goto_7

    .line 318
    :cond_11
    sget-object v5, Ltz/d;->m:Ltz/d;

    .line 319
    .line 320
    if-ne v0, v5, :cond_12

    .line 321
    .line 322
    const v0, 0x7f08043f

    .line 323
    .line 324
    .line 325
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 326
    .line 327
    .line 328
    move-result-object v0

    .line 329
    sget-object v3, Lsz/a;->f:Lsz/a;

    .line 330
    .line 331
    new-instance v5, Llx0/l;

    .line 332
    .line 333
    invoke-direct {v5, v0, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 334
    .line 335
    .line 336
    goto :goto_7

    .line 337
    :cond_12
    sget-object v5, Ltz/d;->n:Ltz/d;

    .line 338
    .line 339
    if-ne v0, v5, :cond_13

    .line 340
    .line 341
    const v0, 0x7f08042e

    .line 342
    .line 343
    .line 344
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 345
    .line 346
    .line 347
    move-result-object v0

    .line 348
    sget-object v3, Lsz/a;->f:Lsz/a;

    .line 349
    .line 350
    new-instance v5, Llx0/l;

    .line 351
    .line 352
    invoke-direct {v5, v0, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 353
    .line 354
    .line 355
    goto :goto_7

    .line 356
    :cond_13
    sget-object v0, Lsz/a;->d:Lsz/a;

    .line 357
    .line 358
    new-instance v5, Llx0/l;

    .line 359
    .line 360
    invoke-direct {v5, v3, v0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 361
    .line 362
    .line 363
    :goto_7
    iget-object v0, v5, Llx0/l;->d:Ljava/lang/Object;

    .line 364
    .line 365
    check-cast v0, Ljava/lang/Number;

    .line 366
    .line 367
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 368
    .line 369
    .line 370
    move-result v0

    .line 371
    iget-object v3, v5, Llx0/l;->e:Ljava/lang/Object;

    .line 372
    .line 373
    check-cast v3, Lsz/a;

    .line 374
    .line 375
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 376
    .line 377
    .line 378
    move-result v3

    .line 379
    if-eqz v3, :cond_16

    .line 380
    .line 381
    if-eq v3, v10, :cond_15

    .line 382
    .line 383
    if-ne v3, v4, :cond_14

    .line 384
    .line 385
    const v3, -0x4f0db8ff

    .line 386
    .line 387
    .line 388
    invoke-virtual {v8, v3}, Ll2/t;->Y(I)V

    .line 389
    .line 390
    .line 391
    invoke-virtual {v8, v11}, Ll2/t;->q(Z)V

    .line 392
    .line 393
    .line 394
    sget-wide v3, Le3/s;->i:J

    .line 395
    .line 396
    :goto_8
    move-wide v6, v3

    .line 397
    goto :goto_9

    .line 398
    :cond_14
    const v0, -0x4f0dca61

    .line 399
    .line 400
    .line 401
    invoke-static {v0, v8, v11}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 402
    .line 403
    .line 404
    move-result-object v0

    .line 405
    throw v0

    .line 406
    :cond_15
    const v3, -0x4f0dc17e

    .line 407
    .line 408
    .line 409
    invoke-virtual {v8, v3}, Ll2/t;->Y(I)V

    .line 410
    .line 411
    .line 412
    sget-object v3, Lj91/h;->a:Ll2/u2;

    .line 413
    .line 414
    invoke-virtual {v8, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 415
    .line 416
    .line 417
    move-result-object v3

    .line 418
    check-cast v3, Lj91/e;

    .line 419
    .line 420
    invoke-virtual {v3}, Lj91/e;->e()J

    .line 421
    .line 422
    .line 423
    move-result-wide v3

    .line 424
    invoke-virtual {v8, v11}, Ll2/t;->q(Z)V

    .line 425
    .line 426
    .line 427
    goto :goto_8

    .line 428
    :cond_16
    const v3, -0x4f0db005

    .line 429
    .line 430
    .line 431
    invoke-virtual {v8, v3}, Ll2/t;->Y(I)V

    .line 432
    .line 433
    .line 434
    sget-object v3, Lj91/h;->a:Ll2/u2;

    .line 435
    .line 436
    invoke-virtual {v8, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 437
    .line 438
    .line 439
    move-result-object v3

    .line 440
    check-cast v3, Lj91/e;

    .line 441
    .line 442
    invoke-virtual {v3}, Lj91/e;->a()J

    .line 443
    .line 444
    .line 445
    move-result-wide v3

    .line 446
    invoke-virtual {v8, v11}, Ll2/t;->q(Z)V

    .line 447
    .line 448
    .line 449
    goto :goto_8

    .line 450
    :goto_9
    invoke-static {v0, v11, v8}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 451
    .line 452
    .line 453
    move-result-object v3

    .line 454
    sget-object v0, Lj91/a;->a:Ll2/u2;

    .line 455
    .line 456
    invoke-virtual {v8, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 457
    .line 458
    .line 459
    move-result-object v0

    .line 460
    check-cast v0, Lj91/c;

    .line 461
    .line 462
    iget v0, v0, Lj91/c;->c:F

    .line 463
    .line 464
    const/16 v17, 0x0

    .line 465
    .line 466
    const/16 v18, 0xb

    .line 467
    .line 468
    sget-object v13, Lx2/p;->b:Lx2/p;

    .line 469
    .line 470
    const/4 v14, 0x0

    .line 471
    const/4 v15, 0x0

    .line 472
    move/from16 v16, v0

    .line 473
    .line 474
    invoke-static/range {v13 .. v18}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 475
    .line 476
    .line 477
    move-result-object v0

    .line 478
    sget v4, Luz/g;->b:F

    .line 479
    .line 480
    invoke-static {v0, v4}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 481
    .line 482
    .line 483
    move-result-object v0

    .line 484
    const-string v4, "battery_charging_icon"

    .line 485
    .line 486
    invoke-static {v0, v4}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 487
    .line 488
    .line 489
    move-result-object v5

    .line 490
    const/16 v9, 0x30

    .line 491
    .line 492
    const/4 v10, 0x0

    .line 493
    const/4 v4, 0x0

    .line 494
    invoke-static/range {v3 .. v10}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 495
    .line 496
    .line 497
    goto/16 :goto_6

    .line 498
    .line 499
    :goto_a
    move v3, v12

    .line 500
    goto :goto_b

    .line 501
    :cond_17
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 502
    .line 503
    .line 504
    move v3, v6

    .line 505
    :goto_b
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 506
    .line 507
    .line 508
    move-result-object v6

    .line 509
    if-eqz v6, :cond_18

    .line 510
    .line 511
    new-instance v0, Luz/c;

    .line 512
    .line 513
    move/from16 v4, p4

    .line 514
    .line 515
    move/from16 v5, p5

    .line 516
    .line 517
    invoke-direct/range {v0 .. v5}, Luz/c;-><init>(Ltz/e;ZZII)V

    .line 518
    .line 519
    .line 520
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 521
    .line 522
    :cond_18
    return-void
.end method

.method public static final e(Ltz/i;Lay0/a;Lay0/a;Lay0/a;Lx2/s;Ll2/o;I)V
    .locals 24

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v3, p2

    .line 4
    .line 5
    move-object/from16 v4, p3

    .line 6
    .line 7
    move-object/from16 v5, p4

    .line 8
    .line 9
    move/from16 v6, p6

    .line 10
    .line 11
    move-object/from16 v0, p5

    .line 12
    .line 13
    check-cast v0, Ll2/t;

    .line 14
    .line 15
    const v2, -0x64c11801

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 19
    .line 20
    .line 21
    and-int/lit8 v2, v6, 0x6

    .line 22
    .line 23
    if-nez v2, :cond_1

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    if-eqz v2, :cond_0

    .line 30
    .line 31
    const/4 v2, 0x4

    .line 32
    goto :goto_0

    .line 33
    :cond_0
    const/4 v2, 0x2

    .line 34
    :goto_0
    or-int/2addr v2, v6

    .line 35
    goto :goto_1

    .line 36
    :cond_1
    move v2, v6

    .line 37
    :goto_1
    and-int/lit8 v7, v6, 0x30

    .line 38
    .line 39
    if-nez v7, :cond_3

    .line 40
    .line 41
    move-object/from16 v7, p1

    .line 42
    .line 43
    invoke-virtual {v0, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v8

    .line 47
    if-eqz v8, :cond_2

    .line 48
    .line 49
    const/16 v8, 0x20

    .line 50
    .line 51
    goto :goto_2

    .line 52
    :cond_2
    const/16 v8, 0x10

    .line 53
    .line 54
    :goto_2
    or-int/2addr v2, v8

    .line 55
    goto :goto_3

    .line 56
    :cond_3
    move-object/from16 v7, p1

    .line 57
    .line 58
    :goto_3
    and-int/lit16 v8, v6, 0x180

    .line 59
    .line 60
    if-nez v8, :cond_5

    .line 61
    .line 62
    invoke-virtual {v0, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result v8

    .line 66
    if-eqz v8, :cond_4

    .line 67
    .line 68
    const/16 v8, 0x100

    .line 69
    .line 70
    goto :goto_4

    .line 71
    :cond_4
    const/16 v8, 0x80

    .line 72
    .line 73
    :goto_4
    or-int/2addr v2, v8

    .line 74
    :cond_5
    and-int/lit16 v8, v6, 0xc00

    .line 75
    .line 76
    if-nez v8, :cond_7

    .line 77
    .line 78
    invoke-virtual {v0, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v8

    .line 82
    if-eqz v8, :cond_6

    .line 83
    .line 84
    const/16 v8, 0x800

    .line 85
    .line 86
    goto :goto_5

    .line 87
    :cond_6
    const/16 v8, 0x400

    .line 88
    .line 89
    :goto_5
    or-int/2addr v2, v8

    .line 90
    :cond_7
    and-int/lit16 v8, v6, 0x6000

    .line 91
    .line 92
    if-nez v8, :cond_9

    .line 93
    .line 94
    invoke-virtual {v0, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result v8

    .line 98
    if-eqz v8, :cond_8

    .line 99
    .line 100
    const/16 v8, 0x4000

    .line 101
    .line 102
    goto :goto_6

    .line 103
    :cond_8
    const/16 v8, 0x2000

    .line 104
    .line 105
    :goto_6
    or-int/2addr v2, v8

    .line 106
    :cond_9
    and-int/lit16 v8, v2, 0x2493

    .line 107
    .line 108
    const/16 v9, 0x2492

    .line 109
    .line 110
    if-eq v8, v9, :cond_a

    .line 111
    .line 112
    const/4 v8, 0x1

    .line 113
    goto :goto_7

    .line 114
    :cond_a
    const/4 v8, 0x0

    .line 115
    :goto_7
    and-int/lit8 v9, v2, 0x1

    .line 116
    .line 117
    invoke-virtual {v0, v9, v8}, Ll2/t;->O(IZ)Z

    .line 118
    .line 119
    .line 120
    move-result v8

    .line 121
    if-eqz v8, :cond_b

    .line 122
    .line 123
    const v8, 0x7f1204ad

    .line 124
    .line 125
    .line 126
    invoke-static {v0, v8}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object v8

    .line 130
    iget-boolean v9, v1, Ltz/i;->d:Z

    .line 131
    .line 132
    invoke-static {v5, v9}, Lxf0/y1;->H(Lx2/s;Z)Lx2/s;

    .line 133
    .line 134
    .line 135
    move-result-object v10

    .line 136
    new-instance v9, Lt10/f;

    .line 137
    .line 138
    const/4 v11, 0x2

    .line 139
    invoke-direct {v9, v1, v3, v4, v11}, Lt10/f;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 140
    .line 141
    .line 142
    const v11, 0x64a26639

    .line 143
    .line 144
    .line 145
    invoke-static {v11, v0, v9}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 146
    .line 147
    .line 148
    move-result-object v9

    .line 149
    and-int/lit8 v2, v2, 0x70

    .line 150
    .line 151
    or-int/lit16 v2, v2, 0x180

    .line 152
    .line 153
    const/16 v23, 0x2710

    .line 154
    .line 155
    move-object v7, v8

    .line 156
    move-object v8, v9

    .line 157
    const-string v9, ""

    .line 158
    .line 159
    const/4 v11, 0x0

    .line 160
    const/4 v12, 0x0

    .line 161
    const/4 v13, 0x0

    .line 162
    const/4 v14, 0x0

    .line 163
    const/4 v15, 0x0

    .line 164
    const/16 v16, 0x0

    .line 165
    .line 166
    const-string v18, "battery_charging_"

    .line 167
    .line 168
    const/16 v19, 0x0

    .line 169
    .line 170
    const v21, 0xdb01b0

    .line 171
    .line 172
    .line 173
    move-object/from16 v17, p1

    .line 174
    .line 175
    move-object/from16 v20, v0

    .line 176
    .line 177
    move/from16 v22, v2

    .line 178
    .line 179
    invoke-static/range {v7 .. v23}, Lxf0/i0;->q(Ljava/lang/String;Lt2/b;Ljava/lang/String;Lx2/s;ZZZLe3/s;ZLay0/k;Lay0/a;Ljava/lang/String;Lx2/s;Ll2/o;III)V

    .line 180
    .line 181
    .line 182
    goto :goto_8

    .line 183
    :cond_b
    move-object/from16 v20, v0

    .line 184
    .line 185
    invoke-virtual/range {v20 .. v20}, Ll2/t;->R()V

    .line 186
    .line 187
    .line 188
    :goto_8
    invoke-virtual/range {v20 .. v20}, Ll2/t;->s()Ll2/u1;

    .line 189
    .line 190
    .line 191
    move-result-object v7

    .line 192
    if-eqz v7, :cond_c

    .line 193
    .line 194
    new-instance v0, Luz/d;

    .line 195
    .line 196
    move-object/from16 v2, p1

    .line 197
    .line 198
    invoke-direct/range {v0 .. v6}, Luz/d;-><init>(Ltz/i;Lay0/a;Lay0/a;Lay0/a;Lx2/s;I)V

    .line 199
    .line 200
    .line 201
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 202
    .line 203
    :cond_c
    return-void
.end method

.method public static final f(Ltz/i;Ll2/o;I)V
    .locals 34

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v5, p1

    .line 4
    .line 5
    check-cast v5, Ll2/t;

    .line 6
    .line 7
    const v2, -0x6f22e5e8

    .line 8
    .line 9
    .line 10
    invoke-virtual {v5, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v5, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    const/4 v3, 0x2

    .line 18
    if-eqz v2, :cond_0

    .line 19
    .line 20
    const/4 v2, 0x4

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    move v2, v3

    .line 23
    :goto_0
    or-int v2, p2, v2

    .line 24
    .line 25
    and-int/lit8 v4, v2, 0x3

    .line 26
    .line 27
    const/4 v8, 0x1

    .line 28
    const/4 v9, 0x0

    .line 29
    if-eq v4, v3, :cond_1

    .line 30
    .line 31
    move v3, v8

    .line 32
    goto :goto_1

    .line 33
    :cond_1
    move v3, v9

    .line 34
    :goto_1
    and-int/2addr v2, v8

    .line 35
    invoke-virtual {v5, v2, v3}, Ll2/t;->O(IZ)Z

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    if-eqz v2, :cond_14

    .line 40
    .line 41
    sget v2, Luz/g;->a:F

    .line 42
    .line 43
    sget-object v10, Lx2/p;->b:Lx2/p;

    .line 44
    .line 45
    const/4 v3, 0x0

    .line 46
    invoke-static {v10, v3, v2, v8}, Landroidx/compose/foundation/layout/d;->b(Lx2/s;FFI)Lx2/s;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    sget-object v3, Lx2/c;->n:Lx2/i;

    .line 51
    .line 52
    sget-object v4, Lk1/j;->a:Lk1/c;

    .line 53
    .line 54
    const/16 v6, 0x30

    .line 55
    .line 56
    invoke-static {v4, v3, v5, v6}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 57
    .line 58
    .line 59
    move-result-object v3

    .line 60
    iget-wide v6, v5, Ll2/t;->T:J

    .line 61
    .line 62
    invoke-static {v6, v7}, Ljava/lang/Long;->hashCode(J)I

    .line 63
    .line 64
    .line 65
    move-result v4

    .line 66
    invoke-virtual {v5}, Ll2/t;->m()Ll2/p1;

    .line 67
    .line 68
    .line 69
    move-result-object v6

    .line 70
    invoke-static {v5, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 71
    .line 72
    .line 73
    move-result-object v2

    .line 74
    sget-object v7, Lv3/k;->m1:Lv3/j;

    .line 75
    .line 76
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 77
    .line 78
    .line 79
    sget-object v11, Lv3/j;->b:Lv3/i;

    .line 80
    .line 81
    invoke-virtual {v5}, Ll2/t;->c0()V

    .line 82
    .line 83
    .line 84
    iget-boolean v7, v5, Ll2/t;->S:Z

    .line 85
    .line 86
    if-eqz v7, :cond_2

    .line 87
    .line 88
    invoke-virtual {v5, v11}, Ll2/t;->l(Lay0/a;)V

    .line 89
    .line 90
    .line 91
    goto :goto_2

    .line 92
    :cond_2
    invoke-virtual {v5}, Ll2/t;->m0()V

    .line 93
    .line 94
    .line 95
    :goto_2
    sget-object v12, Lv3/j;->g:Lv3/h;

    .line 96
    .line 97
    invoke-static {v12, v3, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 98
    .line 99
    .line 100
    sget-object v13, Lv3/j;->f:Lv3/h;

    .line 101
    .line 102
    invoke-static {v13, v6, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 103
    .line 104
    .line 105
    sget-object v14, Lv3/j;->j:Lv3/h;

    .line 106
    .line 107
    iget-boolean v3, v5, Ll2/t;->S:Z

    .line 108
    .line 109
    if-nez v3, :cond_3

    .line 110
    .line 111
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v3

    .line 115
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 116
    .line 117
    .line 118
    move-result-object v6

    .line 119
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 120
    .line 121
    .line 122
    move-result v3

    .line 123
    if-nez v3, :cond_4

    .line 124
    .line 125
    :cond_3
    invoke-static {v4, v5, v4, v14}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 126
    .line 127
    .line 128
    :cond_4
    sget-object v15, Lv3/j;->d:Lv3/h;

    .line 129
    .line 130
    invoke-static {v15, v2, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 131
    .line 132
    .line 133
    iget-object v2, v0, Ltz/i;->a:Ltz/g;

    .line 134
    .line 135
    iget-boolean v3, v0, Ltz/i;->j:Z

    .line 136
    .line 137
    iget-boolean v4, v0, Ltz/i;->c:Z

    .line 138
    .line 139
    instance-of v6, v2, Ltz/e;

    .line 140
    .line 141
    const/16 v24, 0x0

    .line 142
    .line 143
    if-eqz v6, :cond_5

    .line 144
    .line 145
    move-object v6, v2

    .line 146
    check-cast v6, Ltz/e;

    .line 147
    .line 148
    goto :goto_3

    .line 149
    :cond_5
    move-object/from16 v6, v24

    .line 150
    .line 151
    :goto_3
    if-nez v6, :cond_6

    .line 152
    .line 153
    const v6, 0x44283b92

    .line 154
    .line 155
    .line 156
    invoke-virtual {v5, v6}, Ll2/t;->Y(I)V

    .line 157
    .line 158
    .line 159
    invoke-virtual {v5, v9}, Ll2/t;->q(Z)V

    .line 160
    .line 161
    .line 162
    move-object v8, v2

    .line 163
    move/from16 v25, v3

    .line 164
    .line 165
    move/from16 v26, v4

    .line 166
    .line 167
    goto :goto_4

    .line 168
    :cond_6
    const v7, 0x44283b93

    .line 169
    .line 170
    .line 171
    invoke-virtual {v5, v7}, Ll2/t;->Y(I)V

    .line 172
    .line 173
    .line 174
    move v7, v3

    .line 175
    iget-boolean v3, v0, Ltz/i;->c:Z

    .line 176
    .line 177
    move/from16 v16, v4

    .line 178
    .line 179
    iget-boolean v4, v0, Ltz/i;->j:Z

    .line 180
    .line 181
    move-object/from16 v17, v2

    .line 182
    .line 183
    move-object v2, v6

    .line 184
    const/4 v6, 0x0

    .line 185
    move/from16 v18, v7

    .line 186
    .line 187
    const/4 v7, 0x0

    .line 188
    move/from16 v26, v16

    .line 189
    .line 190
    move-object/from16 v8, v17

    .line 191
    .line 192
    move/from16 v25, v18

    .line 193
    .line 194
    invoke-static/range {v2 .. v7}, Luz/g;->d(Ltz/e;ZZLl2/o;II)V

    .line 195
    .line 196
    .line 197
    invoke-virtual {v5, v9}, Ll2/t;->q(Z)V

    .line 198
    .line 199
    .line 200
    :goto_4
    const/high16 v2, 0x3f800000    # 1.0f

    .line 201
    .line 202
    invoke-static {v10, v2}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 203
    .line 204
    .line 205
    move-result-object v2

    .line 206
    sget-object v3, Lx2/c;->o:Lx2/i;

    .line 207
    .line 208
    sget-object v4, Lk1/j;->g:Lk1/f;

    .line 209
    .line 210
    const/16 v6, 0x36

    .line 211
    .line 212
    invoke-static {v4, v3, v5, v6}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 213
    .line 214
    .line 215
    move-result-object v3

    .line 216
    iget-wide v6, v5, Ll2/t;->T:J

    .line 217
    .line 218
    invoke-static {v6, v7}, Ljava/lang/Long;->hashCode(J)I

    .line 219
    .line 220
    .line 221
    move-result v4

    .line 222
    invoke-virtual {v5}, Ll2/t;->m()Ll2/p1;

    .line 223
    .line 224
    .line 225
    move-result-object v6

    .line 226
    invoke-static {v5, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 227
    .line 228
    .line 229
    move-result-object v2

    .line 230
    invoke-virtual {v5}, Ll2/t;->c0()V

    .line 231
    .line 232
    .line 233
    iget-boolean v7, v5, Ll2/t;->S:Z

    .line 234
    .line 235
    if-eqz v7, :cond_7

    .line 236
    .line 237
    invoke-virtual {v5, v11}, Ll2/t;->l(Lay0/a;)V

    .line 238
    .line 239
    .line 240
    goto :goto_5

    .line 241
    :cond_7
    invoke-virtual {v5}, Ll2/t;->m0()V

    .line 242
    .line 243
    .line 244
    :goto_5
    invoke-static {v12, v3, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 245
    .line 246
    .line 247
    invoke-static {v13, v6, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 248
    .line 249
    .line 250
    iget-boolean v3, v5, Ll2/t;->S:Z

    .line 251
    .line 252
    if-nez v3, :cond_8

    .line 253
    .line 254
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    move-result-object v3

    .line 258
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 259
    .line 260
    .line 261
    move-result-object v6

    .line 262
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 263
    .line 264
    .line 265
    move-result v3

    .line 266
    if-nez v3, :cond_9

    .line 267
    .line 268
    :cond_8
    invoke-static {v4, v5, v4, v14}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 269
    .line 270
    .line 271
    :cond_9
    invoke-static {v15, v2, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 272
    .line 273
    .line 274
    instance-of v2, v8, Ltz/e;

    .line 275
    .line 276
    if-eqz v2, :cond_a

    .line 277
    .line 278
    move-object v3, v8

    .line 279
    check-cast v3, Ltz/e;

    .line 280
    .line 281
    goto :goto_6

    .line 282
    :cond_a
    move-object/from16 v3, v24

    .line 283
    .line 284
    :goto_6
    if-eqz v3, :cond_b

    .line 285
    .line 286
    iget-object v3, v3, Ltz/e;->a:Ljava/lang/String;

    .line 287
    .line 288
    goto :goto_7

    .line 289
    :cond_b
    move-object/from16 v3, v24

    .line 290
    .line 291
    :goto_7
    if-nez v3, :cond_c

    .line 292
    .line 293
    const v3, 0x3241d850

    .line 294
    .line 295
    .line 296
    const v4, 0x7f1202bd

    .line 297
    .line 298
    .line 299
    invoke-static {v3, v4, v5, v5, v9}, Lvj/b;->g(IILl2/t;Ll2/t;Z)Ljava/lang/String;

    .line 300
    .line 301
    .line 302
    move-result-object v3

    .line 303
    goto :goto_8

    .line 304
    :cond_c
    const v4, 0x3241d223

    .line 305
    .line 306
    .line 307
    invoke-virtual {v5, v4}, Ll2/t;->Y(I)V

    .line 308
    .line 309
    .line 310
    invoke-virtual {v5, v9}, Ll2/t;->q(Z)V

    .line 311
    .line 312
    .line 313
    :goto_8
    if-nez v26, :cond_e

    .line 314
    .line 315
    if-eqz v25, :cond_d

    .line 316
    .line 317
    goto :goto_a

    .line 318
    :cond_d
    const v4, 0x3241ed8b

    .line 319
    .line 320
    .line 321
    invoke-virtual {v5, v4}, Ll2/t;->Y(I)V

    .line 322
    .line 323
    .line 324
    sget-object v4, Lj91/h;->a:Ll2/u2;

    .line 325
    .line 326
    invoke-virtual {v5, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 327
    .line 328
    .line 329
    move-result-object v4

    .line 330
    check-cast v4, Lj91/e;

    .line 331
    .line 332
    invoke-virtual {v4}, Lj91/e;->q()J

    .line 333
    .line 334
    .line 335
    move-result-wide v6

    .line 336
    :goto_9
    invoke-virtual {v5, v9}, Ll2/t;->q(Z)V

    .line 337
    .line 338
    .line 339
    goto :goto_b

    .line 340
    :cond_e
    :goto_a
    const v4, 0x3241e92c

    .line 341
    .line 342
    .line 343
    invoke-virtual {v5, v4}, Ll2/t;->Y(I)V

    .line 344
    .line 345
    .line 346
    sget-object v4, Lj91/h;->a:Ll2/u2;

    .line 347
    .line 348
    invoke-virtual {v5, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 349
    .line 350
    .line 351
    move-result-object v4

    .line 352
    check-cast v4, Lj91/e;

    .line 353
    .line 354
    invoke-virtual {v4}, Lj91/e;->e()J

    .line 355
    .line 356
    .line 357
    move-result-wide v6

    .line 358
    goto :goto_9

    .line 359
    :goto_b
    sget-object v4, Lj91/j;->a:Ll2/u2;

    .line 360
    .line 361
    invoke-virtual {v5, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 362
    .line 363
    .line 364
    move-result-object v8

    .line 365
    check-cast v8, Lj91/f;

    .line 366
    .line 367
    invoke-virtual {v8}, Lj91/f;->k()Lg4/p0;

    .line 368
    .line 369
    .line 370
    move-result-object v8

    .line 371
    sget-object v11, Lj91/a;->a:Ll2/u2;

    .line 372
    .line 373
    invoke-virtual {v5, v11}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 374
    .line 375
    .line 376
    move-result-object v11

    .line 377
    check-cast v11, Lj91/c;

    .line 378
    .line 379
    iget v13, v11, Lj91/c;->c:F

    .line 380
    .line 381
    const/4 v14, 0x0

    .line 382
    const/16 v15, 0xb

    .line 383
    .line 384
    const/4 v11, 0x0

    .line 385
    const/4 v12, 0x0

    .line 386
    invoke-static/range {v10 .. v15}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 387
    .line 388
    .line 389
    move-result-object v11

    .line 390
    const-string v12, "battery_charging_card_battery_state"

    .line 391
    .line 392
    invoke-static {v11, v12}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 393
    .line 394
    .line 395
    move-result-object v11

    .line 396
    const/16 v22, 0x6000

    .line 397
    .line 398
    const v23, 0xbff0

    .line 399
    .line 400
    .line 401
    move v12, v2

    .line 402
    move-object v2, v3

    .line 403
    move-object/from16 v20, v5

    .line 404
    .line 405
    move-wide v5, v6

    .line 406
    move-object v3, v8

    .line 407
    const-wide/16 v7, 0x0

    .line 408
    .line 409
    move v13, v9

    .line 410
    const/4 v9, 0x0

    .line 411
    move-object v14, v4

    .line 412
    move-object v15, v10

    .line 413
    move-object v4, v11

    .line 414
    const-wide/16 v10, 0x0

    .line 415
    .line 416
    move/from16 v16, v12

    .line 417
    .line 418
    const/4 v12, 0x0

    .line 419
    move/from16 v17, v13

    .line 420
    .line 421
    const/4 v13, 0x0

    .line 422
    move-object/from16 v18, v14

    .line 423
    .line 424
    move-object/from16 v19, v15

    .line 425
    .line 426
    const-wide/16 v14, 0x0

    .line 427
    .line 428
    move/from16 v21, v16

    .line 429
    .line 430
    const/16 v16, 0x0

    .line 431
    .line 432
    move/from16 v27, v17

    .line 433
    .line 434
    const/16 v17, 0x0

    .line 435
    .line 436
    move-object/from16 v28, v18

    .line 437
    .line 438
    const/16 v18, 0x1

    .line 439
    .line 440
    move-object/from16 v29, v19

    .line 441
    .line 442
    const/16 v19, 0x0

    .line 443
    .line 444
    move/from16 v30, v21

    .line 445
    .line 446
    const/16 v21, 0x0

    .line 447
    .line 448
    move/from16 v1, v27

    .line 449
    .line 450
    move-object/from16 v31, v29

    .line 451
    .line 452
    invoke-static/range {v2 .. v23}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 453
    .line 454
    .line 455
    move-object/from16 v5, v20

    .line 456
    .line 457
    if-eqz v26, :cond_11

    .line 458
    .line 459
    iget-boolean v2, v0, Ltz/i;->t:Z

    .line 460
    .line 461
    if-nez v2, :cond_11

    .line 462
    .line 463
    const v2, 0x16026ee6

    .line 464
    .line 465
    .line 466
    invoke-virtual {v5, v2}, Ll2/t;->Y(I)V

    .line 467
    .line 468
    .line 469
    iget-object v3, v0, Ltz/i;->f:Ltz/h;

    .line 470
    .line 471
    if-eqz v3, :cond_f

    .line 472
    .line 473
    iget-object v3, v3, Ltz/h;->b:Ljava/lang/String;

    .line 474
    .line 475
    move-object/from16 v24, v3

    .line 476
    .line 477
    :cond_f
    if-nez v24, :cond_10

    .line 478
    .line 479
    const v2, 0x16026ee5

    .line 480
    .line 481
    .line 482
    invoke-virtual {v5, v2}, Ll2/t;->Y(I)V

    .line 483
    .line 484
    .line 485
    :goto_c
    invoke-virtual {v5, v1}, Ll2/t;->q(Z)V

    .line 486
    .line 487
    .line 488
    goto :goto_d

    .line 489
    :cond_10
    invoke-virtual {v5, v2}, Ll2/t;->Y(I)V

    .line 490
    .line 491
    .line 492
    const v2, 0x7f12041c

    .line 493
    .line 494
    .line 495
    filled-new-array/range {v24 .. v24}, [Ljava/lang/Object;

    .line 496
    .line 497
    .line 498
    move-result-object v3

    .line 499
    invoke-static {v2, v3, v5}, Ljp/ga;->c(I[Ljava/lang/Object;Ll2/o;)Ljava/lang/String;

    .line 500
    .line 501
    .line 502
    move-result-object v2

    .line 503
    move-object/from16 v14, v28

    .line 504
    .line 505
    invoke-virtual {v5, v14}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 506
    .line 507
    .line 508
    move-result-object v3

    .line 509
    check-cast v3, Lj91/f;

    .line 510
    .line 511
    invoke-virtual {v3}, Lj91/f;->m()Lg4/p0;

    .line 512
    .line 513
    .line 514
    move-result-object v3

    .line 515
    const-string v4, "battery_charging_card_time"

    .line 516
    .line 517
    move-object/from16 v10, v31

    .line 518
    .line 519
    invoke-static {v10, v4}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 520
    .line 521
    .line 522
    move-result-object v4

    .line 523
    const/16 v22, 0x6180

    .line 524
    .line 525
    const v23, 0xaff8

    .line 526
    .line 527
    .line 528
    move-object/from16 v20, v5

    .line 529
    .line 530
    const-wide/16 v5, 0x0

    .line 531
    .line 532
    const-wide/16 v7, 0x0

    .line 533
    .line 534
    const/4 v9, 0x0

    .line 535
    const-wide/16 v10, 0x0

    .line 536
    .line 537
    const/4 v12, 0x0

    .line 538
    const/4 v13, 0x0

    .line 539
    const-wide/16 v14, 0x0

    .line 540
    .line 541
    const/16 v16, 0x2

    .line 542
    .line 543
    const/16 v17, 0x0

    .line 544
    .line 545
    const/16 v18, 0x1

    .line 546
    .line 547
    const/16 v19, 0x0

    .line 548
    .line 549
    const/16 v21, 0x180

    .line 550
    .line 551
    invoke-static/range {v2 .. v23}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 552
    .line 553
    .line 554
    move-object/from16 v5, v20

    .line 555
    .line 556
    goto :goto_c

    .line 557
    :goto_d
    invoke-virtual {v5, v1}, Ll2/t;->q(Z)V

    .line 558
    .line 559
    .line 560
    :goto_e
    const/4 v1, 0x1

    .line 561
    goto/16 :goto_10

    .line 562
    .line 563
    :cond_11
    move-object/from16 v14, v28

    .line 564
    .line 565
    move-object/from16 v10, v31

    .line 566
    .line 567
    if-eqz v25, :cond_12

    .line 568
    .line 569
    const v2, 0x1609e0ea

    .line 570
    .line 571
    .line 572
    invoke-virtual {v5, v2}, Ll2/t;->Y(I)V

    .line 573
    .line 574
    .line 575
    invoke-virtual {v5, v1}, Ll2/t;->q(Z)V

    .line 576
    .line 577
    .line 578
    goto :goto_e

    .line 579
    :cond_12
    const v2, 0x160c2912

    .line 580
    .line 581
    .line 582
    invoke-virtual {v5, v2}, Ll2/t;->Y(I)V

    .line 583
    .line 584
    .line 585
    iget-object v2, v0, Ltz/i;->b:Ljava/lang/String;

    .line 586
    .line 587
    if-eqz v30, :cond_13

    .line 588
    .line 589
    const v3, 0x3242898d

    .line 590
    .line 591
    .line 592
    invoke-virtual {v5, v3}, Ll2/t;->Y(I)V

    .line 593
    .line 594
    .line 595
    sget-object v3, Lj91/h;->a:Ll2/u2;

    .line 596
    .line 597
    invoke-virtual {v5, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 598
    .line 599
    .line 600
    move-result-object v3

    .line 601
    check-cast v3, Lj91/e;

    .line 602
    .line 603
    invoke-virtual {v3}, Lj91/e;->s()J

    .line 604
    .line 605
    .line 606
    move-result-wide v3

    .line 607
    invoke-virtual {v5, v1}, Ll2/t;->q(Z)V

    .line 608
    .line 609
    .line 610
    goto :goto_f

    .line 611
    :cond_13
    const v3, 0x3242948e

    .line 612
    .line 613
    .line 614
    invoke-virtual {v5, v3}, Ll2/t;->Y(I)V

    .line 615
    .line 616
    .line 617
    sget-object v3, Lj91/h;->a:Ll2/u2;

    .line 618
    .line 619
    invoke-virtual {v5, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 620
    .line 621
    .line 622
    move-result-object v3

    .line 623
    check-cast v3, Lj91/e;

    .line 624
    .line 625
    invoke-virtual {v3}, Lj91/e;->r()J

    .line 626
    .line 627
    .line 628
    move-result-wide v3

    .line 629
    invoke-virtual {v5, v1}, Ll2/t;->q(Z)V

    .line 630
    .line 631
    .line 632
    :goto_f
    invoke-virtual {v5, v14}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 633
    .line 634
    .line 635
    move-result-object v6

    .line 636
    check-cast v6, Lj91/f;

    .line 637
    .line 638
    invoke-virtual {v6}, Lj91/f;->e()Lg4/p0;

    .line 639
    .line 640
    .line 641
    move-result-object v6

    .line 642
    const-string v7, "battery_charging_card_charging_state"

    .line 643
    .line 644
    invoke-static {v10, v7}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 645
    .line 646
    .line 647
    move-result-object v7

    .line 648
    const/16 v22, 0x6180

    .line 649
    .line 650
    const v23, 0xaff0

    .line 651
    .line 652
    .line 653
    move-object/from16 v20, v5

    .line 654
    .line 655
    move-wide/from16 v32, v3

    .line 656
    .line 657
    move-object v3, v6

    .line 658
    move-wide/from16 v5, v32

    .line 659
    .line 660
    move-object v4, v7

    .line 661
    const-wide/16 v7, 0x0

    .line 662
    .line 663
    const/4 v9, 0x0

    .line 664
    const-wide/16 v10, 0x0

    .line 665
    .line 666
    const/4 v12, 0x0

    .line 667
    const/4 v13, 0x0

    .line 668
    const-wide/16 v14, 0x0

    .line 669
    .line 670
    const/16 v16, 0x2

    .line 671
    .line 672
    const/16 v17, 0x0

    .line 673
    .line 674
    const/16 v18, 0x1

    .line 675
    .line 676
    const/16 v19, 0x0

    .line 677
    .line 678
    const/16 v21, 0x180

    .line 679
    .line 680
    invoke-static/range {v2 .. v23}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 681
    .line 682
    .line 683
    move-object/from16 v5, v20

    .line 684
    .line 685
    invoke-virtual {v5, v1}, Ll2/t;->q(Z)V

    .line 686
    .line 687
    .line 688
    goto/16 :goto_e

    .line 689
    .line 690
    :goto_10
    invoke-virtual {v5, v1}, Ll2/t;->q(Z)V

    .line 691
    .line 692
    .line 693
    invoke-virtual {v5, v1}, Ll2/t;->q(Z)V

    .line 694
    .line 695
    .line 696
    goto :goto_11

    .line 697
    :cond_14
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 698
    .line 699
    .line 700
    :goto_11
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 701
    .line 702
    .line 703
    move-result-object v1

    .line 704
    if-eqz v1, :cond_15

    .line 705
    .line 706
    new-instance v2, Luz/a;

    .line 707
    .line 708
    const/4 v3, 0x0

    .line 709
    move/from16 v4, p2

    .line 710
    .line 711
    invoke-direct {v2, v0, v4, v3}, Luz/a;-><init>(Ltz/i;II)V

    .line 712
    .line 713
    .line 714
    iput-object v2, v1, Ll2/u1;->d:Lay0/n;

    .line 715
    .line 716
    :cond_15
    return-void
.end method

.method public static final g(Ltz/i;Ljava/lang/String;Ll2/o;I)V
    .locals 41

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v12, p2

    .line 6
    .line 7
    check-cast v12, Ll2/t;

    .line 8
    .line 9
    const v1, -0x27f19041

    .line 10
    .line 11
    .line 12
    invoke-virtual {v12, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v12, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    const/4 v1, 0x4

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    const/4 v1, 0x2

    .line 24
    :goto_0
    or-int v1, p3, v1

    .line 25
    .line 26
    invoke-virtual {v12, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    if-eqz v3, :cond_1

    .line 31
    .line 32
    const/16 v3, 0x20

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_1
    const/16 v3, 0x10

    .line 36
    .line 37
    :goto_1
    or-int/2addr v1, v3

    .line 38
    and-int/lit8 v3, v1, 0x13

    .line 39
    .line 40
    const/16 v4, 0x12

    .line 41
    .line 42
    const/4 v5, 0x1

    .line 43
    const/4 v6, 0x0

    .line 44
    if-eq v3, v4, :cond_2

    .line 45
    .line 46
    move v3, v5

    .line 47
    goto :goto_2

    .line 48
    :cond_2
    move v3, v6

    .line 49
    :goto_2
    and-int/2addr v1, v5

    .line 50
    invoke-virtual {v12, v1, v3}, Ll2/t;->O(IZ)Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-eqz v1, :cond_c

    .line 55
    .line 56
    iget-boolean v1, v0, Ltz/i;->c:Z

    .line 57
    .line 58
    if-nez v1, :cond_4

    .line 59
    .line 60
    iget-boolean v1, v0, Ltz/i;->j:Z

    .line 61
    .line 62
    if-eqz v1, :cond_3

    .line 63
    .line 64
    goto :goto_3

    .line 65
    :cond_3
    const v1, -0x494a739d

    .line 66
    .line 67
    .line 68
    invoke-virtual {v12, v1}, Ll2/t;->Y(I)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {v12, v6}, Ll2/t;->q(Z)V

    .line 72
    .line 73
    .line 74
    move v1, v5

    .line 75
    goto/16 :goto_c

    .line 76
    .line 77
    :cond_4
    :goto_3
    const v1, -0x47fed1a2

    .line 78
    .line 79
    .line 80
    invoke-virtual {v12, v1}, Ll2/t;->Y(I)V

    .line 81
    .line 82
    .line 83
    invoke-static {v12}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 84
    .line 85
    .line 86
    move-result-object v1

    .line 87
    iget v1, v1, Lj91/c;->d:F

    .line 88
    .line 89
    const/16 v20, 0x0

    .line 90
    .line 91
    const/16 v21, 0xd

    .line 92
    .line 93
    sget-object v16, Lx2/p;->b:Lx2/p;

    .line 94
    .line 95
    const/16 v17, 0x0

    .line 96
    .line 97
    const/16 v19, 0x0

    .line 98
    .line 99
    move/from16 v18, v1

    .line 100
    .line 101
    invoke-static/range {v16 .. v21}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    const/high16 v3, 0x3f800000    # 1.0f

    .line 106
    .line 107
    invoke-static {v1, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 108
    .line 109
    .line 110
    move-result-object v1

    .line 111
    sget-object v3, Lk1/r0;->d:Lk1/r0;

    .line 112
    .line 113
    invoke-static {v1, v3}, Landroidx/compose/foundation/layout/a;->g(Lx2/s;Lk1/r0;)Lx2/s;

    .line 114
    .line 115
    .line 116
    move-result-object v1

    .line 117
    sget-object v3, Lk1/j;->a:Lk1/c;

    .line 118
    .line 119
    invoke-static {v12}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 120
    .line 121
    .line 122
    move-result-object v3

    .line 123
    iget v3, v3, Lj91/c;->d:F

    .line 124
    .line 125
    invoke-static {v3}, Lk1/j;->g(F)Lk1/h;

    .line 126
    .line 127
    .line 128
    move-result-object v3

    .line 129
    sget-object v4, Lx2/c;->n:Lx2/i;

    .line 130
    .line 131
    const/16 v7, 0x30

    .line 132
    .line 133
    invoke-static {v3, v4, v12, v7}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 134
    .line 135
    .line 136
    move-result-object v3

    .line 137
    iget-wide v7, v12, Ll2/t;->T:J

    .line 138
    .line 139
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 140
    .line 141
    .line 142
    move-result v4

    .line 143
    invoke-virtual {v12}, Ll2/t;->m()Ll2/p1;

    .line 144
    .line 145
    .line 146
    move-result-object v7

    .line 147
    invoke-static {v12, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 148
    .line 149
    .line 150
    move-result-object v1

    .line 151
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 152
    .line 153
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 154
    .line 155
    .line 156
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 157
    .line 158
    invoke-virtual {v12}, Ll2/t;->c0()V

    .line 159
    .line 160
    .line 161
    iget-boolean v9, v12, Ll2/t;->S:Z

    .line 162
    .line 163
    if-eqz v9, :cond_5

    .line 164
    .line 165
    invoke-virtual {v12, v8}, Ll2/t;->l(Lay0/a;)V

    .line 166
    .line 167
    .line 168
    goto :goto_4

    .line 169
    :cond_5
    invoke-virtual {v12}, Ll2/t;->m0()V

    .line 170
    .line 171
    .line 172
    :goto_4
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 173
    .line 174
    invoke-static {v8, v3, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 175
    .line 176
    .line 177
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 178
    .line 179
    invoke-static {v3, v7, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 180
    .line 181
    .line 182
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 183
    .line 184
    iget-boolean v7, v12, Ll2/t;->S:Z

    .line 185
    .line 186
    if-nez v7, :cond_6

    .line 187
    .line 188
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 189
    .line 190
    .line 191
    move-result-object v7

    .line 192
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 193
    .line 194
    .line 195
    move-result-object v8

    .line 196
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 197
    .line 198
    .line 199
    move-result v7

    .line 200
    if-nez v7, :cond_7

    .line 201
    .line 202
    :cond_6
    invoke-static {v4, v12, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 203
    .line 204
    .line 205
    :cond_7
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 206
    .line 207
    invoke-static {v3, v1, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 208
    .line 209
    .line 210
    if-nez v2, :cond_8

    .line 211
    .line 212
    const v1, 0x12a07c8c

    .line 213
    .line 214
    .line 215
    invoke-virtual {v12, v1}, Ll2/t;->Y(I)V

    .line 216
    .line 217
    .line 218
    invoke-virtual {v12, v6}, Ll2/t;->q(Z)V

    .line 219
    .line 220
    .line 221
    move v15, v6

    .line 222
    move-object/from16 v38, v16

    .line 223
    .line 224
    goto :goto_5

    .line 225
    :cond_8
    const v1, 0x12a07c8d

    .line 226
    .line 227
    .line 228
    invoke-virtual {v12, v1}, Ll2/t;->Y(I)V

    .line 229
    .line 230
    .line 231
    invoke-static {v12}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 232
    .line 233
    .line 234
    move-result-object v1

    .line 235
    invoke-virtual {v1}, Lj91/e;->t()J

    .line 236
    .line 237
    .line 238
    move-result-wide v3

    .line 239
    invoke-static {v12}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 240
    .line 241
    .line 242
    move-result-object v1

    .line 243
    invoke-virtual {v1}, Lj91/f;->e()Lg4/p0;

    .line 244
    .line 245
    .line 246
    move-result-object v8

    .line 247
    invoke-static {v12}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 248
    .line 249
    .line 250
    move-result-object v1

    .line 251
    invoke-virtual {v1}, Lj91/e;->s()J

    .line 252
    .line 253
    .line 254
    move-result-wide v9

    .line 255
    const/16 v13, 0xd80

    .line 256
    .line 257
    const/16 v14, 0x101

    .line 258
    .line 259
    const/4 v1, 0x0

    .line 260
    move-wide/from16 v39, v3

    .line 261
    .line 262
    move v4, v6

    .line 263
    move-wide/from16 v6, v39

    .line 264
    .line 265
    const-string v3, "battery_charging_card_limit_text"

    .line 266
    .line 267
    move v11, v4

    .line 268
    const-string v4, "battery_charging_card_limit_icon"

    .line 269
    .line 270
    move/from16 v17, v5

    .line 271
    .line 272
    const v5, 0x7f0802d5

    .line 273
    .line 274
    .line 275
    move/from16 v18, v11

    .line 276
    .line 277
    const/4 v11, 0x0

    .line 278
    move-object/from16 v38, v16

    .line 279
    .line 280
    move/from16 v15, v18

    .line 281
    .line 282
    invoke-static/range {v1 .. v14}, Luz/g;->k(Lx2/s;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;IJLg4/p0;JILl2/o;II)V

    .line 283
    .line 284
    .line 285
    invoke-static {v12, v15}, Luz/g;->j(Ll2/o;I)V

    .line 286
    .line 287
    .line 288
    invoke-virtual {v12, v15}, Ll2/t;->q(Z)V

    .line 289
    .line 290
    .line 291
    :goto_5
    iget-boolean v1, v0, Ltz/i;->c:Z

    .line 292
    .line 293
    if-eqz v1, :cond_9

    .line 294
    .line 295
    const v1, 0x12a96be4

    .line 296
    .line 297
    .line 298
    const v3, 0x7f120445

    .line 299
    .line 300
    .line 301
    invoke-static {v1, v3, v12, v12, v15}, Lvj/b;->g(IILl2/t;Ll2/t;Z)Ljava/lang/String;

    .line 302
    .line 303
    .line 304
    move-result-object v1

    .line 305
    :goto_6
    move-object/from16 v16, v1

    .line 306
    .line 307
    goto :goto_7

    .line 308
    :cond_9
    const v1, 0x12aaf781

    .line 309
    .line 310
    .line 311
    const v3, 0x7f120448

    .line 312
    .line 313
    .line 314
    invoke-static {v1, v3, v12, v12, v15}, Lvj/b;->g(IILl2/t;Ll2/t;Z)Ljava/lang/String;

    .line 315
    .line 316
    .line 317
    move-result-object v1

    .line 318
    goto :goto_6

    .line 319
    :goto_7
    invoke-static {v12}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 320
    .line 321
    .line 322
    move-result-object v1

    .line 323
    invoke-virtual {v1}, Lj91/f;->e()Lg4/p0;

    .line 324
    .line 325
    .line 326
    move-result-object v17

    .line 327
    invoke-static {v12}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 328
    .line 329
    .line 330
    move-result-object v1

    .line 331
    invoke-virtual {v1}, Lj91/e;->s()J

    .line 332
    .line 333
    .line 334
    move-result-wide v19

    .line 335
    const-string v1, "battery_bi_di_card_charging_type"

    .line 336
    .line 337
    move-object/from16 v3, v38

    .line 338
    .line 339
    invoke-static {v3, v1}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 340
    .line 341
    .line 342
    move-result-object v18

    .line 343
    const/16 v36, 0x0

    .line 344
    .line 345
    const v37, 0xfff0

    .line 346
    .line 347
    .line 348
    const-wide/16 v21, 0x0

    .line 349
    .line 350
    const/16 v23, 0x0

    .line 351
    .line 352
    const-wide/16 v24, 0x0

    .line 353
    .line 354
    const/16 v26, 0x0

    .line 355
    .line 356
    const/16 v27, 0x0

    .line 357
    .line 358
    const-wide/16 v28, 0x0

    .line 359
    .line 360
    const/16 v30, 0x0

    .line 361
    .line 362
    const/16 v31, 0x0

    .line 363
    .line 364
    const/16 v32, 0x0

    .line 365
    .line 366
    const/16 v33, 0x0

    .line 367
    .line 368
    const/16 v35, 0x180

    .line 369
    .line 370
    move-object/from16 v34, v12

    .line 371
    .line 372
    invoke-static/range {v16 .. v37}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 373
    .line 374
    .line 375
    iget-object v1, v0, Ltz/i;->f:Ltz/h;

    .line 376
    .line 377
    if-eqz v1, :cond_a

    .line 378
    .line 379
    iget-object v1, v1, Ltz/h;->f:Ljava/lang/String;

    .line 380
    .line 381
    :goto_8
    move-object/from16 v16, v1

    .line 382
    .line 383
    goto :goto_9

    .line 384
    :cond_a
    const/4 v1, 0x0

    .line 385
    goto :goto_8

    .line 386
    :goto_9
    if-nez v16, :cond_b

    .line 387
    .line 388
    const v1, 0x12b05e64

    .line 389
    .line 390
    .line 391
    invoke-virtual {v12, v1}, Ll2/t;->Y(I)V

    .line 392
    .line 393
    .line 394
    :goto_a
    invoke-virtual {v12, v15}, Ll2/t;->q(Z)V

    .line 395
    .line 396
    .line 397
    const/4 v1, 0x1

    .line 398
    goto :goto_b

    .line 399
    :cond_b
    const v1, 0x12b05e65

    .line 400
    .line 401
    .line 402
    invoke-virtual {v12, v1}, Ll2/t;->Y(I)V

    .line 403
    .line 404
    .line 405
    invoke-static {v12, v15}, Luz/g;->j(Ll2/o;I)V

    .line 406
    .line 407
    .line 408
    invoke-static {v12}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 409
    .line 410
    .line 411
    move-result-object v1

    .line 412
    invoke-virtual {v1}, Lj91/e;->s()J

    .line 413
    .line 414
    .line 415
    move-result-wide v19

    .line 416
    invoke-static {v12}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 417
    .line 418
    .line 419
    move-result-object v1

    .line 420
    invoke-virtual {v1}, Lj91/f;->e()Lg4/p0;

    .line 421
    .line 422
    .line 423
    move-result-object v17

    .line 424
    const-string v1, "battery_bi_di_charging_card_power"

    .line 425
    .line 426
    invoke-static {v3, v1}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 427
    .line 428
    .line 429
    move-result-object v18

    .line 430
    const/16 v36, 0x0

    .line 431
    .line 432
    const v37, 0xfff0

    .line 433
    .line 434
    .line 435
    const-wide/16 v21, 0x0

    .line 436
    .line 437
    const/16 v23, 0x0

    .line 438
    .line 439
    const-wide/16 v24, 0x0

    .line 440
    .line 441
    const/16 v26, 0x0

    .line 442
    .line 443
    const/16 v27, 0x0

    .line 444
    .line 445
    const-wide/16 v28, 0x0

    .line 446
    .line 447
    const/16 v30, 0x0

    .line 448
    .line 449
    const/16 v31, 0x0

    .line 450
    .line 451
    const/16 v32, 0x0

    .line 452
    .line 453
    const/16 v33, 0x0

    .line 454
    .line 455
    const/16 v35, 0x180

    .line 456
    .line 457
    move-object/from16 v34, v12

    .line 458
    .line 459
    invoke-static/range {v16 .. v37}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 460
    .line 461
    .line 462
    goto :goto_a

    .line 463
    :goto_b
    invoke-virtual {v12, v1}, Ll2/t;->q(Z)V

    .line 464
    .line 465
    .line 466
    invoke-virtual {v12, v15}, Ll2/t;->q(Z)V

    .line 467
    .line 468
    .line 469
    goto :goto_c

    .line 470
    :cond_c
    move v1, v5

    .line 471
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 472
    .line 473
    .line 474
    :goto_c
    invoke-virtual {v12}, Ll2/t;->s()Ll2/u1;

    .line 475
    .line 476
    .line 477
    move-result-object v3

    .line 478
    if-eqz v3, :cond_d

    .line 479
    .line 480
    new-instance v4, Luu/q0;

    .line 481
    .line 482
    move/from16 v15, p3

    .line 483
    .line 484
    invoke-direct {v4, v15, v1, v0, v2}, Luu/q0;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 485
    .line 486
    .line 487
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 488
    .line 489
    :cond_d
    return-void
.end method

.method public static final h(Ltz/i;Lay0/a;Lay0/a;Ll2/o;I)V
    .locals 22

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v9, p3

    .line 4
    .line 5
    check-cast v9, Ll2/t;

    .line 6
    .line 7
    const v0, 0xce6d0cb

    .line 8
    .line 9
    .line 10
    invoke-virtual {v9, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v9, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

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
    or-int v0, p4, v0

    .line 23
    .line 24
    move-object/from16 v13, p1

    .line 25
    .line 26
    invoke-virtual {v9, v13}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    if-eqz v2, :cond_1

    .line 31
    .line 32
    const/16 v2, 0x20

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_1
    const/16 v2, 0x10

    .line 36
    .line 37
    :goto_1
    or-int/2addr v0, v2

    .line 38
    move-object/from16 v14, p2

    .line 39
    .line 40
    invoke-virtual {v9, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    if-eqz v2, :cond_2

    .line 45
    .line 46
    const/16 v2, 0x100

    .line 47
    .line 48
    goto :goto_2

    .line 49
    :cond_2
    const/16 v2, 0x80

    .line 50
    .line 51
    :goto_2
    or-int/2addr v0, v2

    .line 52
    and-int/lit16 v2, v0, 0x93

    .line 53
    .line 54
    const/16 v3, 0x92

    .line 55
    .line 56
    const/4 v4, 0x0

    .line 57
    if-eq v2, v3, :cond_3

    .line 58
    .line 59
    const/4 v2, 0x1

    .line 60
    goto :goto_3

    .line 61
    :cond_3
    move v2, v4

    .line 62
    :goto_3
    and-int/lit8 v3, v0, 0x1

    .line 63
    .line 64
    invoke-virtual {v9, v3, v2}, Ll2/t;->O(IZ)Z

    .line 65
    .line 66
    .line 67
    move-result v2

    .line 68
    if-eqz v2, :cond_11

    .line 69
    .line 70
    sget-object v2, Lk1/j;->c:Lk1/e;

    .line 71
    .line 72
    sget-object v3, Lx2/c;->p:Lx2/h;

    .line 73
    .line 74
    invoke-static {v2, v3, v9, v4}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 75
    .line 76
    .line 77
    move-result-object v2

    .line 78
    iget-wide v5, v9, Ll2/t;->T:J

    .line 79
    .line 80
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 81
    .line 82
    .line 83
    move-result v3

    .line 84
    invoke-virtual {v9}, Ll2/t;->m()Ll2/p1;

    .line 85
    .line 86
    .line 87
    move-result-object v5

    .line 88
    sget-object v6, Lx2/p;->b:Lx2/p;

    .line 89
    .line 90
    invoke-static {v9, v6}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 91
    .line 92
    .line 93
    move-result-object v7

    .line 94
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 95
    .line 96
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 97
    .line 98
    .line 99
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 100
    .line 101
    invoke-virtual {v9}, Ll2/t;->c0()V

    .line 102
    .line 103
    .line 104
    iget-boolean v10, v9, Ll2/t;->S:Z

    .line 105
    .line 106
    if-eqz v10, :cond_4

    .line 107
    .line 108
    invoke-virtual {v9, v8}, Ll2/t;->l(Lay0/a;)V

    .line 109
    .line 110
    .line 111
    goto :goto_4

    .line 112
    :cond_4
    invoke-virtual {v9}, Ll2/t;->m0()V

    .line 113
    .line 114
    .line 115
    :goto_4
    sget-object v10, Lv3/j;->g:Lv3/h;

    .line 116
    .line 117
    invoke-static {v10, v2, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 118
    .line 119
    .line 120
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 121
    .line 122
    invoke-static {v2, v5, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 123
    .line 124
    .line 125
    sget-object v5, Lv3/j;->j:Lv3/h;

    .line 126
    .line 127
    iget-boolean v11, v9, Ll2/t;->S:Z

    .line 128
    .line 129
    if-nez v11, :cond_5

    .line 130
    .line 131
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object v11

    .line 135
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 136
    .line 137
    .line 138
    move-result-object v12

    .line 139
    invoke-static {v11, v12}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 140
    .line 141
    .line 142
    move-result v11

    .line 143
    if-nez v11, :cond_6

    .line 144
    .line 145
    :cond_5
    invoke-static {v3, v9, v3, v5}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 146
    .line 147
    .line 148
    :cond_6
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 149
    .line 150
    invoke-static {v3, v7, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 151
    .line 152
    .line 153
    const/high16 v7, 0x3f800000    # 1.0f

    .line 154
    .line 155
    invoke-static {v6, v7}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 156
    .line 157
    .line 158
    move-result-object v7

    .line 159
    sget-object v11, Lx2/c;->n:Lx2/i;

    .line 160
    .line 161
    sget-object v12, Lk1/j;->g:Lk1/f;

    .line 162
    .line 163
    const/16 v4, 0x36

    .line 164
    .line 165
    invoke-static {v12, v11, v9, v4}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 166
    .line 167
    .line 168
    move-result-object v4

    .line 169
    iget-wide v11, v9, Ll2/t;->T:J

    .line 170
    .line 171
    invoke-static {v11, v12}, Ljava/lang/Long;->hashCode(J)I

    .line 172
    .line 173
    .line 174
    move-result v11

    .line 175
    invoke-virtual {v9}, Ll2/t;->m()Ll2/p1;

    .line 176
    .line 177
    .line 178
    move-result-object v12

    .line 179
    invoke-static {v9, v7}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 180
    .line 181
    .line 182
    move-result-object v7

    .line 183
    invoke-virtual {v9}, Ll2/t;->c0()V

    .line 184
    .line 185
    .line 186
    iget-boolean v15, v9, Ll2/t;->S:Z

    .line 187
    .line 188
    if-eqz v15, :cond_7

    .line 189
    .line 190
    invoke-virtual {v9, v8}, Ll2/t;->l(Lay0/a;)V

    .line 191
    .line 192
    .line 193
    goto :goto_5

    .line 194
    :cond_7
    invoke-virtual {v9}, Ll2/t;->m0()V

    .line 195
    .line 196
    .line 197
    :goto_5
    invoke-static {v10, v4, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 198
    .line 199
    .line 200
    invoke-static {v2, v12, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 201
    .line 202
    .line 203
    iget-boolean v2, v9, Ll2/t;->S:Z

    .line 204
    .line 205
    if-nez v2, :cond_8

    .line 206
    .line 207
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 208
    .line 209
    .line 210
    move-result-object v2

    .line 211
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 212
    .line 213
    .line 214
    move-result-object v4

    .line 215
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 216
    .line 217
    .line 218
    move-result v2

    .line 219
    if-nez v2, :cond_9

    .line 220
    .line 221
    :cond_8
    invoke-static {v11, v9, v11, v5}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 222
    .line 223
    .line 224
    :cond_9
    invoke-static {v3, v7, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 225
    .line 226
    .line 227
    and-int/lit8 v15, v0, 0xe

    .line 228
    .line 229
    invoke-static {v1, v9, v15}, Luz/g;->f(Ltz/i;Ll2/o;I)V

    .line 230
    .line 231
    .line 232
    const/4 v2, 0x1

    .line 233
    invoke-virtual {v9, v2}, Ll2/t;->q(Z)V

    .line 234
    .line 235
    .line 236
    iget-object v2, v1, Ltz/i;->f:Ltz/h;

    .line 237
    .line 238
    iget-boolean v3, v1, Ltz/i;->j:Z

    .line 239
    .line 240
    if-nez v2, :cond_a

    .line 241
    .line 242
    const v2, 0x5e5a85e

    .line 243
    .line 244
    .line 245
    invoke-virtual {v9, v2}, Ll2/t;->Y(I)V

    .line 246
    .line 247
    .line 248
    const/4 v4, 0x0

    .line 249
    invoke-virtual {v9, v4}, Ll2/t;->q(Z)V

    .line 250
    .line 251
    .line 252
    move/from16 p3, v0

    .line 253
    .line 254
    move/from16 v18, v3

    .line 255
    .line 256
    move-object v10, v9

    .line 257
    goto/16 :goto_a

    .line 258
    .line 259
    :cond_a
    const/4 v4, 0x0

    .line 260
    const v5, 0x5e5a85f

    .line 261
    .line 262
    .line 263
    invoke-virtual {v9, v5}, Ll2/t;->Y(I)V

    .line 264
    .line 265
    .line 266
    move v5, v3

    .line 267
    iget v3, v2, Ltz/h;->a:I

    .line 268
    .line 269
    move v7, v4

    .line 270
    iget-object v4, v2, Ltz/h;->c:Ljava/lang/Integer;

    .line 271
    .line 272
    move v8, v5

    .line 273
    iget-boolean v5, v1, Ltz/i;->c:Z

    .line 274
    .line 275
    move-object/from16 v16, v6

    .line 276
    .line 277
    iget-boolean v6, v1, Ltz/i;->j:Z

    .line 278
    .line 279
    sget-object v10, Lj91/a;->a:Ll2/u2;

    .line 280
    .line 281
    invoke-virtual {v9, v10}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 282
    .line 283
    .line 284
    move-result-object v10

    .line 285
    check-cast v10, Lj91/c;

    .line 286
    .line 287
    iget v10, v10, Lj91/c;->c:F

    .line 288
    .line 289
    const/16 v20, 0x0

    .line 290
    .line 291
    const/16 v21, 0xd

    .line 292
    .line 293
    const/16 v17, 0x0

    .line 294
    .line 295
    const/16 v19, 0x0

    .line 296
    .line 297
    move/from16 v18, v10

    .line 298
    .line 299
    invoke-static/range {v16 .. v21}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 300
    .line 301
    .line 302
    move-result-object v10

    .line 303
    const-string v11, "battery_bi_di_charging_card_strip"

    .line 304
    .line 305
    invoke-static {v10, v11}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 306
    .line 307
    .line 308
    move-result-object v10

    .line 309
    iget-object v11, v1, Ltz/i;->o:Lqr0/l;

    .line 310
    .line 311
    if-eqz v11, :cond_b

    .line 312
    .line 313
    iget v11, v11, Lqr0/l;->d:I

    .line 314
    .line 315
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 316
    .line 317
    .line 318
    move-result-object v11

    .line 319
    :goto_6
    move v12, v8

    .line 320
    goto :goto_7

    .line 321
    :cond_b
    const/4 v11, 0x0

    .line 322
    goto :goto_6

    .line 323
    :goto_7
    iget-boolean v8, v1, Ltz/i;->s:Z

    .line 324
    .line 325
    move-object/from16 v16, v2

    .line 326
    .line 327
    move-object v2, v10

    .line 328
    move-object v10, v9

    .line 329
    iget-boolean v9, v1, Ltz/i;->q:Z

    .line 330
    .line 331
    move/from16 v17, v7

    .line 332
    .line 333
    move-object v7, v11

    .line 334
    const/4 v11, 0x0

    .line 335
    move/from16 v18, v12

    .line 336
    .line 337
    const/4 v12, 0x0

    .line 338
    move/from16 p3, v0

    .line 339
    .line 340
    move-object/from16 v0, v16

    .line 341
    .line 342
    invoke-static/range {v2 .. v12}, Lxf0/t;->a(Lx2/s;ILjava/lang/Integer;ZZLjava/lang/Integer;ZZLl2/o;II)V

    .line 343
    .line 344
    .line 345
    iget-boolean v2, v1, Ltz/i;->i:Z

    .line 346
    .line 347
    if-nez v2, :cond_c

    .line 348
    .line 349
    if-eqz v18, :cond_d

    .line 350
    .line 351
    :cond_c
    const/4 v4, 0x0

    .line 352
    goto :goto_8

    .line 353
    :cond_d
    const v2, 0x71eb531e

    .line 354
    .line 355
    .line 356
    invoke-virtual {v10, v2}, Ll2/t;->Y(I)V

    .line 357
    .line 358
    .line 359
    shl-int/lit8 v2, p3, 0x3

    .line 360
    .line 361
    and-int/lit8 v2, v2, 0x70

    .line 362
    .line 363
    invoke-static {v0, v1, v10, v2}, Luz/g;->i(Ltz/h;Ltz/i;Ll2/o;I)V

    .line 364
    .line 365
    .line 366
    const/4 v4, 0x0

    .line 367
    invoke-virtual {v10, v4}, Ll2/t;->q(Z)V

    .line 368
    .line 369
    .line 370
    goto :goto_9

    .line 371
    :goto_8
    const v0, 0x71e9e206

    .line 372
    .line 373
    .line 374
    invoke-virtual {v10, v0}, Ll2/t;->Y(I)V

    .line 375
    .line 376
    .line 377
    iget-object v0, v1, Ltz/i;->k:Ljava/lang/String;

    .line 378
    .line 379
    invoke-static {v1, v0, v10, v15}, Luz/g;->g(Ltz/i;Ljava/lang/String;Ll2/o;I)V

    .line 380
    .line 381
    .line 382
    invoke-virtual {v10, v4}, Ll2/t;->q(Z)V

    .line 383
    .line 384
    .line 385
    :goto_9
    invoke-virtual {v10, v4}, Ll2/t;->q(Z)V

    .line 386
    .line 387
    .line 388
    :goto_a
    iget-boolean v0, v1, Ltz/i;->p:Z

    .line 389
    .line 390
    if-eqz v0, :cond_10

    .line 391
    .line 392
    iget-boolean v0, v1, Ltz/i;->r:Z

    .line 393
    .line 394
    if-eqz v0, :cond_10

    .line 395
    .line 396
    const v0, 0x52c5d2fa

    .line 397
    .line 398
    .line 399
    invoke-virtual {v10, v0}, Ll2/t;->Y(I)V

    .line 400
    .line 401
    .line 402
    iget-object v2, v1, Ltz/i;->m:Ljava/lang/String;

    .line 403
    .line 404
    if-nez v2, :cond_e

    .line 405
    .line 406
    const v0, 0x5f48c47

    .line 407
    .line 408
    .line 409
    invoke-virtual {v10, v0}, Ll2/t;->Y(I)V

    .line 410
    .line 411
    .line 412
    :goto_b
    const/4 v4, 0x0

    .line 413
    invoke-virtual {v10, v4}, Ll2/t;->q(Z)V

    .line 414
    .line 415
    .line 416
    goto :goto_d

    .line 417
    :cond_e
    const v0, 0x5f48c48

    .line 418
    .line 419
    .line 420
    invoke-virtual {v10, v0}, Ll2/t;->Y(I)V

    .line 421
    .line 422
    .line 423
    iget-object v3, v1, Ltz/i;->k:Ljava/lang/String;

    .line 424
    .line 425
    iget-object v4, v1, Ltz/i;->l:Ljava/lang/String;

    .line 426
    .line 427
    iget-object v5, v1, Ltz/i;->n:Ljava/lang/String;

    .line 428
    .line 429
    iget-boolean v0, v1, Ltz/i;->c:Z

    .line 430
    .line 431
    if-nez v0, :cond_f

    .line 432
    .line 433
    if-nez v18, :cond_f

    .line 434
    .line 435
    const/4 v6, 0x1

    .line 436
    goto :goto_c

    .line 437
    :cond_f
    const/4 v6, 0x0

    .line 438
    :goto_c
    shl-int/lit8 v0, p3, 0xc

    .line 439
    .line 440
    const/high16 v7, 0x3f0000

    .line 441
    .line 442
    and-int/2addr v0, v7

    .line 443
    move-object v9, v10

    .line 444
    move-object v7, v13

    .line 445
    move-object v8, v14

    .line 446
    move v10, v0

    .line 447
    invoke-static/range {v2 .. v10}, Luz/g;->o(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLay0/a;Lay0/a;Ll2/o;I)V

    .line 448
    .line 449
    .line 450
    move-object v10, v9

    .line 451
    goto :goto_b

    .line 452
    :goto_d
    invoke-virtual {v10, v4}, Ll2/t;->q(Z)V

    .line 453
    .line 454
    .line 455
    const/4 v2, 0x1

    .line 456
    goto :goto_e

    .line 457
    :cond_10
    const/4 v4, 0x0

    .line 458
    const v0, 0x5453b6d

    .line 459
    .line 460
    .line 461
    invoke-virtual {v10, v0}, Ll2/t;->Y(I)V

    .line 462
    .line 463
    .line 464
    goto :goto_d

    .line 465
    :goto_e
    invoke-virtual {v10, v2}, Ll2/t;->q(Z)V

    .line 466
    .line 467
    .line 468
    goto :goto_f

    .line 469
    :cond_11
    move-object v10, v9

    .line 470
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 471
    .line 472
    .line 473
    :goto_f
    invoke-virtual {v10}, Ll2/t;->s()Ll2/u1;

    .line 474
    .line 475
    .line 476
    move-result-object v6

    .line 477
    if-eqz v6, :cond_12

    .line 478
    .line 479
    new-instance v0, Luz/f;

    .line 480
    .line 481
    const/4 v5, 0x1

    .line 482
    move-object/from16 v2, p1

    .line 483
    .line 484
    move-object/from16 v3, p2

    .line 485
    .line 486
    move/from16 v4, p4

    .line 487
    .line 488
    invoke-direct/range {v0 .. v5}, Luz/f;-><init>(Ltz/i;Lay0/a;Lay0/a;II)V

    .line 489
    .line 490
    .line 491
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 492
    .line 493
    :cond_12
    return-void
.end method

.method public static final i(Ltz/h;Ltz/i;Ll2/o;I)V
    .locals 25

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v14, p2

    .line 6
    .line 7
    check-cast v14, Ll2/t;

    .line 8
    .line 9
    const v3, 0x2d3f5430

    .line 10
    .line 11
    .line 12
    invoke-virtual {v14, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    and-int/lit8 v3, p3, 0x6

    .line 16
    .line 17
    if-nez v3, :cond_1

    .line 18
    .line 19
    invoke-virtual {v14, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    if-eqz v3, :cond_0

    .line 24
    .line 25
    const/4 v3, 0x4

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 v3, 0x2

    .line 28
    :goto_0
    or-int v3, p3, v3

    .line 29
    .line 30
    goto :goto_1

    .line 31
    :cond_1
    move/from16 v3, p3

    .line 32
    .line 33
    :goto_1
    and-int/lit8 v4, p3, 0x30

    .line 34
    .line 35
    if-nez v4, :cond_3

    .line 36
    .line 37
    invoke-virtual {v14, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v4

    .line 41
    if-eqz v4, :cond_2

    .line 42
    .line 43
    const/16 v4, 0x20

    .line 44
    .line 45
    goto :goto_2

    .line 46
    :cond_2
    const/16 v4, 0x10

    .line 47
    .line 48
    :goto_2
    or-int/2addr v3, v4

    .line 49
    :cond_3
    and-int/lit8 v4, v3, 0x13

    .line 50
    .line 51
    const/16 v5, 0x12

    .line 52
    .line 53
    const/4 v6, 0x1

    .line 54
    const/4 v7, 0x0

    .line 55
    if-eq v4, v5, :cond_4

    .line 56
    .line 57
    move v4, v6

    .line 58
    goto :goto_3

    .line 59
    :cond_4
    move v4, v7

    .line 60
    :goto_3
    and-int/2addr v3, v6

    .line 61
    invoke-virtual {v14, v3, v4}, Ll2/t;->O(IZ)Z

    .line 62
    .line 63
    .line 64
    move-result v3

    .line 65
    if-eqz v3, :cond_b

    .line 66
    .line 67
    invoke-static {v14}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 68
    .line 69
    .line 70
    move-result-object v3

    .line 71
    iget v10, v3, Lj91/c;->d:F

    .line 72
    .line 73
    const/4 v12, 0x0

    .line 74
    const/16 v13, 0xd

    .line 75
    .line 76
    sget-object v8, Lx2/p;->b:Lx2/p;

    .line 77
    .line 78
    const/4 v9, 0x0

    .line 79
    const/4 v11, 0x0

    .line 80
    invoke-static/range {v8 .. v13}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 81
    .line 82
    .line 83
    move-result-object v3

    .line 84
    const/high16 v4, 0x3f800000    # 1.0f

    .line 85
    .line 86
    invoke-static {v3, v4}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 87
    .line 88
    .line 89
    move-result-object v3

    .line 90
    sget-object v4, Lk1/r0;->d:Lk1/r0;

    .line 91
    .line 92
    invoke-static {v3, v4}, Landroidx/compose/foundation/layout/a;->g(Lx2/s;Lk1/r0;)Lx2/s;

    .line 93
    .line 94
    .line 95
    move-result-object v3

    .line 96
    sget-object v4, Lk1/j;->a:Lk1/c;

    .line 97
    .line 98
    invoke-static {v14}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 99
    .line 100
    .line 101
    move-result-object v4

    .line 102
    iget v4, v4, Lj91/c;->d:F

    .line 103
    .line 104
    invoke-static {v4}, Lk1/j;->g(F)Lk1/h;

    .line 105
    .line 106
    .line 107
    move-result-object v4

    .line 108
    sget-object v5, Lx2/c;->n:Lx2/i;

    .line 109
    .line 110
    const/16 v9, 0x30

    .line 111
    .line 112
    invoke-static {v4, v5, v14, v9}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 113
    .line 114
    .line 115
    move-result-object v4

    .line 116
    iget-wide v9, v14, Ll2/t;->T:J

    .line 117
    .line 118
    invoke-static {v9, v10}, Ljava/lang/Long;->hashCode(J)I

    .line 119
    .line 120
    .line 121
    move-result v5

    .line 122
    invoke-virtual {v14}, Ll2/t;->m()Ll2/p1;

    .line 123
    .line 124
    .line 125
    move-result-object v9

    .line 126
    invoke-static {v14, v3}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 127
    .line 128
    .line 129
    move-result-object v3

    .line 130
    sget-object v10, Lv3/k;->m1:Lv3/j;

    .line 131
    .line 132
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 133
    .line 134
    .line 135
    sget-object v10, Lv3/j;->b:Lv3/i;

    .line 136
    .line 137
    invoke-virtual {v14}, Ll2/t;->c0()V

    .line 138
    .line 139
    .line 140
    iget-boolean v11, v14, Ll2/t;->S:Z

    .line 141
    .line 142
    if-eqz v11, :cond_5

    .line 143
    .line 144
    invoke-virtual {v14, v10}, Ll2/t;->l(Lay0/a;)V

    .line 145
    .line 146
    .line 147
    goto :goto_4

    .line 148
    :cond_5
    invoke-virtual {v14}, Ll2/t;->m0()V

    .line 149
    .line 150
    .line 151
    :goto_4
    sget-object v10, Lv3/j;->g:Lv3/h;

    .line 152
    .line 153
    invoke-static {v10, v4, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 154
    .line 155
    .line 156
    sget-object v4, Lv3/j;->f:Lv3/h;

    .line 157
    .line 158
    invoke-static {v4, v9, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 159
    .line 160
    .line 161
    sget-object v4, Lv3/j;->j:Lv3/h;

    .line 162
    .line 163
    iget-boolean v9, v14, Ll2/t;->S:Z

    .line 164
    .line 165
    if-nez v9, :cond_6

    .line 166
    .line 167
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object v9

    .line 171
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 172
    .line 173
    .line 174
    move-result-object v10

    .line 175
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 176
    .line 177
    .line 178
    move-result v9

    .line 179
    if-nez v9, :cond_7

    .line 180
    .line 181
    :cond_6
    invoke-static {v5, v14, v5, v4}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 182
    .line 183
    .line 184
    :cond_7
    sget-object v4, Lv3/j;->d:Lv3/h;

    .line 185
    .line 186
    invoke-static {v4, v3, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 187
    .line 188
    .line 189
    iget-boolean v3, v1, Ltz/i;->q:Z

    .line 190
    .line 191
    if-eqz v3, :cond_9

    .line 192
    .line 193
    const v3, -0x11bc2e82

    .line 194
    .line 195
    .line 196
    invoke-virtual {v14, v3}, Ll2/t;->Y(I)V

    .line 197
    .line 198
    .line 199
    iget-object v4, v1, Ltz/i;->k:Ljava/lang/String;

    .line 200
    .line 201
    if-nez v4, :cond_8

    .line 202
    .line 203
    const v3, -0x11bc2e83

    .line 204
    .line 205
    .line 206
    invoke-virtual {v14, v3}, Ll2/t;->Y(I)V

    .line 207
    .line 208
    .line 209
    invoke-virtual {v14, v7}, Ll2/t;->q(Z)V

    .line 210
    .line 211
    .line 212
    move v1, v7

    .line 213
    move-object v2, v8

    .line 214
    goto :goto_5

    .line 215
    :cond_8
    invoke-virtual {v14, v3}, Ll2/t;->Y(I)V

    .line 216
    .line 217
    .line 218
    invoke-static {v14}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 219
    .line 220
    .line 221
    move-result-object v3

    .line 222
    invoke-virtual {v3}, Lj91/e;->t()J

    .line 223
    .line 224
    .line 225
    move-result-wide v9

    .line 226
    invoke-static {v14}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 227
    .line 228
    .line 229
    move-result-object v3

    .line 230
    invoke-virtual {v3}, Lj91/f;->e()Lg4/p0;

    .line 231
    .line 232
    .line 233
    move-result-object v3

    .line 234
    invoke-static {v14}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 235
    .line 236
    .line 237
    move-result-object v5

    .line 238
    invoke-virtual {v5}, Lj91/e;->s()J

    .line 239
    .line 240
    .line 241
    move-result-wide v11

    .line 242
    const/16 v15, 0xd80

    .line 243
    .line 244
    const/16 v16, 0x101

    .line 245
    .line 246
    move-object v5, v8

    .line 247
    move-wide v8, v9

    .line 248
    move-object v10, v3

    .line 249
    const/4 v3, 0x0

    .line 250
    move-object v13, v5

    .line 251
    const-string v5, "battery_charging_card_limit_text"

    .line 252
    .line 253
    move/from16 v17, v6

    .line 254
    .line 255
    const-string v6, "battery_charging_card_limit_icon"

    .line 256
    .line 257
    move/from16 v18, v7

    .line 258
    .line 259
    const v7, 0x7f0802d5

    .line 260
    .line 261
    .line 262
    move-object/from16 v19, v13

    .line 263
    .line 264
    const/4 v13, 0x0

    .line 265
    move/from16 v1, v18

    .line 266
    .line 267
    move-object/from16 v2, v19

    .line 268
    .line 269
    invoke-static/range {v3 .. v16}, Luz/g;->k(Lx2/s;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;IJLg4/p0;JILl2/o;II)V

    .line 270
    .line 271
    .line 272
    invoke-virtual {v14, v1}, Ll2/t;->q(Z)V

    .line 273
    .line 274
    .line 275
    :goto_5
    invoke-virtual {v14, v1}, Ll2/t;->q(Z)V

    .line 276
    .line 277
    .line 278
    goto :goto_6

    .line 279
    :cond_9
    move v1, v7

    .line 280
    move-object v2, v8

    .line 281
    const v3, -0x11b48f15

    .line 282
    .line 283
    .line 284
    invoke-virtual {v14, v3}, Ll2/t;->Y(I)V

    .line 285
    .line 286
    .line 287
    iget-object v3, v0, Ltz/h;->d:Ljava/lang/String;

    .line 288
    .line 289
    invoke-static {v14}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 290
    .line 291
    .line 292
    move-result-object v4

    .line 293
    invoke-virtual {v4}, Lj91/f;->e()Lg4/p0;

    .line 294
    .line 295
    .line 296
    move-result-object v4

    .line 297
    const-string v5, "battery_charging_card_limit"

    .line 298
    .line 299
    invoke-static {v2, v5}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 300
    .line 301
    .line 302
    move-result-object v5

    .line 303
    const/16 v23, 0x0

    .line 304
    .line 305
    const v24, 0xfff8

    .line 306
    .line 307
    .line 308
    const-wide/16 v6, 0x0

    .line 309
    .line 310
    const-wide/16 v8, 0x0

    .line 311
    .line 312
    const/4 v10, 0x0

    .line 313
    const-wide/16 v11, 0x0

    .line 314
    .line 315
    const/4 v13, 0x0

    .line 316
    move-object/from16 v21, v14

    .line 317
    .line 318
    const/4 v14, 0x0

    .line 319
    const-wide/16 v15, 0x0

    .line 320
    .line 321
    const/16 v17, 0x0

    .line 322
    .line 323
    const/16 v18, 0x0

    .line 324
    .line 325
    const/16 v19, 0x0

    .line 326
    .line 327
    const/16 v20, 0x0

    .line 328
    .line 329
    const/16 v22, 0x180

    .line 330
    .line 331
    invoke-static/range {v3 .. v24}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 332
    .line 333
    .line 334
    move-object/from16 v14, v21

    .line 335
    .line 336
    invoke-virtual {v14, v1}, Ll2/t;->q(Z)V

    .line 337
    .line 338
    .line 339
    :goto_6
    invoke-static {v14, v1}, Luz/g;->j(Ll2/o;I)V

    .line 340
    .line 341
    .line 342
    iget-object v3, v0, Ltz/h;->e:Ljava/lang/String;

    .line 343
    .line 344
    if-nez v3, :cond_a

    .line 345
    .line 346
    const v3, -0x11b036b8

    .line 347
    .line 348
    .line 349
    invoke-virtual {v14, v3}, Ll2/t;->Y(I)V

    .line 350
    .line 351
    .line 352
    :goto_7
    invoke-virtual {v14, v1}, Ll2/t;->q(Z)V

    .line 353
    .line 354
    .line 355
    goto :goto_8

    .line 356
    :cond_a
    const v4, -0x11b036b7

    .line 357
    .line 358
    .line 359
    invoke-virtual {v14, v4}, Ll2/t;->Y(I)V

    .line 360
    .line 361
    .line 362
    invoke-static {v14}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 363
    .line 364
    .line 365
    move-result-object v4

    .line 366
    invoke-virtual {v4}, Lj91/f;->e()Lg4/p0;

    .line 367
    .line 368
    .line 369
    move-result-object v4

    .line 370
    const-string v5, "battery_charging_card_type"

    .line 371
    .line 372
    invoke-static {v2, v5}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 373
    .line 374
    .line 375
    move-result-object v5

    .line 376
    const/16 v23, 0x0

    .line 377
    .line 378
    const v24, 0xfff8

    .line 379
    .line 380
    .line 381
    const-wide/16 v6, 0x0

    .line 382
    .line 383
    const-wide/16 v8, 0x0

    .line 384
    .line 385
    const/4 v10, 0x0

    .line 386
    const-wide/16 v11, 0x0

    .line 387
    .line 388
    const/4 v13, 0x0

    .line 389
    move-object/from16 v21, v14

    .line 390
    .line 391
    const/4 v14, 0x0

    .line 392
    const-wide/16 v15, 0x0

    .line 393
    .line 394
    const/16 v17, 0x0

    .line 395
    .line 396
    const/16 v18, 0x0

    .line 397
    .line 398
    const/16 v19, 0x0

    .line 399
    .line 400
    const/16 v20, 0x0

    .line 401
    .line 402
    const/16 v22, 0x180

    .line 403
    .line 404
    invoke-static/range {v3 .. v24}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 405
    .line 406
    .line 407
    move-object/from16 v14, v21

    .line 408
    .line 409
    invoke-static {v14, v1}, Luz/g;->j(Ll2/o;I)V

    .line 410
    .line 411
    .line 412
    goto :goto_7

    .line 413
    :goto_8
    iget-object v3, v0, Ltz/h;->f:Ljava/lang/String;

    .line 414
    .line 415
    invoke-static {v14}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 416
    .line 417
    .line 418
    move-result-object v1

    .line 419
    invoke-virtual {v1}, Lj91/f;->e()Lg4/p0;

    .line 420
    .line 421
    .line 422
    move-result-object v4

    .line 423
    const-string v1, "battery_charging_card_power"

    .line 424
    .line 425
    invoke-static {v2, v1}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 426
    .line 427
    .line 428
    move-result-object v5

    .line 429
    const/16 v23, 0x0

    .line 430
    .line 431
    const v24, 0xfff8

    .line 432
    .line 433
    .line 434
    const-wide/16 v6, 0x0

    .line 435
    .line 436
    const-wide/16 v8, 0x0

    .line 437
    .line 438
    const/4 v10, 0x0

    .line 439
    const-wide/16 v11, 0x0

    .line 440
    .line 441
    const/4 v13, 0x0

    .line 442
    move-object/from16 v21, v14

    .line 443
    .line 444
    const/4 v14, 0x0

    .line 445
    const-wide/16 v15, 0x0

    .line 446
    .line 447
    const/16 v17, 0x0

    .line 448
    .line 449
    const/16 v18, 0x0

    .line 450
    .line 451
    const/16 v19, 0x0

    .line 452
    .line 453
    const/16 v20, 0x0

    .line 454
    .line 455
    const/16 v22, 0x180

    .line 456
    .line 457
    invoke-static/range {v3 .. v24}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 458
    .line 459
    .line 460
    move-object/from16 v14, v21

    .line 461
    .line 462
    const/4 v1, 0x1

    .line 463
    invoke-virtual {v14, v1}, Ll2/t;->q(Z)V

    .line 464
    .line 465
    .line 466
    goto :goto_9

    .line 467
    :cond_b
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 468
    .line 469
    .line 470
    :goto_9
    invoke-virtual {v14}, Ll2/t;->s()Ll2/u1;

    .line 471
    .line 472
    .line 473
    move-result-object v1

    .line 474
    if-eqz v1, :cond_c

    .line 475
    .line 476
    new-instance v2, Ltj/i;

    .line 477
    .line 478
    const/4 v3, 0x5

    .line 479
    move-object/from16 v4, p1

    .line 480
    .line 481
    move/from16 v5, p3

    .line 482
    .line 483
    invoke-direct {v2, v5, v3, v0, v4}, Ltj/i;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 484
    .line 485
    .line 486
    iput-object v2, v1, Ll2/u1;->d:Lay0/n;

    .line 487
    .line 488
    :cond_c
    return-void
.end method

.method public static final j(Ll2/o;I)V
    .locals 7

    .line 1
    move-object v4, p0

    .line 2
    check-cast v4, Ll2/t;

    .line 3
    .line 4
    const p0, 0x6cb4c586

    .line 5
    .line 6
    .line 7
    invoke-virtual {v4, p0}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    const/4 p0, 0x1

    .line 11
    if-eqz p1, :cond_0

    .line 12
    .line 13
    move v0, p0

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    const/4 v0, 0x0

    .line 16
    :goto_0
    and-int/lit8 v1, p1, 0x1

    .line 17
    .line 18
    invoke-virtual {v4, v1, v0}, Ll2/t;->O(IZ)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_1

    .line 23
    .line 24
    sget-object v0, Lj91/h;->a:Ll2/u2;

    .line 25
    .line 26
    invoke-virtual {v4, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    check-cast v0, Lj91/e;

    .line 31
    .line 32
    invoke-virtual {v0}, Lj91/e;->l()J

    .line 33
    .line 34
    .line 35
    move-result-wide v2

    .line 36
    int-to-float p0, p0

    .line 37
    const/16 v0, 0x10

    .line 38
    .line 39
    int-to-float v0, v0

    .line 40
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 41
    .line 42
    invoke-static {v1, p0, v0}, Landroidx/compose/foundation/layout/d;->o(Lx2/s;FF)Lx2/s;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    const/4 v5, 0x6

    .line 47
    const/4 v6, 0x2

    .line 48
    const/4 v1, 0x0

    .line 49
    invoke-static/range {v0 .. v6}, Lh2/r;->v(Lx2/s;FJLl2/o;II)V

    .line 50
    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_1
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 54
    .line 55
    .line 56
    :goto_1
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    if-eqz p0, :cond_2

    .line 61
    .line 62
    new-instance v0, Luu/s1;

    .line 63
    .line 64
    const/4 v1, 0x5

    .line 65
    invoke-direct {v0, p1, v1}, Luu/s1;-><init>(II)V

    .line 66
    .line 67
    .line 68
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 69
    .line 70
    :cond_2
    return-void
.end method

.method public static final k(Lx2/s;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;IJLg4/p0;JILl2/o;II)V
    .locals 37

    .line 1
    move-object/from16 v3, p2

    .line 2
    .line 3
    move-object/from16 v4, p3

    .line 4
    .line 5
    move/from16 v5, p4

    .line 6
    .line 7
    move/from16 v12, p12

    .line 8
    .line 9
    move/from16 v13, p13

    .line 10
    .line 11
    move-object/from16 v0, p11

    .line 12
    .line 13
    check-cast v0, Ll2/t;

    .line 14
    .line 15
    const v1, 0x720c815c

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 19
    .line 20
    .line 21
    and-int/lit8 v1, v13, 0x1

    .line 22
    .line 23
    if-eqz v1, :cond_0

    .line 24
    .line 25
    or-int/lit8 v2, v12, 0x6

    .line 26
    .line 27
    move v6, v2

    .line 28
    move-object/from16 v2, p0

    .line 29
    .line 30
    goto :goto_1

    .line 31
    :cond_0
    and-int/lit8 v2, v12, 0x6

    .line 32
    .line 33
    if-nez v2, :cond_2

    .line 34
    .line 35
    move-object/from16 v2, p0

    .line 36
    .line 37
    invoke-virtual {v0, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v6

    .line 41
    if-eqz v6, :cond_1

    .line 42
    .line 43
    const/4 v6, 0x4

    .line 44
    goto :goto_0

    .line 45
    :cond_1
    const/4 v6, 0x2

    .line 46
    :goto_0
    or-int/2addr v6, v12

    .line 47
    goto :goto_1

    .line 48
    :cond_2
    move-object/from16 v2, p0

    .line 49
    .line 50
    move v6, v12

    .line 51
    :goto_1
    and-int/lit8 v7, v12, 0x30

    .line 52
    .line 53
    if-nez v7, :cond_4

    .line 54
    .line 55
    move-object/from16 v7, p1

    .line 56
    .line 57
    invoke-virtual {v0, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v8

    .line 61
    if-eqz v8, :cond_3

    .line 62
    .line 63
    const/16 v8, 0x20

    .line 64
    .line 65
    goto :goto_2

    .line 66
    :cond_3
    const/16 v8, 0x10

    .line 67
    .line 68
    :goto_2
    or-int/2addr v6, v8

    .line 69
    goto :goto_3

    .line 70
    :cond_4
    move-object/from16 v7, p1

    .line 71
    .line 72
    :goto_3
    and-int/lit16 v8, v12, 0x180

    .line 73
    .line 74
    if-nez v8, :cond_6

    .line 75
    .line 76
    invoke-virtual {v0, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result v8

    .line 80
    if-eqz v8, :cond_5

    .line 81
    .line 82
    const/16 v8, 0x100

    .line 83
    .line 84
    goto :goto_4

    .line 85
    :cond_5
    const/16 v8, 0x80

    .line 86
    .line 87
    :goto_4
    or-int/2addr v6, v8

    .line 88
    :cond_6
    and-int/lit16 v8, v12, 0xc00

    .line 89
    .line 90
    if-nez v8, :cond_8

    .line 91
    .line 92
    invoke-virtual {v0, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    move-result v8

    .line 96
    if-eqz v8, :cond_7

    .line 97
    .line 98
    const/16 v8, 0x800

    .line 99
    .line 100
    goto :goto_5

    .line 101
    :cond_7
    const/16 v8, 0x400

    .line 102
    .line 103
    :goto_5
    or-int/2addr v6, v8

    .line 104
    :cond_8
    and-int/lit16 v8, v12, 0x6000

    .line 105
    .line 106
    if-nez v8, :cond_a

    .line 107
    .line 108
    invoke-virtual {v0, v5}, Ll2/t;->e(I)Z

    .line 109
    .line 110
    .line 111
    move-result v8

    .line 112
    if-eqz v8, :cond_9

    .line 113
    .line 114
    const/16 v8, 0x4000

    .line 115
    .line 116
    goto :goto_6

    .line 117
    :cond_9
    const/16 v8, 0x2000

    .line 118
    .line 119
    :goto_6
    or-int/2addr v6, v8

    .line 120
    :cond_a
    const/high16 v8, 0x30000

    .line 121
    .line 122
    and-int/2addr v8, v12

    .line 123
    if-nez v8, :cond_c

    .line 124
    .line 125
    move-wide/from16 v8, p5

    .line 126
    .line 127
    invoke-virtual {v0, v8, v9}, Ll2/t;->f(J)Z

    .line 128
    .line 129
    .line 130
    move-result v10

    .line 131
    if-eqz v10, :cond_b

    .line 132
    .line 133
    const/high16 v10, 0x20000

    .line 134
    .line 135
    goto :goto_7

    .line 136
    :cond_b
    const/high16 v10, 0x10000

    .line 137
    .line 138
    :goto_7
    or-int/2addr v6, v10

    .line 139
    goto :goto_8

    .line 140
    :cond_c
    move-wide/from16 v8, p5

    .line 141
    .line 142
    :goto_8
    const/high16 v10, 0x180000

    .line 143
    .line 144
    and-int/2addr v10, v12

    .line 145
    if-nez v10, :cond_e

    .line 146
    .line 147
    move-object/from16 v10, p7

    .line 148
    .line 149
    invoke-virtual {v0, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 150
    .line 151
    .line 152
    move-result v11

    .line 153
    if-eqz v11, :cond_d

    .line 154
    .line 155
    const/high16 v11, 0x100000

    .line 156
    .line 157
    goto :goto_9

    .line 158
    :cond_d
    const/high16 v11, 0x80000

    .line 159
    .line 160
    :goto_9
    or-int/2addr v6, v11

    .line 161
    goto :goto_a

    .line 162
    :cond_e
    move-object/from16 v10, p7

    .line 163
    .line 164
    :goto_a
    const/high16 v11, 0xc00000

    .line 165
    .line 166
    and-int/2addr v11, v12

    .line 167
    move-wide/from16 v14, p8

    .line 168
    .line 169
    if-nez v11, :cond_10

    .line 170
    .line 171
    invoke-virtual {v0, v14, v15}, Ll2/t;->f(J)Z

    .line 172
    .line 173
    .line 174
    move-result v11

    .line 175
    if-eqz v11, :cond_f

    .line 176
    .line 177
    const/high16 v11, 0x800000

    .line 178
    .line 179
    goto :goto_b

    .line 180
    :cond_f
    const/high16 v11, 0x400000

    .line 181
    .line 182
    :goto_b
    or-int/2addr v6, v11

    .line 183
    :cond_10
    and-int/lit16 v11, v13, 0x100

    .line 184
    .line 185
    const/high16 v16, 0x6000000

    .line 186
    .line 187
    if-eqz v11, :cond_11

    .line 188
    .line 189
    or-int v6, v6, v16

    .line 190
    .line 191
    move/from16 p11, v1

    .line 192
    .line 193
    move/from16 v1, p10

    .line 194
    .line 195
    goto :goto_d

    .line 196
    :cond_11
    and-int v16, v12, v16

    .line 197
    .line 198
    move/from16 p11, v1

    .line 199
    .line 200
    move/from16 v1, p10

    .line 201
    .line 202
    if-nez v16, :cond_13

    .line 203
    .line 204
    invoke-virtual {v0, v1}, Ll2/t;->e(I)Z

    .line 205
    .line 206
    .line 207
    move-result v16

    .line 208
    if-eqz v16, :cond_12

    .line 209
    .line 210
    const/high16 v16, 0x4000000

    .line 211
    .line 212
    goto :goto_c

    .line 213
    :cond_12
    const/high16 v16, 0x2000000

    .line 214
    .line 215
    :goto_c
    or-int v6, v6, v16

    .line 216
    .line 217
    :cond_13
    :goto_d
    const v16, 0x2492493

    .line 218
    .line 219
    .line 220
    and-int v1, v6, v16

    .line 221
    .line 222
    const v2, 0x2492492

    .line 223
    .line 224
    .line 225
    if-eq v1, v2, :cond_14

    .line 226
    .line 227
    const/4 v1, 0x1

    .line 228
    goto :goto_e

    .line 229
    :cond_14
    const/4 v1, 0x0

    .line 230
    :goto_e
    and-int/lit8 v2, v6, 0x1

    .line 231
    .line 232
    invoke-virtual {v0, v2, v1}, Ll2/t;->O(IZ)Z

    .line 233
    .line 234
    .line 235
    move-result v1

    .line 236
    if-eqz v1, :cond_1a

    .line 237
    .line 238
    sget-object v16, Lx2/p;->b:Lx2/p;

    .line 239
    .line 240
    if-eqz p11, :cond_15

    .line 241
    .line 242
    move-object/from16 v1, v16

    .line 243
    .line 244
    goto :goto_f

    .line 245
    :cond_15
    move-object/from16 v1, p0

    .line 246
    .line 247
    :goto_f
    if-eqz v11, :cond_16

    .line 248
    .line 249
    const/16 v28, 0x1

    .line 250
    .line 251
    goto :goto_10

    .line 252
    :cond_16
    move/from16 v28, p10

    .line 253
    .line 254
    :goto_10
    sget-object v2, Lx2/c;->n:Lx2/i;

    .line 255
    .line 256
    sget-object v11, Lk1/j;->a:Lk1/c;

    .line 257
    .line 258
    const/16 v14, 0x30

    .line 259
    .line 260
    invoke-static {v11, v2, v0, v14}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 261
    .line 262
    .line 263
    move-result-object v2

    .line 264
    move/from16 p0, v14

    .line 265
    .line 266
    iget-wide v14, v0, Ll2/t;->T:J

    .line 267
    .line 268
    invoke-static {v14, v15}, Ljava/lang/Long;->hashCode(J)I

    .line 269
    .line 270
    .line 271
    move-result v11

    .line 272
    invoke-virtual {v0}, Ll2/t;->m()Ll2/p1;

    .line 273
    .line 274
    .line 275
    move-result-object v14

    .line 276
    invoke-static {v0, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 277
    .line 278
    .line 279
    move-result-object v15

    .line 280
    sget-object v17, Lv3/k;->m1:Lv3/j;

    .line 281
    .line 282
    invoke-virtual/range {v17 .. v17}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 283
    .line 284
    .line 285
    move-object/from16 v36, v1

    .line 286
    .line 287
    sget-object v1, Lv3/j;->b:Lv3/i;

    .line 288
    .line 289
    invoke-virtual {v0}, Ll2/t;->c0()V

    .line 290
    .line 291
    .line 292
    move/from16 v22, v6

    .line 293
    .line 294
    iget-boolean v6, v0, Ll2/t;->S:Z

    .line 295
    .line 296
    if-eqz v6, :cond_17

    .line 297
    .line 298
    invoke-virtual {v0, v1}, Ll2/t;->l(Lay0/a;)V

    .line 299
    .line 300
    .line 301
    goto :goto_11

    .line 302
    :cond_17
    invoke-virtual {v0}, Ll2/t;->m0()V

    .line 303
    .line 304
    .line 305
    :goto_11
    sget-object v1, Lv3/j;->g:Lv3/h;

    .line 306
    .line 307
    invoke-static {v1, v2, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 308
    .line 309
    .line 310
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 311
    .line 312
    invoke-static {v1, v14, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 313
    .line 314
    .line 315
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 316
    .line 317
    iget-boolean v2, v0, Ll2/t;->S:Z

    .line 318
    .line 319
    if-nez v2, :cond_18

    .line 320
    .line 321
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 322
    .line 323
    .line 324
    move-result-object v2

    .line 325
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 326
    .line 327
    .line 328
    move-result-object v6

    .line 329
    invoke-static {v2, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 330
    .line 331
    .line 332
    move-result v2

    .line 333
    if-nez v2, :cond_19

    .line 334
    .line 335
    :cond_18
    invoke-static {v11, v0, v11, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 336
    .line 337
    .line 338
    :cond_19
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 339
    .line 340
    invoke-static {v1, v15, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 341
    .line 342
    .line 343
    shr-int/lit8 v1, v22, 0xc

    .line 344
    .line 345
    and-int/lit8 v2, v1, 0xe

    .line 346
    .line 347
    invoke-static {v5, v2, v0}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 348
    .line 349
    .line 350
    move-result-object v14

    .line 351
    sget-object v2, Lj91/a;->a:Ll2/u2;

    .line 352
    .line 353
    invoke-virtual {v0, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 354
    .line 355
    .line 356
    move-result-object v2

    .line 357
    check-cast v2, Lj91/c;

    .line 358
    .line 359
    iget v2, v2, Lj91/c;->b:F

    .line 360
    .line 361
    const/16 v20, 0x0

    .line 362
    .line 363
    const/16 v21, 0xb

    .line 364
    .line 365
    const/16 v17, 0x0

    .line 366
    .line 367
    const/16 v18, 0x0

    .line 368
    .line 369
    move/from16 v19, v2

    .line 370
    .line 371
    invoke-static/range {v16 .. v21}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 372
    .line 373
    .line 374
    move-result-object v2

    .line 375
    move-object/from16 v6, v16

    .line 376
    .line 377
    sget v11, Luz/g;->c:F

    .line 378
    .line 379
    invoke-static {v2, v11}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 380
    .line 381
    .line 382
    move-result-object v2

    .line 383
    invoke-static {v2, v4}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 384
    .line 385
    .line 386
    move-result-object v16

    .line 387
    shr-int/lit8 v2, v22, 0x6

    .line 388
    .line 389
    and-int/lit16 v2, v2, 0x1c00

    .line 390
    .line 391
    or-int/lit8 v20, v2, 0x30

    .line 392
    .line 393
    const/16 v21, 0x0

    .line 394
    .line 395
    const/4 v15, 0x0

    .line 396
    move-object/from16 v19, v0

    .line 397
    .line 398
    move-wide/from16 v17, v8

    .line 399
    .line 400
    const/4 v0, 0x1

    .line 401
    invoke-static/range {v14 .. v21}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 402
    .line 403
    .line 404
    invoke-static {v6, v3}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 405
    .line 406
    .line 407
    move-result-object v16

    .line 408
    shr-int/lit8 v2, v22, 0x3

    .line 409
    .line 410
    and-int/lit8 v2, v2, 0xe

    .line 411
    .line 412
    shr-int/lit8 v6, v22, 0xf

    .line 413
    .line 414
    and-int/lit8 v6, v6, 0x70

    .line 415
    .line 416
    or-int/2addr v2, v6

    .line 417
    and-int/lit16 v1, v1, 0x1c00

    .line 418
    .line 419
    or-int v33, v2, v1

    .line 420
    .line 421
    shr-int/lit8 v1, v22, 0x12

    .line 422
    .line 423
    and-int/lit16 v1, v1, 0x380

    .line 424
    .line 425
    or-int/lit16 v1, v1, 0x6000

    .line 426
    .line 427
    const v35, 0xaff0

    .line 428
    .line 429
    .line 430
    move-object/from16 v32, v19

    .line 431
    .line 432
    const-wide/16 v19, 0x0

    .line 433
    .line 434
    const/16 v21, 0x0

    .line 435
    .line 436
    const-wide/16 v22, 0x0

    .line 437
    .line 438
    const/16 v24, 0x0

    .line 439
    .line 440
    const/16 v25, 0x0

    .line 441
    .line 442
    const-wide/16 v26, 0x0

    .line 443
    .line 444
    const/16 v29, 0x0

    .line 445
    .line 446
    const/16 v30, 0x1

    .line 447
    .line 448
    const/16 v31, 0x0

    .line 449
    .line 450
    move-wide/from16 v17, p8

    .line 451
    .line 452
    move/from16 v34, v1

    .line 453
    .line 454
    move-object v14, v7

    .line 455
    move-object v15, v10

    .line 456
    invoke-static/range {v14 .. v35}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 457
    .line 458
    .line 459
    move-object/from16 v1, v32

    .line 460
    .line 461
    invoke-virtual {v1, v0}, Ll2/t;->q(Z)V

    .line 462
    .line 463
    .line 464
    move/from16 v11, v28

    .line 465
    .line 466
    goto :goto_12

    .line 467
    :cond_1a
    move-object v1, v0

    .line 468
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 469
    .line 470
    .line 471
    move-object/from16 v36, p0

    .line 472
    .line 473
    move/from16 v11, p10

    .line 474
    .line 475
    :goto_12
    invoke-virtual {v1}, Ll2/t;->s()Ll2/u1;

    .line 476
    .line 477
    .line 478
    move-result-object v14

    .line 479
    if-eqz v14, :cond_1b

    .line 480
    .line 481
    new-instance v0, Luz/b;

    .line 482
    .line 483
    move-object/from16 v2, p1

    .line 484
    .line 485
    move-wide/from16 v6, p5

    .line 486
    .line 487
    move-object/from16 v8, p7

    .line 488
    .line 489
    move-wide/from16 v9, p8

    .line 490
    .line 491
    move-object/from16 v1, v36

    .line 492
    .line 493
    invoke-direct/range {v0 .. v13}, Luz/b;-><init>(Lx2/s;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;IJLg4/p0;JIII)V

    .line 494
    .line 495
    .line 496
    iput-object v0, v14, Ll2/u1;->d:Lay0/n;

    .line 497
    .line 498
    :cond_1b
    return-void
.end method

.method public static final l(Lx2/s;Ljava/lang/String;JLg4/p0;JILl2/o;I)V
    .locals 28

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v7, p8

    .line 4
    .line 5
    check-cast v7, Ll2/t;

    .line 6
    .line 7
    const v0, 0x75200276

    .line 8
    .line 9
    .line 10
    invoke-virtual {v7, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v7, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

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
    or-int v0, p9, v0

    .line 23
    .line 24
    move-object/from16 v2, p1

    .line 25
    .line 26
    invoke-virtual {v7, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    if-eqz v3, :cond_1

    .line 31
    .line 32
    const/16 v3, 0x20

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_1
    const/16 v3, 0x10

    .line 36
    .line 37
    :goto_1
    or-int/2addr v0, v3

    .line 38
    const v3, 0x7f08033b

    .line 39
    .line 40
    .line 41
    invoke-virtual {v7, v3}, Ll2/t;->e(I)Z

    .line 42
    .line 43
    .line 44
    move-result v4

    .line 45
    if-eqz v4, :cond_2

    .line 46
    .line 47
    const/16 v4, 0x4000

    .line 48
    .line 49
    goto :goto_2

    .line 50
    :cond_2
    const/16 v4, 0x2000

    .line 51
    .line 52
    :goto_2
    or-int/2addr v0, v4

    .line 53
    move-wide/from16 v4, p2

    .line 54
    .line 55
    invoke-virtual {v7, v4, v5}, Ll2/t;->f(J)Z

    .line 56
    .line 57
    .line 58
    move-result v6

    .line 59
    if-eqz v6, :cond_3

    .line 60
    .line 61
    const/high16 v6, 0x20000

    .line 62
    .line 63
    goto :goto_3

    .line 64
    :cond_3
    const/high16 v6, 0x10000

    .line 65
    .line 66
    :goto_3
    or-int/2addr v0, v6

    .line 67
    move-object/from16 v6, p4

    .line 68
    .line 69
    invoke-virtual {v7, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    move-result v8

    .line 73
    if-eqz v8, :cond_4

    .line 74
    .line 75
    const/high16 v8, 0x100000

    .line 76
    .line 77
    goto :goto_4

    .line 78
    :cond_4
    const/high16 v8, 0x80000

    .line 79
    .line 80
    :goto_4
    or-int/2addr v0, v8

    .line 81
    move-wide/from16 v8, p5

    .line 82
    .line 83
    invoke-virtual {v7, v8, v9}, Ll2/t;->f(J)Z

    .line 84
    .line 85
    .line 86
    move-result v10

    .line 87
    if-eqz v10, :cond_5

    .line 88
    .line 89
    const/high16 v10, 0x800000

    .line 90
    .line 91
    goto :goto_5

    .line 92
    :cond_5
    const/high16 v10, 0x400000

    .line 93
    .line 94
    :goto_5
    or-int/2addr v0, v10

    .line 95
    const/high16 v10, 0x6000000

    .line 96
    .line 97
    or-int/2addr v0, v10

    .line 98
    const v10, 0x2492493

    .line 99
    .line 100
    .line 101
    and-int/2addr v10, v0

    .line 102
    const v11, 0x2492492

    .line 103
    .line 104
    .line 105
    const/4 v12, 0x1

    .line 106
    if-eq v10, v11, :cond_6

    .line 107
    .line 108
    move v10, v12

    .line 109
    goto :goto_6

    .line 110
    :cond_6
    const/4 v10, 0x0

    .line 111
    :goto_6
    and-int/lit8 v11, v0, 0x1

    .line 112
    .line 113
    invoke-virtual {v7, v11, v10}, Ll2/t;->O(IZ)Z

    .line 114
    .line 115
    .line 116
    move-result v10

    .line 117
    if-eqz v10, :cond_a

    .line 118
    .line 119
    sget-object v10, Lx2/c;->n:Lx2/i;

    .line 120
    .line 121
    sget-object v11, Lk1/j;->b:Lk1/c;

    .line 122
    .line 123
    const/16 v13, 0x36

    .line 124
    .line 125
    invoke-static {v11, v10, v7, v13}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 126
    .line 127
    .line 128
    move-result-object v10

    .line 129
    iget-wide v13, v7, Ll2/t;->T:J

    .line 130
    .line 131
    invoke-static {v13, v14}, Ljava/lang/Long;->hashCode(J)I

    .line 132
    .line 133
    .line 134
    move-result v11

    .line 135
    invoke-virtual {v7}, Ll2/t;->m()Ll2/p1;

    .line 136
    .line 137
    .line 138
    move-result-object v13

    .line 139
    invoke-static {v7, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 140
    .line 141
    .line 142
    move-result-object v14

    .line 143
    sget-object v15, Lv3/k;->m1:Lv3/j;

    .line 144
    .line 145
    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 146
    .line 147
    .line 148
    sget-object v15, Lv3/j;->b:Lv3/i;

    .line 149
    .line 150
    invoke-virtual {v7}, Ll2/t;->c0()V

    .line 151
    .line 152
    .line 153
    iget-boolean v3, v7, Ll2/t;->S:Z

    .line 154
    .line 155
    if-eqz v3, :cond_7

    .line 156
    .line 157
    invoke-virtual {v7, v15}, Ll2/t;->l(Lay0/a;)V

    .line 158
    .line 159
    .line 160
    goto :goto_7

    .line 161
    :cond_7
    invoke-virtual {v7}, Ll2/t;->m0()V

    .line 162
    .line 163
    .line 164
    :goto_7
    sget-object v3, Lv3/j;->g:Lv3/h;

    .line 165
    .line 166
    invoke-static {v3, v10, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 167
    .line 168
    .line 169
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 170
    .line 171
    invoke-static {v3, v13, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 172
    .line 173
    .line 174
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 175
    .line 176
    iget-boolean v10, v7, Ll2/t;->S:Z

    .line 177
    .line 178
    if-nez v10, :cond_8

    .line 179
    .line 180
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object v10

    .line 184
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 185
    .line 186
    .line 187
    move-result-object v13

    .line 188
    invoke-static {v10, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 189
    .line 190
    .line 191
    move-result v10

    .line 192
    if-nez v10, :cond_9

    .line 193
    .line 194
    :cond_8
    invoke-static {v11, v7, v11, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 195
    .line 196
    .line 197
    :cond_9
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 198
    .line 199
    invoke-static {v3, v14, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 200
    .line 201
    .line 202
    sget-object v3, Lj91/a;->a:Ll2/u2;

    .line 203
    .line 204
    invoke-virtual {v7, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    move-result-object v3

    .line 208
    check-cast v3, Lj91/c;

    .line 209
    .line 210
    iget v3, v3, Lj91/c;->b:F

    .line 211
    .line 212
    const/16 v17, 0x0

    .line 213
    .line 214
    const/16 v18, 0xb

    .line 215
    .line 216
    sget-object v13, Lx2/p;->b:Lx2/p;

    .line 217
    .line 218
    const/4 v14, 0x0

    .line 219
    const/4 v15, 0x0

    .line 220
    move/from16 v16, v3

    .line 221
    .line 222
    invoke-static/range {v13 .. v18}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 223
    .line 224
    .line 225
    move-result-object v3

    .line 226
    const-string v10, "battery_charge_mode_profile_text"

    .line 227
    .line 228
    invoke-static {v3, v10}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 229
    .line 230
    .line 231
    move-result-object v3

    .line 232
    move-object v10, v13

    .line 233
    new-instance v13, Lr4/k;

    .line 234
    .line 235
    const/4 v11, 0x3

    .line 236
    invoke-direct {v13, v11}, Lr4/k;-><init>(I)V

    .line 237
    .line 238
    .line 239
    shr-int/lit8 v11, v0, 0x3

    .line 240
    .line 241
    and-int/lit8 v11, v11, 0xe

    .line 242
    .line 243
    shr-int/lit8 v14, v0, 0xf

    .line 244
    .line 245
    and-int/lit8 v14, v14, 0x70

    .line 246
    .line 247
    or-int/2addr v11, v14

    .line 248
    shr-int/lit8 v14, v0, 0xc

    .line 249
    .line 250
    and-int/lit16 v15, v14, 0x1c00

    .line 251
    .line 252
    or-int v21, v11, v15

    .line 253
    .line 254
    const/16 v22, 0x6180

    .line 255
    .line 256
    const v23, 0xabf0

    .line 257
    .line 258
    .line 259
    move-object/from16 v20, v7

    .line 260
    .line 261
    const-wide/16 v7, 0x0

    .line 262
    .line 263
    const/4 v9, 0x0

    .line 264
    move-object v15, v10

    .line 265
    const-wide/16 v10, 0x0

    .line 266
    .line 267
    move/from16 v16, v12

    .line 268
    .line 269
    const/4 v12, 0x0

    .line 270
    move/from16 v17, v14

    .line 271
    .line 272
    move-object/from16 v18, v15

    .line 273
    .line 274
    const-wide/16 v14, 0x0

    .line 275
    .line 276
    move/from16 v19, v16

    .line 277
    .line 278
    const/16 v16, 0x1

    .line 279
    .line 280
    move/from16 v24, v17

    .line 281
    .line 282
    const/16 v17, 0x0

    .line 283
    .line 284
    move-object/from16 v25, v18

    .line 285
    .line 286
    const/16 v18, 0x1

    .line 287
    .line 288
    move/from16 v26, v19

    .line 289
    .line 290
    const/16 v19, 0x0

    .line 291
    .line 292
    move/from16 p8, v0

    .line 293
    .line 294
    move-object v4, v3

    .line 295
    move-object v3, v6

    .line 296
    move-object/from16 v27, v25

    .line 297
    .line 298
    const v0, 0x7f08033b

    .line 299
    .line 300
    .line 301
    move-wide/from16 v5, p5

    .line 302
    .line 303
    invoke-static/range {v2 .. v23}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 304
    .line 305
    .line 306
    move-object/from16 v7, v20

    .line 307
    .line 308
    and-int/lit8 v2, v24, 0xe

    .line 309
    .line 310
    invoke-static {v0, v2, v7}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 311
    .line 312
    .line 313
    move-result-object v2

    .line 314
    sget v0, Luz/g;->c:F

    .line 315
    .line 316
    move-object/from16 v13, v27

    .line 317
    .line 318
    invoke-static {v13, v0}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 319
    .line 320
    .line 321
    move-result-object v0

    .line 322
    const-string v3, "battery_charge_mode_profile_arrow_icon"

    .line 323
    .line 324
    invoke-static {v0, v3}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 325
    .line 326
    .line 327
    move-result-object v4

    .line 328
    shr-int/lit8 v0, p8, 0x6

    .line 329
    .line 330
    and-int/lit16 v0, v0, 0x1c00

    .line 331
    .line 332
    or-int/lit8 v8, v0, 0x30

    .line 333
    .line 334
    const/4 v9, 0x0

    .line 335
    const/4 v3, 0x0

    .line 336
    move-wide/from16 v5, p2

    .line 337
    .line 338
    invoke-static/range {v2 .. v9}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 339
    .line 340
    .line 341
    const/4 v0, 0x1

    .line 342
    invoke-virtual {v7, v0}, Ll2/t;->q(Z)V

    .line 343
    .line 344
    .line 345
    move/from16 v8, v16

    .line 346
    .line 347
    goto :goto_8

    .line 348
    :cond_a
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 349
    .line 350
    .line 351
    move/from16 v8, p7

    .line 352
    .line 353
    :goto_8
    invoke-virtual {v7}, Ll2/t;->s()Ll2/u1;

    .line 354
    .line 355
    .line 356
    move-result-object v10

    .line 357
    if-eqz v10, :cond_b

    .line 358
    .line 359
    new-instance v0, Li91/a;

    .line 360
    .line 361
    move-object/from16 v2, p1

    .line 362
    .line 363
    move-wide/from16 v3, p2

    .line 364
    .line 365
    move-object/from16 v5, p4

    .line 366
    .line 367
    move-wide/from16 v6, p5

    .line 368
    .line 369
    move/from16 v9, p9

    .line 370
    .line 371
    invoke-direct/range {v0 .. v9}, Li91/a;-><init>(Lx2/s;Ljava/lang/String;JLg4/p0;JII)V

    .line 372
    .line 373
    .line 374
    iput-object v0, v10, Ll2/u1;->d:Lay0/n;

    .line 375
    .line 376
    :cond_b
    return-void
.end method

.method public static final m(Ltz/i;Ll2/o;I)V
    .locals 33

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v5, p1

    .line 4
    .line 5
    check-cast v5, Ll2/t;

    .line 6
    .line 7
    const v2, 0x695cdb4f

    .line 8
    .line 9
    .line 10
    invoke-virtual {v5, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v5, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    const/4 v3, 0x2

    .line 18
    if-eqz v2, :cond_0

    .line 19
    .line 20
    const/4 v2, 0x4

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    move v2, v3

    .line 23
    :goto_0
    or-int v2, p2, v2

    .line 24
    .line 25
    and-int/lit8 v4, v2, 0x3

    .line 26
    .line 27
    const/4 v8, 0x1

    .line 28
    const/4 v9, 0x0

    .line 29
    if-eq v4, v3, :cond_1

    .line 30
    .line 31
    move v3, v8

    .line 32
    goto :goto_1

    .line 33
    :cond_1
    move v3, v9

    .line 34
    :goto_1
    and-int/2addr v2, v8

    .line 35
    invoke-virtual {v5, v2, v3}, Ll2/t;->O(IZ)Z

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    if-eqz v2, :cond_12

    .line 40
    .line 41
    sget v2, Luz/g;->a:F

    .line 42
    .line 43
    sget-object v10, Lx2/p;->b:Lx2/p;

    .line 44
    .line 45
    const/4 v3, 0x0

    .line 46
    invoke-static {v10, v3, v2, v8}, Landroidx/compose/foundation/layout/d;->b(Lx2/s;FFI)Lx2/s;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    sget-object v3, Lx2/c;->n:Lx2/i;

    .line 51
    .line 52
    sget-object v4, Lk1/j;->a:Lk1/c;

    .line 53
    .line 54
    const/16 v6, 0x30

    .line 55
    .line 56
    invoke-static {v4, v3, v5, v6}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 57
    .line 58
    .line 59
    move-result-object v3

    .line 60
    iget-wide v6, v5, Ll2/t;->T:J

    .line 61
    .line 62
    invoke-static {v6, v7}, Ljava/lang/Long;->hashCode(J)I

    .line 63
    .line 64
    .line 65
    move-result v4

    .line 66
    invoke-virtual {v5}, Ll2/t;->m()Ll2/p1;

    .line 67
    .line 68
    .line 69
    move-result-object v6

    .line 70
    invoke-static {v5, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 71
    .line 72
    .line 73
    move-result-object v2

    .line 74
    sget-object v7, Lv3/k;->m1:Lv3/j;

    .line 75
    .line 76
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 77
    .line 78
    .line 79
    sget-object v11, Lv3/j;->b:Lv3/i;

    .line 80
    .line 81
    invoke-virtual {v5}, Ll2/t;->c0()V

    .line 82
    .line 83
    .line 84
    iget-boolean v7, v5, Ll2/t;->S:Z

    .line 85
    .line 86
    if-eqz v7, :cond_2

    .line 87
    .line 88
    invoke-virtual {v5, v11}, Ll2/t;->l(Lay0/a;)V

    .line 89
    .line 90
    .line 91
    goto :goto_2

    .line 92
    :cond_2
    invoke-virtual {v5}, Ll2/t;->m0()V

    .line 93
    .line 94
    .line 95
    :goto_2
    sget-object v12, Lv3/j;->g:Lv3/h;

    .line 96
    .line 97
    invoke-static {v12, v3, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 98
    .line 99
    .line 100
    sget-object v13, Lv3/j;->f:Lv3/h;

    .line 101
    .line 102
    invoke-static {v13, v6, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 103
    .line 104
    .line 105
    sget-object v14, Lv3/j;->j:Lv3/h;

    .line 106
    .line 107
    iget-boolean v3, v5, Ll2/t;->S:Z

    .line 108
    .line 109
    if-nez v3, :cond_3

    .line 110
    .line 111
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v3

    .line 115
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 116
    .line 117
    .line 118
    move-result-object v6

    .line 119
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 120
    .line 121
    .line 122
    move-result v3

    .line 123
    if-nez v3, :cond_4

    .line 124
    .line 125
    :cond_3
    invoke-static {v4, v5, v4, v14}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 126
    .line 127
    .line 128
    :cond_4
    sget-object v15, Lv3/j;->d:Lv3/h;

    .line 129
    .line 130
    invoke-static {v15, v2, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 131
    .line 132
    .line 133
    iget-object v2, v0, Ltz/i;->a:Ltz/g;

    .line 134
    .line 135
    iget-boolean v3, v0, Ltz/i;->c:Z

    .line 136
    .line 137
    instance-of v4, v2, Ltz/e;

    .line 138
    .line 139
    const/16 v24, 0x0

    .line 140
    .line 141
    if-eqz v4, :cond_5

    .line 142
    .line 143
    move-object v4, v2

    .line 144
    check-cast v4, Ltz/e;

    .line 145
    .line 146
    goto :goto_3

    .line 147
    :cond_5
    move-object/from16 v4, v24

    .line 148
    .line 149
    :goto_3
    if-nez v4, :cond_6

    .line 150
    .line 151
    const v4, 0x5f459104

    .line 152
    .line 153
    .line 154
    invoke-virtual {v5, v4}, Ll2/t;->Y(I)V

    .line 155
    .line 156
    .line 157
    invoke-virtual {v5, v9}, Ll2/t;->q(Z)V

    .line 158
    .line 159
    .line 160
    move-object v8, v2

    .line 161
    move/from16 v25, v3

    .line 162
    .line 163
    goto :goto_4

    .line 164
    :cond_6
    const v6, 0x5f459105

    .line 165
    .line 166
    .line 167
    invoke-virtual {v5, v6}, Ll2/t;->Y(I)V

    .line 168
    .line 169
    .line 170
    move v6, v3

    .line 171
    iget-boolean v3, v0, Ltz/i;->c:Z

    .line 172
    .line 173
    move v7, v6

    .line 174
    const/4 v6, 0x0

    .line 175
    move/from16 v16, v7

    .line 176
    .line 177
    const/4 v7, 0x4

    .line 178
    move-object/from16 v17, v2

    .line 179
    .line 180
    move-object v2, v4

    .line 181
    const/4 v4, 0x0

    .line 182
    move/from16 v25, v16

    .line 183
    .line 184
    move-object/from16 v8, v17

    .line 185
    .line 186
    invoke-static/range {v2 .. v7}, Luz/g;->d(Ltz/e;ZZLl2/o;II)V

    .line 187
    .line 188
    .line 189
    invoke-virtual {v5, v9}, Ll2/t;->q(Z)V

    .line 190
    .line 191
    .line 192
    :goto_4
    const/high16 v2, 0x3f800000    # 1.0f

    .line 193
    .line 194
    invoke-static {v10, v2}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 195
    .line 196
    .line 197
    move-result-object v2

    .line 198
    sget-object v3, Lx2/c;->o:Lx2/i;

    .line 199
    .line 200
    sget-object v4, Lk1/j;->g:Lk1/f;

    .line 201
    .line 202
    const/16 v6, 0x36

    .line 203
    .line 204
    invoke-static {v4, v3, v5, v6}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 205
    .line 206
    .line 207
    move-result-object v3

    .line 208
    iget-wide v6, v5, Ll2/t;->T:J

    .line 209
    .line 210
    invoke-static {v6, v7}, Ljava/lang/Long;->hashCode(J)I

    .line 211
    .line 212
    .line 213
    move-result v4

    .line 214
    invoke-virtual {v5}, Ll2/t;->m()Ll2/p1;

    .line 215
    .line 216
    .line 217
    move-result-object v6

    .line 218
    invoke-static {v5, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 219
    .line 220
    .line 221
    move-result-object v2

    .line 222
    invoke-virtual {v5}, Ll2/t;->c0()V

    .line 223
    .line 224
    .line 225
    iget-boolean v7, v5, Ll2/t;->S:Z

    .line 226
    .line 227
    if-eqz v7, :cond_7

    .line 228
    .line 229
    invoke-virtual {v5, v11}, Ll2/t;->l(Lay0/a;)V

    .line 230
    .line 231
    .line 232
    goto :goto_5

    .line 233
    :cond_7
    invoke-virtual {v5}, Ll2/t;->m0()V

    .line 234
    .line 235
    .line 236
    :goto_5
    invoke-static {v12, v3, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 237
    .line 238
    .line 239
    invoke-static {v13, v6, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 240
    .line 241
    .line 242
    iget-boolean v3, v5, Ll2/t;->S:Z

    .line 243
    .line 244
    if-nez v3, :cond_8

    .line 245
    .line 246
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 247
    .line 248
    .line 249
    move-result-object v3

    .line 250
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 251
    .line 252
    .line 253
    move-result-object v6

    .line 254
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 255
    .line 256
    .line 257
    move-result v3

    .line 258
    if-nez v3, :cond_9

    .line 259
    .line 260
    :cond_8
    invoke-static {v4, v5, v4, v14}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 261
    .line 262
    .line 263
    :cond_9
    invoke-static {v15, v2, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 264
    .line 265
    .line 266
    instance-of v2, v8, Ltz/e;

    .line 267
    .line 268
    if-eqz v2, :cond_a

    .line 269
    .line 270
    move-object v3, v8

    .line 271
    check-cast v3, Ltz/e;

    .line 272
    .line 273
    goto :goto_6

    .line 274
    :cond_a
    move-object/from16 v3, v24

    .line 275
    .line 276
    :goto_6
    if-eqz v3, :cond_b

    .line 277
    .line 278
    iget-object v3, v3, Ltz/e;->a:Ljava/lang/String;

    .line 279
    .line 280
    goto :goto_7

    .line 281
    :cond_b
    move-object/from16 v3, v24

    .line 282
    .line 283
    :goto_7
    if-nez v3, :cond_c

    .line 284
    .line 285
    const v3, -0x2008ce39

    .line 286
    .line 287
    .line 288
    const v4, 0x7f1202bd

    .line 289
    .line 290
    .line 291
    invoke-static {v3, v4, v5, v5, v9}, Lvj/b;->g(IILl2/t;Ll2/t;Z)Ljava/lang/String;

    .line 292
    .line 293
    .line 294
    move-result-object v3

    .line 295
    goto :goto_8

    .line 296
    :cond_c
    const v4, -0x2008d466

    .line 297
    .line 298
    .line 299
    invoke-virtual {v5, v4}, Ll2/t;->Y(I)V

    .line 300
    .line 301
    .line 302
    invoke-virtual {v5, v9}, Ll2/t;->q(Z)V

    .line 303
    .line 304
    .line 305
    :goto_8
    if-eqz v25, :cond_d

    .line 306
    .line 307
    const v4, -0x2008c03d

    .line 308
    .line 309
    .line 310
    invoke-virtual {v5, v4}, Ll2/t;->Y(I)V

    .line 311
    .line 312
    .line 313
    sget-object v4, Lj91/h;->a:Ll2/u2;

    .line 314
    .line 315
    invoke-virtual {v5, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 316
    .line 317
    .line 318
    move-result-object v4

    .line 319
    check-cast v4, Lj91/e;

    .line 320
    .line 321
    invoke-virtual {v4}, Lj91/e;->e()J

    .line 322
    .line 323
    .line 324
    move-result-wide v6

    .line 325
    :goto_9
    invoke-virtual {v5, v9}, Ll2/t;->q(Z)V

    .line 326
    .line 327
    .line 328
    goto :goto_a

    .line 329
    :cond_d
    const v4, -0x2008bbde

    .line 330
    .line 331
    .line 332
    invoke-virtual {v5, v4}, Ll2/t;->Y(I)V

    .line 333
    .line 334
    .line 335
    sget-object v4, Lj91/h;->a:Ll2/u2;

    .line 336
    .line 337
    invoke-virtual {v5, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 338
    .line 339
    .line 340
    move-result-object v4

    .line 341
    check-cast v4, Lj91/e;

    .line 342
    .line 343
    invoke-virtual {v4}, Lj91/e;->q()J

    .line 344
    .line 345
    .line 346
    move-result-wide v6

    .line 347
    goto :goto_9

    .line 348
    :goto_a
    sget-object v4, Lj91/j;->a:Ll2/u2;

    .line 349
    .line 350
    invoke-virtual {v5, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 351
    .line 352
    .line 353
    move-result-object v8

    .line 354
    check-cast v8, Lj91/f;

    .line 355
    .line 356
    invoke-virtual {v8}, Lj91/f;->k()Lg4/p0;

    .line 357
    .line 358
    .line 359
    move-result-object v8

    .line 360
    sget-object v11, Lj91/a;->a:Ll2/u2;

    .line 361
    .line 362
    invoke-virtual {v5, v11}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 363
    .line 364
    .line 365
    move-result-object v11

    .line 366
    check-cast v11, Lj91/c;

    .line 367
    .line 368
    iget v13, v11, Lj91/c;->c:F

    .line 369
    .line 370
    const/4 v14, 0x0

    .line 371
    const/16 v15, 0xb

    .line 372
    .line 373
    const/4 v11, 0x0

    .line 374
    const/4 v12, 0x0

    .line 375
    invoke-static/range {v10 .. v15}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 376
    .line 377
    .line 378
    move-result-object v11

    .line 379
    const-string v12, "battery_charging_card_battery_state"

    .line 380
    .line 381
    invoke-static {v11, v12}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 382
    .line 383
    .line 384
    move-result-object v11

    .line 385
    const/16 v22, 0x6000

    .line 386
    .line 387
    const v23, 0xbff0

    .line 388
    .line 389
    .line 390
    move v12, v2

    .line 391
    move-object v2, v3

    .line 392
    move-object/from16 v20, v5

    .line 393
    .line 394
    move-wide v5, v6

    .line 395
    move-object v3, v8

    .line 396
    const-wide/16 v7, 0x0

    .line 397
    .line 398
    move v13, v9

    .line 399
    const/4 v9, 0x0

    .line 400
    move-object v14, v4

    .line 401
    move-object v15, v10

    .line 402
    move-object v4, v11

    .line 403
    const-wide/16 v10, 0x0

    .line 404
    .line 405
    move/from16 v16, v12

    .line 406
    .line 407
    const/4 v12, 0x0

    .line 408
    move/from16 v17, v13

    .line 409
    .line 410
    const/4 v13, 0x0

    .line 411
    move-object/from16 v18, v14

    .line 412
    .line 413
    move-object/from16 v19, v15

    .line 414
    .line 415
    const-wide/16 v14, 0x0

    .line 416
    .line 417
    move/from16 v21, v16

    .line 418
    .line 419
    const/16 v16, 0x0

    .line 420
    .line 421
    move/from16 v26, v17

    .line 422
    .line 423
    const/16 v17, 0x0

    .line 424
    .line 425
    move-object/from16 v27, v18

    .line 426
    .line 427
    const/16 v18, 0x1

    .line 428
    .line 429
    move-object/from16 v28, v19

    .line 430
    .line 431
    const/16 v19, 0x0

    .line 432
    .line 433
    move/from16 v29, v21

    .line 434
    .line 435
    const/16 v21, 0x0

    .line 436
    .line 437
    move/from16 v1, v26

    .line 438
    .line 439
    move-object/from16 v30, v28

    .line 440
    .line 441
    invoke-static/range {v2 .. v23}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 442
    .line 443
    .line 444
    move-object/from16 v5, v20

    .line 445
    .line 446
    if-eqz v25, :cond_10

    .line 447
    .line 448
    const v2, 0x1ef6f72e

    .line 449
    .line 450
    .line 451
    invoke-virtual {v5, v2}, Ll2/t;->Y(I)V

    .line 452
    .line 453
    .line 454
    iget-object v3, v0, Ltz/i;->f:Ltz/h;

    .line 455
    .line 456
    if-eqz v3, :cond_e

    .line 457
    .line 458
    iget-object v3, v3, Ltz/h;->b:Ljava/lang/String;

    .line 459
    .line 460
    move-object/from16 v24, v3

    .line 461
    .line 462
    :cond_e
    if-nez v24, :cond_f

    .line 463
    .line 464
    const v2, 0x1ef6f72d

    .line 465
    .line 466
    .line 467
    invoke-virtual {v5, v2}, Ll2/t;->Y(I)V

    .line 468
    .line 469
    .line 470
    :goto_b
    invoke-virtual {v5, v1}, Ll2/t;->q(Z)V

    .line 471
    .line 472
    .line 473
    goto :goto_c

    .line 474
    :cond_f
    invoke-virtual {v5, v2}, Ll2/t;->Y(I)V

    .line 475
    .line 476
    .line 477
    const v2, 0x7f12041c

    .line 478
    .line 479
    .line 480
    filled-new-array/range {v24 .. v24}, [Ljava/lang/Object;

    .line 481
    .line 482
    .line 483
    move-result-object v3

    .line 484
    invoke-static {v2, v3, v5}, Ljp/ga;->c(I[Ljava/lang/Object;Ll2/o;)Ljava/lang/String;

    .line 485
    .line 486
    .line 487
    move-result-object v2

    .line 488
    move-object/from16 v14, v27

    .line 489
    .line 490
    invoke-virtual {v5, v14}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 491
    .line 492
    .line 493
    move-result-object v3

    .line 494
    check-cast v3, Lj91/f;

    .line 495
    .line 496
    invoke-virtual {v3}, Lj91/f;->m()Lg4/p0;

    .line 497
    .line 498
    .line 499
    move-result-object v3

    .line 500
    const-string v4, "battery_charging_card_time"

    .line 501
    .line 502
    move-object/from16 v10, v30

    .line 503
    .line 504
    invoke-static {v10, v4}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 505
    .line 506
    .line 507
    move-result-object v4

    .line 508
    const/16 v22, 0x6180

    .line 509
    .line 510
    const v23, 0xaff8

    .line 511
    .line 512
    .line 513
    move-object/from16 v20, v5

    .line 514
    .line 515
    const-wide/16 v5, 0x0

    .line 516
    .line 517
    const-wide/16 v7, 0x0

    .line 518
    .line 519
    const/4 v9, 0x0

    .line 520
    const-wide/16 v10, 0x0

    .line 521
    .line 522
    const/4 v12, 0x0

    .line 523
    const/4 v13, 0x0

    .line 524
    const-wide/16 v14, 0x0

    .line 525
    .line 526
    const/16 v16, 0x2

    .line 527
    .line 528
    const/16 v17, 0x0

    .line 529
    .line 530
    const/16 v18, 0x1

    .line 531
    .line 532
    const/16 v19, 0x0

    .line 533
    .line 534
    const/16 v21, 0x180

    .line 535
    .line 536
    invoke-static/range {v2 .. v23}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 537
    .line 538
    .line 539
    move-object/from16 v5, v20

    .line 540
    .line 541
    goto :goto_b

    .line 542
    :goto_c
    invoke-virtual {v5, v1}, Ll2/t;->q(Z)V

    .line 543
    .line 544
    .line 545
    :goto_d
    const/4 v1, 0x1

    .line 546
    goto/16 :goto_10

    .line 547
    .line 548
    :cond_10
    move-object/from16 v14, v27

    .line 549
    .line 550
    move-object/from16 v10, v30

    .line 551
    .line 552
    const v2, 0x1efdcfa6

    .line 553
    .line 554
    .line 555
    invoke-virtual {v5, v2}, Ll2/t;->Y(I)V

    .line 556
    .line 557
    .line 558
    iget-object v2, v0, Ltz/i;->b:Ljava/lang/String;

    .line 559
    .line 560
    if-eqz v29, :cond_11

    .line 561
    .line 562
    const v3, -0x2008439c

    .line 563
    .line 564
    .line 565
    invoke-virtual {v5, v3}, Ll2/t;->Y(I)V

    .line 566
    .line 567
    .line 568
    sget-object v3, Lj91/h;->a:Ll2/u2;

    .line 569
    .line 570
    invoke-virtual {v5, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 571
    .line 572
    .line 573
    move-result-object v3

    .line 574
    check-cast v3, Lj91/e;

    .line 575
    .line 576
    invoke-virtual {v3}, Lj91/e;->s()J

    .line 577
    .line 578
    .line 579
    move-result-wide v3

    .line 580
    :goto_e
    invoke-virtual {v5, v1}, Ll2/t;->q(Z)V

    .line 581
    .line 582
    .line 583
    goto :goto_f

    .line 584
    :cond_11
    const v3, -0x20083f1b

    .line 585
    .line 586
    .line 587
    invoke-virtual {v5, v3}, Ll2/t;->Y(I)V

    .line 588
    .line 589
    .line 590
    sget-object v3, Lj91/h;->a:Ll2/u2;

    .line 591
    .line 592
    invoke-virtual {v5, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 593
    .line 594
    .line 595
    move-result-object v3

    .line 596
    check-cast v3, Lj91/e;

    .line 597
    .line 598
    invoke-virtual {v3}, Lj91/e;->r()J

    .line 599
    .line 600
    .line 601
    move-result-wide v3

    .line 602
    goto :goto_e

    .line 603
    :goto_f
    invoke-virtual {v5, v14}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 604
    .line 605
    .line 606
    move-result-object v6

    .line 607
    check-cast v6, Lj91/f;

    .line 608
    .line 609
    invoke-virtual {v6}, Lj91/f;->e()Lg4/p0;

    .line 610
    .line 611
    .line 612
    move-result-object v6

    .line 613
    const-string v7, "battery_charging_card_charging_state"

    .line 614
    .line 615
    invoke-static {v10, v7}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 616
    .line 617
    .line 618
    move-result-object v7

    .line 619
    const/16 v22, 0x6180

    .line 620
    .line 621
    const v23, 0xaff0

    .line 622
    .line 623
    .line 624
    move-object/from16 v20, v5

    .line 625
    .line 626
    move-wide/from16 v31, v3

    .line 627
    .line 628
    move-object v3, v6

    .line 629
    move-wide/from16 v5, v31

    .line 630
    .line 631
    move-object v4, v7

    .line 632
    const-wide/16 v7, 0x0

    .line 633
    .line 634
    const/4 v9, 0x0

    .line 635
    const-wide/16 v10, 0x0

    .line 636
    .line 637
    const/4 v12, 0x0

    .line 638
    const/4 v13, 0x0

    .line 639
    const-wide/16 v14, 0x0

    .line 640
    .line 641
    const/16 v16, 0x2

    .line 642
    .line 643
    const/16 v17, 0x0

    .line 644
    .line 645
    const/16 v18, 0x1

    .line 646
    .line 647
    const/16 v19, 0x0

    .line 648
    .line 649
    const/16 v21, 0x180

    .line 650
    .line 651
    invoke-static/range {v2 .. v23}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 652
    .line 653
    .line 654
    move-object/from16 v5, v20

    .line 655
    .line 656
    invoke-virtual {v5, v1}, Ll2/t;->q(Z)V

    .line 657
    .line 658
    .line 659
    goto :goto_d

    .line 660
    :goto_10
    invoke-virtual {v5, v1}, Ll2/t;->q(Z)V

    .line 661
    .line 662
    .line 663
    invoke-virtual {v5, v1}, Ll2/t;->q(Z)V

    .line 664
    .line 665
    .line 666
    goto :goto_11

    .line 667
    :cond_12
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 668
    .line 669
    .line 670
    :goto_11
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 671
    .line 672
    .line 673
    move-result-object v1

    .line 674
    if-eqz v1, :cond_13

    .line 675
    .line 676
    new-instance v2, Luz/a;

    .line 677
    .line 678
    const/4 v3, 0x1

    .line 679
    move/from16 v4, p2

    .line 680
    .line 681
    invoke-direct {v2, v0, v4, v3}, Luz/a;-><init>(Ltz/i;II)V

    .line 682
    .line 683
    .line 684
    iput-object v2, v1, Ll2/u1;->d:Lay0/n;

    .line 685
    .line 686
    :cond_13
    return-void
.end method

.method public static final n(Ltz/i;Lay0/a;Lay0/a;Ll2/o;I)V
    .locals 22

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v9, p3

    .line 4
    .line 5
    check-cast v9, Ll2/t;

    .line 6
    .line 7
    const v0, -0x66e73b8c

    .line 8
    .line 9
    .line 10
    invoke-virtual {v9, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v9, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

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
    or-int v0, p4, v0

    .line 23
    .line 24
    move-object/from16 v13, p1

    .line 25
    .line 26
    invoke-virtual {v9, v13}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    if-eqz v2, :cond_1

    .line 31
    .line 32
    const/16 v2, 0x20

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_1
    const/16 v2, 0x10

    .line 36
    .line 37
    :goto_1
    or-int/2addr v0, v2

    .line 38
    move-object/from16 v14, p2

    .line 39
    .line 40
    invoke-virtual {v9, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    if-eqz v2, :cond_2

    .line 45
    .line 46
    const/16 v2, 0x100

    .line 47
    .line 48
    goto :goto_2

    .line 49
    :cond_2
    const/16 v2, 0x80

    .line 50
    .line 51
    :goto_2
    or-int/2addr v0, v2

    .line 52
    and-int/lit16 v2, v0, 0x93

    .line 53
    .line 54
    const/16 v3, 0x92

    .line 55
    .line 56
    const/4 v4, 0x0

    .line 57
    if-eq v2, v3, :cond_3

    .line 58
    .line 59
    const/4 v2, 0x1

    .line 60
    goto :goto_3

    .line 61
    :cond_3
    move v2, v4

    .line 62
    :goto_3
    and-int/lit8 v3, v0, 0x1

    .line 63
    .line 64
    invoke-virtual {v9, v3, v2}, Ll2/t;->O(IZ)Z

    .line 65
    .line 66
    .line 67
    move-result v2

    .line 68
    if-eqz v2, :cond_e

    .line 69
    .line 70
    sget-object v2, Lk1/j;->c:Lk1/e;

    .line 71
    .line 72
    sget-object v3, Lx2/c;->p:Lx2/h;

    .line 73
    .line 74
    invoke-static {v2, v3, v9, v4}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 75
    .line 76
    .line 77
    move-result-object v2

    .line 78
    iget-wide v5, v9, Ll2/t;->T:J

    .line 79
    .line 80
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 81
    .line 82
    .line 83
    move-result v3

    .line 84
    invoke-virtual {v9}, Ll2/t;->m()Ll2/p1;

    .line 85
    .line 86
    .line 87
    move-result-object v5

    .line 88
    sget-object v6, Lx2/p;->b:Lx2/p;

    .line 89
    .line 90
    invoke-static {v9, v6}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 91
    .line 92
    .line 93
    move-result-object v7

    .line 94
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 95
    .line 96
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 97
    .line 98
    .line 99
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 100
    .line 101
    invoke-virtual {v9}, Ll2/t;->c0()V

    .line 102
    .line 103
    .line 104
    iget-boolean v10, v9, Ll2/t;->S:Z

    .line 105
    .line 106
    if-eqz v10, :cond_4

    .line 107
    .line 108
    invoke-virtual {v9, v8}, Ll2/t;->l(Lay0/a;)V

    .line 109
    .line 110
    .line 111
    goto :goto_4

    .line 112
    :cond_4
    invoke-virtual {v9}, Ll2/t;->m0()V

    .line 113
    .line 114
    .line 115
    :goto_4
    sget-object v10, Lv3/j;->g:Lv3/h;

    .line 116
    .line 117
    invoke-static {v10, v2, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 118
    .line 119
    .line 120
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 121
    .line 122
    invoke-static {v2, v5, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 123
    .line 124
    .line 125
    sget-object v5, Lv3/j;->j:Lv3/h;

    .line 126
    .line 127
    iget-boolean v11, v9, Ll2/t;->S:Z

    .line 128
    .line 129
    if-nez v11, :cond_5

    .line 130
    .line 131
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object v11

    .line 135
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 136
    .line 137
    .line 138
    move-result-object v12

    .line 139
    invoke-static {v11, v12}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 140
    .line 141
    .line 142
    move-result v11

    .line 143
    if-nez v11, :cond_6

    .line 144
    .line 145
    :cond_5
    invoke-static {v3, v9, v3, v5}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 146
    .line 147
    .line 148
    :cond_6
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 149
    .line 150
    invoke-static {v3, v7, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 151
    .line 152
    .line 153
    const/high16 v7, 0x3f800000    # 1.0f

    .line 154
    .line 155
    invoke-static {v6, v7}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 156
    .line 157
    .line 158
    move-result-object v7

    .line 159
    sget-object v11, Lx2/c;->n:Lx2/i;

    .line 160
    .line 161
    sget-object v12, Lk1/j;->g:Lk1/f;

    .line 162
    .line 163
    const/16 v4, 0x36

    .line 164
    .line 165
    invoke-static {v12, v11, v9, v4}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 166
    .line 167
    .line 168
    move-result-object v4

    .line 169
    iget-wide v11, v9, Ll2/t;->T:J

    .line 170
    .line 171
    invoke-static {v11, v12}, Ljava/lang/Long;->hashCode(J)I

    .line 172
    .line 173
    .line 174
    move-result v11

    .line 175
    invoke-virtual {v9}, Ll2/t;->m()Ll2/p1;

    .line 176
    .line 177
    .line 178
    move-result-object v12

    .line 179
    invoke-static {v9, v7}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 180
    .line 181
    .line 182
    move-result-object v7

    .line 183
    invoke-virtual {v9}, Ll2/t;->c0()V

    .line 184
    .line 185
    .line 186
    iget-boolean v15, v9, Ll2/t;->S:Z

    .line 187
    .line 188
    if-eqz v15, :cond_7

    .line 189
    .line 190
    invoke-virtual {v9, v8}, Ll2/t;->l(Lay0/a;)V

    .line 191
    .line 192
    .line 193
    goto :goto_5

    .line 194
    :cond_7
    invoke-virtual {v9}, Ll2/t;->m0()V

    .line 195
    .line 196
    .line 197
    :goto_5
    invoke-static {v10, v4, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 198
    .line 199
    .line 200
    invoke-static {v2, v12, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 201
    .line 202
    .line 203
    iget-boolean v2, v9, Ll2/t;->S:Z

    .line 204
    .line 205
    if-nez v2, :cond_8

    .line 206
    .line 207
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 208
    .line 209
    .line 210
    move-result-object v2

    .line 211
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 212
    .line 213
    .line 214
    move-result-object v4

    .line 215
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 216
    .line 217
    .line 218
    move-result v2

    .line 219
    if-nez v2, :cond_9

    .line 220
    .line 221
    :cond_8
    invoke-static {v11, v9, v11, v5}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 222
    .line 223
    .line 224
    :cond_9
    invoke-static {v3, v7, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 225
    .line 226
    .line 227
    and-int/lit8 v2, v0, 0xe

    .line 228
    .line 229
    invoke-static {v1, v9, v2}, Luz/g;->m(Ltz/i;Ll2/o;I)V

    .line 230
    .line 231
    .line 232
    const/4 v2, 0x1

    .line 233
    invoke-virtual {v9, v2}, Ll2/t;->q(Z)V

    .line 234
    .line 235
    .line 236
    iget-object v15, v1, Ltz/i;->f:Ltz/h;

    .line 237
    .line 238
    if-nez v15, :cond_a

    .line 239
    .line 240
    const v2, -0x100d22b2

    .line 241
    .line 242
    .line 243
    invoke-virtual {v9, v2}, Ll2/t;->Y(I)V

    .line 244
    .line 245
    .line 246
    const/4 v2, 0x0

    .line 247
    invoke-virtual {v9, v2}, Ll2/t;->q(Z)V

    .line 248
    .line 249
    .line 250
    move/from16 p3, v0

    .line 251
    .line 252
    move v0, v2

    .line 253
    move-object v10, v9

    .line 254
    goto :goto_6

    .line 255
    :cond_a
    const/4 v2, 0x0

    .line 256
    const v3, -0x100d22b1

    .line 257
    .line 258
    .line 259
    invoke-virtual {v9, v3}, Ll2/t;->Y(I)V

    .line 260
    .line 261
    .line 262
    iget v3, v15, Ltz/h;->a:I

    .line 263
    .line 264
    iget-object v4, v15, Ltz/h;->c:Ljava/lang/Integer;

    .line 265
    .line 266
    iget-boolean v5, v1, Ltz/i;->c:Z

    .line 267
    .line 268
    move-object/from16 v16, v6

    .line 269
    .line 270
    iget-boolean v6, v1, Ltz/i;->j:Z

    .line 271
    .line 272
    sget-object v7, Lj91/a;->a:Ll2/u2;

    .line 273
    .line 274
    invoke-virtual {v9, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 275
    .line 276
    .line 277
    move-result-object v7

    .line 278
    check-cast v7, Lj91/c;

    .line 279
    .line 280
    iget v7, v7, Lj91/c;->c:F

    .line 281
    .line 282
    const/16 v20, 0x0

    .line 283
    .line 284
    const/16 v21, 0xd

    .line 285
    .line 286
    const/16 v17, 0x0

    .line 287
    .line 288
    const/16 v19, 0x0

    .line 289
    .line 290
    move/from16 v18, v7

    .line 291
    .line 292
    invoke-static/range {v16 .. v21}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 293
    .line 294
    .line 295
    move-result-object v7

    .line 296
    const-string v8, "battery_charging_card_strip"

    .line 297
    .line 298
    invoke-static {v7, v8}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 299
    .line 300
    .line 301
    move-result-object v7

    .line 302
    const/4 v11, 0x0

    .line 303
    const/16 v12, 0xe0

    .line 304
    .line 305
    move v8, v2

    .line 306
    move-object v2, v7

    .line 307
    const/4 v7, 0x0

    .line 308
    move v10, v8

    .line 309
    const/4 v8, 0x0

    .line 310
    move/from16 v16, v10

    .line 311
    .line 312
    move-object v10, v9

    .line 313
    const/4 v9, 0x0

    .line 314
    move/from16 p3, v0

    .line 315
    .line 316
    move/from16 v0, v16

    .line 317
    .line 318
    invoke-static/range {v2 .. v12}, Lxf0/t;->a(Lx2/s;ILjava/lang/Integer;ZZLjava/lang/Integer;ZZLl2/o;II)V

    .line 319
    .line 320
    .line 321
    shl-int/lit8 v2, p3, 0x3

    .line 322
    .line 323
    and-int/lit8 v2, v2, 0x70

    .line 324
    .line 325
    invoke-static {v15, v1, v10, v2}, Luz/g;->i(Ltz/h;Ltz/i;Ll2/o;I)V

    .line 326
    .line 327
    .line 328
    invoke-virtual {v10, v0}, Ll2/t;->q(Z)V

    .line 329
    .line 330
    .line 331
    :goto_6
    iget-boolean v2, v1, Ltz/i;->p:Z

    .line 332
    .line 333
    if-eqz v2, :cond_d

    .line 334
    .line 335
    iget-boolean v2, v1, Ltz/i;->r:Z

    .line 336
    .line 337
    if-eqz v2, :cond_d

    .line 338
    .line 339
    const v2, 0x28c60e83

    .line 340
    .line 341
    .line 342
    invoke-virtual {v10, v2}, Ll2/t;->Y(I)V

    .line 343
    .line 344
    .line 345
    iget-object v2, v1, Ltz/i;->m:Ljava/lang/String;

    .line 346
    .line 347
    if-nez v2, :cond_b

    .line 348
    .line 349
    const v2, -0x10043e22

    .line 350
    .line 351
    .line 352
    invoke-virtual {v10, v2}, Ll2/t;->Y(I)V

    .line 353
    .line 354
    .line 355
    :goto_7
    invoke-virtual {v10, v0}, Ll2/t;->q(Z)V

    .line 356
    .line 357
    .line 358
    goto :goto_9

    .line 359
    :cond_b
    const v3, -0x10043e21

    .line 360
    .line 361
    .line 362
    invoke-virtual {v10, v3}, Ll2/t;->Y(I)V

    .line 363
    .line 364
    .line 365
    iget-object v3, v1, Ltz/i;->k:Ljava/lang/String;

    .line 366
    .line 367
    iget-object v4, v1, Ltz/i;->l:Ljava/lang/String;

    .line 368
    .line 369
    iget-object v5, v1, Ltz/i;->n:Ljava/lang/String;

    .line 370
    .line 371
    iget-boolean v6, v1, Ltz/i;->c:Z

    .line 372
    .line 373
    if-nez v6, :cond_c

    .line 374
    .line 375
    iget-boolean v6, v1, Ltz/i;->j:Z

    .line 376
    .line 377
    if-nez v6, :cond_c

    .line 378
    .line 379
    const/4 v6, 0x1

    .line 380
    goto :goto_8

    .line 381
    :cond_c
    move v6, v0

    .line 382
    :goto_8
    shl-int/lit8 v7, p3, 0xc

    .line 383
    .line 384
    const/high16 v8, 0x3f0000

    .line 385
    .line 386
    and-int/2addr v7, v8

    .line 387
    move-object v9, v10

    .line 388
    move-object v8, v14

    .line 389
    move v10, v7

    .line 390
    move-object v7, v13

    .line 391
    invoke-static/range {v2 .. v10}, Luz/g;->o(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLay0/a;Lay0/a;Ll2/o;I)V

    .line 392
    .line 393
    .line 394
    move-object v10, v9

    .line 395
    goto :goto_7

    .line 396
    :goto_9
    invoke-virtual {v10, v0}, Ll2/t;->q(Z)V

    .line 397
    .line 398
    .line 399
    const/4 v2, 0x1

    .line 400
    goto :goto_a

    .line 401
    :cond_d
    const v2, -0x1076641c

    .line 402
    .line 403
    .line 404
    invoke-virtual {v10, v2}, Ll2/t;->Y(I)V

    .line 405
    .line 406
    .line 407
    goto :goto_9

    .line 408
    :goto_a
    invoke-virtual {v10, v2}, Ll2/t;->q(Z)V

    .line 409
    .line 410
    .line 411
    goto :goto_b

    .line 412
    :cond_e
    move-object v10, v9

    .line 413
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 414
    .line 415
    .line 416
    :goto_b
    invoke-virtual {v10}, Ll2/t;->s()Ll2/u1;

    .line 417
    .line 418
    .line 419
    move-result-object v6

    .line 420
    if-eqz v6, :cond_f

    .line 421
    .line 422
    new-instance v0, Luz/f;

    .line 423
    .line 424
    const/4 v5, 0x0

    .line 425
    move-object/from16 v2, p1

    .line 426
    .line 427
    move-object/from16 v3, p2

    .line 428
    .line 429
    move/from16 v4, p4

    .line 430
    .line 431
    invoke-direct/range {v0 .. v5}, Luz/f;-><init>(Ltz/i;Lay0/a;Lay0/a;II)V

    .line 432
    .line 433
    .line 434
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 435
    .line 436
    :cond_f
    return-void
.end method

.method public static final o(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLay0/a;Lay0/a;Ll2/o;I)V
    .locals 34

    .line 1
    move-object/from16 v2, p1

    .line 2
    .line 3
    move-object/from16 v3, p2

    .line 4
    .line 5
    move-object/from16 v4, p3

    .line 6
    .line 7
    move/from16 v0, p4

    .line 8
    .line 9
    move-object/from16 v1, p5

    .line 10
    .line 11
    move/from16 v14, p8

    .line 12
    .line 13
    move-object/from16 v12, p7

    .line 14
    .line 15
    check-cast v12, Ll2/t;

    .line 16
    .line 17
    const v5, 0x505a36ea

    .line 18
    .line 19
    .line 20
    invoke-virtual {v12, v5}, Ll2/t;->a0(I)Ll2/t;

    .line 21
    .line 22
    .line 23
    and-int/lit8 v5, v14, 0x6

    .line 24
    .line 25
    if-nez v5, :cond_1

    .line 26
    .line 27
    move-object/from16 v5, p0

    .line 28
    .line 29
    invoke-virtual {v12, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v6

    .line 33
    if-eqz v6, :cond_0

    .line 34
    .line 35
    const/4 v6, 0x4

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    const/4 v6, 0x2

    .line 38
    :goto_0
    or-int/2addr v6, v14

    .line 39
    goto :goto_1

    .line 40
    :cond_1
    move-object/from16 v5, p0

    .line 41
    .line 42
    move v6, v14

    .line 43
    :goto_1
    and-int/lit8 v7, v14, 0x30

    .line 44
    .line 45
    if-nez v7, :cond_3

    .line 46
    .line 47
    invoke-virtual {v12, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result v7

    .line 51
    if-eqz v7, :cond_2

    .line 52
    .line 53
    const/16 v7, 0x20

    .line 54
    .line 55
    goto :goto_2

    .line 56
    :cond_2
    const/16 v7, 0x10

    .line 57
    .line 58
    :goto_2
    or-int/2addr v6, v7

    .line 59
    :cond_3
    and-int/lit16 v7, v14, 0x180

    .line 60
    .line 61
    if-nez v7, :cond_5

    .line 62
    .line 63
    invoke-virtual {v12, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result v7

    .line 67
    if-eqz v7, :cond_4

    .line 68
    .line 69
    const/16 v7, 0x100

    .line 70
    .line 71
    goto :goto_3

    .line 72
    :cond_4
    const/16 v7, 0x80

    .line 73
    .line 74
    :goto_3
    or-int/2addr v6, v7

    .line 75
    :cond_5
    and-int/lit16 v7, v14, 0xc00

    .line 76
    .line 77
    if-nez v7, :cond_7

    .line 78
    .line 79
    invoke-virtual {v12, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    move-result v7

    .line 83
    if-eqz v7, :cond_6

    .line 84
    .line 85
    const/16 v7, 0x800

    .line 86
    .line 87
    goto :goto_4

    .line 88
    :cond_6
    const/16 v7, 0x400

    .line 89
    .line 90
    :goto_4
    or-int/2addr v6, v7

    .line 91
    :cond_7
    and-int/lit16 v7, v14, 0x6000

    .line 92
    .line 93
    if-nez v7, :cond_9

    .line 94
    .line 95
    invoke-virtual {v12, v0}, Ll2/t;->h(Z)Z

    .line 96
    .line 97
    .line 98
    move-result v7

    .line 99
    if-eqz v7, :cond_8

    .line 100
    .line 101
    const/16 v7, 0x4000

    .line 102
    .line 103
    goto :goto_5

    .line 104
    :cond_8
    const/16 v7, 0x2000

    .line 105
    .line 106
    :goto_5
    or-int/2addr v6, v7

    .line 107
    :cond_9
    const/high16 v7, 0x30000

    .line 108
    .line 109
    and-int/2addr v7, v14

    .line 110
    const/high16 v8, 0x20000

    .line 111
    .line 112
    if-nez v7, :cond_b

    .line 113
    .line 114
    invoke-virtual {v12, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 115
    .line 116
    .line 117
    move-result v7

    .line 118
    if-eqz v7, :cond_a

    .line 119
    .line 120
    move v7, v8

    .line 121
    goto :goto_6

    .line 122
    :cond_a
    const/high16 v7, 0x10000

    .line 123
    .line 124
    :goto_6
    or-int/2addr v6, v7

    .line 125
    :cond_b
    const/high16 v7, 0x180000

    .line 126
    .line 127
    and-int/2addr v7, v14

    .line 128
    if-nez v7, :cond_d

    .line 129
    .line 130
    move-object/from16 v7, p6

    .line 131
    .line 132
    invoke-virtual {v12, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    move-result v9

    .line 136
    if-eqz v9, :cond_c

    .line 137
    .line 138
    const/high16 v9, 0x100000

    .line 139
    .line 140
    goto :goto_7

    .line 141
    :cond_c
    const/high16 v9, 0x80000

    .line 142
    .line 143
    :goto_7
    or-int/2addr v6, v9

    .line 144
    goto :goto_8

    .line 145
    :cond_d
    move-object/from16 v7, p6

    .line 146
    .line 147
    :goto_8
    const v9, 0x92493

    .line 148
    .line 149
    .line 150
    and-int/2addr v9, v6

    .line 151
    const v10, 0x92492

    .line 152
    .line 153
    .line 154
    const/4 v11, 0x0

    .line 155
    if-eq v9, v10, :cond_e

    .line 156
    .line 157
    const/4 v9, 0x1

    .line 158
    goto :goto_9

    .line 159
    :cond_e
    move v9, v11

    .line 160
    :goto_9
    and-int/lit8 v10, v6, 0x1

    .line 161
    .line 162
    invoke-virtual {v12, v10, v9}, Ll2/t;->O(IZ)Z

    .line 163
    .line 164
    .line 165
    move-result v9

    .line 166
    if-eqz v9, :cond_27

    .line 167
    .line 168
    invoke-static {v12}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 169
    .line 170
    .line 171
    move-result-object v9

    .line 172
    iget v9, v9, Lj91/c;->d:F

    .line 173
    .line 174
    const/16 v19, 0x0

    .line 175
    .line 176
    const/16 v20, 0xd

    .line 177
    .line 178
    sget-object v15, Lx2/p;->b:Lx2/p;

    .line 179
    .line 180
    const/16 v16, 0x0

    .line 181
    .line 182
    const/16 v18, 0x0

    .line 183
    .line 184
    move/from16 v17, v9

    .line 185
    .line 186
    invoke-static/range {v15 .. v20}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 187
    .line 188
    .line 189
    move-result-object v9

    .line 190
    move-object v10, v15

    .line 191
    const/high16 v15, 0x3f800000    # 1.0f

    .line 192
    .line 193
    invoke-static {v9, v15}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 194
    .line 195
    .line 196
    move-result-object v9

    .line 197
    sget-object v13, Lk1/r0;->d:Lk1/r0;

    .line 198
    .line 199
    invoke-static {v9, v13}, Landroidx/compose/foundation/layout/a;->g(Lx2/s;Lk1/r0;)Lx2/s;

    .line 200
    .line 201
    .line 202
    move-result-object v16

    .line 203
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object v9

    .line 207
    sget-object v13, Ll2/n;->a:Ll2/x0;

    .line 208
    .line 209
    if-ne v9, v13, :cond_f

    .line 210
    .line 211
    invoke-static {v12}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->g(Ll2/t;)Li1/l;

    .line 212
    .line 213
    .line 214
    move-result-object v9

    .line 215
    :cond_f
    move-object/from16 v17, v9

    .line 216
    .line 217
    check-cast v17, Li1/l;

    .line 218
    .line 219
    const/high16 v9, 0x70000

    .line 220
    .line 221
    and-int/2addr v9, v6

    .line 222
    if-ne v9, v8, :cond_10

    .line 223
    .line 224
    const/4 v8, 0x1

    .line 225
    goto :goto_a

    .line 226
    :cond_10
    move v8, v11

    .line 227
    :goto_a
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 228
    .line 229
    .line 230
    move-result-object v9

    .line 231
    if-nez v8, :cond_11

    .line 232
    .line 233
    if-ne v9, v13, :cond_12

    .line 234
    .line 235
    :cond_11
    new-instance v9, Lp61/b;

    .line 236
    .line 237
    const/16 v8, 0xe

    .line 238
    .line 239
    invoke-direct {v9, v1, v8}, Lp61/b;-><init>(Lay0/a;I)V

    .line 240
    .line 241
    .line 242
    invoke-virtual {v12, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 243
    .line 244
    .line 245
    :cond_12
    move-object/from16 v21, v9

    .line 246
    .line 247
    check-cast v21, Lay0/a;

    .line 248
    .line 249
    const/16 v22, 0x1c

    .line 250
    .line 251
    const/16 v18, 0x0

    .line 252
    .line 253
    const/16 v19, 0x0

    .line 254
    .line 255
    const/16 v20, 0x0

    .line 256
    .line 257
    invoke-static/range {v16 .. v22}, Landroidx/compose/foundation/a;->d(Lx2/s;Li1/l;Le1/s0;ZLd4/i;Lay0/a;I)Lx2/s;

    .line 258
    .line 259
    .line 260
    move-result-object v8

    .line 261
    const-string v9, "battery_bi_di_charging_card_profile_section"

    .line 262
    .line 263
    invoke-static {v8, v9}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 264
    .line 265
    .line 266
    move-result-object v8

    .line 267
    sget-object v9, Lk1/j;->c:Lk1/e;

    .line 268
    .line 269
    sget-object v13, Lx2/c;->p:Lx2/h;

    .line 270
    .line 271
    invoke-static {v9, v13, v12, v11}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 272
    .line 273
    .line 274
    move-result-object v15

    .line 275
    iget-wide v0, v12, Ll2/t;->T:J

    .line 276
    .line 277
    invoke-static {v0, v1}, Ljava/lang/Long;->hashCode(J)I

    .line 278
    .line 279
    .line 280
    move-result v0

    .line 281
    invoke-virtual {v12}, Ll2/t;->m()Ll2/p1;

    .line 282
    .line 283
    .line 284
    move-result-object v1

    .line 285
    invoke-static {v12, v8}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 286
    .line 287
    .line 288
    move-result-object v8

    .line 289
    sget-object v17, Lv3/k;->m1:Lv3/j;

    .line 290
    .line 291
    invoke-virtual/range {v17 .. v17}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 292
    .line 293
    .line 294
    sget-object v11, Lv3/j;->b:Lv3/i;

    .line 295
    .line 296
    invoke-virtual {v12}, Ll2/t;->c0()V

    .line 297
    .line 298
    .line 299
    iget-boolean v2, v12, Ll2/t;->S:Z

    .line 300
    .line 301
    if-eqz v2, :cond_13

    .line 302
    .line 303
    invoke-virtual {v12, v11}, Ll2/t;->l(Lay0/a;)V

    .line 304
    .line 305
    .line 306
    goto :goto_b

    .line 307
    :cond_13
    invoke-virtual {v12}, Ll2/t;->m0()V

    .line 308
    .line 309
    .line 310
    :goto_b
    sget-object v2, Lv3/j;->g:Lv3/h;

    .line 311
    .line 312
    invoke-static {v2, v15, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 313
    .line 314
    .line 315
    sget-object v15, Lv3/j;->f:Lv3/h;

    .line 316
    .line 317
    invoke-static {v15, v1, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 318
    .line 319
    .line 320
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 321
    .line 322
    iget-boolean v3, v12, Ll2/t;->S:Z

    .line 323
    .line 324
    if-nez v3, :cond_14

    .line 325
    .line 326
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 327
    .line 328
    .line 329
    move-result-object v3

    .line 330
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 331
    .line 332
    .line 333
    move-result-object v4

    .line 334
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 335
    .line 336
    .line 337
    move-result v3

    .line 338
    if-nez v3, :cond_15

    .line 339
    .line 340
    :cond_14
    invoke-static {v0, v12, v0, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 341
    .line 342
    .line 343
    :cond_15
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 344
    .line 345
    invoke-static {v0, v8, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 346
    .line 347
    .line 348
    const/high16 v3, 0x3f800000    # 1.0f

    .line 349
    .line 350
    invoke-static {v10, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 351
    .line 352
    .line 353
    move-result-object v4

    .line 354
    const/4 v8, 0x6

    .line 355
    const/4 v5, 0x0

    .line 356
    invoke-static {v8, v5, v12, v4}, Li91/j0;->D(IILl2/o;Lx2/s;)V

    .line 357
    .line 358
    .line 359
    invoke-static {v10, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 360
    .line 361
    .line 362
    move-result-object v17

    .line 363
    invoke-static {v12}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 364
    .line 365
    .line 366
    move-result-object v3

    .line 367
    iget v3, v3, Lj91/c;->d:F

    .line 368
    .line 369
    const/16 v21, 0x0

    .line 370
    .line 371
    const/16 v22, 0xd

    .line 372
    .line 373
    const/16 v18, 0x0

    .line 374
    .line 375
    const/16 v20, 0x0

    .line 376
    .line 377
    move/from16 v19, v3

    .line 378
    .line 379
    invoke-static/range {v17 .. v22}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 380
    .line 381
    .line 382
    move-result-object v3

    .line 383
    invoke-static {v9, v13, v12, v5}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 384
    .line 385
    .line 386
    move-result-object v4

    .line 387
    iget-wide v8, v12, Ll2/t;->T:J

    .line 388
    .line 389
    invoke-static {v8, v9}, Ljava/lang/Long;->hashCode(J)I

    .line 390
    .line 391
    .line 392
    move-result v5

    .line 393
    invoke-virtual {v12}, Ll2/t;->m()Ll2/p1;

    .line 394
    .line 395
    .line 396
    move-result-object v8

    .line 397
    invoke-static {v12, v3}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 398
    .line 399
    .line 400
    move-result-object v3

    .line 401
    invoke-virtual {v12}, Ll2/t;->c0()V

    .line 402
    .line 403
    .line 404
    iget-boolean v9, v12, Ll2/t;->S:Z

    .line 405
    .line 406
    if-eqz v9, :cond_16

    .line 407
    .line 408
    invoke-virtual {v12, v11}, Ll2/t;->l(Lay0/a;)V

    .line 409
    .line 410
    .line 411
    goto :goto_c

    .line 412
    :cond_16
    invoke-virtual {v12}, Ll2/t;->m0()V

    .line 413
    .line 414
    .line 415
    :goto_c
    invoke-static {v2, v4, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 416
    .line 417
    .line 418
    invoke-static {v15, v8, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 419
    .line 420
    .line 421
    iget-boolean v4, v12, Ll2/t;->S:Z

    .line 422
    .line 423
    if-nez v4, :cond_17

    .line 424
    .line 425
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 426
    .line 427
    .line 428
    move-result-object v4

    .line 429
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 430
    .line 431
    .line 432
    move-result-object v8

    .line 433
    invoke-static {v4, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 434
    .line 435
    .line 436
    move-result v4

    .line 437
    if-nez v4, :cond_18

    .line 438
    .line 439
    :cond_17
    invoke-static {v5, v12, v5, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 440
    .line 441
    .line 442
    :cond_18
    invoke-static {v0, v3, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 443
    .line 444
    .line 445
    const/high16 v3, 0x3f800000    # 1.0f

    .line 446
    .line 447
    invoke-static {v10, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 448
    .line 449
    .line 450
    move-result-object v4

    .line 451
    sget-object v3, Lx2/c;->n:Lx2/i;

    .line 452
    .line 453
    sget-object v5, Lk1/j;->g:Lk1/f;

    .line 454
    .line 455
    const/16 v8, 0x36

    .line 456
    .line 457
    invoke-static {v5, v3, v12, v8}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 458
    .line 459
    .line 460
    move-result-object v9

    .line 461
    move-object/from16 v17, v9

    .line 462
    .line 463
    iget-wide v8, v12, Ll2/t;->T:J

    .line 464
    .line 465
    invoke-static {v8, v9}, Ljava/lang/Long;->hashCode(J)I

    .line 466
    .line 467
    .line 468
    move-result v8

    .line 469
    invoke-virtual {v12}, Ll2/t;->m()Ll2/p1;

    .line 470
    .line 471
    .line 472
    move-result-object v9

    .line 473
    invoke-static {v12, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 474
    .line 475
    .line 476
    move-result-object v4

    .line 477
    invoke-virtual {v12}, Ll2/t;->c0()V

    .line 478
    .line 479
    .line 480
    iget-boolean v13, v12, Ll2/t;->S:Z

    .line 481
    .line 482
    if-eqz v13, :cond_19

    .line 483
    .line 484
    invoke-virtual {v12, v11}, Ll2/t;->l(Lay0/a;)V

    .line 485
    .line 486
    .line 487
    :goto_d
    move-object/from16 v13, v17

    .line 488
    .line 489
    goto :goto_e

    .line 490
    :cond_19
    invoke-virtual {v12}, Ll2/t;->m0()V

    .line 491
    .line 492
    .line 493
    goto :goto_d

    .line 494
    :goto_e
    invoke-static {v2, v13, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 495
    .line 496
    .line 497
    invoke-static {v15, v9, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 498
    .line 499
    .line 500
    iget-boolean v9, v12, Ll2/t;->S:Z

    .line 501
    .line 502
    if-nez v9, :cond_1a

    .line 503
    .line 504
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 505
    .line 506
    .line 507
    move-result-object v9

    .line 508
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 509
    .line 510
    .line 511
    move-result-object v13

    .line 512
    invoke-static {v9, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 513
    .line 514
    .line 515
    move-result v9

    .line 516
    if-nez v9, :cond_1b

    .line 517
    .line 518
    :cond_1a
    invoke-static {v8, v12, v8, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 519
    .line 520
    .line 521
    :cond_1b
    invoke-static {v0, v4, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 522
    .line 523
    .line 524
    invoke-static {v12}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 525
    .line 526
    .line 527
    move-result-object v4

    .line 528
    invoke-virtual {v4}, Lj91/e;->q()J

    .line 529
    .line 530
    .line 531
    move-result-wide v20

    .line 532
    invoke-static {v12}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 533
    .line 534
    .line 535
    move-result-object v4

    .line 536
    invoke-virtual {v4}, Lj91/f;->m()Lg4/p0;

    .line 537
    .line 538
    .line 539
    move-result-object v22

    .line 540
    invoke-static {v12}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 541
    .line 542
    .line 543
    move-result-object v4

    .line 544
    invoke-virtual {v4}, Lj91/e;->q()J

    .line 545
    .line 546
    .line 547
    move-result-wide v23

    .line 548
    const/high16 v4, 0x3f800000    # 1.0f

    .line 549
    .line 550
    float-to-double v8, v4

    .line 551
    const-wide/16 v29, 0x0

    .line 552
    .line 553
    cmpl-double v8, v8, v29

    .line 554
    .line 555
    const-string v31, "invalid weight; must be greater than zero"

    .line 556
    .line 557
    if-lez v8, :cond_1c

    .line 558
    .line 559
    :goto_f
    move-object v8, v15

    .line 560
    goto :goto_10

    .line 561
    :cond_1c
    invoke-static/range {v31 .. v31}, Ll1/a;->a(Ljava/lang/String;)V

    .line 562
    .line 563
    .line 564
    goto :goto_f

    .line 565
    :goto_10
    new-instance v15, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 566
    .line 567
    const v32, 0x7f7fffff    # Float.MAX_VALUE

    .line 568
    .line 569
    .line 570
    cmpl-float v9, v4, v32

    .line 571
    .line 572
    if-lez v9, :cond_1d

    .line 573
    .line 574
    move/from16 v9, v32

    .line 575
    .line 576
    :goto_11
    const/4 v13, 0x1

    .line 577
    goto :goto_12

    .line 578
    :cond_1d
    move v9, v4

    .line 579
    goto :goto_11

    .line 580
    :goto_12
    invoke-direct {v15, v9, v13}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 581
    .line 582
    .line 583
    shl-int/lit8 v6, v6, 0x3

    .line 584
    .line 585
    and-int/lit8 v6, v6, 0x70

    .line 586
    .line 587
    const v9, 0x6000d80

    .line 588
    .line 589
    .line 590
    or-int v27, v6, v9

    .line 591
    .line 592
    const/16 v28, 0x0

    .line 593
    .line 594
    const-string v17, "battery_bi_di_charging_card_profile_text"

    .line 595
    .line 596
    const-string v18, "battery_bi_di_charging_profile_icon"

    .line 597
    .line 598
    const v19, 0x7f0803e4

    .line 599
    .line 600
    .line 601
    const/16 v25, 0x2

    .line 602
    .line 603
    move-object/from16 v16, p0

    .line 604
    .line 605
    move-object/from16 v26, v12

    .line 606
    .line 607
    invoke-static/range {v15 .. v28}, Luz/g;->k(Lx2/s;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;IJLg4/p0;JILl2/o;II)V

    .line 608
    .line 609
    .line 610
    if-nez p3, :cond_1e

    .line 611
    .line 612
    const v6, 0x3f357093

    .line 613
    .line 614
    .line 615
    invoke-virtual {v12, v6}, Ll2/t;->Y(I)V

    .line 616
    .line 617
    .line 618
    const/4 v6, 0x0

    .line 619
    invoke-virtual {v12, v6}, Ll2/t;->q(Z)V

    .line 620
    .line 621
    .line 622
    move-object/from16 p7, v0

    .line 623
    .line 624
    move-object/from16 v16, v1

    .line 625
    .line 626
    move-object v0, v5

    .line 627
    move v1, v6

    .line 628
    move-object/from16 v18, v8

    .line 629
    .line 630
    move-object/from16 v21, v10

    .line 631
    .line 632
    move-object v14, v11

    .line 633
    move v15, v13

    .line 634
    goto :goto_13

    .line 635
    :cond_1e
    const/4 v6, 0x0

    .line 636
    const v9, 0x3f357094

    .line 637
    .line 638
    .line 639
    invoke-virtual {v12, v9}, Ll2/t;->Y(I)V

    .line 640
    .line 641
    .line 642
    invoke-static {v12}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 643
    .line 644
    .line 645
    move-result-object v9

    .line 646
    iget v9, v9, Lj91/c;->d:F

    .line 647
    .line 648
    invoke-static {v10, v9}, Landroidx/compose/foundation/layout/d;->r(Lx2/s;F)Lx2/s;

    .line 649
    .line 650
    .line 651
    move-result-object v9

    .line 652
    invoke-static {v12, v9}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 653
    .line 654
    .line 655
    invoke-static {v12}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 656
    .line 657
    .line 658
    move-result-object v9

    .line 659
    invoke-virtual {v9}, Lj91/e;->q()J

    .line 660
    .line 661
    .line 662
    move-result-wide v21

    .line 663
    invoke-static {v12}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 664
    .line 665
    .line 666
    move-result-object v9

    .line 667
    invoke-virtual {v9}, Lj91/f;->e()Lg4/p0;

    .line 668
    .line 669
    .line 670
    move-result-object v9

    .line 671
    invoke-static {v12}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 672
    .line 673
    .line 674
    move-result-object v15

    .line 675
    invoke-virtual {v15}, Lj91/e;->q()J

    .line 676
    .line 677
    .line 678
    move-result-wide v23

    .line 679
    const/16 v18, 0x0

    .line 680
    .line 681
    const/16 v20, 0xf

    .line 682
    .line 683
    const/16 v16, 0x0

    .line 684
    .line 685
    const/16 v17, 0x0

    .line 686
    .line 687
    move-object/from16 v19, v7

    .line 688
    .line 689
    move-object v15, v10

    .line 690
    invoke-static/range {v15 .. v20}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    .line 691
    .line 692
    .line 693
    move-result-object v7

    .line 694
    move-object v10, v11

    .line 695
    const/4 v11, 0x0

    .line 696
    move/from16 v16, v13

    .line 697
    .line 698
    const/16 v13, 0xd80

    .line 699
    .line 700
    move-object/from16 p7, v0

    .line 701
    .line 702
    move-object v0, v5

    .line 703
    move-object v4, v7

    .line 704
    move-object/from16 v18, v8

    .line 705
    .line 706
    move-object v8, v9

    .line 707
    move-object v14, v10

    .line 708
    move-wide/from16 v9, v23

    .line 709
    .line 710
    move-object/from16 v5, p3

    .line 711
    .line 712
    move/from16 v33, v16

    .line 713
    .line 714
    move-object/from16 v16, v1

    .line 715
    .line 716
    move v1, v6

    .line 717
    move-wide/from16 v6, v21

    .line 718
    .line 719
    move-object/from16 v21, v15

    .line 720
    .line 721
    move/from16 v15, v33

    .line 722
    .line 723
    invoke-static/range {v4 .. v13}, Luz/g;->l(Lx2/s;Ljava/lang/String;JLg4/p0;JILl2/o;I)V

    .line 724
    .line 725
    .line 726
    invoke-virtual {v12, v1}, Ll2/t;->q(Z)V

    .line 727
    .line 728
    .line 729
    :goto_13
    invoke-virtual {v12, v15}, Ll2/t;->q(Z)V

    .line 730
    .line 731
    .line 732
    invoke-static {v12}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 733
    .line 734
    .line 735
    move-result-object v4

    .line 736
    iget v4, v4, Lj91/c;->c:F

    .line 737
    .line 738
    const/16 v25, 0x0

    .line 739
    .line 740
    const/16 v26, 0xd

    .line 741
    .line 742
    const/16 v22, 0x0

    .line 743
    .line 744
    const/16 v24, 0x0

    .line 745
    .line 746
    move/from16 v23, v4

    .line 747
    .line 748
    invoke-static/range {v21 .. v26}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 749
    .line 750
    .line 751
    move-result-object v4

    .line 752
    const/high16 v5, 0x3f800000    # 1.0f

    .line 753
    .line 754
    invoke-static {v4, v5}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 755
    .line 756
    .line 757
    move-result-object v4

    .line 758
    const/16 v13, 0x36

    .line 759
    .line 760
    invoke-static {v0, v3, v12, v13}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 761
    .line 762
    .line 763
    move-result-object v0

    .line 764
    iget-wide v5, v12, Ll2/t;->T:J

    .line 765
    .line 766
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 767
    .line 768
    .line 769
    move-result v3

    .line 770
    invoke-virtual {v12}, Ll2/t;->m()Ll2/p1;

    .line 771
    .line 772
    .line 773
    move-result-object v5

    .line 774
    invoke-static {v12, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 775
    .line 776
    .line 777
    move-result-object v4

    .line 778
    invoke-virtual {v12}, Ll2/t;->c0()V

    .line 779
    .line 780
    .line 781
    iget-boolean v6, v12, Ll2/t;->S:Z

    .line 782
    .line 783
    if-eqz v6, :cond_1f

    .line 784
    .line 785
    invoke-virtual {v12, v14}, Ll2/t;->l(Lay0/a;)V

    .line 786
    .line 787
    .line 788
    goto :goto_14

    .line 789
    :cond_1f
    invoke-virtual {v12}, Ll2/t;->m0()V

    .line 790
    .line 791
    .line 792
    :goto_14
    invoke-static {v2, v0, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 793
    .line 794
    .line 795
    move-object/from16 v8, v18

    .line 796
    .line 797
    invoke-static {v8, v5, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 798
    .line 799
    .line 800
    iget-boolean v0, v12, Ll2/t;->S:Z

    .line 801
    .line 802
    if-nez v0, :cond_20

    .line 803
    .line 804
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 805
    .line 806
    .line 807
    move-result-object v0

    .line 808
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 809
    .line 810
    .line 811
    move-result-object v2

    .line 812
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 813
    .line 814
    .line 815
    move-result v0

    .line 816
    if-nez v0, :cond_21

    .line 817
    .line 818
    :cond_20
    move-object/from16 v0, v16

    .line 819
    .line 820
    goto :goto_16

    .line 821
    :cond_21
    :goto_15
    move-object/from16 v0, p7

    .line 822
    .line 823
    goto :goto_17

    .line 824
    :goto_16
    invoke-static {v3, v12, v3, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 825
    .line 826
    .line 827
    goto :goto_15

    .line 828
    :goto_17
    invoke-static {v0, v4, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 829
    .line 830
    .line 831
    const/4 v0, 0x0

    .line 832
    if-eqz p1, :cond_22

    .line 833
    .line 834
    if-eqz p4, :cond_22

    .line 835
    .line 836
    move-object/from16 v16, p1

    .line 837
    .line 838
    goto :goto_18

    .line 839
    :cond_22
    move-object/from16 v16, v0

    .line 840
    .line 841
    :goto_18
    if-nez v16, :cond_23

    .line 842
    .line 843
    const v0, 0x27ffa487

    .line 844
    .line 845
    .line 846
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 847
    .line 848
    .line 849
    invoke-virtual {v12, v1}, Ll2/t;->q(Z)V

    .line 850
    .line 851
    .line 852
    move v0, v15

    .line 853
    goto :goto_1a

    .line 854
    :cond_23
    const v0, 0x27ffa488

    .line 855
    .line 856
    .line 857
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 858
    .line 859
    .line 860
    invoke-static {v12}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 861
    .line 862
    .line 863
    move-result-object v0

    .line 864
    invoke-virtual {v0}, Lj91/e;->t()J

    .line 865
    .line 866
    .line 867
    move-result-wide v20

    .line 868
    invoke-static {v12}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 869
    .line 870
    .line 871
    move-result-object v0

    .line 872
    invoke-virtual {v0}, Lj91/f;->e()Lg4/p0;

    .line 873
    .line 874
    .line 875
    move-result-object v22

    .line 876
    invoke-static {v12}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 877
    .line 878
    .line 879
    move-result-object v0

    .line 880
    invoke-virtual {v0}, Lj91/e;->s()J

    .line 881
    .line 882
    .line 883
    move-result-wide v23

    .line 884
    const/high16 v3, 0x3f800000    # 1.0f

    .line 885
    .line 886
    float-to-double v4, v3

    .line 887
    cmpl-double v0, v4, v29

    .line 888
    .line 889
    if-lez v0, :cond_24

    .line 890
    .line 891
    goto :goto_19

    .line 892
    :cond_24
    invoke-static/range {v31 .. v31}, Ll1/a;->a(Ljava/lang/String;)V

    .line 893
    .line 894
    .line 895
    :goto_19
    new-instance v0, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 896
    .line 897
    cmpl-float v2, v3, v32

    .line 898
    .line 899
    if-lez v2, :cond_25

    .line 900
    .line 901
    move/from16 v3, v32

    .line 902
    .line 903
    :cond_25
    invoke-direct {v0, v3, v15}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 904
    .line 905
    .line 906
    const/16 v27, 0xd80

    .line 907
    .line 908
    const/16 v28, 0x100

    .line 909
    .line 910
    const-string v17, "battery_bi_di_charging_card_range_text"

    .line 911
    .line 912
    const-string v18, "battery_bi_di_charging_range_icon"

    .line 913
    .line 914
    const v19, 0x7f0802d5

    .line 915
    .line 916
    .line 917
    const/16 v25, 0x0

    .line 918
    .line 919
    move/from16 v26, v15

    .line 920
    .line 921
    move-object v15, v0

    .line 922
    move/from16 v0, v26

    .line 923
    .line 924
    move-object/from16 v26, v12

    .line 925
    .line 926
    invoke-static/range {v15 .. v28}, Luz/g;->k(Lx2/s;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;IJLg4/p0;JILl2/o;II)V

    .line 927
    .line 928
    .line 929
    invoke-virtual {v12, v1}, Ll2/t;->q(Z)V

    .line 930
    .line 931
    .line 932
    :goto_1a
    if-nez p2, :cond_26

    .line 933
    .line 934
    const v2, 0x28092094

    .line 935
    .line 936
    .line 937
    invoke-virtual {v12, v2}, Ll2/t;->Y(I)V

    .line 938
    .line 939
    .line 940
    :goto_1b
    invoke-virtual {v12, v1}, Ll2/t;->q(Z)V

    .line 941
    .line 942
    .line 943
    goto :goto_1c

    .line 944
    :cond_26
    const v2, 0x28092095

    .line 945
    .line 946
    .line 947
    invoke-virtual {v12, v2}, Ll2/t;->Y(I)V

    .line 948
    .line 949
    .line 950
    invoke-static {v12}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 951
    .line 952
    .line 953
    move-result-object v2

    .line 954
    invoke-virtual {v2}, Lj91/e;->t()J

    .line 955
    .line 956
    .line 957
    move-result-wide v8

    .line 958
    invoke-static {v12}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 959
    .line 960
    .line 961
    move-result-object v2

    .line 962
    invoke-virtual {v2}, Lj91/f;->e()Lg4/p0;

    .line 963
    .line 964
    .line 965
    move-result-object v10

    .line 966
    invoke-static {v12}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 967
    .line 968
    .line 969
    move-result-object v2

    .line 970
    invoke-virtual {v2}, Lj91/e;->s()J

    .line 971
    .line 972
    .line 973
    move-result-wide v2

    .line 974
    const v15, 0x6000d80

    .line 975
    .line 976
    .line 977
    const/16 v16, 0x1

    .line 978
    .line 979
    move-object/from16 v26, v12

    .line 980
    .line 981
    move-wide v11, v2

    .line 982
    const/4 v3, 0x0

    .line 983
    const-string v5, "battery_bi_di_charging_card_ready_at_text"

    .line 984
    .line 985
    const-string v6, "battery_bi_di_charging_ready_at_icon"

    .line 986
    .line 987
    const v7, 0x7f080293

    .line 988
    .line 989
    .line 990
    const/4 v13, 0x2

    .line 991
    move-object/from16 v4, p2

    .line 992
    .line 993
    move-object/from16 v14, v26

    .line 994
    .line 995
    invoke-static/range {v3 .. v16}, Luz/g;->k(Lx2/s;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;IJLg4/p0;JILl2/o;II)V

    .line 996
    .line 997
    .line 998
    move-object v12, v14

    .line 999
    goto :goto_1b

    .line 1000
    :goto_1c
    invoke-static {v12, v0, v0, v0}, Lf2/m0;->w(Ll2/t;ZZZ)V

    .line 1001
    .line 1002
    .line 1003
    goto :goto_1d

    .line 1004
    :cond_27
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 1005
    .line 1006
    .line 1007
    :goto_1d
    invoke-virtual {v12}, Ll2/t;->s()Ll2/u1;

    .line 1008
    .line 1009
    .line 1010
    move-result-object v9

    .line 1011
    if-eqz v9, :cond_28

    .line 1012
    .line 1013
    new-instance v0, Le71/i;

    .line 1014
    .line 1015
    move-object/from16 v1, p0

    .line 1016
    .line 1017
    move-object/from16 v2, p1

    .line 1018
    .line 1019
    move-object/from16 v3, p2

    .line 1020
    .line 1021
    move-object/from16 v4, p3

    .line 1022
    .line 1023
    move/from16 v5, p4

    .line 1024
    .line 1025
    move-object/from16 v6, p5

    .line 1026
    .line 1027
    move-object/from16 v7, p6

    .line 1028
    .line 1029
    move/from16 v8, p8

    .line 1030
    .line 1031
    invoke-direct/range {v0 .. v8}, Le71/i;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLay0/a;Lay0/a;I)V

    .line 1032
    .line 1033
    .line 1034
    iput-object v0, v9, Ll2/u1;->d:Lay0/n;

    .line 1035
    .line 1036
    :cond_28
    return-void
.end method
