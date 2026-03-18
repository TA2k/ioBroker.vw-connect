.class public abstract Llp/qa;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(IILjava/lang/String;Ll2/o;Lx2/s;Z)V
    .locals 19

    .line 1
    move/from16 v4, p0

    .line 2
    .line 3
    move-object/from16 v0, p3

    .line 4
    .line 5
    check-cast v0, Ll2/t;

    .line 6
    .line 7
    const v1, -0x7f67b714

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    and-int/lit8 v1, p1, 0x2

    .line 14
    .line 15
    if-eqz v1, :cond_0

    .line 16
    .line 17
    or-int/lit8 v2, v4, 0x30

    .line 18
    .line 19
    move v3, v2

    .line 20
    move-object/from16 v2, p4

    .line 21
    .line 22
    goto :goto_1

    .line 23
    :cond_0
    and-int/lit8 v2, v4, 0x30

    .line 24
    .line 25
    if-nez v2, :cond_2

    .line 26
    .line 27
    move-object/from16 v2, p4

    .line 28
    .line 29
    invoke-virtual {v0, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    if-eqz v3, :cond_1

    .line 34
    .line 35
    const/16 v3, 0x20

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_1
    const/16 v3, 0x10

    .line 39
    .line 40
    :goto_0
    or-int/2addr v3, v4

    .line 41
    goto :goto_1

    .line 42
    :cond_2
    move-object/from16 v2, p4

    .line 43
    .line 44
    move v3, v4

    .line 45
    :goto_1
    and-int/lit8 v5, p1, 0x4

    .line 46
    .line 47
    const/16 v6, 0x100

    .line 48
    .line 49
    if-eqz v5, :cond_4

    .line 50
    .line 51
    or-int/lit16 v3, v3, 0x180

    .line 52
    .line 53
    :cond_3
    move/from16 v7, p5

    .line 54
    .line 55
    goto :goto_3

    .line 56
    :cond_4
    and-int/lit16 v7, v4, 0x180

    .line 57
    .line 58
    if-nez v7, :cond_3

    .line 59
    .line 60
    move/from16 v7, p5

    .line 61
    .line 62
    invoke-virtual {v0, v7}, Ll2/t;->h(Z)Z

    .line 63
    .line 64
    .line 65
    move-result v8

    .line 66
    if-eqz v8, :cond_5

    .line 67
    .line 68
    move v8, v6

    .line 69
    goto :goto_2

    .line 70
    :cond_5
    const/16 v8, 0x80

    .line 71
    .line 72
    :goto_2
    or-int/2addr v3, v8

    .line 73
    :goto_3
    and-int/lit16 v8, v3, 0x93

    .line 74
    .line 75
    const/16 v9, 0x92

    .line 76
    .line 77
    const/4 v10, 0x1

    .line 78
    const/4 v11, 0x0

    .line 79
    if-eq v8, v9, :cond_6

    .line 80
    .line 81
    move v8, v10

    .line 82
    goto :goto_4

    .line 83
    :cond_6
    move v8, v11

    .line 84
    :goto_4
    and-int/lit8 v9, v3, 0x1

    .line 85
    .line 86
    invoke-virtual {v0, v9, v8}, Ll2/t;->O(IZ)Z

    .line 87
    .line 88
    .line 89
    move-result v8

    .line 90
    if-eqz v8, :cond_10

    .line 91
    .line 92
    if-eqz v1, :cond_7

    .line 93
    .line 94
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 95
    .line 96
    move-object v2, v1

    .line 97
    :cond_7
    move v1, v3

    .line 98
    if-eqz v5, :cond_8

    .line 99
    .line 100
    move v3, v11

    .line 101
    goto :goto_5

    .line 102
    :cond_8
    move v3, v7

    .line 103
    :goto_5
    invoke-static {v0}, Lxf0/y1;->F(Ll2/o;)Z

    .line 104
    .line 105
    .line 106
    move-result v5

    .line 107
    if-eqz v5, :cond_9

    .line 108
    .line 109
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 110
    .line 111
    .line 112
    move-result-object v7

    .line 113
    if-eqz v7, :cond_11

    .line 114
    .line 115
    new-instance v0, Lgr0/b;

    .line 116
    .line 117
    const/4 v6, 0x1

    .line 118
    move/from16 v5, p1

    .line 119
    .line 120
    move-object/from16 v1, p2

    .line 121
    .line 122
    invoke-direct/range {v0 .. v6}, Lgr0/b;-><init>(Ljava/lang/String;Lx2/s;ZIII)V

    .line 123
    .line 124
    .line 125
    :goto_6
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 126
    .line 127
    return-void

    .line 128
    :cond_9
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 129
    .line 130
    const-class v5, Lho0/b;

    .line 131
    .line 132
    invoke-virtual {v4, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 133
    .line 134
    .line 135
    move-result-object v7

    .line 136
    invoke-interface {v7}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 137
    .line 138
    .line 139
    move-result-object v7

    .line 140
    new-instance v8, Ljava/lang/StringBuilder;

    .line 141
    .line 142
    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V

    .line 143
    .line 144
    .line 145
    invoke-virtual {v8, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 146
    .line 147
    .line 148
    move-object/from16 v9, p2

    .line 149
    .line 150
    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 151
    .line 152
    .line 153
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 154
    .line 155
    .line 156
    move-result-object v7

    .line 157
    invoke-static {v7}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 158
    .line 159
    .line 160
    move-result-object v16

    .line 161
    const v7, -0x6040e0aa

    .line 162
    .line 163
    .line 164
    invoke-virtual {v0, v7}, Ll2/t;->Y(I)V

    .line 165
    .line 166
    .line 167
    invoke-static {v0}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 168
    .line 169
    .line 170
    move-result-object v7

    .line 171
    if-eqz v7, :cond_f

    .line 172
    .line 173
    invoke-static {v7}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 174
    .line 175
    .line 176
    move-result-object v15

    .line 177
    invoke-static {v0}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 178
    .line 179
    .line 180
    move-result-object v17

    .line 181
    invoke-virtual {v4, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 182
    .line 183
    .line 184
    move-result-object v12

    .line 185
    invoke-interface {v7}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 186
    .line 187
    .line 188
    move-result-object v13

    .line 189
    const/4 v14, 0x0

    .line 190
    const/16 v18, 0x0

    .line 191
    .line 192
    invoke-static/range {v12 .. v18}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 193
    .line 194
    .line 195
    move-result-object v4

    .line 196
    invoke-virtual {v0, v11}, Ll2/t;->q(Z)V

    .line 197
    .line 198
    .line 199
    check-cast v4, Lql0/j;

    .line 200
    .line 201
    invoke-static {v4, v0, v11, v10}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 202
    .line 203
    .line 204
    check-cast v4, Lho0/b;

    .line 205
    .line 206
    sget-object v5, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 207
    .line 208
    invoke-virtual {v0, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    move-result-object v5

    .line 212
    check-cast v5, Landroid/content/Context;

    .line 213
    .line 214
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 215
    .line 216
    .line 217
    move-result-object v7

    .line 218
    sget-object v8, Ll2/n;->a:Ll2/x0;

    .line 219
    .line 220
    if-ne v7, v8, :cond_a

    .line 221
    .line 222
    sget-object v7, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 223
    .line 224
    invoke-static {v7}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 225
    .line 226
    .line 227
    move-result-object v7

    .line 228
    invoke-virtual {v0, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 229
    .line 230
    .line 231
    :cond_a
    check-cast v7, Ll2/b1;

    .line 232
    .line 233
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 234
    .line 235
    .line 236
    move-result-object v12

    .line 237
    if-ne v12, v8, :cond_b

    .line 238
    .line 239
    new-instance v12, La8/q;

    .line 240
    .line 241
    invoke-direct {v12, v5}, La8/q;-><init>(Landroid/content/Context;)V

    .line 242
    .line 243
    .line 244
    iget-boolean v5, v12, La8/q;->u:Z

    .line 245
    .line 246
    xor-int/2addr v5, v10

    .line 247
    invoke-static {v5}, Lw7/a;->j(Z)V

    .line 248
    .line 249
    .line 250
    iput-boolean v10, v12, La8/q;->u:Z

    .line 251
    .line 252
    new-instance v5, La8/i0;

    .line 253
    .line 254
    invoke-direct {v5, v12}, La8/i0;-><init>(La8/q;)V

    .line 255
    .line 256
    .line 257
    invoke-virtual {v0, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 258
    .line 259
    .line 260
    move-object v12, v5

    .line 261
    :cond_b
    check-cast v12, Landroidx/media3/exoplayer/ExoPlayer;

    .line 262
    .line 263
    invoke-static {v12}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 264
    .line 265
    .line 266
    shl-int/lit8 v5, v1, 0x3

    .line 267
    .line 268
    and-int/lit16 v5, v5, 0x380

    .line 269
    .line 270
    or-int/lit8 v5, v5, 0x30

    .line 271
    .line 272
    invoke-static {v12, v7, v2, v0, v5}, Llp/qa;->b(Landroidx/media3/exoplayer/ExoPlayer;Ll2/t2;Lx2/s;Ll2/o;I)V

    .line 273
    .line 274
    .line 275
    invoke-virtual {v0, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 276
    .line 277
    .line 278
    move-result v5

    .line 279
    and-int/lit16 v1, v1, 0x380

    .line 280
    .line 281
    if-ne v1, v6, :cond_c

    .line 282
    .line 283
    goto :goto_7

    .line 284
    :cond_c
    move v10, v11

    .line 285
    :goto_7
    or-int v1, v5, v10

    .line 286
    .line 287
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 288
    .line 289
    .line 290
    move-result-object v5

    .line 291
    if-nez v1, :cond_d

    .line 292
    .line 293
    if-ne v5, v8, :cond_e

    .line 294
    .line 295
    :cond_d
    new-instance v5, Laa/l;

    .line 296
    .line 297
    const/4 v1, 0x2

    .line 298
    invoke-direct {v5, v12, v3, v7, v1}, Laa/l;-><init>(Ljava/lang/Object;ZLjava/lang/Object;I)V

    .line 299
    .line 300
    .line 301
    invoke-virtual {v0, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 302
    .line 303
    .line 304
    :cond_e
    check-cast v5, Lay0/k;

    .line 305
    .line 306
    invoke-static {v12, v5, v0}, Ll2/l0;->a(Ljava/lang/Object;Lay0/k;Ll2/o;)V

    .line 307
    .line 308
    .line 309
    invoke-static {v4, v12, v0, v11}, Llp/qa;->c(Lho0/b;Landroidx/media3/exoplayer/ExoPlayer;Ll2/o;I)V

    .line 310
    .line 311
    .line 312
    goto :goto_8

    .line 313
    :cond_f
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 314
    .line 315
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 316
    .line 317
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 318
    .line 319
    .line 320
    throw v0

    .line 321
    :cond_10
    move-object/from16 v9, p2

    .line 322
    .line 323
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 324
    .line 325
    .line 326
    move v3, v7

    .line 327
    :goto_8
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 328
    .line 329
    .line 330
    move-result-object v7

    .line 331
    if-eqz v7, :cond_11

    .line 332
    .line 333
    new-instance v0, Lgr0/b;

    .line 334
    .line 335
    const/4 v6, 0x2

    .line 336
    move/from16 v4, p0

    .line 337
    .line 338
    move/from16 v5, p1

    .line 339
    .line 340
    move-object v1, v9

    .line 341
    invoke-direct/range {v0 .. v6}, Lgr0/b;-><init>(Ljava/lang/String;Lx2/s;ZIII)V

    .line 342
    .line 343
    .line 344
    goto/16 :goto_6

    .line 345
    .line 346
    :cond_11
    return-void
.end method

.method public static final b(Landroidx/media3/exoplayer/ExoPlayer;Ll2/t2;Lx2/s;Ll2/o;I)V
    .locals 6

    .line 1
    move-object v4, p3

    .line 2
    check-cast v4, Ll2/t;

    .line 3
    .line 4
    const p3, -0x2456b965

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
    if-nez p3, :cond_1

    .line 13
    .line 14
    invoke-virtual {v4, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result p3

    .line 18
    if-eqz p3, :cond_0

    .line 19
    .line 20
    const/4 p3, 0x4

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 p3, 0x2

    .line 23
    :goto_0
    or-int/2addr p3, p4

    .line 24
    goto :goto_1

    .line 25
    :cond_1
    move p3, p4

    .line 26
    :goto_1
    and-int/lit8 v0, p4, 0x30

    .line 27
    .line 28
    if-nez v0, :cond_3

    .line 29
    .line 30
    invoke-virtual {v4, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-eqz v0, :cond_2

    .line 35
    .line 36
    const/16 v0, 0x20

    .line 37
    .line 38
    goto :goto_2

    .line 39
    :cond_2
    const/16 v0, 0x10

    .line 40
    .line 41
    :goto_2
    or-int/2addr p3, v0

    .line 42
    :cond_3
    and-int/lit16 v0, p4, 0x180

    .line 43
    .line 44
    if-nez v0, :cond_5

    .line 45
    .line 46
    invoke-virtual {v4, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    if-eqz v0, :cond_4

    .line 51
    .line 52
    const/16 v0, 0x100

    .line 53
    .line 54
    goto :goto_3

    .line 55
    :cond_4
    const/16 v0, 0x80

    .line 56
    .line 57
    :goto_3
    or-int/2addr p3, v0

    .line 58
    :cond_5
    and-int/lit16 v0, p3, 0x93

    .line 59
    .line 60
    const/16 v1, 0x92

    .line 61
    .line 62
    const/4 v2, 0x1

    .line 63
    if-eq v0, v1, :cond_6

    .line 64
    .line 65
    move v0, v2

    .line 66
    goto :goto_4

    .line 67
    :cond_6
    const/4 v0, 0x0

    .line 68
    :goto_4
    and-int/2addr p3, v2

    .line 69
    invoke-virtual {v4, p3, v0}, Ll2/t;->O(IZ)Z

    .line 70
    .line 71
    .line 72
    move-result p3

    .line 73
    if-eqz p3, :cond_a

    .line 74
    .line 75
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p3

    .line 79
    check-cast p3, Ljava/lang/Boolean;

    .line 80
    .line 81
    invoke-virtual {p3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 82
    .line 83
    .line 84
    move-result p3

    .line 85
    if-eqz p3, :cond_7

    .line 86
    .line 87
    const/high16 p3, 0x3f800000    # 1.0f

    .line 88
    .line 89
    goto :goto_5

    .line 90
    :cond_7
    const/4 p3, 0x0

    .line 91
    :goto_5
    invoke-static {p2, p3}, Ljp/a2;->a(Lx2/s;F)Lx2/s;

    .line 92
    .line 93
    .line 94
    move-result-object v5

    .line 95
    invoke-virtual {v4, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    move-result p3

    .line 99
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    if-nez p3, :cond_8

    .line 104
    .line 105
    sget-object p3, Ll2/n;->a:Ll2/x0;

    .line 106
    .line 107
    if-ne v0, p3, :cond_9

    .line 108
    .line 109
    :cond_8
    new-instance v0, Lio0/a;

    .line 110
    .line 111
    const/4 p3, 0x0

    .line 112
    invoke-direct {v0, p0, p3}, Lio0/a;-><init>(Landroidx/media3/exoplayer/ExoPlayer;I)V

    .line 113
    .line 114
    .line 115
    invoke-virtual {v4, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    :cond_9
    move-object v2, v0

    .line 119
    check-cast v2, Lay0/k;

    .line 120
    .line 121
    const/4 v0, 0x0

    .line 122
    const/4 v1, 0x4

    .line 123
    const/4 v3, 0x0

    .line 124
    invoke-static/range {v0 .. v5}, Landroidx/compose/ui/viewinterop/a;->a(IILay0/k;Lay0/k;Ll2/o;Lx2/s;)V

    .line 125
    .line 126
    .line 127
    goto :goto_6

    .line 128
    :cond_a
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 129
    .line 130
    .line 131
    :goto_6
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 132
    .line 133
    .line 134
    move-result-object p3

    .line 135
    if-eqz p3, :cond_b

    .line 136
    .line 137
    new-instance v0, Li50/j0;

    .line 138
    .line 139
    const/4 v2, 0x5

    .line 140
    move-object v3, p0

    .line 141
    move-object v4, p1

    .line 142
    move-object v5, p2

    .line 143
    move v1, p4

    .line 144
    invoke-direct/range {v0 .. v5}, Li50/j0;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 145
    .line 146
    .line 147
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 148
    .line 149
    :cond_b
    return-void
.end method

.method public static final c(Lho0/b;Landroidx/media3/exoplayer/ExoPlayer;Ll2/o;I)V
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p3

    .line 6
    .line 7
    move-object/from16 v3, p2

    .line 8
    .line 9
    check-cast v3, Ll2/t;

    .line 10
    .line 11
    const v4, 0x8711ae3

    .line 12
    .line 13
    .line 14
    invoke-virtual {v3, v4}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v3, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v4

    .line 21
    if-eqz v4, :cond_0

    .line 22
    .line 23
    const/4 v4, 0x4

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 v4, 0x2

    .line 26
    :goto_0
    or-int/2addr v4, v2

    .line 27
    invoke-virtual {v3, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v5

    .line 31
    if-eqz v5, :cond_1

    .line 32
    .line 33
    const/16 v5, 0x20

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_1
    const/16 v5, 0x10

    .line 37
    .line 38
    :goto_1
    or-int/2addr v4, v5

    .line 39
    and-int/lit8 v5, v4, 0x13

    .line 40
    .line 41
    const/16 v6, 0x12

    .line 42
    .line 43
    const/4 v7, 0x1

    .line 44
    if-eq v5, v6, :cond_2

    .line 45
    .line 46
    move v5, v7

    .line 47
    goto :goto_2

    .line 48
    :cond_2
    const/4 v5, 0x0

    .line 49
    :goto_2
    and-int/2addr v4, v7

    .line 50
    invoke-virtual {v3, v4, v5}, Ll2/t;->O(IZ)Z

    .line 51
    .line 52
    .line 53
    move-result v4

    .line 54
    if-eqz v4, :cond_5

    .line 55
    .line 56
    iget-object v4, v0, Lql0/j;->g:Lyy0/l1;

    .line 57
    .line 58
    const/4 v11, 0x0

    .line 59
    invoke-static {v4, v11, v3, v7}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 60
    .line 61
    .line 62
    move-result-object v4

    .line 63
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v4

    .line 67
    check-cast v4, Lho0/a;

    .line 68
    .line 69
    iget-object v4, v4, Lho0/a;->a:Lgo0/b;

    .line 70
    .line 71
    instance-of v5, v4, Lgo0/b;

    .line 72
    .line 73
    if-eqz v5, :cond_6

    .line 74
    .line 75
    iget-object v4, v4, Lgo0/b;->a:Lgo0/a;

    .line 76
    .line 77
    instance-of v5, v4, Lgo0/a;

    .line 78
    .line 79
    if-eqz v5, :cond_4

    .line 80
    .line 81
    new-instance v5, Landroid/net/Uri$Builder;

    .line 82
    .line 83
    invoke-direct {v5}, Landroid/net/Uri$Builder;-><init>()V

    .line 84
    .line 85
    .line 86
    const-string v6, "android.resource"

    .line 87
    .line 88
    invoke-virtual {v5, v6}, Landroid/net/Uri$Builder;->scheme(Ljava/lang/String;)Landroid/net/Uri$Builder;

    .line 89
    .line 90
    .line 91
    move-result-object v5

    .line 92
    iget v4, v4, Lgo0/a;->a:I

    .line 93
    .line 94
    invoke-static {v4}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object v4

    .line 98
    invoke-virtual {v5, v4}, Landroid/net/Uri$Builder;->path(Ljava/lang/String;)Landroid/net/Uri$Builder;

    .line 99
    .line 100
    .line 101
    move-result-object v4

    .line 102
    invoke-virtual {v4}, Landroid/net/Uri$Builder;->build()Landroid/net/Uri;

    .line 103
    .line 104
    .line 105
    move-result-object v9

    .line 106
    sget v4, Lt7/x;->g:I

    .line 107
    .line 108
    new-instance v4, Lo8/s;

    .line 109
    .line 110
    invoke-direct {v4}, Lo8/s;-><init>()V

    .line 111
    .line 112
    .line 113
    sget-object v5, Lhr/h0;->e:Lhr/f0;

    .line 114
    .line 115
    sget-object v5, Lhr/x0;->h:Lhr/x0;

    .line 116
    .line 117
    sget-object v12, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 118
    .line 119
    sget-object v13, Lhr/x0;->h:Lhr/x0;

    .line 120
    .line 121
    new-instance v5, Lt7/s;

    .line 122
    .line 123
    invoke-direct {v5}, Lt7/s;-><init>()V

    .line 124
    .line 125
    .line 126
    sget-object v20, Lt7/v;->a:Lt7/v;

    .line 127
    .line 128
    if-eqz v9, :cond_3

    .line 129
    .line 130
    new-instance v8, Lt7/u;

    .line 131
    .line 132
    const/4 v10, 0x0

    .line 133
    const-wide v14, -0x7fffffffffffffffL    # -4.9E-324

    .line 134
    .line 135
    .line 136
    .line 137
    .line 138
    invoke-direct/range {v8 .. v15}, Lt7/u;-><init>(Landroid/net/Uri;Ljava/lang/String;Lkp/o9;Ljava/util/List;Lhr/h0;J)V

    .line 139
    .line 140
    .line 141
    move-object/from16 v17, v8

    .line 142
    .line 143
    goto :goto_3

    .line 144
    :cond_3
    move-object/from16 v17, v11

    .line 145
    .line 146
    :goto_3
    new-instance v14, Lt7/x;

    .line 147
    .line 148
    new-instance v6, Lt7/r;

    .line 149
    .line 150
    invoke-direct {v6, v4}, Lt7/q;-><init>(Lo8/s;)V

    .line 151
    .line 152
    .line 153
    new-instance v4, Lt7/t;

    .line 154
    .line 155
    invoke-direct {v4, v5}, Lt7/t;-><init>(Lt7/s;)V

    .line 156
    .line 157
    .line 158
    sget-object v19, Lt7/a0;->B:Lt7/a0;

    .line 159
    .line 160
    const-string v15, ""

    .line 161
    .line 162
    move-object/from16 v18, v4

    .line 163
    .line 164
    move-object/from16 v16, v6

    .line 165
    .line 166
    invoke-direct/range {v14 .. v20}, Lt7/x;-><init>(Ljava/lang/String;Lt7/r;Lt7/u;Lt7/t;Lt7/a0;Lt7/v;)V

    .line 167
    .line 168
    .line 169
    move-object v4, v1

    .line 170
    check-cast v4, Lap0/o;

    .line 171
    .line 172
    invoke-virtual {v4, v14}, Lap0/o;->U(Lt7/x;)V

    .line 173
    .line 174
    .line 175
    goto :goto_4

    .line 176
    :cond_4
    new-instance v0, La8/r0;

    .line 177
    .line 178
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 179
    .line 180
    .line 181
    throw v0

    .line 182
    :cond_5
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 183
    .line 184
    .line 185
    :cond_6
    :goto_4
    invoke-virtual {v3}, Ll2/t;->s()Ll2/u1;

    .line 186
    .line 187
    .line 188
    move-result-object v3

    .line 189
    if-eqz v3, :cond_7

    .line 190
    .line 191
    new-instance v4, Li40/k0;

    .line 192
    .line 193
    const/16 v5, 0x19

    .line 194
    .line 195
    invoke-direct {v4, v2, v5, v0, v1}, Li40/k0;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 196
    .line 197
    .line 198
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 199
    .line 200
    :cond_7
    return-void
.end method

.method public static final d(II)V
    .locals 3

    .line 1
    if-ltz p0, :cond_0

    .line 2
    .line 3
    if-ge p0, p1, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    new-instance v0, Ljava/lang/IndexOutOfBoundsException;

    .line 7
    .line 8
    const-string v1, "index: "

    .line 9
    .line 10
    const-string v2, ", size: "

    .line 11
    .line 12
    invoke-static {v1, v2, p0, p1}, Lp3/m;->i(Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    invoke-direct {v0, p0}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    throw v0
.end method

.method public static final e(II)V
    .locals 3

    .line 1
    if-ltz p0, :cond_0

    .line 2
    .line 3
    if-gt p0, p1, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    new-instance v0, Ljava/lang/IndexOutOfBoundsException;

    .line 7
    .line 8
    const-string v1, "index: "

    .line 9
    .line 10
    const-string v2, ", size: "

    .line 11
    .line 12
    invoke-static {v1, v2, p0, p1}, Lp3/m;->i(Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    invoke-direct {v0, p0}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    throw v0
.end method

.method public static final f(III)V
    .locals 4

    .line 1
    const-string v0, "fromIndex: "

    .line 2
    .line 3
    if-ltz p0, :cond_1

    .line 4
    .line 5
    if-gt p1, p2, :cond_1

    .line 6
    .line 7
    if-gt p0, p1, :cond_0

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    new-instance p2, Ljava/lang/IllegalArgumentException;

    .line 11
    .line 12
    const-string v1, " > toIndex: "

    .line 13
    .line 14
    invoke-static {v0, v1, p0, p1}, Lp3/m;->i(Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-direct {p2, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    throw p2

    .line 22
    :cond_1
    new-instance v1, Ljava/lang/IndexOutOfBoundsException;

    .line 23
    .line 24
    const-string v2, ", toIndex: "

    .line 25
    .line 26
    const-string v3, ", size: "

    .line 27
    .line 28
    invoke-static {p0, p1, v0, v2, v3}, Lu/w;->j(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-direct {v1, p0}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw v1
.end method
