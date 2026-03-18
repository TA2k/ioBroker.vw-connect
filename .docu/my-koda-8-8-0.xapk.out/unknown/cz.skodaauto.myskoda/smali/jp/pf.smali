.class public abstract Ljp/pf;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/lang/String;Lyj/b;Lxh/e;Lh2/d6;Lyy0/l1;Ll2/o;I)V
    .locals 16

    .line 1
    move-object/from16 v5, p4

    .line 2
    .line 3
    move-object/from16 v6, p5

    .line 4
    .line 5
    check-cast v6, Ll2/t;

    .line 6
    .line 7
    const v0, 0x1a1ef8bd

    .line 8
    .line 9
    .line 10
    invoke-virtual {v6, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    move-object/from16 v1, p0

    .line 14
    .line 15
    invoke-virtual {v6, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    const/4 v2, 0x4

    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    move v0, v2

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    const/4 v0, 0x2

    .line 25
    :goto_0
    or-int v0, p6, v0

    .line 26
    .line 27
    move-object/from16 v3, p1

    .line 28
    .line 29
    invoke-virtual {v6, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v4

    .line 33
    const/16 v7, 0x20

    .line 34
    .line 35
    if-eqz v4, :cond_1

    .line 36
    .line 37
    move v4, v7

    .line 38
    goto :goto_1

    .line 39
    :cond_1
    const/16 v4, 0x10

    .line 40
    .line 41
    :goto_1
    or-int/2addr v0, v4

    .line 42
    move-object/from16 v4, p2

    .line 43
    .line 44
    invoke-virtual {v6, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v8

    .line 48
    const/16 v9, 0x100

    .line 49
    .line 50
    if-eqz v8, :cond_2

    .line 51
    .line 52
    move v8, v9

    .line 53
    goto :goto_2

    .line 54
    :cond_2
    const/16 v8, 0x80

    .line 55
    .line 56
    :goto_2
    or-int/2addr v0, v8

    .line 57
    move-object/from16 v8, p3

    .line 58
    .line 59
    invoke-virtual {v6, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v10

    .line 63
    const/16 v11, 0x800

    .line 64
    .line 65
    if-eqz v10, :cond_3

    .line 66
    .line 67
    move v10, v11

    .line 68
    goto :goto_3

    .line 69
    :cond_3
    const/16 v10, 0x400

    .line 70
    .line 71
    :goto_3
    or-int/2addr v0, v10

    .line 72
    invoke-virtual {v6, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v10

    .line 76
    if-eqz v10, :cond_4

    .line 77
    .line 78
    const/16 v10, 0x4000

    .line 79
    .line 80
    goto :goto_4

    .line 81
    :cond_4
    const/16 v10, 0x2000

    .line 82
    .line 83
    :goto_4
    or-int/2addr v0, v10

    .line 84
    and-int/lit16 v10, v0, 0x2493

    .line 85
    .line 86
    const/16 v12, 0x2492

    .line 87
    .line 88
    const/4 v13, 0x1

    .line 89
    const/4 v14, 0x0

    .line 90
    if-eq v10, v12, :cond_5

    .line 91
    .line 92
    move v10, v13

    .line 93
    goto :goto_5

    .line 94
    :cond_5
    move v10, v14

    .line 95
    :goto_5
    and-int/lit8 v12, v0, 0x1

    .line 96
    .line 97
    invoke-virtual {v6, v12, v10}, Ll2/t;->O(IZ)Z

    .line 98
    .line 99
    .line 100
    move-result v10

    .line 101
    if-eqz v10, :cond_11

    .line 102
    .line 103
    and-int/lit8 v10, v0, 0xe

    .line 104
    .line 105
    if-ne v10, v2, :cond_6

    .line 106
    .line 107
    move v2, v13

    .line 108
    goto :goto_6

    .line 109
    :cond_6
    move v2, v14

    .line 110
    :goto_6
    and-int/lit8 v10, v0, 0x70

    .line 111
    .line 112
    if-ne v10, v7, :cond_7

    .line 113
    .line 114
    move v7, v13

    .line 115
    goto :goto_7

    .line 116
    :cond_7
    move v7, v14

    .line 117
    :goto_7
    or-int/2addr v2, v7

    .line 118
    and-int/lit16 v7, v0, 0x380

    .line 119
    .line 120
    if-ne v7, v9, :cond_8

    .line 121
    .line 122
    move v7, v13

    .line 123
    goto :goto_8

    .line 124
    :cond_8
    move v7, v14

    .line 125
    :goto_8
    or-int/2addr v2, v7

    .line 126
    and-int/lit16 v0, v0, 0x1c00

    .line 127
    .line 128
    if-ne v0, v11, :cond_9

    .line 129
    .line 130
    goto :goto_9

    .line 131
    :cond_9
    move v13, v14

    .line 132
    :goto_9
    or-int v0, v2, v13

    .line 133
    .line 134
    invoke-virtual {v6, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 135
    .line 136
    .line 137
    move-result v2

    .line 138
    or-int/2addr v0, v2

    .line 139
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object v2

    .line 143
    sget-object v7, Ll2/n;->a:Ll2/x0;

    .line 144
    .line 145
    if-nez v0, :cond_a

    .line 146
    .line 147
    if-ne v2, v7, :cond_b

    .line 148
    .line 149
    :cond_a
    new-instance v0, Lc/b;

    .line 150
    .line 151
    move-object v2, v3

    .line 152
    move-object v3, v4

    .line 153
    move-object v4, v8

    .line 154
    invoke-direct/range {v0 .. v5}, Lc/b;-><init>(Ljava/lang/String;Lyj/b;Lxh/e;Lh2/d6;Lyy0/l1;)V

    .line 155
    .line 156
    .line 157
    invoke-virtual {v6, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 158
    .line 159
    .line 160
    move-object v2, v0

    .line 161
    :cond_b
    check-cast v2, Lay0/k;

    .line 162
    .line 163
    sget-object v0, Lw3/q1;->a:Ll2/u2;

    .line 164
    .line 165
    invoke-virtual {v6, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object v0

    .line 169
    check-cast v0, Ljava/lang/Boolean;

    .line 170
    .line 171
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 172
    .line 173
    .line 174
    move-result v0

    .line 175
    if-eqz v0, :cond_c

    .line 176
    .line 177
    const v0, -0x105bcaaa

    .line 178
    .line 179
    .line 180
    invoke-virtual {v6, v0}, Ll2/t;->Y(I)V

    .line 181
    .line 182
    .line 183
    invoke-virtual {v6, v14}, Ll2/t;->q(Z)V

    .line 184
    .line 185
    .line 186
    const/4 v0, 0x0

    .line 187
    goto :goto_a

    .line 188
    :cond_c
    const v0, 0x31054eee

    .line 189
    .line 190
    .line 191
    invoke-virtual {v6, v0}, Ll2/t;->Y(I)V

    .line 192
    .line 193
    .line 194
    sget-object v0, Lzb/x;->a:Ll2/u2;

    .line 195
    .line 196
    invoke-virtual {v6, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 197
    .line 198
    .line 199
    move-result-object v0

    .line 200
    check-cast v0, Lhi/a;

    .line 201
    .line 202
    invoke-virtual {v6, v14}, Ll2/t;->q(Z)V

    .line 203
    .line 204
    .line 205
    :goto_a
    new-instance v3, Lnd/e;

    .line 206
    .line 207
    const/16 v1, 0xb

    .line 208
    .line 209
    invoke-direct {v3, v0, v2, v1}, Lnd/e;-><init>(Lhi/a;Lay0/k;I)V

    .line 210
    .line 211
    .line 212
    invoke-static {v6}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 213
    .line 214
    .line 215
    move-result-object v1

    .line 216
    if-eqz v1, :cond_10

    .line 217
    .line 218
    instance-of v0, v1, Landroidx/lifecycle/k;

    .line 219
    .line 220
    if-eqz v0, :cond_d

    .line 221
    .line 222
    move-object v0, v1

    .line 223
    check-cast v0, Landroidx/lifecycle/k;

    .line 224
    .line 225
    invoke-interface {v0}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 226
    .line 227
    .line 228
    move-result-object v0

    .line 229
    :goto_b
    move-object v4, v0

    .line 230
    goto :goto_c

    .line 231
    :cond_d
    sget-object v0, Lp7/a;->b:Lp7/a;

    .line 232
    .line 233
    goto :goto_b

    .line 234
    :goto_c
    const-class v0, Lqg/n;

    .line 235
    .line 236
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 237
    .line 238
    invoke-virtual {v2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 239
    .line 240
    .line 241
    move-result-object v0

    .line 242
    const/4 v2, 0x0

    .line 243
    move-object v5, v6

    .line 244
    invoke-static/range {v0 .. v5}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 245
    .line 246
    .line 247
    move-result-object v0

    .line 248
    move-object v10, v0

    .line 249
    check-cast v10, Lqg/n;

    .line 250
    .line 251
    invoke-static {v5}, Lmg/a;->c(Ll2/o;)Lmg/k;

    .line 252
    .line 253
    .line 254
    move-result-object v0

    .line 255
    iget-object v1, v10, Lqg/n;->m:Lyy0/l1;

    .line 256
    .line 257
    invoke-static {v1, v5}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 258
    .line 259
    .line 260
    move-result-object v1

    .line 261
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 262
    .line 263
    .line 264
    move-result-object v1

    .line 265
    check-cast v1, Llc/q;

    .line 266
    .line 267
    invoke-virtual {v5, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 268
    .line 269
    .line 270
    move-result v2

    .line 271
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 272
    .line 273
    .line 274
    move-result-object v3

    .line 275
    if-nez v2, :cond_e

    .line 276
    .line 277
    if-ne v3, v7, :cond_f

    .line 278
    .line 279
    :cond_e
    new-instance v8, Lo90/f;

    .line 280
    .line 281
    const/4 v14, 0x0

    .line 282
    const/16 v15, 0xa

    .line 283
    .line 284
    const/4 v9, 0x1

    .line 285
    const-class v11, Lqg/n;

    .line 286
    .line 287
    const-string v12, "onUiEvent"

    .line 288
    .line 289
    const-string v13, "onUiEvent(Lcariad/charging/multicharge/kitten/subscription/presentation/overview/SubscriptionOverviewUiEvent;)V"

    .line 290
    .line 291
    invoke-direct/range {v8 .. v15}, Lo90/f;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 292
    .line 293
    .line 294
    invoke-virtual {v5, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 295
    .line 296
    .line 297
    move-object v3, v8

    .line 298
    :cond_f
    check-cast v3, Lhy0/g;

    .line 299
    .line 300
    check-cast v3, Lay0/k;

    .line 301
    .line 302
    const/16 v2, 0x8

    .line 303
    .line 304
    invoke-interface {v0, v1, v3, v5, v2}, Lmg/k;->S(Llc/q;Lay0/k;Ll2/o;I)V

    .line 305
    .line 306
    .line 307
    goto :goto_d

    .line 308
    :cond_10
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 309
    .line 310
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 311
    .line 312
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 313
    .line 314
    .line 315
    throw v0

    .line 316
    :cond_11
    move-object v5, v6

    .line 317
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 318
    .line 319
    .line 320
    :goto_d
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 321
    .line 322
    .line 323
    move-result-object v8

    .line 324
    if-eqz v8, :cond_12

    .line 325
    .line 326
    new-instance v0, Lb10/c;

    .line 327
    .line 328
    const/16 v7, 0x1c

    .line 329
    .line 330
    move-object/from16 v1, p0

    .line 331
    .line 332
    move-object/from16 v2, p1

    .line 333
    .line 334
    move-object/from16 v3, p2

    .line 335
    .line 336
    move-object/from16 v4, p3

    .line 337
    .line 338
    move-object/from16 v5, p4

    .line 339
    .line 340
    move/from16 v6, p6

    .line 341
    .line 342
    invoke-direct/range {v0 .. v7}, Lb10/c;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    .line 343
    .line 344
    .line 345
    iput-object v0, v8, Ll2/u1;->d:Lay0/n;

    .line 346
    .line 347
    :cond_12
    return-void
.end method

.method public static b(Landroid/view/Window;Z)V
    .locals 2

    .line 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    const/16 v1, 0x23

    .line 4
    .line 5
    if-lt v0, v1, :cond_0

    .line 6
    .line 7
    invoke-static {p0, p1}, Ld6/h;->g(Landroid/view/Window;Z)V

    .line 8
    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    const/16 v1, 0x1e

    .line 12
    .line 13
    if-lt v0, v1, :cond_1

    .line 14
    .line 15
    invoke-static {p0, p1}, Ld6/h;->f(Landroid/view/Window;Z)V

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :cond_1
    invoke-virtual {p0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    invoke-virtual {p0}, Landroid/view/View;->getSystemUiVisibility()I

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz p1, :cond_2

    .line 28
    .line 29
    and-int/lit16 p1, v0, -0x701

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_2
    or-int/lit16 p1, v0, 0x700

    .line 33
    .line 34
    :goto_0
    invoke-virtual {p0, p1}, Landroid/view/View;->setSystemUiVisibility(I)V

    .line 35
    .line 36
    .line 37
    return-void
.end method
