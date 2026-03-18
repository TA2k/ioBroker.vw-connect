.class public abstract Ljp/oa;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lac/e;Lac/a0;ZLxh/e;Ll2/o;I)V
    .locals 18

    .line 1
    move-object/from16 v2, p1

    .line 2
    .line 3
    const-string v0, "userLegalCountry"

    .line 4
    .line 5
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    move-object/from16 v6, p4

    .line 9
    .line 10
    check-cast v6, Ll2/t;

    .line 11
    .line 12
    const v0, -0x6c99c22

    .line 13
    .line 14
    .line 15
    invoke-virtual {v6, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 16
    .line 17
    .line 18
    and-int/lit8 v0, p5, 0x6

    .line 19
    .line 20
    const/4 v7, 0x2

    .line 21
    const/4 v1, 0x4

    .line 22
    if-nez v0, :cond_1

    .line 23
    .line 24
    move-object/from16 v0, p0

    .line 25
    .line 26
    invoke-virtual {v6, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    if-eqz v3, :cond_0

    .line 31
    .line 32
    move v3, v1

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    move v3, v7

    .line 35
    :goto_0
    or-int v3, p5, v3

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_1
    move-object/from16 v0, p0

    .line 39
    .line 40
    move/from16 v3, p5

    .line 41
    .line 42
    :goto_1
    invoke-virtual {v6, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v4

    .line 46
    const/16 v5, 0x20

    .line 47
    .line 48
    if-eqz v4, :cond_2

    .line 49
    .line 50
    move v4, v5

    .line 51
    goto :goto_2

    .line 52
    :cond_2
    const/16 v4, 0x10

    .line 53
    .line 54
    :goto_2
    or-int/2addr v3, v4

    .line 55
    move/from16 v4, p2

    .line 56
    .line 57
    invoke-virtual {v6, v4}, Ll2/t;->h(Z)Z

    .line 58
    .line 59
    .line 60
    move-result v8

    .line 61
    const/16 v9, 0x100

    .line 62
    .line 63
    if-eqz v8, :cond_3

    .line 64
    .line 65
    move v8, v9

    .line 66
    goto :goto_3

    .line 67
    :cond_3
    const/16 v8, 0x80

    .line 68
    .line 69
    :goto_3
    or-int/2addr v3, v8

    .line 70
    move-object/from16 v8, p3

    .line 71
    .line 72
    invoke-virtual {v6, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v10

    .line 76
    const/16 v11, 0x800

    .line 77
    .line 78
    if-eqz v10, :cond_4

    .line 79
    .line 80
    move v10, v11

    .line 81
    goto :goto_4

    .line 82
    :cond_4
    const/16 v10, 0x400

    .line 83
    .line 84
    :goto_4
    or-int/2addr v3, v10

    .line 85
    and-int/lit16 v10, v3, 0x493

    .line 86
    .line 87
    const/16 v12, 0x492

    .line 88
    .line 89
    const/4 v13, 0x1

    .line 90
    const/4 v14, 0x0

    .line 91
    if-eq v10, v12, :cond_5

    .line 92
    .line 93
    move v10, v13

    .line 94
    goto :goto_5

    .line 95
    :cond_5
    move v10, v14

    .line 96
    :goto_5
    and-int/lit8 v12, v3, 0x1

    .line 97
    .line 98
    invoke-virtual {v6, v12, v10}, Ll2/t;->O(IZ)Z

    .line 99
    .line 100
    .line 101
    move-result v10

    .line 102
    if-eqz v10, :cond_12

    .line 103
    .line 104
    and-int/lit8 v10, v3, 0xe

    .line 105
    .line 106
    if-eq v10, v1, :cond_6

    .line 107
    .line 108
    move v1, v14

    .line 109
    goto :goto_6

    .line 110
    :cond_6
    move v1, v13

    .line 111
    :goto_6
    and-int/lit8 v10, v3, 0x70

    .line 112
    .line 113
    if-eq v10, v5, :cond_8

    .line 114
    .line 115
    invoke-virtual {v6, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    move-result v5

    .line 119
    if-eqz v5, :cond_7

    .line 120
    .line 121
    goto :goto_7

    .line 122
    :cond_7
    move v5, v14

    .line 123
    goto :goto_8

    .line 124
    :cond_8
    :goto_7
    move v5, v13

    .line 125
    :goto_8
    or-int/2addr v1, v5

    .line 126
    and-int/lit16 v5, v3, 0x380

    .line 127
    .line 128
    if-ne v5, v9, :cond_9

    .line 129
    .line 130
    move v5, v13

    .line 131
    goto :goto_9

    .line 132
    :cond_9
    move v5, v14

    .line 133
    :goto_9
    or-int/2addr v1, v5

    .line 134
    and-int/lit16 v3, v3, 0x1c00

    .line 135
    .line 136
    if-ne v3, v11, :cond_a

    .line 137
    .line 138
    goto :goto_a

    .line 139
    :cond_a
    move v13, v14

    .line 140
    :goto_a
    or-int/2addr v1, v13

    .line 141
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v3

    .line 145
    sget-object v9, Ll2/n;->a:Ll2/x0;

    .line 146
    .line 147
    if-nez v1, :cond_b

    .line 148
    .line 149
    if-ne v3, v9, :cond_c

    .line 150
    .line 151
    :cond_b
    new-instance v0, Le2/g;

    .line 152
    .line 153
    const/4 v5, 0x5

    .line 154
    move-object/from16 v1, p0

    .line 155
    .line 156
    move v3, v4

    .line 157
    move-object v4, v8

    .line 158
    invoke-direct/range {v0 .. v5}, Le2/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZLjava/lang/Object;I)V

    .line 159
    .line 160
    .line 161
    invoke-virtual {v6, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 162
    .line 163
    .line 164
    move-object v3, v0

    .line 165
    :cond_c
    check-cast v3, Lay0/k;

    .line 166
    .line 167
    sget-object v0, Lw3/q1;->a:Ll2/u2;

    .line 168
    .line 169
    invoke-virtual {v6, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object v0

    .line 173
    check-cast v0, Ljava/lang/Boolean;

    .line 174
    .line 175
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 176
    .line 177
    .line 178
    move-result v0

    .line 179
    if-eqz v0, :cond_d

    .line 180
    .line 181
    const v0, -0x105bcaaa

    .line 182
    .line 183
    .line 184
    invoke-virtual {v6, v0}, Ll2/t;->Y(I)V

    .line 185
    .line 186
    .line 187
    invoke-virtual {v6, v14}, Ll2/t;->q(Z)V

    .line 188
    .line 189
    .line 190
    const/4 v0, 0x0

    .line 191
    goto :goto_b

    .line 192
    :cond_d
    const v0, 0x31054eee

    .line 193
    .line 194
    .line 195
    invoke-virtual {v6, v0}, Ll2/t;->Y(I)V

    .line 196
    .line 197
    .line 198
    sget-object v0, Lzb/x;->a:Ll2/u2;

    .line 199
    .line 200
    invoke-virtual {v6, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    move-result-object v0

    .line 204
    check-cast v0, Lhi/a;

    .line 205
    .line 206
    invoke-virtual {v6, v14}, Ll2/t;->q(Z)V

    .line 207
    .line 208
    .line 209
    :goto_b
    new-instance v4, Lnd/e;

    .line 210
    .line 211
    invoke-direct {v4, v0, v3, v7}, Lnd/e;-><init>(Lhi/a;Lay0/k;I)V

    .line 212
    .line 213
    .line 214
    invoke-static {v6}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 215
    .line 216
    .line 217
    move-result-object v2

    .line 218
    if-eqz v2, :cond_11

    .line 219
    .line 220
    instance-of v0, v2, Landroidx/lifecycle/k;

    .line 221
    .line 222
    if-eqz v0, :cond_e

    .line 223
    .line 224
    move-object v0, v2

    .line 225
    check-cast v0, Landroidx/lifecycle/k;

    .line 226
    .line 227
    invoke-interface {v0}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 228
    .line 229
    .line 230
    move-result-object v0

    .line 231
    :goto_c
    move-object v5, v0

    .line 232
    goto :goto_d

    .line 233
    :cond_e
    sget-object v0, Lp7/a;->b:Lp7/a;

    .line 234
    .line 235
    goto :goto_c

    .line 236
    :goto_d
    const-class v0, Lng/g;

    .line 237
    .line 238
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 239
    .line 240
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 241
    .line 242
    .line 243
    move-result-object v1

    .line 244
    const/4 v3, 0x0

    .line 245
    invoke-static/range {v1 .. v6}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 246
    .line 247
    .line 248
    move-result-object v0

    .line 249
    move-object v12, v0

    .line 250
    check-cast v12, Lng/g;

    .line 251
    .line 252
    invoke-static {v6}, Lmg/a;->c(Ll2/o;)Lmg/k;

    .line 253
    .line 254
    .line 255
    move-result-object v0

    .line 256
    iget-object v1, v12, Lng/g;->f:Lyy0/l1;

    .line 257
    .line 258
    invoke-static {v1, v6}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 259
    .line 260
    .line 261
    move-result-object v1

    .line 262
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 263
    .line 264
    .line 265
    move-result-object v1

    .line 266
    check-cast v1, Lng/e;

    .line 267
    .line 268
    invoke-virtual {v6, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 269
    .line 270
    .line 271
    move-result v2

    .line 272
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 273
    .line 274
    .line 275
    move-result-object v3

    .line 276
    if-nez v2, :cond_f

    .line 277
    .line 278
    if-ne v3, v9, :cond_10

    .line 279
    .line 280
    :cond_f
    new-instance v10, Ln70/x;

    .line 281
    .line 282
    const/16 v16, 0x0

    .line 283
    .line 284
    const/16 v17, 0xb

    .line 285
    .line 286
    const/4 v11, 0x1

    .line 287
    const-class v13, Lng/g;

    .line 288
    .line 289
    const-string v14, "onUiEvent"

    .line 290
    .line 291
    const-string v15, "onUiEvent(Lcariad/charging/multicharge/kitten/subscription/presentation/billingadress/BillingAddressUiEvent;)V"

    .line 292
    .line 293
    invoke-direct/range {v10 .. v17}, Ln70/x;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 294
    .line 295
    .line 296
    invoke-virtual {v6, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 297
    .line 298
    .line 299
    move-object v3, v10

    .line 300
    :cond_10
    check-cast v3, Lhy0/g;

    .line 301
    .line 302
    check-cast v3, Lay0/k;

    .line 303
    .line 304
    sget-object v2, Lac/x;->v:Lac/x;

    .line 305
    .line 306
    const/16 v2, 0x8

    .line 307
    .line 308
    invoke-interface {v0, v1, v3, v6, v2}, Lmg/k;->n0(Lng/e;Lay0/k;Ll2/o;I)V

    .line 309
    .line 310
    .line 311
    goto :goto_e

    .line 312
    :cond_11
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 313
    .line 314
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 315
    .line 316
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 317
    .line 318
    .line 319
    throw v0

    .line 320
    :cond_12
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 321
    .line 322
    .line 323
    :goto_e
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 324
    .line 325
    .line 326
    move-result-object v7

    .line 327
    if-eqz v7, :cond_13

    .line 328
    .line 329
    new-instance v0, Lbl/d;

    .line 330
    .line 331
    const/16 v6, 0xb

    .line 332
    .line 333
    move-object/from16 v1, p0

    .line 334
    .line 335
    move-object/from16 v2, p1

    .line 336
    .line 337
    move/from16 v3, p2

    .line 338
    .line 339
    move-object/from16 v4, p3

    .line 340
    .line 341
    move/from16 v5, p5

    .line 342
    .line 343
    invoke-direct/range {v0 .. v6}, Lbl/d;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZLjava/lang/Object;II)V

    .line 344
    .line 345
    .line 346
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 347
    .line 348
    :cond_13
    return-void
.end method

.method public static final b(Landroid/content/Context;)Landroid/app/Activity;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p0, Landroid/app/Activity;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    check-cast p0, Landroid/app/Activity;

    .line 11
    .line 12
    return-object p0

    .line 13
    :cond_0
    instance-of v0, p0, Landroid/content/ContextWrapper;

    .line 14
    .line 15
    if-eqz v0, :cond_1

    .line 16
    .line 17
    check-cast p0, Landroid/content/ContextWrapper;

    .line 18
    .line 19
    invoke-virtual {p0}, Landroid/content/ContextWrapper;->getBaseContext()Landroid/content/Context;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    const-string v0, "getBaseContext(...)"

    .line 24
    .line 25
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-static {p0}, Ljp/oa;->b(Landroid/content/Context;)Landroid/app/Activity;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0

    .line 33
    :cond_1
    const/4 p0, 0x0

    .line 34
    return-object p0
.end method
