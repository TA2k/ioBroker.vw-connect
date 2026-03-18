.class public abstract Llp/wb;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lyj/b;Ljava/util/List;Lgz0/p;Lgz0/p;Ll2/o;I)V
    .locals 17

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
    const-string v0, "filters"

    .line 8
    .line 9
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    move-object/from16 v7, p4

    .line 13
    .line 14
    check-cast v7, Ll2/t;

    .line 15
    .line 16
    const v0, -0x3f33bedc

    .line 17
    .line 18
    .line 19
    invoke-virtual {v7, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 20
    .line 21
    .line 22
    move-object/from16 v1, p0

    .line 23
    .line 24
    invoke-virtual {v7, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    const/4 v5, 0x4

    .line 29
    if-eqz v0, :cond_0

    .line 30
    .line 31
    move v0, v5

    .line 32
    goto :goto_0

    .line 33
    :cond_0
    const/4 v0, 0x2

    .line 34
    :goto_0
    or-int v0, p5, v0

    .line 35
    .line 36
    invoke-virtual {v7, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result v6

    .line 40
    if-eqz v6, :cond_1

    .line 41
    .line 42
    const/16 v6, 0x20

    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_1
    const/16 v6, 0x10

    .line 46
    .line 47
    :goto_1
    or-int/2addr v0, v6

    .line 48
    invoke-virtual {v7, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v6

    .line 52
    if-eqz v6, :cond_2

    .line 53
    .line 54
    const/16 v6, 0x100

    .line 55
    .line 56
    goto :goto_2

    .line 57
    :cond_2
    const/16 v6, 0x80

    .line 58
    .line 59
    :goto_2
    or-int/2addr v0, v6

    .line 60
    invoke-virtual {v7, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result v6

    .line 64
    if-eqz v6, :cond_3

    .line 65
    .line 66
    const/16 v6, 0x800

    .line 67
    .line 68
    goto :goto_3

    .line 69
    :cond_3
    const/16 v6, 0x400

    .line 70
    .line 71
    :goto_3
    or-int/2addr v0, v6

    .line 72
    and-int/lit16 v6, v0, 0x493

    .line 73
    .line 74
    const/16 v8, 0x492

    .line 75
    .line 76
    const/4 v9, 0x1

    .line 77
    const/4 v10, 0x0

    .line 78
    if-eq v6, v8, :cond_4

    .line 79
    .line 80
    move v6, v9

    .line 81
    goto :goto_4

    .line 82
    :cond_4
    move v6, v10

    .line 83
    :goto_4
    and-int/lit8 v8, v0, 0x1

    .line 84
    .line 85
    invoke-virtual {v7, v8, v6}, Ll2/t;->O(IZ)Z

    .line 86
    .line 87
    .line 88
    move-result v6

    .line 89
    if-eqz v6, :cond_d

    .line 90
    .line 91
    sget-object v6, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 92
    .line 93
    invoke-virtual {v7, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v6

    .line 97
    check-cast v6, Landroid/content/Context;

    .line 98
    .line 99
    and-int/lit8 v0, v0, 0xe

    .line 100
    .line 101
    if-ne v0, v5, :cond_5

    .line 102
    .line 103
    goto :goto_5

    .line 104
    :cond_5
    move v9, v10

    .line 105
    :goto_5
    invoke-virtual {v7, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    move-result v0

    .line 109
    or-int/2addr v0, v9

    .line 110
    invoke-virtual {v7, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 111
    .line 112
    .line 113
    move-result v5

    .line 114
    or-int/2addr v0, v5

    .line 115
    invoke-virtual {v7, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    move-result v5

    .line 119
    or-int/2addr v0, v5

    .line 120
    invoke-virtual {v7, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 121
    .line 122
    .line 123
    move-result v5

    .line 124
    or-int/2addr v0, v5

    .line 125
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v5

    .line 129
    sget-object v8, Ll2/n;->a:Ll2/x0;

    .line 130
    .line 131
    if-nez v0, :cond_6

    .line 132
    .line 133
    if-ne v5, v8, :cond_7

    .line 134
    .line 135
    :cond_6
    new-instance v0, Lc/b;

    .line 136
    .line 137
    move-object v5, v6

    .line 138
    const/4 v6, 0x5

    .line 139
    invoke-direct/range {v0 .. v6}, Lc/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 140
    .line 141
    .line 142
    invoke-virtual {v7, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 143
    .line 144
    .line 145
    move-object v5, v0

    .line 146
    :cond_7
    check-cast v5, Lay0/k;

    .line 147
    .line 148
    sget-object v0, Lw3/q1;->a:Ll2/u2;

    .line 149
    .line 150
    invoke-virtual {v7, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object v0

    .line 154
    check-cast v0, Ljava/lang/Boolean;

    .line 155
    .line 156
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 157
    .line 158
    .line 159
    move-result v0

    .line 160
    if-eqz v0, :cond_8

    .line 161
    .line 162
    const v0, -0x105bcaaa

    .line 163
    .line 164
    .line 165
    invoke-virtual {v7, v0}, Ll2/t;->Y(I)V

    .line 166
    .line 167
    .line 168
    invoke-virtual {v7, v10}, Ll2/t;->q(Z)V

    .line 169
    .line 170
    .line 171
    const/4 v0, 0x0

    .line 172
    goto :goto_6

    .line 173
    :cond_8
    const v0, 0x31054eee

    .line 174
    .line 175
    .line 176
    invoke-virtual {v7, v0}, Ll2/t;->Y(I)V

    .line 177
    .line 178
    .line 179
    sget-object v0, Lzb/x;->a:Ll2/u2;

    .line 180
    .line 181
    invoke-virtual {v7, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object v0

    .line 185
    check-cast v0, Lhi/a;

    .line 186
    .line 187
    invoke-virtual {v7, v10}, Ll2/t;->q(Z)V

    .line 188
    .line 189
    .line 190
    :goto_6
    new-instance v4, Laf/a;

    .line 191
    .line 192
    const/16 v1, 0x15

    .line 193
    .line 194
    invoke-direct {v4, v0, v5, v1}, Laf/a;-><init>(Lhi/a;Lay0/k;I)V

    .line 195
    .line 196
    .line 197
    invoke-static {v7}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 198
    .line 199
    .line 200
    move-result-object v2

    .line 201
    if-eqz v2, :cond_c

    .line 202
    .line 203
    instance-of v0, v2, Landroidx/lifecycle/k;

    .line 204
    .line 205
    if-eqz v0, :cond_9

    .line 206
    .line 207
    move-object v0, v2

    .line 208
    check-cast v0, Landroidx/lifecycle/k;

    .line 209
    .line 210
    invoke-interface {v0}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 211
    .line 212
    .line 213
    move-result-object v0

    .line 214
    :goto_7
    move-object v5, v0

    .line 215
    goto :goto_8

    .line 216
    :cond_9
    sget-object v0, Lp7/a;->b:Lp7/a;

    .line 217
    .line 218
    goto :goto_7

    .line 219
    :goto_8
    const-class v0, Ljd/j;

    .line 220
    .line 221
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 222
    .line 223
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 224
    .line 225
    .line 226
    move-result-object v1

    .line 227
    const/4 v3, 0x0

    .line 228
    move-object v6, v7

    .line 229
    invoke-static/range {v1 .. v6}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 230
    .line 231
    .line 232
    move-result-object v0

    .line 233
    move-object v11, v0

    .line 234
    check-cast v11, Ljd/j;

    .line 235
    .line 236
    sget-object v0, Lzb/x;->b:Ll2/u2;

    .line 237
    .line 238
    invoke-virtual {v6, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 239
    .line 240
    .line 241
    move-result-object v0

    .line 242
    const-string v1, "null cannot be cast to non-null type cariad.charging.multicharge.kitten.charginghistory.presentation.HomeChargingHistoryUi"

    .line 243
    .line 244
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 245
    .line 246
    .line 247
    check-cast v0, Lfd/b;

    .line 248
    .line 249
    iget-object v1, v11, Ljd/j;->h:Lyy0/c2;

    .line 250
    .line 251
    invoke-static {v1, v6}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 252
    .line 253
    .line 254
    move-result-object v1

    .line 255
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 256
    .line 257
    .line 258
    move-result-object v1

    .line 259
    check-cast v1, Llc/q;

    .line 260
    .line 261
    invoke-virtual {v6, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 262
    .line 263
    .line 264
    move-result v2

    .line 265
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 266
    .line 267
    .line 268
    move-result-object v3

    .line 269
    if-nez v2, :cond_a

    .line 270
    .line 271
    if-ne v3, v8, :cond_b

    .line 272
    .line 273
    :cond_a
    new-instance v9, Lio/ktor/utils/io/g0;

    .line 274
    .line 275
    const/4 v15, 0x0

    .line 276
    const/16 v16, 0x5

    .line 277
    .line 278
    const/4 v10, 0x1

    .line 279
    const-class v12, Ljd/j;

    .line 280
    .line 281
    const-string v13, "onUiEvent"

    .line 282
    .line 283
    const-string v14, "onUiEvent(Lcariad/charging/multicharge/kitten/charginghistory/presentation/home/exportpdf/HomeChargingHistoryExportPDFUiEvent;)V"

    .line 284
    .line 285
    invoke-direct/range {v9 .. v16}, Lio/ktor/utils/io/g0;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 286
    .line 287
    .line 288
    invoke-virtual {v6, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 289
    .line 290
    .line 291
    move-object v3, v9

    .line 292
    :cond_b
    check-cast v3, Lhy0/g;

    .line 293
    .line 294
    check-cast v3, Lay0/k;

    .line 295
    .line 296
    const/16 v2, 0x8

    .line 297
    .line 298
    invoke-interface {v0, v1, v3, v6, v2}, Lfd/b;->p0(Llc/q;Lay0/k;Ll2/o;I)V

    .line 299
    .line 300
    .line 301
    goto :goto_9

    .line 302
    :cond_c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 303
    .line 304
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 305
    .line 306
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 307
    .line 308
    .line 309
    throw v0

    .line 310
    :cond_d
    move-object v6, v7

    .line 311
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 312
    .line 313
    .line 314
    :goto_9
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 315
    .line 316
    .line 317
    move-result-object v7

    .line 318
    if-eqz v7, :cond_e

    .line 319
    .line 320
    new-instance v0, Laj0/b;

    .line 321
    .line 322
    const/16 v6, 0x15

    .line 323
    .line 324
    move-object/from16 v1, p0

    .line 325
    .line 326
    move-object/from16 v2, p1

    .line 327
    .line 328
    move-object/from16 v3, p2

    .line 329
    .line 330
    move-object/from16 v4, p3

    .line 331
    .line 332
    move/from16 v5, p5

    .line 333
    .line 334
    invoke-direct/range {v0 .. v6}, Laj0/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    .line 335
    .line 336
    .line 337
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 338
    .line 339
    :cond_e
    return-void
.end method

.method public static b(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "TRuntime."

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    const/4 v0, 0x3

    .line 8
    invoke-static {p1, v0}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-static {p2, p0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    invoke-static {p1, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 23
    .line 24
    .line 25
    :cond_0
    return-void
.end method

.method public static c(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Exception;)V
    .locals 1

    .line 1
    const-string v0, "TRuntime."

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const/4 v0, 0x6

    .line 8
    invoke-static {p0, v0}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    invoke-static {p0, p1, p2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 15
    .line 16
    .line 17
    :cond_0
    return-void
.end method
