.class public abstract Lkp/w9;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh6/f;


# direct methods
.method public static final a(Lki/j;Lxh/e;Ll2/o;I)V
    .locals 25

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
    const-string v3, "params"

    .line 8
    .line 9
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    move-object/from16 v9, p2

    .line 13
    .line 14
    check-cast v9, Ll2/t;

    .line 15
    .line 16
    const v3, -0x1a3d8947

    .line 17
    .line 18
    .line 19
    invoke-virtual {v9, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v9, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    const/4 v4, 0x4

    .line 27
    if-eqz v3, :cond_0

    .line 28
    .line 29
    move v3, v4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v3, 0x2

    .line 32
    :goto_0
    or-int/2addr v3, v2

    .line 33
    invoke-virtual {v9, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v5

    .line 37
    if-eqz v5, :cond_1

    .line 38
    .line 39
    const/16 v5, 0x20

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    const/16 v5, 0x10

    .line 43
    .line 44
    :goto_1
    or-int/2addr v3, v5

    .line 45
    and-int/lit8 v5, v3, 0x13

    .line 46
    .line 47
    const/16 v6, 0x12

    .line 48
    .line 49
    const/4 v7, 0x1

    .line 50
    const/4 v8, 0x0

    .line 51
    if-eq v5, v6, :cond_2

    .line 52
    .line 53
    move v5, v7

    .line 54
    goto :goto_2

    .line 55
    :cond_2
    move v5, v8

    .line 56
    :goto_2
    and-int/lit8 v6, v3, 0x1

    .line 57
    .line 58
    invoke-virtual {v9, v6, v5}, Ll2/t;->O(IZ)Z

    .line 59
    .line 60
    .line 61
    move-result v5

    .line 62
    if-eqz v5, :cond_e

    .line 63
    .line 64
    and-int/lit8 v3, v3, 0xe

    .line 65
    .line 66
    if-eq v3, v4, :cond_4

    .line 67
    .line 68
    invoke-virtual {v9, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v3

    .line 72
    if-eqz v3, :cond_3

    .line 73
    .line 74
    goto :goto_3

    .line 75
    :cond_3
    move v7, v8

    .line 76
    :cond_4
    :goto_3
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object v3

    .line 80
    sget-object v10, Ll2/n;->a:Ll2/x0;

    .line 81
    .line 82
    if-nez v7, :cond_5

    .line 83
    .line 84
    if-ne v3, v10, :cond_6

    .line 85
    .line 86
    :cond_5
    new-instance v3, Lpg/m;

    .line 87
    .line 88
    const/16 v4, 0x10

    .line 89
    .line 90
    invoke-direct {v3, v0, v4}, Lpg/m;-><init>(Ljava/lang/Object;I)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {v9, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    :cond_6
    check-cast v3, Lay0/k;

    .line 97
    .line 98
    sget-object v4, Lw3/q1;->a:Ll2/u2;

    .line 99
    .line 100
    invoke-virtual {v9, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v4

    .line 104
    check-cast v4, Ljava/lang/Boolean;

    .line 105
    .line 106
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 107
    .line 108
    .line 109
    move-result v4

    .line 110
    const/16 v16, 0x0

    .line 111
    .line 112
    if-eqz v4, :cond_7

    .line 113
    .line 114
    const v4, -0x105bcaaa

    .line 115
    .line 116
    .line 117
    invoke-virtual {v9, v4}, Ll2/t;->Y(I)V

    .line 118
    .line 119
    .line 120
    invoke-virtual {v9, v8}, Ll2/t;->q(Z)V

    .line 121
    .line 122
    .line 123
    move-object/from16 v4, v16

    .line 124
    .line 125
    goto :goto_4

    .line 126
    :cond_7
    const v4, 0x31054eee

    .line 127
    .line 128
    .line 129
    invoke-virtual {v9, v4}, Ll2/t;->Y(I)V

    .line 130
    .line 131
    .line 132
    sget-object v4, Lzb/x;->a:Ll2/u2;

    .line 133
    .line 134
    invoke-virtual {v9, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v4

    .line 138
    check-cast v4, Lhi/a;

    .line 139
    .line 140
    invoke-virtual {v9, v8}, Ll2/t;->q(Z)V

    .line 141
    .line 142
    .line 143
    :goto_4
    new-instance v7, Lnd/e;

    .line 144
    .line 145
    const/16 v5, 0x17

    .line 146
    .line 147
    invoke-direct {v7, v4, v3, v5}, Lnd/e;-><init>(Lhi/a;Lay0/k;I)V

    .line 148
    .line 149
    .line 150
    invoke-static {v9}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 151
    .line 152
    .line 153
    move-result-object v5

    .line 154
    if-eqz v5, :cond_d

    .line 155
    .line 156
    instance-of v3, v5, Landroidx/lifecycle/k;

    .line 157
    .line 158
    if-eqz v3, :cond_8

    .line 159
    .line 160
    move-object v3, v5

    .line 161
    check-cast v3, Landroidx/lifecycle/k;

    .line 162
    .line 163
    invoke-interface {v3}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 164
    .line 165
    .line 166
    move-result-object v3

    .line 167
    :goto_5
    move-object v8, v3

    .line 168
    goto :goto_6

    .line 169
    :cond_8
    sget-object v3, Lp7/a;->b:Lp7/a;

    .line 170
    .line 171
    goto :goto_5

    .line 172
    :goto_6
    const-class v3, Ltd/x;

    .line 173
    .line 174
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 175
    .line 176
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 177
    .line 178
    .line 179
    move-result-object v4

    .line 180
    const/4 v6, 0x0

    .line 181
    invoke-static/range {v4 .. v9}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 182
    .line 183
    .line 184
    move-result-object v3

    .line 185
    move-object v14, v3

    .line 186
    check-cast v14, Ltd/x;

    .line 187
    .line 188
    iget-object v3, v14, Ltd/x;->j:Lyy0/l1;

    .line 189
    .line 190
    invoke-static {v3, v9}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 191
    .line 192
    .line 193
    move-result-object v3

    .line 194
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object v3

    .line 198
    move-object v13, v3

    .line 199
    check-cast v13, Ltd/s;

    .line 200
    .line 201
    invoke-static {v1, v9}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 202
    .line 203
    .line 204
    move-result-object v15

    .line 205
    invoke-virtual {v9, v13}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 206
    .line 207
    .line 208
    move-result v3

    .line 209
    invoke-virtual {v9, v15}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 210
    .line 211
    .line 212
    move-result v4

    .line 213
    or-int/2addr v3, v4

    .line 214
    invoke-virtual {v9, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 215
    .line 216
    .line 217
    move-result v4

    .line 218
    or-int/2addr v3, v4

    .line 219
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 220
    .line 221
    .line 222
    move-result-object v4

    .line 223
    if-nez v3, :cond_9

    .line 224
    .line 225
    if-ne v4, v10, :cond_a

    .line 226
    .line 227
    :cond_9
    new-instance v11, Lqh/a;

    .line 228
    .line 229
    const/4 v12, 0x6

    .line 230
    invoke-direct/range {v11 .. v16}, Lqh/a;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 231
    .line 232
    .line 233
    invoke-virtual {v9, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 234
    .line 235
    .line 236
    move-object v4, v11

    .line 237
    :cond_a
    check-cast v4, Lay0/n;

    .line 238
    .line 239
    invoke-static {v4, v13, v9}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 240
    .line 241
    .line 242
    sget-object v3, Lzb/x;->b:Ll2/u2;

    .line 243
    .line 244
    invoke-virtual {v9, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 245
    .line 246
    .line 247
    move-result-object v3

    .line 248
    const-string v4, "null cannot be cast to non-null type cariad.charging.multicharge.kitten.chargingstatistics.presentation.ChargingStatisticsUi"

    .line 249
    .line 250
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 251
    .line 252
    .line 253
    check-cast v3, Lrd/c;

    .line 254
    .line 255
    iget-object v4, v14, Ltd/x;->i:Lyy0/l1;

    .line 256
    .line 257
    invoke-static {v4, v9}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 258
    .line 259
    .line 260
    move-result-object v4

    .line 261
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 262
    .line 263
    .line 264
    move-result-object v4

    .line 265
    check-cast v4, Llc/q;

    .line 266
    .line 267
    invoke-virtual {v9, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 268
    .line 269
    .line 270
    move-result v5

    .line 271
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 272
    .line 273
    .line 274
    move-result-object v6

    .line 275
    if-nez v5, :cond_b

    .line 276
    .line 277
    if-ne v6, v10, :cond_c

    .line 278
    .line 279
    :cond_b
    new-instance v17, Lt10/k;

    .line 280
    .line 281
    const/16 v23, 0x0

    .line 282
    .line 283
    const/16 v24, 0x8

    .line 284
    .line 285
    const/16 v18, 0x1

    .line 286
    .line 287
    const-class v20, Ltd/x;

    .line 288
    .line 289
    const-string v21, "onUiEvent"

    .line 290
    .line 291
    const-string v22, "onUiEvent(Lcariad/charging/multicharge/kitten/chargingstatistics/presentation/overview/ChargingStatisticsOverviewUiEvent;)V"

    .line 292
    .line 293
    move-object/from16 v19, v14

    .line 294
    .line 295
    invoke-direct/range {v17 .. v24}, Lt10/k;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 296
    .line 297
    .line 298
    move-object/from16 v6, v17

    .line 299
    .line 300
    invoke-virtual {v9, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 301
    .line 302
    .line 303
    :cond_c
    check-cast v6, Lhy0/g;

    .line 304
    .line 305
    check-cast v6, Lay0/k;

    .line 306
    .line 307
    const/16 v5, 0x8

    .line 308
    .line 309
    invoke-interface {v3, v4, v6, v9, v5}, Lrd/c;->c(Llc/q;Lay0/k;Ll2/o;I)V

    .line 310
    .line 311
    .line 312
    goto :goto_7

    .line 313
    :cond_d
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
    :cond_e
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 322
    .line 323
    .line 324
    :goto_7
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 325
    .line 326
    .line 327
    move-result-object v3

    .line 328
    if-eqz v3, :cond_f

    .line 329
    .line 330
    new-instance v4, Lo50/b;

    .line 331
    .line 332
    const/16 v5, 0x19

    .line 333
    .line 334
    invoke-direct {v4, v2, v5, v0, v1}, Lo50/b;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 335
    .line 336
    .line 337
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 338
    .line 339
    :cond_f
    return-void
.end method
