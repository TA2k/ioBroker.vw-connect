.class public abstract Lkp/c0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/lang/String;Luf/n;Lyj/b;Ll2/o;I)V
    .locals 21

    .line 1
    move-object/from16 v3, p0

    .line 2
    .line 3
    move-object/from16 v4, p1

    .line 4
    .line 5
    move-object/from16 v0, p2

    .line 6
    .line 7
    const-string v1, "vin"

    .line 8
    .line 9
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v1, "plugAndChargeStatus"

    .line 13
    .line 14
    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    move-object/from16 v8, p3

    .line 18
    .line 19
    check-cast v8, Ll2/t;

    .line 20
    .line 21
    const v1, 0x23652ef7

    .line 22
    .line 23
    .line 24
    invoke-virtual {v8, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v8, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    const/4 v2, 0x4

    .line 32
    if-eqz v1, :cond_0

    .line 33
    .line 34
    move v1, v2

    .line 35
    goto :goto_0

    .line 36
    :cond_0
    const/4 v1, 0x2

    .line 37
    :goto_0
    or-int v1, p4, v1

    .line 38
    .line 39
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 40
    .line 41
    .line 42
    move-result v5

    .line 43
    invoke-virtual {v8, v5}, Ll2/t;->e(I)Z

    .line 44
    .line 45
    .line 46
    move-result v5

    .line 47
    const/16 v6, 0x20

    .line 48
    .line 49
    if-eqz v5, :cond_1

    .line 50
    .line 51
    move v5, v6

    .line 52
    goto :goto_1

    .line 53
    :cond_1
    const/16 v5, 0x10

    .line 54
    .line 55
    :goto_1
    or-int/2addr v1, v5

    .line 56
    invoke-virtual {v8, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v5

    .line 60
    const/16 v7, 0x100

    .line 61
    .line 62
    if-eqz v5, :cond_2

    .line 63
    .line 64
    move v5, v7

    .line 65
    goto :goto_2

    .line 66
    :cond_2
    const/16 v5, 0x80

    .line 67
    .line 68
    :goto_2
    or-int/2addr v1, v5

    .line 69
    and-int/lit16 v5, v1, 0x93

    .line 70
    .line 71
    const/16 v9, 0x92

    .line 72
    .line 73
    const/4 v10, 0x1

    .line 74
    const/4 v11, 0x0

    .line 75
    if-eq v5, v9, :cond_3

    .line 76
    .line 77
    move v5, v10

    .line 78
    goto :goto_3

    .line 79
    :cond_3
    move v5, v11

    .line 80
    :goto_3
    and-int/lit8 v9, v1, 0x1

    .line 81
    .line 82
    invoke-virtual {v8, v9, v5}, Ll2/t;->O(IZ)Z

    .line 83
    .line 84
    .line 85
    move-result v5

    .line 86
    if-eqz v5, :cond_e

    .line 87
    .line 88
    and-int/lit8 v5, v1, 0xe

    .line 89
    .line 90
    if-ne v5, v2, :cond_4

    .line 91
    .line 92
    move v2, v10

    .line 93
    goto :goto_4

    .line 94
    :cond_4
    move v2, v11

    .line 95
    :goto_4
    and-int/lit8 v5, v1, 0x70

    .line 96
    .line 97
    if-ne v5, v6, :cond_5

    .line 98
    .line 99
    move v5, v10

    .line 100
    goto :goto_5

    .line 101
    :cond_5
    move v5, v11

    .line 102
    :goto_5
    or-int/2addr v2, v5

    .line 103
    and-int/lit16 v5, v1, 0x380

    .line 104
    .line 105
    if-ne v5, v7, :cond_6

    .line 106
    .line 107
    goto :goto_6

    .line 108
    :cond_6
    move v10, v11

    .line 109
    :goto_6
    or-int/2addr v2, v10

    .line 110
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v5

    .line 114
    sget-object v12, Ll2/n;->a:Ll2/x0;

    .line 115
    .line 116
    if-nez v2, :cond_7

    .line 117
    .line 118
    if-ne v5, v12, :cond_8

    .line 119
    .line 120
    :cond_7
    new-instance v5, Lkv0/e;

    .line 121
    .line 122
    const/16 v2, 0xe

    .line 123
    .line 124
    invoke-direct {v5, v3, v4, v0, v2}, Lkv0/e;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {v8, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 128
    .line 129
    .line 130
    :cond_8
    check-cast v5, Lay0/k;

    .line 131
    .line 132
    sget-object v2, Lw3/q1;->a:Ll2/u2;

    .line 133
    .line 134
    invoke-virtual {v8, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v2

    .line 138
    check-cast v2, Ljava/lang/Boolean;

    .line 139
    .line 140
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 141
    .line 142
    .line 143
    move-result v2

    .line 144
    if-eqz v2, :cond_9

    .line 145
    .line 146
    const v2, -0x105bcaaa

    .line 147
    .line 148
    .line 149
    invoke-virtual {v8, v2}, Ll2/t;->Y(I)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {v8, v11}, Ll2/t;->q(Z)V

    .line 153
    .line 154
    .line 155
    const/4 v2, 0x0

    .line 156
    :goto_7
    move-object v10, v8

    .line 157
    goto :goto_8

    .line 158
    :cond_9
    const v2, 0x31054eee

    .line 159
    .line 160
    .line 161
    invoke-virtual {v8, v2}, Ll2/t;->Y(I)V

    .line 162
    .line 163
    .line 164
    sget-object v2, Lzb/x;->a:Ll2/u2;

    .line 165
    .line 166
    invoke-virtual {v8, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object v2

    .line 170
    check-cast v2, Lhi/a;

    .line 171
    .line 172
    invoke-virtual {v8, v11}, Ll2/t;->q(Z)V

    .line 173
    .line 174
    .line 175
    goto :goto_7

    .line 176
    :goto_8
    new-instance v8, Lnd/e;

    .line 177
    .line 178
    const/16 v6, 0xe

    .line 179
    .line 180
    invoke-direct {v8, v2, v5, v6}, Lnd/e;-><init>(Lhi/a;Lay0/k;I)V

    .line 181
    .line 182
    .line 183
    invoke-static {v10}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 184
    .line 185
    .line 186
    move-result-object v6

    .line 187
    if-eqz v6, :cond_d

    .line 188
    .line 189
    instance-of v2, v6, Landroidx/lifecycle/k;

    .line 190
    .line 191
    if-eqz v2, :cond_a

    .line 192
    .line 193
    move-object v2, v6

    .line 194
    check-cast v2, Landroidx/lifecycle/k;

    .line 195
    .line 196
    invoke-interface {v2}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 197
    .line 198
    .line 199
    move-result-object v2

    .line 200
    :goto_9
    move-object v9, v2

    .line 201
    goto :goto_a

    .line 202
    :cond_a
    sget-object v2, Lp7/a;->b:Lp7/a;

    .line 203
    .line 204
    goto :goto_9

    .line 205
    :goto_a
    const-class v2, Lrf/d;

    .line 206
    .line 207
    sget-object v5, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 208
    .line 209
    invoke-virtual {v5, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 210
    .line 211
    .line 212
    move-result-object v5

    .line 213
    const/4 v7, 0x0

    .line 214
    invoke-static/range {v5 .. v10}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 215
    .line 216
    .line 217
    move-result-object v2

    .line 218
    move-object v15, v2

    .line 219
    check-cast v15, Lrf/d;

    .line 220
    .line 221
    invoke-static {v10}, Ljp/of;->d(Ll2/o;)Lqf/d;

    .line 222
    .line 223
    .line 224
    move-result-object v4

    .line 225
    iget-object v2, v15, Lrf/d;->k:Lyy0/c2;

    .line 226
    .line 227
    invoke-static {v2, v10}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 228
    .line 229
    .line 230
    move-result-object v2

    .line 231
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    move-result-object v2

    .line 235
    move-object v6, v2

    .line 236
    check-cast v6, Llc/q;

    .line 237
    .line 238
    invoke-virtual {v10, v15}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 239
    .line 240
    .line 241
    move-result v2

    .line 242
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 243
    .line 244
    .line 245
    move-result-object v5

    .line 246
    if-nez v2, :cond_b

    .line 247
    .line 248
    if-ne v5, v12, :cond_c

    .line 249
    .line 250
    :cond_b
    new-instance v13, Lo90/f;

    .line 251
    .line 252
    const/16 v19, 0x0

    .line 253
    .line 254
    const/16 v20, 0x15

    .line 255
    .line 256
    const/4 v14, 0x1

    .line 257
    const-class v16, Lrf/d;

    .line 258
    .line 259
    const-string v17, "onUiEvent"

    .line 260
    .line 261
    const-string v18, "onUiEvent(Lcariad/charging/multicharge/kitten/plugandcharge/presentation/activationDeactivation/PlugAndChargeActivationDeactivationUiEvent;)V"

    .line 262
    .line 263
    invoke-direct/range {v13 .. v20}, Lo90/f;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 264
    .line 265
    .line 266
    invoke-virtual {v10, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 267
    .line 268
    .line 269
    move-object v5, v13

    .line 270
    :cond_c
    check-cast v5, Lhy0/g;

    .line 271
    .line 272
    move-object v7, v5

    .line 273
    check-cast v7, Lay0/k;

    .line 274
    .line 275
    shr-int/lit8 v1, v1, 0x3

    .line 276
    .line 277
    and-int/lit8 v1, v1, 0xe

    .line 278
    .line 279
    or-int/lit8 v9, v1, 0x40

    .line 280
    .line 281
    move-object/from16 v5, p1

    .line 282
    .line 283
    move-object v8, v10

    .line 284
    invoke-interface/range {v4 .. v9}, Lqf/d;->y0(Luf/n;Llc/q;Lay0/k;Ll2/o;I)V

    .line 285
    .line 286
    .line 287
    goto :goto_b

    .line 288
    :cond_d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 289
    .line 290
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 291
    .line 292
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 293
    .line 294
    .line 295
    throw v0

    .line 296
    :cond_e
    move-object v10, v8

    .line 297
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 298
    .line 299
    .line 300
    :goto_b
    invoke-virtual {v10}, Ll2/t;->s()Ll2/u1;

    .line 301
    .line 302
    .line 303
    move-result-object v6

    .line 304
    if-eqz v6, :cond_f

    .line 305
    .line 306
    new-instance v0, Lqv0/f;

    .line 307
    .line 308
    const/4 v2, 0x2

    .line 309
    move-object/from16 v4, p1

    .line 310
    .line 311
    move-object/from16 v5, p2

    .line 312
    .line 313
    move/from16 v1, p4

    .line 314
    .line 315
    invoke-direct/range {v0 .. v5}, Lqv0/f;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 316
    .line 317
    .line 318
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 319
    .line 320
    :cond_f
    return-void
.end method
