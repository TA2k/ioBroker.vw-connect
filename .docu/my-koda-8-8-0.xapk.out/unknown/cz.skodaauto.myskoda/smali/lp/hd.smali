.class public abstract Llp/hd;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lwe/d;Lay0/a;Ll2/o;I)V
    .locals 6

    .line 1
    check-cast p2, Ll2/t;

    .line 2
    .line 3
    const v0, -0x67014381

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p3, 0x6

    .line 10
    .line 11
    const/4 v1, 0x4

    .line 12
    if-nez v0, :cond_2

    .line 13
    .line 14
    and-int/lit8 v0, p3, 0x8

    .line 15
    .line 16
    if-nez v0, :cond_0

    .line 17
    .line 18
    invoke-virtual {p2, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    invoke-virtual {p2, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    :goto_0
    if-eqz v0, :cond_1

    .line 28
    .line 29
    move v0, v1

    .line 30
    goto :goto_1

    .line 31
    :cond_1
    const/4 v0, 0x2

    .line 32
    :goto_1
    or-int/2addr v0, p3

    .line 33
    goto :goto_2

    .line 34
    :cond_2
    move v0, p3

    .line 35
    :goto_2
    and-int/lit8 v2, p3, 0x30

    .line 36
    .line 37
    if-nez v2, :cond_4

    .line 38
    .line 39
    invoke-virtual {p2, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v2

    .line 43
    if-eqz v2, :cond_3

    .line 44
    .line 45
    const/16 v2, 0x20

    .line 46
    .line 47
    goto :goto_3

    .line 48
    :cond_3
    const/16 v2, 0x10

    .line 49
    .line 50
    :goto_3
    or-int/2addr v0, v2

    .line 51
    :cond_4
    and-int/lit8 v2, v0, 0x13

    .line 52
    .line 53
    const/16 v3, 0x12

    .line 54
    .line 55
    const/4 v4, 0x0

    .line 56
    const/4 v5, 0x1

    .line 57
    if-eq v2, v3, :cond_5

    .line 58
    .line 59
    move v2, v5

    .line 60
    goto :goto_4

    .line 61
    :cond_5
    move v2, v4

    .line 62
    :goto_4
    and-int/lit8 v3, v0, 0x1

    .line 63
    .line 64
    invoke-virtual {p2, v3, v2}, Ll2/t;->O(IZ)Z

    .line 65
    .line 66
    .line 67
    move-result v2

    .line 68
    if-eqz v2, :cond_a

    .line 69
    .line 70
    invoke-static {p1, p2}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 71
    .line 72
    .line 73
    move-result-object v2

    .line 74
    and-int/lit8 v3, v0, 0xe

    .line 75
    .line 76
    if-eq v3, v1, :cond_6

    .line 77
    .line 78
    and-int/lit8 v0, v0, 0x8

    .line 79
    .line 80
    if-eqz v0, :cond_7

    .line 81
    .line 82
    invoke-virtual {p2, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 83
    .line 84
    .line 85
    move-result v0

    .line 86
    if-eqz v0, :cond_7

    .line 87
    .line 88
    :cond_6
    move v4, v5

    .line 89
    :cond_7
    invoke-virtual {p2, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result v0

    .line 93
    or-int/2addr v0, v4

    .line 94
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v1

    .line 98
    if-nez v0, :cond_8

    .line 99
    .line 100
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 101
    .line 102
    if-ne v1, v0, :cond_9

    .line 103
    .line 104
    :cond_8
    new-instance v1, Lwa0/c;

    .line 105
    .line 106
    const/4 v0, 0x0

    .line 107
    const/4 v3, 0x1

    .line 108
    invoke-direct {v1, v3, p0, v2, v0}, Lwa0/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {p2, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 112
    .line 113
    .line 114
    :cond_9
    check-cast v1, Lay0/n;

    .line 115
    .line 116
    invoke-static {v1, p0, p2}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 117
    .line 118
    .line 119
    goto :goto_5

    .line 120
    :cond_a
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 121
    .line 122
    .line 123
    :goto_5
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 124
    .line 125
    .line 126
    move-result-object p2

    .line 127
    if-eqz p2, :cond_b

    .line 128
    .line 129
    new-instance v0, Ltj/i;

    .line 130
    .line 131
    const/16 v1, 0x10

    .line 132
    .line 133
    invoke-direct {v0, p3, v1, p0, p1}, Ltj/i;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 137
    .line 138
    :cond_b
    return-void
.end method

.method public static final b(Ljava/lang/String;Ljava/lang/String;Lje/r;Lay0/a;Ll2/o;I)V
    .locals 21

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v3, p2

    .line 6
    .line 7
    move-object/from16 v4, p3

    .line 8
    .line 9
    const-string v0, "vin"

    .line 10
    .line 11
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    const-string v0, "profileUuid"

    .line 15
    .line 16
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    const-string v0, "fixedRateRegistered"

    .line 20
    .line 21
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    move-object/from16 v10, p4

    .line 25
    .line 26
    check-cast v10, Ll2/t;

    .line 27
    .line 28
    const v0, -0x7ccc91e8

    .line 29
    .line 30
    .line 31
    invoke-virtual {v10, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 32
    .line 33
    .line 34
    invoke-virtual {v10, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    const/4 v5, 0x4

    .line 39
    if-eqz v0, :cond_0

    .line 40
    .line 41
    move v0, v5

    .line 42
    goto :goto_0

    .line 43
    :cond_0
    const/4 v0, 0x2

    .line 44
    :goto_0
    or-int v0, p5, v0

    .line 45
    .line 46
    invoke-virtual {v10, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v6

    .line 50
    const/16 v7, 0x20

    .line 51
    .line 52
    if-eqz v6, :cond_1

    .line 53
    .line 54
    move v6, v7

    .line 55
    goto :goto_1

    .line 56
    :cond_1
    const/16 v6, 0x10

    .line 57
    .line 58
    :goto_1
    or-int/2addr v0, v6

    .line 59
    invoke-virtual {v10, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v6

    .line 63
    const/16 v8, 0x100

    .line 64
    .line 65
    if-eqz v6, :cond_2

    .line 66
    .line 67
    move v6, v8

    .line 68
    goto :goto_2

    .line 69
    :cond_2
    const/16 v6, 0x80

    .line 70
    .line 71
    :goto_2
    or-int/2addr v0, v6

    .line 72
    invoke-virtual {v10, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v6

    .line 76
    if-eqz v6, :cond_3

    .line 77
    .line 78
    const/16 v6, 0x800

    .line 79
    .line 80
    goto :goto_3

    .line 81
    :cond_3
    const/16 v6, 0x400

    .line 82
    .line 83
    :goto_3
    or-int/2addr v0, v6

    .line 84
    and-int/lit16 v6, v0, 0x493

    .line 85
    .line 86
    const/16 v9, 0x492

    .line 87
    .line 88
    const/4 v11, 0x1

    .line 89
    const/4 v12, 0x0

    .line 90
    if-eq v6, v9, :cond_4

    .line 91
    .line 92
    move v6, v11

    .line 93
    goto :goto_4

    .line 94
    :cond_4
    move v6, v12

    .line 95
    :goto_4
    and-int/lit8 v9, v0, 0x1

    .line 96
    .line 97
    invoke-virtual {v10, v9, v6}, Ll2/t;->O(IZ)Z

    .line 98
    .line 99
    .line 100
    move-result v6

    .line 101
    if-eqz v6, :cond_f

    .line 102
    .line 103
    and-int/lit8 v6, v0, 0xe

    .line 104
    .line 105
    if-ne v6, v5, :cond_5

    .line 106
    .line 107
    move v5, v11

    .line 108
    goto :goto_5

    .line 109
    :cond_5
    move v5, v12

    .line 110
    :goto_5
    and-int/lit8 v6, v0, 0x70

    .line 111
    .line 112
    if-ne v6, v7, :cond_6

    .line 113
    .line 114
    move v6, v11

    .line 115
    goto :goto_6

    .line 116
    :cond_6
    move v6, v12

    .line 117
    :goto_6
    or-int/2addr v5, v6

    .line 118
    and-int/lit16 v6, v0, 0x380

    .line 119
    .line 120
    if-ne v6, v8, :cond_7

    .line 121
    .line 122
    goto :goto_7

    .line 123
    :cond_7
    move v11, v12

    .line 124
    :goto_7
    or-int/2addr v5, v11

    .line 125
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v6

    .line 129
    sget-object v11, Ll2/n;->a:Ll2/x0;

    .line 130
    .line 131
    if-nez v5, :cond_8

    .line 132
    .line 133
    if-ne v6, v11, :cond_9

    .line 134
    .line 135
    :cond_8
    new-instance v6, Lkv0/e;

    .line 136
    .line 137
    const/16 v5, 0x1d

    .line 138
    .line 139
    invoke-direct {v6, v1, v2, v3, v5}, Lkv0/e;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 140
    .line 141
    .line 142
    invoke-virtual {v10, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 143
    .line 144
    .line 145
    :cond_9
    check-cast v6, Lay0/k;

    .line 146
    .line 147
    sget-object v5, Lw3/q1;->a:Ll2/u2;

    .line 148
    .line 149
    invoke-virtual {v10, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object v5

    .line 153
    check-cast v5, Ljava/lang/Boolean;

    .line 154
    .line 155
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 156
    .line 157
    .line 158
    move-result v5

    .line 159
    if-eqz v5, :cond_a

    .line 160
    .line 161
    const v5, -0x105bcaaa

    .line 162
    .line 163
    .line 164
    invoke-virtual {v10, v5}, Ll2/t;->Y(I)V

    .line 165
    .line 166
    .line 167
    invoke-virtual {v10, v12}, Ll2/t;->q(Z)V

    .line 168
    .line 169
    .line 170
    const/4 v5, 0x0

    .line 171
    goto :goto_8

    .line 172
    :cond_a
    const v5, 0x31054eee

    .line 173
    .line 174
    .line 175
    invoke-virtual {v10, v5}, Ll2/t;->Y(I)V

    .line 176
    .line 177
    .line 178
    sget-object v5, Lzb/x;->a:Ll2/u2;

    .line 179
    .line 180
    invoke-virtual {v10, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object v5

    .line 184
    check-cast v5, Lhi/a;

    .line 185
    .line 186
    invoke-virtual {v10, v12}, Ll2/t;->q(Z)V

    .line 187
    .line 188
    .line 189
    :goto_8
    new-instance v8, Lvh/i;

    .line 190
    .line 191
    const/4 v7, 0x2

    .line 192
    invoke-direct {v8, v7, v5, v6}, Lvh/i;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 193
    .line 194
    .line 195
    invoke-static {v10}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 196
    .line 197
    .line 198
    move-result-object v6

    .line 199
    if-eqz v6, :cond_e

    .line 200
    .line 201
    instance-of v5, v6, Landroidx/lifecycle/k;

    .line 202
    .line 203
    if-eqz v5, :cond_b

    .line 204
    .line 205
    move-object v5, v6

    .line 206
    check-cast v5, Landroidx/lifecycle/k;

    .line 207
    .line 208
    invoke-interface {v5}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 209
    .line 210
    .line 211
    move-result-object v5

    .line 212
    :goto_9
    move-object v9, v5

    .line 213
    goto :goto_a

    .line 214
    :cond_b
    sget-object v5, Lp7/a;->b:Lp7/a;

    .line 215
    .line 216
    goto :goto_9

    .line 217
    :goto_a
    const-class v5, Lwe/f;

    .line 218
    .line 219
    sget-object v7, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 220
    .line 221
    invoke-virtual {v7, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 222
    .line 223
    .line 224
    move-result-object v5

    .line 225
    const/4 v7, 0x0

    .line 226
    invoke-static/range {v5 .. v10}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 227
    .line 228
    .line 229
    move-result-object v5

    .line 230
    move-object v15, v5

    .line 231
    check-cast v15, Lwe/f;

    .line 232
    .line 233
    iget-object v5, v15, Lwe/f;->k:Lyy0/l1;

    .line 234
    .line 235
    invoke-static {v5, v10}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 236
    .line 237
    .line 238
    move-result-object v5

    .line 239
    invoke-interface {v5}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 240
    .line 241
    .line 242
    move-result-object v6

    .line 243
    check-cast v6, Lwe/d;

    .line 244
    .line 245
    shr-int/lit8 v0, v0, 0x6

    .line 246
    .line 247
    and-int/lit8 v0, v0, 0x70

    .line 248
    .line 249
    invoke-static {v6, v4, v10, v0}, Llp/hd;->a(Lwe/d;Lay0/a;Ll2/o;I)V

    .line 250
    .line 251
    .line 252
    invoke-static {v10}, Llp/nf;->a(Ll2/o;)Lle/c;

    .line 253
    .line 254
    .line 255
    move-result-object v0

    .line 256
    invoke-interface {v5}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 257
    .line 258
    .line 259
    move-result-object v5

    .line 260
    check-cast v5, Lwe/d;

    .line 261
    .line 262
    invoke-virtual {v10, v15}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 263
    .line 264
    .line 265
    move-result v6

    .line 266
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 267
    .line 268
    .line 269
    move-result-object v7

    .line 270
    if-nez v6, :cond_c

    .line 271
    .line 272
    if-ne v7, v11, :cond_d

    .line 273
    .line 274
    :cond_c
    new-instance v13, Lwc/a;

    .line 275
    .line 276
    const/16 v19, 0x0

    .line 277
    .line 278
    const/16 v20, 0x1

    .line 279
    .line 280
    const/4 v14, 0x1

    .line 281
    const-class v16, Lwe/f;

    .line 282
    .line 283
    const-string v17, "onUiEvent"

    .line 284
    .line 285
    const-string v18, "onUiEvent(Lcariad/charging/multicharge/kitten/kola/presentation/wizard/fixedrate/enterprice/KolaWizardEnterPriceUiEvent;)V"

    .line 286
    .line 287
    invoke-direct/range {v13 .. v20}, Lwc/a;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 288
    .line 289
    .line 290
    invoke-virtual {v10, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 291
    .line 292
    .line 293
    move-object v7, v13

    .line 294
    :cond_d
    check-cast v7, Lhy0/g;

    .line 295
    .line 296
    check-cast v7, Lay0/k;

    .line 297
    .line 298
    invoke-interface {v0, v5, v7, v10, v12}, Lle/c;->q(Lwe/d;Lay0/k;Ll2/o;I)V

    .line 299
    .line 300
    .line 301
    goto :goto_b

    .line 302
    :cond_e
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
    :cond_f
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 311
    .line 312
    .line 313
    :goto_b
    invoke-virtual {v10}, Ll2/t;->s()Ll2/u1;

    .line 314
    .line 315
    .line 316
    move-result-object v7

    .line 317
    if-eqz v7, :cond_10

    .line 318
    .line 319
    new-instance v0, Lo50/p;

    .line 320
    .line 321
    const/16 v6, 0x1c

    .line 322
    .line 323
    move/from16 v5, p5

    .line 324
    .line 325
    invoke-direct/range {v0 .. v6}, Lo50/p;-><init>(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Lay0/a;II)V

    .line 326
    .line 327
    .line 328
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 329
    .line 330
    :cond_10
    return-void
.end method

.method public static c(Lka/r0;Lka/u;Landroid/view/View;Landroid/view/View;Lka/f0;Z)I
    .locals 0

    .line 1
    invoke-virtual {p4}, Lka/f0;->v()I

    .line 2
    .line 3
    .line 4
    move-result p4

    .line 5
    if-eqz p4, :cond_2

    .line 6
    .line 7
    invoke-virtual {p0}, Lka/r0;->b()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    if-eqz p0, :cond_2

    .line 12
    .line 13
    if-eqz p2, :cond_2

    .line 14
    .line 15
    if-nez p3, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    if-nez p5, :cond_1

    .line 19
    .line 20
    invoke-static {p2}, Lka/f0;->H(Landroid/view/View;)I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    invoke-static {p3}, Lka/f0;->H(Landroid/view/View;)I

    .line 25
    .line 26
    .line 27
    move-result p1

    .line 28
    sub-int/2addr p0, p1

    .line 29
    invoke-static {p0}, Ljava/lang/Math;->abs(I)I

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    add-int/lit8 p0, p0, 0x1

    .line 34
    .line 35
    return p0

    .line 36
    :cond_1
    invoke-virtual {p1, p3}, Lka/u;->d(Landroid/view/View;)I

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    invoke-virtual {p1, p2}, Lka/u;->g(Landroid/view/View;)I

    .line 41
    .line 42
    .line 43
    move-result p2

    .line 44
    sub-int/2addr p0, p2

    .line 45
    invoke-virtual {p1}, Lka/u;->n()I

    .line 46
    .line 47
    .line 48
    move-result p1

    .line 49
    invoke-static {p1, p0}, Ljava/lang/Math;->min(II)I

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    return p0

    .line 54
    :cond_2
    :goto_0
    const/4 p0, 0x0

    .line 55
    return p0
.end method

.method public static d(Lka/r0;Lka/u;Landroid/view/View;Landroid/view/View;Lka/f0;ZZ)I
    .locals 3

    .line 1
    invoke-virtual {p4}, Lka/f0;->v()I

    .line 2
    .line 3
    .line 4
    move-result p4

    .line 5
    const/4 v0, 0x0

    .line 6
    if-eqz p4, :cond_3

    .line 7
    .line 8
    invoke-virtual {p0}, Lka/r0;->b()I

    .line 9
    .line 10
    .line 11
    move-result p4

    .line 12
    if-eqz p4, :cond_3

    .line 13
    .line 14
    if-eqz p2, :cond_3

    .line 15
    .line 16
    if-nez p3, :cond_0

    .line 17
    .line 18
    goto :goto_1

    .line 19
    :cond_0
    invoke-static {p2}, Lka/f0;->H(Landroid/view/View;)I

    .line 20
    .line 21
    .line 22
    move-result p4

    .line 23
    invoke-static {p3}, Lka/f0;->H(Landroid/view/View;)I

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    invoke-static {p4, v1}, Ljava/lang/Math;->min(II)I

    .line 28
    .line 29
    .line 30
    move-result p4

    .line 31
    invoke-static {p2}, Lka/f0;->H(Landroid/view/View;)I

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    invoke-static {p3}, Lka/f0;->H(Landroid/view/View;)I

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    invoke-static {v1, v2}, Ljava/lang/Math;->max(II)I

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz p6, :cond_1

    .line 44
    .line 45
    invoke-virtual {p0}, Lka/r0;->b()I

    .line 46
    .line 47
    .line 48
    move-result p0

    .line 49
    sub-int/2addr p0, v1

    .line 50
    add-int/lit8 p0, p0, -0x1

    .line 51
    .line 52
    invoke-static {v0, p0}, Ljava/lang/Math;->max(II)I

    .line 53
    .line 54
    .line 55
    move-result p0

    .line 56
    goto :goto_0

    .line 57
    :cond_1
    invoke-static {v0, p4}, Ljava/lang/Math;->max(II)I

    .line 58
    .line 59
    .line 60
    move-result p0

    .line 61
    :goto_0
    if-nez p5, :cond_2

    .line 62
    .line 63
    return p0

    .line 64
    :cond_2
    invoke-virtual {p1, p3}, Lka/u;->d(Landroid/view/View;)I

    .line 65
    .line 66
    .line 67
    move-result p4

    .line 68
    invoke-virtual {p1, p2}, Lka/u;->g(Landroid/view/View;)I

    .line 69
    .line 70
    .line 71
    move-result p5

    .line 72
    sub-int/2addr p4, p5

    .line 73
    invoke-static {p4}, Ljava/lang/Math;->abs(I)I

    .line 74
    .line 75
    .line 76
    move-result p4

    .line 77
    invoke-static {p2}, Lka/f0;->H(Landroid/view/View;)I

    .line 78
    .line 79
    .line 80
    move-result p5

    .line 81
    invoke-static {p3}, Lka/f0;->H(Landroid/view/View;)I

    .line 82
    .line 83
    .line 84
    move-result p3

    .line 85
    sub-int/2addr p5, p3

    .line 86
    invoke-static {p5}, Ljava/lang/Math;->abs(I)I

    .line 87
    .line 88
    .line 89
    move-result p3

    .line 90
    add-int/lit8 p3, p3, 0x1

    .line 91
    .line 92
    int-to-float p4, p4

    .line 93
    int-to-float p3, p3

    .line 94
    div-float/2addr p4, p3

    .line 95
    int-to-float p0, p0

    .line 96
    mul-float/2addr p0, p4

    .line 97
    invoke-virtual {p1}, Lka/u;->m()I

    .line 98
    .line 99
    .line 100
    move-result p3

    .line 101
    invoke-virtual {p1, p2}, Lka/u;->g(Landroid/view/View;)I

    .line 102
    .line 103
    .line 104
    move-result p1

    .line 105
    sub-int/2addr p3, p1

    .line 106
    int-to-float p1, p3

    .line 107
    add-float/2addr p0, p1

    .line 108
    invoke-static {p0}, Ljava/lang/Math;->round(F)I

    .line 109
    .line 110
    .line 111
    move-result p0

    .line 112
    return p0

    .line 113
    :cond_3
    :goto_1
    return v0
.end method

.method public static e(Lka/r0;Lka/u;Landroid/view/View;Landroid/view/View;Lka/f0;Z)I
    .locals 0

    .line 1
    invoke-virtual {p4}, Lka/f0;->v()I

    .line 2
    .line 3
    .line 4
    move-result p4

    .line 5
    if-eqz p4, :cond_2

    .line 6
    .line 7
    invoke-virtual {p0}, Lka/r0;->b()I

    .line 8
    .line 9
    .line 10
    move-result p4

    .line 11
    if-eqz p4, :cond_2

    .line 12
    .line 13
    if-eqz p2, :cond_2

    .line 14
    .line 15
    if-nez p3, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    if-nez p5, :cond_1

    .line 19
    .line 20
    invoke-virtual {p0}, Lka/r0;->b()I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    return p0

    .line 25
    :cond_1
    invoke-virtual {p1, p3}, Lka/u;->d(Landroid/view/View;)I

    .line 26
    .line 27
    .line 28
    move-result p4

    .line 29
    invoke-virtual {p1, p2}, Lka/u;->g(Landroid/view/View;)I

    .line 30
    .line 31
    .line 32
    move-result p1

    .line 33
    sub-int/2addr p4, p1

    .line 34
    invoke-static {p2}, Lka/f0;->H(Landroid/view/View;)I

    .line 35
    .line 36
    .line 37
    move-result p1

    .line 38
    invoke-static {p3}, Lka/f0;->H(Landroid/view/View;)I

    .line 39
    .line 40
    .line 41
    move-result p2

    .line 42
    sub-int/2addr p1, p2

    .line 43
    invoke-static {p1}, Ljava/lang/Math;->abs(I)I

    .line 44
    .line 45
    .line 46
    move-result p1

    .line 47
    add-int/lit8 p1, p1, 0x1

    .line 48
    .line 49
    int-to-float p2, p4

    .line 50
    int-to-float p1, p1

    .line 51
    div-float/2addr p2, p1

    .line 52
    invoke-virtual {p0}, Lka/r0;->b()I

    .line 53
    .line 54
    .line 55
    move-result p0

    .line 56
    int-to-float p0, p0

    .line 57
    mul-float/2addr p2, p0

    .line 58
    float-to-int p0, p2

    .line 59
    return p0

    .line 60
    :cond_2
    :goto_0
    const/4 p0, 0x0

    .line 61
    return p0
.end method
