.class public abstract Llp/l1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/lang/String;Ljava/lang/String;Lay0/a;Ll2/o;I)V
    .locals 20

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
    const-string v0, "vin"

    .line 8
    .line 9
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v0, "profileUuid"

    .line 13
    .line 14
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    const-string v0, "dynamicRateRegistered"

    .line 18
    .line 19
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    move-object/from16 v9, p3

    .line 23
    .line 24
    check-cast v9, Ll2/t;

    .line 25
    .line 26
    const v0, 0x6ae38020

    .line 27
    .line 28
    .line 29
    invoke-virtual {v9, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v9, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    const/4 v4, 0x4

    .line 37
    if-eqz v0, :cond_0

    .line 38
    .line 39
    move v0, v4

    .line 40
    goto :goto_0

    .line 41
    :cond_0
    const/4 v0, 0x2

    .line 42
    :goto_0
    or-int v0, p4, v0

    .line 43
    .line 44
    invoke-virtual {v9, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v5

    .line 48
    const/16 v6, 0x20

    .line 49
    .line 50
    if-eqz v5, :cond_1

    .line 51
    .line 52
    move v5, v6

    .line 53
    goto :goto_1

    .line 54
    :cond_1
    const/16 v5, 0x10

    .line 55
    .line 56
    :goto_1
    or-int/2addr v0, v5

    .line 57
    invoke-virtual {v9, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v5

    .line 61
    const/16 v7, 0x100

    .line 62
    .line 63
    if-eqz v5, :cond_2

    .line 64
    .line 65
    move v5, v7

    .line 66
    goto :goto_2

    .line 67
    :cond_2
    const/16 v5, 0x80

    .line 68
    .line 69
    :goto_2
    or-int/2addr v0, v5

    .line 70
    and-int/lit16 v5, v0, 0x93

    .line 71
    .line 72
    const/16 v8, 0x92

    .line 73
    .line 74
    const/4 v10, 0x1

    .line 75
    const/4 v11, 0x0

    .line 76
    if-eq v5, v8, :cond_3

    .line 77
    .line 78
    move v5, v10

    .line 79
    goto :goto_3

    .line 80
    :cond_3
    move v5, v11

    .line 81
    :goto_3
    and-int/lit8 v8, v0, 0x1

    .line 82
    .line 83
    invoke-virtual {v9, v8, v5}, Ll2/t;->O(IZ)Z

    .line 84
    .line 85
    .line 86
    move-result v5

    .line 87
    if-eqz v5, :cond_e

    .line 88
    .line 89
    and-int/lit8 v5, v0, 0xe

    .line 90
    .line 91
    if-ne v5, v4, :cond_4

    .line 92
    .line 93
    move v4, v10

    .line 94
    goto :goto_4

    .line 95
    :cond_4
    move v4, v11

    .line 96
    :goto_4
    and-int/lit8 v5, v0, 0x70

    .line 97
    .line 98
    if-ne v5, v6, :cond_5

    .line 99
    .line 100
    move v5, v10

    .line 101
    goto :goto_5

    .line 102
    :cond_5
    move v5, v11

    .line 103
    :goto_5
    or-int/2addr v4, v5

    .line 104
    and-int/lit16 v0, v0, 0x380

    .line 105
    .line 106
    if-ne v0, v7, :cond_6

    .line 107
    .line 108
    goto :goto_6

    .line 109
    :cond_6
    move v10, v11

    .line 110
    :goto_6
    or-int v0, v4, v10

    .line 111
    .line 112
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v4

    .line 116
    sget-object v10, Ll2/n;->a:Ll2/x0;

    .line 117
    .line 118
    if-nez v0, :cond_7

    .line 119
    .line 120
    if-ne v4, v10, :cond_8

    .line 121
    .line 122
    :cond_7
    new-instance v4, Lne/a;

    .line 123
    .line 124
    const/4 v0, 0x3

    .line 125
    invoke-direct {v4, v1, v2, v3, v0}, Lne/a;-><init>(Ljava/lang/String;Ljava/lang/String;Lay0/a;I)V

    .line 126
    .line 127
    .line 128
    invoke-virtual {v9, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 129
    .line 130
    .line 131
    :cond_8
    check-cast v4, Lay0/k;

    .line 132
    .line 133
    sget-object v0, Lw3/q1;->a:Ll2/u2;

    .line 134
    .line 135
    invoke-virtual {v9, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object v0

    .line 139
    check-cast v0, Ljava/lang/Boolean;

    .line 140
    .line 141
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 142
    .line 143
    .line 144
    move-result v0

    .line 145
    if-eqz v0, :cond_9

    .line 146
    .line 147
    const v0, -0x105bcaaa

    .line 148
    .line 149
    .line 150
    invoke-virtual {v9, v0}, Ll2/t;->Y(I)V

    .line 151
    .line 152
    .line 153
    invoke-virtual {v9, v11}, Ll2/t;->q(Z)V

    .line 154
    .line 155
    .line 156
    const/4 v0, 0x0

    .line 157
    goto :goto_7

    .line 158
    :cond_9
    const v0, 0x31054eee

    .line 159
    .line 160
    .line 161
    invoke-virtual {v9, v0}, Ll2/t;->Y(I)V

    .line 162
    .line 163
    .line 164
    sget-object v0, Lzb/x;->a:Ll2/u2;

    .line 165
    .line 166
    invoke-virtual {v9, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object v0

    .line 170
    check-cast v0, Lhi/a;

    .line 171
    .line 172
    invoke-virtual {v9, v11}, Ll2/t;->q(Z)V

    .line 173
    .line 174
    .line 175
    :goto_7
    new-instance v7, Lnd/e;

    .line 176
    .line 177
    const/16 v5, 0x1a

    .line 178
    .line 179
    invoke-direct {v7, v0, v4, v5}, Lnd/e;-><init>(Lhi/a;Lay0/k;I)V

    .line 180
    .line 181
    .line 182
    invoke-static {v9}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 183
    .line 184
    .line 185
    move-result-object v5

    .line 186
    if-eqz v5, :cond_d

    .line 187
    .line 188
    instance-of v0, v5, Landroidx/lifecycle/k;

    .line 189
    .line 190
    if-eqz v0, :cond_a

    .line 191
    .line 192
    move-object v0, v5

    .line 193
    check-cast v0, Landroidx/lifecycle/k;

    .line 194
    .line 195
    invoke-interface {v0}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 196
    .line 197
    .line 198
    move-result-object v0

    .line 199
    :goto_8
    move-object v8, v0

    .line 200
    goto :goto_9

    .line 201
    :cond_a
    sget-object v0, Lp7/a;->b:Lp7/a;

    .line 202
    .line 203
    goto :goto_8

    .line 204
    :goto_9
    const-class v0, Lue/b;

    .line 205
    .line 206
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 207
    .line 208
    invoke-virtual {v4, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 209
    .line 210
    .line 211
    move-result-object v4

    .line 212
    const/4 v6, 0x0

    .line 213
    invoke-static/range {v4 .. v9}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 214
    .line 215
    .line 216
    move-result-object v0

    .line 217
    move-object v14, v0

    .line 218
    check-cast v14, Lue/b;

    .line 219
    .line 220
    iget-object v0, v14, Lue/b;->g:Lyy0/l1;

    .line 221
    .line 222
    invoke-static {v0, v9}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 223
    .line 224
    .line 225
    move-result-object v0

    .line 226
    invoke-static {v9}, Llp/nf;->a(Ll2/o;)Lle/c;

    .line 227
    .line 228
    .line 229
    move-result-object v4

    .line 230
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 231
    .line 232
    .line 233
    move-result-object v0

    .line 234
    check-cast v0, Lue/a;

    .line 235
    .line 236
    invoke-virtual {v9, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 237
    .line 238
    .line 239
    move-result v5

    .line 240
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 241
    .line 242
    .line 243
    move-result-object v6

    .line 244
    if-nez v5, :cond_b

    .line 245
    .line 246
    if-ne v6, v10, :cond_c

    .line 247
    .line 248
    :cond_b
    new-instance v12, Lt10/k;

    .line 249
    .line 250
    const/16 v18, 0x0

    .line 251
    .line 252
    const/16 v19, 0x10

    .line 253
    .line 254
    const/4 v13, 0x1

    .line 255
    const-class v15, Lue/b;

    .line 256
    .line 257
    const-string v16, "onUiEvent"

    .line 258
    .line 259
    const-string v17, "onUiEvent(Lcariad/charging/multicharge/kitten/kola/presentation/wizard/dynamicrate/countryregion/EnterCountryRegionUiEvent;)V"

    .line 260
    .line 261
    invoke-direct/range {v12 .. v19}, Lt10/k;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 262
    .line 263
    .line 264
    invoke-virtual {v9, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 265
    .line 266
    .line 267
    move-object v6, v12

    .line 268
    :cond_c
    check-cast v6, Lhy0/g;

    .line 269
    .line 270
    check-cast v6, Lay0/k;

    .line 271
    .line 272
    invoke-interface {v4, v0, v6, v9, v11}, Lle/c;->H0(Lue/a;Lay0/k;Ll2/o;I)V

    .line 273
    .line 274
    .line 275
    goto :goto_a

    .line 276
    :cond_d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 277
    .line 278
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 279
    .line 280
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 281
    .line 282
    .line 283
    throw v0

    .line 284
    :cond_e
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 285
    .line 286
    .line 287
    :goto_a
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 288
    .line 289
    .line 290
    move-result-object v6

    .line 291
    if-eqz v6, :cond_f

    .line 292
    .line 293
    new-instance v0, Lak/k;

    .line 294
    .line 295
    const/4 v5, 0x3

    .line 296
    move/from16 v4, p4

    .line 297
    .line 298
    invoke-direct/range {v0 .. v5}, Lak/k;-><init>(Ljava/lang/String;Ljava/lang/String;Lay0/a;II)V

    .line 299
    .line 300
    .line 301
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 302
    .line 303
    :cond_f
    return-void
.end method

.method public static final b(Ljava/lang/String;)Z
    .locals 1

    .line 1
    const-string v0, "method"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "POST"

    .line 7
    .line 8
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-nez v0, :cond_1

    .line 13
    .line 14
    const-string v0, "PATCH"

    .line 15
    .line 16
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-nez v0, :cond_1

    .line 21
    .line 22
    const-string v0, "PUT"

    .line 23
    .line 24
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    if-nez v0, :cond_1

    .line 29
    .line 30
    const-string v0, "DELETE"

    .line 31
    .line 32
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    if-nez v0, :cond_1

    .line 37
    .line 38
    const-string v0, "MOVE"

    .line 39
    .line 40
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    if-eqz p0, :cond_0

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_0
    const/4 p0, 0x0

    .line 48
    return p0

    .line 49
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 50
    return p0
.end method

.method public static final c(Ljava/lang/String;)Z
    .locals 1

    .line 1
    const-string v0, "method"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "GET"

    .line 7
    .line 8
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-nez v0, :cond_0

    .line 13
    .line 14
    const-string v0, "HEAD"

    .line 15
    .line 16
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    if-nez p0, :cond_0

    .line 21
    .line 22
    const/4 p0, 0x1

    .line 23
    return p0

    .line 24
    :cond_0
    const/4 p0, 0x0

    .line 25
    return p0
.end method
