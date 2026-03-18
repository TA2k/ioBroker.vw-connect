.class public abstract Lkp/y9;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Luf/p;Ljava/lang/String;Lyj/b;Ll2/o;I)V
    .locals 19

    .line 1
    move-object/from16 v2, p1

    .line 2
    .line 3
    move-object/from16 v3, p2

    .line 4
    .line 5
    const-string v0, "vin"

    .line 6
    .line 7
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    move-object/from16 v8, p3

    .line 11
    .line 12
    check-cast v8, Ll2/t;

    .line 13
    .line 14
    const v0, 0x546c9fbc

    .line 15
    .line 16
    .line 17
    invoke-virtual {v8, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 18
    .line 19
    .line 20
    invoke-virtual/range {p0 .. p0}, Ljava/lang/Enum;->ordinal()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    invoke-virtual {v8, v0}, Ll2/t;->e(I)Z

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    if-eqz v0, :cond_0

    .line 29
    .line 30
    const/4 v0, 0x4

    .line 31
    goto :goto_0

    .line 32
    :cond_0
    const/4 v0, 0x2

    .line 33
    :goto_0
    or-int v0, p4, v0

    .line 34
    .line 35
    invoke-virtual {v8, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    const/16 v4, 0x20

    .line 40
    .line 41
    if-eqz v1, :cond_1

    .line 42
    .line 43
    move v1, v4

    .line 44
    goto :goto_1

    .line 45
    :cond_1
    const/16 v1, 0x10

    .line 46
    .line 47
    :goto_1
    or-int/2addr v0, v1

    .line 48
    invoke-virtual {v8, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v1

    .line 52
    const/16 v5, 0x100

    .line 53
    .line 54
    if-eqz v1, :cond_2

    .line 55
    .line 56
    move v1, v5

    .line 57
    goto :goto_2

    .line 58
    :cond_2
    const/16 v1, 0x80

    .line 59
    .line 60
    :goto_2
    or-int/2addr v0, v1

    .line 61
    and-int/lit16 v1, v0, 0x93

    .line 62
    .line 63
    const/16 v6, 0x92

    .line 64
    .line 65
    const/4 v7, 0x1

    .line 66
    const/4 v9, 0x0

    .line 67
    if-eq v1, v6, :cond_3

    .line 68
    .line 69
    move v1, v7

    .line 70
    goto :goto_3

    .line 71
    :cond_3
    move v1, v9

    .line 72
    :goto_3
    and-int/lit8 v6, v0, 0x1

    .line 73
    .line 74
    invoke-virtual {v8, v6, v1}, Ll2/t;->O(IZ)Z

    .line 75
    .line 76
    .line 77
    move-result v1

    .line 78
    if-eqz v1, :cond_d

    .line 79
    .line 80
    and-int/lit8 v1, v0, 0x70

    .line 81
    .line 82
    if-ne v1, v4, :cond_4

    .line 83
    .line 84
    move v1, v7

    .line 85
    goto :goto_4

    .line 86
    :cond_4
    move v1, v9

    .line 87
    :goto_4
    and-int/lit16 v4, v0, 0x380

    .line 88
    .line 89
    if-ne v4, v5, :cond_5

    .line 90
    .line 91
    goto :goto_5

    .line 92
    :cond_5
    move v7, v9

    .line 93
    :goto_5
    or-int/2addr v1, v7

    .line 94
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v4

    .line 98
    sget-object v10, Ll2/n;->a:Ll2/x0;

    .line 99
    .line 100
    if-nez v1, :cond_6

    .line 101
    .line 102
    if-ne v4, v10, :cond_7

    .line 103
    .line 104
    :cond_6
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/n;

    .line 105
    .line 106
    const/4 v1, 0x7

    .line 107
    invoke-direct {v4, v1, v2, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/n;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    invoke-virtual {v8, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    :cond_7
    check-cast v4, Lay0/k;

    .line 114
    .line 115
    sget-object v1, Lw3/q1;->a:Ll2/u2;

    .line 116
    .line 117
    invoke-virtual {v8, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object v1

    .line 121
    check-cast v1, Ljava/lang/Boolean;

    .line 122
    .line 123
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 124
    .line 125
    .line 126
    move-result v1

    .line 127
    if-eqz v1, :cond_8

    .line 128
    .line 129
    const v1, -0x105bcaaa

    .line 130
    .line 131
    .line 132
    invoke-virtual {v8, v1}, Ll2/t;->Y(I)V

    .line 133
    .line 134
    .line 135
    invoke-virtual {v8, v9}, Ll2/t;->q(Z)V

    .line 136
    .line 137
    .line 138
    const/4 v1, 0x0

    .line 139
    goto :goto_6

    .line 140
    :cond_8
    const v1, 0x31054eee

    .line 141
    .line 142
    .line 143
    invoke-virtual {v8, v1}, Ll2/t;->Y(I)V

    .line 144
    .line 145
    .line 146
    sget-object v1, Lzb/x;->a:Ll2/u2;

    .line 147
    .line 148
    invoke-virtual {v8, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object v1

    .line 152
    check-cast v1, Lhi/a;

    .line 153
    .line 154
    invoke-virtual {v8, v9}, Ll2/t;->q(Z)V

    .line 155
    .line 156
    .line 157
    :goto_6
    new-instance v7, Lnd/e;

    .line 158
    .line 159
    const/16 v5, 0x18

    .line 160
    .line 161
    invoke-direct {v7, v1, v4, v5}, Lnd/e;-><init>(Lhi/a;Lay0/k;I)V

    .line 162
    .line 163
    .line 164
    invoke-static {v8}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 165
    .line 166
    .line 167
    move-result-object v5

    .line 168
    if-eqz v5, :cond_c

    .line 169
    .line 170
    instance-of v1, v5, Landroidx/lifecycle/k;

    .line 171
    .line 172
    if-eqz v1, :cond_9

    .line 173
    .line 174
    move-object v1, v5

    .line 175
    check-cast v1, Landroidx/lifecycle/k;

    .line 176
    .line 177
    invoke-interface {v1}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 178
    .line 179
    .line 180
    move-result-object v1

    .line 181
    goto :goto_7

    .line 182
    :cond_9
    sget-object v1, Lp7/a;->b:Lp7/a;

    .line 183
    .line 184
    :goto_7
    const-class v4, Ltf/c;

    .line 185
    .line 186
    sget-object v6, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 187
    .line 188
    invoke-virtual {v6, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 189
    .line 190
    .line 191
    move-result-object v4

    .line 192
    const/4 v6, 0x0

    .line 193
    move-object v9, v8

    .line 194
    move-object v8, v1

    .line 195
    invoke-static/range {v4 .. v9}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 196
    .line 197
    .line 198
    move-result-object v1

    .line 199
    move-object v8, v9

    .line 200
    move-object v13, v1

    .line 201
    check-cast v13, Ltf/c;

    .line 202
    .line 203
    invoke-static {v8}, Ljp/of;->d(Ll2/o;)Lqf/d;

    .line 204
    .line 205
    .line 206
    move-result-object v4

    .line 207
    iget-object v1, v13, Ltf/c;->h:Lyy0/c2;

    .line 208
    .line 209
    invoke-static {v1, v8}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 210
    .line 211
    .line 212
    move-result-object v1

    .line 213
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 214
    .line 215
    .line 216
    move-result-object v1

    .line 217
    move-object v6, v1

    .line 218
    check-cast v6, Llc/q;

    .line 219
    .line 220
    invoke-virtual {v8, v13}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 221
    .line 222
    .line 223
    move-result v1

    .line 224
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    move-result-object v5

    .line 228
    if-nez v1, :cond_a

    .line 229
    .line 230
    if-ne v5, v10, :cond_b

    .line 231
    .line 232
    :cond_a
    new-instance v11, Lt10/k;

    .line 233
    .line 234
    const/16 v17, 0x0

    .line 235
    .line 236
    const/16 v18, 0xa

    .line 237
    .line 238
    const/4 v12, 0x1

    .line 239
    const-class v14, Ltf/c;

    .line 240
    .line 241
    const-string v15, "onUiEvent"

    .line 242
    .line 243
    const-string v16, "onUiEvent(Lcariad/charging/multicharge/kitten/plugandcharge/presentation/installationUninstallation/PlugAndChargeContractInstallationUninstallationUiEvent;)V"

    .line 244
    .line 245
    invoke-direct/range {v11 .. v18}, Lt10/k;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 246
    .line 247
    .line 248
    invoke-virtual {v8, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 249
    .line 250
    .line 251
    move-object v5, v11

    .line 252
    :cond_b
    check-cast v5, Lhy0/g;

    .line 253
    .line 254
    move-object v7, v5

    .line 255
    check-cast v7, Lay0/k;

    .line 256
    .line 257
    and-int/lit8 v0, v0, 0xe

    .line 258
    .line 259
    or-int/lit8 v9, v0, 0x40

    .line 260
    .line 261
    move-object/from16 v5, p0

    .line 262
    .line 263
    invoke-interface/range {v4 .. v9}, Lqf/d;->Y(Luf/p;Llc/q;Lay0/k;Ll2/o;I)V

    .line 264
    .line 265
    .line 266
    goto :goto_8

    .line 267
    :cond_c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 268
    .line 269
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 270
    .line 271
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 272
    .line 273
    .line 274
    throw v0

    .line 275
    :cond_d
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 276
    .line 277
    .line 278
    :goto_8
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 279
    .line 280
    .line 281
    move-result-object v6

    .line 282
    if-eqz v6, :cond_e

    .line 283
    .line 284
    new-instance v0, Lqv0/f;

    .line 285
    .line 286
    const/16 v5, 0xb

    .line 287
    .line 288
    move-object/from16 v1, p0

    .line 289
    .line 290
    move/from16 v4, p4

    .line 291
    .line 292
    invoke-direct/range {v0 .. v5}, Lqv0/f;-><init>(Ljava/lang/Object;Ljava/lang/String;Lay0/a;II)V

    .line 293
    .line 294
    .line 295
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 296
    .line 297
    :cond_e
    return-void
.end method

.method public static b(Ljava/util/List;Lj0/h;Lj0/c;)Ly4/k;
    .locals 4

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    if-eqz v2, :cond_0

    .line 15
    .line 16
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    check-cast v2, Lh0/t0;

    .line 21
    .line 22
    invoke-virtual {v2}, Lh0/t0;->c()Lcom/google/common/util/concurrent/ListenableFuture;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    invoke-static {v2}, Lk0/h;->d(Lcom/google/common/util/concurrent/ListenableFuture;)Lcom/google/common/util/concurrent/ListenableFuture;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    new-instance v1, Lk0/k;

    .line 35
    .line 36
    new-instance v2, Ljava/util/ArrayList;

    .line 37
    .line 38
    invoke-direct {v2, v0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 39
    .line 40
    .line 41
    const/4 v0, 0x0

    .line 42
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 43
    .line 44
    .line 45
    move-result-object v3

    .line 46
    invoke-direct {v1, v2, v0, v3}, Lk0/k;-><init>(Ljava/util/ArrayList;ZLj0/a;)V

    .line 47
    .line 48
    .line 49
    new-instance v0, Ldu/f;

    .line 50
    .line 51
    const-wide/16 v2, 0x1388

    .line 52
    .line 53
    invoke-direct {v0, v1, p2, v2, v3}, Ldu/f;-><init>(Ljava/lang/Object;Ljava/lang/Object;J)V

    .line 54
    .line 55
    .line 56
    invoke-static {v0}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 57
    .line 58
    .line 59
    move-result-object p2

    .line 60
    new-instance v0, Lbb/i;

    .line 61
    .line 62
    const/4 v1, 0x7

    .line 63
    invoke-direct {v0, p2, p1, p0, v1}, Lbb/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 64
    .line 65
    .line 66
    invoke-static {v0}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    return-object p0
.end method
