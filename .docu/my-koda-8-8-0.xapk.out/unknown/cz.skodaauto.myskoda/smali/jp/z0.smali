.class public abstract Ljp/z0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/lang/String;Lay0/k;Lay0/a;Ll2/o;I)V
    .locals 12

    .line 1
    const-string v0, "vin"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "gotoPcidshare"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "gotoSubscribeFlow"

    .line 12
    .line 13
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    move-object v11, p3

    .line 17
    check-cast v11, Ll2/t;

    .line 18
    .line 19
    const v0, 0x8b01882

    .line 20
    .line 21
    .line 22
    invoke-virtual {v11, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 23
    .line 24
    .line 25
    invoke-virtual {v11, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    const/4 v1, 0x4

    .line 30
    if-eqz v0, :cond_0

    .line 31
    .line 32
    move v0, v1

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    const/4 v0, 0x2

    .line 35
    :goto_0
    or-int v0, p4, v0

    .line 36
    .line 37
    invoke-virtual {v11, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    if-eqz v2, :cond_1

    .line 42
    .line 43
    const/16 v2, 0x20

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_1
    const/16 v2, 0x10

    .line 47
    .line 48
    :goto_1
    or-int/2addr v0, v2

    .line 49
    invoke-virtual {v11, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v2

    .line 53
    if-eqz v2, :cond_2

    .line 54
    .line 55
    const/16 v2, 0x100

    .line 56
    .line 57
    goto :goto_2

    .line 58
    :cond_2
    const/16 v2, 0x80

    .line 59
    .line 60
    :goto_2
    or-int/2addr v0, v2

    .line 61
    and-int/lit16 v2, v0, 0x93

    .line 62
    .line 63
    const/16 v6, 0x92

    .line 64
    .line 65
    const/4 v7, 0x1

    .line 66
    const/4 v8, 0x0

    .line 67
    if-eq v2, v6, :cond_3

    .line 68
    .line 69
    move v2, v7

    .line 70
    goto :goto_3

    .line 71
    :cond_3
    move v2, v8

    .line 72
    :goto_3
    and-int/lit8 v6, v0, 0x1

    .line 73
    .line 74
    invoke-virtual {v11, v6, v2}, Ll2/t;->O(IZ)Z

    .line 75
    .line 76
    .line 77
    move-result v2

    .line 78
    if-eqz v2, :cond_c

    .line 79
    .line 80
    and-int/lit8 v0, v0, 0xe

    .line 81
    .line 82
    if-ne v0, v1, :cond_4

    .line 83
    .line 84
    goto :goto_4

    .line 85
    :cond_4
    move v7, v8

    .line 86
    :goto_4
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v0

    .line 90
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 91
    .line 92
    if-nez v7, :cond_5

    .line 93
    .line 94
    if-ne v0, v1, :cond_6

    .line 95
    .line 96
    :cond_5
    new-instance v0, Lac0/r;

    .line 97
    .line 98
    const/4 v2, 0x1

    .line 99
    invoke-direct {v0, p0, v2}, Lac0/r;-><init>(Ljava/lang/String;I)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v11, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    :cond_6
    check-cast v0, Lay0/k;

    .line 106
    .line 107
    sget-object v2, Lw3/q1;->a:Ll2/u2;

    .line 108
    .line 109
    invoke-virtual {v11, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v2

    .line 113
    check-cast v2, Ljava/lang/Boolean;

    .line 114
    .line 115
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 116
    .line 117
    .line 118
    move-result v2

    .line 119
    if-eqz v2, :cond_7

    .line 120
    .line 121
    const v2, -0x105bcaaa

    .line 122
    .line 123
    .line 124
    invoke-virtual {v11, v2}, Ll2/t;->Y(I)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {v11, v8}, Ll2/t;->q(Z)V

    .line 128
    .line 129
    .line 130
    const/4 v2, 0x0

    .line 131
    goto :goto_5

    .line 132
    :cond_7
    const v2, 0x31054eee

    .line 133
    .line 134
    .line 135
    invoke-virtual {v11, v2}, Ll2/t;->Y(I)V

    .line 136
    .line 137
    .line 138
    sget-object v2, Lzb/x;->a:Ll2/u2;

    .line 139
    .line 140
    invoke-virtual {v11, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object v2

    .line 144
    check-cast v2, Lhi/a;

    .line 145
    .line 146
    invoke-virtual {v11, v8}, Ll2/t;->q(Z)V

    .line 147
    .line 148
    .line 149
    :goto_5
    new-instance v9, Laf/a;

    .line 150
    .line 151
    const/4 v3, 0x1

    .line 152
    invoke-direct {v9, v2, v0, v3}, Laf/a;-><init>(Lhi/a;Lay0/k;I)V

    .line 153
    .line 154
    .line 155
    invoke-static {v11}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 156
    .line 157
    .line 158
    move-result-object v7

    .line 159
    if-eqz v7, :cond_b

    .line 160
    .line 161
    instance-of v0, v7, Landroidx/lifecycle/k;

    .line 162
    .line 163
    if-eqz v0, :cond_8

    .line 164
    .line 165
    move-object v0, v7

    .line 166
    check-cast v0, Landroidx/lifecycle/k;

    .line 167
    .line 168
    invoke-interface {v0}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 169
    .line 170
    .line 171
    move-result-object v0

    .line 172
    :goto_6
    move-object v10, v0

    .line 173
    goto :goto_7

    .line 174
    :cond_8
    sget-object v0, Lp7/a;->b:Lp7/a;

    .line 175
    .line 176
    goto :goto_6

    .line 177
    :goto_7
    const-class v0, Lag/u;

    .line 178
    .line 179
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 180
    .line 181
    invoke-virtual {v2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 182
    .line 183
    .line 184
    move-result-object v6

    .line 185
    const/4 v8, 0x0

    .line 186
    invoke-static/range {v6 .. v11}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 187
    .line 188
    .line 189
    move-result-object v0

    .line 190
    check-cast v0, Lag/u;

    .line 191
    .line 192
    iget-object v2, v0, Lag/u;->i:Lyy0/l1;

    .line 193
    .line 194
    invoke-static {v2, v11}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 195
    .line 196
    .line 197
    move-result-object v2

    .line 198
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v2

    .line 202
    move-object v3, v2

    .line 203
    check-cast v3, Lag/k;

    .line 204
    .line 205
    invoke-static {p1, v11}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 206
    .line 207
    .line 208
    move-result-object v2

    .line 209
    invoke-static {p2, v11}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 210
    .line 211
    .line 212
    move-result-object v6

    .line 213
    invoke-static {v11}, Lzb/b;->r(Ll2/o;)Lay0/a;

    .line 214
    .line 215
    .line 216
    move-result-object v4

    .line 217
    invoke-static {v4, v11}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 218
    .line 219
    .line 220
    move-result-object v7

    .line 221
    invoke-virtual {v11, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 222
    .line 223
    .line 224
    move-result v4

    .line 225
    invoke-virtual {v11, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 226
    .line 227
    .line 228
    move-result v5

    .line 229
    or-int/2addr v4, v5

    .line 230
    invoke-virtual {v11, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 231
    .line 232
    .line 233
    move-result v5

    .line 234
    or-int/2addr v4, v5

    .line 235
    invoke-virtual {v11, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 236
    .line 237
    .line 238
    move-result v5

    .line 239
    or-int/2addr v4, v5

    .line 240
    invoke-virtual {v11, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 241
    .line 242
    .line 243
    move-result v5

    .line 244
    or-int/2addr v4, v5

    .line 245
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 246
    .line 247
    .line 248
    move-result-object v5

    .line 249
    if-nez v4, :cond_9

    .line 250
    .line 251
    if-ne v5, v1, :cond_a

    .line 252
    .line 253
    :cond_9
    move-object v5, v2

    .line 254
    goto :goto_8

    .line 255
    :cond_a
    move-object v4, v0

    .line 256
    goto :goto_9

    .line 257
    :goto_8
    new-instance v2, La71/b0;

    .line 258
    .line 259
    const/4 v8, 0x0

    .line 260
    const/4 v9, 0x1

    .line 261
    move-object v4, v0

    .line 262
    invoke-direct/range {v2 .. v9}, La71/b0;-><init>(Ljava/lang/Object;Landroidx/lifecycle/b1;Ll2/b1;Ll2/b1;Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 263
    .line 264
    .line 265
    invoke-virtual {v11, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 266
    .line 267
    .line 268
    move-object v5, v2

    .line 269
    :goto_9
    check-cast v5, Lay0/n;

    .line 270
    .line 271
    invoke-static {v5, v3, v11}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 272
    .line 273
    .line 274
    iget-object v0, v4, Lag/u;->h:Lyy0/l1;

    .line 275
    .line 276
    invoke-static {v0, v11}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 277
    .line 278
    .line 279
    move-result-object v0

    .line 280
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 281
    .line 282
    .line 283
    move-result-object v0

    .line 284
    check-cast v0, Llc/q;

    .line 285
    .line 286
    sget-object v0, Lzb/x;->b:Ll2/u2;

    .line 287
    .line 288
    invoke-virtual {v11, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 289
    .line 290
    .line 291
    move-result-object v0

    .line 292
    const-string v1, "null cannot be cast to non-null type cariad.charging.multicharge.kitten.plugandchargeoffline.presentation.PlugAndChargeOfflineUi"

    .line 293
    .line 294
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 295
    .line 296
    .line 297
    new-instance v0, Ljava/lang/ClassCastException;

    .line 298
    .line 299
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 300
    .line 301
    .line 302
    throw v0

    .line 303
    :cond_b
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 304
    .line 305
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 306
    .line 307
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 308
    .line 309
    .line 310
    throw v0

    .line 311
    :cond_c
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 312
    .line 313
    .line 314
    invoke-virtual {v11}, Ll2/t;->s()Ll2/u1;

    .line 315
    .line 316
    .line 317
    move-result-object v6

    .line 318
    if-eqz v6, :cond_d

    .line 319
    .line 320
    new-instance v0, Laa/w;

    .line 321
    .line 322
    const/4 v2, 0x2

    .line 323
    move-object v3, p0

    .line 324
    move-object v4, p1

    .line 325
    move-object v5, p2

    .line 326
    move/from16 v1, p4

    .line 327
    .line 328
    invoke-direct/range {v0 .. v5}, Laa/w;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 329
    .line 330
    .line 331
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 332
    .line 333
    :cond_d
    return-void
.end method

.method public static final b([B)Ljava/util/LinkedHashSet;
    .locals 7

    .line 1
    const-string v0, "bytes"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ljava/util/LinkedHashSet;

    .line 7
    .line 8
    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 9
    .line 10
    .line 11
    array-length v1, p0

    .line 12
    if-nez v1, :cond_0

    .line 13
    .line 14
    return-object v0

    .line 15
    :cond_0
    new-instance v1, Ljava/io/ByteArrayInputStream;

    .line 16
    .line 17
    invoke-direct {v1, p0}, Ljava/io/ByteArrayInputStream;-><init>([B)V

    .line 18
    .line 19
    .line 20
    :try_start_0
    new-instance p0, Ljava/io/ObjectInputStream;

    .line 21
    .line 22
    invoke-direct {p0, v1}, Ljava/io/ObjectInputStream;-><init>(Ljava/io/InputStream;)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 23
    .line 24
    .line 25
    :try_start_1
    invoke-virtual {p0}, Ljava/io/ObjectInputStream;->readInt()I

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    const/4 v3, 0x0

    .line 30
    :goto_0
    if-ge v3, v2, :cond_1

    .line 31
    .line 32
    invoke-virtual {p0}, Ljava/io/ObjectInputStream;->readUTF()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v4

    .line 36
    invoke-static {v4}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 37
    .line 38
    .line 39
    move-result-object v4

    .line 40
    invoke-virtual {p0}, Ljava/io/ObjectInputStream;->readBoolean()Z

    .line 41
    .line 42
    .line 43
    move-result v5

    .line 44
    new-instance v6, Leb/d;

    .line 45
    .line 46
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    invoke-direct {v6, v5, v4}, Leb/d;-><init>(ZLandroid/net/Uri;)V

    .line 50
    .line 51
    .line 52
    invoke-interface {v0, v6}, Ljava/util/Set;->add(Ljava/lang/Object;)Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 53
    .line 54
    .line 55
    add-int/lit8 v3, v3, 0x1

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :catchall_0
    move-exception v2

    .line 59
    goto :goto_1

    .line 60
    :cond_1
    :try_start_2
    invoke-virtual {p0}, Ljava/io/ObjectInputStream;->close()V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 61
    .line 62
    .line 63
    goto :goto_3

    .line 64
    :catchall_1
    move-exception p0

    .line 65
    goto :goto_4

    .line 66
    :catch_0
    move-exception p0

    .line 67
    goto :goto_2

    .line 68
    :goto_1
    :try_start_3
    throw v2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 69
    :catchall_2
    move-exception v3

    .line 70
    :try_start_4
    invoke-static {p0, v2}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 71
    .line 72
    .line 73
    throw v3
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 74
    :goto_2
    :try_start_5
    invoke-virtual {p0}, Ljava/lang/Throwable;->printStackTrace()V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 75
    .line 76
    .line 77
    :goto_3
    invoke-virtual {v1}, Ljava/io/ByteArrayInputStream;->close()V

    .line 78
    .line 79
    .line 80
    return-object v0

    .line 81
    :goto_4
    :try_start_6
    throw p0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_3

    .line 82
    :catchall_3
    move-exception v0

    .line 83
    invoke-static {v1, p0}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 84
    .line 85
    .line 86
    throw v0
.end method

.method public static final c(Lnb/d;)[B
    .locals 10

    .line 1
    const-string v0, "requestCompat"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 7
    .line 8
    iget-object p0, p0, Lnb/d;->a:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Landroid/net/NetworkRequest;

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    if-nez p0, :cond_0

    .line 14
    .line 15
    new-array p0, v1, [B

    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_0
    new-instance v2, Ljava/io/ByteArrayOutputStream;

    .line 19
    .line 20
    invoke-direct {v2}, Ljava/io/ByteArrayOutputStream;-><init>()V

    .line 21
    .line 22
    .line 23
    :try_start_0
    new-instance v3, Ljava/io/ObjectOutputStream;

    .line 24
    .line 25
    invoke-direct {v3, v2}, Ljava/io/ObjectOutputStream;-><init>(Ljava/io/OutputStream;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 26
    .line 27
    .line 28
    const/16 v4, 0x1f

    .line 29
    .line 30
    if-lt v0, v4, :cond_1

    .line 31
    .line 32
    :try_start_1
    invoke-static {p0}, Lh4/b;->B(Landroid/net/NetworkRequest;)[I

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    const-string v5, "getTransportTypes(...)"

    .line 37
    .line 38
    invoke-static {v0, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    const/16 v0, 0xa

    .line 43
    .line 44
    new-array v5, v0, [I

    .line 45
    .line 46
    fill-array-data v5, :array_0

    .line 47
    .line 48
    .line 49
    new-instance v6, Ljava/util/ArrayList;

    .line 50
    .line 51
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 52
    .line 53
    .line 54
    move v7, v1

    .line 55
    :goto_0
    if-ge v7, v0, :cond_3

    .line 56
    .line 57
    aget v8, v5, v7

    .line 58
    .line 59
    invoke-virtual {p0, v8}, Landroid/net/NetworkRequest;->hasTransport(I)Z

    .line 60
    .line 61
    .line 62
    move-result v9

    .line 63
    if-eqz v9, :cond_2

    .line 64
    .line 65
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 66
    .line 67
    .line 68
    move-result-object v8

    .line 69
    invoke-virtual {v6, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    :cond_2
    add-int/lit8 v7, v7, 0x1

    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_3
    invoke-static {v6}, Lmx0/q;->w0(Ljava/util/Collection;)[I

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    :goto_1
    sget v5, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 80
    .line 81
    if-lt v5, v4, :cond_4

    .line 82
    .line 83
    invoke-static {p0}, Lh4/b;->D(Landroid/net/NetworkRequest;)[I

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    const-string v4, "getCapabilities(...)"

    .line 88
    .line 89
    invoke-static {p0, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    goto :goto_3

    .line 93
    :cond_4
    const/16 v4, 0x1e

    .line 94
    .line 95
    new-array v5, v4, [I

    .line 96
    .line 97
    fill-array-data v5, :array_1

    .line 98
    .line 99
    .line 100
    new-instance v6, Ljava/util/ArrayList;

    .line 101
    .line 102
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 103
    .line 104
    .line 105
    move v7, v1

    .line 106
    :goto_2
    if-ge v7, v4, :cond_6

    .line 107
    .line 108
    aget v8, v5, v7

    .line 109
    .line 110
    invoke-virtual {p0, v8}, Landroid/net/NetworkRequest;->hasCapability(I)Z

    .line 111
    .line 112
    .line 113
    move-result v9

    .line 114
    if-eqz v9, :cond_5

    .line 115
    .line 116
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 117
    .line 118
    .line 119
    move-result-object v8

    .line 120
    invoke-virtual {v6, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 121
    .line 122
    .line 123
    :cond_5
    add-int/lit8 v7, v7, 0x1

    .line 124
    .line 125
    goto :goto_2

    .line 126
    :cond_6
    invoke-static {v6}, Lmx0/q;->w0(Ljava/util/Collection;)[I

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    :goto_3
    array-length v4, v0

    .line 131
    invoke-virtual {v3, v4}, Ljava/io/ObjectOutputStream;->writeInt(I)V

    .line 132
    .line 133
    .line 134
    array-length v4, v0

    .line 135
    move v5, v1

    .line 136
    :goto_4
    if-ge v5, v4, :cond_7

    .line 137
    .line 138
    aget v6, v0, v5

    .line 139
    .line 140
    invoke-virtual {v3, v6}, Ljava/io/ObjectOutputStream;->writeInt(I)V

    .line 141
    .line 142
    .line 143
    add-int/lit8 v5, v5, 0x1

    .line 144
    .line 145
    goto :goto_4

    .line 146
    :catchall_0
    move-exception p0

    .line 147
    goto :goto_6

    .line 148
    :cond_7
    array-length v0, p0

    .line 149
    invoke-virtual {v3, v0}, Ljava/io/ObjectOutputStream;->writeInt(I)V

    .line 150
    .line 151
    .line 152
    array-length v0, p0

    .line 153
    :goto_5
    if-ge v1, v0, :cond_8

    .line 154
    .line 155
    aget v4, p0, v1

    .line 156
    .line 157
    invoke-virtual {v3, v4}, Ljava/io/ObjectOutputStream;->writeInt(I)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 158
    .line 159
    .line 160
    add-int/lit8 v1, v1, 0x1

    .line 161
    .line 162
    goto :goto_5

    .line 163
    :cond_8
    :try_start_2
    invoke-virtual {v3}, Ljava/io/ObjectOutputStream;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 164
    .line 165
    .line 166
    invoke-virtual {v2}, Ljava/io/ByteArrayOutputStream;->close()V

    .line 167
    .line 168
    .line 169
    invoke-virtual {v2}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 170
    .line 171
    .line 172
    move-result-object p0

    .line 173
    const-string v0, "toByteArray(...)"

    .line 174
    .line 175
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 176
    .line 177
    .line 178
    return-object p0

    .line 179
    :catchall_1
    move-exception p0

    .line 180
    goto :goto_7

    .line 181
    :goto_6
    :try_start_3
    throw p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 182
    :catchall_2
    move-exception v0

    .line 183
    :try_start_4
    invoke-static {v3, p0}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 184
    .line 185
    .line 186
    throw v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 187
    :goto_7
    :try_start_5
    throw p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    .line 188
    :catchall_3
    move-exception v0

    .line 189
    invoke-static {v2, p0}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 190
    .line 191
    .line 192
    throw v0

    .line 193
    :array_0
    .array-data 4
        0x2
        0x0
        0x3
        0x6
        0xa
        0x9
        0x8
        0x4
        0x1
        0x5
    .end array-data

    .line 194
    .line 195
    .line 196
    .line 197
    .line 198
    .line 199
    .line 200
    .line 201
    .line 202
    .line 203
    .line 204
    .line 205
    .line 206
    .line 207
    .line 208
    .line 209
    .line 210
    .line 211
    .line 212
    .line 213
    .line 214
    .line 215
    .line 216
    .line 217
    :array_1
    .array-data 4
        0x11
        0x5
        0x2
        0xa
        0x1d
        0x13
        0x3
        0x20
        0x7
        0x4
        0xc
        0x24
        0x17
        0x0
        0x21
        0x14
        0xb
        0xd
        0x12
        0x15
        0xf
        0x23
        0x22
        0x8
        0x1
        0x19
        0xe
        0x10
        0x6
        0x9
    .end array-data
.end method

.method public static final d(I)Leb/a;
    .locals 3

    .line 1
    if-eqz p0, :cond_1

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    if-ne p0, v0, :cond_0

    .line 5
    .line 6
    sget-object p0, Leb/a;->e:Leb/a;

    .line 7
    .line 8
    return-object p0

    .line 9
    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 10
    .line 11
    const-string v1, "Could not convert "

    .line 12
    .line 13
    const-string v2, " to BackoffPolicy"

    .line 14
    .line 15
    invoke-static {v1, p0, v2}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    throw v0

    .line 23
    :cond_1
    sget-object p0, Leb/a;->d:Leb/a;

    .line 24
    .line 25
    return-object p0
.end method

.method public static final e(I)Leb/x;
    .locals 3

    .line 1
    if-eqz p0, :cond_5

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    if-eq p0, v0, :cond_4

    .line 5
    .line 6
    const/4 v0, 0x2

    .line 7
    if-eq p0, v0, :cond_3

    .line 8
    .line 9
    const/4 v0, 0x3

    .line 10
    if-eq p0, v0, :cond_2

    .line 11
    .line 12
    const/4 v0, 0x4

    .line 13
    if-eq p0, v0, :cond_1

    .line 14
    .line 15
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 16
    .line 17
    const/16 v1, 0x1e

    .line 18
    .line 19
    if-lt v0, v1, :cond_0

    .line 20
    .line 21
    const/4 v0, 0x5

    .line 22
    if-ne p0, v0, :cond_0

    .line 23
    .line 24
    sget-object p0, Leb/x;->i:Leb/x;

    .line 25
    .line 26
    return-object p0

    .line 27
    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 28
    .line 29
    const-string v1, "Could not convert "

    .line 30
    .line 31
    const-string v2, " to NetworkType"

    .line 32
    .line 33
    invoke-static {v1, p0, v2}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    throw v0

    .line 41
    :cond_1
    sget-object p0, Leb/x;->h:Leb/x;

    .line 42
    .line 43
    return-object p0

    .line 44
    :cond_2
    sget-object p0, Leb/x;->g:Leb/x;

    .line 45
    .line 46
    return-object p0

    .line 47
    :cond_3
    sget-object p0, Leb/x;->f:Leb/x;

    .line 48
    .line 49
    return-object p0

    .line 50
    :cond_4
    sget-object p0, Leb/x;->e:Leb/x;

    .line 51
    .line 52
    return-object p0

    .line 53
    :cond_5
    sget-object p0, Leb/x;->d:Leb/x;

    .line 54
    .line 55
    return-object p0
.end method

.method public static final f(I)Leb/e0;
    .locals 3

    .line 1
    if-eqz p0, :cond_1

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    if-ne p0, v0, :cond_0

    .line 5
    .line 6
    sget-object p0, Leb/e0;->e:Leb/e0;

    .line 7
    .line 8
    return-object p0

    .line 9
    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 10
    .line 11
    const-string v1, "Could not convert "

    .line 12
    .line 13
    const-string v2, " to OutOfQuotaPolicy"

    .line 14
    .line 15
    invoke-static {v1, p0, v2}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    throw v0

    .line 23
    :cond_1
    sget-object p0, Leb/e0;->d:Leb/e0;

    .line 24
    .line 25
    return-object p0
.end method

.method public static final g(I)Leb/h0;
    .locals 3

    .line 1
    if-eqz p0, :cond_5

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    if-eq p0, v0, :cond_4

    .line 5
    .line 6
    const/4 v0, 0x2

    .line 7
    if-eq p0, v0, :cond_3

    .line 8
    .line 9
    const/4 v0, 0x3

    .line 10
    if-eq p0, v0, :cond_2

    .line 11
    .line 12
    const/4 v0, 0x4

    .line 13
    if-eq p0, v0, :cond_1

    .line 14
    .line 15
    const/4 v0, 0x5

    .line 16
    if-ne p0, v0, :cond_0

    .line 17
    .line 18
    sget-object p0, Leb/h0;->i:Leb/h0;

    .line 19
    .line 20
    return-object p0

    .line 21
    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 22
    .line 23
    const-string v1, "Could not convert "

    .line 24
    .line 25
    const-string v2, " to State"

    .line 26
    .line 27
    invoke-static {v1, p0, v2}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw v0

    .line 35
    :cond_1
    sget-object p0, Leb/h0;->h:Leb/h0;

    .line 36
    .line 37
    return-object p0

    .line 38
    :cond_2
    sget-object p0, Leb/h0;->g:Leb/h0;

    .line 39
    .line 40
    return-object p0

    .line 41
    :cond_3
    sget-object p0, Leb/h0;->f:Leb/h0;

    .line 42
    .line 43
    return-object p0

    .line 44
    :cond_4
    sget-object p0, Leb/h0;->e:Leb/h0;

    .line 45
    .line 46
    return-object p0

    .line 47
    :cond_5
    sget-object p0, Leb/h0;->d:Leb/h0;

    .line 48
    .line 49
    return-object p0
.end method

.method public static final j(Leb/x;)I
    .locals 3

    .line 1
    const-string v0, "networkType"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-eqz v0, :cond_2

    .line 11
    .line 12
    const/4 v1, 0x1

    .line 13
    if-eq v0, v1, :cond_1

    .line 14
    .line 15
    const/4 v1, 0x2

    .line 16
    if-eq v0, v1, :cond_1

    .line 17
    .line 18
    const/4 v1, 0x3

    .line 19
    if-eq v0, v1, :cond_1

    .line 20
    .line 21
    const/4 v1, 0x4

    .line 22
    if-eq v0, v1, :cond_1

    .line 23
    .line 24
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 25
    .line 26
    const/16 v1, 0x1e

    .line 27
    .line 28
    if-lt v0, v1, :cond_0

    .line 29
    .line 30
    sget-object v0, Leb/x;->i:Leb/x;

    .line 31
    .line 32
    if-ne p0, v0, :cond_0

    .line 33
    .line 34
    const/4 p0, 0x5

    .line 35
    return p0

    .line 36
    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 37
    .line 38
    new-instance v1, Ljava/lang/StringBuilder;

    .line 39
    .line 40
    const-string v2, "Could not convert "

    .line 41
    .line 42
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    const-string p0, " to int"

    .line 49
    .line 50
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw v0

    .line 61
    :cond_1
    return v1

    .line 62
    :cond_2
    const/4 p0, 0x0

    .line 63
    return p0
.end method

.method public static final k(Ljava/util/Set;)[B
    .locals 4

    .line 1
    const-string v0, "triggers"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Ljava/util/Set;->isEmpty()Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    const/4 p0, 0x0

    .line 13
    new-array p0, p0, [B

    .line 14
    .line 15
    return-object p0

    .line 16
    :cond_0
    new-instance v0, Ljava/io/ByteArrayOutputStream;

    .line 17
    .line 18
    invoke-direct {v0}, Ljava/io/ByteArrayOutputStream;-><init>()V

    .line 19
    .line 20
    .line 21
    :try_start_0
    new-instance v1, Ljava/io/ObjectOutputStream;

    .line 22
    .line 23
    invoke-direct {v1, v0}, Ljava/io/ObjectOutputStream;-><init>(Ljava/io/OutputStream;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 24
    .line 25
    .line 26
    :try_start_1
    invoke-interface {p0}, Ljava/util/Set;->size()I

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    invoke-virtual {v1, v2}, Ljava/io/ObjectOutputStream;->writeInt(I)V

    .line 31
    .line 32
    .line 33
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    if-eqz v2, :cond_1

    .line 42
    .line 43
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    check-cast v2, Leb/d;

    .line 48
    .line 49
    iget-object v3, v2, Leb/d;->a:Landroid/net/Uri;

    .line 50
    .line 51
    invoke-virtual {v3}, Landroid/net/Uri;->toString()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v3

    .line 55
    invoke-virtual {v1, v3}, Ljava/io/ObjectOutputStream;->writeUTF(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    iget-boolean v2, v2, Leb/d;->b:Z

    .line 59
    .line 60
    invoke-virtual {v1, v2}, Ljava/io/ObjectOutputStream;->writeBoolean(Z)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 61
    .line 62
    .line 63
    goto :goto_0

    .line 64
    :catchall_0
    move-exception p0

    .line 65
    goto :goto_1

    .line 66
    :cond_1
    :try_start_2
    invoke-interface {v1}, Ljava/io/Closeable;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 67
    .line 68
    .line 69
    invoke-interface {v0}, Ljava/io/Closeable;->close()V

    .line 70
    .line 71
    .line 72
    invoke-virtual {v0}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    const-string v0, "toByteArray(...)"

    .line 77
    .line 78
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    return-object p0

    .line 82
    :catchall_1
    move-exception p0

    .line 83
    goto :goto_2

    .line 84
    :goto_1
    :try_start_3
    throw p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 85
    :catchall_2
    move-exception v2

    .line 86
    :try_start_4
    invoke-static {v1, p0}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 87
    .line 88
    .line 89
    throw v2
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 90
    :goto_2
    :try_start_5
    throw p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    .line 91
    :catchall_3
    move-exception v1

    .line 92
    invoke-static {v0, p0}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 93
    .line 94
    .line 95
    throw v1
.end method

.method public static final l(Leb/h0;)I
    .locals 1

    .line 1
    const-string v0, "state"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    if-eqz p0, :cond_2

    .line 11
    .line 12
    const/4 v0, 0x1

    .line 13
    if-eq p0, v0, :cond_1

    .line 14
    .line 15
    const/4 v0, 0x2

    .line 16
    if-eq p0, v0, :cond_1

    .line 17
    .line 18
    const/4 v0, 0x3

    .line 19
    if-eq p0, v0, :cond_1

    .line 20
    .line 21
    const/4 v0, 0x4

    .line 22
    if-eq p0, v0, :cond_1

    .line 23
    .line 24
    const/4 v0, 0x5

    .line 25
    if-ne p0, v0, :cond_0

    .line 26
    .line 27
    return v0

    .line 28
    :cond_0
    new-instance p0, La8/r0;

    .line 29
    .line 30
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 31
    .line 32
    .line 33
    throw p0

    .line 34
    :cond_1
    return v0

    .line 35
    :cond_2
    const/4 p0, 0x0

    .line 36
    return p0
.end method

.method public static final m([B)Lnb/d;
    .locals 6

    .line 1
    const-string v0, "bytes"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v0, p0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    new-instance p0, Lnb/d;

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    invoke-direct {p0, v0}, Lnb/d;-><init>(Landroid/net/NetworkRequest;)V

    .line 13
    .line 14
    .line 15
    return-object p0

    .line 16
    :cond_0
    new-instance v0, Ljava/io/ByteArrayInputStream;

    .line 17
    .line 18
    invoke-direct {v0, p0}, Ljava/io/ByteArrayInputStream;-><init>([B)V

    .line 19
    .line 20
    .line 21
    :try_start_0
    new-instance p0, Ljava/io/ObjectInputStream;

    .line 22
    .line 23
    invoke-direct {p0, v0}, Ljava/io/ObjectInputStream;-><init>(Ljava/io/InputStream;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 24
    .line 25
    .line 26
    :try_start_1
    invoke-virtual {p0}, Ljava/io/ObjectInputStream;->readInt()I

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    new-array v2, v1, [I

    .line 31
    .line 32
    const/4 v3, 0x0

    .line 33
    move v4, v3

    .line 34
    :goto_0
    if-ge v4, v1, :cond_1

    .line 35
    .line 36
    invoke-virtual {p0}, Ljava/io/ObjectInputStream;->readInt()I

    .line 37
    .line 38
    .line 39
    move-result v5

    .line 40
    aput v5, v2, v4

    .line 41
    .line 42
    add-int/lit8 v4, v4, 0x1

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :catchall_0
    move-exception v1

    .line 46
    goto :goto_2

    .line 47
    :cond_1
    invoke-virtual {p0}, Ljava/io/ObjectInputStream;->readInt()I

    .line 48
    .line 49
    .line 50
    move-result v1

    .line 51
    new-array v4, v1, [I

    .line 52
    .line 53
    :goto_1
    if-ge v3, v1, :cond_2

    .line 54
    .line 55
    invoke-virtual {p0}, Ljava/io/ObjectInputStream;->readInt()I

    .line 56
    .line 57
    .line 58
    move-result v5

    .line 59
    aput v5, v4, v3

    .line 60
    .line 61
    add-int/lit8 v3, v3, 0x1

    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_2
    invoke-static {v4, v2}, Lnb/e;->c([I[I)Lnb/d;

    .line 65
    .line 66
    .line 67
    move-result-object v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 68
    :try_start_2
    invoke-virtual {p0}, Ljava/io/ObjectInputStream;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 69
    .line 70
    .line 71
    invoke-virtual {v0}, Ljava/io/ByteArrayInputStream;->close()V

    .line 72
    .line 73
    .line 74
    return-object v1

    .line 75
    :catchall_1
    move-exception p0

    .line 76
    goto :goto_3

    .line 77
    :goto_2
    :try_start_3
    throw v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 78
    :catchall_2
    move-exception v2

    .line 79
    :try_start_4
    invoke-static {p0, v1}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 80
    .line 81
    .line 82
    throw v2
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 83
    :goto_3
    :try_start_5
    throw p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    .line 84
    :catchall_3
    move-exception v1

    .line 85
    invoke-static {v0, p0}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 86
    .line 87
    .line 88
    throw v1
.end method


# virtual methods
.method public abstract h()Z
.end method

.method public abstract i()Z
.end method
