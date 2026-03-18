.class public abstract Lkp/w7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/lang/String;Ljava/lang/String;Lyj/b;Lxh/e;Ll2/o;I)V
    .locals 17

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    const-string v0, "vin"

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    move-object/from16 v6, p4

    .line 9
    .line 10
    check-cast v6, Ll2/t;

    .line 11
    .line 12
    const v0, 0x23e13954

    .line 13
    .line 14
    .line 15
    invoke-virtual {v6, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v6, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    const/4 v2, 0x4

    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    move v0, v2

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 v0, 0x2

    .line 28
    :goto_0
    or-int v0, p5, v0

    .line 29
    .line 30
    move-object/from16 v3, p1

    .line 31
    .line 32
    invoke-virtual {v6, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v4

    .line 36
    const/16 v5, 0x20

    .line 37
    .line 38
    if-eqz v4, :cond_1

    .line 39
    .line 40
    move v4, v5

    .line 41
    goto :goto_1

    .line 42
    :cond_1
    const/16 v4, 0x10

    .line 43
    .line 44
    :goto_1
    or-int/2addr v0, v4

    .line 45
    move-object/from16 v4, p2

    .line 46
    .line 47
    invoke-virtual {v6, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result v7

    .line 51
    const/16 v8, 0x100

    .line 52
    .line 53
    if-eqz v7, :cond_2

    .line 54
    .line 55
    move v7, v8

    .line 56
    goto :goto_2

    .line 57
    :cond_2
    const/16 v7, 0x80

    .line 58
    .line 59
    :goto_2
    or-int/2addr v0, v7

    .line 60
    move-object/from16 v7, p3

    .line 61
    .line 62
    invoke-virtual {v6, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result v9

    .line 66
    const/16 v10, 0x800

    .line 67
    .line 68
    if-eqz v9, :cond_3

    .line 69
    .line 70
    move v9, v10

    .line 71
    goto :goto_3

    .line 72
    :cond_3
    const/16 v9, 0x400

    .line 73
    .line 74
    :goto_3
    or-int/2addr v0, v9

    .line 75
    and-int/lit16 v9, v0, 0x493

    .line 76
    .line 77
    const/16 v11, 0x492

    .line 78
    .line 79
    const/4 v12, 0x1

    .line 80
    const/4 v13, 0x0

    .line 81
    if-eq v9, v11, :cond_4

    .line 82
    .line 83
    move v9, v12

    .line 84
    goto :goto_4

    .line 85
    :cond_4
    move v9, v13

    .line 86
    :goto_4
    and-int/lit8 v11, v0, 0x1

    .line 87
    .line 88
    invoke-virtual {v6, v11, v9}, Ll2/t;->O(IZ)Z

    .line 89
    .line 90
    .line 91
    move-result v9

    .line 92
    if-eqz v9, :cond_10

    .line 93
    .line 94
    and-int/lit8 v9, v0, 0xe

    .line 95
    .line 96
    if-ne v9, v2, :cond_5

    .line 97
    .line 98
    move v2, v12

    .line 99
    goto :goto_5

    .line 100
    :cond_5
    move v2, v13

    .line 101
    :goto_5
    and-int/lit8 v9, v0, 0x70

    .line 102
    .line 103
    if-ne v9, v5, :cond_6

    .line 104
    .line 105
    move v5, v12

    .line 106
    goto :goto_6

    .line 107
    :cond_6
    move v5, v13

    .line 108
    :goto_6
    or-int/2addr v2, v5

    .line 109
    and-int/lit16 v5, v0, 0x380

    .line 110
    .line 111
    if-ne v5, v8, :cond_7

    .line 112
    .line 113
    move v5, v12

    .line 114
    goto :goto_7

    .line 115
    :cond_7
    move v5, v13

    .line 116
    :goto_7
    or-int/2addr v2, v5

    .line 117
    and-int/lit16 v0, v0, 0x1c00

    .line 118
    .line 119
    if-ne v0, v10, :cond_8

    .line 120
    .line 121
    goto :goto_8

    .line 122
    :cond_8
    move v12, v13

    .line 123
    :goto_8
    or-int v0, v2, v12

    .line 124
    .line 125
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v2

    .line 129
    sget-object v8, Ll2/n;->a:Ll2/x0;

    .line 130
    .line 131
    if-nez v0, :cond_9

    .line 132
    .line 133
    if-ne v2, v8, :cond_a

    .line 134
    .line 135
    :cond_9
    new-instance v0, Lsf/a;

    .line 136
    .line 137
    const/4 v5, 0x0

    .line 138
    move-object v2, v3

    .line 139
    move-object v3, v4

    .line 140
    move-object v4, v7

    .line 141
    invoke-direct/range {v0 .. v5}, Lsf/a;-><init>(Ljava/lang/String;Ljava/lang/String;Lyj/b;Lxh/e;I)V

    .line 142
    .line 143
    .line 144
    invoke-virtual {v6, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 145
    .line 146
    .line 147
    move-object v2, v0

    .line 148
    :cond_a
    check-cast v2, Lay0/k;

    .line 149
    .line 150
    sget-object v0, Lw3/q1;->a:Ll2/u2;

    .line 151
    .line 152
    invoke-virtual {v6, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v0

    .line 156
    check-cast v0, Ljava/lang/Boolean;

    .line 157
    .line 158
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 159
    .line 160
    .line 161
    move-result v0

    .line 162
    if-eqz v0, :cond_b

    .line 163
    .line 164
    const v0, -0x105bcaaa

    .line 165
    .line 166
    .line 167
    invoke-virtual {v6, v0}, Ll2/t;->Y(I)V

    .line 168
    .line 169
    .line 170
    invoke-virtual {v6, v13}, Ll2/t;->q(Z)V

    .line 171
    .line 172
    .line 173
    const/4 v0, 0x0

    .line 174
    goto :goto_9

    .line 175
    :cond_b
    const v0, 0x31054eee

    .line 176
    .line 177
    .line 178
    invoke-virtual {v6, v0}, Ll2/t;->Y(I)V

    .line 179
    .line 180
    .line 181
    sget-object v0, Lzb/x;->a:Ll2/u2;

    .line 182
    .line 183
    invoke-virtual {v6, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 184
    .line 185
    .line 186
    move-result-object v0

    .line 187
    check-cast v0, Lhi/a;

    .line 188
    .line 189
    invoke-virtual {v6, v13}, Ll2/t;->q(Z)V

    .line 190
    .line 191
    .line 192
    :goto_9
    new-instance v4, Lnd/e;

    .line 193
    .line 194
    const/16 v1, 0x13

    .line 195
    .line 196
    invoke-direct {v4, v0, v2, v1}, Lnd/e;-><init>(Lhi/a;Lay0/k;I)V

    .line 197
    .line 198
    .line 199
    invoke-static {v6}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 200
    .line 201
    .line 202
    move-result-object v2

    .line 203
    if-eqz v2, :cond_f

    .line 204
    .line 205
    instance-of v0, v2, Landroidx/lifecycle/k;

    .line 206
    .line 207
    if-eqz v0, :cond_c

    .line 208
    .line 209
    move-object v0, v2

    .line 210
    check-cast v0, Landroidx/lifecycle/k;

    .line 211
    .line 212
    invoke-interface {v0}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 213
    .line 214
    .line 215
    move-result-object v0

    .line 216
    :goto_a
    move-object v5, v0

    .line 217
    goto :goto_b

    .line 218
    :cond_c
    sget-object v0, Lp7/a;->b:Lp7/a;

    .line 219
    .line 220
    goto :goto_a

    .line 221
    :goto_b
    const-class v0, Lsf/f;

    .line 222
    .line 223
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 224
    .line 225
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 226
    .line 227
    .line 228
    move-result-object v1

    .line 229
    const/4 v3, 0x0

    .line 230
    invoke-static/range {v1 .. v6}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 231
    .line 232
    .line 233
    move-result-object v0

    .line 234
    move-object v11, v0

    .line 235
    check-cast v11, Lsf/f;

    .line 236
    .line 237
    invoke-static {v6}, Ljp/of;->d(Ll2/o;)Lqf/d;

    .line 238
    .line 239
    .line 240
    move-result-object v0

    .line 241
    iget-object v1, v11, Lsf/f;->h:Lyy0/c2;

    .line 242
    .line 243
    invoke-static {v1, v6}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 244
    .line 245
    .line 246
    move-result-object v1

    .line 247
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    move-result-object v1

    .line 251
    check-cast v1, Llc/q;

    .line 252
    .line 253
    invoke-virtual {v6, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 254
    .line 255
    .line 256
    move-result v2

    .line 257
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 258
    .line 259
    .line 260
    move-result-object v3

    .line 261
    if-nez v2, :cond_d

    .line 262
    .line 263
    if-ne v3, v8, :cond_e

    .line 264
    .line 265
    :cond_d
    new-instance v9, Ls60/h;

    .line 266
    .line 267
    const/4 v15, 0x0

    .line 268
    const/16 v16, 0x10

    .line 269
    .line 270
    const/4 v10, 0x1

    .line 271
    const-class v12, Lsf/f;

    .line 272
    .line 273
    const-string v13, "onUiEvent"

    .line 274
    .line 275
    const-string v14, "onUiEvent(Lcariad/charging/multicharge/kitten/plugandcharge/presentation/confirmUninstallation/PlugAndChargeConfirmUninstallationUiEvent;)V"

    .line 276
    .line 277
    invoke-direct/range {v9 .. v16}, Ls60/h;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 278
    .line 279
    .line 280
    invoke-virtual {v6, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 281
    .line 282
    .line 283
    move-object v3, v9

    .line 284
    :cond_e
    check-cast v3, Lhy0/g;

    .line 285
    .line 286
    check-cast v3, Lay0/k;

    .line 287
    .line 288
    const/16 v2, 0x8

    .line 289
    .line 290
    invoke-interface {v0, v1, v3, v6, v2}, Lqf/d;->U(Llc/q;Lay0/k;Ll2/o;I)V

    .line 291
    .line 292
    .line 293
    goto :goto_c

    .line 294
    :cond_f
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 295
    .line 296
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 297
    .line 298
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 299
    .line 300
    .line 301
    throw v0

    .line 302
    :cond_10
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 303
    .line 304
    .line 305
    :goto_c
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 306
    .line 307
    .line 308
    move-result-object v7

    .line 309
    if-eqz v7, :cond_11

    .line 310
    .line 311
    new-instance v0, Lsf/b;

    .line 312
    .line 313
    const/4 v6, 0x0

    .line 314
    move-object/from16 v1, p0

    .line 315
    .line 316
    move-object/from16 v2, p1

    .line 317
    .line 318
    move-object/from16 v3, p2

    .line 319
    .line 320
    move-object/from16 v4, p3

    .line 321
    .line 322
    move/from16 v5, p5

    .line 323
    .line 324
    invoke-direct/range {v0 .. v6}, Lsf/b;-><init>(Ljava/lang/String;Ljava/lang/String;Lyj/b;Lxh/e;II)V

    .line 325
    .line 326
    .line 327
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 328
    .line 329
    :cond_11
    return-void
.end method

.method public static final b(Landroid/content/Context;)V
    .locals 10

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "androidx.work.workdb"

    .line 7
    .line 8
    invoke-virtual {p0, v0}, Landroid/content/Context;->getDatabasePath(Ljava/lang/String;)Ljava/io/File;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    const-string v2, "getDatabasePath(...)"

    .line 13
    .line 14
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v1}, Ljava/io/File;->exists()Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_5

    .line 22
    .line 23
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    sget-object v3, Lfb/q;->a:Ljava/lang/String;

    .line 28
    .line 29
    const-string v4, "Migrating WorkDatabase to the no-backup directory"

    .line 30
    .line 31
    invoke-virtual {v1, v3, v4}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0, v0}, Landroid/content/Context;->getDatabasePath(Ljava/lang/String;)Ljava/io/File;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p0}, Landroid/content/Context;->getNoBackupFilesDir()Ljava/io/File;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    const-string v1, "getNoBackupFilesDir(...)"

    .line 46
    .line 47
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    sget-object v1, Lfb/q;->b:[Ljava/lang/String;

    .line 51
    .line 52
    array-length v2, v1

    .line 53
    invoke-static {v2}, Lmx0/x;->k(I)I

    .line 54
    .line 55
    .line 56
    move-result v2

    .line 57
    const/16 v3, 0x10

    .line 58
    .line 59
    if-ge v2, v3, :cond_0

    .line 60
    .line 61
    move v2, v3

    .line 62
    :cond_0
    new-instance v3, Ljava/util/LinkedHashMap;

    .line 63
    .line 64
    invoke-direct {v3, v2}, Ljava/util/LinkedHashMap;-><init>(I)V

    .line 65
    .line 66
    .line 67
    array-length v2, v1

    .line 68
    const/4 v4, 0x0

    .line 69
    :goto_0
    if-ge v4, v2, :cond_1

    .line 70
    .line 71
    aget-object v5, v1, v4

    .line 72
    .line 73
    new-instance v6, Ljava/io/File;

    .line 74
    .line 75
    new-instance v7, Ljava/lang/StringBuilder;

    .line 76
    .line 77
    invoke-direct {v7}, Ljava/lang/StringBuilder;-><init>()V

    .line 78
    .line 79
    .line 80
    invoke-virtual {v0}, Ljava/io/File;->getPath()Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object v8

    .line 84
    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    invoke-virtual {v7, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object v7

    .line 94
    invoke-direct {v6, v7}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    new-instance v7, Ljava/io/File;

    .line 98
    .line 99
    new-instance v8, Ljava/lang/StringBuilder;

    .line 100
    .line 101
    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V

    .line 102
    .line 103
    .line 104
    invoke-virtual {p0}, Ljava/io/File;->getPath()Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v9

    .line 108
    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 109
    .line 110
    .line 111
    invoke-virtual {v8, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v5

    .line 118
    invoke-direct {v7, v5}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    invoke-interface {v3, v6, v7}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    add-int/lit8 v4, v4, 0x1

    .line 125
    .line 126
    goto :goto_0

    .line 127
    :cond_1
    new-instance v1, Llx0/l;

    .line 128
    .line 129
    invoke-direct {v1, v0, p0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 130
    .line 131
    .line 132
    invoke-static {v3, v1}, Lmx0/x;->q(Ljava/util/Map;Llx0/l;)Ljava/util/Map;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    invoke-interface {p0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 137
    .line 138
    .line 139
    move-result-object p0

    .line 140
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 141
    .line 142
    .line 143
    move-result-object p0

    .line 144
    :cond_2
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 145
    .line 146
    .line 147
    move-result v0

    .line 148
    if-eqz v0, :cond_5

    .line 149
    .line 150
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object v0

    .line 154
    check-cast v0, Ljava/util/Map$Entry;

    .line 155
    .line 156
    invoke-interface {v0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v1

    .line 160
    check-cast v1, Ljava/io/File;

    .line 161
    .line 162
    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object v0

    .line 166
    check-cast v0, Ljava/io/File;

    .line 167
    .line 168
    invoke-virtual {v1}, Ljava/io/File;->exists()Z

    .line 169
    .line 170
    .line 171
    move-result v2

    .line 172
    if-eqz v2, :cond_2

    .line 173
    .line 174
    invoke-virtual {v0}, Ljava/io/File;->exists()Z

    .line 175
    .line 176
    .line 177
    move-result v2

    .line 178
    if-eqz v2, :cond_3

    .line 179
    .line 180
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 181
    .line 182
    .line 183
    move-result-object v2

    .line 184
    sget-object v3, Lfb/q;->a:Ljava/lang/String;

    .line 185
    .line 186
    new-instance v4, Ljava/lang/StringBuilder;

    .line 187
    .line 188
    const-string v5, "Over-writing contents of "

    .line 189
    .line 190
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 194
    .line 195
    .line 196
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 197
    .line 198
    .line 199
    move-result-object v4

    .line 200
    invoke-virtual {v2, v3, v4}, Leb/w;->g(Ljava/lang/String;Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    :cond_3
    invoke-virtual {v1, v0}, Ljava/io/File;->renameTo(Ljava/io/File;)Z

    .line 204
    .line 205
    .line 206
    move-result v2

    .line 207
    if-eqz v2, :cond_4

    .line 208
    .line 209
    new-instance v2, Ljava/lang/StringBuilder;

    .line 210
    .line 211
    const-string v3, "Migrated "

    .line 212
    .line 213
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 214
    .line 215
    .line 216
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 217
    .line 218
    .line 219
    const-string v1, "to "

    .line 220
    .line 221
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 222
    .line 223
    .line 224
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 225
    .line 226
    .line 227
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 228
    .line 229
    .line 230
    move-result-object v0

    .line 231
    goto :goto_2

    .line 232
    :cond_4
    new-instance v2, Ljava/lang/StringBuilder;

    .line 233
    .line 234
    const-string v3, "Renaming "

    .line 235
    .line 236
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 237
    .line 238
    .line 239
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 240
    .line 241
    .line 242
    const-string v1, " to "

    .line 243
    .line 244
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 245
    .line 246
    .line 247
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 248
    .line 249
    .line 250
    const-string v0, " failed"

    .line 251
    .line 252
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 253
    .line 254
    .line 255
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 256
    .line 257
    .line 258
    move-result-object v0

    .line 259
    :goto_2
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 260
    .line 261
    .line 262
    move-result-object v1

    .line 263
    sget-object v2, Lfb/q;->a:Ljava/lang/String;

    .line 264
    .line 265
    invoke-virtual {v1, v2, v0}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 266
    .line 267
    .line 268
    goto :goto_1

    .line 269
    :cond_5
    return-void
.end method
