.class public Landroidx/core/google/shortcuts/ShortcutInfoChangeListenerImpl;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Landroid/content/Context;

.field public final b:Lbp/v;

.field public final c:Lbp/b;

.field public final d:Lhu/q;


# direct methods
.method public constructor <init>(Landroid/content/Context;Lbp/v;Lbp/b;Lhu/q;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Landroidx/core/google/shortcuts/ShortcutInfoChangeListenerImpl;->a:Landroid/content/Context;

    .line 5
    .line 6
    iput-object p2, p0, Landroidx/core/google/shortcuts/ShortcutInfoChangeListenerImpl;->b:Lbp/v;

    .line 7
    .line 8
    iput-object p3, p0, Landroidx/core/google/shortcuts/ShortcutInfoChangeListenerImpl;->c:Lbp/b;

    .line 9
    .line 10
    iput-object p4, p0, Landroidx/core/google/shortcuts/ShortcutInfoChangeListenerImpl;->d:Lhu/q;

    .line 11
    .line 12
    return-void
.end method

.method public static getInstance(Landroid/content/Context;)Landroidx/core/google/shortcuts/ShortcutInfoChangeListenerImpl;
    .locals 5

    .line 1
    new-instance v0, Landroidx/core/google/shortcuts/ShortcutInfoChangeListenerImpl;

    .line 2
    .line 3
    const-class v1, Lbp/v;

    .line 4
    .line 5
    monitor-enter v1

    .line 6
    :try_start_0
    invoke-static {p0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    sget-object v2, Lbp/v;->b:Ljava/lang/ref/WeakReference;

    .line 10
    .line 11
    const/4 v3, 0x0

    .line 12
    if-nez v2, :cond_0

    .line 13
    .line 14
    move-object v2, v3

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    invoke-virtual {v2}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    check-cast v2, Lbp/v;

    .line 21
    .line 22
    :goto_0
    if-nez v2, :cond_1

    .line 23
    .line 24
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    new-instance v4, Lbp/v;

    .line 29
    .line 30
    invoke-direct {v4, v2}, Lbp/v;-><init>(Landroid/content/Context;)V

    .line 31
    .line 32
    .line 33
    new-instance v2, Ljava/lang/ref/WeakReference;

    .line 34
    .line 35
    invoke-direct {v2, v4}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    sput-object v2, Lbp/v;->b:Ljava/lang/ref/WeakReference;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 39
    .line 40
    monitor-exit v1

    .line 41
    move-object v2, v4

    .line 42
    goto :goto_1

    .line 43
    :catchall_0
    move-exception p0

    .line 44
    goto :goto_5

    .line 45
    :cond_1
    monitor-exit v1

    .line 46
    :goto_1
    const-class v4, Lbp/b;

    .line 47
    .line 48
    monitor-enter v4

    .line 49
    :try_start_1
    sget-object v1, Lbp/b;->b:Ljava/lang/ref/WeakReference;

    .line 50
    .line 51
    if-nez v1, :cond_2

    .line 52
    .line 53
    goto :goto_2

    .line 54
    :cond_2
    invoke-virtual {v1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    move-object v3, v1

    .line 59
    check-cast v3, Lbp/b;

    .line 60
    .line 61
    :goto_2
    if-nez v3, :cond_3

    .line 62
    .line 63
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    new-instance v3, Lbp/b;

    .line 68
    .line 69
    invoke-direct {v3, v1}, Lbp/b;-><init>(Landroid/content/Context;)V

    .line 70
    .line 71
    .line 72
    new-instance v1, Ljava/lang/ref/WeakReference;

    .line 73
    .line 74
    invoke-direct {v1, v3}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    sput-object v1, Lbp/b;->b:Ljava/lang/ref/WeakReference;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 78
    .line 79
    :cond_3
    monitor-exit v4

    .line 80
    goto :goto_3

    .line 81
    :catchall_1
    move-exception p0

    .line 82
    goto :goto_4

    .line 83
    :goto_3
    invoke-static {p0}, Lkp/k;->b(Landroid/content/Context;)Lhu/q;

    .line 84
    .line 85
    .line 86
    move-result-object v1

    .line 87
    invoke-direct {v0, p0, v2, v3, v1}, Landroidx/core/google/shortcuts/ShortcutInfoChangeListenerImpl;-><init>(Landroid/content/Context;Lbp/v;Lbp/b;Lhu/q;)V

    .line 88
    .line 89
    .line 90
    return-object v0

    .line 91
    :goto_4
    :try_start_2
    monitor-exit v4
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 92
    throw p0

    .line 93
    :goto_5
    :try_start_3
    monitor-exit v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 94
    throw p0
.end method


# virtual methods
.method public final a(Ljava/util/List;)V
    .locals 19

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    new-instance v2, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 6
    .line 7
    .line 8
    invoke-interface/range {p1 .. p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 9
    .line 10
    .line 11
    move-result-object v3

    .line 12
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    const/4 v4, 0x0

    .line 17
    if-eqz v0, :cond_e

    .line 18
    .line 19
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    move-object v5, v0

    .line 24
    check-cast v5, Lo5/a;

    .line 25
    .line 26
    iget-object v0, v5, Lo5/a;->b:Ljava/lang/String;

    .line 27
    .line 28
    iget-object v6, v1, Landroidx/core/google/shortcuts/ShortcutInfoChangeListenerImpl;->a:Landroid/content/Context;

    .line 29
    .line 30
    invoke-static {v6, v0}, Lkp/k;->a(Landroid/content/Context;Ljava/lang/String;)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v7

    .line 34
    iget-object v0, v5, Lo5/a;->c:[Landroid/content/Intent;

    .line 35
    .line 36
    array-length v8, v0

    .line 37
    const/4 v9, 0x1

    .line 38
    sub-int/2addr v8, v9

    .line 39
    aget-object v0, v0, v8

    .line 40
    .line 41
    invoke-virtual {v0, v9}, Landroid/content/Intent;->toUri(I)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v8

    .line 45
    const-string v10, "shortcutUrl"

    .line 46
    .line 47
    iget-object v0, v1, Landroidx/core/google/shortcuts/ShortcutInfoChangeListenerImpl;->d:Lhu/q;

    .line 48
    .line 49
    if-nez v0, :cond_0

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_0
    :try_start_0
    invoke-virtual {v0}, Lhu/q;->C()Lor/e;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    const-string v11, "UTF-8"

    .line 57
    .line 58
    invoke-static {v11}, Ljava/nio/charset/Charset;->forName(Ljava/lang/String;)Ljava/nio/charset/Charset;

    .line 59
    .line 60
    .line 61
    move-result-object v11

    .line 62
    invoke-virtual {v8, v11}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 63
    .line 64
    .line 65
    move-result-object v11

    .line 66
    invoke-interface {v0, v11}, Lmr/b;->b([B)[B

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    invoke-static {v0, v4}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object v0

    .line 74
    new-instance v11, Landroid/content/Intent;

    .line 75
    .line 76
    const-class v12, Landroidx/core/google/shortcuts/TrampolineActivity;

    .line 77
    .line 78
    invoke-direct {v11, v6, v12}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {v6}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v6

    .line 85
    invoke-virtual {v11, v6}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;

    .line 86
    .line 87
    .line 88
    const-string v6, "androidx.core.content.pm.SHORTCUT_LISTENER"

    .line 89
    .line 90
    invoke-virtual {v11, v6}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;

    .line 91
    .line 92
    .line 93
    invoke-virtual {v11, v10, v8}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 94
    .line 95
    .line 96
    const-string v6, "shortcutTag"

    .line 97
    .line 98
    invoke-virtual {v11, v6, v0}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 99
    .line 100
    .line 101
    invoke-virtual {v11, v9}, Landroid/content/Intent;->toUri(I)Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object v8
    :try_end_0
    .catch Ljava/security/GeneralSecurityException; {:try_start_0 .. :try_end_0} :catch_0

    .line 105
    goto :goto_1

    .line 106
    :catch_0
    move-exception v0

    .line 107
    const-string v6, "ShortcutUtils"

    .line 108
    .line 109
    const-string v9, "failed to generate tag for shortcut."

    .line 110
    .line 111
    invoke-static {v6, v9, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 112
    .line 113
    .line 114
    :goto_1
    iget-object v0, v5, Lo5/a;->d:Ljava/lang/String;

    .line 115
    .line 116
    invoke-virtual {v0}, Ljava/lang/String;->toString()Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object v0

    .line 120
    new-instance v6, Lq5/c;

    .line 121
    .line 122
    const-string v9, "Shortcut"

    .line 123
    .line 124
    invoke-direct {v6, v9}, Leb/j0;-><init>(Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    iget-object v9, v5, Lo5/a;->b:Ljava/lang/String;

    .line 128
    .line 129
    filled-new-array {v9}, [Ljava/lang/String;

    .line 130
    .line 131
    .line 132
    move-result-object v9

    .line 133
    const-string v11, "id"

    .line 134
    .line 135
    invoke-virtual {v6, v11, v9}, Leb/j0;->C(Ljava/lang/String;[Ljava/lang/String;)V

    .line 136
    .line 137
    .line 138
    invoke-static {v7}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 139
    .line 140
    .line 141
    iput-object v7, v6, Leb/j0;->g:Ljava/lang/Object;

    .line 142
    .line 143
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 144
    .line 145
    .line 146
    filled-new-array {v0}, [Ljava/lang/String;

    .line 147
    .line 148
    .line 149
    move-result-object v7

    .line 150
    const-string v9, "name"

    .line 151
    .line 152
    invoke-virtual {v6, v9, v7}, Leb/j0;->C(Ljava/lang/String;[Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    const-string v7, "shortcutLabel"

    .line 156
    .line 157
    filled-new-array {v0}, [Ljava/lang/String;

    .line 158
    .line 159
    .line 160
    move-result-object v0

    .line 161
    invoke-virtual {v6, v7, v0}, Leb/j0;->C(Ljava/lang/String;[Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    filled-new-array {v8}, [Ljava/lang/String;

    .line 165
    .line 166
    .line 167
    move-result-object v0

    .line 168
    invoke-virtual {v6, v10, v0}, Leb/j0;->C(Ljava/lang/String;[Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    iget-object v0, v5, Lo5/a;->e:Ljava/lang/String;

    .line 172
    .line 173
    if-eqz v0, :cond_1

    .line 174
    .line 175
    invoke-virtual {v0}, Ljava/lang/String;->toString()Ljava/lang/String;

    .line 176
    .line 177
    .line 178
    move-result-object v0

    .line 179
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 180
    .line 181
    .line 182
    filled-new-array {v0}, [Ljava/lang/String;

    .line 183
    .line 184
    .line 185
    move-result-object v7

    .line 186
    const-string v8, "description"

    .line 187
    .line 188
    invoke-virtual {v6, v8, v7}, Leb/j0;->C(Ljava/lang/String;[Ljava/lang/String;)V

    .line 189
    .line 190
    .line 191
    const-string v7, "shortcutDescription"

    .line 192
    .line 193
    filled-new-array {v0}, [Ljava/lang/String;

    .line 194
    .line 195
    .line 196
    move-result-object v0

    .line 197
    invoke-virtual {v6, v7, v0}, Leb/j0;->C(Ljava/lang/String;[Ljava/lang/String;)V

    .line 198
    .line 199
    .line 200
    :cond_1
    iget-object v0, v5, Lo5/a;->g:Ljava/util/HashSet;

    .line 201
    .line 202
    if-eqz v0, :cond_a

    .line 203
    .line 204
    new-instance v0, Ljava/util/ArrayList;

    .line 205
    .line 206
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 207
    .line 208
    .line 209
    iget-object v7, v5, Lo5/a;->g:Ljava/util/HashSet;

    .line 210
    .line 211
    invoke-virtual {v7}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 212
    .line 213
    .line 214
    move-result-object v7

    .line 215
    :goto_2
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 216
    .line 217
    .line 218
    move-result v8

    .line 219
    if-eqz v8, :cond_9

    .line 220
    .line 221
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    move-result-object v8

    .line 225
    check-cast v8, Ljava/lang/String;

    .line 226
    .line 227
    const-string v10, "actions.intent."

    .line 228
    .line 229
    invoke-virtual {v8, v10}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 230
    .line 231
    .line 232
    move-result v10

    .line 233
    if-nez v10, :cond_2

    .line 234
    .line 235
    goto :goto_2

    .line 236
    :cond_2
    iget-object v10, v5, Lo5/a;->h:Landroid/os/PersistableBundle;

    .line 237
    .line 238
    new-instance v11, Lq5/a;

    .line 239
    .line 240
    const-string v12, "Capability"

    .line 241
    .line 242
    invoke-direct {v11, v12}, Leb/j0;-><init>(Ljava/lang/String;)V

    .line 243
    .line 244
    .line 245
    filled-new-array {v8}, [Ljava/lang/String;

    .line 246
    .line 247
    .line 248
    move-result-object v12

    .line 249
    invoke-virtual {v11, v9, v12}, Leb/j0;->C(Ljava/lang/String;[Ljava/lang/String;)V

    .line 250
    .line 251
    .line 252
    if-nez v10, :cond_3

    .line 253
    .line 254
    :goto_3
    move-object/from16 v16, v3

    .line 255
    .line 256
    move-object/from16 v17, v7

    .line 257
    .line 258
    goto/16 :goto_6

    .line 259
    .line 260
    :cond_3
    invoke-virtual {v10, v8}, Landroid/os/BaseBundle;->getStringArray(Ljava/lang/String;)[Ljava/lang/String;

    .line 261
    .line 262
    .line 263
    move-result-object v12

    .line 264
    if-nez v12, :cond_4

    .line 265
    .line 266
    goto :goto_3

    .line 267
    :cond_4
    new-instance v13, Ljava/util/ArrayList;

    .line 268
    .line 269
    invoke-direct {v13}, Ljava/util/ArrayList;-><init>()V

    .line 270
    .line 271
    .line 272
    array-length v14, v12

    .line 273
    move v15, v4

    .line 274
    :goto_4
    if-ge v15, v14, :cond_7

    .line 275
    .line 276
    aget-object v4, v12, v15

    .line 277
    .line 278
    move-object/from16 v16, v3

    .line 279
    .line 280
    new-instance v3, Lq5/b;

    .line 281
    .line 282
    move-object/from16 v17, v7

    .line 283
    .line 284
    const-string v7, "Parameter"

    .line 285
    .line 286
    invoke-direct {v3, v7}, Leb/j0;-><init>(Ljava/lang/String;)V

    .line 287
    .line 288
    .line 289
    invoke-static {v4}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 290
    .line 291
    .line 292
    filled-new-array {v4}, [Ljava/lang/String;

    .line 293
    .line 294
    .line 295
    move-result-object v7

    .line 296
    invoke-virtual {v3, v9, v7}, Leb/j0;->C(Ljava/lang/String;[Ljava/lang/String;)V

    .line 297
    .line 298
    .line 299
    new-instance v7, Ljava/lang/StringBuilder;

    .line 300
    .line 301
    invoke-direct {v7}, Ljava/lang/StringBuilder;-><init>()V

    .line 302
    .line 303
    .line 304
    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 305
    .line 306
    .line 307
    move-object/from16 v18, v8

    .line 308
    .line 309
    const-string v8, "/"

    .line 310
    .line 311
    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 312
    .line 313
    .line 314
    invoke-virtual {v7, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 315
    .line 316
    .line 317
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 318
    .line 319
    .line 320
    move-result-object v4

    .line 321
    invoke-virtual {v10, v4}, Landroid/os/BaseBundle;->getStringArray(Ljava/lang/String;)[Ljava/lang/String;

    .line 322
    .line 323
    .line 324
    move-result-object v4

    .line 325
    if-eqz v4, :cond_6

    .line 326
    .line 327
    array-length v7, v4

    .line 328
    if-nez v7, :cond_5

    .line 329
    .line 330
    goto :goto_5

    .line 331
    :cond_5
    const-string v7, "value"

    .line 332
    .line 333
    invoke-virtual {v3, v7, v4}, Leb/j0;->C(Ljava/lang/String;[Ljava/lang/String;)V

    .line 334
    .line 335
    .line 336
    invoke-virtual {v13, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 337
    .line 338
    .line 339
    :cond_6
    :goto_5
    add-int/lit8 v15, v15, 0x1

    .line 340
    .line 341
    move-object/from16 v3, v16

    .line 342
    .line 343
    move-object/from16 v7, v17

    .line 344
    .line 345
    move-object/from16 v8, v18

    .line 346
    .line 347
    const/4 v4, 0x0

    .line 348
    goto :goto_4

    .line 349
    :cond_7
    move-object/from16 v16, v3

    .line 350
    .line 351
    move-object/from16 v17, v7

    .line 352
    .line 353
    invoke-virtual {v13}, Ljava/util/ArrayList;->size()I

    .line 354
    .line 355
    .line 356
    move-result v3

    .line 357
    if-lez v3, :cond_8

    .line 358
    .line 359
    const/4 v3, 0x0

    .line 360
    new-array v4, v3, [Lq5/b;

    .line 361
    .line 362
    invoke-virtual {v13, v4}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 363
    .line 364
    .line 365
    move-result-object v3

    .line 366
    check-cast v3, [Lq5/b;

    .line 367
    .line 368
    const-string v4, "parameter"

    .line 369
    .line 370
    invoke-virtual {v11, v4, v3}, Leb/j0;->B(Ljava/lang/String;[Leb/j0;)V

    .line 371
    .line 372
    .line 373
    :cond_8
    :goto_6
    invoke-virtual {v0, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 374
    .line 375
    .line 376
    move-object/from16 v3, v16

    .line 377
    .line 378
    move-object/from16 v7, v17

    .line 379
    .line 380
    const/4 v4, 0x0

    .line 381
    goto/16 :goto_2

    .line 382
    .line 383
    :cond_9
    move-object/from16 v16, v3

    .line 384
    .line 385
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 386
    .line 387
    .line 388
    move-result v3

    .line 389
    if-nez v3, :cond_b

    .line 390
    .line 391
    const/4 v3, 0x0

    .line 392
    new-array v3, v3, [Lq5/a;

    .line 393
    .line 394
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 395
    .line 396
    .line 397
    move-result-object v0

    .line 398
    check-cast v0, [Lq5/a;

    .line 399
    .line 400
    const-string v3, "capability"

    .line 401
    .line 402
    invoke-virtual {v6, v3, v0}, Leb/j0;->B(Ljava/lang/String;[Leb/j0;)V

    .line 403
    .line 404
    .line 405
    goto :goto_7

    .line 406
    :cond_a
    move-object/from16 v16, v3

    .line 407
    .line 408
    :cond_b
    :goto_7
    iget-object v0, v5, Lo5/a;->f:Landroidx/core/graphics/drawable/IconCompat;

    .line 409
    .line 410
    if-eqz v0, :cond_d

    .line 411
    .line 412
    invoke-virtual {v0}, Landroidx/core/graphics/drawable/IconCompat;->c()I

    .line 413
    .line 414
    .line 415
    move-result v3

    .line 416
    const/4 v4, 0x6

    .line 417
    if-eq v3, v4, :cond_c

    .line 418
    .line 419
    invoke-virtual {v0}, Landroidx/core/graphics/drawable/IconCompat;->c()I

    .line 420
    .line 421
    .line 422
    move-result v3

    .line 423
    const/4 v4, 0x4

    .line 424
    if-ne v3, v4, :cond_d

    .line 425
    .line 426
    :cond_c
    invoke-virtual {v0}, Landroidx/core/graphics/drawable/IconCompat;->d()Landroid/net/Uri;

    .line 427
    .line 428
    .line 429
    move-result-object v0

    .line 430
    invoke-virtual {v0}, Landroid/net/Uri;->toString()Ljava/lang/String;

    .line 431
    .line 432
    .line 433
    move-result-object v0

    .line 434
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 435
    .line 436
    .line 437
    filled-new-array {v0}, [Ljava/lang/String;

    .line 438
    .line 439
    .line 440
    move-result-object v0

    .line 441
    const-string v3, "image"

    .line 442
    .line 443
    invoke-virtual {v6, v3, v0}, Leb/j0;->C(Ljava/lang/String;[Ljava/lang/String;)V

    .line 444
    .line 445
    .line 446
    :cond_d
    invoke-virtual {v6}, Leb/j0;->a()Lcom/google/firebase/appindexing/internal/Thing;

    .line 447
    .line 448
    .line 449
    move-result-object v0

    .line 450
    invoke-virtual {v2, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 451
    .line 452
    .line 453
    move-object/from16 v3, v16

    .line 454
    .line 455
    goto/16 :goto_0

    .line 456
    .line 457
    :cond_e
    move v3, v4

    .line 458
    new-array v0, v3, [Lcom/google/firebase/appindexing/internal/Thing;

    .line 459
    .line 460
    invoke-virtual {v2, v0}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 461
    .line 462
    .line 463
    move-result-object v0

    .line 464
    check-cast v0, [Lcom/google/firebase/appindexing/internal/Thing;

    .line 465
    .line 466
    if-nez v0, :cond_f

    .line 467
    .line 468
    const/4 v0, 0x0

    .line 469
    move-object v7, v0

    .line 470
    goto :goto_8

    .line 471
    :cond_f
    :try_start_1
    array-length v2, v0

    .line 472
    new-array v4, v2, [Lcom/google/firebase/appindexing/internal/Thing;

    .line 473
    .line 474
    invoke-static {v0, v3, v4, v3, v2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 475
    .line 476
    .line 477
    move-object v7, v4

    .line 478
    :goto_8
    if-nez v7, :cond_10

    .line 479
    .line 480
    new-instance v0, Leo/a;

    .line 481
    .line 482
    const-string v1, "Indexables cannot be null."

    .line 483
    .line 484
    invoke-direct {v0, v1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 485
    .line 486
    .line 487
    invoke-static {v0}, Ljp/l1;->d(Ljava/lang/Exception;)Laq/t;
    :try_end_1
    .catch Ljava/lang/ArrayStoreException; {:try_start_1 .. :try_end_1} :catch_1

    .line 488
    .line 489
    .line 490
    goto :goto_9

    .line 491
    :cond_10
    new-instance v5, Lfs/f;

    .line 492
    .line 493
    const/4 v11, 0x0

    .line 494
    const/4 v12, 0x0

    .line 495
    const/4 v6, 0x1

    .line 496
    const/4 v8, 0x0

    .line 497
    const/4 v9, 0x0

    .line 498
    const/4 v10, 0x0

    .line 499
    invoke-direct/range {v5 .. v12}, Lfs/f;-><init>(I[Lcom/google/firebase/appindexing/internal/Thing;[Ljava/lang/String;[Ljava/lang/String;Lbp/p;Ljava/lang/String;Ljava/lang/String;)V

    .line 500
    .line 501
    .line 502
    iget-object v0, v1, Landroidx/core/google/shortcuts/ShortcutInfoChangeListenerImpl;->b:Lbp/v;

    .line 503
    .line 504
    iget-object v0, v0, Lbp/v;->a:Lbp/u;

    .line 505
    .line 506
    invoke-virtual {v0, v5}, Lbp/u;->a(Lfs/f;)Laq/t;

    .line 507
    .line 508
    .line 509
    goto :goto_9

    .line 510
    :catch_1
    new-instance v0, Leo/a;

    .line 511
    .line 512
    const-string v1, "Custom Indexable-objects are not allowed. Please use the \'Indexables\'-class for creating the objects."

    .line 513
    .line 514
    invoke-direct {v0, v1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 515
    .line 516
    .line 517
    invoke-static {v0}, Ljp/l1;->d(Ljava/lang/Exception;)Laq/t;

    .line 518
    .line 519
    .line 520
    :goto_9
    return-void
.end method
