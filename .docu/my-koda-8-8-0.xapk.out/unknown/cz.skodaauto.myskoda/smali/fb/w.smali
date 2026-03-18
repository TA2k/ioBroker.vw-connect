.class public abstract Lfb/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Lm6/u0;Lb3/g;Ljava/util/List;Lpw0/a;Lay0/a;)Lm6/w;
    .locals 2

    .line 1
    const-string v0, "migrations"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lm6/b0;

    .line 7
    .line 8
    sget-object v1, Lm6/a0;->f:Lm6/a0;

    .line 9
    .line 10
    invoke-direct {v0, p0, v1, p4}, Lm6/b0;-><init>(Lm6/u0;Lay0/k;Lay0/a;)V

    .line 11
    .line 12
    .line 13
    if-eqz p1, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    new-instance p1, La61/a;

    .line 17
    .line 18
    const/16 p0, 0xa

    .line 19
    .line 20
    invoke-direct {p1, p0}, La61/a;-><init>(I)V

    .line 21
    .line 22
    .line 23
    :goto_0
    new-instance p0, Lk31/t;

    .line 24
    .line 25
    const/4 p4, 0x0

    .line 26
    const/16 v1, 0x13

    .line 27
    .line 28
    invoke-direct {p0, p2, p4, v1}, Lk31/t;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 29
    .line 30
    .line 31
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    new-instance p2, Lm6/w;

    .line 36
    .line 37
    invoke-direct {p2, v0, p0, p1, p3}, Lm6/w;-><init>(Lm6/b0;Ljava/util/List;Lm6/c;Lvy0/b0;)V

    .line 38
    .line 39
    .line 40
    return-object p2
.end method

.method public static final b(Landroid/content/Context;Leb/b;)Lfb/u;
    .locals 9

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Lob/a;

    .line 7
    .line 8
    iget-object v0, p1, Leb/b;->c:Ljava/util/concurrent/ExecutorService;

    .line 9
    .line 10
    invoke-direct {v4, v0}, Lob/a;-><init>(Ljava/util/concurrent/ExecutorService;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    const-string v1, "getApplicationContext(...)"

    .line 18
    .line 19
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    const-string v2, "getSerialTaskExecutor(...)"

    .line 23
    .line 24
    iget-object v3, v4, Lob/a;->a:Lla/a0;

    .line 25
    .line 26
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    iget-object v2, p1, Leb/b;->d:Leb/j;

    .line 30
    .line 31
    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 32
    .line 33
    .line 34
    move-result-object v5

    .line 35
    const v6, 0x7f050007

    .line 36
    .line 37
    .line 38
    invoke-virtual {v5, v6}, Landroid/content/res/Resources;->getBoolean(I)Z

    .line 39
    .line 40
    .line 41
    move-result v5

    .line 42
    const-string v6, "clock"

    .line 43
    .line 44
    invoke-static {v2, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    const/4 v6, 0x1

    .line 48
    const-class v7, Landroidx/work/impl/WorkDatabase;

    .line 49
    .line 50
    if-eqz v5, :cond_0

    .line 51
    .line 52
    new-instance v5, Lla/s;

    .line 53
    .line 54
    const/4 v8, 0x0

    .line 55
    invoke-direct {v5, v0, v7, v8}, Lla/s;-><init>(Landroid/content/Context;Ljava/lang/Class;Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    iput-boolean v6, v5, Lla/s;->i:Z

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_0
    const-string v5, "androidx.work.workdb"

    .line 62
    .line 63
    invoke-static {v0, v7, v5}, Llp/ff;->c(Landroid/content/Context;Ljava/lang/Class;Ljava/lang/String;)Lla/s;

    .line 64
    .line 65
    .line 66
    move-result-object v5

    .line 67
    new-instance v7, La8/t;

    .line 68
    .line 69
    const/16 v8, 0x1b

    .line 70
    .line 71
    invoke-direct {v7, v0, v8}, La8/t;-><init>(Ljava/lang/Object;I)V

    .line 72
    .line 73
    .line 74
    iput-object v7, v5, Lla/s;->h:Landroidx/sqlite/db/a;

    .line 75
    .line 76
    :goto_0
    iput-object v3, v5, Lla/s;->f:Ljava/util/concurrent/Executor;

    .line 77
    .line 78
    new-instance v3, Lfb/a;

    .line 79
    .line 80
    invoke-direct {v3, v2}, Lfb/a;-><init>(Leb/j;)V

    .line 81
    .line 82
    .line 83
    iget-object v2, v5, Lla/s;->d:Ljava/util/ArrayList;

    .line 84
    .line 85
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    new-array v2, v6, [Loa/b;

    .line 89
    .line 90
    sget-object v3, Lfb/c;->h:Lfb/c;

    .line 91
    .line 92
    const/4 v7, 0x0

    .line 93
    aput-object v3, v2, v7

    .line 94
    .line 95
    invoke-virtual {v5, v2}, Lla/s;->a([Loa/b;)V

    .line 96
    .line 97
    .line 98
    new-instance v2, Lfb/f;

    .line 99
    .line 100
    const/4 v3, 0x2

    .line 101
    const/4 v8, 0x3

    .line 102
    invoke-direct {v2, v0, v3, v8}, Lfb/f;-><init>(Landroid/content/Context;II)V

    .line 103
    .line 104
    .line 105
    new-array v3, v6, [Loa/b;

    .line 106
    .line 107
    aput-object v2, v3, v7

    .line 108
    .line 109
    invoke-virtual {v5, v3}, Lla/s;->a([Loa/b;)V

    .line 110
    .line 111
    .line 112
    new-array v2, v6, [Loa/b;

    .line 113
    .line 114
    sget-object v3, Lfb/c;->i:Lfb/c;

    .line 115
    .line 116
    aput-object v3, v2, v7

    .line 117
    .line 118
    invoke-virtual {v5, v2}, Lla/s;->a([Loa/b;)V

    .line 119
    .line 120
    .line 121
    new-array v2, v6, [Loa/b;

    .line 122
    .line 123
    sget-object v3, Lfb/c;->j:Lfb/c;

    .line 124
    .line 125
    aput-object v3, v2, v7

    .line 126
    .line 127
    invoke-virtual {v5, v2}, Lla/s;->a([Loa/b;)V

    .line 128
    .line 129
    .line 130
    new-instance v2, Lfb/f;

    .line 131
    .line 132
    const/4 v3, 0x5

    .line 133
    const/4 v8, 0x6

    .line 134
    invoke-direct {v2, v0, v3, v8}, Lfb/f;-><init>(Landroid/content/Context;II)V

    .line 135
    .line 136
    .line 137
    new-array v3, v6, [Loa/b;

    .line 138
    .line 139
    aput-object v2, v3, v7

    .line 140
    .line 141
    invoke-virtual {v5, v3}, Lla/s;->a([Loa/b;)V

    .line 142
    .line 143
    .line 144
    new-array v2, v6, [Loa/b;

    .line 145
    .line 146
    sget-object v3, Lfb/c;->k:Lfb/c;

    .line 147
    .line 148
    aput-object v3, v2, v7

    .line 149
    .line 150
    invoke-virtual {v5, v2}, Lla/s;->a([Loa/b;)V

    .line 151
    .line 152
    .line 153
    new-array v2, v6, [Loa/b;

    .line 154
    .line 155
    sget-object v3, Lfb/c;->l:Lfb/c;

    .line 156
    .line 157
    aput-object v3, v2, v7

    .line 158
    .line 159
    invoke-virtual {v5, v2}, Lla/s;->a([Loa/b;)V

    .line 160
    .line 161
    .line 162
    new-array v2, v6, [Loa/b;

    .line 163
    .line 164
    sget-object v3, Lfb/c;->m:Lfb/c;

    .line 165
    .line 166
    aput-object v3, v2, v7

    .line 167
    .line 168
    invoke-virtual {v5, v2}, Lla/s;->a([Loa/b;)V

    .line 169
    .line 170
    .line 171
    new-instance v2, Lfb/f;

    .line 172
    .line 173
    invoke-direct {v2, v0}, Lfb/f;-><init>(Landroid/content/Context;)V

    .line 174
    .line 175
    .line 176
    new-array v3, v6, [Loa/b;

    .line 177
    .line 178
    aput-object v2, v3, v7

    .line 179
    .line 180
    invoke-virtual {v5, v3}, Lla/s;->a([Loa/b;)V

    .line 181
    .line 182
    .line 183
    new-instance v2, Lfb/f;

    .line 184
    .line 185
    const/16 v3, 0xa

    .line 186
    .line 187
    const/16 v8, 0xb

    .line 188
    .line 189
    invoke-direct {v2, v0, v3, v8}, Lfb/f;-><init>(Landroid/content/Context;II)V

    .line 190
    .line 191
    .line 192
    new-array v3, v6, [Loa/b;

    .line 193
    .line 194
    aput-object v2, v3, v7

    .line 195
    .line 196
    invoke-virtual {v5, v3}, Lla/s;->a([Loa/b;)V

    .line 197
    .line 198
    .line 199
    new-array v2, v6, [Loa/b;

    .line 200
    .line 201
    sget-object v3, Lfb/c;->d:Lfb/c;

    .line 202
    .line 203
    aput-object v3, v2, v7

    .line 204
    .line 205
    invoke-virtual {v5, v2}, Lla/s;->a([Loa/b;)V

    .line 206
    .line 207
    .line 208
    new-array v2, v6, [Loa/b;

    .line 209
    .line 210
    sget-object v3, Lfb/c;->e:Lfb/c;

    .line 211
    .line 212
    aput-object v3, v2, v7

    .line 213
    .line 214
    invoke-virtual {v5, v2}, Lla/s;->a([Loa/b;)V

    .line 215
    .line 216
    .line 217
    new-array v2, v6, [Loa/b;

    .line 218
    .line 219
    sget-object v3, Lfb/c;->f:Lfb/c;

    .line 220
    .line 221
    aput-object v3, v2, v7

    .line 222
    .line 223
    invoke-virtual {v5, v2}, Lla/s;->a([Loa/b;)V

    .line 224
    .line 225
    .line 226
    new-array v2, v6, [Loa/b;

    .line 227
    .line 228
    sget-object v3, Lfb/c;->g:Lfb/c;

    .line 229
    .line 230
    aput-object v3, v2, v7

    .line 231
    .line 232
    invoke-virtual {v5, v2}, Lla/s;->a([Loa/b;)V

    .line 233
    .line 234
    .line 235
    new-instance v2, Lfb/f;

    .line 236
    .line 237
    const/16 v3, 0x15

    .line 238
    .line 239
    const/16 v8, 0x16

    .line 240
    .line 241
    invoke-direct {v2, v0, v3, v8}, Lfb/f;-><init>(Landroid/content/Context;II)V

    .line 242
    .line 243
    .line 244
    new-array v0, v6, [Loa/b;

    .line 245
    .line 246
    aput-object v2, v0, v7

    .line 247
    .line 248
    invoke-virtual {v5, v0}, Lla/s;->a([Loa/b;)V

    .line 249
    .line 250
    .line 251
    iput-boolean v7, v5, Lla/s;->p:Z

    .line 252
    .line 253
    iput-boolean v6, v5, Lla/s;->q:Z

    .line 254
    .line 255
    iput-boolean v6, v5, Lla/s;->r:Z

    .line 256
    .line 257
    invoke-virtual {v5}, Lla/s;->b()Lla/u;

    .line 258
    .line 259
    .line 260
    move-result-object v0

    .line 261
    move-object v5, v0

    .line 262
    check-cast v5, Landroidx/work/impl/WorkDatabase;

    .line 263
    .line 264
    new-instance v6, Lkb/i;

    .line 265
    .line 266
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 267
    .line 268
    .line 269
    move-result-object v0

    .line 270
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 271
    .line 272
    .line 273
    invoke-direct {v6, v0, v4}, Lkb/i;-><init>(Landroid/content/Context;Lob/a;)V

    .line 274
    .line 275
    .line 276
    new-instance v7, Lfb/e;

    .line 277
    .line 278
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 279
    .line 280
    .line 281
    move-result-object v0

    .line 282
    invoke-direct {v7, v0, p1, v4, v5}, Lfb/e;-><init>(Landroid/content/Context;Leb/b;Lob/a;Landroidx/work/impl/WorkDatabase;)V

    .line 283
    .line 284
    .line 285
    sget-object v1, Lfb/v;->d:Lfb/v;

    .line 286
    .line 287
    move-object v2, p0

    .line 288
    move-object v3, p1

    .line 289
    invoke-virtual/range {v1 .. v7}, Lfb/v;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 290
    .line 291
    .line 292
    move-result-object p0

    .line 293
    check-cast p0, Ljava/util/List;

    .line 294
    .line 295
    new-instance v1, Lfb/u;

    .line 296
    .line 297
    invoke-virtual {v2}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 298
    .line 299
    .line 300
    move-result-object v2

    .line 301
    move-object v8, v6

    .line 302
    move-object v6, p0

    .line 303
    invoke-direct/range {v1 .. v8}, Lfb/u;-><init>(Landroid/content/Context;Leb/b;Lob/a;Landroidx/work/impl/WorkDatabase;Ljava/util/List;Lfb/e;Lkb/i;)V

    .line 304
    .line 305
    .line 306
    return-object v1
.end method

.method public static c(Lz2/e;Landroid/util/LongSparseArray;)V
    .locals 6

    .line 1
    invoke-virtual {p1}, Landroid/util/LongSparseArray;->size()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    :goto_0
    if-ge v1, v0, :cond_2

    .line 7
    .line 8
    invoke-virtual {p1, v1}, Landroid/util/LongSparseArray;->keyAt(I)J

    .line 9
    .line 10
    .line 11
    move-result-wide v2

    .line 12
    invoke-virtual {p1, v2, v3}, Landroid/util/LongSparseArray;->get(J)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v4

    .line 16
    invoke-static {v4}, Lz2/c;->c(Ljava/lang/Object;)Landroid/view/translation/ViewTranslationResponse;

    .line 17
    .line 18
    .line 19
    move-result-object v4

    .line 20
    if-eqz v4, :cond_1

    .line 21
    .line 22
    invoke-static {v4}, Lz2/c;->a(Landroid/view/translation/ViewTranslationResponse;)Landroid/view/translation/TranslationResponseValue;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    if-eqz v4, :cond_1

    .line 27
    .line 28
    invoke-static {v4}, Lz2/c;->d(Landroid/view/translation/TranslationResponseValue;)Ljava/lang/CharSequence;

    .line 29
    .line 30
    .line 31
    move-result-object v4

    .line 32
    if-eqz v4, :cond_1

    .line 33
    .line 34
    invoke-virtual {p0}, Lz2/e;->d()Landroidx/collection/p;

    .line 35
    .line 36
    .line 37
    move-result-object v5

    .line 38
    long-to-int v2, v2

    .line 39
    invoke-virtual {v5, v2}, Landroidx/collection/p;->b(I)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    check-cast v2, Ld4/r;

    .line 44
    .line 45
    if-eqz v2, :cond_1

    .line 46
    .line 47
    iget-object v2, v2, Ld4/r;->a:Ld4/q;

    .line 48
    .line 49
    if-eqz v2, :cond_1

    .line 50
    .line 51
    iget-object v2, v2, Ld4/q;->d:Ld4/l;

    .line 52
    .line 53
    sget-object v3, Ld4/k;->k:Ld4/z;

    .line 54
    .line 55
    iget-object v2, v2, Ld4/l;->d:Landroidx/collection/q0;

    .line 56
    .line 57
    invoke-virtual {v2, v3}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v2

    .line 61
    if-nez v2, :cond_0

    .line 62
    .line 63
    const/4 v2, 0x0

    .line 64
    :cond_0
    check-cast v2, Ld4/a;

    .line 65
    .line 66
    if-eqz v2, :cond_1

    .line 67
    .line 68
    iget-object v2, v2, Ld4/a;->b:Llx0/e;

    .line 69
    .line 70
    check-cast v2, Lay0/k;

    .line 71
    .line 72
    if-eqz v2, :cond_1

    .line 73
    .line 74
    new-instance v3, Lg4/g;

    .line 75
    .line 76
    invoke-virtual {v4}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object v4

    .line 80
    invoke-direct {v3, v4}, Lg4/g;-><init>(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    invoke-interface {v2, v3}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v2

    .line 87
    check-cast v2, Ljava/lang/Boolean;

    .line 88
    .line 89
    :cond_1
    add-int/lit8 v1, v1, 0x1

    .line 90
    .line 91
    goto :goto_0

    .line 92
    :cond_2
    return-void
.end method

.method public static final d(Landroid/content/BroadcastReceiver;Lpx0/g;Lay0/n;)V
    .locals 2

    .line 1
    invoke-static {}, Lvy0/e0;->f()Lvy0/z1;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {v0, p1}, Ljp/de;->d(Lpx0/e;Lpx0/g;)Lpx0/g;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-static {p1}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    invoke-virtual {p0}, Landroid/content/BroadcastReceiver;->goAsync()Landroid/content/BroadcastReceiver$PendingResult;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    new-instance v0, La7/k;

    .line 18
    .line 19
    const/4 v1, 0x0

    .line 20
    invoke-direct {v0, p2, p1, p0, v1}, La7/k;-><init>(Lay0/n;Lpw0/a;Landroid/content/BroadcastReceiver$PendingResult;Lkotlin/coroutines/Continuation;)V

    .line 21
    .line 22
    .line 23
    const/4 p0, 0x3

    .line 24
    invoke-static {p1, v1, v1, v0, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 25
    .line 26
    .line 27
    return-void
.end method
