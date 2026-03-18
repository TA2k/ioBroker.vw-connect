.class public abstract Llv/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Landroid/util/SparseArray;

.field public static final b:Landroid/util/SparseArray;

.field public static final c:Ljava/util/concurrent/atomic/AtomicReference;

.field public static final d:Ljava/util/HashMap;


# direct methods
.method static constructor <clinit>()V
    .locals 16

    .line 1
    new-instance v0, Landroid/util/SparseArray;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/util/SparseArray;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Llv/a;->a:Landroid/util/SparseArray;

    .line 7
    .line 8
    new-instance v1, Landroid/util/SparseArray;

    .line 9
    .line 10
    invoke-direct {v1}, Landroid/util/SparseArray;-><init>()V

    .line 11
    .line 12
    .line 13
    sput-object v1, Llv/a;->b:Landroid/util/SparseArray;

    .line 14
    .line 15
    new-instance v2, Ljava/util/concurrent/atomic/AtomicReference;

    .line 16
    .line 17
    invoke-direct {v2}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    .line 18
    .line 19
    .line 20
    sput-object v2, Llv/a;->c:Ljava/util/concurrent/atomic/AtomicReference;

    .line 21
    .line 22
    sget-object v2, Ljp/kc;->e:Ljp/kc;

    .line 23
    .line 24
    const/4 v3, -0x1

    .line 25
    invoke-virtual {v0, v3, v2}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    const/4 v2, 0x1

    .line 29
    sget-object v3, Ljp/kc;->f:Ljp/kc;

    .line 30
    .line 31
    invoke-virtual {v0, v2, v3}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    const/4 v3, 0x2

    .line 35
    sget-object v4, Ljp/kc;->g:Ljp/kc;

    .line 36
    .line 37
    invoke-virtual {v0, v3, v4}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    const/4 v4, 0x4

    .line 41
    sget-object v5, Ljp/kc;->h:Ljp/kc;

    .line 42
    .line 43
    invoke-virtual {v0, v4, v5}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    const/16 v5, 0x8

    .line 47
    .line 48
    sget-object v6, Ljp/kc;->i:Ljp/kc;

    .line 49
    .line 50
    invoke-virtual {v0, v5, v6}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    const/16 v6, 0x10

    .line 54
    .line 55
    sget-object v7, Ljp/kc;->j:Ljp/kc;

    .line 56
    .line 57
    invoke-virtual {v0, v6, v7}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    const/16 v7, 0x20

    .line 61
    .line 62
    sget-object v8, Ljp/kc;->k:Ljp/kc;

    .line 63
    .line 64
    invoke-virtual {v0, v7, v8}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    const/16 v8, 0x40

    .line 68
    .line 69
    sget-object v9, Ljp/kc;->l:Ljp/kc;

    .line 70
    .line 71
    invoke-virtual {v0, v8, v9}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    const/16 v9, 0x80

    .line 75
    .line 76
    sget-object v10, Ljp/kc;->m:Ljp/kc;

    .line 77
    .line 78
    invoke-virtual {v0, v9, v10}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    const/16 v10, 0x100

    .line 82
    .line 83
    sget-object v11, Ljp/kc;->n:Ljp/kc;

    .line 84
    .line 85
    invoke-virtual {v0, v10, v11}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    const/16 v11, 0x200

    .line 89
    .line 90
    sget-object v12, Ljp/kc;->o:Ljp/kc;

    .line 91
    .line 92
    invoke-virtual {v0, v11, v12}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    const/16 v12, 0x400

    .line 96
    .line 97
    sget-object v13, Ljp/kc;->p:Ljp/kc;

    .line 98
    .line 99
    invoke-virtual {v0, v12, v13}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    const/16 v13, 0x800

    .line 103
    .line 104
    sget-object v14, Ljp/kc;->q:Ljp/kc;

    .line 105
    .line 106
    invoke-virtual {v0, v13, v14}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    const/16 v14, 0x1000

    .line 110
    .line 111
    sget-object v15, Ljp/kc;->r:Ljp/kc;

    .line 112
    .line 113
    invoke-virtual {v0, v14, v15}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    sget-object v0, Ljp/lc;->e:Ljp/lc;

    .line 117
    .line 118
    const/4 v15, 0x0

    .line 119
    invoke-virtual {v1, v15, v0}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    sget-object v0, Ljp/lc;->f:Ljp/lc;

    .line 123
    .line 124
    invoke-virtual {v1, v2, v0}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 125
    .line 126
    .line 127
    sget-object v0, Ljp/lc;->g:Ljp/lc;

    .line 128
    .line 129
    invoke-virtual {v1, v3, v0}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 130
    .line 131
    .line 132
    sget-object v0, Ljp/lc;->h:Ljp/lc;

    .line 133
    .line 134
    const/4 v15, 0x3

    .line 135
    invoke-virtual {v1, v15, v0}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 136
    .line 137
    .line 138
    sget-object v0, Ljp/lc;->i:Ljp/lc;

    .line 139
    .line 140
    invoke-virtual {v1, v4, v0}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 141
    .line 142
    .line 143
    sget-object v0, Ljp/lc;->j:Ljp/lc;

    .line 144
    .line 145
    const/4 v15, 0x5

    .line 146
    invoke-virtual {v1, v15, v0}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 147
    .line 148
    .line 149
    sget-object v0, Ljp/lc;->k:Ljp/lc;

    .line 150
    .line 151
    const/4 v15, 0x6

    .line 152
    invoke-virtual {v1, v15, v0}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 153
    .line 154
    .line 155
    sget-object v0, Ljp/lc;->l:Ljp/lc;

    .line 156
    .line 157
    const/4 v15, 0x7

    .line 158
    invoke-virtual {v1, v15, v0}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 159
    .line 160
    .line 161
    sget-object v0, Ljp/lc;->m:Ljp/lc;

    .line 162
    .line 163
    invoke-virtual {v1, v5, v0}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 164
    .line 165
    .line 166
    sget-object v0, Ljp/lc;->n:Ljp/lc;

    .line 167
    .line 168
    const/16 v15, 0x9

    .line 169
    .line 170
    invoke-virtual {v1, v15, v0}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 171
    .line 172
    .line 173
    sget-object v0, Ljp/lc;->o:Ljp/lc;

    .line 174
    .line 175
    const/16 v15, 0xa

    .line 176
    .line 177
    invoke-virtual {v1, v15, v0}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 178
    .line 179
    .line 180
    sget-object v0, Ljp/lc;->p:Ljp/lc;

    .line 181
    .line 182
    const/16 v15, 0xb

    .line 183
    .line 184
    invoke-virtual {v1, v15, v0}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 185
    .line 186
    .line 187
    sget-object v0, Ljp/lc;->q:Ljp/lc;

    .line 188
    .line 189
    const/16 v15, 0xc

    .line 190
    .line 191
    invoke-virtual {v1, v15, v0}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 192
    .line 193
    .line 194
    new-instance v0, Ljava/util/HashMap;

    .line 195
    .line 196
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 197
    .line 198
    .line 199
    sput-object v0, Llv/a;->d:Ljava/util/HashMap;

    .line 200
    .line 201
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 202
    .line 203
    .line 204
    move-result-object v1

    .line 205
    sget-object v2, Ljp/og;->e:Ljp/og;

    .line 206
    .line 207
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 208
    .line 209
    .line 210
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 211
    .line 212
    .line 213
    move-result-object v1

    .line 214
    sget-object v2, Ljp/og;->f:Ljp/og;

    .line 215
    .line 216
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 217
    .line 218
    .line 219
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 220
    .line 221
    .line 222
    move-result-object v1

    .line 223
    sget-object v2, Ljp/og;->g:Ljp/og;

    .line 224
    .line 225
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 226
    .line 227
    .line 228
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 229
    .line 230
    .line 231
    move-result-object v1

    .line 232
    sget-object v2, Ljp/og;->h:Ljp/og;

    .line 233
    .line 234
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 235
    .line 236
    .line 237
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 238
    .line 239
    .line 240
    move-result-object v1

    .line 241
    sget-object v2, Ljp/og;->i:Ljp/og;

    .line 242
    .line 243
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 244
    .line 245
    .line 246
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 247
    .line 248
    .line 249
    move-result-object v1

    .line 250
    sget-object v2, Ljp/og;->j:Ljp/og;

    .line 251
    .line 252
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 253
    .line 254
    .line 255
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 256
    .line 257
    .line 258
    move-result-object v1

    .line 259
    sget-object v2, Ljp/og;->k:Ljp/og;

    .line 260
    .line 261
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 262
    .line 263
    .line 264
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 265
    .line 266
    .line 267
    move-result-object v1

    .line 268
    sget-object v2, Ljp/og;->l:Ljp/og;

    .line 269
    .line 270
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 271
    .line 272
    .line 273
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 274
    .line 275
    .line 276
    move-result-object v1

    .line 277
    sget-object v2, Ljp/og;->m:Ljp/og;

    .line 278
    .line 279
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 280
    .line 281
    .line 282
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 283
    .line 284
    .line 285
    move-result-object v1

    .line 286
    sget-object v2, Ljp/og;->n:Ljp/og;

    .line 287
    .line 288
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 289
    .line 290
    .line 291
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 292
    .line 293
    .line 294
    move-result-object v1

    .line 295
    sget-object v2, Ljp/og;->o:Ljp/og;

    .line 296
    .line 297
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 298
    .line 299
    .line 300
    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 301
    .line 302
    .line 303
    move-result-object v1

    .line 304
    sget-object v2, Ljp/og;->p:Ljp/og;

    .line 305
    .line 306
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 307
    .line 308
    .line 309
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 310
    .line 311
    .line 312
    move-result-object v1

    .line 313
    sget-object v2, Ljp/og;->q:Ljp/og;

    .line 314
    .line 315
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 316
    .line 317
    .line 318
    return-void
.end method

.method public static a(Lhv/b;)Ljp/pg;
    .locals 4

    .line 1
    iget p0, p0, Lhv/b;->a:I

    .line 2
    .line 3
    new-instance v0, Lin/o;

    .line 4
    .line 5
    invoke-direct {v0}, Lin/o;-><init>()V

    .line 6
    .line 7
    .line 8
    sget-object v1, Llv/a;->d:Ljava/util/HashMap;

    .line 9
    .line 10
    if-nez p0, :cond_2

    .line 11
    .line 12
    invoke-virtual {v1}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    check-cast p0, Ljava/util/Collection;

    .line 17
    .line 18
    instance-of v1, p0, Ljava/util/Collection;

    .line 19
    .line 20
    if-eqz v1, :cond_1

    .line 21
    .line 22
    move-object v1, p0

    .line 23
    check-cast v1, Ljava/util/Collection;

    .line 24
    .line 25
    iget v2, v0, Lin/o;->a:I

    .line 26
    .line 27
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    add-int/2addr v3, v2

    .line 32
    invoke-virtual {v0, v3}, Lin/o;->r(I)V

    .line 33
    .line 34
    .line 35
    instance-of v2, v1, Ljp/u;

    .line 36
    .line 37
    if-nez v2, :cond_0

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_0
    check-cast v1, Ljp/u;

    .line 41
    .line 42
    iget-object p0, v0, Lin/o;->c:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast p0, [Ljava/lang/Object;

    .line 45
    .line 46
    iget v2, v0, Lin/o;->a:I

    .line 47
    .line 48
    invoke-virtual {v1, v2, p0}, Ljp/u;->c(I[Ljava/lang/Object;)I

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    iput p0, v0, Lin/o;->a:I

    .line 53
    .line 54
    goto :goto_3

    .line 55
    :cond_1
    :goto_0
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    if-eqz v1, :cond_4

    .line 64
    .line 65
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    invoke-virtual {v0, v1}, Lin/o;->q(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_2
    invoke-virtual {v1}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 78
    .line 79
    .line 80
    move-result-object v1

    .line 81
    :cond_3
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 82
    .line 83
    .line 84
    move-result v2

    .line 85
    if-eqz v2, :cond_4

    .line 86
    .line 87
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v2

    .line 91
    check-cast v2, Ljava/util/Map$Entry;

    .line 92
    .line 93
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v3

    .line 97
    check-cast v3, Ljava/lang/Integer;

    .line 98
    .line 99
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 100
    .line 101
    .line 102
    move-result v3

    .line 103
    and-int/2addr v3, p0

    .line 104
    if-eqz v3, :cond_3

    .line 105
    .line 106
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v2

    .line 110
    check-cast v2, Ljp/og;

    .line 111
    .line 112
    invoke-virtual {v0, v2}, Lin/o;->q(Ljava/lang/Object;)V

    .line 113
    .line 114
    .line 115
    goto :goto_2

    .line 116
    :cond_4
    :goto_3
    new-instance p0, Lj1/a;

    .line 117
    .line 118
    const/4 v1, 0x3

    .line 119
    const/4 v2, 0x0

    .line 120
    invoke-direct {p0, v1, v2}, Lj1/a;-><init>(IZ)V

    .line 121
    .line 122
    .line 123
    invoke-virtual {v0}, Lin/o;->s()Ljp/c0;

    .line 124
    .line 125
    .line 126
    move-result-object v0

    .line 127
    iput-object v0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 128
    .line 129
    new-instance v0, Ljp/pg;

    .line 130
    .line 131
    invoke-direct {v0, p0}, Ljp/pg;-><init>(Lj1/a;)V

    .line 132
    .line 133
    .line 134
    return-object v0
.end method

.method public static b(Ljp/vg;Ljp/ac;)V
    .locals 1

    .line 1
    new-instance v0, Ljp/nc;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p1, v0, Ljp/nc;->a:Ljp/ac;

    .line 7
    .line 8
    sget-object p1, Ljp/bc;->q:Ljp/bc;

    .line 9
    .line 10
    invoke-virtual {p0, v0, p1}, Ljp/vg;->b(Ljp/ug;Ljp/bc;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public static c()Z
    .locals 3

    .line 1
    sget-object v0, Llv/a;->c:Ljava/util/concurrent/atomic/AtomicReference;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    check-cast v0, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    return v0

    .line 20
    :cond_0
    invoke-static {}, Lfv/f;->c()Lfv/f;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    invoke-virtual {v1}, Lfv/f;->b()Landroid/content/Context;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    sget-object v2, Llv/g;->h:Ljp/c0;

    .line 29
    .line 30
    const-string v2, "com.google.mlkit.dynamite.barcode"

    .line 31
    .line 32
    invoke-static {v1, v2}, Lzo/d;->a(Landroid/content/Context;Ljava/lang/String;)I

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    if-lez v1, :cond_1

    .line 37
    .line 38
    const/4 v1, 0x1

    .line 39
    goto :goto_0

    .line 40
    :cond_1
    const/4 v1, 0x0

    .line 41
    :goto_0
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    invoke-virtual {v0, v2}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    return v1
.end method
