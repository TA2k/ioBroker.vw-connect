.class public final Lsu/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lqu/a;

.field public final b:Ljava/util/Set;

.field public final c:Lcom/google/android/gms/maps/model/LatLng;

.field public final synthetic d:Lsu/i;


# direct methods
.method public constructor <init>(Lsu/i;Lqu/a;Ljava/util/Set;Lcom/google/android/gms/maps/model/LatLng;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lsu/d;->d:Lsu/i;

    .line 5
    .line 6
    iput-object p2, p0, Lsu/d;->a:Lqu/a;

    .line 7
    .line 8
    iput-object p3, p0, Lsu/d;->b:Ljava/util/Set;

    .line 9
    .line 10
    iput-object p4, p0, Lsu/d;->c:Lcom/google/android/gms/maps/model/LatLng;

    .line 11
    .line 12
    return-void
.end method

.method public static a(Lsu/d;Lsu/e;)V
    .locals 12

    .line 1
    iget-object v0, p1, Lsu/e;->l:Lsu/i;

    .line 2
    .line 3
    iget-object v1, p1, Lsu/e;->j:Ljava/util/LinkedList;

    .line 4
    .line 5
    iget-object p1, p1, Lsu/e;->d:Ljava/util/concurrent/locks/ReentrantLock;

    .line 6
    .line 7
    iget-object v2, p0, Lsu/d;->b:Ljava/util/Set;

    .line 8
    .line 9
    iget-object v3, p0, Lsu/d;->c:Lcom/google/android/gms/maps/model/LatLng;

    .line 10
    .line 11
    iget-object v4, p0, Lsu/d;->d:Lsu/i;

    .line 12
    .line 13
    iget-object p0, p0, Lsu/d;->a:Lqu/a;

    .line 14
    .line 15
    invoke-interface {p0}, Lqu/a;->a()I

    .line 16
    .line 17
    .line 18
    move-result v5

    .line 19
    iget v6, v4, Lsu/i;->k:I

    .line 20
    .line 21
    if-lt v5, v6, :cond_0

    .line 22
    .line 23
    const/4 v5, 0x1

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 v5, 0x0

    .line 26
    :goto_0
    iget-object v6, v4, Lsu/i;->m:Lb81/c;

    .line 27
    .line 28
    iget-object v7, v4, Lsu/i;->c:Lqu/c;

    .line 29
    .line 30
    iget-object v8, v4, Lsu/i;->j:Lb81/c;

    .line 31
    .line 32
    if-nez v5, :cond_5

    .line 33
    .line 34
    invoke-interface {p0}, Lqu/a;->b()Ljava/util/Collection;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 43
    .line 44
    .line 45
    move-result v5

    .line 46
    if-eqz v5, :cond_4

    .line 47
    .line 48
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v5

    .line 52
    check-cast v5, Lzj0/c;

    .line 53
    .line 54
    iget-object v6, v8, Lb81/c;->e:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast v6, Ljava/util/HashMap;

    .line 57
    .line 58
    invoke-virtual {v6, v5}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v6

    .line 62
    check-cast v6, Lsp/k;

    .line 63
    .line 64
    if-nez v6, :cond_2

    .line 65
    .line 66
    new-instance v6, Lsp/l;

    .line 67
    .line 68
    invoke-direct {v6}, Lsp/l;-><init>()V

    .line 69
    .line 70
    .line 71
    if-eqz v3, :cond_1

    .line 72
    .line 73
    iput-object v3, v6, Lsp/l;->d:Lcom/google/android/gms/maps/model/LatLng;

    .line 74
    .line 75
    goto :goto_2

    .line 76
    :cond_1
    invoke-virtual {v5}, Lzj0/c;->a()Lcom/google/android/gms/maps/model/LatLng;

    .line 77
    .line 78
    .line 79
    move-result-object v9

    .line 80
    iput-object v9, v6, Lsp/l;->d:Lcom/google/android/gms/maps/model/LatLng;

    .line 81
    .line 82
    iget-object v9, v5, Lzj0/c;->b:Lxj0/r;

    .line 83
    .line 84
    invoke-static {v9}, Lzj0/d;->o(Lxj0/r;)F

    .line 85
    .line 86
    .line 87
    move-result v9

    .line 88
    iput v9, v6, Lsp/l;->q:F

    .line 89
    .line 90
    :goto_2
    invoke-virtual {v4, v5, v6}, Lsu/i;->e(Lzj0/c;Lsp/l;)V

    .line 91
    .line 92
    .line 93
    iget-object v9, v7, Lqu/c;->e:Ltu/a;

    .line 94
    .line 95
    iget-object v10, v9, Ltu/a;->f:Ltu/b;

    .line 96
    .line 97
    iget-object v10, v10, Ltu/b;->d:Lqp/g;

    .line 98
    .line 99
    invoke-virtual {v10, v6}, Lqp/g;->a(Lsp/l;)Lsp/k;

    .line 100
    .line 101
    .line 102
    move-result-object v6

    .line 103
    iget-object v10, v9, Ltu/a;->a:Ljava/util/LinkedHashSet;

    .line 104
    .line 105
    invoke-interface {v10, v6}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    iget-object v10, v9, Ltu/a;->b:Ltu/b;

    .line 109
    .line 110
    iget-object v10, v10, Ltu/b;->e:Ljava/util/HashMap;

    .line 111
    .line 112
    invoke-virtual {v10, v6, v9}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    new-instance v9, Lsu/f;

    .line 116
    .line 117
    invoke-direct {v9, v6}, Lsu/f;-><init>(Lsp/k;)V

    .line 118
    .line 119
    .line 120
    iget-object v10, v8, Lb81/c;->e:Ljava/lang/Object;

    .line 121
    .line 122
    check-cast v10, Ljava/util/HashMap;

    .line 123
    .line 124
    invoke-virtual {v10, v5, v6}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    iget-object v10, v8, Lb81/c;->f:Ljava/lang/Object;

    .line 128
    .line 129
    check-cast v10, Ljava/util/HashMap;

    .line 130
    .line 131
    invoke-virtual {v10, v6, v5}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    if-eqz v3, :cond_3

    .line 135
    .line 136
    invoke-virtual {v5}, Lzj0/c;->a()Lcom/google/android/gms/maps/model/LatLng;

    .line 137
    .line 138
    .line 139
    move-result-object v5

    .line 140
    invoke-virtual {p1}, Ljava/util/concurrent/locks/ReentrantLock;->lock()V

    .line 141
    .line 142
    .line 143
    new-instance v6, Lsu/c;

    .line 144
    .line 145
    invoke-direct {v6, v0, v9, v3, v5}, Lsu/c;-><init>(Lsu/i;Lsu/f;Lcom/google/android/gms/maps/model/LatLng;Lcom/google/android/gms/maps/model/LatLng;)V

    .line 146
    .line 147
    .line 148
    invoke-virtual {v1, v6}, Ljava/util/LinkedList;->add(Ljava/lang/Object;)Z

    .line 149
    .line 150
    .line 151
    invoke-virtual {p1}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    .line 152
    .line 153
    .line 154
    goto :goto_3

    .line 155
    :cond_2
    new-instance v9, Lsu/f;

    .line 156
    .line 157
    invoke-direct {v9, v6}, Lsu/f;-><init>(Lsp/k;)V

    .line 158
    .line 159
    .line 160
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 161
    .line 162
    .line 163
    invoke-virtual {v6}, Lsp/k;->a()Lcom/google/android/gms/maps/model/LatLng;

    .line 164
    .line 165
    .line 166
    move-result-object v10

    .line 167
    invoke-virtual {v5}, Lzj0/c;->a()Lcom/google/android/gms/maps/model/LatLng;

    .line 168
    .line 169
    .line 170
    move-result-object v11

    .line 171
    invoke-virtual {v10, v11}, Lcom/google/android/gms/maps/model/LatLng;->equals(Ljava/lang/Object;)Z

    .line 172
    .line 173
    .line 174
    move-result v10

    .line 175
    if-nez v10, :cond_3

    .line 176
    .line 177
    invoke-virtual {v5}, Lzj0/c;->a()Lcom/google/android/gms/maps/model/LatLng;

    .line 178
    .line 179
    .line 180
    move-result-object v10

    .line 181
    invoke-virtual {v6, v10}, Lsp/k;->e(Lcom/google/android/gms/maps/model/LatLng;)V

    .line 182
    .line 183
    .line 184
    iget-object v5, v5, Lzj0/c;->b:Lxj0/r;

    .line 185
    .line 186
    invoke-static {v5}, Lzj0/d;->o(Lxj0/r;)F

    .line 187
    .line 188
    .line 189
    move-result v5

    .line 190
    invoke-virtual {v6, v5}, Lsp/k;->g(F)V

    .line 191
    .line 192
    .line 193
    invoke-virtual {v6}, Lsp/k;->b()Z

    .line 194
    .line 195
    .line 196
    move-result v5

    .line 197
    if-eqz v5, :cond_3

    .line 198
    .line 199
    invoke-virtual {v6}, Lsp/k;->h()V

    .line 200
    .line 201
    .line 202
    :cond_3
    :goto_3
    invoke-interface {v2, v9}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 203
    .line 204
    .line 205
    goto/16 :goto_1

    .line 206
    .line 207
    :cond_4
    return-void

    .line 208
    :cond_5
    iget-object v5, v6, Lb81/c;->e:Ljava/lang/Object;

    .line 209
    .line 210
    check-cast v5, Ljava/util/HashMap;

    .line 211
    .line 212
    invoke-virtual {v5, p0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object v5

    .line 216
    check-cast v5, Lsp/k;

    .line 217
    .line 218
    if-nez v5, :cond_8

    .line 219
    .line 220
    new-instance v5, Lsp/l;

    .line 221
    .line 222
    invoke-direct {v5}, Lsp/l;-><init>()V

    .line 223
    .line 224
    .line 225
    if-nez v3, :cond_6

    .line 226
    .line 227
    invoke-interface {p0}, Lqu/a;->getPosition()Lcom/google/android/gms/maps/model/LatLng;

    .line 228
    .line 229
    .line 230
    move-result-object v8

    .line 231
    goto :goto_4

    .line 232
    :cond_6
    move-object v8, v3

    .line 233
    :goto_4
    if-eqz v8, :cond_7

    .line 234
    .line 235
    iput-object v8, v5, Lsp/l;->d:Lcom/google/android/gms/maps/model/LatLng;

    .line 236
    .line 237
    invoke-virtual {v4, p0}, Lsu/i;->c(Lqu/a;)Lsp/b;

    .line 238
    .line 239
    .line 240
    move-result-object v4

    .line 241
    iput-object v4, v5, Lsp/l;->g:Lsp/b;

    .line 242
    .line 243
    iget-object v4, v7, Lqu/c;->f:Ltu/a;

    .line 244
    .line 245
    iget-object v7, v4, Ltu/a;->f:Ltu/b;

    .line 246
    .line 247
    iget-object v7, v7, Ltu/b;->d:Lqp/g;

    .line 248
    .line 249
    invoke-virtual {v7, v5}, Lqp/g;->a(Lsp/l;)Lsp/k;

    .line 250
    .line 251
    .line 252
    move-result-object v5

    .line 253
    iget-object v7, v4, Ltu/a;->a:Ljava/util/LinkedHashSet;

    .line 254
    .line 255
    invoke-interface {v7, v5}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 256
    .line 257
    .line 258
    iget-object v7, v4, Ltu/a;->b:Ltu/b;

    .line 259
    .line 260
    iget-object v7, v7, Ltu/b;->e:Ljava/util/HashMap;

    .line 261
    .line 262
    invoke-virtual {v7, v5, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 263
    .line 264
    .line 265
    iget-object v4, v6, Lb81/c;->e:Ljava/lang/Object;

    .line 266
    .line 267
    check-cast v4, Ljava/util/HashMap;

    .line 268
    .line 269
    invoke-virtual {v4, p0, v5}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 270
    .line 271
    .line 272
    iget-object v4, v6, Lb81/c;->f:Ljava/lang/Object;

    .line 273
    .line 274
    check-cast v4, Ljava/util/HashMap;

    .line 275
    .line 276
    invoke-virtual {v4, v5, p0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 277
    .line 278
    .line 279
    new-instance v4, Lsu/f;

    .line 280
    .line 281
    invoke-direct {v4, v5}, Lsu/f;-><init>(Lsp/k;)V

    .line 282
    .line 283
    .line 284
    if-eqz v3, :cond_9

    .line 285
    .line 286
    invoke-interface {p0}, Lqu/a;->getPosition()Lcom/google/android/gms/maps/model/LatLng;

    .line 287
    .line 288
    .line 289
    move-result-object p0

    .line 290
    invoke-virtual {p1}, Ljava/util/concurrent/locks/ReentrantLock;->lock()V

    .line 291
    .line 292
    .line 293
    new-instance v5, Lsu/c;

    .line 294
    .line 295
    invoke-direct {v5, v0, v4, v3, p0}, Lsu/c;-><init>(Lsu/i;Lsu/f;Lcom/google/android/gms/maps/model/LatLng;Lcom/google/android/gms/maps/model/LatLng;)V

    .line 296
    .line 297
    .line 298
    invoke-virtual {v1, v5}, Ljava/util/LinkedList;->add(Ljava/lang/Object;)Z

    .line 299
    .line 300
    .line 301
    invoke-virtual {p1}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    .line 302
    .line 303
    .line 304
    goto :goto_5

    .line 305
    :cond_7
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 306
    .line 307
    const-string p1, "latlng cannot be null - a position is required."

    .line 308
    .line 309
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 310
    .line 311
    .line 312
    throw p0

    .line 313
    :cond_8
    new-instance p1, Lsu/f;

    .line 314
    .line 315
    invoke-direct {p1, v5}, Lsu/f;-><init>(Lsp/k;)V

    .line 316
    .line 317
    .line 318
    invoke-virtual {v4, p0}, Lsu/i;->c(Lqu/a;)Lsp/b;

    .line 319
    .line 320
    .line 321
    move-result-object p0

    .line 322
    invoke-virtual {v5, p0}, Lsp/k;->d(Lsp/b;)V

    .line 323
    .line 324
    .line 325
    move-object v4, p1

    .line 326
    :cond_9
    :goto_5
    invoke-interface {v2, v4}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 327
    .line 328
    .line 329
    return-void
.end method
