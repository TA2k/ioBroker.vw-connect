.class public final Lh01/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lg01/c;

.field public final b:Lh01/q;

.field public final c:I

.field public final d:I

.field public final e:I

.field public final f:I

.field public final g:Z

.field public final h:Z

.field public final i:Ld01/a;

.field public final j:Lbu/c;

.field public final k:Lh01/o;

.field public final l:Z

.field public m:Lh01/v;

.field public n:Lb0/n1;

.field public o:Ld01/w0;

.field public final p:Lmx0/l;


# direct methods
.method public constructor <init>(Lg01/c;Lh01/q;IIIIZZLd01/a;Lbu/c;Lh01/o;Ld01/k0;)V
    .locals 1

    .line 1
    const-string v0, "taskRunner"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "connectionPool"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "routeDatabase"

    .line 12
    .line 13
    invoke-static {p10, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lh01/r;->a:Lg01/c;

    .line 20
    .line 21
    iput-object p2, p0, Lh01/r;->b:Lh01/q;

    .line 22
    .line 23
    iput p3, p0, Lh01/r;->c:I

    .line 24
    .line 25
    iput p4, p0, Lh01/r;->d:I

    .line 26
    .line 27
    iput p5, p0, Lh01/r;->e:I

    .line 28
    .line 29
    iput p6, p0, Lh01/r;->f:I

    .line 30
    .line 31
    iput-boolean p7, p0, Lh01/r;->g:Z

    .line 32
    .line 33
    iput-boolean p8, p0, Lh01/r;->h:Z

    .line 34
    .line 35
    iput-object p9, p0, Lh01/r;->i:Ld01/a;

    .line 36
    .line 37
    iput-object p10, p0, Lh01/r;->j:Lbu/c;

    .line 38
    .line 39
    iput-object p11, p0, Lh01/r;->k:Lh01/o;

    .line 40
    .line 41
    iget-object p1, p12, Ld01/k0;->b:Ljava/lang/String;

    .line 42
    .line 43
    const-string p2, "GET"

    .line 44
    .line 45
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result p1

    .line 49
    xor-int/lit8 p1, p1, 0x1

    .line 50
    .line 51
    iput-boolean p1, p0, Lh01/r;->l:Z

    .line 52
    .line 53
    new-instance p1, Lmx0/l;

    .line 54
    .line 55
    invoke-direct {p1}, Lmx0/l;-><init>()V

    .line 56
    .line 57
    .line 58
    iput-object p1, p0, Lh01/r;->p:Lmx0/l;

    .line 59
    .line 60
    return-void
.end method


# virtual methods
.method public final a(Lh01/p;)Z
    .locals 4

    .line 1
    iget-object v0, p0, Lh01/r;->p:Lmx0/l;

    .line 2
    .line 3
    invoke-virtual {v0}, Lmx0/l;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x1

    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    goto :goto_1

    .line 11
    :cond_0
    iget-object v0, p0, Lh01/r;->o:Ld01/w0;

    .line 12
    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    goto :goto_1

    .line 16
    :cond_1
    if-eqz p1, :cond_5

    .line 17
    .line 18
    monitor-enter p1

    .line 19
    :try_start_0
    iget v0, p1, Lh01/p;->l:I

    .line 20
    .line 21
    const/4 v2, 0x0

    .line 22
    if-eqz v0, :cond_2

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_2
    iget-boolean v0, p1, Lh01/p;->j:Z

    .line 26
    .line 27
    if-nez v0, :cond_3

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_3
    iget-object v0, p1, Lh01/p;->c:Ld01/w0;

    .line 31
    .line 32
    iget-object v0, v0, Ld01/w0;->a:Ld01/a;

    .line 33
    .line 34
    iget-object v0, v0, Ld01/a;->h:Ld01/a0;

    .line 35
    .line 36
    iget-object v3, p0, Lh01/r;->i:Ld01/a;

    .line 37
    .line 38
    iget-object v3, v3, Ld01/a;->h:Ld01/a0;

    .line 39
    .line 40
    invoke-static {v0, v3}, Le01/g;->a(Ld01/a0;Ld01/a0;)Z

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    if-nez v0, :cond_4

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_4
    iget-object v2, p1, Lh01/p;->c:Ld01/w0;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 48
    .line 49
    :goto_0
    monitor-exit p1

    .line 50
    if-eqz v2, :cond_5

    .line 51
    .line 52
    iput-object v2, p0, Lh01/r;->o:Ld01/w0;

    .line 53
    .line 54
    return v1

    .line 55
    :catchall_0
    move-exception p0

    .line 56
    monitor-exit p1

    .line 57
    throw p0

    .line 58
    :cond_5
    iget-object p1, p0, Lh01/r;->m:Lh01/v;

    .line 59
    .line 60
    if-eqz p1, :cond_6

    .line 61
    .line 62
    iget v0, p1, Lh01/v;->b:I

    .line 63
    .line 64
    iget-object p1, p1, Lh01/v;->a:Ljava/util/ArrayList;

    .line 65
    .line 66
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 67
    .line 68
    .line 69
    move-result p1

    .line 70
    if-ge v0, p1, :cond_6

    .line 71
    .line 72
    return v1

    .line 73
    :cond_6
    iget-object p0, p0, Lh01/r;->n:Lb0/n1;

    .line 74
    .line 75
    if-nez p0, :cond_7

    .line 76
    .line 77
    :goto_1
    return v1

    .line 78
    :cond_7
    invoke-virtual {p0}, Lb0/n1;->n()Z

    .line 79
    .line 80
    .line 81
    move-result p0

    .line 82
    return p0
.end method

.method public final b()Lh01/u;
    .locals 12

    .line 1
    iget-object v0, p0, Lh01/r;->k:Lh01/o;

    .line 2
    .line 3
    iget-object v0, v0, Lh01/o;->l:Lh01/p;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v2, 0x1

    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    :cond_0
    :goto_0
    move-object v3, v1

    .line 10
    goto :goto_3

    .line 11
    :cond_1
    iget-boolean v3, p0, Lh01/r;->l:Z

    .line 12
    .line 13
    invoke-virtual {v0, v3}, Lh01/p;->g(Z)Z

    .line 14
    .line 15
    .line 16
    move-result v3

    .line 17
    monitor-enter v0

    .line 18
    if-nez v3, :cond_2

    .line 19
    .line 20
    :try_start_0
    iput-boolean v2, v0, Lh01/p;->j:Z

    .line 21
    .line 22
    iget-object v3, p0, Lh01/r;->k:Lh01/o;

    .line 23
    .line 24
    invoke-virtual {v3}, Lh01/o;->i()Ljava/net/Socket;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    goto :goto_2

    .line 29
    :catchall_0
    move-exception p0

    .line 30
    goto/16 :goto_11

    .line 31
    .line 32
    :cond_2
    iget-boolean v3, v0, Lh01/p;->j:Z

    .line 33
    .line 34
    if-nez v3, :cond_4

    .line 35
    .line 36
    iget-object v3, v0, Lh01/p;->c:Ld01/w0;

    .line 37
    .line 38
    iget-object v3, v3, Ld01/w0;->a:Ld01/a;

    .line 39
    .line 40
    iget-object v3, v3, Ld01/a;->h:Ld01/a0;

    .line 41
    .line 42
    invoke-virtual {p0, v3}, Lh01/r;->e(Ld01/a0;)Z

    .line 43
    .line 44
    .line 45
    move-result v3

    .line 46
    if-nez v3, :cond_3

    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_3
    move-object v3, v1

    .line 50
    goto :goto_2

    .line 51
    :cond_4
    :goto_1
    iget-object v3, p0, Lh01/r;->k:Lh01/o;

    .line 52
    .line 53
    invoke-virtual {v3}, Lh01/o;->i()Ljava/net/Socket;

    .line 54
    .line 55
    .line 56
    move-result-object v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 57
    :goto_2
    monitor-exit v0

    .line 58
    iget-object v4, p0, Lh01/r;->k:Lh01/o;

    .line 59
    .line 60
    iget-object v4, v4, Lh01/o;->l:Lh01/p;

    .line 61
    .line 62
    if-eqz v4, :cond_6

    .line 63
    .line 64
    if-nez v3, :cond_5

    .line 65
    .line 66
    new-instance v3, Lh01/s;

    .line 67
    .line 68
    invoke-direct {v3, v0}, Lh01/s;-><init>(Lh01/p;)V

    .line 69
    .line 70
    .line 71
    goto :goto_3

    .line 72
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 73
    .line 74
    const-string v0, "Check failed."

    .line 75
    .line 76
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    throw p0

    .line 80
    :cond_6
    if-eqz v3, :cond_0

    .line 81
    .line 82
    invoke-static {v3}, Le01/g;->c(Ljava/net/Socket;)V

    .line 83
    .line 84
    .line 85
    goto :goto_0

    .line 86
    :goto_3
    if-eqz v3, :cond_7

    .line 87
    .line 88
    return-object v3

    .line 89
    :cond_7
    invoke-virtual {p0, v1, v1}, Lh01/r;->d(Lh01/c;Ljava/util/List;)Lh01/s;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    if-eqz v0, :cond_8

    .line 94
    .line 95
    return-object v0

    .line 96
    :cond_8
    iget-object v0, p0, Lh01/r;->p:Lmx0/l;

    .line 97
    .line 98
    invoke-virtual {v0}, Lmx0/l;->isEmpty()Z

    .line 99
    .line 100
    .line 101
    move-result v0

    .line 102
    if-nez v0, :cond_9

    .line 103
    .line 104
    iget-object p0, p0, Lh01/r;->p:Lmx0/l;

    .line 105
    .line 106
    invoke-virtual {p0}, Lmx0/l;->removeFirst()Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    check-cast p0, Lh01/u;

    .line 111
    .line 112
    return-object p0

    .line 113
    :cond_9
    iget-object v0, p0, Lh01/r;->o:Ld01/w0;

    .line 114
    .line 115
    if-eqz v0, :cond_a

    .line 116
    .line 117
    iput-object v1, p0, Lh01/r;->o:Ld01/w0;

    .line 118
    .line 119
    invoke-virtual {p0, v0, v1}, Lh01/r;->c(Ld01/w0;Ljava/util/ArrayList;)Lh01/c;

    .line 120
    .line 121
    .line 122
    move-result-object v0

    .line 123
    goto/16 :goto_10

    .line 124
    .line 125
    :cond_a
    iget-object v0, p0, Lh01/r;->m:Lh01/v;

    .line 126
    .line 127
    if-eqz v0, :cond_c

    .line 128
    .line 129
    iget v3, v0, Lh01/v;->b:I

    .line 130
    .line 131
    iget-object v4, v0, Lh01/v;->a:Ljava/util/ArrayList;

    .line 132
    .line 133
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 134
    .line 135
    .line 136
    move-result v4

    .line 137
    if-ge v3, v4, :cond_c

    .line 138
    .line 139
    iget v2, v0, Lh01/v;->b:I

    .line 140
    .line 141
    iget-object v3, v0, Lh01/v;->a:Ljava/util/ArrayList;

    .line 142
    .line 143
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 144
    .line 145
    .line 146
    move-result v4

    .line 147
    if-ge v2, v4, :cond_b

    .line 148
    .line 149
    iget v2, v0, Lh01/v;->b:I

    .line 150
    .line 151
    add-int/lit8 v4, v2, 0x1

    .line 152
    .line 153
    iput v4, v0, Lh01/v;->b:I

    .line 154
    .line 155
    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object v0

    .line 159
    check-cast v0, Ld01/w0;

    .line 160
    .line 161
    invoke-virtual {p0, v0, v1}, Lh01/r;->c(Ld01/w0;Ljava/util/ArrayList;)Lh01/c;

    .line 162
    .line 163
    .line 164
    move-result-object v0

    .line 165
    goto/16 :goto_10

    .line 166
    .line 167
    :cond_b
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 168
    .line 169
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 170
    .line 171
    .line 172
    throw p0

    .line 173
    :cond_c
    iget-object v0, p0, Lh01/r;->n:Lb0/n1;

    .line 174
    .line 175
    if-nez v0, :cond_d

    .line 176
    .line 177
    new-instance v0, Lb0/n1;

    .line 178
    .line 179
    iget-object v1, p0, Lh01/r;->i:Ld01/a;

    .line 180
    .line 181
    iget-object v3, p0, Lh01/r;->j:Lbu/c;

    .line 182
    .line 183
    iget-object v4, p0, Lh01/r;->k:Lh01/o;

    .line 184
    .line 185
    iget-boolean v5, p0, Lh01/r;->h:Z

    .line 186
    .line 187
    invoke-direct {v0, v1, v3, v4, v5}, Lb0/n1;-><init>(Ld01/a;Lbu/c;Lh01/o;Z)V

    .line 188
    .line 189
    .line 190
    iput-object v0, p0, Lh01/r;->n:Lb0/n1;

    .line 191
    .line 192
    :cond_d
    invoke-virtual {v0}, Lb0/n1;->n()Z

    .line 193
    .line 194
    .line 195
    move-result v1

    .line 196
    if-eqz v1, :cond_2a

    .line 197
    .line 198
    invoke-virtual {v0}, Lb0/n1;->n()Z

    .line 199
    .line 200
    .line 201
    move-result v1

    .line 202
    if-eqz v1, :cond_29

    .line 203
    .line 204
    new-instance v1, Ljava/util/ArrayList;

    .line 205
    .line 206
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 207
    .line 208
    .line 209
    :cond_e
    iget v3, v0, Lb0/n1;->d:I

    .line 210
    .line 211
    iget-object v4, v0, Lb0/n1;->i:Ljava/lang/Object;

    .line 212
    .line 213
    check-cast v4, Ljava/util/List;

    .line 214
    .line 215
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 216
    .line 217
    .line 218
    move-result v4

    .line 219
    if-ge v3, v4, :cond_24

    .line 220
    .line 221
    iget-object v3, v0, Lb0/n1;->g:Ljava/lang/Object;

    .line 222
    .line 223
    check-cast v3, Ld01/a;

    .line 224
    .line 225
    const-string v4, "No route to "

    .line 226
    .line 227
    iget v5, v0, Lb0/n1;->d:I

    .line 228
    .line 229
    iget-object v6, v0, Lb0/n1;->i:Ljava/lang/Object;

    .line 230
    .line 231
    check-cast v6, Ljava/util/List;

    .line 232
    .line 233
    invoke-interface {v6}, Ljava/util/List;->size()I

    .line 234
    .line 235
    .line 236
    move-result v6

    .line 237
    if-ge v5, v6, :cond_23

    .line 238
    .line 239
    iget-object v5, v0, Lb0/n1;->i:Ljava/lang/Object;

    .line 240
    .line 241
    check-cast v5, Ljava/util/List;

    .line 242
    .line 243
    iget v6, v0, Lb0/n1;->d:I

    .line 244
    .line 245
    add-int/lit8 v7, v6, 0x1

    .line 246
    .line 247
    iput v7, v0, Lb0/n1;->d:I

    .line 248
    .line 249
    invoke-interface {v5, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 250
    .line 251
    .line 252
    move-result-object v5

    .line 253
    check-cast v5, Ljava/net/Proxy;

    .line 254
    .line 255
    new-instance v6, Ljava/util/ArrayList;

    .line 256
    .line 257
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 258
    .line 259
    .line 260
    iput-object v6, v0, Lb0/n1;->f:Ljava/lang/Object;

    .line 261
    .line 262
    invoke-virtual {v5}, Ljava/net/Proxy;->type()Ljava/net/Proxy$Type;

    .line 263
    .line 264
    .line 265
    move-result-object v7

    .line 266
    sget-object v8, Ljava/net/Proxy$Type;->DIRECT:Ljava/net/Proxy$Type;

    .line 267
    .line 268
    if-eq v7, v8, :cond_12

    .line 269
    .line 270
    invoke-virtual {v5}, Ljava/net/Proxy;->type()Ljava/net/Proxy$Type;

    .line 271
    .line 272
    .line 273
    move-result-object v7

    .line 274
    sget-object v8, Ljava/net/Proxy$Type;->SOCKS:Ljava/net/Proxy$Type;

    .line 275
    .line 276
    if-ne v7, v8, :cond_f

    .line 277
    .line 278
    goto :goto_5

    .line 279
    :cond_f
    invoke-virtual {v5}, Ljava/net/Proxy;->address()Ljava/net/SocketAddress;

    .line 280
    .line 281
    .line 282
    move-result-object v7

    .line 283
    instance-of v8, v7, Ljava/net/InetSocketAddress;

    .line 284
    .line 285
    if-eqz v8, :cond_11

    .line 286
    .line 287
    check-cast v7, Ljava/net/InetSocketAddress;

    .line 288
    .line 289
    invoke-virtual {v7}, Ljava/net/InetSocketAddress;->getAddress()Ljava/net/InetAddress;

    .line 290
    .line 291
    .line 292
    move-result-object v8

    .line 293
    if-nez v8, :cond_10

    .line 294
    .line 295
    invoke-virtual {v7}, Ljava/net/InetSocketAddress;->getHostName()Ljava/lang/String;

    .line 296
    .line 297
    .line 298
    move-result-object v8

    .line 299
    const-string v9, "getHostName(...)"

    .line 300
    .line 301
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 302
    .line 303
    .line 304
    goto :goto_4

    .line 305
    :cond_10
    invoke-virtual {v8}, Ljava/net/InetAddress;->getHostAddress()Ljava/lang/String;

    .line 306
    .line 307
    .line 308
    move-result-object v8

    .line 309
    const-string v9, "getHostAddress(...)"

    .line 310
    .line 311
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 312
    .line 313
    .line 314
    :goto_4
    invoke-virtual {v7}, Ljava/net/InetSocketAddress;->getPort()I

    .line 315
    .line 316
    .line 317
    move-result v7

    .line 318
    goto :goto_6

    .line 319
    :cond_11
    new-instance p0, Ljava/lang/StringBuilder;

    .line 320
    .line 321
    const-string v0, "Proxy.address() is not an InetSocketAddress: "

    .line 322
    .line 323
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 324
    .line 325
    .line 326
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 327
    .line 328
    .line 329
    move-result-object v0

    .line 330
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 331
    .line 332
    .line 333
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 334
    .line 335
    .line 336
    move-result-object p0

    .line 337
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 338
    .line 339
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 340
    .line 341
    .line 342
    move-result-object p0

    .line 343
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 344
    .line 345
    .line 346
    throw v0

    .line 347
    :cond_12
    :goto_5
    iget-object v7, v3, Ld01/a;->h:Ld01/a0;

    .line 348
    .line 349
    iget-object v8, v7, Ld01/a0;->d:Ljava/lang/String;

    .line 350
    .line 351
    iget v7, v7, Ld01/a0;->e:I

    .line 352
    .line 353
    :goto_6
    if-gt v2, v7, :cond_22

    .line 354
    .line 355
    const/high16 v9, 0x10000

    .line 356
    .line 357
    if-ge v7, v9, :cond_22

    .line 358
    .line 359
    invoke-virtual {v5}, Ljava/net/Proxy;->type()Ljava/net/Proxy$Type;

    .line 360
    .line 361
    .line 362
    move-result-object v4

    .line 363
    sget-object v9, Ljava/net/Proxy$Type;->SOCKS:Ljava/net/Proxy$Type;

    .line 364
    .line 365
    if-ne v4, v9, :cond_13

    .line 366
    .line 367
    invoke-static {v8, v7}, Ljava/net/InetSocketAddress;->createUnresolved(Ljava/lang/String;I)Ljava/net/InetSocketAddress;

    .line 368
    .line 369
    .line 370
    move-result-object v3

    .line 371
    invoke-virtual {v6, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 372
    .line 373
    .line 374
    goto/16 :goto_d

    .line 375
    .line 376
    :cond_13
    sget-object v4, Le01/d;->a:Lly0/n;

    .line 377
    .line 378
    const-string v4, "<this>"

    .line 379
    .line 380
    invoke-static {v8, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 381
    .line 382
    .line 383
    sget-object v4, Le01/d;->a:Lly0/n;

    .line 384
    .line 385
    invoke-virtual {v4, v8}, Lly0/n;->d(Ljava/lang/CharSequence;)Z

    .line 386
    .line 387
    .line 388
    move-result v4

    .line 389
    if-eqz v4, :cond_14

    .line 390
    .line 391
    invoke-static {v8}, Ljava/net/InetAddress;->getByName(Ljava/lang/String;)Ljava/net/InetAddress;

    .line 392
    .line 393
    .line 394
    move-result-object v3

    .line 395
    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 396
    .line 397
    .line 398
    move-result-object v3

    .line 399
    goto :goto_7

    .line 400
    :cond_14
    iget-object v4, v3, Ld01/a;->a:Ld01/r;

    .line 401
    .line 402
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 403
    .line 404
    .line 405
    :try_start_1
    invoke-static {v8}, Ljava/net/InetAddress;->getAllByName(Ljava/lang/String;)[Ljava/net/InetAddress;

    .line 406
    .line 407
    .line 408
    move-result-object v4

    .line 409
    const-string v9, "getAllByName(...)"

    .line 410
    .line 411
    invoke-static {v4, v9}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 412
    .line 413
    .line 414
    invoke-static {v4}, Lmx0/n;->b0([Ljava/lang/Object;)Ljava/util/List;

    .line 415
    .line 416
    .line 417
    move-result-object v4
    :try_end_1
    .catch Ljava/lang/NullPointerException; {:try_start_1 .. :try_end_1} :catch_0

    .line 418
    invoke-interface {v4}, Ljava/util/List;->isEmpty()Z

    .line 419
    .line 420
    .line 421
    move-result v9

    .line 422
    if-nez v9, :cond_21

    .line 423
    .line 424
    move-object v3, v4

    .line 425
    :goto_7
    iget-boolean v4, v0, Lb0/n1;->e:Z

    .line 426
    .line 427
    if-eqz v4, :cond_1d

    .line 428
    .line 429
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 430
    .line 431
    .line 432
    move-result v4

    .line 433
    const/4 v8, 0x2

    .line 434
    if-ge v4, v8, :cond_15

    .line 435
    .line 436
    goto/16 :goto_b

    .line 437
    .line 438
    :cond_15
    move-object v4, v3

    .line 439
    check-cast v4, Ljava/lang/Iterable;

    .line 440
    .line 441
    new-instance v8, Ljava/util/ArrayList;

    .line 442
    .line 443
    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    .line 444
    .line 445
    .line 446
    new-instance v9, Ljava/util/ArrayList;

    .line 447
    .line 448
    invoke-direct {v9}, Ljava/util/ArrayList;-><init>()V

    .line 449
    .line 450
    .line 451
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 452
    .line 453
    .line 454
    move-result-object v4

    .line 455
    :goto_8
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 456
    .line 457
    .line 458
    move-result v10

    .line 459
    if-eqz v10, :cond_17

    .line 460
    .line 461
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 462
    .line 463
    .line 464
    move-result-object v10

    .line 465
    move-object v11, v10

    .line 466
    check-cast v11, Ljava/net/InetAddress;

    .line 467
    .line 468
    instance-of v11, v11, Ljava/net/Inet6Address;

    .line 469
    .line 470
    if-eqz v11, :cond_16

    .line 471
    .line 472
    invoke-virtual {v8, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 473
    .line 474
    .line 475
    goto :goto_8

    .line 476
    :cond_16
    invoke-virtual {v9, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 477
    .line 478
    .line 479
    goto :goto_8

    .line 480
    :cond_17
    invoke-virtual {v8}, Ljava/util/ArrayList;->isEmpty()Z

    .line 481
    .line 482
    .line 483
    move-result v4

    .line 484
    if-nez v4, :cond_1d

    .line 485
    .line 486
    invoke-virtual {v9}, Ljava/util/ArrayList;->isEmpty()Z

    .line 487
    .line 488
    .line 489
    move-result v4

    .line 490
    if-eqz v4, :cond_18

    .line 491
    .line 492
    goto :goto_b

    .line 493
    :cond_18
    sget-object v3, Le01/e;->a:[B

    .line 494
    .line 495
    invoke-virtual {v8}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 496
    .line 497
    .line 498
    move-result-object v4

    .line 499
    invoke-virtual {v9}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 500
    .line 501
    .line 502
    move-result-object v8

    .line 503
    invoke-static {}, Ljp/k1;->f()Lnx0/c;

    .line 504
    .line 505
    .line 506
    move-result-object v9

    .line 507
    :cond_19
    :goto_9
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 508
    .line 509
    .line 510
    move-result v3

    .line 511
    if-nez v3, :cond_1b

    .line 512
    .line 513
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 514
    .line 515
    .line 516
    move-result v3

    .line 517
    if-eqz v3, :cond_1a

    .line 518
    .line 519
    goto :goto_a

    .line 520
    :cond_1a
    invoke-static {v9}, Ljp/k1;->d(Ljava/util/List;)Lnx0/c;

    .line 521
    .line 522
    .line 523
    move-result-object v3

    .line 524
    goto :goto_b

    .line 525
    :cond_1b
    :goto_a
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 526
    .line 527
    .line 528
    move-result v3

    .line 529
    if-eqz v3, :cond_1c

    .line 530
    .line 531
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 532
    .line 533
    .line 534
    move-result-object v3

    .line 535
    invoke-virtual {v9, v3}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 536
    .line 537
    .line 538
    :cond_1c
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 539
    .line 540
    .line 541
    move-result v3

    .line 542
    if-eqz v3, :cond_19

    .line 543
    .line 544
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 545
    .line 546
    .line 547
    move-result-object v3

    .line 548
    invoke-virtual {v9, v3}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 549
    .line 550
    .line 551
    goto :goto_9

    .line 552
    :cond_1d
    :goto_b
    invoke-interface {v3}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 553
    .line 554
    .line 555
    move-result-object v3

    .line 556
    :goto_c
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 557
    .line 558
    .line 559
    move-result v4

    .line 560
    if-eqz v4, :cond_1e

    .line 561
    .line 562
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 563
    .line 564
    .line 565
    move-result-object v4

    .line 566
    check-cast v4, Ljava/net/InetAddress;

    .line 567
    .line 568
    new-instance v8, Ljava/net/InetSocketAddress;

    .line 569
    .line 570
    invoke-direct {v8, v4, v7}, Ljava/net/InetSocketAddress;-><init>(Ljava/net/InetAddress;I)V

    .line 571
    .line 572
    .line 573
    invoke-virtual {v6, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 574
    .line 575
    .line 576
    goto :goto_c

    .line 577
    :cond_1e
    :goto_d
    iget-object v3, v0, Lb0/n1;->f:Ljava/lang/Object;

    .line 578
    .line 579
    invoke-interface {v3}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 580
    .line 581
    .line 582
    move-result-object v3

    .line 583
    :goto_e
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 584
    .line 585
    .line 586
    move-result v4

    .line 587
    if-eqz v4, :cond_20

    .line 588
    .line 589
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 590
    .line 591
    .line 592
    move-result-object v4

    .line 593
    check-cast v4, Ljava/net/InetSocketAddress;

    .line 594
    .line 595
    new-instance v6, Ld01/w0;

    .line 596
    .line 597
    iget-object v7, v0, Lb0/n1;->g:Ljava/lang/Object;

    .line 598
    .line 599
    check-cast v7, Ld01/a;

    .line 600
    .line 601
    invoke-direct {v6, v7, v5, v4}, Ld01/w0;-><init>(Ld01/a;Ljava/net/Proxy;Ljava/net/InetSocketAddress;)V

    .line 602
    .line 603
    .line 604
    iget-object v4, v0, Lb0/n1;->h:Ljava/lang/Object;

    .line 605
    .line 606
    check-cast v4, Lbu/c;

    .line 607
    .line 608
    monitor-enter v4

    .line 609
    :try_start_2
    iget-object v7, v4, Lbu/c;->e:Ljava/lang/Object;

    .line 610
    .line 611
    check-cast v7, Ljava/util/LinkedHashSet;

    .line 612
    .line 613
    invoke-interface {v7, v6}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 614
    .line 615
    .line 616
    move-result v7
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 617
    monitor-exit v4

    .line 618
    if-eqz v7, :cond_1f

    .line 619
    .line 620
    iget-object v4, v0, Lb0/n1;->j:Ljava/lang/Object;

    .line 621
    .line 622
    check-cast v4, Ljava/util/ArrayList;

    .line 623
    .line 624
    invoke-virtual {v4, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 625
    .line 626
    .line 627
    goto :goto_e

    .line 628
    :cond_1f
    invoke-virtual {v1, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 629
    .line 630
    .line 631
    goto :goto_e

    .line 632
    :catchall_1
    move-exception p0

    .line 633
    :try_start_3
    monitor-exit v4
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 634
    throw p0

    .line 635
    :cond_20
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 636
    .line 637
    .line 638
    move-result v3

    .line 639
    if-nez v3, :cond_e

    .line 640
    .line 641
    goto :goto_f

    .line 642
    :cond_21
    new-instance p0, Ljava/net/UnknownHostException;

    .line 643
    .line 644
    new-instance v0, Ljava/lang/StringBuilder;

    .line 645
    .line 646
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 647
    .line 648
    .line 649
    iget-object v1, v3, Ld01/a;->a:Ld01/r;

    .line 650
    .line 651
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 652
    .line 653
    .line 654
    const-string v1, " returned no addresses for "

    .line 655
    .line 656
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 657
    .line 658
    .line 659
    invoke-virtual {v0, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 660
    .line 661
    .line 662
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 663
    .line 664
    .line 665
    move-result-object v0

    .line 666
    invoke-direct {p0, v0}, Ljava/net/UnknownHostException;-><init>(Ljava/lang/String;)V

    .line 667
    .line 668
    .line 669
    throw p0

    .line 670
    :catch_0
    move-exception p0

    .line 671
    new-instance v0, Ljava/net/UnknownHostException;

    .line 672
    .line 673
    const-string v1, "Broken system behaviour for dns lookup of "

    .line 674
    .line 675
    invoke-virtual {v1, v8}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 676
    .line 677
    .line 678
    move-result-object v1

    .line 679
    invoke-direct {v0, v1}, Ljava/net/UnknownHostException;-><init>(Ljava/lang/String;)V

    .line 680
    .line 681
    .line 682
    invoke-virtual {v0, p0}, Ljava/lang/Throwable;->initCause(Ljava/lang/Throwable;)Ljava/lang/Throwable;

    .line 683
    .line 684
    .line 685
    throw v0

    .line 686
    :cond_22
    new-instance p0, Ljava/net/SocketException;

    .line 687
    .line 688
    new-instance v0, Ljava/lang/StringBuilder;

    .line 689
    .line 690
    invoke-direct {v0, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 691
    .line 692
    .line 693
    invoke-virtual {v0, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 694
    .line 695
    .line 696
    const/16 v1, 0x3a

    .line 697
    .line 698
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 699
    .line 700
    .line 701
    invoke-virtual {v0, v7}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 702
    .line 703
    .line 704
    const-string v1, "; port is out of range"

    .line 705
    .line 706
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 707
    .line 708
    .line 709
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 710
    .line 711
    .line 712
    move-result-object v0

    .line 713
    invoke-direct {p0, v0}, Ljava/net/SocketException;-><init>(Ljava/lang/String;)V

    .line 714
    .line 715
    .line 716
    throw p0

    .line 717
    :cond_23
    new-instance p0, Ljava/net/SocketException;

    .line 718
    .line 719
    new-instance v1, Ljava/lang/StringBuilder;

    .line 720
    .line 721
    invoke-direct {v1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 722
    .line 723
    .line 724
    iget-object v2, v3, Ld01/a;->h:Ld01/a0;

    .line 725
    .line 726
    iget-object v2, v2, Ld01/a0;->d:Ljava/lang/String;

    .line 727
    .line 728
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 729
    .line 730
    .line 731
    const-string v2, "; exhausted proxy configurations: "

    .line 732
    .line 733
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 734
    .line 735
    .line 736
    iget-object v0, v0, Lb0/n1;->i:Ljava/lang/Object;

    .line 737
    .line 738
    check-cast v0, Ljava/util/List;

    .line 739
    .line 740
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 741
    .line 742
    .line 743
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 744
    .line 745
    .line 746
    move-result-object v0

    .line 747
    invoke-direct {p0, v0}, Ljava/net/SocketException;-><init>(Ljava/lang/String;)V

    .line 748
    .line 749
    .line 750
    throw p0

    .line 751
    :cond_24
    :goto_f
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 752
    .line 753
    .line 754
    move-result v2

    .line 755
    if-eqz v2, :cond_25

    .line 756
    .line 757
    iget-object v2, v0, Lb0/n1;->j:Ljava/lang/Object;

    .line 758
    .line 759
    check-cast v2, Ljava/util/ArrayList;

    .line 760
    .line 761
    invoke-static {v2, v1}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 762
    .line 763
    .line 764
    iget-object v0, v0, Lb0/n1;->j:Ljava/lang/Object;

    .line 765
    .line 766
    check-cast v0, Ljava/util/ArrayList;

    .line 767
    .line 768
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 769
    .line 770
    .line 771
    :cond_25
    new-instance v0, Lh01/v;

    .line 772
    .line 773
    invoke-direct {v0, v1}, Lh01/v;-><init>(Ljava/util/ArrayList;)V

    .line 774
    .line 775
    .line 776
    iput-object v0, p0, Lh01/r;->m:Lh01/v;

    .line 777
    .line 778
    iget-object v2, p0, Lh01/r;->k:Lh01/o;

    .line 779
    .line 780
    iget-boolean v2, v2, Lh01/o;->t:Z

    .line 781
    .line 782
    if-nez v2, :cond_28

    .line 783
    .line 784
    iget v2, v0, Lh01/v;->b:I

    .line 785
    .line 786
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 787
    .line 788
    .line 789
    move-result v3

    .line 790
    if-ge v2, v3, :cond_27

    .line 791
    .line 792
    iget v2, v0, Lh01/v;->b:I

    .line 793
    .line 794
    add-int/lit8 v3, v2, 0x1

    .line 795
    .line 796
    iput v3, v0, Lh01/v;->b:I

    .line 797
    .line 798
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 799
    .line 800
    .line 801
    move-result-object v0

    .line 802
    check-cast v0, Ld01/w0;

    .line 803
    .line 804
    invoke-virtual {p0, v0, v1}, Lh01/r;->c(Ld01/w0;Ljava/util/ArrayList;)Lh01/c;

    .line 805
    .line 806
    .line 807
    move-result-object v0

    .line 808
    :goto_10
    iget-object v1, v0, Lh01/c;->k:Ljava/util/List;

    .line 809
    .line 810
    invoke-virtual {p0, v0, v1}, Lh01/r;->d(Lh01/c;Ljava/util/List;)Lh01/s;

    .line 811
    .line 812
    .line 813
    move-result-object p0

    .line 814
    if-eqz p0, :cond_26

    .line 815
    .line 816
    return-object p0

    .line 817
    :cond_26
    return-object v0

    .line 818
    :cond_27
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 819
    .line 820
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 821
    .line 822
    .line 823
    throw p0

    .line 824
    :cond_28
    new-instance p0, Ljava/io/IOException;

    .line 825
    .line 826
    const-string v0, "Canceled"

    .line 827
    .line 828
    invoke-direct {p0, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 829
    .line 830
    .line 831
    throw p0

    .line 832
    :cond_29
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 833
    .line 834
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 835
    .line 836
    .line 837
    throw p0

    .line 838
    :cond_2a
    new-instance p0, Ljava/io/IOException;

    .line 839
    .line 840
    const-string v0, "exhausted all routes"

    .line 841
    .line 842
    invoke-direct {p0, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 843
    .line 844
    .line 845
    throw p0

    .line 846
    :goto_11
    monitor-exit v0

    .line 847
    throw p0
.end method

.method public final c(Ld01/w0;Ljava/util/ArrayList;)Lh01/c;
    .locals 29

    .line 1
    move-object/from16 v9, p0

    .line 2
    .line 3
    move-object/from16 v10, p1

    .line 4
    .line 5
    const-string v0, "route"

    .line 6
    .line 7
    invoke-static {v10, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object v0, v10, Ld01/w0;->a:Ld01/a;

    .line 11
    .line 12
    iget-object v1, v0, Ld01/a;->c:Ljavax/net/ssl/SSLSocketFactory;

    .line 13
    .line 14
    if-nez v1, :cond_2

    .line 15
    .line 16
    iget-object v0, v0, Ld01/a;->j:Ljava/util/List;

    .line 17
    .line 18
    sget-object v1, Ld01/p;->h:Ld01/p;

    .line 19
    .line 20
    invoke-interface {v0, v1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-eqz v0, :cond_1

    .line 25
    .line 26
    iget-object v0, v10, Ld01/w0;->a:Ld01/a;

    .line 27
    .line 28
    iget-object v0, v0, Ld01/a;->h:Ld01/a0;

    .line 29
    .line 30
    iget-object v0, v0, Ld01/a0;->d:Ljava/lang/String;

    .line 31
    .line 32
    sget-object v1, Ln01/d;->a:Ln01/b;

    .line 33
    .line 34
    sget-object v1, Ln01/d;->a:Ln01/b;

    .line 35
    .line 36
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    const-string v1, "hostname"

    .line 40
    .line 41
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    invoke-static {}, Landroid/security/NetworkSecurityPolicy;->getInstance()Landroid/security/NetworkSecurityPolicy;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    invoke-virtual {v1, v0}, Landroid/security/NetworkSecurityPolicy;->isCleartextTrafficPermitted(Ljava/lang/String;)Z

    .line 49
    .line 50
    .line 51
    move-result v1

    .line 52
    if-eqz v1, :cond_0

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_0
    new-instance v1, Ljava/net/UnknownServiceException;

    .line 56
    .line 57
    const-string v2, "CLEARTEXT communication to "

    .line 58
    .line 59
    const-string v3, " not permitted by network security policy"

    .line 60
    .line 61
    invoke-static {v2, v0, v3}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    invoke-direct {v1, v0}, Ljava/net/UnknownServiceException;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw v1

    .line 69
    :cond_1
    new-instance v0, Ljava/net/UnknownServiceException;

    .line 70
    .line 71
    const-string v1, "CLEARTEXT communication not enabled for client"

    .line 72
    .line 73
    invoke-direct {v0, v1}, Ljava/net/UnknownServiceException;-><init>(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    throw v0

    .line 77
    :cond_2
    iget-object v0, v0, Ld01/a;->i:Ljava/util/List;

    .line 78
    .line 79
    sget-object v1, Ld01/i0;->j:Ld01/i0;

    .line 80
    .line 81
    invoke-interface {v0, v1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 82
    .line 83
    .line 84
    move-result v0

    .line 85
    if-nez v0, :cond_7

    .line 86
    .line 87
    :goto_0
    iget-object v0, v10, Ld01/w0;->b:Ljava/net/Proxy;

    .line 88
    .line 89
    invoke-virtual {v0}, Ljava/net/Proxy;->type()Ljava/net/Proxy$Type;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    sget-object v1, Ljava/net/Proxy$Type;->HTTP:Ljava/net/Proxy$Type;

    .line 94
    .line 95
    const/4 v2, 0x0

    .line 96
    if-eq v0, v1, :cond_3

    .line 97
    .line 98
    goto :goto_1

    .line 99
    :cond_3
    iget-object v0, v10, Ld01/w0;->a:Ld01/a;

    .line 100
    .line 101
    iget-object v1, v0, Ld01/a;->c:Ljavax/net/ssl/SSLSocketFactory;

    .line 102
    .line 103
    if-nez v1, :cond_5

    .line 104
    .line 105
    iget-object v0, v0, Ld01/a;->i:Ljava/util/List;

    .line 106
    .line 107
    sget-object v1, Ld01/i0;->j:Ld01/i0;

    .line 108
    .line 109
    invoke-interface {v0, v1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 110
    .line 111
    .line 112
    move-result v0

    .line 113
    if-eqz v0, :cond_4

    .line 114
    .line 115
    goto :goto_2

    .line 116
    :cond_4
    :goto_1
    move-object v13, v2

    .line 117
    goto/16 :goto_3

    .line 118
    .line 119
    :cond_5
    :goto_2
    new-instance v0, Ld01/j0;

    .line 120
    .line 121
    invoke-direct {v0}, Ld01/j0;-><init>()V

    .line 122
    .line 123
    .line 124
    iget-object v1, v10, Ld01/w0;->a:Ld01/a;

    .line 125
    .line 126
    iget-object v1, v1, Ld01/a;->h:Ld01/a0;

    .line 127
    .line 128
    const-string v3, "url"

    .line 129
    .line 130
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 131
    .line 132
    .line 133
    iput-object v1, v0, Ld01/j0;->a:Ld01/a0;

    .line 134
    .line 135
    const-string v1, "CONNECT"

    .line 136
    .line 137
    invoke-virtual {v0, v1, v2}, Ld01/j0;->e(Ljava/lang/String;Ld01/r0;)V

    .line 138
    .line 139
    .line 140
    iget-object v1, v10, Ld01/w0;->a:Ld01/a;

    .line 141
    .line 142
    iget-object v2, v1, Ld01/a;->h:Ld01/a0;

    .line 143
    .line 144
    const/4 v3, 0x1

    .line 145
    invoke-static {v2, v3}, Le01/g;->i(Ld01/a0;Z)Ljava/lang/String;

    .line 146
    .line 147
    .line 148
    move-result-object v2

    .line 149
    const-string v3, "Host"

    .line 150
    .line 151
    invoke-virtual {v0, v3, v2}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 152
    .line 153
    .line 154
    const-string v2, "Proxy-Connection"

    .line 155
    .line 156
    const-string v3, "Keep-Alive"

    .line 157
    .line 158
    invoke-virtual {v0, v2, v3}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 159
    .line 160
    .line 161
    const-string v2, "User-Agent"

    .line 162
    .line 163
    const-string v3, "okhttp/5.3.0"

    .line 164
    .line 165
    invoke-virtual {v0, v2, v3}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 166
    .line 167
    .line 168
    new-instance v12, Ld01/k0;

    .line 169
    .line 170
    invoke-direct {v12, v0}, Ld01/k0;-><init>(Ld01/j0;)V

    .line 171
    .line 172
    .line 173
    sget-object v18, Ld01/v0;->d:Ld01/u0;

    .line 174
    .line 175
    sget-object v28, Ld01/y0;->v0:Ld01/r;

    .line 176
    .line 177
    new-instance v0, Ld01/x;

    .line 178
    .line 179
    const/4 v2, 0x0

    .line 180
    invoke-direct {v0, v2, v2}, Ld01/x;-><init>(BI)V

    .line 181
    .line 182
    .line 183
    sget-object v13, Ld01/i0;->g:Ld01/i0;

    .line 184
    .line 185
    const-string v2, "Proxy-Authenticate"

    .line 186
    .line 187
    invoke-static {v2}, Ljp/yg;->j(Ljava/lang/String;)V

    .line 188
    .line 189
    .line 190
    const-string v3, "OkHttp-Preemptive"

    .line 191
    .line 192
    invoke-static {v3, v2}, Ljp/yg;->k(Ljava/lang/String;Ljava/lang/String;)V

    .line 193
    .line 194
    .line 195
    invoke-virtual {v0, v2}, Ld01/x;->o(Ljava/lang/String;)V

    .line 196
    .line 197
    .line 198
    invoke-static {v0, v2, v3}, Ljp/yg;->i(Ld01/x;Ljava/lang/String;Ljava/lang/String;)V

    .line 199
    .line 200
    .line 201
    invoke-virtual {v0}, Ld01/x;->j()Ld01/y;

    .line 202
    .line 203
    .line 204
    move-result-object v17

    .line 205
    new-instance v11, Ld01/t0;

    .line 206
    .line 207
    const-string v14, "Preemptive Authenticate"

    .line 208
    .line 209
    const/16 v15, 0x197

    .line 210
    .line 211
    const/16 v16, 0x0

    .line 212
    .line 213
    const/16 v19, 0x0

    .line 214
    .line 215
    const/16 v20, 0x0

    .line 216
    .line 217
    const/16 v21, 0x0

    .line 218
    .line 219
    const/16 v22, 0x0

    .line 220
    .line 221
    const-wide/16 v23, -0x1

    .line 222
    .line 223
    const-wide/16 v25, -0x1

    .line 224
    .line 225
    const/16 v27, 0x0

    .line 226
    .line 227
    invoke-direct/range {v11 .. v28}, Ld01/t0;-><init>(Ld01/k0;Ld01/i0;Ljava/lang/String;ILd01/w;Ld01/y;Ld01/v0;Lu01/g0;Ld01/t0;Ld01/t0;Ld01/t0;JJLh01/g;Ld01/y0;)V

    .line 228
    .line 229
    .line 230
    iget-object v0, v1, Ld01/a;->f:Ld01/c;

    .line 231
    .line 232
    invoke-interface {v0, v10, v11}, Ld01/c;->a(Ld01/w0;Ld01/t0;)Ld01/k0;

    .line 233
    .line 234
    .line 235
    move-result-object v0

    .line 236
    if-nez v0, :cond_6

    .line 237
    .line 238
    move-object v2, v12

    .line 239
    goto :goto_1

    .line 240
    :cond_6
    move-object v2, v0

    .line 241
    goto :goto_1

    .line 242
    :goto_3
    new-instance v0, Lh01/c;

    .line 243
    .line 244
    iget-object v1, v9, Lh01/r;->a:Lg01/c;

    .line 245
    .line 246
    iget-object v2, v9, Lh01/r;->b:Lh01/q;

    .line 247
    .line 248
    iget v3, v9, Lh01/r;->c:I

    .line 249
    .line 250
    iget v4, v9, Lh01/r;->d:I

    .line 251
    .line 252
    iget v5, v9, Lh01/r;->e:I

    .line 253
    .line 254
    iget v6, v9, Lh01/r;->f:I

    .line 255
    .line 256
    iget-boolean v7, v9, Lh01/r;->g:Z

    .line 257
    .line 258
    iget-object v8, v9, Lh01/r;->k:Lh01/o;

    .line 259
    .line 260
    const/4 v14, -0x1

    .line 261
    const/4 v15, 0x0

    .line 262
    const/4 v12, 0x0

    .line 263
    move-object/from16 v11, p2

    .line 264
    .line 265
    invoke-direct/range {v0 .. v15}, Lh01/c;-><init>(Lg01/c;Lh01/q;IIIIZLh01/o;Lh01/r;Ld01/w0;Ljava/util/List;ILd01/k0;IZ)V

    .line 266
    .line 267
    .line 268
    return-object v0

    .line 269
    :cond_7
    new-instance v0, Ljava/net/UnknownServiceException;

    .line 270
    .line 271
    const-string v1, "H2_PRIOR_KNOWLEDGE cannot be used with HTTPS"

    .line 272
    .line 273
    invoke-direct {v0, v1}, Ljava/net/UnknownServiceException;-><init>(Ljava/lang/String;)V

    .line 274
    .line 275
    .line 276
    throw v0
.end method

.method public final d(Lh01/c;Ljava/util/List;)Lh01/s;
    .locals 10

    .line 1
    iget-object v0, p0, Lh01/r;->b:Lh01/q;

    .line 2
    .line 3
    iget-boolean v1, p0, Lh01/r;->l:Z

    .line 4
    .line 5
    iget-object v2, p0, Lh01/r;->i:Ld01/a;

    .line 6
    .line 7
    iget-object v3, p0, Lh01/r;->k:Lh01/o;

    .line 8
    .line 9
    const/4 v4, 0x0

    .line 10
    const/4 v5, 0x1

    .line 11
    if-eqz p1, :cond_0

    .line 12
    .line 13
    invoke-virtual {p1}, Lh01/c;->a()Z

    .line 14
    .line 15
    .line 16
    move-result v6

    .line 17
    if-eqz v6, :cond_0

    .line 18
    .line 19
    move v6, v5

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    move v6, v4

    .line 22
    :goto_0
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    iget-object v0, v0, Lh01/q;->h:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast v0, Ljava/util/concurrent/ConcurrentLinkedQueue;

    .line 28
    .line 29
    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentLinkedQueue;->iterator()Ljava/util/Iterator;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    const-string v7, "iterator(...)"

    .line 34
    .line 35
    invoke-static {v0, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    :cond_1
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 39
    .line 40
    .line 41
    move-result v7

    .line 42
    const/4 v8, 0x0

    .line 43
    if-eqz v7, :cond_6

    .line 44
    .line 45
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v7

    .line 49
    check-cast v7, Lh01/p;

    .line 50
    .line 51
    invoke-static {v7}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    monitor-enter v7

    .line 55
    if-eqz v6, :cond_3

    .line 56
    .line 57
    :try_start_0
    iget-object v9, v7, Lh01/p;->i:Lk01/p;

    .line 58
    .line 59
    if-eqz v9, :cond_2

    .line 60
    .line 61
    move v9, v5

    .line 62
    goto :goto_2

    .line 63
    :cond_2
    move v9, v4

    .line 64
    :goto_2
    if-nez v9, :cond_3

    .line 65
    .line 66
    :goto_3
    move v9, v4

    .line 67
    goto :goto_4

    .line 68
    :catchall_0
    move-exception p0

    .line 69
    goto :goto_5

    .line 70
    :cond_3
    invoke-virtual {v7, v2, p2}, Lh01/p;->f(Ld01/a;Ljava/util/List;)Z

    .line 71
    .line 72
    .line 73
    move-result v9

    .line 74
    if-nez v9, :cond_4

    .line 75
    .line 76
    goto :goto_3

    .line 77
    :cond_4
    invoke-virtual {v3, v7}, Lh01/o;->b(Lh01/p;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 78
    .line 79
    .line 80
    move v9, v5

    .line 81
    :goto_4
    monitor-exit v7

    .line 82
    if-eqz v9, :cond_1

    .line 83
    .line 84
    invoke-virtual {v7, v1}, Lh01/p;->g(Z)Z

    .line 85
    .line 86
    .line 87
    move-result v9

    .line 88
    if-eqz v9, :cond_5

    .line 89
    .line 90
    goto :goto_6

    .line 91
    :cond_5
    monitor-enter v7

    .line 92
    :try_start_1
    iput-boolean v5, v7, Lh01/p;->j:Z

    .line 93
    .line 94
    invoke-virtual {v3}, Lh01/o;->i()Ljava/net/Socket;

    .line 95
    .line 96
    .line 97
    move-result-object v8
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 98
    monitor-exit v7

    .line 99
    if-eqz v8, :cond_1

    .line 100
    .line 101
    invoke-static {v8}, Le01/g;->c(Ljava/net/Socket;)V

    .line 102
    .line 103
    .line 104
    goto :goto_1

    .line 105
    :catchall_1
    move-exception p0

    .line 106
    monitor-exit v7

    .line 107
    throw p0

    .line 108
    :goto_5
    monitor-exit v7

    .line 109
    throw p0

    .line 110
    :cond_6
    move-object v7, v8

    .line 111
    :goto_6
    if-nez v7, :cond_7

    .line 112
    .line 113
    return-object v8

    .line 114
    :cond_7
    if-eqz p1, :cond_8

    .line 115
    .line 116
    iget-object p2, p1, Lh01/c;->j:Ld01/w0;

    .line 117
    .line 118
    iput-object p2, p0, Lh01/r;->o:Ld01/w0;

    .line 119
    .line 120
    iget-object p0, p1, Lh01/c;->r:Ljava/net/Socket;

    .line 121
    .line 122
    if-eqz p0, :cond_8

    .line 123
    .line 124
    invoke-static {p0}, Le01/g;->c(Ljava/net/Socket;)V

    .line 125
    .line 126
    .line 127
    :cond_8
    new-instance p0, Lh01/s;

    .line 128
    .line 129
    invoke-direct {p0, v7}, Lh01/s;-><init>(Lh01/p;)V

    .line 130
    .line 131
    .line 132
    return-object p0
.end method

.method public final e(Ld01/a0;)Z
    .locals 2

    .line 1
    const-string v0, "url"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lh01/r;->i:Ld01/a;

    .line 7
    .line 8
    iget-object p0, p0, Ld01/a;->h:Ld01/a0;

    .line 9
    .line 10
    iget v0, p1, Ld01/a0;->e:I

    .line 11
    .line 12
    iget v1, p0, Ld01/a0;->e:I

    .line 13
    .line 14
    if-ne v0, v1, :cond_0

    .line 15
    .line 16
    iget-object p1, p1, Ld01/a0;->d:Ljava/lang/String;

    .line 17
    .line 18
    iget-object p0, p0, Ld01/a0;->d:Ljava/lang/String;

    .line 19
    .line 20
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    if-eqz p0, :cond_0

    .line 25
    .line 26
    const/4 p0, 0x1

    .line 27
    return p0

    .line 28
    :cond_0
    const/4 p0, 0x0

    .line 29
    return p0
.end method
