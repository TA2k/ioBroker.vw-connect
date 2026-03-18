.class public final Lqd0/j;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Lqd0/k;


# direct methods
.method public synthetic constructor <init>(Lqd0/k;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lqd0/j;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lqd0/j;->f:Lqd0/k;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget v0, p0, Lqd0/j;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lqd0/j;

    .line 7
    .line 8
    iget-object p0, p0, Lqd0/j;->f:Lqd0/k;

    .line 9
    .line 10
    const/4 v1, 0x2

    .line 11
    invoke-direct {v0, p0, p2, v1}, Lqd0/j;-><init>(Lqd0/k;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Lqd0/j;->e:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Lqd0/j;

    .line 18
    .line 19
    iget-object p0, p0, Lqd0/j;->f:Lqd0/k;

    .line 20
    .line 21
    const/4 v1, 0x1

    .line 22
    invoke-direct {v0, p0, p2, v1}, Lqd0/j;-><init>(Lqd0/k;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Lqd0/j;->e:Ljava/lang/Object;

    .line 26
    .line 27
    return-object v0

    .line 28
    :pswitch_1
    new-instance v0, Lqd0/j;

    .line 29
    .line 30
    iget-object p0, p0, Lqd0/j;->f:Lqd0/k;

    .line 31
    .line 32
    const/4 v1, 0x0

    .line 33
    invoke-direct {v0, p0, p2, v1}, Lqd0/j;-><init>(Lqd0/k;Lkotlin/coroutines/Continuation;I)V

    .line 34
    .line 35
    .line 36
    iput-object p1, v0, Lqd0/j;->e:Ljava/lang/Object;

    .line 37
    .line 38
    return-object v0

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lqd0/j;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/s;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lqd0/j;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lqd0/j;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lqd0/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-object p1

    .line 22
    :pswitch_0
    check-cast p1, Lrd0/m;

    .line 23
    .line 24
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 25
    .line 26
    invoke-virtual {p0, p1, p2}, Lqd0/j;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    check-cast p0, Lqd0/j;

    .line 31
    .line 32
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    invoke-virtual {p0, p1}, Lqd0/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    return-object p1

    .line 38
    :pswitch_1
    check-cast p1, Lne0/s;

    .line 39
    .line 40
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 41
    .line 42
    invoke-virtual {p0, p1, p2}, Lqd0/j;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    check-cast p0, Lqd0/j;

    .line 47
    .line 48
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 49
    .line 50
    invoke-virtual {p0, p1}, Lqd0/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    return-object p1

    .line 54
    nop

    .line 55
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Lqd0/j;->d:I

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    iget-object v2, p0, Lqd0/j;->f:Lqd0/k;

    .line 5
    .line 6
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 7
    .line 8
    iget-object p0, p0, Lqd0/j;->e:Ljava/lang/Object;

    .line 9
    .line 10
    packed-switch v0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    check-cast p0, Lne0/s;

    .line 14
    .line 15
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 16
    .line 17
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    iget-object p1, v2, Lqd0/k;->b:Lqd0/y;

    .line 21
    .line 22
    instance-of v0, p0, Lne0/e;

    .line 23
    .line 24
    if-eqz v0, :cond_1

    .line 25
    .line 26
    :try_start_0
    check-cast p0, Lne0/e;

    .line 27
    .line 28
    iget-object p0, p0, Lne0/e;->a:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast p0, Lrd0/m;

    .line 31
    .line 32
    new-instance p0, Lne0/e;

    .line 33
    .line 34
    invoke-direct {p0, v3}, Lne0/e;-><init>(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :catchall_0
    move-exception v0

    .line 39
    move-object p0, v0

    .line 40
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    :goto_0
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 45
    .line 46
    .line 47
    move-result-object v5

    .line 48
    if-nez v5, :cond_0

    .line 49
    .line 50
    goto :goto_1

    .line 51
    :cond_0
    new-instance v4, Lne0/c;

    .line 52
    .line 53
    const/4 v8, 0x0

    .line 54
    const/16 v9, 0x1e

    .line 55
    .line 56
    const/4 v6, 0x0

    .line 57
    const/4 v7, 0x0

    .line 58
    invoke-direct/range {v4 .. v9}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 59
    .line 60
    .line 61
    move-object p0, v4

    .line 62
    :goto_1
    check-cast p0, Lne0/s;

    .line 63
    .line 64
    goto :goto_2

    .line 65
    :cond_1
    instance-of v0, p0, Lne0/c;

    .line 66
    .line 67
    if-eqz v0, :cond_2

    .line 68
    .line 69
    goto :goto_2

    .line 70
    :cond_2
    instance-of v0, p0, Lne0/d;

    .line 71
    .line 72
    if-eqz v0, :cond_3

    .line 73
    .line 74
    :goto_2
    check-cast p1, Lod0/u;

    .line 75
    .line 76
    const-string v0, "state"

    .line 77
    .line 78
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    iget-object p1, p1, Lod0/u;->c:Lyy0/c2;

    .line 82
    .line 83
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 84
    .line 85
    .line 86
    const/4 v0, 0x0

    .line 87
    invoke-virtual {p1, v0, p0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    return-object v3

    .line 91
    :cond_3
    new-instance p0, La8/r0;

    .line 92
    .line 93
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 94
    .line 95
    .line 96
    throw p0

    .line 97
    :pswitch_0
    check-cast p0, Lrd0/m;

    .line 98
    .line 99
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 100
    .line 101
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    iget-object p1, v2, Lqd0/k;->b:Lqd0/y;

    .line 105
    .line 106
    move-object v0, p1

    .line 107
    check-cast v0, Lod0/u;

    .line 108
    .line 109
    iget-object v2, v0, Lod0/u;->h:Ljava/time/OffsetDateTime;

    .line 110
    .line 111
    if-nez v2, :cond_4

    .line 112
    .line 113
    invoke-virtual {v0}, Lod0/u;->b()V

    .line 114
    .line 115
    .line 116
    :cond_4
    iget-object v0, p0, Lrd0/m;->b:Ljava/time/OffsetDateTime;

    .line 117
    .line 118
    if-eqz v0, :cond_5

    .line 119
    .line 120
    move-object v2, p1

    .line 121
    check-cast v2, Lod0/u;

    .line 122
    .line 123
    iput-object v0, v2, Lod0/u;->h:Ljava/time/OffsetDateTime;

    .line 124
    .line 125
    :cond_5
    iget-object p0, p0, Lrd0/m;->a:Ljava/util/ArrayList;

    .line 126
    .line 127
    check-cast p1, Lod0/u;

    .line 128
    .line 129
    iget-object v0, p1, Lod0/u;->b:Ljava/lang/Object;

    .line 130
    .line 131
    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    .line 132
    .line 133
    .line 134
    move-result v2

    .line 135
    if-nez v2, :cond_6

    .line 136
    .line 137
    move-object v2, v0

    .line 138
    check-cast v2, Ljava/util/Collection;

    .line 139
    .line 140
    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    .line 141
    .line 142
    .line 143
    move-result v2

    .line 144
    if-nez v2, :cond_6

    .line 145
    .line 146
    invoke-static {p0}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object v2

    .line 150
    check-cast v2, Lrd0/q;

    .line 151
    .line 152
    invoke-static {v0}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v0

    .line 156
    check-cast v0, Lrd0/q;

    .line 157
    .line 158
    iget v4, v2, Lrd0/q;->d:I

    .line 159
    .line 160
    iget v5, v0, Lrd0/q;->d:I

    .line 161
    .line 162
    if-ne v4, v5, :cond_6

    .line 163
    .line 164
    iget-object v2, v2, Lrd0/q;->c:Ljava/time/Month;

    .line 165
    .line 166
    iget-object v0, v0, Lrd0/q;->c:Ljava/time/Month;

    .line 167
    .line 168
    if-ne v2, v0, :cond_6

    .line 169
    .line 170
    invoke-static {}, Ljp/k1;->f()Lnx0/c;

    .line 171
    .line 172
    .line 173
    move-result-object v0

    .line 174
    iget-object v2, p1, Lod0/u;->b:Ljava/lang/Object;

    .line 175
    .line 176
    invoke-static {v2}, Lmx0/q;->E(Ljava/util/List;)Ljava/util/List;

    .line 177
    .line 178
    .line 179
    move-result-object v2

    .line 180
    check-cast v2, Ljava/util/Collection;

    .line 181
    .line 182
    invoke-virtual {v0, v2}, Lnx0/c;->addAll(Ljava/util/Collection;)Z

    .line 183
    .line 184
    .line 185
    iget-object v2, p1, Lod0/u;->b:Ljava/lang/Object;

    .line 186
    .line 187
    invoke-static {v2}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object v2

    .line 191
    check-cast v2, Lrd0/q;

    .line 192
    .line 193
    invoke-static {p0}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 194
    .line 195
    .line 196
    move-result-object v4

    .line 197
    check-cast v4, Lrd0/q;

    .line 198
    .line 199
    const-string v5, "<this>"

    .line 200
    .line 201
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 202
    .line 203
    .line 204
    new-instance v5, Lrd0/q;

    .line 205
    .line 206
    iget-object v6, v2, Lrd0/q;->a:Lqr0/h;

    .line 207
    .line 208
    iget-object v2, v2, Lrd0/q;->b:Ljava/util/ArrayList;

    .line 209
    .line 210
    iget-object v4, v4, Lrd0/q;->b:Ljava/util/ArrayList;

    .line 211
    .line 212
    invoke-static {v4, v2}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 213
    .line 214
    .line 215
    move-result-object v2

    .line 216
    invoke-direct {v5, v6, v2}, Lrd0/q;-><init>(Lqr0/h;Ljava/util/ArrayList;)V

    .line 217
    .line 218
    .line 219
    invoke-virtual {v0, v5}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 220
    .line 221
    .line 222
    invoke-static {p0, v1}, Lmx0/q;->D(Ljava/lang/Iterable;I)Ljava/util/List;

    .line 223
    .line 224
    .line 225
    move-result-object p0

    .line 226
    check-cast p0, Ljava/util/Collection;

    .line 227
    .line 228
    invoke-virtual {v0, p0}, Lnx0/c;->addAll(Ljava/util/Collection;)Z

    .line 229
    .line 230
    .line 231
    invoke-static {v0}, Ljp/k1;->d(Ljava/util/List;)Lnx0/c;

    .line 232
    .line 233
    .line 234
    move-result-object p0

    .line 235
    goto :goto_3

    .line 236
    :cond_6
    iget-object v0, p1, Lod0/u;->b:Ljava/lang/Object;

    .line 237
    .line 238
    check-cast v0, Ljava/util/Collection;

    .line 239
    .line 240
    invoke-static {p0, v0}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 241
    .line 242
    .line 243
    move-result-object p0

    .line 244
    :goto_3
    iput-object p0, p1, Lod0/u;->b:Ljava/lang/Object;

    .line 245
    .line 246
    return-object v3

    .line 247
    :pswitch_1
    check-cast p0, Lne0/s;

    .line 248
    .line 249
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 250
    .line 251
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 252
    .line 253
    .line 254
    iget-object p1, v2, Lqd0/k;->b:Lqd0/y;

    .line 255
    .line 256
    instance-of v0, p0, Lne0/e;

    .line 257
    .line 258
    const/4 v2, 0x0

    .line 259
    if-eqz v0, :cond_8

    .line 260
    .line 261
    check-cast p0, Lne0/e;

    .line 262
    .line 263
    iget-object p0, p0, Lne0/e;->a:Ljava/lang/Object;

    .line 264
    .line 265
    check-cast p0, Lrd0/m;

    .line 266
    .line 267
    iget-object v0, p0, Lrd0/m;->b:Ljava/time/OffsetDateTime;

    .line 268
    .line 269
    if-eqz v0, :cond_9

    .line 270
    .line 271
    iget-object p0, p0, Lrd0/m;->a:Ljava/util/ArrayList;

    .line 272
    .line 273
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 274
    .line 275
    .line 276
    move-result-object p0

    .line 277
    move v0, v2

    .line 278
    :goto_4
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 279
    .line 280
    .line 281
    move-result v4

    .line 282
    if-eqz v4, :cond_7

    .line 283
    .line 284
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 285
    .line 286
    .line 287
    move-result-object v4

    .line 288
    check-cast v4, Lrd0/q;

    .line 289
    .line 290
    iget-object v4, v4, Lrd0/q;->b:Ljava/util/ArrayList;

    .line 291
    .line 292
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 293
    .line 294
    .line 295
    move-result v4

    .line 296
    add-int/2addr v0, v4

    .line 297
    goto :goto_4

    .line 298
    :cond_7
    const/16 p0, 0x14

    .line 299
    .line 300
    if-ge v0, p0, :cond_8

    .line 301
    .line 302
    goto :goto_5

    .line 303
    :cond_8
    move v1, v2

    .line 304
    :cond_9
    :goto_5
    check-cast p1, Lod0/u;

    .line 305
    .line 306
    iput-boolean v1, p1, Lod0/u;->e:Z

    .line 307
    .line 308
    return-object v3

    .line 309
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
