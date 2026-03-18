.class public final Lzv0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvy0/b0;
.implements Ljava/io/Closeable;


# static fields
.field public static final synthetic p:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;


# instance fields
.field private volatile synthetic closed:I

.field public final d:Lcw0/c;

.field public final e:Lzv0/e;

.field public final f:Z

.field public final g:Lvy0/k1;

.field public final h:Lpx0/g;

.field public final i:Lkw0/e;

.field public final j:Llw0/a;

.field public final k:Lkw0/e;

.field public final l:Llw0/a;

.field public final m:Lvw0/d;

.field public final n:Lj1/a;

.field public final o:Lzv0/e;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-class v0, Lzv0/c;

    .line 2
    .line 3
    const-string v1, "closed"

    .line 4
    .line 5
    invoke-static {v0, v1}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sput-object v0, Lzv0/c;->p:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 10
    .line 11
    return-void
.end method

.method public constructor <init>(Lcw0/c;Lzv0/e;Z)V
    .locals 6

    .line 1
    const-string v0, "engine"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lzv0/c;->d:Lcw0/c;

    .line 10
    .line 11
    iput-object p2, p0, Lzv0/c;->e:Lzv0/e;

    .line 12
    .line 13
    const/4 v0, 0x0

    .line 14
    iput v0, p0, Lzv0/c;->closed:I

    .line 15
    .line 16
    invoke-interface {p1}, Lvy0/b0;->getCoroutineContext()Lpx0/g;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    sget-object v2, Lvy0/h1;->d:Lvy0/h1;

    .line 21
    .line 22
    invoke-interface {v1, v2}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    check-cast v1, Lvy0/i1;

    .line 27
    .line 28
    new-instance v2, Lvy0/k1;

    .line 29
    .line 30
    invoke-direct {v2, v1}, Lvy0/k1;-><init>(Lvy0/i1;)V

    .line 31
    .line 32
    .line 33
    iput-object v2, p0, Lzv0/c;->g:Lvy0/k1;

    .line 34
    .line 35
    invoke-interface {p1}, Lvy0/b0;->getCoroutineContext()Lpx0/g;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    invoke-interface {v1, v2}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    iput-object v1, p0, Lzv0/c;->h:Lpx0/g;

    .line 44
    .line 45
    new-instance v1, Lkw0/e;

    .line 46
    .line 47
    invoke-direct {v1, v0}, Lkw0/e;-><init>(I)V

    .line 48
    .line 49
    .line 50
    iput-object v1, p0, Lzv0/c;->i:Lkw0/e;

    .line 51
    .line 52
    new-instance v1, Llw0/a;

    .line 53
    .line 54
    const/4 v3, 0x1

    .line 55
    invoke-direct {v1, v3}, Llw0/a;-><init>(I)V

    .line 56
    .line 57
    .line 58
    iput-object v1, p0, Lzv0/c;->j:Llw0/a;

    .line 59
    .line 60
    new-instance v1, Lkw0/e;

    .line 61
    .line 62
    invoke-direct {v1, v3}, Lkw0/e;-><init>(I)V

    .line 63
    .line 64
    .line 65
    iput-object v1, p0, Lzv0/c;->k:Lkw0/e;

    .line 66
    .line 67
    new-instance v3, Llw0/a;

    .line 68
    .line 69
    invoke-direct {v3, v0}, Llw0/a;-><init>(I)V

    .line 70
    .line 71
    .line 72
    iput-object v3, p0, Lzv0/c;->l:Llw0/a;

    .line 73
    .line 74
    new-instance v3, Lvw0/d;

    .line 75
    .line 76
    invoke-direct {v3}, Lvw0/d;-><init>()V

    .line 77
    .line 78
    .line 79
    iput-object v3, p0, Lzv0/c;->m:Lvw0/d;

    .line 80
    .line 81
    new-instance v3, Lj1/a;

    .line 82
    .line 83
    const/16 v4, 0x16

    .line 84
    .line 85
    invoke-direct {v3, v4}, Lj1/a;-><init>(I)V

    .line 86
    .line 87
    .line 88
    iput-object v3, p0, Lzv0/c;->n:Lj1/a;

    .line 89
    .line 90
    new-instance v3, Lzv0/e;

    .line 91
    .line 92
    invoke-direct {v3}, Lzv0/e;-><init>()V

    .line 93
    .line 94
    .line 95
    iput-object v3, p0, Lzv0/c;->o:Lzv0/e;

    .line 96
    .line 97
    iget-boolean v4, p0, Lzv0/c;->f:Z

    .line 98
    .line 99
    if-eqz v4, :cond_0

    .line 100
    .line 101
    new-instance v4, Lcw0/b;

    .line 102
    .line 103
    invoke-direct {v4, p0}, Lcw0/b;-><init>(Lzv0/c;)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {v2, v4}, Lvy0/p1;->E(Lay0/k;)Lvy0/r0;

    .line 107
    .line 108
    .line 109
    :cond_0
    sget-object v2, Lkw0/e;->o:Lj51/i;

    .line 110
    .line 111
    new-instance v4, Lal0/f;

    .line 112
    .line 113
    const/4 v5, 0x0

    .line 114
    invoke-direct {v4, p0, p1, v5}, Lal0/f;-><init>(Lzv0/c;Lcw0/c;Lkotlin/coroutines/Continuation;)V

    .line 115
    .line 116
    .line 117
    invoke-virtual {v1, v2, v4}, Lyw0/d;->f(Lj51/i;Lay0/o;)V

    .line 118
    .line 119
    .line 120
    sget-object p1, Lkw0/e;->p:Lj51/i;

    .line 121
    .line 122
    new-instance v2, Lzv0/a;

    .line 123
    .line 124
    invoke-direct {v2, p0, v5}, Lzv0/a;-><init>(Lzv0/c;Lkotlin/coroutines/Continuation;)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {v1, p1, v2}, Lyw0/d;->f(Lj51/i;Lay0/o;)V

    .line 128
    .line 129
    .line 130
    sget-object p1, Lfw0/f0;->b:Lgw0/c;

    .line 131
    .line 132
    new-instance v1, Lzv0/d;

    .line 133
    .line 134
    invoke-direct {v1, v0}, Lzv0/d;-><init>(I)V

    .line 135
    .line 136
    .line 137
    invoke-virtual {v3, p1, v1}, Lzv0/e;->a(Lfw0/t;Lay0/k;)V

    .line 138
    .line 139
    .line 140
    sget-object p1, Lfw0/c;->c:Lgw0/c;

    .line 141
    .line 142
    new-instance v1, Lzv0/d;

    .line 143
    .line 144
    invoke-direct {v1, v0}, Lzv0/d;-><init>(I)V

    .line 145
    .line 146
    .line 147
    invoke-virtual {v3, p1, v1}, Lzv0/e;->a(Lfw0/t;Lay0/k;)V

    .line 148
    .line 149
    .line 150
    sget-object p1, Lfw0/k;->d:Lgw0/c;

    .line 151
    .line 152
    new-instance v1, Lzv0/d;

    .line 153
    .line 154
    invoke-direct {v1, v0}, Lzv0/d;-><init>(I)V

    .line 155
    .line 156
    .line 157
    invoke-virtual {v3, p1, v1}, Lzv0/e;->a(Lfw0/t;Lay0/k;)V

    .line 158
    .line 159
    .line 160
    iget-boolean p1, p2, Lzv0/e;->f:Z

    .line 161
    .line 162
    if-eqz p1, :cond_1

    .line 163
    .line 164
    new-instance p1, Lz70/e0;

    .line 165
    .line 166
    const/16 v1, 0x1c

    .line 167
    .line 168
    invoke-direct {p1, v1}, Lz70/e0;-><init>(I)V

    .line 169
    .line 170
    .line 171
    iget-object v1, v3, Lzv0/e;->c:Ljava/util/LinkedHashMap;

    .line 172
    .line 173
    const-string v2, "DefaultTransformers"

    .line 174
    .line 175
    invoke-interface {v1, v2, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    :cond_1
    sget-object p1, Lfw0/w0;->b:Lfw0/a;

    .line 179
    .line 180
    new-instance v1, Lzv0/d;

    .line 181
    .line 182
    invoke-direct {v1, v0}, Lzv0/d;-><init>(I)V

    .line 183
    .line 184
    .line 185
    invoke-virtual {v3, p1, v1}, Lzv0/e;->a(Lfw0/t;Lay0/k;)V

    .line 186
    .line 187
    .line 188
    sget-object p1, Lfw0/s;->b:Lgw0/c;

    .line 189
    .line 190
    new-instance v1, Lzv0/d;

    .line 191
    .line 192
    invoke-direct {v1, v0}, Lzv0/d;-><init>(I)V

    .line 193
    .line 194
    .line 195
    invoke-virtual {v3, p1, v1}, Lzv0/e;->a(Lfw0/t;Lay0/k;)V

    .line 196
    .line 197
    .line 198
    iget-boolean v1, p2, Lzv0/e;->e:Z

    .line 199
    .line 200
    if-eqz v1, :cond_2

    .line 201
    .line 202
    sget-object v1, Lfw0/e0;->d:Lgw0/c;

    .line 203
    .line 204
    new-instance v2, Lzv0/d;

    .line 205
    .line 206
    invoke-direct {v2, v0}, Lzv0/d;-><init>(I)V

    .line 207
    .line 208
    .line 209
    invoke-virtual {v3, v1, v2}, Lzv0/e;->a(Lfw0/t;Lay0/k;)V

    .line 210
    .line 211
    .line 212
    :cond_2
    invoke-virtual {v3, p2}, Lzv0/e;->b(Lzv0/e;)V

    .line 213
    .line 214
    .line 215
    iget-boolean p2, p2, Lzv0/e;->f:Z

    .line 216
    .line 217
    if-eqz p2, :cond_3

    .line 218
    .line 219
    sget-object p2, Lfw0/a0;->b:Lgw0/c;

    .line 220
    .line 221
    new-instance v1, Lzv0/d;

    .line 222
    .line 223
    invoke-direct {v1, v0}, Lzv0/d;-><init>(I)V

    .line 224
    .line 225
    .line 226
    invoke-virtual {v3, p2, v1}, Lzv0/e;->a(Lfw0/t;Lay0/k;)V

    .line 227
    .line 228
    .line 229
    :cond_3
    sget-object p2, Lfw0/f;->a:Lvw0/a;

    .line 230
    .line 231
    new-instance p2, Lf31/n;

    .line 232
    .line 233
    invoke-direct {p2, v3}, Lf31/n;-><init>(Lzv0/e;)V

    .line 234
    .line 235
    .line 236
    invoke-virtual {v3, p1, p2}, Lzv0/e;->a(Lfw0/t;Lay0/k;)V

    .line 237
    .line 238
    .line 239
    iget-object p1, v3, Lzv0/e;->a:Ljava/util/LinkedHashMap;

    .line 240
    .line 241
    invoke-virtual {p1}, Ljava/util/LinkedHashMap;->values()Ljava/util/Collection;

    .line 242
    .line 243
    .line 244
    move-result-object p1

    .line 245
    check-cast p1, Ljava/lang/Iterable;

    .line 246
    .line 247
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 248
    .line 249
    .line 250
    move-result-object p1

    .line 251
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 252
    .line 253
    .line 254
    move-result p2

    .line 255
    if-eqz p2, :cond_4

    .line 256
    .line 257
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 258
    .line 259
    .line 260
    move-result-object p2

    .line 261
    check-cast p2, Lay0/k;

    .line 262
    .line 263
    invoke-interface {p2, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 264
    .line 265
    .line 266
    goto :goto_0

    .line 267
    :cond_4
    iget-object p1, v3, Lzv0/e;->c:Ljava/util/LinkedHashMap;

    .line 268
    .line 269
    invoke-virtual {p1}, Ljava/util/LinkedHashMap;->values()Ljava/util/Collection;

    .line 270
    .line 271
    .line 272
    move-result-object p1

    .line 273
    check-cast p1, Ljava/lang/Iterable;

    .line 274
    .line 275
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 276
    .line 277
    .line 278
    move-result-object p1

    .line 279
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 280
    .line 281
    .line 282
    move-result p2

    .line 283
    if-eqz p2, :cond_5

    .line 284
    .line 285
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 286
    .line 287
    .line 288
    move-result-object p2

    .line 289
    check-cast p2, Lay0/k;

    .line 290
    .line 291
    invoke-interface {p2, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 292
    .line 293
    .line 294
    goto :goto_1

    .line 295
    :cond_5
    iget-object p1, p0, Lzv0/c;->j:Llw0/a;

    .line 296
    .line 297
    sget-object p2, Llw0/a;->j:Lj51/i;

    .line 298
    .line 299
    new-instance v0, La7/l0;

    .line 300
    .line 301
    const/16 v1, 0x9

    .line 302
    .line 303
    invoke-direct {v0, p0, v5, v1}, La7/l0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 304
    .line 305
    .line 306
    invoke-virtual {p1, p2, v0}, Lyw0/d;->f(Lj51/i;Lay0/o;)V

    .line 307
    .line 308
    .line 309
    iput-boolean p3, p0, Lzv0/c;->f:Z

    .line 310
    .line 311
    return-void
.end method


# virtual methods
.method public final a(Lkw0/c;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Lzv0/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lzv0/b;

    .line 7
    .line 8
    iget v1, v0, Lzv0/b;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lzv0/b;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lzv0/b;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lzv0/b;-><init>(Lzv0/c;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lzv0/b;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lzv0/b;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    iget-object p2, p0, Lzv0/c;->n:Lj1/a;

    .line 52
    .line 53
    sget-object v2, Lmw0/a;->a:Lgv/a;

    .line 54
    .line 55
    invoke-virtual {p2, v2}, Lj1/a;->w(Lgv/a;)V

    .line 56
    .line 57
    .line 58
    iget-object p2, p1, Lkw0/c;->d:Ljava/lang/Object;

    .line 59
    .line 60
    iput v3, v0, Lzv0/b;->f:I

    .line 61
    .line 62
    iget-object p0, p0, Lzv0/c;->i:Lkw0/e;

    .line 63
    .line 64
    invoke-virtual {p0, p1, p2, v0}, Lyw0/d;->a(Ljava/lang/Object;Ljava/lang/Object;Lrx0/c;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p2

    .line 68
    if-ne p2, v1, :cond_3

    .line 69
    .line 70
    return-object v1

    .line 71
    :cond_3
    :goto_1
    const-string p0, "null cannot be cast to non-null type io.ktor.client.call.HttpClientCall"

    .line 72
    .line 73
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    check-cast p2, Law0/c;

    .line 77
    .line 78
    return-object p2
.end method

.method public final close()V
    .locals 10

    .line 1
    sget-object v0, Lzv0/c;->p:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    invoke-virtual {v0, p0, v1, v2}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->compareAndSet(Ljava/lang/Object;II)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    goto/16 :goto_2

    .line 12
    .line 13
    :cond_0
    iget-object v0, p0, Lzv0/c;->m:Lvw0/d;

    .line 14
    .line 15
    sget-object v3, Lfw0/u;->a:Lvw0/a;

    .line 16
    .line 17
    invoke-virtual {v0, v3}, Lvw0/d;->b(Lvw0/a;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    check-cast v0, Lvw0/d;

    .line 22
    .line 23
    invoke-virtual {v0}, Lvw0/d;->c()Ljava/util/Map;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    invoke-interface {v3}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 28
    .line 29
    .line 30
    move-result-object v3

    .line 31
    check-cast v3, Ljava/lang/Iterable;

    .line 32
    .line 33
    invoke-static {v3}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 34
    .line 35
    .line 36
    move-result-object v3

    .line 37
    check-cast v3, Ljava/lang/Iterable;

    .line 38
    .line 39
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    :cond_1
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 44
    .line 45
    .line 46
    move-result v4

    .line 47
    if-eqz v4, :cond_8

    .line 48
    .line 49
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v4

    .line 53
    check-cast v4, Lvw0/a;

    .line 54
    .line 55
    const-string v5, "null cannot be cast to non-null type io.ktor.util.AttributeKey<kotlin.Any>"

    .line 56
    .line 57
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0, v4}, Lvw0/d;->b(Lvw0/a;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v4

    .line 64
    instance-of v5, v4, Ljava/lang/AutoCloseable;

    .line 65
    .line 66
    if-eqz v5, :cond_1

    .line 67
    .line 68
    check-cast v4, Ljava/lang/AutoCloseable;

    .line 69
    .line 70
    instance-of v5, v4, Ljava/lang/AutoCloseable;

    .line 71
    .line 72
    if-eqz v5, :cond_2

    .line 73
    .line 74
    invoke-interface {v4}, Ljava/lang/AutoCloseable;->close()V

    .line 75
    .line 76
    .line 77
    goto :goto_0

    .line 78
    :cond_2
    instance-of v5, v4, Ljava/util/concurrent/ExecutorService;

    .line 79
    .line 80
    if-eqz v5, :cond_6

    .line 81
    .line 82
    check-cast v4, Ljava/util/concurrent/ExecutorService;

    .line 83
    .line 84
    invoke-static {}, Ljava/util/concurrent/ForkJoinPool;->commonPool()Ljava/util/concurrent/ForkJoinPool;

    .line 85
    .line 86
    .line 87
    move-result-object v5

    .line 88
    if-ne v4, v5, :cond_3

    .line 89
    .line 90
    goto :goto_0

    .line 91
    :cond_3
    invoke-interface {v4}, Ljava/util/concurrent/ExecutorService;->isTerminated()Z

    .line 92
    .line 93
    .line 94
    move-result v5

    .line 95
    if-nez v5, :cond_1

    .line 96
    .line 97
    invoke-interface {v4}, Ljava/util/concurrent/ExecutorService;->shutdown()V

    .line 98
    .line 99
    .line 100
    move v6, v1

    .line 101
    :cond_4
    :goto_1
    if-nez v5, :cond_5

    .line 102
    .line 103
    :try_start_0
    sget-object v7, Ljava/util/concurrent/TimeUnit;->DAYS:Ljava/util/concurrent/TimeUnit;

    .line 104
    .line 105
    const-wide/16 v8, 0x1

    .line 106
    .line 107
    invoke-interface {v4, v8, v9, v7}, Ljava/util/concurrent/ExecutorService;->awaitTermination(JLjava/util/concurrent/TimeUnit;)Z

    .line 108
    .line 109
    .line 110
    move-result v5
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0

    .line 111
    goto :goto_1

    .line 112
    :catch_0
    if-nez v6, :cond_4

    .line 113
    .line 114
    invoke-interface {v4}, Ljava/util/concurrent/ExecutorService;->shutdownNow()Ljava/util/List;

    .line 115
    .line 116
    .line 117
    move v6, v2

    .line 118
    goto :goto_1

    .line 119
    :cond_5
    if-eqz v6, :cond_1

    .line 120
    .line 121
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 122
    .line 123
    .line 124
    move-result-object v4

    .line 125
    invoke-virtual {v4}, Ljava/lang/Thread;->interrupt()V

    .line 126
    .line 127
    .line 128
    goto :goto_0

    .line 129
    :cond_6
    instance-of v5, v4, Landroid/content/res/TypedArray;

    .line 130
    .line 131
    if-eqz v5, :cond_7

    .line 132
    .line 133
    check-cast v4, Landroid/content/res/TypedArray;

    .line 134
    .line 135
    invoke-virtual {v4}, Landroid/content/res/TypedArray;->recycle()V

    .line 136
    .line 137
    .line 138
    goto :goto_0

    .line 139
    :cond_7
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 140
    .line 141
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 142
    .line 143
    .line 144
    throw p0

    .line 145
    :cond_8
    iget-object v0, p0, Lzv0/c;->g:Lvy0/k1;

    .line 146
    .line 147
    invoke-virtual {v0}, Lvy0/k1;->l0()Z

    .line 148
    .line 149
    .line 150
    iget-boolean v0, p0, Lzv0/c;->f:Z

    .line 151
    .line 152
    if-eqz v0, :cond_9

    .line 153
    .line 154
    iget-object p0, p0, Lzv0/c;->d:Lcw0/c;

    .line 155
    .line 156
    invoke-interface {p0}, Ljava/io/Closeable;->close()V

    .line 157
    .line 158
    .line 159
    :cond_9
    :goto_2
    return-void
.end method

.method public final getCoroutineContext()Lpx0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lzv0/c;->h:Lpx0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "HttpClient["

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lzv0/c;->d:Lcw0/c;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const/16 p0, 0x5d

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method
