.class public final Lfw0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lgw0/a;
.implements Lfw0/t;


# static fields
.field public static final e:Lfw0/a;

.field public static final f:Lfw0/a;

.field public static final g:Lfw0/a;

.field public static final h:Lfw0/a;

.field public static final i:Lfw0/a;

.field public static final j:Lfw0/a;


# instance fields
.field public final synthetic d:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lfw0/a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lfw0/a;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lfw0/a;->e:Lfw0/a;

    .line 8
    .line 9
    new-instance v0, Lfw0/a;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1}, Lfw0/a;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lfw0/a;->f:Lfw0/a;

    .line 16
    .line 17
    new-instance v0, Lfw0/a;

    .line 18
    .line 19
    const/4 v1, 0x2

    .line 20
    invoke-direct {v0, v1}, Lfw0/a;-><init>(I)V

    .line 21
    .line 22
    .line 23
    sput-object v0, Lfw0/a;->g:Lfw0/a;

    .line 24
    .line 25
    new-instance v0, Lfw0/a;

    .line 26
    .line 27
    const/4 v1, 0x3

    .line 28
    invoke-direct {v0, v1}, Lfw0/a;-><init>(I)V

    .line 29
    .line 30
    .line 31
    sput-object v0, Lfw0/a;->h:Lfw0/a;

    .line 32
    .line 33
    new-instance v0, Lfw0/a;

    .line 34
    .line 35
    const/4 v1, 0x4

    .line 36
    invoke-direct {v0, v1}, Lfw0/a;-><init>(I)V

    .line 37
    .line 38
    .line 39
    sput-object v0, Lfw0/a;->i:Lfw0/a;

    .line 40
    .line 41
    new-instance v0, Lfw0/a;

    .line 42
    .line 43
    const/4 v1, 0x5

    .line 44
    invoke-direct {v0, v1}, Lfw0/a;-><init>(I)V

    .line 45
    .line 46
    .line 47
    sput-object v0, Lfw0/a;->j:Lfw0/a;

    .line 48
    .line 49
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lfw0/a;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public a(Lzv0/c;Lrx0/i;)V
    .locals 8

    .line 1
    iget p0, p0, Lfw0/a;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p2, Lay0/o;

    .line 7
    .line 8
    const-string p0, "client"

    .line 9
    .line 10
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p1, Lzv0/c;->i:Lkw0/e;

    .line 14
    .line 15
    sget-object p1, Lkw0/e;->g:Lj51/i;

    .line 16
    .line 17
    new-instance v0, Lfw0/b1;

    .line 18
    .line 19
    const/4 v1, 0x0

    .line 20
    const/4 v2, 0x2

    .line 21
    invoke-direct {v0, p2, v1, v2}, Lfw0/b1;-><init>(Lay0/o;Lkotlin/coroutines/Continuation;I)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0, p1, v0}, Lyw0/d;->f(Lj51/i;Lay0/o;)V

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    :pswitch_0
    check-cast p2, Lay0/o;

    .line 29
    .line 30
    const-string p0, "client"

    .line 31
    .line 32
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    iget-object p0, p1, Lzv0/c;->i:Lkw0/e;

    .line 36
    .line 37
    sget-object p1, Lkw0/e;->g:Lj51/i;

    .line 38
    .line 39
    new-instance v0, Lfw0/b1;

    .line 40
    .line 41
    const/4 v1, 0x0

    .line 42
    const/4 v2, 0x1

    .line 43
    invoke-direct {v0, p2, v1, v2}, Lfw0/b1;-><init>(Lay0/o;Lkotlin/coroutines/Continuation;I)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {p0, p1, v0}, Lyw0/d;->f(Lj51/i;Lay0/o;)V

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    :pswitch_1
    check-cast p2, Lay0/o;

    .line 51
    .line 52
    const-string p0, "client"

    .line 53
    .line 54
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    iget-object p0, p1, Lzv0/c;->i:Lkw0/e;

    .line 58
    .line 59
    sget-object p1, Lkw0/e;->j:Lj51/i;

    .line 60
    .line 61
    new-instance v0, Lfw0/b;

    .line 62
    .line 63
    const/4 v1, 0x0

    .line 64
    const/4 v2, 0x1

    .line 65
    invoke-direct {v0, p2, v1, v2}, Lfw0/b;-><init>(Lay0/o;Lkotlin/coroutines/Continuation;I)V

    .line 66
    .line 67
    .line 68
    invoke-virtual {p0, p1, v0}, Lyw0/d;->f(Lj51/i;Lay0/o;)V

    .line 69
    .line 70
    .line 71
    return-void

    .line 72
    :pswitch_2
    check-cast p2, Lay0/o;

    .line 73
    .line 74
    const-string p0, "client"

    .line 75
    .line 76
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    new-instance p0, Lj51/i;

    .line 80
    .line 81
    const-string v0, "BeforeReceive"

    .line 82
    .line 83
    const/4 v1, 0x6

    .line 84
    invoke-direct {p0, v0, v1}, Lj51/i;-><init>(Ljava/lang/String;I)V

    .line 85
    .line 86
    .line 87
    iget-object p1, p1, Lzv0/c;->j:Llw0/a;

    .line 88
    .line 89
    sget-object v0, Llw0/a;->j:Lj51/i;

    .line 90
    .line 91
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 92
    .line 93
    .line 94
    const-string v1, "reference"

    .line 95
    .line 96
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    invoke-virtual {p1, p0}, Lyw0/d;->e(Lj51/i;)Z

    .line 100
    .line 101
    .line 102
    move-result v1

    .line 103
    if-eqz v1, :cond_0

    .line 104
    .line 105
    goto :goto_0

    .line 106
    :cond_0
    invoke-virtual {p1, v0}, Lyw0/d;->c(Lj51/i;)I

    .line 107
    .line 108
    .line 109
    move-result v1

    .line 110
    const/4 v2, -0x1

    .line 111
    if-eq v1, v2, :cond_1

    .line 112
    .line 113
    iget-object v0, p1, Lyw0/d;->a:Ljava/util/ArrayList;

    .line 114
    .line 115
    new-instance v2, Lyw0/c;

    .line 116
    .line 117
    new-instance v3, Lyw0/h;

    .line 118
    .line 119
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 120
    .line 121
    .line 122
    invoke-direct {v2, p0, v3}, Lyw0/c;-><init>(Lj51/i;Lcp0/r;)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {v0, v1, v2}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 126
    .line 127
    .line 128
    :goto_0
    new-instance v0, Lfw0/b1;

    .line 129
    .line 130
    const/4 v1, 0x0

    .line 131
    const/4 v2, 0x0

    .line 132
    invoke-direct {v0, p2, v1, v2}, Lfw0/b1;-><init>(Lay0/o;Lkotlin/coroutines/Continuation;I)V

    .line 133
    .line 134
    .line 135
    invoke-virtual {p1, p0, v0}, Lyw0/d;->f(Lj51/i;Lay0/o;)V

    .line 136
    .line 137
    .line 138
    return-void

    .line 139
    :cond_1
    new-instance p0, Lt11/a;

    .line 140
    .line 141
    new-instance p1, Ljava/lang/StringBuilder;

    .line 142
    .line 143
    const-string p2, "Phase "

    .line 144
    .line 145
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 149
    .line 150
    .line 151
    const-string p2, " was not registered for this pipeline"

    .line 152
    .line 153
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 154
    .line 155
    .line 156
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 157
    .line 158
    .line 159
    move-result-object p1

    .line 160
    invoke-direct {p0, p1}, Lt11/a;-><init>(Ljava/lang/String;)V

    .line 161
    .line 162
    .line 163
    throw p0

    .line 164
    :pswitch_3
    check-cast p2, Lay0/o;

    .line 165
    .line 166
    const-string p0, "client"

    .line 167
    .line 168
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    new-instance p0, Lj51/i;

    .line 172
    .line 173
    const-string v0, "ObservableContent"

    .line 174
    .line 175
    const/4 v1, 0x6

    .line 176
    invoke-direct {p0, v0, v1}, Lj51/i;-><init>(Ljava/lang/String;I)V

    .line 177
    .line 178
    .line 179
    iget-object p1, p1, Lzv0/c;->i:Lkw0/e;

    .line 180
    .line 181
    sget-object v0, Lkw0/e;->j:Lj51/i;

    .line 182
    .line 183
    iget-object v1, p1, Lyw0/d;->a:Ljava/util/ArrayList;

    .line 184
    .line 185
    const-string v2, "reference"

    .line 186
    .line 187
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 188
    .line 189
    .line 190
    invoke-virtual {p1, p0}, Lyw0/d;->e(Lj51/i;)Z

    .line 191
    .line 192
    .line 193
    move-result v2

    .line 194
    const/4 v3, 0x0

    .line 195
    if-eqz v2, :cond_2

    .line 196
    .line 197
    goto :goto_6

    .line 198
    :cond_2
    invoke-virtual {p1, v0}, Lyw0/d;->c(Lj51/i;)I

    .line 199
    .line 200
    .line 201
    move-result v2

    .line 202
    const/4 v4, -0x1

    .line 203
    if-eq v2, v4, :cond_9

    .line 204
    .line 205
    add-int/lit8 v4, v2, 0x1

    .line 206
    .line 207
    invoke-static {v1}, Ljp/k1;->h(Ljava/util/List;)I

    .line 208
    .line 209
    .line 210
    move-result v5

    .line 211
    if-gt v4, v5, :cond_8

    .line 212
    .line 213
    :goto_1
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 214
    .line 215
    .line 216
    move-result-object v6

    .line 217
    instance-of v7, v6, Lyw0/c;

    .line 218
    .line 219
    if-eqz v7, :cond_3

    .line 220
    .line 221
    check-cast v6, Lyw0/c;

    .line 222
    .line 223
    goto :goto_2

    .line 224
    :cond_3
    move-object v6, v3

    .line 225
    :goto_2
    if-eqz v6, :cond_8

    .line 226
    .line 227
    iget-object v6, v6, Lyw0/c;->b:Lcp0/r;

    .line 228
    .line 229
    if-nez v6, :cond_4

    .line 230
    .line 231
    goto :goto_5

    .line 232
    :cond_4
    instance-of v7, v6, Lyw0/g;

    .line 233
    .line 234
    if-eqz v7, :cond_5

    .line 235
    .line 236
    check-cast v6, Lyw0/g;

    .line 237
    .line 238
    goto :goto_3

    .line 239
    :cond_5
    move-object v6, v3

    .line 240
    :goto_3
    if-eqz v6, :cond_7

    .line 241
    .line 242
    iget-object v6, v6, Lyw0/g;->a:Lj51/i;

    .line 243
    .line 244
    if-nez v6, :cond_6

    .line 245
    .line 246
    goto :goto_4

    .line 247
    :cond_6
    invoke-virtual {v6, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 248
    .line 249
    .line 250
    move-result v6

    .line 251
    if-eqz v6, :cond_7

    .line 252
    .line 253
    move v2, v4

    .line 254
    :cond_7
    :goto_4
    if-eq v4, v5, :cond_8

    .line 255
    .line 256
    add-int/lit8 v4, v4, 0x1

    .line 257
    .line 258
    goto :goto_1

    .line 259
    :cond_8
    :goto_5
    add-int/lit8 v2, v2, 0x1

    .line 260
    .line 261
    new-instance v4, Lyw0/c;

    .line 262
    .line 263
    new-instance v5, Lyw0/g;

    .line 264
    .line 265
    invoke-direct {v5, v0}, Lyw0/g;-><init>(Lj51/i;)V

    .line 266
    .line 267
    .line 268
    invoke-direct {v4, p0, v5}, Lyw0/c;-><init>(Lj51/i;Lcp0/r;)V

    .line 269
    .line 270
    .line 271
    invoke-virtual {v1, v2, v4}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 272
    .line 273
    .line 274
    :goto_6
    new-instance v0, Lfw0/b;

    .line 275
    .line 276
    const/4 v1, 0x0

    .line 277
    invoke-direct {v0, p2, v3, v1}, Lfw0/b;-><init>(Lay0/o;Lkotlin/coroutines/Continuation;I)V

    .line 278
    .line 279
    .line 280
    invoke-virtual {p1, p0, v0}, Lyw0/d;->f(Lj51/i;Lay0/o;)V

    .line 281
    .line 282
    .line 283
    return-void

    .line 284
    :cond_9
    new-instance p0, Lt11/a;

    .line 285
    .line 286
    new-instance p1, Ljava/lang/StringBuilder;

    .line 287
    .line 288
    const-string p2, "Phase "

    .line 289
    .line 290
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 291
    .line 292
    .line 293
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 294
    .line 295
    .line 296
    const-string p2, " was not registered for this pipeline"

    .line 297
    .line 298
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 299
    .line 300
    .line 301
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 302
    .line 303
    .line 304
    move-result-object p1

    .line 305
    invoke-direct {p0, p1}, Lt11/a;-><init>(Ljava/lang/String;)V

    .line 306
    .line 307
    .line 308
    throw p0

    .line 309
    :pswitch_4
    check-cast p2, Lay0/n;

    .line 310
    .line 311
    const-string p0, "client"

    .line 312
    .line 313
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 314
    .line 315
    .line 316
    iget-object p0, p1, Lzv0/c;->l:Llw0/a;

    .line 317
    .line 318
    sget-object p1, Llw0/a;->i:Lj51/i;

    .line 319
    .line 320
    new-instance v0, La90/c;

    .line 321
    .line 322
    const/4 v1, 0x0

    .line 323
    const/16 v2, 0x18

    .line 324
    .line 325
    invoke-direct {v0, p2, v1, v2}, La90/c;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 326
    .line 327
    .line 328
    invoke-virtual {p0, p1, v0}, Lyw0/d;->f(Lj51/i;Lay0/o;)V

    .line 329
    .line 330
    .line 331
    return-void

    .line 332
    nop

    .line 333
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public b(Lay0/k;)Ljava/lang/Object;
    .locals 1

    .line 1
    new-instance p0, Lfw0/a;

    .line 2
    .line 3
    const/4 v0, 0x6

    .line 4
    invoke-direct {p0, v0}, Lfw0/a;-><init>(I)V

    .line 5
    .line 6
    .line 7
    invoke-interface {p1, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    new-instance p0, Lfw0/w0;

    .line 11
    .line 12
    invoke-direct {p0}, Lfw0/w0;-><init>()V

    .line 13
    .line 14
    .line 15
    return-object p0
.end method

.method public d(Ljava/lang/Object;Lzv0/c;)V
    .locals 3

    .line 1
    check-cast p1, Lfw0/w0;

    .line 2
    .line 3
    const-string p0, "plugin"

    .line 4
    .line 5
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string p0, "scope"

    .line 9
    .line 10
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p2, Lzv0/c;->i:Lkw0/e;

    .line 14
    .line 15
    sget-object v0, Lkw0/e;->k:Lj51/i;

    .line 16
    .line 17
    new-instance v1, Lfw0/v0;

    .line 18
    .line 19
    const/4 v2, 0x0

    .line 20
    invoke-direct {v1, p1, p2, v2}, Lfw0/v0;-><init>(Lfw0/w0;Lzv0/c;Lkotlin/coroutines/Continuation;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0, v0, v1}, Lyw0/d;->f(Lj51/i;Lay0/o;)V

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method public getKey()Lvw0/a;
    .locals 0

    .line 1
    sget-object p0, Lfw0/w0;->c:Lvw0/a;

    .line 2
    .line 3
    return-object p0
.end method
