.class public final Lba0/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lba0/v;


# direct methods
.method public synthetic constructor <init>(Lba0/v;I)V
    .locals 0

    .line 1
    iput p2, p0, Lba0/r;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lba0/r;->e:Lba0/v;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget p2, p0, Lba0/r;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v3, p1

    .line 7
    check-cast v3, Laa0/c;

    .line 8
    .line 9
    iget-object p0, p0, Lba0/r;->e:Lba0/v;

    .line 10
    .line 11
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    move-object v0, p1

    .line 16
    check-cast v0, Lba0/u;

    .line 17
    .line 18
    const/4 v7, 0x0

    .line 19
    const/16 v8, 0x7b

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    const/4 v2, 0x0

    .line 23
    const/4 v4, 0x0

    .line 24
    const/4 v5, 0x0

    .line 25
    const/4 v6, 0x0

    .line 26
    invoke-static/range {v0 .. v8}, Lba0/u;->a(Lba0/u;Llf0/i;Ler0/g;Laa0/c;ZLql0/g;Ljava/util/List;ZI)Lba0/u;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 31
    .line 32
    .line 33
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    return-object p0

    .line 36
    :pswitch_0
    check-cast p1, Lne0/s;

    .line 37
    .line 38
    instance-of p2, p1, Lne0/d;

    .line 39
    .line 40
    iget-object p0, p0, Lba0/r;->e:Lba0/v;

    .line 41
    .line 42
    if-eqz p2, :cond_0

    .line 43
    .line 44
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    move-object v0, p1

    .line 49
    check-cast v0, Lba0/u;

    .line 50
    .line 51
    const/4 v7, 0x0

    .line 52
    const/16 v8, 0x17

    .line 53
    .line 54
    const/4 v1, 0x0

    .line 55
    const/4 v2, 0x0

    .line 56
    const/4 v3, 0x0

    .line 57
    const/4 v4, 0x1

    .line 58
    const/4 v5, 0x0

    .line 59
    sget-object v6, Lmx0/s;->d:Lmx0/s;

    .line 60
    .line 61
    invoke-static/range {v0 .. v8}, Lba0/u;->a(Lba0/u;Llf0/i;Ler0/g;Laa0/c;ZLql0/g;Ljava/util/List;ZI)Lba0/u;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 66
    .line 67
    .line 68
    goto/16 :goto_1

    .line 69
    .line 70
    :cond_0
    instance-of p2, p1, Lne0/e;

    .line 71
    .line 72
    if-eqz p2, :cond_2

    .line 73
    .line 74
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 75
    .line 76
    .line 77
    move-result-object p2

    .line 78
    move-object v0, p2

    .line 79
    check-cast v0, Lba0/u;

    .line 80
    .line 81
    check-cast p1, Lne0/e;

    .line 82
    .line 83
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast p1, Ljava/util/List;

    .line 86
    .line 87
    check-cast p1, Ljava/lang/Iterable;

    .line 88
    .line 89
    new-instance v6, Ljava/util/ArrayList;

    .line 90
    .line 91
    const/16 p2, 0xa

    .line 92
    .line 93
    invoke-static {p1, p2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 94
    .line 95
    .line 96
    move-result p2

    .line 97
    invoke-direct {v6, p2}, Ljava/util/ArrayList;-><init>(I)V

    .line 98
    .line 99
    .line 100
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 101
    .line 102
    .line 103
    move-result-object p1

    .line 104
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 105
    .line 106
    .line 107
    move-result p2

    .line 108
    if-eqz p2, :cond_1

    .line 109
    .line 110
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object p2

    .line 114
    check-cast p2, Laa0/j;

    .line 115
    .line 116
    new-instance v1, Lba0/t;

    .line 117
    .line 118
    iget-object v2, p2, Laa0/j;->a:Ljava/lang/String;

    .line 119
    .line 120
    iget-object v3, p2, Laa0/j;->b:Ljava/lang/String;

    .line 121
    .line 122
    iget-object v4, p2, Laa0/j;->c:Ljava/lang/String;

    .line 123
    .line 124
    iget-object p2, p2, Laa0/j;->d:Ljava/time/OffsetDateTime;

    .line 125
    .line 126
    invoke-static {p2}, Lvo/a;->g(Ljava/time/OffsetDateTime;)Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object p2

    .line 130
    const-string v5, " | "

    .line 131
    .line 132
    invoke-static {v4, v5, p2}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object p2

    .line 136
    invoke-direct {v1, v2, v3, p2}, Lba0/t;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    invoke-virtual {v6, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 140
    .line 141
    .line 142
    goto :goto_0

    .line 143
    :cond_1
    const/4 v7, 0x0

    .line 144
    const/16 v8, 0x57

    .line 145
    .line 146
    const/4 v1, 0x0

    .line 147
    const/4 v2, 0x0

    .line 148
    const/4 v3, 0x0

    .line 149
    const/4 v4, 0x0

    .line 150
    const/4 v5, 0x0

    .line 151
    invoke-static/range {v0 .. v8}, Lba0/u;->a(Lba0/u;Llf0/i;Ler0/g;Laa0/c;ZLql0/g;Ljava/util/List;ZI)Lba0/u;

    .line 152
    .line 153
    .line 154
    move-result-object p1

    .line 155
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 156
    .line 157
    .line 158
    goto :goto_1

    .line 159
    :cond_2
    instance-of p2, p1, Lne0/c;

    .line 160
    .line 161
    if-eqz p2, :cond_3

    .line 162
    .line 163
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 164
    .line 165
    .line 166
    move-result-object p2

    .line 167
    move-object v0, p2

    .line 168
    check-cast v0, Lba0/u;

    .line 169
    .line 170
    check-cast p1, Lne0/c;

    .line 171
    .line 172
    iget-object p2, p0, Lba0/v;->n:Lij0/a;

    .line 173
    .line 174
    invoke-static {p1, p2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 175
    .line 176
    .line 177
    move-result-object v5

    .line 178
    const/4 v7, 0x0

    .line 179
    const/16 v8, 0x6f

    .line 180
    .line 181
    const/4 v1, 0x0

    .line 182
    const/4 v2, 0x0

    .line 183
    const/4 v3, 0x0

    .line 184
    const/4 v4, 0x0

    .line 185
    const/4 v6, 0x0

    .line 186
    invoke-static/range {v0 .. v8}, Lba0/u;->a(Lba0/u;Llf0/i;Ler0/g;Laa0/c;ZLql0/g;Ljava/util/List;ZI)Lba0/u;

    .line 187
    .line 188
    .line 189
    move-result-object p1

    .line 190
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 191
    .line 192
    .line 193
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 194
    .line 195
    return-object p0

    .line 196
    :cond_3
    new-instance p0, La8/r0;

    .line 197
    .line 198
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 199
    .line 200
    .line 201
    throw p0

    .line 202
    :pswitch_1
    check-cast p1, Lne0/s;

    .line 203
    .line 204
    instance-of p2, p1, Lne0/c;

    .line 205
    .line 206
    iget-object p0, p0, Lba0/r;->e:Lba0/v;

    .line 207
    .line 208
    if-eqz p2, :cond_4

    .line 209
    .line 210
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 211
    .line 212
    .line 213
    move-result-object p2

    .line 214
    move-object v0, p2

    .line 215
    check-cast v0, Lba0/u;

    .line 216
    .line 217
    check-cast p1, Lne0/c;

    .line 218
    .line 219
    iget-object p2, p0, Lba0/v;->n:Lij0/a;

    .line 220
    .line 221
    invoke-static {p1, p2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 222
    .line 223
    .line 224
    move-result-object v5

    .line 225
    const/4 v7, 0x0

    .line 226
    const/16 v8, 0x6f

    .line 227
    .line 228
    const/4 v1, 0x0

    .line 229
    const/4 v2, 0x0

    .line 230
    const/4 v3, 0x0

    .line 231
    const/4 v4, 0x0

    .line 232
    const/4 v6, 0x0

    .line 233
    invoke-static/range {v0 .. v8}, Lba0/u;->a(Lba0/u;Llf0/i;Ler0/g;Laa0/c;ZLql0/g;Ljava/util/List;ZI)Lba0/u;

    .line 234
    .line 235
    .line 236
    move-result-object p1

    .line 237
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 238
    .line 239
    .line 240
    goto :goto_2

    .line 241
    :cond_4
    sget-object p2, Lne0/d;->a:Lne0/d;

    .line 242
    .line 243
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 244
    .line 245
    .line 246
    move-result p2

    .line 247
    if-eqz p2, :cond_5

    .line 248
    .line 249
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 250
    .line 251
    .line 252
    move-result-object p1

    .line 253
    move-object v0, p1

    .line 254
    check-cast v0, Lba0/u;

    .line 255
    .line 256
    const/4 v7, 0x0

    .line 257
    const/16 v8, 0x77

    .line 258
    .line 259
    const/4 v1, 0x0

    .line 260
    const/4 v2, 0x0

    .line 261
    const/4 v3, 0x0

    .line 262
    const/4 v4, 0x1

    .line 263
    const/4 v5, 0x0

    .line 264
    const/4 v6, 0x0

    .line 265
    invoke-static/range {v0 .. v8}, Lba0/u;->a(Lba0/u;Llf0/i;Ler0/g;Laa0/c;ZLql0/g;Ljava/util/List;ZI)Lba0/u;

    .line 266
    .line 267
    .line 268
    move-result-object p1

    .line 269
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 270
    .line 271
    .line 272
    goto :goto_2

    .line 273
    :cond_5
    instance-of p2, p1, Lne0/e;

    .line 274
    .line 275
    if-eqz p2, :cond_6

    .line 276
    .line 277
    check-cast p1, Lne0/e;

    .line 278
    .line 279
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 280
    .line 281
    check-cast p1, Lss0/b;

    .line 282
    .line 283
    invoke-static {p0, p1}, Lba0/v;->h(Lba0/v;Lss0/b;)V

    .line 284
    .line 285
    .line 286
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 287
    .line 288
    .line 289
    move-result-object p1

    .line 290
    new-instance p2, Lba0/s;

    .line 291
    .line 292
    const/4 v0, 0x1

    .line 293
    const/4 v1, 0x0

    .line 294
    invoke-direct {p2, p0, v1, v0}, Lba0/s;-><init>(Lba0/v;Lkotlin/coroutines/Continuation;I)V

    .line 295
    .line 296
    .line 297
    const/4 v0, 0x3

    .line 298
    invoke-static {p1, v1, v1, p2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 299
    .line 300
    .line 301
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 302
    .line 303
    .line 304
    move-result-object p1

    .line 305
    new-instance p2, Lba0/s;

    .line 306
    .line 307
    const/4 v2, 0x2

    .line 308
    invoke-direct {p2, p0, v1, v2}, Lba0/s;-><init>(Lba0/v;Lkotlin/coroutines/Continuation;I)V

    .line 309
    .line 310
    .line 311
    invoke-static {p1, v1, v1, p2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 312
    .line 313
    .line 314
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 315
    .line 316
    return-object p0

    .line 317
    :cond_6
    new-instance p0, La8/r0;

    .line 318
    .line 319
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 320
    .line 321
    .line 322
    throw p0

    .line 323
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
