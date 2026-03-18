.class public final synthetic Ly40/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ly40/b;


# direct methods
.method public synthetic constructor <init>(Ly40/b;I)V
    .locals 0

    .line 1
    iput p2, p0, Ly40/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ly40/a;->e:Ly40/b;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Ly40/a;->d:I

    .line 2
    .line 3
    check-cast p1, Lk21/a;

    .line 4
    .line 5
    check-cast p2, Lg21/a;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    const-string v0, "$this$scopedFactory"

    .line 11
    .line 12
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    const-string v0, "it"

    .line 16
    .line 17
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    new-instance p2, Lz40/g;

    .line 21
    .line 22
    iget-object p0, p0, Ly40/a;->e:Ly40/b;

    .line 23
    .line 24
    iget-object p0, p0, Ly40/b;->a:Ljava/lang/String;

    .line 25
    .line 26
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 31
    .line 32
    const-class v2, Lal0/s0;

    .line 33
    .line 34
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    const/4 v3, 0x0

    .line 39
    invoke-virtual {p1, v2, v0, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    check-cast v0, Lal0/s0;

    .line 44
    .line 45
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    const-class v2, Lwj0/r;

    .line 50
    .line 51
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    invoke-virtual {p1, v1, p0, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    check-cast p0, Lwj0/r;

    .line 60
    .line 61
    invoke-direct {p2, v0, p0}, Lz40/g;-><init>(Lal0/s0;Lwj0/r;)V

    .line 62
    .line 63
    .line 64
    return-object p2

    .line 65
    :pswitch_0
    const-string v0, "$this$scopedFactory"

    .line 66
    .line 67
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    const-string v0, "it"

    .line 71
    .line 72
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    new-instance p2, Lz40/f;

    .line 76
    .line 77
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 78
    .line 79
    const-class v1, Lal0/p0;

    .line 80
    .line 81
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 82
    .line 83
    .line 84
    move-result-object v1

    .line 85
    const/4 v2, 0x0

    .line 86
    invoke-virtual {p1, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v1

    .line 90
    check-cast v1, Lal0/p0;

    .line 91
    .line 92
    iget-object p0, p0, Ly40/a;->e:Ly40/b;

    .line 93
    .line 94
    iget-object p0, p0, Ly40/b;->a:Ljava/lang/String;

    .line 95
    .line 96
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 97
    .line 98
    .line 99
    move-result-object v3

    .line 100
    const-class v4, Lal0/s0;

    .line 101
    .line 102
    invoke-virtual {v0, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 103
    .line 104
    .line 105
    move-result-object v4

    .line 106
    invoke-virtual {p1, v4, v3, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v3

    .line 110
    check-cast v3, Lal0/s0;

    .line 111
    .line 112
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    const-class v4, Lwj0/r;

    .line 117
    .line 118
    invoke-virtual {v0, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 119
    .line 120
    .line 121
    move-result-object v0

    .line 122
    invoke-virtual {p1, v0, p0, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    check-cast p0, Lwj0/r;

    .line 127
    .line 128
    invoke-direct {p2, v1, v3, p0}, Lz40/f;-><init>(Lal0/p0;Lal0/s0;Lwj0/r;)V

    .line 129
    .line 130
    .line 131
    return-object p2

    .line 132
    :pswitch_1
    const-string v0, "$this$scopedFactory"

    .line 133
    .line 134
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 135
    .line 136
    .line 137
    const-string v0, "it"

    .line 138
    .line 139
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 140
    .line 141
    .line 142
    new-instance p2, Lz40/j;

    .line 143
    .line 144
    iget-object p0, p0, Ly40/a;->e:Ly40/b;

    .line 145
    .line 146
    iget-object p0, p0, Ly40/b;->a:Ljava/lang/String;

    .line 147
    .line 148
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 149
    .line 150
    .line 151
    move-result-object p0

    .line 152
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 153
    .line 154
    const-class v1, Lal0/x0;

    .line 155
    .line 156
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 157
    .line 158
    .line 159
    move-result-object v1

    .line 160
    const/4 v2, 0x0

    .line 161
    invoke-virtual {p1, v1, p0, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    move-result-object p0

    .line 165
    check-cast p0, Lal0/x0;

    .line 166
    .line 167
    const-class v1, Lwj0/k;

    .line 168
    .line 169
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 170
    .line 171
    .line 172
    move-result-object v1

    .line 173
    invoke-virtual {p1, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object v1

    .line 177
    check-cast v1, Lwj0/k;

    .line 178
    .line 179
    const-class v3, Lrq0/f;

    .line 180
    .line 181
    invoke-virtual {v0, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 182
    .line 183
    .line 184
    move-result-object v0

    .line 185
    invoke-virtual {p1, v0, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object p1

    .line 189
    check-cast p1, Lrq0/f;

    .line 190
    .line 191
    invoke-direct {p2, p0, v1, p1}, Lz40/j;-><init>(Lal0/x0;Lwj0/k;Lrq0/f;)V

    .line 192
    .line 193
    .line 194
    return-object p2

    .line 195
    :pswitch_2
    const-string v0, "$this$scopedFactory"

    .line 196
    .line 197
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 198
    .line 199
    .line 200
    const-string v0, "it"

    .line 201
    .line 202
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 203
    .line 204
    .line 205
    new-instance v1, Lz40/c;

    .line 206
    .line 207
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 208
    .line 209
    const-class v0, Lwj0/k;

    .line 210
    .line 211
    invoke-virtual {p2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 212
    .line 213
    .line 214
    move-result-object v0

    .line 215
    const/4 v2, 0x0

    .line 216
    invoke-virtual {p1, v0, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 217
    .line 218
    .line 219
    move-result-object v0

    .line 220
    check-cast v0, Lwj0/k;

    .line 221
    .line 222
    iget-object p0, p0, Ly40/a;->e:Ly40/b;

    .line 223
    .line 224
    iget-object p0, p0, Ly40/b;->a:Ljava/lang/String;

    .line 225
    .line 226
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 227
    .line 228
    .line 229
    move-result-object v3

    .line 230
    const-class v4, Lal0/x0;

    .line 231
    .line 232
    invoke-virtual {p2, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 233
    .line 234
    .line 235
    move-result-object v4

    .line 236
    invoke-virtual {p1, v4, v3, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 237
    .line 238
    .line 239
    move-result-object v3

    .line 240
    check-cast v3, Lal0/x0;

    .line 241
    .line 242
    const-class v4, Lal0/h0;

    .line 243
    .line 244
    invoke-virtual {p2, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 245
    .line 246
    .line 247
    move-result-object v4

    .line 248
    invoke-virtual {p1, v4, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 249
    .line 250
    .line 251
    move-result-object v4

    .line 252
    check-cast v4, Lal0/h0;

    .line 253
    .line 254
    const-class v5, Lal0/q0;

    .line 255
    .line 256
    invoke-virtual {p2, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 257
    .line 258
    .line 259
    move-result-object v5

    .line 260
    invoke-virtual {p1, v5, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 261
    .line 262
    .line 263
    move-result-object v5

    .line 264
    check-cast v5, Lal0/q0;

    .line 265
    .line 266
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 267
    .line 268
    .line 269
    move-result-object v6

    .line 270
    const-class v7, Lal0/j;

    .line 271
    .line 272
    invoke-virtual {p2, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 273
    .line 274
    .line 275
    move-result-object v7

    .line 276
    invoke-virtual {p1, v7, v6, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 277
    .line 278
    .line 279
    move-result-object v6

    .line 280
    check-cast v6, Lal0/j;

    .line 281
    .line 282
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 283
    .line 284
    .line 285
    move-result-object v7

    .line 286
    const-class v8, Lal0/c;

    .line 287
    .line 288
    invoke-virtual {p2, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 289
    .line 290
    .line 291
    move-result-object v8

    .line 292
    invoke-virtual {p1, v8, v7, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 293
    .line 294
    .line 295
    move-result-object v7

    .line 296
    check-cast v7, Lal0/c;

    .line 297
    .line 298
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 299
    .line 300
    .line 301
    move-result-object p0

    .line 302
    const-class v8, Lwj0/x;

    .line 303
    .line 304
    invoke-virtual {p2, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 305
    .line 306
    .line 307
    move-result-object v8

    .line 308
    invoke-virtual {p1, v8, p0, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 309
    .line 310
    .line 311
    move-result-object p0

    .line 312
    move-object v8, p0

    .line 313
    check-cast v8, Lwj0/x;

    .line 314
    .line 315
    const-class p0, Lwj0/g;

    .line 316
    .line 317
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 318
    .line 319
    .line 320
    move-result-object p0

    .line 321
    invoke-virtual {p1, p0, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 322
    .line 323
    .line 324
    move-result-object p0

    .line 325
    move-object v9, p0

    .line 326
    check-cast v9, Lwj0/g;

    .line 327
    .line 328
    move-object v2, v0

    .line 329
    invoke-direct/range {v1 .. v9}, Lz40/c;-><init>(Lwj0/k;Lal0/x0;Lal0/h0;Lal0/q0;Lal0/j;Lal0/c;Lwj0/x;Lwj0/g;)V

    .line 330
    .line 331
    .line 332
    return-object v1

    .line 333
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
