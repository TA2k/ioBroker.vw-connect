.class public final Lnz/g;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput p1, p0, Lnz/g;->d:I

    iput-object p2, p0, Lnz/g;->e:Ljava/lang/Object;

    iput-object p3, p0, Lnz/g;->f:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 2
    iput p3, p0, Lnz/g;->d:I

    iput-object p1, p0, Lnz/g;->f:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method private final b(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lnz/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lne0/s;

    .line 4
    .line 5
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 6
    .line 7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Lro0/k;

    .line 13
    .line 14
    new-instance p1, Lro0/h;

    .line 15
    .line 16
    const/4 v1, 0x2

    .line 17
    invoke-direct {p1, v0, v1}, Lro0/h;-><init>(Lne0/s;I)V

    .line 18
    .line 19
    .line 20
    const-string v0, "MULTI.MySkoda"

    .line 21
    .line 22
    invoke-static {v0, p0, p1}, Llp/nd;->f(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 23
    .line 24
    .line 25
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    return-object p0
.end method

.method private final d(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lnz/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lne0/s;

    .line 4
    .line 5
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 6
    .line 7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Lro0/l;

    .line 13
    .line 14
    new-instance p1, Lro0/h;

    .line 15
    .line 16
    const/4 v1, 0x3

    .line 17
    invoke-direct {p1, v0, v1}, Lro0/h;-><init>(Lne0/s;I)V

    .line 18
    .line 19
    .line 20
    const-string v0, "MULTI.MySkoda"

    .line 21
    .line 22
    invoke-static {v0, p0, p1}, Llp/nd;->f(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 23
    .line 24
    .line 25
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    return-object p0
.end method

.method private final e(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lrt0/o;

    .line 4
    .line 5
    iget-object p0, p0, Lnz/g;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lcn0/c;

    .line 8
    .line 9
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 10
    .line 11
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    if-eqz p0, :cond_0

    .line 15
    .line 16
    iget-object p1, p0, Lcn0/c;->e:Lcn0/a;

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    const/4 p1, 0x0

    .line 20
    :goto_0
    if-nez p1, :cond_1

    .line 21
    .line 22
    const/4 p1, -0x1

    .line 23
    goto :goto_1

    .line 24
    :cond_1
    sget-object v1, Lrt0/n;->a:[I

    .line 25
    .line 26
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 27
    .line 28
    .line 29
    move-result p1

    .line 30
    aget p1, v1, p1

    .line 31
    .line 32
    :goto_1
    const/4 v1, 0x1

    .line 33
    if-eq p1, v1, :cond_3

    .line 34
    .line 35
    const/4 v1, 0x2

    .line 36
    if-eq p1, v1, :cond_2

    .line 37
    .line 38
    goto :goto_2

    .line 39
    :cond_2
    sget-object p1, Lst0/g;->c:Lst0/g;

    .line 40
    .line 41
    invoke-static {v0, p0, p1}, Lrt0/o;->a(Lrt0/o;Lcn0/c;Lkr0/c;)V

    .line 42
    .line 43
    .line 44
    goto :goto_2

    .line 45
    :cond_3
    sget-object p1, Lst0/g;->b:Lst0/g;

    .line 46
    .line 47
    invoke-static {v0, p0, p1}, Lrt0/o;->a(Lrt0/o;Lcn0/c;Lkr0/c;)V

    .line 48
    .line 49
    .line 50
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    return-object p0
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget v0, p0, Lnz/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lnz/g;

    .line 7
    .line 8
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Ls10/h;

    .line 11
    .line 12
    const/16 v1, 0x1d

    .line 13
    .line 14
    invoke-direct {v0, p0, p2, v1}, Lnz/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 15
    .line 16
    .line 17
    iput-object p1, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 18
    .line 19
    return-object v0

    .line 20
    :pswitch_0
    new-instance v0, Lnz/g;

    .line 21
    .line 22
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast p0, Lrt0/o;

    .line 25
    .line 26
    const/16 v1, 0x1c

    .line 27
    .line 28
    invoke-direct {v0, p0, p2, v1}, Lnz/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 29
    .line 30
    .line 31
    iput-object p1, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 32
    .line 33
    return-object v0

    .line 34
    :pswitch_1
    new-instance v0, Lnz/g;

    .line 35
    .line 36
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast p0, Lro0/l;

    .line 39
    .line 40
    const/16 v1, 0x1b

    .line 41
    .line 42
    invoke-direct {v0, p0, p2, v1}, Lnz/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 43
    .line 44
    .line 45
    iput-object p1, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 46
    .line 47
    return-object v0

    .line 48
    :pswitch_2
    new-instance v0, Lnz/g;

    .line 49
    .line 50
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast p0, Lro0/k;

    .line 53
    .line 54
    const/16 v1, 0x1a

    .line 55
    .line 56
    invoke-direct {v0, p0, p2, v1}, Lnz/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 57
    .line 58
    .line 59
    iput-object p1, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 60
    .line 61
    return-object v0

    .line 62
    :pswitch_3
    new-instance v0, Lnz/g;

    .line 63
    .line 64
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast p0, Lro0/j;

    .line 67
    .line 68
    const/16 v1, 0x19

    .line 69
    .line 70
    invoke-direct {v0, p0, p2, v1}, Lnz/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 71
    .line 72
    .line 73
    iput-object p1, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 74
    .line 75
    return-object v0

    .line 76
    :pswitch_4
    new-instance v0, Lnz/g;

    .line 77
    .line 78
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast p0, Lro0/i;

    .line 81
    .line 82
    const/16 v1, 0x18

    .line 83
    .line 84
    invoke-direct {v0, p0, p2, v1}, Lnz/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 85
    .line 86
    .line 87
    iput-object p1, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 88
    .line 89
    return-object v0

    .line 90
    :pswitch_5
    new-instance v0, Lnz/g;

    .line 91
    .line 92
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 93
    .line 94
    check-cast p0, Lr60/x;

    .line 95
    .line 96
    const/16 v1, 0x17

    .line 97
    .line 98
    invoke-direct {v0, p0, p2, v1}, Lnz/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 99
    .line 100
    .line 101
    iput-object p1, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 102
    .line 103
    return-object v0

    .line 104
    :pswitch_6
    new-instance p1, Lnz/g;

    .line 105
    .line 106
    iget-object v0, p0, Lnz/g;->e:Ljava/lang/Object;

    .line 107
    .line 108
    check-cast v0, Lr60/s;

    .line 109
    .line 110
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 111
    .line 112
    check-cast p0, Ljava/lang/String;

    .line 113
    .line 114
    const/16 v1, 0x16

    .line 115
    .line 116
    invoke-direct {p1, v1, v0, p0, p2}, Lnz/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 117
    .line 118
    .line 119
    return-object p1

    .line 120
    :pswitch_7
    new-instance v0, Lnz/g;

    .line 121
    .line 122
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 123
    .line 124
    check-cast p0, Lr60/g;

    .line 125
    .line 126
    const/16 v1, 0x15

    .line 127
    .line 128
    invoke-direct {v0, p0, p2, v1}, Lnz/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 129
    .line 130
    .line 131
    iput-object p1, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 132
    .line 133
    return-object v0

    .line 134
    :pswitch_8
    new-instance v0, Lnz/g;

    .line 135
    .line 136
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 137
    .line 138
    check-cast p0, Lr31/i;

    .line 139
    .line 140
    const/16 v1, 0x14

    .line 141
    .line 142
    invoke-direct {v0, p0, p2, v1}, Lnz/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 143
    .line 144
    .line 145
    iput-object p1, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 146
    .line 147
    return-object v0

    .line 148
    :pswitch_9
    new-instance p1, Lnz/g;

    .line 149
    .line 150
    iget-object v0, p0, Lnz/g;->e:Ljava/lang/Object;

    .line 151
    .line 152
    check-cast v0, Lqi/a;

    .line 153
    .line 154
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 155
    .line 156
    check-cast p0, Lmi/c;

    .line 157
    .line 158
    const/16 v1, 0x13

    .line 159
    .line 160
    invoke-direct {p1, v1, v0, p0, p2}, Lnz/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 161
    .line 162
    .line 163
    return-object p1

    .line 164
    :pswitch_a
    new-instance v0, Lnz/g;

    .line 165
    .line 166
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 167
    .line 168
    check-cast p0, Lqd0/j0;

    .line 169
    .line 170
    const/16 v1, 0x12

    .line 171
    .line 172
    invoke-direct {v0, p0, p2, v1}, Lnz/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 173
    .line 174
    .line 175
    iput-object p1, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 176
    .line 177
    return-object v0

    .line 178
    :pswitch_b
    new-instance v0, Lnz/g;

    .line 179
    .line 180
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 181
    .line 182
    check-cast p0, Lqd0/i;

    .line 183
    .line 184
    const/16 v1, 0x11

    .line 185
    .line 186
    invoke-direct {v0, p0, p2, v1}, Lnz/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 187
    .line 188
    .line 189
    iput-object p1, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 190
    .line 191
    return-object v0

    .line 192
    :pswitch_c
    new-instance v0, Lnz/g;

    .line 193
    .line 194
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 195
    .line 196
    check-cast p0, Lqa0/b;

    .line 197
    .line 198
    const/16 v1, 0x10

    .line 199
    .line 200
    invoke-direct {v0, p0, p2, v1}, Lnz/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 201
    .line 202
    .line 203
    iput-object p1, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 204
    .line 205
    return-object v0

    .line 206
    :pswitch_d
    new-instance v0, Lnz/g;

    .line 207
    .line 208
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 209
    .line 210
    check-cast p0, Lq70/i;

    .line 211
    .line 212
    const/16 v1, 0xf

    .line 213
    .line 214
    invoke-direct {v0, p0, p2, v1}, Lnz/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 215
    .line 216
    .line 217
    iput-object p1, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 218
    .line 219
    return-object v0

    .line 220
    :pswitch_e
    new-instance v0, Lnz/g;

    .line 221
    .line 222
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 223
    .line 224
    check-cast p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;

    .line 225
    .line 226
    const/16 v1, 0xe

    .line 227
    .line 228
    invoke-direct {v0, p0, p2, v1}, Lnz/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 229
    .line 230
    .line 231
    iput-object p1, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 232
    .line 233
    return-object v0

    .line 234
    :pswitch_f
    new-instance p1, Lnz/g;

    .line 235
    .line 236
    iget-object v0, p0, Lnz/g;->e:Ljava/lang/Object;

    .line 237
    .line 238
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;

    .line 239
    .line 240
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 241
    .line 242
    check-cast p0, Landroid/content/Context;

    .line 243
    .line 244
    const/16 v1, 0xd

    .line 245
    .line 246
    invoke-direct {p1, v1, v0, p0, p2}, Lnz/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 247
    .line 248
    .line 249
    return-object p1

    .line 250
    :pswitch_10
    new-instance v0, Lnz/g;

    .line 251
    .line 252
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 253
    .line 254
    check-cast p0, Lq40/h;

    .line 255
    .line 256
    const/16 v1, 0xc

    .line 257
    .line 258
    invoke-direct {v0, p0, p2, v1}, Lnz/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 259
    .line 260
    .line 261
    iput-object p1, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 262
    .line 263
    return-object v0

    .line 264
    :pswitch_11
    new-instance v0, Lnz/g;

    .line 265
    .line 266
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 267
    .line 268
    check-cast p0, Lq40/c;

    .line 269
    .line 270
    const/16 v1, 0xb

    .line 271
    .line 272
    invoke-direct {v0, p0, p2, v1}, Lnz/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 273
    .line 274
    .line 275
    iput-object p1, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 276
    .line 277
    return-object v0

    .line 278
    :pswitch_12
    new-instance p1, Lnz/g;

    .line 279
    .line 280
    iget-object v0, p0, Lnz/g;->e:Ljava/lang/Object;

    .line 281
    .line 282
    check-cast v0, Lq40/c;

    .line 283
    .line 284
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 285
    .line 286
    check-cast p0, Lo40/h;

    .line 287
    .line 288
    const/16 v1, 0xa

    .line 289
    .line 290
    invoke-direct {p1, v1, v0, p0, p2}, Lnz/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 291
    .line 292
    .line 293
    return-object p1

    .line 294
    :pswitch_13
    new-instance v0, Lnz/g;

    .line 295
    .line 296
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 297
    .line 298
    check-cast p0, Lq30/h;

    .line 299
    .line 300
    const/16 v1, 0x9

    .line 301
    .line 302
    invoke-direct {v0, p0, p2, v1}, Lnz/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 303
    .line 304
    .line 305
    iput-object p1, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 306
    .line 307
    return-object v0

    .line 308
    :pswitch_14
    new-instance p1, Lnz/g;

    .line 309
    .line 310
    iget-object v0, p0, Lnz/g;->e:Ljava/lang/Object;

    .line 311
    .line 312
    check-cast v0, Lpp0/j;

    .line 313
    .line 314
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 315
    .line 316
    check-cast p0, Lqp0/g;

    .line 317
    .line 318
    const/16 v1, 0x8

    .line 319
    .line 320
    invoke-direct {p1, v1, v0, p0, p2}, Lnz/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 321
    .line 322
    .line 323
    return-object p1

    .line 324
    :pswitch_15
    new-instance v0, Lnz/g;

    .line 325
    .line 326
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 327
    .line 328
    check-cast p0, Lpp0/h;

    .line 329
    .line 330
    const/4 v1, 0x7

    .line 331
    invoke-direct {v0, p0, p2, v1}, Lnz/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 332
    .line 333
    .line 334
    iput-object p1, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 335
    .line 336
    return-object v0

    .line 337
    :pswitch_16
    new-instance v0, Lnz/g;

    .line 338
    .line 339
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 340
    .line 341
    check-cast p0, Lpp0/e;

    .line 342
    .line 343
    const/4 v1, 0x6

    .line 344
    invoke-direct {v0, p0, p2, v1}, Lnz/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 345
    .line 346
    .line 347
    iput-object p1, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 348
    .line 349
    return-object v0

    .line 350
    :pswitch_17
    new-instance p1, Lnz/g;

    .line 351
    .line 352
    iget-object v0, p0, Lnz/g;->e:Ljava/lang/Object;

    .line 353
    .line 354
    check-cast v0, Loq0/a;

    .line 355
    .line 356
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 357
    .line 358
    check-cast p0, Lmq0/b;

    .line 359
    .line 360
    const/4 v1, 0x5

    .line 361
    invoke-direct {p1, v1, v0, p0, p2}, Lnz/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 362
    .line 363
    .line 364
    return-object p1

    .line 365
    :pswitch_18
    new-instance p1, Lnz/g;

    .line 366
    .line 367
    iget-object v0, p0, Lnz/g;->e:Ljava/lang/Object;

    .line 368
    .line 369
    check-cast v0, Loq0/a;

    .line 370
    .line 371
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 372
    .line 373
    check-cast p0, Lmq0/a;

    .line 374
    .line 375
    const/4 v1, 0x4

    .line 376
    invoke-direct {p1, v1, v0, p0, p2}, Lnz/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 377
    .line 378
    .line 379
    return-object p1

    .line 380
    :pswitch_19
    new-instance p1, Lnz/g;

    .line 381
    .line 382
    iget-object v0, p0, Lnz/g;->e:Ljava/lang/Object;

    .line 383
    .line 384
    check-cast v0, Lay0/n;

    .line 385
    .line 386
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 387
    .line 388
    check-cast p0, Ll2/b1;

    .line 389
    .line 390
    const/4 v1, 0x3

    .line 391
    invoke-direct {p1, v1, v0, p0, p2}, Lnz/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 392
    .line 393
    .line 394
    return-object p1

    .line 395
    :pswitch_1a
    new-instance p1, Lnz/g;

    .line 396
    .line 397
    iget-object v0, p0, Lnz/g;->e:Ljava/lang/Object;

    .line 398
    .line 399
    check-cast v0, Lo30/n;

    .line 400
    .line 401
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 402
    .line 403
    check-cast p0, Ljava/lang/String;

    .line 404
    .line 405
    const/4 v1, 0x2

    .line 406
    invoke-direct {p1, v1, v0, p0, p2}, Lnz/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 407
    .line 408
    .line 409
    return-object p1

    .line 410
    :pswitch_1b
    new-instance v0, Lnz/g;

    .line 411
    .line 412
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 413
    .line 414
    check-cast p0, Lo30/c;

    .line 415
    .line 416
    const/4 v1, 0x1

    .line 417
    invoke-direct {v0, p0, p2, v1}, Lnz/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 418
    .line 419
    .line 420
    iput-object p1, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 421
    .line 422
    return-object v0

    .line 423
    :pswitch_1c
    new-instance v0, Lnz/g;

    .line 424
    .line 425
    iget-object p0, p0, Lnz/g;->f:Ljava/lang/Object;

    .line 426
    .line 427
    check-cast p0, Lnz/j;

    .line 428
    .line 429
    const/4 v1, 0x0

    .line 430
    invoke-direct {v0, p0, p2, v1}, Lnz/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 431
    .line 432
    .line 433
    iput-object p1, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 434
    .line 435
    return-object v0

    .line 436
    nop

    .line 437
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lnz/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/t;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lnz/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lnz/g;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lnz/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-object p1

    .line 22
    :pswitch_0
    check-cast p1, Lcn0/c;

    .line 23
    .line 24
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 25
    .line 26
    invoke-virtual {p0, p1, p2}, Lnz/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    check-cast p0, Lnz/g;

    .line 31
    .line 32
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    invoke-virtual {p0, p1}, Lnz/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    invoke-virtual {p0, p1, p2}, Lnz/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    check-cast p0, Lnz/g;

    .line 47
    .line 48
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 49
    .line 50
    invoke-virtual {p0, p1}, Lnz/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    return-object p1

    .line 54
    :pswitch_2
    check-cast p1, Lne0/s;

    .line 55
    .line 56
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 57
    .line 58
    invoke-virtual {p0, p1, p2}, Lnz/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    check-cast p0, Lnz/g;

    .line 63
    .line 64
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 65
    .line 66
    invoke-virtual {p0, p1}, Lnz/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    return-object p1

    .line 70
    :pswitch_3
    check-cast p1, Lne0/s;

    .line 71
    .line 72
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 73
    .line 74
    invoke-virtual {p0, p1, p2}, Lnz/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    check-cast p0, Lnz/g;

    .line 79
    .line 80
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 81
    .line 82
    invoke-virtual {p0, p1}, Lnz/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    return-object p1

    .line 86
    :pswitch_4
    check-cast p1, Lne0/s;

    .line 87
    .line 88
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 89
    .line 90
    invoke-virtual {p0, p1, p2}, Lnz/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    check-cast p0, Lnz/g;

    .line 95
    .line 96
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 97
    .line 98
    invoke-virtual {p0, p1}, Lnz/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    return-object p1

    .line 102
    :pswitch_5
    check-cast p1, Lon0/h;

    .line 103
    .line 104
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 105
    .line 106
    invoke-virtual {p0, p1, p2}, Lnz/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    check-cast p0, Lnz/g;

    .line 111
    .line 112
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 113
    .line 114
    invoke-virtual {p0, p1}, Lnz/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    return-object p1

    .line 118
    :pswitch_6
    check-cast p1, Lvy0/b0;

    .line 119
    .line 120
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 121
    .line 122
    invoke-virtual {p0, p1, p2}, Lnz/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    check-cast p0, Lnz/g;

    .line 127
    .line 128
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 129
    .line 130
    invoke-virtual {p0, p1}, Lnz/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    return-object p1

    .line 134
    :pswitch_7
    check-cast p1, Llx0/l;

    .line 135
    .line 136
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 137
    .line 138
    invoke-virtual {p0, p1, p2}, Lnz/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    check-cast p0, Lnz/g;

    .line 143
    .line 144
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 145
    .line 146
    invoke-virtual {p0, p1}, Lnz/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    return-object p1

    .line 150
    :pswitch_8
    check-cast p1, Ljava/lang/String;

    .line 151
    .line 152
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 153
    .line 154
    invoke-virtual {p0, p1, p2}, Lnz/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 155
    .line 156
    .line 157
    move-result-object p0

    .line 158
    check-cast p0, Lnz/g;

    .line 159
    .line 160
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 161
    .line 162
    invoke-virtual {p0, p1}, Lnz/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    return-object p1

    .line 166
    :pswitch_9
    check-cast p1, Lvy0/b0;

    .line 167
    .line 168
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 169
    .line 170
    invoke-virtual {p0, p1, p2}, Lnz/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 171
    .line 172
    .line 173
    move-result-object p0

    .line 174
    check-cast p0, Lnz/g;

    .line 175
    .line 176
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 177
    .line 178
    invoke-virtual {p0, p1}, Lnz/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 179
    .line 180
    .line 181
    move-result-object p0

    .line 182
    return-object p0

    .line 183
    :pswitch_a
    check-cast p1, Lcn0/c;

    .line 184
    .line 185
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 186
    .line 187
    invoke-virtual {p0, p1, p2}, Lnz/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 188
    .line 189
    .line 190
    move-result-object p0

    .line 191
    check-cast p0, Lnz/g;

    .line 192
    .line 193
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 194
    .line 195
    invoke-virtual {p0, p1}, Lnz/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    return-object p1

    .line 199
    :pswitch_b
    check-cast p1, Lne0/s;

    .line 200
    .line 201
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 202
    .line 203
    invoke-virtual {p0, p1, p2}, Lnz/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 204
    .line 205
    .line 206
    move-result-object p0

    .line 207
    check-cast p0, Lnz/g;

    .line 208
    .line 209
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 210
    .line 211
    invoke-virtual {p0, p1}, Lnz/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    return-object p1

    .line 215
    :pswitch_c
    check-cast p1, Lne0/s;

    .line 216
    .line 217
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 218
    .line 219
    invoke-virtual {p0, p1, p2}, Lnz/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 220
    .line 221
    .line 222
    move-result-object p0

    .line 223
    check-cast p0, Lnz/g;

    .line 224
    .line 225
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 226
    .line 227
    invoke-virtual {p0, p1}, Lnz/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 228
    .line 229
    .line 230
    return-object p1

    .line 231
    :pswitch_d
    check-cast p1, Lvy0/b0;

    .line 232
    .line 233
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 234
    .line 235
    invoke-virtual {p0, p1, p2}, Lnz/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 236
    .line 237
    .line 238
    move-result-object p0

    .line 239
    check-cast p0, Lnz/g;

    .line 240
    .line 241
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 242
    .line 243
    invoke-virtual {p0, p1}, Lnz/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 244
    .line 245
    .line 246
    move-result-object p0

    .line 247
    return-object p0

    .line 248
    :pswitch_e
    check-cast p1, Lvy0/b0;

    .line 249
    .line 250
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 251
    .line 252
    invoke-virtual {p0, p1, p2}, Lnz/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 253
    .line 254
    .line 255
    move-result-object p0

    .line 256
    check-cast p0, Lnz/g;

    .line 257
    .line 258
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 259
    .line 260
    invoke-virtual {p0, p1}, Lnz/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 261
    .line 262
    .line 263
    return-object p1

    .line 264
    :pswitch_f
    check-cast p1, Lvy0/b0;

    .line 265
    .line 266
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 267
    .line 268
    invoke-virtual {p0, p1, p2}, Lnz/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 269
    .line 270
    .line 271
    move-result-object p0

    .line 272
    check-cast p0, Lnz/g;

    .line 273
    .line 274
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 275
    .line 276
    invoke-virtual {p0, p1}, Lnz/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 277
    .line 278
    .line 279
    return-object p1

    .line 280
    :pswitch_10
    check-cast p1, Lss0/b;

    .line 281
    .line 282
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 283
    .line 284
    invoke-virtual {p0, p1, p2}, Lnz/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 285
    .line 286
    .line 287
    move-result-object p0

    .line 288
    check-cast p0, Lnz/g;

    .line 289
    .line 290
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 291
    .line 292
    invoke-virtual {p0, p1}, Lnz/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 293
    .line 294
    .line 295
    return-object p1

    .line 296
    :pswitch_11
    check-cast p1, Lon0/h;

    .line 297
    .line 298
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 299
    .line 300
    invoke-virtual {p0, p1, p2}, Lnz/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 301
    .line 302
    .line 303
    move-result-object p0

    .line 304
    check-cast p0, Lnz/g;

    .line 305
    .line 306
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 307
    .line 308
    invoke-virtual {p0, p1}, Lnz/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 309
    .line 310
    .line 311
    return-object p1

    .line 312
    :pswitch_12
    check-cast p1, Lvy0/b0;

    .line 313
    .line 314
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 315
    .line 316
    invoke-virtual {p0, p1, p2}, Lnz/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 317
    .line 318
    .line 319
    move-result-object p0

    .line 320
    check-cast p0, Lnz/g;

    .line 321
    .line 322
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 323
    .line 324
    invoke-virtual {p0, p1}, Lnz/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 325
    .line 326
    .line 327
    return-object p1

    .line 328
    :pswitch_13
    check-cast p1, Lyr0/e;

    .line 329
    .line 330
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 331
    .line 332
    invoke-virtual {p0, p1, p2}, Lnz/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 333
    .line 334
    .line 335
    move-result-object p0

    .line 336
    check-cast p0, Lnz/g;

    .line 337
    .line 338
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 339
    .line 340
    invoke-virtual {p0, p1}, Lnz/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 341
    .line 342
    .line 343
    return-object p1

    .line 344
    :pswitch_14
    check-cast p1, Lqp0/o;

    .line 345
    .line 346
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 347
    .line 348
    invoke-virtual {p0, p1, p2}, Lnz/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 349
    .line 350
    .line 351
    move-result-object p0

    .line 352
    check-cast p0, Lnz/g;

    .line 353
    .line 354
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 355
    .line 356
    invoke-virtual {p0, p1}, Lnz/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 357
    .line 358
    .line 359
    return-object p1

    .line 360
    :pswitch_15
    check-cast p1, Lne0/s;

    .line 361
    .line 362
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 363
    .line 364
    invoke-virtual {p0, p1, p2}, Lnz/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 365
    .line 366
    .line 367
    move-result-object p0

    .line 368
    check-cast p0, Lnz/g;

    .line 369
    .line 370
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 371
    .line 372
    invoke-virtual {p0, p1}, Lnz/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 373
    .line 374
    .line 375
    return-object p1

    .line 376
    :pswitch_16
    check-cast p1, Lqp0/a;

    .line 377
    .line 378
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 379
    .line 380
    invoke-virtual {p0, p1, p2}, Lnz/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 381
    .line 382
    .line 383
    move-result-object p0

    .line 384
    check-cast p0, Lnz/g;

    .line 385
    .line 386
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 387
    .line 388
    invoke-virtual {p0, p1}, Lnz/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 389
    .line 390
    .line 391
    return-object p1

    .line 392
    :pswitch_17
    check-cast p1, Lvy0/b0;

    .line 393
    .line 394
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 395
    .line 396
    invoke-virtual {p0, p1, p2}, Lnz/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 397
    .line 398
    .line 399
    move-result-object p0

    .line 400
    check-cast p0, Lnz/g;

    .line 401
    .line 402
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 403
    .line 404
    invoke-virtual {p0, p1}, Lnz/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 405
    .line 406
    .line 407
    return-object p1

    .line 408
    :pswitch_18
    check-cast p1, Lvy0/b0;

    .line 409
    .line 410
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 411
    .line 412
    invoke-virtual {p0, p1, p2}, Lnz/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 413
    .line 414
    .line 415
    move-result-object p0

    .line 416
    check-cast p0, Lnz/g;

    .line 417
    .line 418
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 419
    .line 420
    invoke-virtual {p0, p1}, Lnz/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 421
    .line 422
    .line 423
    return-object p1

    .line 424
    :pswitch_19
    check-cast p1, Lvy0/b0;

    .line 425
    .line 426
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 427
    .line 428
    invoke-virtual {p0, p1, p2}, Lnz/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 429
    .line 430
    .line 431
    move-result-object p0

    .line 432
    check-cast p0, Lnz/g;

    .line 433
    .line 434
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 435
    .line 436
    invoke-virtual {p0, p1}, Lnz/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 437
    .line 438
    .line 439
    return-object p1

    .line 440
    :pswitch_1a
    check-cast p1, Lyy0/j;

    .line 441
    .line 442
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 443
    .line 444
    invoke-virtual {p0, p1, p2}, Lnz/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 445
    .line 446
    .line 447
    move-result-object p0

    .line 448
    check-cast p0, Lnz/g;

    .line 449
    .line 450
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 451
    .line 452
    invoke-virtual {p0, p1}, Lnz/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 453
    .line 454
    .line 455
    return-object p1

    .line 456
    :pswitch_1b
    check-cast p1, Lp30/c;

    .line 457
    .line 458
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 459
    .line 460
    invoke-virtual {p0, p1, p2}, Lnz/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 461
    .line 462
    .line 463
    move-result-object p0

    .line 464
    check-cast p0, Lnz/g;

    .line 465
    .line 466
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 467
    .line 468
    invoke-virtual {p0, p1}, Lnz/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 469
    .line 470
    .line 471
    return-object p1

    .line 472
    :pswitch_1c
    check-cast p1, Lvy0/b0;

    .line 473
    .line 474
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 475
    .line 476
    invoke-virtual {p0, p1, p2}, Lnz/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 477
    .line 478
    .line 479
    move-result-object p0

    .line 480
    check-cast p0, Lnz/g;

    .line 481
    .line 482
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 483
    .line 484
    invoke-virtual {p0, p1}, Lnz/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 485
    .line 486
    .line 487
    move-result-object p0

    .line 488
    return-object p0

    .line 489
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 36

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lnz/g;->d:I

    .line 4
    .line 5
    const-class v2, Landroid/content/pm/ShortcutManager;

    .line 6
    .line 7
    const-string v4, " "

    .line 8
    .line 9
    const-string v5, "\n"

    .line 10
    .line 11
    const/16 v7, 0xd

    .line 12
    .line 13
    const-string v8, "MULTI.MySkoda"

    .line 14
    .line 15
    const-string v10, ""

    .line 16
    .line 17
    const/16 v12, 0x8

    .line 18
    .line 19
    const/4 v13, 0x7

    .line 20
    const/4 v15, 0x5

    .line 21
    const/4 v3, 0x2

    .line 22
    const/16 v17, 0x1e

    .line 23
    .line 24
    const/4 v6, 0x0

    .line 25
    const/16 v18, 0x4

    .line 26
    .line 27
    const/4 v11, 0x1

    .line 28
    const/4 v14, 0x0

    .line 29
    sget-object v19, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    iget-object v9, v0, Lnz/g;->f:Ljava/lang/Object;

    .line 32
    .line 33
    packed-switch v1, :pswitch_data_0

    .line 34
    .line 35
    .line 36
    check-cast v9, Ls10/h;

    .line 37
    .line 38
    iget-object v0, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast v0, Lne0/t;

    .line 41
    .line 42
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 43
    .line 44
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    instance-of v1, v0, Lne0/c;

    .line 48
    .line 49
    if-eqz v1, :cond_0

    .line 50
    .line 51
    invoke-virtual {v9}, Lql0/j;->a()Lql0/h;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    check-cast v1, Ls10/g;

    .line 56
    .line 57
    check-cast v0, Lne0/c;

    .line 58
    .line 59
    iget-object v2, v9, Ls10/h;->j:Lij0/a;

    .line 60
    .line 61
    invoke-static {v0, v2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    invoke-static {v1, v0, v14, v3}, Ls10/g;->a(Ls10/g;Lql0/g;Ls10/f;I)Ls10/g;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    invoke-virtual {v9, v0}, Lql0/j;->g(Lql0/h;)V

    .line 70
    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_0
    instance-of v0, v0, Lne0/e;

    .line 74
    .line 75
    if-eqz v0, :cond_1

    .line 76
    .line 77
    iget-object v0, v9, Ls10/h;->i:Ltr0/b;

    .line 78
    .line 79
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    :goto_0
    return-object v19

    .line 83
    :cond_1
    new-instance v0, La8/r0;

    .line 84
    .line 85
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 86
    .line 87
    .line 88
    throw v0

    .line 89
    :pswitch_0
    invoke-direct/range {p0 .. p1}, Lnz/g;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    return-object v0

    .line 94
    :pswitch_1
    invoke-direct/range {p0 .. p1}, Lnz/g;->d(Ljava/lang/Object;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v0

    .line 98
    return-object v0

    .line 99
    :pswitch_2
    invoke-direct/range {p0 .. p1}, Lnz/g;->b(Ljava/lang/Object;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    return-object v0

    .line 104
    :pswitch_3
    iget-object v0, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 105
    .line 106
    check-cast v0, Lne0/s;

    .line 107
    .line 108
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 109
    .line 110
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    check-cast v9, Lro0/j;

    .line 114
    .line 115
    new-instance v1, Lro0/h;

    .line 116
    .line 117
    invoke-direct {v1, v0, v11}, Lro0/h;-><init>(Lne0/s;I)V

    .line 118
    .line 119
    .line 120
    invoke-static {v8, v9, v1}, Llp/nd;->f(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 121
    .line 122
    .line 123
    return-object v19

    .line 124
    :pswitch_4
    iget-object v0, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 125
    .line 126
    check-cast v0, Lne0/s;

    .line 127
    .line 128
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 129
    .line 130
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 131
    .line 132
    .line 133
    check-cast v9, Lro0/i;

    .line 134
    .line 135
    new-instance v1, Lro0/h;

    .line 136
    .line 137
    invoke-direct {v1, v0, v6}, Lro0/h;-><init>(Lne0/s;I)V

    .line 138
    .line 139
    .line 140
    invoke-static {v8, v9, v1}, Llp/nd;->f(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 141
    .line 142
    .line 143
    return-object v19

    .line 144
    :pswitch_5
    check-cast v9, Lr60/x;

    .line 145
    .line 146
    iget-object v0, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 147
    .line 148
    move-object/from16 v24, v0

    .line 149
    .line 150
    check-cast v24, Lon0/h;

    .line 151
    .line 152
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 153
    .line 154
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 155
    .line 156
    .line 157
    invoke-virtual/range {v24 .. v24}, Ljava/lang/Enum;->ordinal()I

    .line 158
    .line 159
    .line 160
    move-result v0

    .line 161
    if-eq v0, v15, :cond_2

    .line 162
    .line 163
    if-eq v0, v7, :cond_2

    .line 164
    .line 165
    if-eq v0, v13, :cond_2

    .line 166
    .line 167
    if-eq v0, v12, :cond_2

    .line 168
    .line 169
    const/16 v1, 0x9

    .line 170
    .line 171
    if-eq v0, v1, :cond_2

    .line 172
    .line 173
    goto/16 :goto_2

    .line 174
    .line 175
    :cond_2
    invoke-virtual {v9}, Lql0/j;->a()Lql0/h;

    .line 176
    .line 177
    .line 178
    move-result-object v0

    .line 179
    check-cast v0, Lr60/w;

    .line 180
    .line 181
    iget-object v0, v0, Lr60/w;->a:Ljava/util/List;

    .line 182
    .line 183
    check-cast v0, Ljava/util/Collection;

    .line 184
    .line 185
    invoke-static {v0}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 186
    .line 187
    .line 188
    move-result-object v0

    .line 189
    invoke-virtual {v9}, Lql0/j;->a()Lql0/h;

    .line 190
    .line 191
    .line 192
    move-result-object v1

    .line 193
    check-cast v1, Lr60/w;

    .line 194
    .line 195
    iget-object v1, v1, Lr60/w;->b:Lon0/e;

    .line 196
    .line 197
    if-eqz v1, :cond_5

    .line 198
    .line 199
    invoke-virtual {v9}, Lql0/j;->a()Lql0/h;

    .line 200
    .line 201
    .line 202
    move-result-object v1

    .line 203
    check-cast v1, Lr60/w;

    .line 204
    .line 205
    iget-object v1, v1, Lr60/w;->b:Lon0/e;

    .line 206
    .line 207
    if-eqz v1, :cond_3

    .line 208
    .line 209
    iget-object v1, v1, Lon0/e;->g:Ljava/time/OffsetDateTime;

    .line 210
    .line 211
    goto :goto_1

    .line 212
    :cond_3
    move-object v1, v14

    .line 213
    :goto_1
    invoke-static {v1}, Ljava/time/YearMonth;->from(Ljava/time/temporal/TemporalAccessor;)Ljava/time/YearMonth;

    .line 214
    .line 215
    .line 216
    move-result-object v1

    .line 217
    sget-object v2, Lr60/u;->e:Lr60/u;

    .line 218
    .line 219
    invoke-virtual {v9}, Lql0/j;->a()Lql0/h;

    .line 220
    .line 221
    .line 222
    move-result-object v3

    .line 223
    check-cast v3, Lr60/w;

    .line 224
    .line 225
    iget-object v3, v3, Lr60/w;->b:Lon0/e;

    .line 226
    .line 227
    if-eqz v3, :cond_4

    .line 228
    .line 229
    iget-object v4, v3, Lon0/e;->a:Ljava/lang/String;

    .line 230
    .line 231
    iget-object v5, v3, Lon0/e;->b:Ljava/lang/String;

    .line 232
    .line 233
    iget-object v6, v3, Lon0/e;->c:Ljava/lang/String;

    .line 234
    .line 235
    iget-object v7, v3, Lon0/e;->e:Lon0/d;

    .line 236
    .line 237
    iget-object v8, v3, Lon0/e;->f:Ljava/lang/String;

    .line 238
    .line 239
    iget-object v10, v3, Lon0/e;->g:Ljava/time/OffsetDateTime;

    .line 240
    .line 241
    iget-object v12, v3, Lon0/e;->h:Ljava/lang/String;

    .line 242
    .line 243
    iget-object v13, v3, Lon0/e;->i:Ljava/lang/String;

    .line 244
    .line 245
    iget-object v14, v3, Lon0/e;->j:Ljava/lang/Double;

    .line 246
    .line 247
    iget-object v3, v3, Lon0/e;->k:Lon0/l;

    .line 248
    .line 249
    const-string v15, "id"

    .line 250
    .line 251
    invoke-static {v4, v15}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 252
    .line 253
    .line 254
    const-string v15, "locationId"

    .line 255
    .line 256
    invoke-static {v5, v15}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 257
    .line 258
    .line 259
    const-string v15, "formattedCardName"

    .line 260
    .line 261
    invoke-static {v6, v15}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 262
    .line 263
    .line 264
    new-instance v20, Lon0/e;

    .line 265
    .line 266
    move-object/from16 v31, v3

    .line 267
    .line 268
    move-object/from16 v21, v4

    .line 269
    .line 270
    move-object/from16 v22, v5

    .line 271
    .line 272
    move-object/from16 v23, v6

    .line 273
    .line 274
    move-object/from16 v25, v7

    .line 275
    .line 276
    move-object/from16 v26, v8

    .line 277
    .line 278
    move-object/from16 v27, v10

    .line 279
    .line 280
    move-object/from16 v28, v12

    .line 281
    .line 282
    move-object/from16 v29, v13

    .line 283
    .line 284
    move-object/from16 v30, v14

    .line 285
    .line 286
    invoke-direct/range {v20 .. v31}, Lon0/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lon0/h;Lon0/d;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Double;Lon0/l;)V

    .line 287
    .line 288
    .line 289
    move-object/from16 v14, v20

    .line 290
    .line 291
    :cond_4
    new-instance v3, Lr60/v;

    .line 292
    .line 293
    invoke-direct {v3, v2, v1, v14}, Lr60/v;-><init>(Lr60/u;Ljava/time/YearMonth;Lon0/e;)V

    .line 294
    .line 295
    .line 296
    invoke-virtual {v0, v11, v3}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 297
    .line 298
    .line 299
    :cond_5
    invoke-virtual {v9}, Lql0/j;->a()Lql0/h;

    .line 300
    .line 301
    .line 302
    move-result-object v1

    .line 303
    move-object v2, v1

    .line 304
    check-cast v2, Lr60/w;

    .line 305
    .line 306
    invoke-static {v0}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 307
    .line 308
    .line 309
    move-result-object v3

    .line 310
    const/4 v6, 0x0

    .line 311
    const/16 v7, 0xc

    .line 312
    .line 313
    const/4 v4, 0x0

    .line 314
    const/4 v5, 0x0

    .line 315
    invoke-static/range {v2 .. v7}, Lr60/w;->a(Lr60/w;Ljava/util/List;Lon0/e;Lql0/g;ZI)Lr60/w;

    .line 316
    .line 317
    .line 318
    move-result-object v0

    .line 319
    invoke-virtual {v9, v0}, Lql0/j;->g(Lql0/h;)V

    .line 320
    .line 321
    .line 322
    :goto_2
    return-object v19

    .line 323
    :pswitch_6
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 324
    .line 325
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 326
    .line 327
    .line 328
    iget-object v0, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 329
    .line 330
    check-cast v0, Lr60/s;

    .line 331
    .line 332
    iget-object v0, v0, Lr60/s;->m:Lbd0/c;

    .line 333
    .line 334
    check-cast v9, Ljava/lang/String;

    .line 335
    .line 336
    and-int/lit8 v1, v17, 0x2

    .line 337
    .line 338
    if-eqz v1, :cond_6

    .line 339
    .line 340
    move/from16 v22, v11

    .line 341
    .line 342
    goto :goto_3

    .line 343
    :cond_6
    move/from16 v22, v6

    .line 344
    .line 345
    :goto_3
    and-int/lit8 v1, v17, 0x4

    .line 346
    .line 347
    if-eqz v1, :cond_7

    .line 348
    .line 349
    move/from16 v23, v11

    .line 350
    .line 351
    goto :goto_4

    .line 352
    :cond_7
    move/from16 v23, v6

    .line 353
    .line 354
    :goto_4
    and-int/lit8 v1, v17, 0x8

    .line 355
    .line 356
    if-eqz v1, :cond_8

    .line 357
    .line 358
    move/from16 v24, v6

    .line 359
    .line 360
    goto :goto_5

    .line 361
    :cond_8
    move/from16 v24, v11

    .line 362
    .line 363
    :goto_5
    and-int/lit8 v1, v17, 0x10

    .line 364
    .line 365
    if-eqz v1, :cond_9

    .line 366
    .line 367
    move/from16 v25, v6

    .line 368
    .line 369
    goto :goto_6

    .line 370
    :cond_9
    move/from16 v25, v11

    .line 371
    .line 372
    :goto_6
    const-string v1, "url"

    .line 373
    .line 374
    invoke-static {v9, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 375
    .line 376
    .line 377
    iget-object v0, v0, Lbd0/c;->a:Lbd0/a;

    .line 378
    .line 379
    new-instance v1, Ljava/net/URL;

    .line 380
    .line 381
    invoke-direct {v1, v9}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 382
    .line 383
    .line 384
    move-object/from16 v20, v0

    .line 385
    .line 386
    check-cast v20, Lzc0/b;

    .line 387
    .line 388
    move-object/from16 v21, v1

    .line 389
    .line 390
    invoke-virtual/range {v20 .. v25}, Lzc0/b;->b(Ljava/net/URL;ZZZZ)Lyy0/m1;

    .line 391
    .line 392
    .line 393
    return-object v19

    .line 394
    :pswitch_7
    check-cast v9, Lr60/g;

    .line 395
    .line 396
    iget-object v0, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 397
    .line 398
    check-cast v0, Llx0/l;

    .line 399
    .line 400
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 401
    .line 402
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 403
    .line 404
    .line 405
    iget-object v1, v0, Llx0/l;->d:Ljava/lang/Object;

    .line 406
    .line 407
    check-cast v1, Lne0/s;

    .line 408
    .line 409
    iget-object v0, v0, Llx0/l;->e:Ljava/lang/Object;

    .line 410
    .line 411
    check-cast v0, Lne0/s;

    .line 412
    .line 413
    instance-of v2, v1, Lne0/d;

    .line 414
    .line 415
    if-eqz v2, :cond_a

    .line 416
    .line 417
    invoke-virtual {v9}, Lql0/j;->a()Lql0/h;

    .line 418
    .line 419
    .line 420
    move-result-object v0

    .line 421
    move-object/from16 v20, v0

    .line 422
    .line 423
    check-cast v20, Lr60/b;

    .line 424
    .line 425
    const/16 v30, 0x0

    .line 426
    .line 427
    const/16 v31, 0x3f7

    .line 428
    .line 429
    const/16 v21, 0x0

    .line 430
    .line 431
    const/16 v22, 0x0

    .line 432
    .line 433
    const/16 v23, 0x0

    .line 434
    .line 435
    const/16 v24, 0x1

    .line 436
    .line 437
    const/16 v25, 0x0

    .line 438
    .line 439
    const/16 v26, 0x0

    .line 440
    .line 441
    const/16 v27, 0x0

    .line 442
    .line 443
    const/16 v28, 0x0

    .line 444
    .line 445
    const/16 v29, 0x0

    .line 446
    .line 447
    invoke-static/range {v20 .. v31}, Lr60/b;->a(Lr60/b;Ljava/lang/String;ZLql0/g;ZLjava/lang/String;Ljava/util/List;Ljava/lang/String;ZLon0/a0;Ljava/lang/String;I)Lr60/b;

    .line 448
    .line 449
    .line 450
    move-result-object v0

    .line 451
    invoke-virtual {v9, v0}, Lql0/j;->g(Lql0/h;)V

    .line 452
    .line 453
    .line 454
    goto/16 :goto_8

    .line 455
    .line 456
    :cond_a
    instance-of v2, v1, Lne0/c;

    .line 457
    .line 458
    if-eqz v2, :cond_b

    .line 459
    .line 460
    check-cast v1, Lne0/c;

    .line 461
    .line 462
    invoke-static {v9, v1}, Lr60/g;->j(Lr60/g;Lne0/c;)V

    .line 463
    .line 464
    .line 465
    goto/16 :goto_8

    .line 466
    .line 467
    :cond_b
    instance-of v2, v0, Lne0/d;

    .line 468
    .line 469
    if-eqz v2, :cond_c

    .line 470
    .line 471
    invoke-virtual {v9}, Lql0/j;->a()Lql0/h;

    .line 472
    .line 473
    .line 474
    move-result-object v0

    .line 475
    move-object/from16 v20, v0

    .line 476
    .line 477
    check-cast v20, Lr60/b;

    .line 478
    .line 479
    const/16 v30, 0x0

    .line 480
    .line 481
    const/16 v31, 0x3f7

    .line 482
    .line 483
    const/16 v21, 0x0

    .line 484
    .line 485
    const/16 v22, 0x0

    .line 486
    .line 487
    const/16 v23, 0x0

    .line 488
    .line 489
    const/16 v24, 0x1

    .line 490
    .line 491
    const/16 v25, 0x0

    .line 492
    .line 493
    const/16 v26, 0x0

    .line 494
    .line 495
    const/16 v27, 0x0

    .line 496
    .line 497
    const/16 v28, 0x0

    .line 498
    .line 499
    const/16 v29, 0x0

    .line 500
    .line 501
    invoke-static/range {v20 .. v31}, Lr60/b;->a(Lr60/b;Ljava/lang/String;ZLql0/g;ZLjava/lang/String;Ljava/util/List;Ljava/lang/String;ZLon0/a0;Ljava/lang/String;I)Lr60/b;

    .line 502
    .line 503
    .line 504
    move-result-object v0

    .line 505
    invoke-virtual {v9, v0}, Lql0/j;->g(Lql0/h;)V

    .line 506
    .line 507
    .line 508
    goto/16 :goto_8

    .line 509
    .line 510
    :cond_c
    instance-of v2, v0, Lne0/c;

    .line 511
    .line 512
    if-eqz v2, :cond_d

    .line 513
    .line 514
    check-cast v0, Lne0/c;

    .line 515
    .line 516
    invoke-static {v9, v0}, Lr60/g;->j(Lr60/g;Lne0/c;)V

    .line 517
    .line 518
    .line 519
    goto/16 :goto_8

    .line 520
    .line 521
    :cond_d
    instance-of v2, v0, Lne0/e;

    .line 522
    .line 523
    if-eqz v2, :cond_12

    .line 524
    .line 525
    instance-of v2, v1, Lne0/e;

    .line 526
    .line 527
    if-eqz v2, :cond_12

    .line 528
    .line 529
    check-cast v0, Lne0/e;

    .line 530
    .line 531
    iget-object v0, v0, Lne0/e;->a:Ljava/lang/Object;

    .line 532
    .line 533
    check-cast v0, Lon0/q;

    .line 534
    .line 535
    check-cast v1, Lne0/e;

    .line 536
    .line 537
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 538
    .line 539
    check-cast v1, Lss0/k;

    .line 540
    .line 541
    iget-object v1, v1, Lss0/k;->c:Ljava/lang/String;

    .line 542
    .line 543
    if-nez v1, :cond_e

    .line 544
    .line 545
    move-object v1, v10

    .line 546
    :cond_e
    invoke-virtual {v9}, Lql0/j;->a()Lql0/h;

    .line 547
    .line 548
    .line 549
    move-result-object v2

    .line 550
    move-object/from16 v20, v2

    .line 551
    .line 552
    check-cast v20, Lr60/b;

    .line 553
    .line 554
    invoke-static {v1}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 555
    .line 556
    .line 557
    move-result v2

    .line 558
    if-eqz v2, :cond_f

    .line 559
    .line 560
    iget-object v1, v0, Lon0/q;->f:Ljava/util/ArrayList;

    .line 561
    .line 562
    invoke-static {v1}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 563
    .line 564
    .line 565
    move-result-object v1

    .line 566
    check-cast v1, Lon0/p;

    .line 567
    .line 568
    iget-object v1, v1, Lon0/p;->c:Ljava/lang/String;

    .line 569
    .line 570
    :cond_f
    move-object/from16 v25, v1

    .line 571
    .line 572
    iget-object v1, v0, Lon0/q;->e:Lon0/n;

    .line 573
    .line 574
    iget-object v2, v1, Lon0/n;->e:Ljava/lang/String;

    .line 575
    .line 576
    iget-object v6, v1, Lon0/n;->c:Ljava/lang/String;

    .line 577
    .line 578
    iget-object v7, v1, Lon0/n;->d:Ljava/lang/String;

    .line 579
    .line 580
    iget-object v8, v1, Lon0/n;->a:Ljava/lang/String;

    .line 581
    .line 582
    iget-object v1, v1, Lon0/n;->b:Ljava/lang/String;

    .line 583
    .line 584
    const-string v11, "isoCode"

    .line 585
    .line 586
    invoke-static {v1, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 587
    .line 588
    .line 589
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 590
    .line 591
    .line 592
    move-result v11

    .line 593
    if-ne v11, v3, :cond_11

    .line 594
    .line 595
    sget-object v3, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 596
    .line 597
    invoke-virtual {v1, v3}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 598
    .line 599
    .line 600
    move-result-object v1

    .line 601
    const-string v3, "toUpperCase(...)"

    .line 602
    .line 603
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 604
    .line 605
    .line 606
    invoke-static {v1}, Lcom/google/android/gms/internal/measurement/j4;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 607
    .line 608
    .line 609
    move-result-object v1

    .line 610
    new-instance v3, Ljava/lang/StringBuilder;

    .line 611
    .line 612
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    .line 613
    .line 614
    .line 615
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 616
    .line 617
    .line 618
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 619
    .line 620
    .line 621
    invoke-virtual {v3, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 622
    .line 623
    .line 624
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 625
    .line 626
    .line 627
    invoke-virtual {v3, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 628
    .line 629
    .line 630
    invoke-static {v3, v4, v8, v5, v1}, Lvj/b;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 631
    .line 632
    .line 633
    move-result-object v1

    .line 634
    if-nez v1, :cond_10

    .line 635
    .line 636
    move-object/from16 v21, v10

    .line 637
    .line 638
    goto :goto_7

    .line 639
    :cond_10
    move-object/from16 v21, v1

    .line 640
    .line 641
    :goto_7
    iget-object v0, v0, Lon0/q;->g:Ljava/util/List;

    .line 642
    .line 643
    invoke-static {v0}, Lr60/g;->k(Ljava/util/List;)Lon0/a0;

    .line 644
    .line 645
    .line 646
    move-result-object v29

    .line 647
    const/16 v30, 0x0

    .line 648
    .line 649
    const/16 v31, 0x2c6

    .line 650
    .line 651
    const/16 v22, 0x0

    .line 652
    .line 653
    const/16 v23, 0x0

    .line 654
    .line 655
    const/16 v24, 0x0

    .line 656
    .line 657
    const/16 v27, 0x0

    .line 658
    .line 659
    const/16 v28, 0x0

    .line 660
    .line 661
    move-object/from16 v26, v0

    .line 662
    .line 663
    invoke-static/range {v20 .. v31}, Lr60/b;->a(Lr60/b;Ljava/lang/String;ZLql0/g;ZLjava/lang/String;Ljava/util/List;Ljava/lang/String;ZLon0/a0;Ljava/lang/String;I)Lr60/b;

    .line 664
    .line 665
    .line 666
    move-result-object v0

    .line 667
    invoke-virtual {v9, v0}, Lql0/j;->g(Lql0/h;)V

    .line 668
    .line 669
    .line 670
    goto :goto_8

    .line 671
    :cond_11
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 672
    .line 673
    const-string v1, "Iso code doesn\'t match ISO 3166-1 Alpha-2"

    .line 674
    .line 675
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 676
    .line 677
    .line 678
    throw v0

    .line 679
    :cond_12
    :goto_8
    return-object v19

    .line 680
    :pswitch_8
    iget-object v0, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 681
    .line 682
    check-cast v0, Ljava/lang/String;

    .line 683
    .line 684
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 685
    .line 686
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 687
    .line 688
    .line 689
    check-cast v9, Lr31/i;

    .line 690
    .line 691
    const-string v1, "text"

    .line 692
    .line 693
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 694
    .line 695
    .line 696
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 697
    .line 698
    .line 699
    iget-object v1, v9, Lr31/i;->i:Lk31/e0;

    .line 700
    .line 701
    invoke-virtual {v1, v0}, Lk31/e0;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 702
    .line 703
    .line 704
    move-result-object v1

    .line 705
    iget-object v2, v9, Lq41/b;->d:Lyy0/c2;

    .line 706
    .line 707
    :cond_13
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 708
    .line 709
    .line 710
    move-result-object v0

    .line 711
    move-object v3, v0

    .line 712
    check-cast v3, Lr31/j;

    .line 713
    .line 714
    invoke-static {v1}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 715
    .line 716
    .line 717
    move-result v4

    .line 718
    xor-int/2addr v4, v11

    .line 719
    const/16 v5, 0x1a

    .line 720
    .line 721
    invoke-static {v3, v1, v4, v6, v5}, Lr31/j;->a(Lr31/j;Ljava/lang/String;ZZI)Lr31/j;

    .line 722
    .line 723
    .line 724
    move-result-object v3

    .line 725
    invoke-virtual {v2, v0, v3}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 726
    .line 727
    .line 728
    move-result v0

    .line 729
    if-eqz v0, :cond_13

    .line 730
    .line 731
    return-object v19

    .line 732
    :pswitch_9
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 733
    .line 734
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 735
    .line 736
    .line 737
    iget-object v0, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 738
    .line 739
    check-cast v0, Lqi/a;

    .line 740
    .line 741
    iget-object v0, v0, Lqi/a;->a:Landroid/content/SharedPreferences;

    .line 742
    .line 743
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 744
    .line 745
    .line 746
    move-result-object v0

    .line 747
    sget-object v1, Lqi/b;->a:Lvz0/t;

    .line 748
    .line 749
    check-cast v9, Lmi/c;

    .line 750
    .line 751
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 752
    .line 753
    .line 754
    sget-object v2, Lmi/c;->Companion:Lmi/b;

    .line 755
    .line 756
    invoke-virtual {v2}, Lmi/b;->serializer()Lqz0/a;

    .line 757
    .line 758
    .line 759
    move-result-object v2

    .line 760
    check-cast v2, Lqz0/a;

    .line 761
    .line 762
    invoke-virtual {v1, v2, v9}, Lvz0/d;->d(Lqz0/a;Ljava/lang/Object;)Ljava/lang/String;

    .line 763
    .line 764
    .line 765
    move-result-object v1

    .line 766
    const-string v2, "data"

    .line 767
    .line 768
    invoke-interface {v0, v2, v1}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 769
    .line 770
    .line 771
    move-result-object v0

    .line 772
    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->commit()Z

    .line 773
    .line 774
    .line 775
    move-result v0

    .line 776
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 777
    .line 778
    .line 779
    move-result-object v0

    .line 780
    return-object v0

    .line 781
    :pswitch_a
    check-cast v9, Lqd0/j0;

    .line 782
    .line 783
    iget-object v0, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 784
    .line 785
    check-cast v0, Lcn0/c;

    .line 786
    .line 787
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 788
    .line 789
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 790
    .line 791
    .line 792
    if-eqz v0, :cond_14

    .line 793
    .line 794
    iget-object v14, v0, Lcn0/c;->e:Lcn0/a;

    .line 795
    .line 796
    :cond_14
    if-nez v14, :cond_15

    .line 797
    .line 798
    const/4 v1, -0x1

    .line 799
    goto :goto_9

    .line 800
    :cond_15
    sget-object v1, Lqd0/i0;->a:[I

    .line 801
    .line 802
    invoke-virtual {v14}, Ljava/lang/Enum;->ordinal()I

    .line 803
    .line 804
    .line 805
    move-result v2

    .line 806
    aget v1, v1, v2

    .line 807
    .line 808
    :goto_9
    if-eq v1, v11, :cond_17

    .line 809
    .line 810
    if-eq v1, v3, :cond_16

    .line 811
    .line 812
    goto :goto_a

    .line 813
    :cond_16
    sget-object v1, Lrd0/w;->c:Lrd0/w;

    .line 814
    .line 815
    invoke-static {v9, v0, v1}, Lqd0/j0;->a(Lqd0/j0;Lcn0/c;Lkr0/c;)V

    .line 816
    .line 817
    .line 818
    goto :goto_a

    .line 819
    :cond_17
    sget-object v1, Lrd0/w;->b:Lrd0/w;

    .line 820
    .line 821
    invoke-static {v9, v0, v1}, Lqd0/j0;->a(Lqd0/j0;Lcn0/c;Lkr0/c;)V

    .line 822
    .line 823
    .line 824
    :goto_a
    return-object v19

    .line 825
    :pswitch_b
    iget-object v0, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 826
    .line 827
    check-cast v0, Lne0/s;

    .line 828
    .line 829
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 830
    .line 831
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 832
    .line 833
    .line 834
    check-cast v9, Lqd0/i;

    .line 835
    .line 836
    iget-object v1, v9, Lqd0/i;->b:Lqd0/z;

    .line 837
    .line 838
    check-cast v1, Lod0/v;

    .line 839
    .line 840
    invoke-virtual {v1, v0}, Lod0/v;->b(Lne0/s;)V

    .line 841
    .line 842
    .line 843
    return-object v19

    .line 844
    :pswitch_c
    iget-object v0, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 845
    .line 846
    check-cast v0, Lne0/s;

    .line 847
    .line 848
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 849
    .line 850
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 851
    .line 852
    .line 853
    check-cast v9, Lqa0/b;

    .line 854
    .line 855
    iget-object v1, v9, Lqa0/b;->c:Lqa0/c;

    .line 856
    .line 857
    check-cast v1, Loa0/a;

    .line 858
    .line 859
    iget-object v2, v1, Loa0/a;->a:Lwe0/a;

    .line 860
    .line 861
    const-string v3, "readinessStatus"

    .line 862
    .line 863
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 864
    .line 865
    .line 866
    iget-object v1, v1, Loa0/a;->c:Lyy0/c2;

    .line 867
    .line 868
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 869
    .line 870
    .line 871
    invoke-virtual {v1, v14, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 872
    .line 873
    .line 874
    instance-of v0, v0, Lne0/e;

    .line 875
    .line 876
    if-eqz v0, :cond_18

    .line 877
    .line 878
    check-cast v2, Lwe0/c;

    .line 879
    .line 880
    invoke-virtual {v2}, Lwe0/c;->c()V

    .line 881
    .line 882
    .line 883
    goto :goto_b

    .line 884
    :cond_18
    check-cast v2, Lwe0/c;

    .line 885
    .line 886
    invoke-virtual {v2}, Lwe0/c;->a()V

    .line 887
    .line 888
    .line 889
    :goto_b
    return-object v19

    .line 890
    :pswitch_d
    iget-object v0, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 891
    .line 892
    move-object v1, v0

    .line 893
    check-cast v1, Lvy0/b0;

    .line 894
    .line 895
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 896
    .line 897
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 898
    .line 899
    .line 900
    check-cast v9, Lq70/i;

    .line 901
    .line 902
    iget-object v0, v9, Lq70/i;->a:Lyw/b;

    .line 903
    .line 904
    const-string v2, "\\A"

    .line 905
    .line 906
    new-instance v7, Ljava/util/ArrayList;

    .line 907
    .line 908
    sget-object v8, Lyw/a;->a:[Ljava/lang/String;

    .line 909
    .line 910
    invoke-static {v8}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 911
    .line 912
    .line 913
    move-result-object v8

    .line 914
    invoke-direct {v7, v8}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 915
    .line 916
    .line 917
    invoke-virtual {v0, v7}, Lyw/b;->b(Ljava/util/ArrayList;)Z

    .line 918
    .line 919
    .line 920
    move-result v7

    .line 921
    if-nez v7, :cond_2d

    .line 922
    .line 923
    new-instance v7, Ljava/util/ArrayList;

    .line 924
    .line 925
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 926
    .line 927
    .line 928
    sget-object v8, Lyw/a;->b:[Ljava/lang/String;

    .line 929
    .line 930
    invoke-static {v8}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 931
    .line 932
    .line 933
    move-result-object v8

    .line 934
    invoke-virtual {v7, v8}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 935
    .line 936
    .line 937
    invoke-virtual {v0, v7}, Lyw/b;->b(Ljava/util/ArrayList;)Z

    .line 938
    .line 939
    .line 940
    move-result v0

    .line 941
    if-nez v0, :cond_2d

    .line 942
    .line 943
    const-string v7, "su"

    .line 944
    .line 945
    invoke-static {v7}, Lyw/b;->a(Ljava/lang/String;)Z

    .line 946
    .line 947
    .line 948
    move-result v0

    .line 949
    if-nez v0, :cond_2d

    .line 950
    .line 951
    new-instance v8, Ljava/util/HashMap;

    .line 952
    .line 953
    invoke-direct {v8}, Ljava/util/HashMap;-><init>()V

    .line 954
    .line 955
    .line 956
    const-string v0, "ro.debuggable"

    .line 957
    .line 958
    const-string v9, "1"

    .line 959
    .line 960
    invoke-virtual {v8, v0, v9}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 961
    .line 962
    .line 963
    const-string v0, "ro.secure"

    .line 964
    .line 965
    const-string v9, "0"

    .line 966
    .line 967
    invoke-virtual {v8, v0, v9}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 968
    .line 969
    .line 970
    :try_start_0
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;

    .line 971
    .line 972
    .line 973
    move-result-object v0

    .line 974
    const-string v9, "getprop"

    .line 975
    .line 976
    invoke-virtual {v0, v9}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;

    .line 977
    .line 978
    .line 979
    move-result-object v0

    .line 980
    invoke-virtual {v0}, Ljava/lang/Process;->getInputStream()Ljava/io/InputStream;

    .line 981
    .line 982
    .line 983
    move-result-object v0

    .line 984
    if-nez v0, :cond_19

    .line 985
    .line 986
    :goto_c
    move-object v0, v14

    .line 987
    goto :goto_d

    .line 988
    :cond_19
    new-instance v9, Ljava/util/Scanner;

    .line 989
    .line 990
    invoke-direct {v9, v0}, Ljava/util/Scanner;-><init>(Ljava/io/InputStream;)V

    .line 991
    .line 992
    .line 993
    invoke-virtual {v9, v2}, Ljava/util/Scanner;->useDelimiter(Ljava/lang/String;)Ljava/util/Scanner;

    .line 994
    .line 995
    .line 996
    move-result-object v0

    .line 997
    invoke-virtual {v0}, Ljava/util/Scanner;->next()Ljava/lang/String;

    .line 998
    .line 999
    .line 1000
    move-result-object v0

    .line 1001
    invoke-virtual {v0, v5}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 1002
    .line 1003
    .line 1004
    move-result-object v0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/util/NoSuchElementException; {:try_start_0 .. :try_end_0} :catch_0

    .line 1005
    goto :goto_d

    .line 1006
    :catch_0
    move-exception v0

    .line 1007
    invoke-virtual {v0}, Ljava/lang/Throwable;->printStackTrace()V

    .line 1008
    .line 1009
    .line 1010
    goto :goto_c

    .line 1011
    :goto_d
    if-nez v0, :cond_1b

    .line 1012
    .line 1013
    move/from16 v16, v6

    .line 1014
    .line 1015
    :cond_1a
    move/from16 v21, v3

    .line 1016
    .line 1017
    move/from16 v23, v15

    .line 1018
    .line 1019
    goto/16 :goto_11

    .line 1020
    .line 1021
    :cond_1b
    array-length v9, v0

    .line 1022
    move v12, v6

    .line 1023
    move/from16 v16, v12

    .line 1024
    .line 1025
    :goto_e
    if-ge v12, v9, :cond_1a

    .line 1026
    .line 1027
    move/from16 v21, v3

    .line 1028
    .line 1029
    aget-object v3, v0, v12

    .line 1030
    .line 1031
    invoke-virtual {v8}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    .line 1032
    .line 1033
    .line 1034
    move-result-object v17

    .line 1035
    invoke-interface/range {v17 .. v17}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 1036
    .line 1037
    .line 1038
    move-result-object v17

    .line 1039
    :goto_f
    invoke-interface/range {v17 .. v17}, Ljava/util/Iterator;->hasNext()Z

    .line 1040
    .line 1041
    .line 1042
    move-result v18

    .line 1043
    if-eqz v18, :cond_1e

    .line 1044
    .line 1045
    invoke-interface/range {v17 .. v17}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1046
    .line 1047
    .line 1048
    move-result-object v18

    .line 1049
    move-object/from16 v6, v18

    .line 1050
    .line 1051
    check-cast v6, Ljava/lang/String;

    .line 1052
    .line 1053
    invoke-virtual {v3, v6}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 1054
    .line 1055
    .line 1056
    move-result v18

    .line 1057
    if-eqz v18, :cond_1c

    .line 1058
    .line 1059
    invoke-virtual {v8, v6}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1060
    .line 1061
    .line 1062
    move-result-object v18

    .line 1063
    move/from16 v23, v15

    .line 1064
    .line 1065
    move-object/from16 v15, v18

    .line 1066
    .line 1067
    check-cast v15, Ljava/lang/String;

    .line 1068
    .line 1069
    const-string v14, "["

    .line 1070
    .line 1071
    const-string v11, "]"

    .line 1072
    .line 1073
    invoke-static {v14, v15, v11}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1074
    .line 1075
    .line 1076
    move-result-object v11

    .line 1077
    invoke-virtual {v3, v11}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 1078
    .line 1079
    .line 1080
    move-result v14

    .line 1081
    if-eqz v14, :cond_1d

    .line 1082
    .line 1083
    new-instance v14, Ljava/lang/StringBuilder;

    .line 1084
    .line 1085
    invoke-direct {v14}, Ljava/lang/StringBuilder;-><init>()V

    .line 1086
    .line 1087
    .line 1088
    invoke-virtual {v14, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1089
    .line 1090
    .line 1091
    const-string v6, " = "

    .line 1092
    .line 1093
    invoke-virtual {v14, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1094
    .line 1095
    .line 1096
    invoke-virtual {v14, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1097
    .line 1098
    .line 1099
    const-string v6, " detected!"

    .line 1100
    .line 1101
    invoke-virtual {v14, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1102
    .line 1103
    .line 1104
    invoke-virtual {v14}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1105
    .line 1106
    .line 1107
    move-result-object v6

    .line 1108
    invoke-static {v6}, Ljp/o1;->e(Ljava/lang/String;)V

    .line 1109
    .line 1110
    .line 1111
    const/16 v16, 0x1

    .line 1112
    .line 1113
    goto :goto_10

    .line 1114
    :cond_1c
    move/from16 v23, v15

    .line 1115
    .line 1116
    :cond_1d
    :goto_10
    move/from16 v15, v23

    .line 1117
    .line 1118
    const/4 v6, 0x0

    .line 1119
    const/4 v11, 0x1

    .line 1120
    const/4 v14, 0x0

    .line 1121
    goto :goto_f

    .line 1122
    :cond_1e
    move/from16 v23, v15

    .line 1123
    .line 1124
    add-int/lit8 v12, v12, 0x1

    .line 1125
    .line 1126
    move/from16 v3, v21

    .line 1127
    .line 1128
    const/4 v6, 0x0

    .line 1129
    const/4 v11, 0x1

    .line 1130
    const/4 v14, 0x0

    .line 1131
    goto :goto_e

    .line 1132
    :goto_11
    if-nez v16, :cond_2d

    .line 1133
    .line 1134
    :try_start_1
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;

    .line 1135
    .line 1136
    .line 1137
    move-result-object v0

    .line 1138
    const-string v3, "mount"

    .line 1139
    .line 1140
    invoke-virtual {v0, v3}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;

    .line 1141
    .line 1142
    .line 1143
    move-result-object v0

    .line 1144
    invoke-virtual {v0}, Ljava/lang/Process;->getInputStream()Ljava/io/InputStream;

    .line 1145
    .line 1146
    .line 1147
    move-result-object v0

    .line 1148
    if-nez v0, :cond_1f

    .line 1149
    .line 1150
    :goto_12
    const/4 v0, 0x0

    .line 1151
    goto :goto_13

    .line 1152
    :cond_1f
    new-instance v3, Ljava/util/Scanner;

    .line 1153
    .line 1154
    invoke-direct {v3, v0}, Ljava/util/Scanner;-><init>(Ljava/io/InputStream;)V

    .line 1155
    .line 1156
    .line 1157
    invoke-virtual {v3, v2}, Ljava/util/Scanner;->useDelimiter(Ljava/lang/String;)Ljava/util/Scanner;

    .line 1158
    .line 1159
    .line 1160
    move-result-object v0

    .line 1161
    invoke-virtual {v0}, Ljava/util/Scanner;->next()Ljava/lang/String;

    .line 1162
    .line 1163
    .line 1164
    move-result-object v0

    .line 1165
    invoke-virtual {v0, v5}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 1166
    .line 1167
    .line 1168
    move-result-object v0
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/util/NoSuchElementException; {:try_start_1 .. :try_end_1} :catch_1

    .line 1169
    goto :goto_13

    .line 1170
    :catch_1
    move-exception v0

    .line 1171
    invoke-virtual {v0}, Ljava/lang/Throwable;->printStackTrace()V

    .line 1172
    .line 1173
    .line 1174
    goto :goto_12

    .line 1175
    :goto_13
    if-nez v0, :cond_20

    .line 1176
    .line 1177
    const/4 v5, 0x0

    .line 1178
    goto/16 :goto_1a

    .line 1179
    .line 1180
    :cond_20
    array-length v2, v0

    .line 1181
    const/4 v3, 0x0

    .line 1182
    const/4 v5, 0x0

    .line 1183
    :goto_14
    if-ge v3, v2, :cond_25

    .line 1184
    .line 1185
    aget-object v6, v0, v3

    .line 1186
    .line 1187
    invoke-virtual {v6, v4}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 1188
    .line 1189
    .line 1190
    move-result-object v8

    .line 1191
    array-length v9, v8

    .line 1192
    const/4 v11, 0x6

    .line 1193
    if-ge v9, v11, :cond_21

    .line 1194
    .line 1195
    const-string v8, "Error formatting mount line: "

    .line 1196
    .line 1197
    invoke-virtual {v8, v6}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 1198
    .line 1199
    .line 1200
    move-result-object v6

    .line 1201
    invoke-static {v6}, Ljp/o1;->a(Ljava/io/Serializable;)V

    .line 1202
    .line 1203
    .line 1204
    :goto_15
    move-object/from16 p0, v0

    .line 1205
    .line 1206
    move/from16 v16, v2

    .line 1207
    .line 1208
    goto :goto_19

    .line 1209
    :cond_21
    aget-object v9, v8, v21

    .line 1210
    .line 1211
    aget-object v8, v8, v23

    .line 1212
    .line 1213
    move v11, v5

    .line 1214
    const/4 v5, 0x0

    .line 1215
    :goto_16
    if-ge v5, v13, :cond_24

    .line 1216
    .line 1217
    sget-object v12, Lyw/a;->d:[Ljava/lang/String;

    .line 1218
    .line 1219
    aget-object v12, v12, v5

    .line 1220
    .line 1221
    invoke-virtual {v9, v12}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1222
    .line 1223
    .line 1224
    move-result v14

    .line 1225
    if-eqz v14, :cond_23

    .line 1226
    .line 1227
    const-string v14, "("

    .line 1228
    .line 1229
    invoke-virtual {v8, v14, v10}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    .line 1230
    .line 1231
    .line 1232
    move-result-object v8

    .line 1233
    const-string v14, ")"

    .line 1234
    .line 1235
    invoke-virtual {v8, v14, v10}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    .line 1236
    .line 1237
    .line 1238
    move-result-object v8

    .line 1239
    const-string v14, ","

    .line 1240
    .line 1241
    invoke-virtual {v8, v14}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 1242
    .line 1243
    .line 1244
    move-result-object v14

    .line 1245
    array-length v15, v14

    .line 1246
    const/4 v13, 0x0

    .line 1247
    :goto_17
    if-ge v13, v15, :cond_23

    .line 1248
    .line 1249
    move-object/from16 p0, v0

    .line 1250
    .line 1251
    aget-object v0, v14, v13

    .line 1252
    .line 1253
    move/from16 v16, v2

    .line 1254
    .line 1255
    const-string v2, "rw"

    .line 1256
    .line 1257
    invoke-virtual {v0, v2}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1258
    .line 1259
    .line 1260
    move-result v0

    .line 1261
    if-eqz v0, :cond_22

    .line 1262
    .line 1263
    new-instance v0, Ljava/lang/StringBuilder;

    .line 1264
    .line 1265
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 1266
    .line 1267
    .line 1268
    invoke-virtual {v0, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1269
    .line 1270
    .line 1271
    const-string v2, " path is mounted with rw permissions! "

    .line 1272
    .line 1273
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1274
    .line 1275
    .line 1276
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1277
    .line 1278
    .line 1279
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1280
    .line 1281
    .line 1282
    move-result-object v0

    .line 1283
    invoke-static {v0}, Ljp/o1;->e(Ljava/lang/String;)V

    .line 1284
    .line 1285
    .line 1286
    const/4 v11, 0x1

    .line 1287
    goto :goto_18

    .line 1288
    :cond_22
    add-int/lit8 v13, v13, 0x1

    .line 1289
    .line 1290
    move-object/from16 v0, p0

    .line 1291
    .line 1292
    move/from16 v2, v16

    .line 1293
    .line 1294
    goto :goto_17

    .line 1295
    :cond_23
    move-object/from16 p0, v0

    .line 1296
    .line 1297
    move/from16 v16, v2

    .line 1298
    .line 1299
    :goto_18
    add-int/lit8 v5, v5, 0x1

    .line 1300
    .line 1301
    move-object/from16 v0, p0

    .line 1302
    .line 1303
    move/from16 v2, v16

    .line 1304
    .line 1305
    const/4 v13, 0x7

    .line 1306
    goto :goto_16

    .line 1307
    :cond_24
    move v5, v11

    .line 1308
    goto :goto_15

    .line 1309
    :goto_19
    add-int/lit8 v3, v3, 0x1

    .line 1310
    .line 1311
    move-object/from16 v0, p0

    .line 1312
    .line 1313
    move/from16 v2, v16

    .line 1314
    .line 1315
    const/4 v13, 0x7

    .line 1316
    goto/16 :goto_14

    .line 1317
    .line 1318
    :cond_25
    :goto_1a
    if-nez v5, :cond_2d

    .line 1319
    .line 1320
    sget-object v0, Landroid/os/Build;->TAGS:Ljava/lang/String;

    .line 1321
    .line 1322
    if-eqz v0, :cond_26

    .line 1323
    .line 1324
    const-string v2, "test-keys"

    .line 1325
    .line 1326
    invoke-virtual {v0, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 1327
    .line 1328
    .line 1329
    move-result v0

    .line 1330
    if-eqz v0, :cond_26

    .line 1331
    .line 1332
    const/4 v0, 0x1

    .line 1333
    goto :goto_1b

    .line 1334
    :cond_26
    const/4 v0, 0x0

    .line 1335
    :goto_1b
    if-nez v0, :cond_2d

    .line 1336
    .line 1337
    :try_start_2
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;

    .line 1338
    .line 1339
    .line 1340
    move-result-object v0

    .line 1341
    const-string v2, "which"

    .line 1342
    .line 1343
    filled-new-array {v2, v7}, [Ljava/lang/String;

    .line 1344
    .line 1345
    .line 1346
    move-result-object v2

    .line 1347
    invoke-virtual {v0, v2}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;

    .line 1348
    .line 1349
    .line 1350
    move-result-object v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 1351
    :try_start_3
    new-instance v2, Ljava/io/BufferedReader;

    .line 1352
    .line 1353
    new-instance v3, Ljava/io/InputStreamReader;

    .line 1354
    .line 1355
    invoke-virtual {v0}, Ljava/lang/Process;->getInputStream()Ljava/io/InputStream;

    .line 1356
    .line 1357
    .line 1358
    move-result-object v4

    .line 1359
    invoke-direct {v3, v4}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;)V

    .line 1360
    .line 1361
    .line 1362
    invoke-direct {v2, v3}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V

    .line 1363
    .line 1364
    .line 1365
    invoke-virtual {v2}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    .line 1366
    .line 1367
    .line 1368
    move-result-object v2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 1369
    if-eqz v2, :cond_27

    .line 1370
    .line 1371
    const/4 v2, 0x1

    .line 1372
    goto :goto_1c

    .line 1373
    :cond_27
    const/4 v2, 0x0

    .line 1374
    :goto_1c
    invoke-virtual {v0}, Ljava/lang/Process;->destroy()V

    .line 1375
    .line 1376
    .line 1377
    goto :goto_1d

    .line 1378
    :catchall_0
    const/4 v0, 0x0

    .line 1379
    :catchall_1
    if-eqz v0, :cond_28

    .line 1380
    .line 1381
    invoke-virtual {v0}, Ljava/lang/Process;->destroy()V

    .line 1382
    .line 1383
    .line 1384
    :cond_28
    const/4 v2, 0x0

    .line 1385
    :goto_1d
    if-nez v2, :cond_2d

    .line 1386
    .line 1387
    new-instance v0, Lcom/scottyab/rootbeer/RootBeerNative;

    .line 1388
    .line 1389
    sget-boolean v0, Lcom/scottyab/rootbeer/RootBeerNative;->a:Z

    .line 1390
    .line 1391
    if-nez v0, :cond_2a

    .line 1392
    .line 1393
    const-string v0, "We could not load the native library to test for root"

    .line 1394
    .line 1395
    invoke-static {v0}, Ljp/o1;->a(Ljava/io/Serializable;)V

    .line 1396
    .line 1397
    .line 1398
    :catch_2
    :cond_29
    const/4 v0, 0x0

    .line 1399
    goto :goto_1f

    .line 1400
    :cond_2a
    invoke-static {}, Lyw/a;->a()[Ljava/lang/String;

    .line 1401
    .line 1402
    .line 1403
    move-result-object v0

    .line 1404
    array-length v2, v0

    .line 1405
    new-array v3, v2, [Ljava/lang/String;

    .line 1406
    .line 1407
    const/4 v4, 0x0

    .line 1408
    :goto_1e
    if-ge v4, v2, :cond_2b

    .line 1409
    .line 1410
    new-instance v5, Ljava/lang/StringBuilder;

    .line 1411
    .line 1412
    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    .line 1413
    .line 1414
    .line 1415
    aget-object v6, v0, v4

    .line 1416
    .line 1417
    invoke-static {v5, v6, v7}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1418
    .line 1419
    .line 1420
    move-result-object v5

    .line 1421
    aput-object v5, v3, v4

    .line 1422
    .line 1423
    add-int/lit8 v4, v4, 0x1

    .line 1424
    .line 1425
    goto :goto_1e

    .line 1426
    :cond_2b
    new-instance v0, Lcom/scottyab/rootbeer/RootBeerNative;

    .line 1427
    .line 1428
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 1429
    .line 1430
    .line 1431
    const/4 v2, 0x1

    .line 1432
    :try_start_4
    invoke-virtual {v0, v2}, Lcom/scottyab/rootbeer/RootBeerNative;->setLogDebugMessages(Z)I

    .line 1433
    .line 1434
    .line 1435
    invoke-virtual {v0, v3}, Lcom/scottyab/rootbeer/RootBeerNative;->checkForRoot([Ljava/lang/Object;)I

    .line 1436
    .line 1437
    .line 1438
    move-result v0
    :try_end_4
    .catch Ljava/lang/UnsatisfiedLinkError; {:try_start_4 .. :try_end_4} :catch_2

    .line 1439
    if-lez v0, :cond_29

    .line 1440
    .line 1441
    const/4 v0, 0x1

    .line 1442
    :goto_1f
    if-nez v0, :cond_2d

    .line 1443
    .line 1444
    const-string v0, "magisk"

    .line 1445
    .line 1446
    invoke-static {v0}, Lyw/b;->a(Ljava/lang/String;)Z

    .line 1447
    .line 1448
    .line 1449
    move-result v0

    .line 1450
    if-eqz v0, :cond_2c

    .line 1451
    .line 1452
    goto :goto_20

    .line 1453
    :cond_2c
    const/4 v6, 0x0

    .line 1454
    goto :goto_21

    .line 1455
    :cond_2d
    :goto_20
    const/4 v6, 0x1

    .line 1456
    :goto_21
    invoke-static {v6}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 1457
    .line 1458
    .line 1459
    move-result-object v0

    .line 1460
    new-instance v2, Lfw0/n;

    .line 1461
    .line 1462
    const/4 v11, 0x6

    .line 1463
    invoke-direct {v2, v11, v6}, Lfw0/n;-><init>(IZ)V

    .line 1464
    .line 1465
    .line 1466
    const/4 v3, 0x0

    .line 1467
    invoke-static {v3, v1, v2}, Llp/nd;->f(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 1468
    .line 1469
    .line 1470
    return-object v0

    .line 1471
    :pswitch_e
    move-object v3, v14

    .line 1472
    move/from16 v23, v15

    .line 1473
    .line 1474
    iget-object v0, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 1475
    .line 1476
    check-cast v0, Lvy0/b0;

    .line 1477
    .line 1478
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 1479
    .line 1480
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1481
    .line 1482
    .line 1483
    check-cast v9, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;

    .line 1484
    .line 1485
    invoke-virtual {v9}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;->getWindowHasFocus()Lyy0/j1;

    .line 1486
    .line 1487
    .line 1488
    move-result-object v1

    .line 1489
    invoke-static {v9}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;->access$getLifecycleState$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;)Lyy0/a2;

    .line 1490
    .line 1491
    .line 1492
    move-result-object v2

    .line 1493
    new-instance v4, Lgc/a;

    .line 1494
    .line 1495
    const/4 v5, 0x3

    .line 1496
    invoke-direct {v4, v9, v3, v5}, Lgc/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 1497
    .line 1498
    .line 1499
    new-instance v3, Lbn0/f;

    .line 1500
    .line 1501
    move/from16 v5, v23

    .line 1502
    .line 1503
    invoke-direct {v3, v1, v2, v4, v5}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 1504
    .line 1505
    .line 1506
    invoke-static {v3, v0}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 1507
    .line 1508
    .line 1509
    return-object v19

    .line 1510
    :pswitch_f
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 1511
    .line 1512
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1513
    .line 1514
    .line 1515
    iget-object v0, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 1516
    .line 1517
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;

    .line 1518
    .line 1519
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;->getRpaViewModel()Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAViewModel;

    .line 1520
    .line 1521
    .line 1522
    move-result-object v0

    .line 1523
    check-cast v9, Landroid/content/Context;

    .line 1524
    .line 1525
    invoke-virtual {v9}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 1526
    .line 1527
    .line 1528
    move-result-object v1

    .line 1529
    invoke-virtual {v1}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 1530
    .line 1531
    .line 1532
    move-result-object v1

    .line 1533
    const-string v2, "getDisplayMetrics(...)"

    .line 1534
    .line 1535
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1536
    .line 1537
    .line 1538
    invoke-interface {v0, v1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAViewModel;->updateDisplayMetrics(Landroid/util/DisplayMetrics;)V

    .line 1539
    .line 1540
    .line 1541
    return-object v19

    .line 1542
    :pswitch_10
    iget-object v0, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 1543
    .line 1544
    check-cast v0, Lss0/b;

    .line 1545
    .line 1546
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 1547
    .line 1548
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1549
    .line 1550
    .line 1551
    sget-object v1, Lss0/e;->t1:Lss0/e;

    .line 1552
    .line 1553
    invoke-static {v0, v1}, Lkp/u6;->d(Lss0/b;Lss0/e;)Ler0/g;

    .line 1554
    .line 1555
    .line 1556
    move-result-object v33

    .line 1557
    check-cast v9, Lq40/h;

    .line 1558
    .line 1559
    invoke-virtual {v9}, Lql0/j;->a()Lql0/h;

    .line 1560
    .line 1561
    .line 1562
    move-result-object v0

    .line 1563
    move-object/from16 v20, v0

    .line 1564
    .line 1565
    check-cast v20, Lq40/d;

    .line 1566
    .line 1567
    const/16 v34, 0x0

    .line 1568
    .line 1569
    const/16 v35, 0x2fff

    .line 1570
    .line 1571
    const/16 v21, 0x0

    .line 1572
    .line 1573
    const/16 v22, 0x0

    .line 1574
    .line 1575
    const/16 v23, 0x0

    .line 1576
    .line 1577
    const/16 v24, 0x0

    .line 1578
    .line 1579
    const/16 v25, 0x0

    .line 1580
    .line 1581
    const/16 v26, 0x0

    .line 1582
    .line 1583
    const/16 v27, 0x0

    .line 1584
    .line 1585
    const/16 v28, 0x0

    .line 1586
    .line 1587
    const/16 v29, 0x0

    .line 1588
    .line 1589
    const/16 v30, 0x0

    .line 1590
    .line 1591
    const/16 v31, 0x0

    .line 1592
    .line 1593
    const/16 v32, 0x0

    .line 1594
    .line 1595
    invoke-static/range {v20 .. v35}, Lq40/d;->a(Lq40/d;Lon0/j;Ljava/lang/String;Lon0/x;Lon0/z;Lon0/w;Ljava/util/ArrayList;Ljava/util/List;ZZZZLql0/g;Ler0/g;Lqr0/s;I)Lq40/d;

    .line 1596
    .line 1597
    .line 1598
    move-result-object v0

    .line 1599
    move-object/from16 v1, v33

    .line 1600
    .line 1601
    invoke-virtual {v9, v0}, Lql0/j;->g(Lql0/h;)V

    .line 1602
    .line 1603
    .line 1604
    sget-object v0, Ler0/g;->d:Ler0/g;

    .line 1605
    .line 1606
    if-eq v1, v0, :cond_2e

    .line 1607
    .line 1608
    invoke-virtual {v9}, Lql0/j;->a()Lql0/h;

    .line 1609
    .line 1610
    .line 1611
    move-result-object v0

    .line 1612
    move-object/from16 v20, v0

    .line 1613
    .line 1614
    check-cast v20, Lq40/d;

    .line 1615
    .line 1616
    const/16 v34, 0x0

    .line 1617
    .line 1618
    const/16 v35, 0x3bff

    .line 1619
    .line 1620
    const/16 v21, 0x0

    .line 1621
    .line 1622
    const/16 v22, 0x0

    .line 1623
    .line 1624
    const/16 v23, 0x0

    .line 1625
    .line 1626
    const/16 v24, 0x0

    .line 1627
    .line 1628
    const/16 v25, 0x0

    .line 1629
    .line 1630
    const/16 v26, 0x0

    .line 1631
    .line 1632
    const/16 v27, 0x0

    .line 1633
    .line 1634
    const/16 v28, 0x0

    .line 1635
    .line 1636
    const/16 v29, 0x0

    .line 1637
    .line 1638
    const/16 v30, 0x0

    .line 1639
    .line 1640
    const/16 v31, 0x0

    .line 1641
    .line 1642
    const/16 v32, 0x0

    .line 1643
    .line 1644
    const/16 v33, 0x0

    .line 1645
    .line 1646
    invoke-static/range {v20 .. v35}, Lq40/d;->a(Lq40/d;Lon0/j;Ljava/lang/String;Lon0/x;Lon0/z;Lon0/w;Ljava/util/ArrayList;Ljava/util/List;ZZZZLql0/g;Ler0/g;Lqr0/s;I)Lq40/d;

    .line 1647
    .line 1648
    .line 1649
    move-result-object v0

    .line 1650
    invoke-virtual {v9, v0}, Lql0/j;->g(Lql0/h;)V

    .line 1651
    .line 1652
    .line 1653
    :cond_2e
    return-object v19

    .line 1654
    :pswitch_11
    check-cast v9, Lq40/c;

    .line 1655
    .line 1656
    iget-object v1, v9, Lq40/c;->k:Ljava/lang/Class;

    .line 1657
    .line 1658
    iget-object v2, v9, Lq40/c;->h:Lxh0/d;

    .line 1659
    .line 1660
    iget-object v0, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 1661
    .line 1662
    check-cast v0, Lon0/h;

    .line 1663
    .line 1664
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 1665
    .line 1666
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1667
    .line 1668
    .line 1669
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 1670
    .line 1671
    .line 1672
    move-result v0

    .line 1673
    const/4 v5, 0x5

    .line 1674
    if-eq v0, v5, :cond_2f

    .line 1675
    .line 1676
    if-eq v0, v7, :cond_30

    .line 1677
    .line 1678
    const/4 v3, 0x7

    .line 1679
    if-eq v0, v3, :cond_2f

    .line 1680
    .line 1681
    if-eq v0, v12, :cond_2f

    .line 1682
    .line 1683
    goto :goto_23

    .line 1684
    :cond_2f
    const/4 v3, 0x0

    .line 1685
    goto :goto_22

    .line 1686
    :cond_30
    new-instance v0, Lxh0/c;

    .line 1687
    .line 1688
    invoke-direct {v0, v1}, Lxh0/c;-><init>(Ljava/lang/Class;)V

    .line 1689
    .line 1690
    .line 1691
    check-cast v2, Lvh0/a;

    .line 1692
    .line 1693
    iget-object v1, v2, Lvh0/a;->a:Lyy0/c2;

    .line 1694
    .line 1695
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1696
    .line 1697
    .line 1698
    const/4 v3, 0x0

    .line 1699
    invoke-virtual {v1, v3, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1700
    .line 1701
    .line 1702
    iget-object v0, v9, Lq40/c;->j:Lo40/t;

    .line 1703
    .line 1704
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 1705
    .line 1706
    .line 1707
    goto :goto_23

    .line 1708
    :goto_22
    new-instance v0, Lxh0/c;

    .line 1709
    .line 1710
    invoke-direct {v0, v1}, Lxh0/c;-><init>(Ljava/lang/Class;)V

    .line 1711
    .line 1712
    .line 1713
    check-cast v2, Lvh0/a;

    .line 1714
    .line 1715
    iget-object v1, v2, Lvh0/a;->a:Lyy0/c2;

    .line 1716
    .line 1717
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1718
    .line 1719
    .line 1720
    invoke-virtual {v1, v3, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1721
    .line 1722
    .line 1723
    iget-object v0, v9, Lq40/c;->l:Lo40/s;

    .line 1724
    .line 1725
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 1726
    .line 1727
    .line 1728
    :goto_23
    return-object v19

    .line 1729
    :pswitch_12
    move-object v3, v14

    .line 1730
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 1731
    .line 1732
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1733
    .line 1734
    .line 1735
    iget-object v0, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 1736
    .line 1737
    check-cast v0, Lq40/c;

    .line 1738
    .line 1739
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 1740
    .line 1741
    .line 1742
    move-result-object v1

    .line 1743
    new-instance v2, Lq40/b;

    .line 1744
    .line 1745
    const/4 v4, 0x0

    .line 1746
    invoke-direct {v2, v0, v3, v4}, Lq40/b;-><init>(Lq40/c;Lkotlin/coroutines/Continuation;I)V

    .line 1747
    .line 1748
    .line 1749
    const/4 v5, 0x3

    .line 1750
    invoke-static {v1, v3, v3, v2, v5}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 1751
    .line 1752
    .line 1753
    iget-object v1, v0, Lq40/c;->h:Lxh0/d;

    .line 1754
    .line 1755
    new-instance v2, Lxh0/b;

    .line 1756
    .line 1757
    iget-object v4, v0, Lq40/c;->k:Ljava/lang/Class;

    .line 1758
    .line 1759
    invoke-direct {v2, v4}, Lxh0/b;-><init>(Ljava/lang/Class;)V

    .line 1760
    .line 1761
    .line 1762
    check-cast v1, Lvh0/a;

    .line 1763
    .line 1764
    iget-object v1, v1, Lvh0/a;->a:Lyy0/c2;

    .line 1765
    .line 1766
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1767
    .line 1768
    .line 1769
    invoke-virtual {v1, v3, v2}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1770
    .line 1771
    .line 1772
    check-cast v9, Lo40/h;

    .line 1773
    .line 1774
    invoke-virtual {v9}, Lo40/h;->invoke()Ljava/lang/Object;

    .line 1775
    .line 1776
    .line 1777
    move-result-object v1

    .line 1778
    check-cast v1, Lon0/m;

    .line 1779
    .line 1780
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1781
    .line 1782
    .line 1783
    move-result-object v2

    .line 1784
    check-cast v2, Lq40/a;

    .line 1785
    .line 1786
    if-eqz v1, :cond_31

    .line 1787
    .line 1788
    iget-object v3, v1, Lon0/m;->d:Ljava/lang/String;

    .line 1789
    .line 1790
    goto :goto_24

    .line 1791
    :cond_31
    const/4 v3, 0x0

    .line 1792
    :goto_24
    if-eqz v1, :cond_32

    .line 1793
    .line 1794
    iget-object v1, v1, Lon0/m;->b:Lon0/w;

    .line 1795
    .line 1796
    if-eqz v1, :cond_32

    .line 1797
    .line 1798
    iget-object v1, v1, Lon0/w;->b:Ljava/lang/String;

    .line 1799
    .line 1800
    goto :goto_25

    .line 1801
    :cond_32
    const/4 v1, 0x0

    .line 1802
    :goto_25
    const/16 v4, 0x19

    .line 1803
    .line 1804
    const/4 v5, 0x0

    .line 1805
    invoke-static {v2, v5, v3, v1, v4}, Lq40/a;->a(Lq40/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lq40/a;

    .line 1806
    .line 1807
    .line 1808
    move-result-object v1

    .line 1809
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 1810
    .line 1811
    .line 1812
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 1813
    .line 1814
    .line 1815
    move-result-object v1

    .line 1816
    new-instance v2, Lq40/b;

    .line 1817
    .line 1818
    const/4 v3, 0x1

    .line 1819
    invoke-direct {v2, v0, v5, v3}, Lq40/b;-><init>(Lq40/c;Lkotlin/coroutines/Continuation;I)V

    .line 1820
    .line 1821
    .line 1822
    const/4 v0, 0x3

    .line 1823
    invoke-static {v1, v5, v5, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 1824
    .line 1825
    .line 1826
    return-object v19

    .line 1827
    :pswitch_13
    iget-object v0, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 1828
    .line 1829
    check-cast v0, Lyr0/e;

    .line 1830
    .line 1831
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 1832
    .line 1833
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1834
    .line 1835
    .line 1836
    iget-object v0, v0, Lyr0/e;->c:Ljava/lang/String;

    .line 1837
    .line 1838
    if-nez v0, :cond_33

    .line 1839
    .line 1840
    move-object v2, v10

    .line 1841
    goto :goto_26

    .line 1842
    :cond_33
    move-object v2, v0

    .line 1843
    :goto_26
    check-cast v9, Lq30/h;

    .line 1844
    .line 1845
    invoke-virtual {v9}, Lql0/j;->a()Lql0/h;

    .line 1846
    .line 1847
    .line 1848
    move-result-object v0

    .line 1849
    move-object v1, v0

    .line 1850
    check-cast v1, Lq30/g;

    .line 1851
    .line 1852
    const/4 v5, 0x0

    .line 1853
    const/16 v6, 0x1e

    .line 1854
    .line 1855
    const/4 v3, 0x0

    .line 1856
    const/4 v4, 0x0

    .line 1857
    invoke-static/range {v1 .. v6}, Lq30/g;->a(Lq30/g;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;ZI)Lq30/g;

    .line 1858
    .line 1859
    .line 1860
    move-result-object v0

    .line 1861
    invoke-virtual {v9, v0}, Lql0/j;->g(Lql0/h;)V

    .line 1862
    .line 1863
    .line 1864
    return-object v19

    .line 1865
    :pswitch_14
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 1866
    .line 1867
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1868
    .line 1869
    .line 1870
    iget-object v0, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 1871
    .line 1872
    check-cast v0, Lpp0/j;

    .line 1873
    .line 1874
    iget-object v0, v0, Lpp0/j;->c:Lpp0/c0;

    .line 1875
    .line 1876
    check-cast v9, Lqp0/g;

    .line 1877
    .line 1878
    check-cast v0, Lnp0/b;

    .line 1879
    .line 1880
    iget-object v0, v0, Lnp0/b;->j:Lyy0/c2;

    .line 1881
    .line 1882
    invoke-virtual {v0, v9}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 1883
    .line 1884
    .line 1885
    return-object v19

    .line 1886
    :pswitch_15
    iget-object v0, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 1887
    .line 1888
    check-cast v0, Lne0/s;

    .line 1889
    .line 1890
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 1891
    .line 1892
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1893
    .line 1894
    .line 1895
    check-cast v9, Lpp0/h;

    .line 1896
    .line 1897
    iget-object v1, v9, Lpp0/h;->a:Lpp0/c0;

    .line 1898
    .line 1899
    check-cast v1, Lnp0/b;

    .line 1900
    .line 1901
    const-string v2, "navigationRoute"

    .line 1902
    .line 1903
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1904
    .line 1905
    .line 1906
    iget-object v1, v1, Lnp0/b;->p:Lyy0/c2;

    .line 1907
    .line 1908
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1909
    .line 1910
    .line 1911
    const/4 v3, 0x0

    .line 1912
    invoke-virtual {v1, v3, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1913
    .line 1914
    .line 1915
    return-object v19

    .line 1916
    :pswitch_16
    iget-object v0, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 1917
    .line 1918
    check-cast v0, Lqp0/a;

    .line 1919
    .line 1920
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 1921
    .line 1922
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1923
    .line 1924
    .line 1925
    check-cast v9, Lpp0/e;

    .line 1926
    .line 1927
    iget-object v1, v9, Lpp0/e;->e:Lpp0/c0;

    .line 1928
    .line 1929
    iget-object v0, v0, Lqp0/a;->c:Ljava/lang/String;

    .line 1930
    .line 1931
    check-cast v1, Lnp0/b;

    .line 1932
    .line 1933
    iput-object v0, v1, Lnp0/b;->n:Ljava/lang/String;

    .line 1934
    .line 1935
    return-object v19

    .line 1936
    :pswitch_17
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 1937
    .line 1938
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1939
    .line 1940
    .line 1941
    iget-object v0, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 1942
    .line 1943
    check-cast v0, Loq0/a;

    .line 1944
    .line 1945
    iget-object v0, v0, Loq0/a;->a:Landroid/content/Context;

    .line 1946
    .line 1947
    check-cast v9, Lmq0/b;

    .line 1948
    .line 1949
    iget-object v1, v9, Lmq0/b;->d:Ljava/lang/String;

    .line 1950
    .line 1951
    invoke-static {v1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 1952
    .line 1953
    .line 1954
    move-result-object v1

    .line 1955
    invoke-virtual {v0, v2}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    .line 1956
    .line 1957
    .line 1958
    move-result-object v2

    .line 1959
    check-cast v2, Landroid/content/pm/ShortcutManager;

    .line 1960
    .line 1961
    invoke-virtual {v2, v1}, Landroid/content/pm/ShortcutManager;->removeDynamicShortcuts(Ljava/util/List;)V

    .line 1962
    .line 1963
    .line 1964
    invoke-static {v0}, Lo5/c;->e(Landroid/content/Context;)Lo5/b;

    .line 1965
    .line 1966
    .line 1967
    move-result-object v2

    .line 1968
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1969
    .line 1970
    .line 1971
    invoke-static {v0}, Lo5/c;->d(Landroid/content/Context;)Ljava/util/List;

    .line 1972
    .line 1973
    .line 1974
    move-result-object v0

    .line 1975
    check-cast v0, Ljava/util/ArrayList;

    .line 1976
    .line 1977
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1978
    .line 1979
    .line 1980
    move-result-object v0

    .line 1981
    :goto_27
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 1982
    .line 1983
    .line 1984
    move-result v2

    .line 1985
    if-eqz v2, :cond_35

    .line 1986
    .line 1987
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1988
    .line 1989
    .line 1990
    move-result-object v2

    .line 1991
    check-cast v2, Landroidx/core/google/shortcuts/ShortcutInfoChangeListenerImpl;

    .line 1992
    .line 1993
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1994
    .line 1995
    .line 1996
    new-instance v3, Ljava/util/ArrayList;

    .line 1997
    .line 1998
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 1999
    .line 2000
    .line 2001
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 2002
    .line 2003
    .line 2004
    move-result-object v4

    .line 2005
    :goto_28
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 2006
    .line 2007
    .line 2008
    move-result v5

    .line 2009
    if-eqz v5, :cond_34

    .line 2010
    .line 2011
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2012
    .line 2013
    .line 2014
    move-result-object v5

    .line 2015
    check-cast v5, Ljava/lang/String;

    .line 2016
    .line 2017
    iget-object v6, v2, Landroidx/core/google/shortcuts/ShortcutInfoChangeListenerImpl;->a:Landroid/content/Context;

    .line 2018
    .line 2019
    invoke-static {v6, v5}, Lkp/k;->a(Landroid/content/Context;Ljava/lang/String;)Ljava/lang/String;

    .line 2020
    .line 2021
    .line 2022
    move-result-object v5

    .line 2023
    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 2024
    .line 2025
    .line 2026
    goto :goto_28

    .line 2027
    :cond_34
    iget-object v2, v2, Landroidx/core/google/shortcuts/ShortcutInfoChangeListenerImpl;->b:Lbp/v;

    .line 2028
    .line 2029
    const/4 v4, 0x0

    .line 2030
    new-array v5, v4, [Ljava/lang/String;

    .line 2031
    .line 2032
    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 2033
    .line 2034
    .line 2035
    move-result-object v3

    .line 2036
    move-object v7, v3

    .line 2037
    check-cast v7, [Ljava/lang/String;

    .line 2038
    .line 2039
    new-instance v4, Lfs/f;

    .line 2040
    .line 2041
    const/4 v10, 0x0

    .line 2042
    const/4 v11, 0x0

    .line 2043
    const/4 v5, 0x3

    .line 2044
    const/4 v6, 0x0

    .line 2045
    const/4 v8, 0x0

    .line 2046
    const/4 v9, 0x0

    .line 2047
    invoke-direct/range {v4 .. v11}, Lfs/f;-><init>(I[Lcom/google/firebase/appindexing/internal/Thing;[Ljava/lang/String;[Ljava/lang/String;Lbp/p;Ljava/lang/String;Ljava/lang/String;)V

    .line 2048
    .line 2049
    .line 2050
    iget-object v2, v2, Lbp/v;->a:Lbp/u;

    .line 2051
    .line 2052
    invoke-virtual {v2, v4}, Lbp/u;->a(Lfs/f;)Laq/t;

    .line 2053
    .line 2054
    .line 2055
    goto :goto_27

    .line 2056
    :cond_35
    return-object v19

    .line 2057
    :pswitch_18
    move/from16 v21, v3

    .line 2058
    .line 2059
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 2060
    .line 2061
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 2062
    .line 2063
    .line 2064
    iget-object v0, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 2065
    .line 2066
    check-cast v0, Loq0/a;

    .line 2067
    .line 2068
    iget-object v1, v0, Loq0/a;->a:Landroid/content/Context;

    .line 2069
    .line 2070
    check-cast v9, Lmq0/a;

    .line 2071
    .line 2072
    iget-object v3, v9, Lmq0/a;->a:Lmq0/b;

    .line 2073
    .line 2074
    iget-object v4, v3, Lmq0/b;->d:Ljava/lang/String;

    .line 2075
    .line 2076
    new-instance v5, Lo5/a;

    .line 2077
    .line 2078
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 2079
    .line 2080
    .line 2081
    iput-object v1, v5, Lo5/a;->a:Landroid/content/Context;

    .line 2082
    .line 2083
    iput-object v4, v5, Lo5/a;->b:Ljava/lang/String;

    .line 2084
    .line 2085
    iget-object v0, v0, Loq0/a;->b:Lij0/a;

    .line 2086
    .line 2087
    invoke-static {v0, v3}, Ljp/va;->b(Lij0/a;Lmq0/b;)Ljava/lang/String;

    .line 2088
    .line 2089
    .line 2090
    move-result-object v3

    .line 2091
    iput-object v3, v5, Lo5/a;->d:Ljava/lang/String;

    .line 2092
    .line 2093
    iget-object v3, v9, Lmq0/a;->a:Lmq0/b;

    .line 2094
    .line 2095
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 2096
    .line 2097
    .line 2098
    move-result v4

    .line 2099
    if-eqz v4, :cond_38

    .line 2100
    .line 2101
    const/4 v6, 0x1

    .line 2102
    if-eq v4, v6, :cond_37

    .line 2103
    .line 2104
    move/from16 v6, v21

    .line 2105
    .line 2106
    if-ne v4, v6, :cond_36

    .line 2107
    .line 2108
    const/4 v4, 0x0

    .line 2109
    new-array v6, v4, [Ljava/lang/Object;

    .line 2110
    .line 2111
    move-object v7, v0

    .line 2112
    check-cast v7, Ljj0/f;

    .line 2113
    .line 2114
    const v8, 0x7f12121e

    .line 2115
    .line 2116
    .line 2117
    invoke-virtual {v7, v8, v6}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 2118
    .line 2119
    .line 2120
    move-result-object v6

    .line 2121
    goto :goto_29

    .line 2122
    :cond_36
    new-instance v0, La8/r0;

    .line 2123
    .line 2124
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 2125
    .line 2126
    .line 2127
    throw v0

    .line 2128
    :cond_37
    const/4 v4, 0x0

    .line 2129
    new-array v6, v4, [Ljava/lang/Object;

    .line 2130
    .line 2131
    move-object v7, v0

    .line 2132
    check-cast v7, Ljj0/f;

    .line 2133
    .line 2134
    const v8, 0x7f121220

    .line 2135
    .line 2136
    .line 2137
    invoke-virtual {v7, v8, v6}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 2138
    .line 2139
    .line 2140
    move-result-object v6

    .line 2141
    goto :goto_29

    .line 2142
    :cond_38
    const/4 v4, 0x0

    .line 2143
    new-array v6, v4, [Ljava/lang/Object;

    .line 2144
    .line 2145
    move-object v4, v0

    .line 2146
    check-cast v4, Ljj0/f;

    .line 2147
    .line 2148
    const v7, 0x7f12121d

    .line 2149
    .line 2150
    .line 2151
    invoke-virtual {v4, v7, v6}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 2152
    .line 2153
    .line 2154
    move-result-object v6

    .line 2155
    :goto_29
    iput-object v6, v5, Lo5/a;->e:Ljava/lang/String;

    .line 2156
    .line 2157
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 2158
    .line 2159
    .line 2160
    move-result v4

    .line 2161
    if-eqz v4, :cond_3b

    .line 2162
    .line 2163
    const/4 v6, 0x1

    .line 2164
    if-eq v4, v6, :cond_3a

    .line 2165
    .line 2166
    const/4 v6, 0x2

    .line 2167
    if-ne v4, v6, :cond_39

    .line 2168
    .line 2169
    const v4, 0x7f0f0002

    .line 2170
    .line 2171
    .line 2172
    goto :goto_2a

    .line 2173
    :cond_39
    new-instance v0, La8/r0;

    .line 2174
    .line 2175
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 2176
    .line 2177
    .line 2178
    throw v0

    .line 2179
    :cond_3a
    const v4, 0x7f0f0003

    .line 2180
    .line 2181
    .line 2182
    goto :goto_2a

    .line 2183
    :cond_3b
    const v4, 0x7f0f0004

    .line 2184
    .line 2185
    .line 2186
    :goto_2a
    sget-object v6, Landroidx/core/graphics/drawable/IconCompat;->k:Landroid/graphics/PorterDuff$Mode;

    .line 2187
    .line 2188
    invoke-virtual {v1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 2189
    .line 2190
    .line 2191
    move-result-object v6

    .line 2192
    invoke-virtual {v1}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 2193
    .line 2194
    .line 2195
    move-result-object v7

    .line 2196
    invoke-static {v6, v7, v4}, Landroidx/core/graphics/drawable/IconCompat;->a(Landroid/content/res/Resources;Ljava/lang/String;I)Landroidx/core/graphics/drawable/IconCompat;

    .line 2197
    .line 2198
    .line 2199
    move-result-object v4

    .line 2200
    iput-object v4, v5, Lo5/a;->f:Landroidx/core/graphics/drawable/IconCompat;

    .line 2201
    .line 2202
    invoke-static {v0, v3}, Ljp/va;->b(Lij0/a;Lmq0/b;)Ljava/lang/String;

    .line 2203
    .line 2204
    .line 2205
    move-result-object v0

    .line 2206
    invoke-static {v0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 2207
    .line 2208
    .line 2209
    move-result-object v0

    .line 2210
    new-instance v3, Ljava/util/HashSet;

    .line 2211
    .line 2212
    invoke-direct {v3}, Ljava/util/HashSet;-><init>()V

    .line 2213
    .line 2214
    .line 2215
    const-string v4, "actions.intent.GET_THING"

    .line 2216
    .line 2217
    invoke-virtual {v3, v4}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 2218
    .line 2219
    .line 2220
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 2221
    .line 2222
    .line 2223
    move-result v6

    .line 2224
    if-nez v6, :cond_3d

    .line 2225
    .line 2226
    new-instance v6, Ljava/util/HashMap;

    .line 2227
    .line 2228
    invoke-direct {v6}, Ljava/util/HashMap;-><init>()V

    .line 2229
    .line 2230
    .line 2231
    invoke-virtual {v6, v4}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2232
    .line 2233
    .line 2234
    move-result-object v7

    .line 2235
    if-nez v7, :cond_3c

    .line 2236
    .line 2237
    new-instance v7, Ljava/util/HashMap;

    .line 2238
    .line 2239
    invoke-direct {v7}, Ljava/util/HashMap;-><init>()V

    .line 2240
    .line 2241
    .line 2242
    invoke-virtual {v6, v4, v7}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 2243
    .line 2244
    .line 2245
    :cond_3c
    invoke-virtual {v6, v4}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2246
    .line 2247
    .line 2248
    move-result-object v4

    .line 2249
    check-cast v4, Ljava/util/Map;

    .line 2250
    .line 2251
    const-string v7, "thing.name"

    .line 2252
    .line 2253
    invoke-interface {v4, v7, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 2254
    .line 2255
    .line 2256
    goto :goto_2b

    .line 2257
    :cond_3d
    const/4 v6, 0x0

    .line 2258
    :goto_2b
    new-instance v0, Landroid/content/Intent;

    .line 2259
    .line 2260
    const-string v4, "android.intent.action.VIEW"

    .line 2261
    .line 2262
    invoke-direct {v0, v4}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 2263
    .line 2264
    .line 2265
    iget-object v4, v9, Lmq0/a;->b:Ljava/lang/String;

    .line 2266
    .line 2267
    invoke-static {v4}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 2268
    .line 2269
    .line 2270
    move-result-object v4

    .line 2271
    invoke-virtual {v0, v4}, Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;

    .line 2272
    .line 2273
    .line 2274
    filled-new-array {v0}, [Landroid/content/Intent;

    .line 2275
    .line 2276
    .line 2277
    move-result-object v0

    .line 2278
    iput-object v0, v5, Lo5/a;->c:[Landroid/content/Intent;

    .line 2279
    .line 2280
    iget-object v0, v5, Lo5/a;->d:Ljava/lang/String;

    .line 2281
    .line 2282
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 2283
    .line 2284
    .line 2285
    move-result v0

    .line 2286
    if-nez v0, :cond_55

    .line 2287
    .line 2288
    iget-object v0, v5, Lo5/a;->c:[Landroid/content/Intent;

    .line 2289
    .line 2290
    if-eqz v0, :cond_54

    .line 2291
    .line 2292
    array-length v0, v0

    .line 2293
    if-eqz v0, :cond_54

    .line 2294
    .line 2295
    iget-object v0, v5, Lo5/a;->g:Ljava/util/HashSet;

    .line 2296
    .line 2297
    if-nez v0, :cond_3e

    .line 2298
    .line 2299
    new-instance v0, Ljava/util/HashSet;

    .line 2300
    .line 2301
    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    .line 2302
    .line 2303
    .line 2304
    iput-object v0, v5, Lo5/a;->g:Ljava/util/HashSet;

    .line 2305
    .line 2306
    :cond_3e
    iget-object v0, v5, Lo5/a;->g:Ljava/util/HashSet;

    .line 2307
    .line 2308
    invoke-interface {v0, v3}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    .line 2309
    .line 2310
    .line 2311
    if-eqz v6, :cond_42

    .line 2312
    .line 2313
    iget-object v0, v5, Lo5/a;->h:Landroid/os/PersistableBundle;

    .line 2314
    .line 2315
    if-nez v0, :cond_3f

    .line 2316
    .line 2317
    new-instance v0, Landroid/os/PersistableBundle;

    .line 2318
    .line 2319
    invoke-direct {v0}, Landroid/os/PersistableBundle;-><init>()V

    .line 2320
    .line 2321
    .line 2322
    iput-object v0, v5, Lo5/a;->h:Landroid/os/PersistableBundle;

    .line 2323
    .line 2324
    :cond_3f
    invoke-virtual {v6}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    .line 2325
    .line 2326
    .line 2327
    move-result-object v0

    .line 2328
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 2329
    .line 2330
    .line 2331
    move-result-object v0

    .line 2332
    :cond_40
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 2333
    .line 2334
    .line 2335
    move-result v3

    .line 2336
    if-eqz v3, :cond_42

    .line 2337
    .line 2338
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2339
    .line 2340
    .line 2341
    move-result-object v3

    .line 2342
    check-cast v3, Ljava/lang/String;

    .line 2343
    .line 2344
    invoke-virtual {v6, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2345
    .line 2346
    .line 2347
    move-result-object v4

    .line 2348
    check-cast v4, Ljava/util/Map;

    .line 2349
    .line 2350
    invoke-interface {v4}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 2351
    .line 2352
    .line 2353
    move-result-object v7

    .line 2354
    iget-object v8, v5, Lo5/a;->h:Landroid/os/PersistableBundle;

    .line 2355
    .line 2356
    const/4 v9, 0x0

    .line 2357
    new-array v10, v9, [Ljava/lang/String;

    .line 2358
    .line 2359
    invoke-interface {v7, v10}, Ljava/util/Set;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 2360
    .line 2361
    .line 2362
    move-result-object v7

    .line 2363
    check-cast v7, [Ljava/lang/String;

    .line 2364
    .line 2365
    invoke-virtual {v8, v3, v7}, Landroid/os/BaseBundle;->putStringArray(Ljava/lang/String;[Ljava/lang/String;)V

    .line 2366
    .line 2367
    .line 2368
    invoke-interface {v4}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 2369
    .line 2370
    .line 2371
    move-result-object v7

    .line 2372
    invoke-interface {v7}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 2373
    .line 2374
    .line 2375
    move-result-object v7

    .line 2376
    :goto_2c
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 2377
    .line 2378
    .line 2379
    move-result v8

    .line 2380
    if-eqz v8, :cond_40

    .line 2381
    .line 2382
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2383
    .line 2384
    .line 2385
    move-result-object v8

    .line 2386
    check-cast v8, Ljava/lang/String;

    .line 2387
    .line 2388
    invoke-interface {v4, v8}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2389
    .line 2390
    .line 2391
    move-result-object v9

    .line 2392
    check-cast v9, Ljava/util/List;

    .line 2393
    .line 2394
    iget-object v10, v5, Lo5/a;->h:Landroid/os/PersistableBundle;

    .line 2395
    .line 2396
    const-string v11, "/"

    .line 2397
    .line 2398
    invoke-static {v3, v11, v8}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 2399
    .line 2400
    .line 2401
    move-result-object v8

    .line 2402
    const/4 v11, 0x0

    .line 2403
    if-nez v9, :cond_41

    .line 2404
    .line 2405
    new-array v9, v11, [Ljava/lang/String;

    .line 2406
    .line 2407
    goto :goto_2d

    .line 2408
    :cond_41
    new-array v12, v11, [Ljava/lang/String;

    .line 2409
    .line 2410
    invoke-interface {v9, v12}, Ljava/util/List;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 2411
    .line 2412
    .line 2413
    move-result-object v9

    .line 2414
    check-cast v9, [Ljava/lang/String;

    .line 2415
    .line 2416
    :goto_2d
    invoke-virtual {v10, v8, v9}, Landroid/os/BaseBundle;->putStringArray(Ljava/lang/String;[Ljava/lang/String;)V

    .line 2417
    .line 2418
    .line 2419
    goto :goto_2c

    .line 2420
    :cond_42
    const/4 v11, 0x0

    .line 2421
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2422
    .line 2423
    invoke-virtual {v1, v2}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    .line 2424
    .line 2425
    .line 2426
    move-result-object v3

    .line 2427
    check-cast v3, Landroid/content/pm/ShortcutManager;

    .line 2428
    .line 2429
    invoke-virtual {v3}, Landroid/content/pm/ShortcutManager;->getMaxShortcutCountPerActivity()I

    .line 2430
    .line 2431
    .line 2432
    move-result v3

    .line 2433
    if-nez v3, :cond_43

    .line 2434
    .line 2435
    goto/16 :goto_38

    .line 2436
    .line 2437
    :cond_43
    const/16 v4, 0x1d

    .line 2438
    .line 2439
    if-gt v0, v4, :cond_49

    .line 2440
    .line 2441
    iget-object v4, v5, Lo5/a;->f:Landroidx/core/graphics/drawable/IconCompat;

    .line 2442
    .line 2443
    if-nez v4, :cond_44

    .line 2444
    .line 2445
    goto :goto_2f

    .line 2446
    :cond_44
    iget v6, v4, Landroidx/core/graphics/drawable/IconCompat;->a:I

    .line 2447
    .line 2448
    const/4 v7, 0x6

    .line 2449
    if-eq v6, v7, :cond_45

    .line 2450
    .line 2451
    move/from16 v8, v18

    .line 2452
    .line 2453
    if-eq v6, v8, :cond_45

    .line 2454
    .line 2455
    goto :goto_2f

    .line 2456
    :cond_45
    invoke-virtual {v4, v1}, Landroidx/core/graphics/drawable/IconCompat;->e(Landroid/content/Context;)Ljava/io/InputStream;

    .line 2457
    .line 2458
    .line 2459
    move-result-object v4

    .line 2460
    if-nez v4, :cond_46

    .line 2461
    .line 2462
    goto :goto_2f

    .line 2463
    :cond_46
    invoke-static {v4}, Landroid/graphics/BitmapFactory;->decodeStream(Ljava/io/InputStream;)Landroid/graphics/Bitmap;

    .line 2464
    .line 2465
    .line 2466
    move-result-object v4

    .line 2467
    if-nez v4, :cond_47

    .line 2468
    .line 2469
    goto :goto_2f

    .line 2470
    :cond_47
    if-ne v6, v7, :cond_48

    .line 2471
    .line 2472
    new-instance v6, Landroidx/core/graphics/drawable/IconCompat;

    .line 2473
    .line 2474
    const/4 v7, 0x5

    .line 2475
    invoke-direct {v6, v7}, Landroidx/core/graphics/drawable/IconCompat;-><init>(I)V

    .line 2476
    .line 2477
    .line 2478
    iput-object v4, v6, Landroidx/core/graphics/drawable/IconCompat;->b:Ljava/lang/Object;

    .line 2479
    .line 2480
    goto :goto_2e

    .line 2481
    :cond_48
    new-instance v6, Landroidx/core/graphics/drawable/IconCompat;

    .line 2482
    .line 2483
    const/4 v7, 0x1

    .line 2484
    invoke-direct {v6, v7}, Landroidx/core/graphics/drawable/IconCompat;-><init>(I)V

    .line 2485
    .line 2486
    .line 2487
    iput-object v4, v6, Landroidx/core/graphics/drawable/IconCompat;->b:Ljava/lang/Object;

    .line 2488
    .line 2489
    :goto_2e
    iput-object v6, v5, Lo5/a;->f:Landroidx/core/graphics/drawable/IconCompat;

    .line 2490
    .line 2491
    :cond_49
    :goto_2f
    move/from16 v4, v17

    .line 2492
    .line 2493
    if-lt v0, v4, :cond_4a

    .line 2494
    .line 2495
    invoke-virtual {v1, v2}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    .line 2496
    .line 2497
    .line 2498
    move-result-object v0

    .line 2499
    check-cast v0, Landroid/content/pm/ShortcutManager;

    .line 2500
    .line 2501
    invoke-virtual {v5}, Lo5/a;->a()Landroid/content/pm/ShortcutInfo;

    .line 2502
    .line 2503
    .line 2504
    move-result-object v2

    .line 2505
    invoke-static {v0, v2}, Ln01/a;->j(Landroid/content/pm/ShortcutManager;Landroid/content/pm/ShortcutInfo;)V

    .line 2506
    .line 2507
    .line 2508
    goto :goto_31

    .line 2509
    :cond_4a
    invoke-virtual {v1, v2}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    .line 2510
    .line 2511
    .line 2512
    move-result-object v0

    .line 2513
    check-cast v0, Landroid/content/pm/ShortcutManager;

    .line 2514
    .line 2515
    invoke-virtual {v0}, Landroid/content/pm/ShortcutManager;->isRateLimitingActive()Z

    .line 2516
    .line 2517
    .line 2518
    move-result v2

    .line 2519
    if-eqz v2, :cond_4b

    .line 2520
    .line 2521
    goto/16 :goto_38

    .line 2522
    .line 2523
    :cond_4b
    invoke-virtual {v0}, Landroid/content/pm/ShortcutManager;->getDynamicShortcuts()Ljava/util/List;

    .line 2524
    .line 2525
    .line 2526
    move-result-object v2

    .line 2527
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 2528
    .line 2529
    .line 2530
    move-result v4

    .line 2531
    if-lt v4, v3, :cond_4e

    .line 2532
    .line 2533
    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 2534
    .line 2535
    .line 2536
    move-result-object v2

    .line 2537
    const/4 v4, 0x0

    .line 2538
    const/4 v6, -0x1

    .line 2539
    :cond_4c
    :goto_30
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 2540
    .line 2541
    .line 2542
    move-result v7

    .line 2543
    if-eqz v7, :cond_4d

    .line 2544
    .line 2545
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2546
    .line 2547
    .line 2548
    move-result-object v7

    .line 2549
    check-cast v7, Landroid/content/pm/ShortcutInfo;

    .line 2550
    .line 2551
    invoke-virtual {v7}, Landroid/content/pm/ShortcutInfo;->getRank()I

    .line 2552
    .line 2553
    .line 2554
    move-result v8

    .line 2555
    if-le v8, v6, :cond_4c

    .line 2556
    .line 2557
    invoke-virtual {v7}, Landroid/content/pm/ShortcutInfo;->getId()Ljava/lang/String;

    .line 2558
    .line 2559
    .line 2560
    move-result-object v4

    .line 2561
    invoke-virtual {v7}, Landroid/content/pm/ShortcutInfo;->getRank()I

    .line 2562
    .line 2563
    .line 2564
    move-result v6

    .line 2565
    goto :goto_30

    .line 2566
    :cond_4d
    filled-new-array {v4}, [Ljava/lang/String;

    .line 2567
    .line 2568
    .line 2569
    move-result-object v2

    .line 2570
    invoke-static {v2}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 2571
    .line 2572
    .line 2573
    move-result-object v2

    .line 2574
    invoke-virtual {v0, v2}, Landroid/content/pm/ShortcutManager;->removeDynamicShortcuts(Ljava/util/List;)V

    .line 2575
    .line 2576
    .line 2577
    :cond_4e
    invoke-virtual {v5}, Lo5/a;->a()Landroid/content/pm/ShortcutInfo;

    .line 2578
    .line 2579
    .line 2580
    move-result-object v2

    .line 2581
    filled-new-array {v2}, [Landroid/content/pm/ShortcutInfo;

    .line 2582
    .line 2583
    .line 2584
    move-result-object v2

    .line 2585
    invoke-static {v2}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 2586
    .line 2587
    .line 2588
    move-result-object v2

    .line 2589
    invoke-virtual {v0, v2}, Landroid/content/pm/ShortcutManager;->addDynamicShortcuts(Ljava/util/List;)Z

    .line 2590
    .line 2591
    .line 2592
    :goto_31
    invoke-static {v1}, Lo5/c;->e(Landroid/content/Context;)Lo5/b;

    .line 2593
    .line 2594
    .line 2595
    move-result-object v0

    .line 2596
    :try_start_5
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2597
    .line 2598
    .line 2599
    new-instance v0, Ljava/util/ArrayList;

    .line 2600
    .line 2601
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 2602
    .line 2603
    .line 2604
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 2605
    .line 2606
    .line 2607
    move-result v2

    .line 2608
    if-lt v2, v3, :cond_51

    .line 2609
    .line 2610
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 2611
    .line 2612
    .line 2613
    move-result-object v0

    .line 2614
    const/4 v3, -0x1

    .line 2615
    const/4 v14, 0x0

    .line 2616
    :cond_4f
    :goto_32
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 2617
    .line 2618
    .line 2619
    move-result v2

    .line 2620
    if-eqz v2, :cond_50

    .line 2621
    .line 2622
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2623
    .line 2624
    .line 2625
    move-result-object v2

    .line 2626
    check-cast v2, Lo5/a;

    .line 2627
    .line 2628
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2629
    .line 2630
    .line 2631
    if-gez v3, :cond_4f

    .line 2632
    .line 2633
    iget-object v2, v2, Lo5/a;->b:Ljava/lang/String;

    .line 2634
    .line 2635
    move-object v14, v2

    .line 2636
    move v3, v11

    .line 2637
    goto :goto_32

    .line 2638
    :cond_50
    filled-new-array {v14}, [Ljava/lang/String;

    .line 2639
    .line 2640
    .line 2641
    move-result-object v0

    .line 2642
    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 2643
    .line 2644
    .line 2645
    goto :goto_33

    .line 2646
    :catchall_2
    move-exception v0

    .line 2647
    goto :goto_35

    .line 2648
    :cond_51
    :goto_33
    filled-new-array {v5}, [Lo5/a;

    .line 2649
    .line 2650
    .line 2651
    move-result-object v0

    .line 2652
    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;
    :try_end_5
    .catch Ljava/lang/Exception; {:try_start_5 .. :try_end_5} :catch_3
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 2653
    .line 2654
    .line 2655
    invoke-static {v1}, Lo5/c;->d(Landroid/content/Context;)Ljava/util/List;

    .line 2656
    .line 2657
    .line 2658
    move-result-object v0

    .line 2659
    check-cast v0, Ljava/util/ArrayList;

    .line 2660
    .line 2661
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 2662
    .line 2663
    .line 2664
    move-result-object v0

    .line 2665
    :goto_34
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 2666
    .line 2667
    .line 2668
    move-result v2

    .line 2669
    if-eqz v2, :cond_52

    .line 2670
    .line 2671
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2672
    .line 2673
    .line 2674
    move-result-object v2

    .line 2675
    check-cast v2, Landroidx/core/google/shortcuts/ShortcutInfoChangeListenerImpl;

    .line 2676
    .line 2677
    invoke-static {v5}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 2678
    .line 2679
    .line 2680
    move-result-object v3

    .line 2681
    invoke-virtual {v2, v3}, Landroidx/core/google/shortcuts/ShortcutInfoChangeListenerImpl;->a(Ljava/util/List;)V

    .line 2682
    .line 2683
    .line 2684
    goto :goto_34

    .line 2685
    :cond_52
    iget-object v0, v5, Lo5/a;->b:Ljava/lang/String;

    .line 2686
    .line 2687
    invoke-static {v1, v0}, Lo5/c;->f(Landroid/content/Context;Ljava/lang/String;)V

    .line 2688
    .line 2689
    .line 2690
    goto :goto_38

    .line 2691
    :goto_35
    invoke-static {v1}, Lo5/c;->d(Landroid/content/Context;)Ljava/util/List;

    .line 2692
    .line 2693
    .line 2694
    move-result-object v2

    .line 2695
    check-cast v2, Ljava/util/ArrayList;

    .line 2696
    .line 2697
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 2698
    .line 2699
    .line 2700
    move-result-object v2

    .line 2701
    :goto_36
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 2702
    .line 2703
    .line 2704
    move-result v3

    .line 2705
    if-eqz v3, :cond_53

    .line 2706
    .line 2707
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2708
    .line 2709
    .line 2710
    move-result-object v3

    .line 2711
    check-cast v3, Landroidx/core/google/shortcuts/ShortcutInfoChangeListenerImpl;

    .line 2712
    .line 2713
    invoke-static {v5}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 2714
    .line 2715
    .line 2716
    move-result-object v4

    .line 2717
    invoke-virtual {v3, v4}, Landroidx/core/google/shortcuts/ShortcutInfoChangeListenerImpl;->a(Ljava/util/List;)V

    .line 2718
    .line 2719
    .line 2720
    goto :goto_36

    .line 2721
    :cond_53
    iget-object v2, v5, Lo5/a;->b:Ljava/lang/String;

    .line 2722
    .line 2723
    invoke-static {v1, v2}, Lo5/c;->f(Landroid/content/Context;Ljava/lang/String;)V

    .line 2724
    .line 2725
    .line 2726
    throw v0

    .line 2727
    :catch_3
    invoke-static {v1}, Lo5/c;->d(Landroid/content/Context;)Ljava/util/List;

    .line 2728
    .line 2729
    .line 2730
    move-result-object v0

    .line 2731
    check-cast v0, Ljava/util/ArrayList;

    .line 2732
    .line 2733
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 2734
    .line 2735
    .line 2736
    move-result-object v0

    .line 2737
    :goto_37
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 2738
    .line 2739
    .line 2740
    move-result v2

    .line 2741
    if-eqz v2, :cond_52

    .line 2742
    .line 2743
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2744
    .line 2745
    .line 2746
    move-result-object v2

    .line 2747
    check-cast v2, Landroidx/core/google/shortcuts/ShortcutInfoChangeListenerImpl;

    .line 2748
    .line 2749
    invoke-static {v5}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 2750
    .line 2751
    .line 2752
    move-result-object v3

    .line 2753
    invoke-virtual {v2, v3}, Landroidx/core/google/shortcuts/ShortcutInfoChangeListenerImpl;->a(Ljava/util/List;)V

    .line 2754
    .line 2755
    .line 2756
    goto :goto_37

    .line 2757
    :goto_38
    return-object v19

    .line 2758
    :cond_54
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 2759
    .line 2760
    const-string v1, "Shortcut must have an intent"

    .line 2761
    .line 2762
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 2763
    .line 2764
    .line 2765
    throw v0

    .line 2766
    :cond_55
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 2767
    .line 2768
    const-string v1, "Shortcut must have a non-empty label"

    .line 2769
    .line 2770
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 2771
    .line 2772
    .line 2773
    throw v0

    .line 2774
    :pswitch_19
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 2775
    .line 2776
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 2777
    .line 2778
    .line 2779
    iget-object v0, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 2780
    .line 2781
    check-cast v0, Lay0/n;

    .line 2782
    .line 2783
    check-cast v9, Ll2/b1;

    .line 2784
    .line 2785
    invoke-interface {v9}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 2786
    .line 2787
    .line 2788
    move-result-object v1

    .line 2789
    check-cast v1, Ld3/b;

    .line 2790
    .line 2791
    iget-wide v1, v1, Ld3/b;->a:J

    .line 2792
    .line 2793
    const/16 v3, 0x20

    .line 2794
    .line 2795
    shr-long/2addr v1, v3

    .line 2796
    long-to-int v1, v1

    .line 2797
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 2798
    .line 2799
    .line 2800
    move-result v1

    .line 2801
    new-instance v2, Ljava/lang/Float;

    .line 2802
    .line 2803
    invoke-direct {v2, v1}, Ljava/lang/Float;-><init>(F)V

    .line 2804
    .line 2805
    .line 2806
    invoke-interface {v9}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 2807
    .line 2808
    .line 2809
    move-result-object v1

    .line 2810
    check-cast v1, Ld3/b;

    .line 2811
    .line 2812
    iget-wide v3, v1, Ld3/b;->a:J

    .line 2813
    .line 2814
    const-wide v5, 0xffffffffL

    .line 2815
    .line 2816
    .line 2817
    .line 2818
    .line 2819
    and-long/2addr v3, v5

    .line 2820
    long-to-int v1, v3

    .line 2821
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 2822
    .line 2823
    .line 2824
    move-result v1

    .line 2825
    new-instance v3, Ljava/lang/Float;

    .line 2826
    .line 2827
    invoke-direct {v3, v1}, Ljava/lang/Float;-><init>(F)V

    .line 2828
    .line 2829
    .line 2830
    invoke-interface {v0, v2, v3}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 2831
    .line 2832
    .line 2833
    return-object v19

    .line 2834
    :pswitch_1a
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 2835
    .line 2836
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 2837
    .line 2838
    .line 2839
    iget-object v0, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 2840
    .line 2841
    check-cast v0, Lo30/n;

    .line 2842
    .line 2843
    iget-object v0, v0, Lo30/n;->b:Lo30/i;

    .line 2844
    .line 2845
    check-cast v9, Ljava/lang/String;

    .line 2846
    .line 2847
    new-instance v1, Lp30/c;

    .line 2848
    .line 2849
    new-instance v2, Lp30/a;

    .line 2850
    .line 2851
    const/4 v3, 0x0

    .line 2852
    invoke-direct {v2, v9, v3}, Lp30/a;-><init>(Ljava/lang/String;Ljava/util/ArrayList;)V

    .line 2853
    .line 2854
    .line 2855
    invoke-static {v2}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 2856
    .line 2857
    .line 2858
    move-result-object v2

    .line 2859
    const/4 v6, 0x1

    .line 2860
    invoke-direct {v1, v6, v2}, Lp30/c;-><init>(ZLjava/util/List;)V

    .line 2861
    .line 2862
    .line 2863
    check-cast v0, Lm30/a;

    .line 2864
    .line 2865
    iget-object v0, v0, Lm30/a;->b:Lyy0/c2;

    .line 2866
    .line 2867
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 2868
    .line 2869
    .line 2870
    move-result-object v2

    .line 2871
    check-cast v2, Ljava/util/Collection;

    .line 2872
    .line 2873
    invoke-static {v2, v1}, Lmx0/q;->b0(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 2874
    .line 2875
    .line 2876
    move-result-object v1

    .line 2877
    invoke-virtual {v0, v3, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2878
    .line 2879
    .line 2880
    return-object v19

    .line 2881
    :pswitch_1b
    iget-object v0, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 2882
    .line 2883
    check-cast v0, Lp30/c;

    .line 2884
    .line 2885
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 2886
    .line 2887
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 2888
    .line 2889
    .line 2890
    check-cast v9, Lo30/c;

    .line 2891
    .line 2892
    iget-object v1, v9, Lo30/c;->b:Lo30/i;

    .line 2893
    .line 2894
    check-cast v1, Lm30/a;

    .line 2895
    .line 2896
    const-string v2, "messages"

    .line 2897
    .line 2898
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2899
    .line 2900
    .line 2901
    iget-object v1, v1, Lm30/a;->b:Lyy0/c2;

    .line 2902
    .line 2903
    invoke-virtual {v1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 2904
    .line 2905
    .line 2906
    move-result-object v2

    .line 2907
    check-cast v2, Ljava/util/Collection;

    .line 2908
    .line 2909
    invoke-static {v2, v0}, Lmx0/q;->b0(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 2910
    .line 2911
    .line 2912
    move-result-object v0

    .line 2913
    const/4 v3, 0x0

    .line 2914
    invoke-virtual {v1, v3, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2915
    .line 2916
    .line 2917
    return-object v19

    .line 2918
    :pswitch_1c
    move-object v3, v14

    .line 2919
    iget-object v0, v0, Lnz/g;->e:Ljava/lang/Object;

    .line 2920
    .line 2921
    check-cast v0, Lvy0/b0;

    .line 2922
    .line 2923
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 2924
    .line 2925
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 2926
    .line 2927
    .line 2928
    new-instance v1, Lnz/b;

    .line 2929
    .line 2930
    check-cast v9, Lnz/j;

    .line 2931
    .line 2932
    const/4 v5, 0x3

    .line 2933
    invoke-direct {v1, v9, v3, v5}, Lnz/b;-><init>(Lnz/j;Lkotlin/coroutines/Continuation;I)V

    .line 2934
    .line 2935
    .line 2936
    invoke-static {v0, v3, v3, v1, v5}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 2937
    .line 2938
    .line 2939
    new-instance v1, Lnz/b;

    .line 2940
    .line 2941
    const/4 v8, 0x4

    .line 2942
    invoke-direct {v1, v9, v3, v8}, Lnz/b;-><init>(Lnz/j;Lkotlin/coroutines/Continuation;I)V

    .line 2943
    .line 2944
    .line 2945
    invoke-static {v0, v3, v3, v1, v5}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 2946
    .line 2947
    .line 2948
    move-result-object v0

    .line 2949
    return-object v0

    .line 2950
    nop

    .line 2951
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
