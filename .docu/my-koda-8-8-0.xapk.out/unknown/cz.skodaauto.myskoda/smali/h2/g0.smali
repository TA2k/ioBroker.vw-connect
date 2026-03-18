.class public final synthetic Lh2/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lvy0/b0;

.field public final synthetic f:Lh2/r8;


# direct methods
.method public synthetic constructor <init>(Lh2/r8;Lvy0/b0;I)V
    .locals 0

    .line 1
    iput p3, p0, Lh2/g0;->d:I

    iput-object p1, p0, Lh2/g0;->f:Lh2/r8;

    iput-object p2, p0, Lh2/g0;->e:Lvy0/b0;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lvy0/b0;Lh2/r8;I)V
    .locals 0

    .line 2
    iput p3, p0, Lh2/g0;->d:I

    iput-object p1, p0, Lh2/g0;->e:Lvy0/b0;

    iput-object p2, p0, Lh2/g0;->f:Lh2/r8;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lh2/g0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lxk0/c0;

    .line 7
    .line 8
    const/4 v1, 0x6

    .line 9
    iget-object v2, p0, Lh2/g0;->f:Lh2/r8;

    .line 10
    .line 11
    const/4 v3, 0x0

    .line 12
    invoke-direct {v0, v2, v3, v1}, Lxk0/c0;-><init>(Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 13
    .line 14
    .line 15
    const/4 v1, 0x3

    .line 16
    iget-object p0, p0, Lh2/g0;->e:Lvy0/b0;

    .line 17
    .line 18
    invoke-static {p0, v3, v3, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 19
    .line 20
    .line 21
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_0
    new-instance v0, Lxk0/c0;

    .line 25
    .line 26
    const/4 v1, 0x4

    .line 27
    iget-object v2, p0, Lh2/g0;->f:Lh2/r8;

    .line 28
    .line 29
    const/4 v3, 0x0

    .line 30
    invoke-direct {v0, v2, v3, v1}, Lxk0/c0;-><init>(Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 31
    .line 32
    .line 33
    const/4 v1, 0x3

    .line 34
    iget-object p0, p0, Lh2/g0;->e:Lvy0/b0;

    .line 35
    .line 36
    invoke-static {p0, v3, v3, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 37
    .line 38
    .line 39
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 40
    .line 41
    return-object p0

    .line 42
    :pswitch_1
    new-instance v0, Lxk0/c0;

    .line 43
    .line 44
    const/4 v1, 0x3

    .line 45
    iget-object v2, p0, Lh2/g0;->f:Lh2/r8;

    .line 46
    .line 47
    const/4 v3, 0x0

    .line 48
    invoke-direct {v0, v2, v3, v1}, Lxk0/c0;-><init>(Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 49
    .line 50
    .line 51
    iget-object p0, p0, Lh2/g0;->e:Lvy0/b0;

    .line 52
    .line 53
    invoke-static {p0, v3, v3, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 54
    .line 55
    .line 56
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 57
    .line 58
    return-object p0

    .line 59
    :pswitch_2
    new-instance v0, Lxk0/c0;

    .line 60
    .line 61
    const/4 v1, 0x0

    .line 62
    iget-object v2, p0, Lh2/g0;->f:Lh2/r8;

    .line 63
    .line 64
    const/4 v3, 0x0

    .line 65
    invoke-direct {v0, v2, v3, v1}, Lxk0/c0;-><init>(Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 66
    .line 67
    .line 68
    const/4 v1, 0x3

    .line 69
    iget-object p0, p0, Lh2/g0;->e:Lvy0/b0;

    .line 70
    .line 71
    invoke-static {p0, v3, v3, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 72
    .line 73
    .line 74
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 75
    .line 76
    return-object p0

    .line 77
    :pswitch_3
    new-instance v0, Lh2/i0;

    .line 78
    .line 79
    const/16 v1, 0x1b

    .line 80
    .line 81
    iget-object v2, p0, Lh2/g0;->f:Lh2/r8;

    .line 82
    .line 83
    const/4 v3, 0x0

    .line 84
    invoke-direct {v0, v2, v3, v1}, Lh2/i0;-><init>(Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 85
    .line 86
    .line 87
    const/4 v1, 0x3

    .line 88
    iget-object p0, p0, Lh2/g0;->e:Lvy0/b0;

    .line 89
    .line 90
    invoke-static {p0, v3, v3, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 91
    .line 92
    .line 93
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 94
    .line 95
    return-object p0

    .line 96
    :pswitch_4
    new-instance v0, Lh2/i0;

    .line 97
    .line 98
    const/16 v1, 0x18

    .line 99
    .line 100
    iget-object v2, p0, Lh2/g0;->f:Lh2/r8;

    .line 101
    .line 102
    const/4 v3, 0x0

    .line 103
    invoke-direct {v0, v2, v3, v1}, Lh2/i0;-><init>(Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 104
    .line 105
    .line 106
    const/4 v1, 0x3

    .line 107
    iget-object p0, p0, Lh2/g0;->e:Lvy0/b0;

    .line 108
    .line 109
    invoke-static {p0, v3, v3, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 110
    .line 111
    .line 112
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 113
    .line 114
    return-object p0

    .line 115
    :pswitch_5
    new-instance v0, Lh2/i0;

    .line 116
    .line 117
    const/16 v1, 0x13

    .line 118
    .line 119
    iget-object v2, p0, Lh2/g0;->f:Lh2/r8;

    .line 120
    .line 121
    const/4 v3, 0x0

    .line 122
    invoke-direct {v0, v2, v3, v1}, Lh2/i0;-><init>(Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 123
    .line 124
    .line 125
    const/4 v1, 0x3

    .line 126
    iget-object p0, p0, Lh2/g0;->e:Lvy0/b0;

    .line 127
    .line 128
    invoke-static {p0, v3, v3, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 129
    .line 130
    .line 131
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 132
    .line 133
    return-object p0

    .line 134
    :pswitch_6
    new-instance v0, Lh2/i0;

    .line 135
    .line 136
    const/16 v1, 0x10

    .line 137
    .line 138
    iget-object v2, p0, Lh2/g0;->f:Lh2/r8;

    .line 139
    .line 140
    const/4 v3, 0x0

    .line 141
    invoke-direct {v0, v2, v3, v1}, Lh2/i0;-><init>(Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 142
    .line 143
    .line 144
    const/4 v1, 0x3

    .line 145
    iget-object p0, p0, Lh2/g0;->e:Lvy0/b0;

    .line 146
    .line 147
    invoke-static {p0, v3, v3, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 148
    .line 149
    .line 150
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 151
    .line 152
    return-object p0

    .line 153
    :pswitch_7
    iget-object v0, p0, Lh2/g0;->f:Lh2/r8;

    .line 154
    .line 155
    iget-object v1, v0, Lh2/r8;->e:Li2/p;

    .line 156
    .line 157
    iget-object v1, v1, Li2/p;->d:Lay0/k;

    .line 158
    .line 159
    sget-object v2, Lh2/s8;->f:Lh2/s8;

    .line 160
    .line 161
    invoke-interface {v1, v2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    move-result-object v1

    .line 165
    check-cast v1, Ljava/lang/Boolean;

    .line 166
    .line 167
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 168
    .line 169
    .line 170
    move-result v1

    .line 171
    if-eqz v1, :cond_0

    .line 172
    .line 173
    new-instance v1, Lh2/i0;

    .line 174
    .line 175
    const/16 v2, 0xd

    .line 176
    .line 177
    const/4 v3, 0x0

    .line 178
    invoke-direct {v1, v0, v3, v2}, Lh2/i0;-><init>(Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 179
    .line 180
    .line 181
    const/4 v0, 0x3

    .line 182
    iget-object p0, p0, Lh2/g0;->e:Lvy0/b0;

    .line 183
    .line 184
    invoke-static {p0, v3, v3, v1, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 185
    .line 186
    .line 187
    :cond_0
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 188
    .line 189
    return-object p0

    .line 190
    :pswitch_8
    new-instance v0, Lh2/i0;

    .line 191
    .line 192
    const/4 v1, 0x5

    .line 193
    iget-object v2, p0, Lh2/g0;->f:Lh2/r8;

    .line 194
    .line 195
    const/4 v3, 0x0

    .line 196
    invoke-direct {v0, v2, v3, v1}, Lh2/i0;-><init>(Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 197
    .line 198
    .line 199
    const/4 v1, 0x3

    .line 200
    iget-object p0, p0, Lh2/g0;->e:Lvy0/b0;

    .line 201
    .line 202
    invoke-static {p0, v3, v3, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 203
    .line 204
    .line 205
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 206
    .line 207
    return-object p0

    .line 208
    :pswitch_9
    new-instance v0, Lh2/i0;

    .line 209
    .line 210
    const/4 v1, 0x4

    .line 211
    iget-object v2, p0, Lh2/g0;->f:Lh2/r8;

    .line 212
    .line 213
    const/4 v3, 0x0

    .line 214
    invoke-direct {v0, v2, v3, v1}, Lh2/i0;-><init>(Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 215
    .line 216
    .line 217
    const/4 v1, 0x3

    .line 218
    iget-object p0, p0, Lh2/g0;->e:Lvy0/b0;

    .line 219
    .line 220
    invoke-static {p0, v3, v3, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 221
    .line 222
    .line 223
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 224
    .line 225
    return-object p0

    .line 226
    :pswitch_a
    new-instance v0, Lh2/i0;

    .line 227
    .line 228
    const/4 v1, 0x3

    .line 229
    iget-object v2, p0, Lh2/g0;->f:Lh2/r8;

    .line 230
    .line 231
    const/4 v3, 0x0

    .line 232
    invoke-direct {v0, v2, v3, v1}, Lh2/i0;-><init>(Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 233
    .line 234
    .line 235
    iget-object p0, p0, Lh2/g0;->e:Lvy0/b0;

    .line 236
    .line 237
    invoke-static {p0, v3, v3, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 238
    .line 239
    .line 240
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 241
    .line 242
    return-object p0

    .line 243
    :pswitch_b
    iget-object v0, p0, Lh2/g0;->f:Lh2/r8;

    .line 244
    .line 245
    invoke-virtual {v0}, Lh2/r8;->c()Lh2/s8;

    .line 246
    .line 247
    .line 248
    move-result-object v1

    .line 249
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 250
    .line 251
    .line 252
    move-result v1

    .line 253
    const/4 v2, 0x1

    .line 254
    const/4 v3, 0x3

    .line 255
    iget-object p0, p0, Lh2/g0;->e:Lvy0/b0;

    .line 256
    .line 257
    const/4 v4, 0x0

    .line 258
    if-eq v1, v2, :cond_2

    .line 259
    .line 260
    const/4 v2, 0x2

    .line 261
    if-eq v1, v2, :cond_1

    .line 262
    .line 263
    new-instance v1, Lh2/i0;

    .line 264
    .line 265
    const/4 v2, 0x2

    .line 266
    invoke-direct {v1, v0, v4, v2}, Lh2/i0;-><init>(Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 267
    .line 268
    .line 269
    invoke-static {p0, v4, v4, v1, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 270
    .line 271
    .line 272
    goto :goto_0

    .line 273
    :cond_1
    new-instance v1, Lh2/i0;

    .line 274
    .line 275
    const/4 v2, 0x1

    .line 276
    invoke-direct {v1, v0, v4, v2}, Lh2/i0;-><init>(Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 277
    .line 278
    .line 279
    invoke-static {p0, v4, v4, v1, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 280
    .line 281
    .line 282
    goto :goto_0

    .line 283
    :cond_2
    new-instance v1, Lh2/i0;

    .line 284
    .line 285
    const/4 v2, 0x0

    .line 286
    invoke-direct {v1, v0, v4, v2}, Lh2/i0;-><init>(Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 287
    .line 288
    .line 289
    invoke-static {p0, v4, v4, v1, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 290
    .line 291
    .line 292
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 293
    .line 294
    return-object p0

    .line 295
    :pswitch_data_0
    .packed-switch 0x0
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
