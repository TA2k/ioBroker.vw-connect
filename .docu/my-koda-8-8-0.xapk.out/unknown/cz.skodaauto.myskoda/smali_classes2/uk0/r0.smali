.class public final Luk0/r0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Luk0/r;

.field public final b:Luk0/v;


# direct methods
.method public constructor <init>(Luk0/r;Luk0/v;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Luk0/r0;->a:Luk0/r;

    .line 5
    .line 6
    iput-object p2, p0, Luk0/r0;->b:Luk0/v;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Luk0/r0;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p1, Luk0/q0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Luk0/q0;

    .line 7
    .line 8
    iget v1, v0, Luk0/q0;->f:I

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
    iput v1, v0, Luk0/q0;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Luk0/q0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Luk0/q0;-><init>(Luk0/r0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Luk0/q0;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Luk0/q0;->f:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    const/4 v5, 0x0

    .line 34
    if-eqz v2, :cond_3

    .line 35
    .line 36
    if-eq v2, v4, :cond_2

    .line 37
    .line 38
    if-ne v2, v3, :cond_1

    .line 39
    .line 40
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    goto/16 :goto_7

    .line 44
    .line 45
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 46
    .line 47
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 48
    .line 49
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iget-object p1, p0, Luk0/r0;->b:Luk0/v;

    .line 61
    .line 62
    check-cast p1, Lsk0/b;

    .line 63
    .line 64
    iget-object p1, p1, Lsk0/b;->b:Lyy0/l1;

    .line 65
    .line 66
    iput v4, v0, Luk0/q0;->f:I

    .line 67
    .line 68
    invoke-static {p1, v0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object p1

    .line 72
    if-ne p1, v1, :cond_4

    .line 73
    .line 74
    goto/16 :goto_6

    .line 75
    .line 76
    :cond_4
    :goto_1
    instance-of v2, p1, Lne0/e;

    .line 77
    .line 78
    if-eqz v2, :cond_5

    .line 79
    .line 80
    check-cast p1, Lne0/e;

    .line 81
    .line 82
    goto :goto_2

    .line 83
    :cond_5
    move-object p1, v5

    .line 84
    :goto_2
    if-eqz p1, :cond_16

    .line 85
    .line 86
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 87
    .line 88
    check-cast p1, Lvk0/j0;

    .line 89
    .line 90
    if-nez p1, :cond_6

    .line 91
    .line 92
    goto/16 :goto_8

    .line 93
    .line 94
    :cond_6
    invoke-interface {p1}, Lvk0/j0;->getId()Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object v2

    .line 98
    instance-of v6, p1, Lvk0/j;

    .line 99
    .line 100
    if-eqz v6, :cond_7

    .line 101
    .line 102
    sget-object v6, Lvk0/k0;->d:Lvk0/k0;

    .line 103
    .line 104
    goto :goto_4

    .line 105
    :cond_7
    instance-of v6, p1, Lvk0/q;

    .line 106
    .line 107
    if-eqz v6, :cond_8

    .line 108
    .line 109
    sget-object v6, Lvk0/k0;->e:Lvk0/k0;

    .line 110
    .line 111
    goto :goto_4

    .line 112
    :cond_8
    instance-of v6, p1, Lvk0/p;

    .line 113
    .line 114
    if-eqz v6, :cond_9

    .line 115
    .line 116
    sget-object v6, Lvk0/k0;->f:Lvk0/k0;

    .line 117
    .line 118
    goto :goto_4

    .line 119
    :cond_9
    instance-of v6, p1, Lvk0/t;

    .line 120
    .line 121
    if-eqz v6, :cond_a

    .line 122
    .line 123
    sget-object v6, Lvk0/k0;->k:Lvk0/k0;

    .line 124
    .line 125
    goto :goto_4

    .line 126
    :cond_a
    instance-of v6, p1, Lvk0/c0;

    .line 127
    .line 128
    if-eqz v6, :cond_b

    .line 129
    .line 130
    sget-object v6, Lvk0/k0;->g:Lvk0/k0;

    .line 131
    .line 132
    goto :goto_4

    .line 133
    :cond_b
    instance-of v6, p1, Lvk0/d0;

    .line 134
    .line 135
    if-eqz v6, :cond_d

    .line 136
    .line 137
    sget-object v6, Lvk0/k0;->i:Lvk0/k0;

    .line 138
    .line 139
    move-object v7, p1

    .line 140
    check-cast v7, Lvk0/d0;

    .line 141
    .line 142
    iget-boolean v7, v7, Lvk0/d0;->n:Z

    .line 143
    .line 144
    if-eqz v7, :cond_c

    .line 145
    .line 146
    goto :goto_3

    .line 147
    :cond_c
    move-object v6, v5

    .line 148
    :goto_3
    if-nez v6, :cond_11

    .line 149
    .line 150
    sget-object v6, Lvk0/k0;->h:Lvk0/k0;

    .line 151
    .line 152
    goto :goto_4

    .line 153
    :cond_d
    instance-of v6, p1, Lvk0/s0;

    .line 154
    .line 155
    if-eqz v6, :cond_e

    .line 156
    .line 157
    sget-object v6, Lvk0/k0;->j:Lvk0/k0;

    .line 158
    .line 159
    goto :goto_4

    .line 160
    :cond_e
    instance-of v6, p1, Lvk0/t0;

    .line 161
    .line 162
    if-eqz v6, :cond_f

    .line 163
    .line 164
    sget-object v6, Lvk0/k0;->l:Lvk0/k0;

    .line 165
    .line 166
    goto :goto_4

    .line 167
    :cond_f
    instance-of v6, p1, Lvk0/v;

    .line 168
    .line 169
    if-eqz v6, :cond_10

    .line 170
    .line 171
    sget-object v6, Lvk0/k0;->m:Lvk0/k0;

    .line 172
    .line 173
    goto :goto_4

    .line 174
    :cond_10
    instance-of v6, p1, Lvk0/a;

    .line 175
    .line 176
    if-eqz v6, :cond_14

    .line 177
    .line 178
    sget-object v6, Lvk0/k0;->n:Lvk0/k0;

    .line 179
    .line 180
    :cond_11
    :goto_4
    invoke-interface {p1}, Lvk0/j0;->f()Lvk0/y;

    .line 181
    .line 182
    .line 183
    move-result-object p1

    .line 184
    if-eqz p1, :cond_12

    .line 185
    .line 186
    iget-object p1, p1, Lvk0/y;->a:Ljava/lang/String;

    .line 187
    .line 188
    goto :goto_5

    .line 189
    :cond_12
    move-object p1, v5

    .line 190
    :goto_5
    iput v3, v0, Luk0/q0;->f:I

    .line 191
    .line 192
    new-instance v3, Luk0/k;

    .line 193
    .line 194
    invoke-direct {v3, v2, v6, p1, v4}, Luk0/k;-><init>(Ljava/lang/String;Lvk0/k0;Ljava/lang/String;Z)V

    .line 195
    .line 196
    .line 197
    iget-object p1, p0, Luk0/r0;->a:Luk0/r;

    .line 198
    .line 199
    invoke-virtual {p1, v3, v0}, Luk0/r;->c(Luk0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    move-result-object p1

    .line 203
    if-ne p1, v1, :cond_13

    .line 204
    .line 205
    :goto_6
    return-object v1

    .line 206
    :cond_13
    :goto_7
    check-cast p1, Lyy0/i;

    .line 207
    .line 208
    new-instance v0, Lrp0/a;

    .line 209
    .line 210
    const/16 v1, 0x18

    .line 211
    .line 212
    invoke-direct {v0, p0, v5, v1}, Lrp0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 213
    .line 214
    .line 215
    new-instance v1, Lne0/n;

    .line 216
    .line 217
    invoke-direct {v1, v0, p1}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 218
    .line 219
    .line 220
    new-instance p1, Lkn/o;

    .line 221
    .line 222
    const/4 v0, 0x5

    .line 223
    invoke-direct {p1, p0, v5, v0}, Lkn/o;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 224
    .line 225
    .line 226
    new-instance p0, Lyy0/x;

    .line 227
    .line 228
    invoke-direct {p0, v1, p1}, Lyy0/x;-><init>(Lyy0/i;Lay0/o;)V

    .line 229
    .line 230
    .line 231
    return-object p0

    .line 232
    :cond_14
    instance-of p0, p1, Lvk0/d;

    .line 233
    .line 234
    if-eqz p0, :cond_15

    .line 235
    .line 236
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 237
    .line 238
    new-instance v0, Ljava/lang/StringBuilder;

    .line 239
    .line 240
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 241
    .line 242
    .line 243
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 244
    .line 245
    .line 246
    const-string p1, " should not be final class"

    .line 247
    .line 248
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 249
    .line 250
    .line 251
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 252
    .line 253
    .line 254
    move-result-object p1

    .line 255
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 256
    .line 257
    .line 258
    throw p0

    .line 259
    :cond_15
    new-instance p0, La8/r0;

    .line 260
    .line 261
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 262
    .line 263
    .line 264
    throw p0

    .line 265
    :cond_16
    :goto_8
    new-instance v0, Lne0/c;

    .line 266
    .line 267
    new-instance v1, Ljava/util/NoSuchElementException;

    .line 268
    .line 269
    const-string p0, "Trying to refresh selected poi, when no poi is selected!"

    .line 270
    .line 271
    invoke-direct {v1, p0}, Ljava/util/NoSuchElementException;-><init>(Ljava/lang/String;)V

    .line 272
    .line 273
    .line 274
    const/4 v4, 0x0

    .line 275
    const/16 v5, 0x1e

    .line 276
    .line 277
    const/4 v2, 0x0

    .line 278
    const/4 v3, 0x0

    .line 279
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 280
    .line 281
    .line 282
    new-instance p0, Lyy0/m;

    .line 283
    .line 284
    const/4 p1, 0x0

    .line 285
    invoke-direct {p0, v0, p1}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 286
    .line 287
    .line 288
    return-object p0
.end method
