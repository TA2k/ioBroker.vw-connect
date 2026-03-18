.class public final Lib/h;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Lyy0/j;

.field public synthetic g:[Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lib/h;->d:I

    .line 2
    .line 3
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget p0, p0, Lib/h;->d:I

    .line 2
    .line 3
    check-cast p1, Lyy0/j;

    .line 4
    .line 5
    check-cast p2, [Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 8
    .line 9
    packed-switch p0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    new-instance p0, Lib/h;

    .line 13
    .line 14
    const/4 v0, 0x3

    .line 15
    const/4 v1, 0x2

    .line 16
    invoke-direct {p0, v0, p3, v1}, Lib/h;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lib/h;->f:Lyy0/j;

    .line 20
    .line 21
    iput-object p2, p0, Lib/h;->g:[Ljava/lang/Object;

    .line 22
    .line 23
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 24
    .line 25
    invoke-virtual {p0, p1}, Lib/h;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0

    .line 30
    :pswitch_0
    new-instance p0, Lib/h;

    .line 31
    .line 32
    const/4 v0, 0x3

    .line 33
    const/4 v1, 0x1

    .line 34
    invoke-direct {p0, v0, p3, v1}, Lib/h;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 35
    .line 36
    .line 37
    iput-object p1, p0, Lib/h;->f:Lyy0/j;

    .line 38
    .line 39
    iput-object p2, p0, Lib/h;->g:[Ljava/lang/Object;

    .line 40
    .line 41
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    invoke-virtual {p0, p1}, Lib/h;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0

    .line 48
    :pswitch_1
    new-instance p0, Lib/h;

    .line 49
    .line 50
    const/4 v0, 0x3

    .line 51
    const/4 v1, 0x0

    .line 52
    invoke-direct {p0, v0, p3, v1}, Lib/h;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 53
    .line 54
    .line 55
    iput-object p1, p0, Lib/h;->f:Lyy0/j;

    .line 56
    .line 57
    iput-object p2, p0, Lib/h;->g:[Ljava/lang/Object;

    .line 58
    .line 59
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 60
    .line 61
    invoke-virtual {p0, p1}, Lib/h;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    return-object p0

    .line 66
    nop

    .line 67
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lib/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lib/h;->e:I

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    if-eqz v1, :cond_1

    .line 12
    .line 13
    if-ne v1, v2, :cond_0

    .line 14
    .line 15
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 20
    .line 21
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 22
    .line 23
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    throw p0

    .line 27
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    iget-object p1, p0, Lib/h;->f:Lyy0/j;

    .line 31
    .line 32
    iget-object v1, p0, Lib/h;->g:[Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v1, [Ljava/lang/Boolean;

    .line 35
    .line 36
    sget-object v3, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 37
    .line 38
    invoke-static {v3, v1}, Lmx0/n;->e(Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    const/4 v3, 0x0

    .line 47
    iput-object v3, p0, Lib/h;->f:Lyy0/j;

    .line 48
    .line 49
    iput-object v3, p0, Lib/h;->g:[Ljava/lang/Object;

    .line 50
    .line 51
    iput v2, p0, Lib/h;->e:I

    .line 52
    .line 53
    invoke-interface {p1, v1, p0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    if-ne p0, v0, :cond_2

    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 61
    .line 62
    :goto_1
    return-object v0

    .line 63
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 64
    .line 65
    iget v1, p0, Lib/h;->e:I

    .line 66
    .line 67
    const/4 v2, 0x1

    .line 68
    if-eqz v1, :cond_4

    .line 69
    .line 70
    if-ne v1, v2, :cond_3

    .line 71
    .line 72
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    goto/16 :goto_5

    .line 76
    .line 77
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 78
    .line 79
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 80
    .line 81
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    throw p0

    .line 85
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    iget-object v1, p0, Lib/h;->f:Lyy0/j;

    .line 89
    .line 90
    iget-object p1, p0, Lib/h;->g:[Ljava/lang/Object;

    .line 91
    .line 92
    check-cast p1, [Lne0/s;

    .line 93
    .line 94
    new-instance v3, Ljava/util/ArrayList;

    .line 95
    .line 96
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 97
    .line 98
    .line 99
    array-length v4, p1

    .line 100
    const/4 v5, 0x0

    .line 101
    :goto_2
    const/4 v6, 0x0

    .line 102
    if-ge v5, v4, :cond_8

    .line 103
    .line 104
    aget-object v7, p1, v5

    .line 105
    .line 106
    instance-of v8, v7, Lne0/e;

    .line 107
    .line 108
    if-eqz v8, :cond_5

    .line 109
    .line 110
    check-cast v7, Lne0/e;

    .line 111
    .line 112
    goto :goto_3

    .line 113
    :cond_5
    move-object v7, v6

    .line 114
    :goto_3
    if-eqz v7, :cond_6

    .line 115
    .line 116
    iget-object v6, v7, Lne0/e;->a:Ljava/lang/Object;

    .line 117
    .line 118
    check-cast v6, Ljava/time/OffsetDateTime;

    .line 119
    .line 120
    :cond_6
    if-eqz v6, :cond_7

    .line 121
    .line 122
    invoke-virtual {v3, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 123
    .line 124
    .line 125
    :cond_7
    add-int/lit8 v5, v5, 0x1

    .line 126
    .line 127
    goto :goto_2

    .line 128
    :cond_8
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 129
    .line 130
    .line 131
    move-result-object v3

    .line 132
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 133
    .line 134
    .line 135
    move-result p1

    .line 136
    if-nez p1, :cond_9

    .line 137
    .line 138
    move-object p1, v6

    .line 139
    goto :goto_4

    .line 140
    :cond_9
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object p1

    .line 144
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 145
    .line 146
    .line 147
    move-result v4

    .line 148
    if-nez v4, :cond_a

    .line 149
    .line 150
    goto :goto_4

    .line 151
    :cond_a
    move-object v4, p1

    .line 152
    check-cast v4, Ljava/time/OffsetDateTime;

    .line 153
    .line 154
    invoke-virtual {v4}, Ljava/time/OffsetDateTime;->toInstant()Ljava/time/Instant;

    .line 155
    .line 156
    .line 157
    move-result-object v4

    .line 158
    invoke-virtual {v4}, Ljava/time/Instant;->toEpochMilli()J

    .line 159
    .line 160
    .line 161
    move-result-wide v4

    .line 162
    :cond_b
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object v7

    .line 166
    move-object v8, v7

    .line 167
    check-cast v8, Ljava/time/OffsetDateTime;

    .line 168
    .line 169
    invoke-virtual {v8}, Ljava/time/OffsetDateTime;->toInstant()Ljava/time/Instant;

    .line 170
    .line 171
    .line 172
    move-result-object v8

    .line 173
    invoke-virtual {v8}, Ljava/time/Instant;->toEpochMilli()J

    .line 174
    .line 175
    .line 176
    move-result-wide v8

    .line 177
    cmp-long v10, v4, v8

    .line 178
    .line 179
    if-gez v10, :cond_c

    .line 180
    .line 181
    move-object p1, v7

    .line 182
    move-wide v4, v8

    .line 183
    :cond_c
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 184
    .line 185
    .line 186
    move-result v7

    .line 187
    if-nez v7, :cond_b

    .line 188
    .line 189
    :goto_4
    iput-object v6, p0, Lib/h;->f:Lyy0/j;

    .line 190
    .line 191
    iput-object v6, p0, Lib/h;->g:[Ljava/lang/Object;

    .line 192
    .line 193
    iput v2, p0, Lib/h;->e:I

    .line 194
    .line 195
    invoke-interface {v1, p1, p0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    move-result-object p0

    .line 199
    if-ne p0, v0, :cond_d

    .line 200
    .line 201
    goto :goto_6

    .line 202
    :cond_d
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 203
    .line 204
    :goto_6
    return-object v0

    .line 205
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 206
    .line 207
    iget v1, p0, Lib/h;->e:I

    .line 208
    .line 209
    const/4 v2, 0x1

    .line 210
    if-eqz v1, :cond_f

    .line 211
    .line 212
    if-ne v1, v2, :cond_e

    .line 213
    .line 214
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 215
    .line 216
    .line 217
    goto :goto_a

    .line 218
    :cond_e
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 219
    .line 220
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 221
    .line 222
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 223
    .line 224
    .line 225
    throw p0

    .line 226
    :cond_f
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 227
    .line 228
    .line 229
    iget-object p1, p0, Lib/h;->f:Lyy0/j;

    .line 230
    .line 231
    iget-object v1, p0, Lib/h;->g:[Ljava/lang/Object;

    .line 232
    .line 233
    check-cast v1, [Lib/c;

    .line 234
    .line 235
    array-length v3, v1

    .line 236
    const/4 v4, 0x0

    .line 237
    :goto_7
    sget-object v5, Lib/a;->a:Lib/a;

    .line 238
    .line 239
    if-ge v4, v3, :cond_11

    .line 240
    .line 241
    aget-object v6, v1, v4

    .line 242
    .line 243
    invoke-static {v6, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 244
    .line 245
    .line 246
    move-result v7

    .line 247
    if-nez v7, :cond_10

    .line 248
    .line 249
    goto :goto_8

    .line 250
    :cond_10
    add-int/lit8 v4, v4, 0x1

    .line 251
    .line 252
    goto :goto_7

    .line 253
    :cond_11
    const/4 v6, 0x0

    .line 254
    :goto_8
    if-nez v6, :cond_12

    .line 255
    .line 256
    goto :goto_9

    .line 257
    :cond_12
    move-object v5, v6

    .line 258
    :goto_9
    iput v2, p0, Lib/h;->e:I

    .line 259
    .line 260
    invoke-interface {p1, v5, p0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 261
    .line 262
    .line 263
    move-result-object p0

    .line 264
    if-ne p0, v0, :cond_13

    .line 265
    .line 266
    goto :goto_b

    .line 267
    :cond_13
    :goto_a
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 268
    .line 269
    :goto_b
    return-object v0

    .line 270
    nop

    .line 271
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
