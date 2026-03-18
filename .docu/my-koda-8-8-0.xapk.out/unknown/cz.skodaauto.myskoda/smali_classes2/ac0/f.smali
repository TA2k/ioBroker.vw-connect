.class public final Lac0/f;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lac0/w;


# direct methods
.method public synthetic constructor <init>(Lac0/w;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lac0/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lac0/f;->f:Lac0/w;

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
    .locals 1

    .line 1
    iget p1, p0, Lac0/f;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lac0/f;

    .line 7
    .line 8
    iget-object p0, p0, Lac0/f;->f:Lac0/w;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lac0/f;-><init>(Lac0/w;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lac0/f;

    .line 16
    .line 17
    iget-object p0, p0, Lac0/f;->f:Lac0/w;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lac0/f;-><init>(Lac0/w;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lac0/f;->d:I

    .line 2
    .line 3
    check-cast p1, Lvy0/b0;

    .line 4
    .line 5
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lac0/f;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lac0/f;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lac0/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lac0/f;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lac0/f;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lac0/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 35
    .line 36
    return-object p0

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lac0/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lac0/f;->f:Lac0/w;

    .line 7
    .line 8
    iget-object v0, v1, Lac0/w;->s:Ljava/util/concurrent/ConcurrentHashMap;

    .line 9
    .line 10
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 11
    .line 12
    iget v3, p0, Lac0/f;->e:I

    .line 13
    .line 14
    const/4 v4, 0x0

    .line 15
    const/4 v5, 0x2

    .line 16
    const/4 v6, 0x1

    .line 17
    if-eqz v3, :cond_2

    .line 18
    .line 19
    if-eq v3, v6, :cond_1

    .line 20
    .line 21
    if-ne v3, v5, :cond_0

    .line 22
    .line 23
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 24
    .line 25
    .line 26
    goto :goto_1

    .line 27
    :catch_0
    move-exception v0

    .line 28
    move-object p0, v0

    .line 29
    goto/16 :goto_3

    .line 30
    .line 31
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 32
    .line 33
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 34
    .line 35
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw p0

    .line 39
    :cond_1
    :try_start_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 40
    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    :try_start_2
    new-instance p1, La2/m;

    .line 47
    .line 48
    const/16 v3, 0xb

    .line 49
    .line 50
    invoke-direct {p1, v3}, La2/m;-><init>(I)V

    .line 51
    .line 52
    .line 53
    invoke-static {v4, v1, p1}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 54
    .line 55
    .line 56
    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentHashMap;->isEmpty()Z

    .line 57
    .line 58
    .line 59
    move-result p1

    .line 60
    if-nez p1, :cond_7

    .line 61
    .line 62
    iput v6, p0, Lac0/f;->e:I

    .line 63
    .line 64
    iget-object p1, v1, Lac0/w;->j:Lpx0/g;

    .line 65
    .line 66
    new-instance v3, Lac0/n;

    .line 67
    .line 68
    const/4 v7, 0x1

    .line 69
    invoke-direct {v3, v1, v4, v7}, Lac0/n;-><init>(Lac0/w;Lkotlin/coroutines/Continuation;I)V

    .line 70
    .line 71
    .line 72
    invoke-static {p1, v3, p0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    if-ne p1, v2, :cond_3

    .line 77
    .line 78
    goto/16 :goto_4

    .line 79
    .line 80
    :cond_3
    :goto_0
    check-cast p1, Ljava/lang/Boolean;

    .line 81
    .line 82
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 83
    .line 84
    .line 85
    move-result p1

    .line 86
    if-nez p1, :cond_4

    .line 87
    .line 88
    iput-boolean v6, v1, Lac0/w;->p:Z

    .line 89
    .line 90
    iput v5, p0, Lac0/f;->e:I

    .line 91
    .line 92
    invoke-virtual {v1, v6, p0}, Lac0/w;->d(ZLrx0/c;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    if-ne p0, v2, :cond_4

    .line 97
    .line 98
    goto :goto_4

    .line 99
    :cond_4
    :goto_1
    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentHashMap;->keySet()Ljava/util/Set;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    const-string p1, "<get-keys>(...)"

    .line 104
    .line 105
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    check-cast p0, Ljava/lang/Iterable;

    .line 109
    .line 110
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    :cond_5
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 115
    .line 116
    .line 117
    move-result p1

    .line 118
    if-eqz p1, :cond_8

    .line 119
    .line 120
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object p1

    .line 124
    check-cast p1, Ldc0/b;

    .line 125
    .line 126
    iget-object p1, p1, Ldc0/b;->a:Ljava/lang/String;

    .line 127
    .line 128
    const/4 v2, 0x0

    .line 129
    invoke-virtual {v1, p1, v2}, Lac0/w;->f(Ljava/lang/String;Z)V

    .line 130
    .line 131
    .line 132
    new-instance v3, Ldc0/b;

    .line 133
    .line 134
    invoke-direct {v3, p1}, Ldc0/b;-><init>(Ljava/lang/String;)V

    .line 135
    .line 136
    .line 137
    invoke-virtual {v0, v3}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object v3

    .line 141
    check-cast v3, Lac0/l;

    .line 142
    .line 143
    if-eqz v3, :cond_6

    .line 144
    .line 145
    iget v2, v3, Lac0/l;->a:I

    .line 146
    .line 147
    :cond_6
    if-lez v2, :cond_5

    .line 148
    .line 149
    invoke-virtual {v1, p1}, Lac0/w;->e(Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    goto :goto_2

    .line 153
    :cond_7
    new-instance p0, La2/m;

    .line 154
    .line 155
    const/16 p1, 0xc

    .line 156
    .line 157
    invoke-direct {p0, p1}, La2/m;-><init>(I)V

    .line 158
    .line 159
    .line 160
    invoke-static {v4, v1, p0}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 161
    .line 162
    .line 163
    :cond_8
    new-instance v2, Lne0/e;

    .line 164
    .line 165
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 166
    .line 167
    invoke-direct {v2, p0}, Lne0/e;-><init>(Ljava/lang/Object;)V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0

    .line 168
    .line 169
    .line 170
    goto :goto_4

    .line 171
    :goto_3
    new-instance p1, Lac0/b;

    .line 172
    .line 173
    const/4 v0, 0x6

    .line 174
    invoke-direct {p1, v0, p0}, Lac0/b;-><init>(ILjava/lang/Exception;)V

    .line 175
    .line 176
    .line 177
    invoke-static {v4, v1, p1}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 178
    .line 179
    .line 180
    new-instance v5, Lne0/c;

    .line 181
    .line 182
    new-instance v6, Ljava/io/IOException;

    .line 183
    .line 184
    const-string p1, "Unable to manual reconnect to MQTT broker."

    .line 185
    .line 186
    invoke-direct {v6, p1, p0}, Ljava/io/IOException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 187
    .line 188
    .line 189
    const/4 v9, 0x0

    .line 190
    const/16 v10, 0x1e

    .line 191
    .line 192
    const/4 v7, 0x0

    .line 193
    const/4 v8, 0x0

    .line 194
    invoke-direct/range {v5 .. v10}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 195
    .line 196
    .line 197
    move-object v2, v5

    .line 198
    :goto_4
    return-object v2

    .line 199
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 200
    .line 201
    iget v1, p0, Lac0/f;->e:I

    .line 202
    .line 203
    const/4 v2, 0x1

    .line 204
    if-eqz v1, :cond_a

    .line 205
    .line 206
    if-eq v1, v2, :cond_9

    .line 207
    .line 208
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 209
    .line 210
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 211
    .line 212
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 213
    .line 214
    .line 215
    throw p0

    .line 216
    :cond_9
    invoke-static {p1}, Lc1/j0;->i(Ljava/lang/Object;)La8/r0;

    .line 217
    .line 218
    .line 219
    move-result-object p0

    .line 220
    throw p0

    .line 221
    :cond_a
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 222
    .line 223
    .line 224
    iget-object p1, p0, Lac0/f;->f:Lac0/w;

    .line 225
    .line 226
    iget-object v1, p1, Lac0/w;->r:Lac0/q;

    .line 227
    .line 228
    iget-object v1, v1, Lac0/q;->d:Lyy0/q1;

    .line 229
    .line 230
    new-instance v3, Lac0/e;

    .line 231
    .line 232
    const/4 v4, 0x0

    .line 233
    invoke-direct {v3, p1, v4}, Lac0/e;-><init>(Ljava/lang/Object;I)V

    .line 234
    .line 235
    .line 236
    iput v2, p0, Lac0/f;->e:I

    .line 237
    .line 238
    invoke-virtual {v1, v3, p0}, Lyy0/q1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 239
    .line 240
    .line 241
    return-object v0

    .line 242
    nop

    .line 243
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
