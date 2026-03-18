.class public final Ly70/b;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ly70/f;


# direct methods
.method public synthetic constructor <init>(Ly70/f;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ly70/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ly70/b;->f:Ly70/f;

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
    iget p1, p0, Ly70/b;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Ly70/b;

    .line 7
    .line 8
    iget-object p0, p0, Ly70/b;->f:Ly70/f;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Ly70/b;-><init>(Ly70/f;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Ly70/b;

    .line 16
    .line 17
    iget-object p0, p0, Ly70/b;->f:Ly70/f;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Ly70/b;-><init>(Ly70/f;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Ly70/b;->d:I

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
    invoke-virtual {p0, p1, p2}, Ly70/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ly70/b;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ly70/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ly70/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ly70/b;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ly70/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    iget v0, p0, Ly70/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Ly70/b;->e:I

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
    goto/16 :goto_3

    .line 19
    .line 20
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 21
    .line 22
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 23
    .line 24
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    throw p0

    .line 28
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    iget-object p1, p0, Ly70/b;->f:Ly70/f;

    .line 32
    .line 33
    invoke-virtual {p1}, Lql0/j;->a()Lql0/h;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    check-cast v1, Ly70/d;

    .line 38
    .line 39
    iget-object v3, v1, Ly70/d;->f:Ljava/util/List;

    .line 40
    .line 41
    check-cast v3, Ljava/lang/Iterable;

    .line 42
    .line 43
    new-instance v4, Ljava/util/ArrayList;

    .line 44
    .line 45
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 46
    .line 47
    .line 48
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 49
    .line 50
    .line 51
    move-result-object v3

    .line 52
    :cond_2
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 53
    .line 54
    .line 55
    move-result v5

    .line 56
    if-eqz v5, :cond_3

    .line 57
    .line 58
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v5

    .line 62
    move-object v6, v5

    .line 63
    check-cast v6, Ly70/c;

    .line 64
    .line 65
    iget-boolean v6, v6, Ly70/c;->c:Z

    .line 66
    .line 67
    if-eqz v6, :cond_2

    .line 68
    .line 69
    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_3
    new-instance v9, Ljava/util/ArrayList;

    .line 74
    .line 75
    const/16 v3, 0xa

    .line 76
    .line 77
    invoke-static {v4, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 78
    .line 79
    .line 80
    move-result v3

    .line 81
    invoke-direct {v9, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 82
    .line 83
    .line 84
    invoke-virtual {v4}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 85
    .line 86
    .line 87
    move-result-object v3

    .line 88
    :goto_1
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 89
    .line 90
    .line 91
    move-result v4

    .line 92
    if-eqz v4, :cond_4

    .line 93
    .line 94
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v4

    .line 98
    check-cast v4, Ly70/c;

    .line 99
    .line 100
    iget-object v4, v4, Ly70/c;->a:Lcq0/w;

    .line 101
    .line 102
    invoke-virtual {v9, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    goto :goto_1

    .line 106
    :cond_4
    iget-boolean v3, v1, Ly70/d;->l:Z

    .line 107
    .line 108
    if-eqz v3, :cond_5

    .line 109
    .line 110
    new-instance v7, Lcq0/i;

    .line 111
    .line 112
    iget-object v8, v1, Ly70/d;->h:Lqr0/d;

    .line 113
    .line 114
    iget-object v10, v1, Ly70/d;->b:Ljava/time/OffsetDateTime;

    .line 115
    .line 116
    iget-object v11, v1, Ly70/d;->c:Ljava/time/OffsetDateTime;

    .line 117
    .line 118
    iget-object v12, v1, Ly70/d;->e:Ljava/lang/String;

    .line 119
    .line 120
    iget-boolean v13, v1, Ly70/d;->d:Z

    .line 121
    .line 122
    invoke-direct/range {v7 .. v13}, Lcq0/i;-><init>(Lqr0/d;Ljava/util/ArrayList;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/lang/String;Z)V

    .line 123
    .line 124
    .line 125
    goto :goto_2

    .line 126
    :cond_5
    const/4 v7, 0x0

    .line 127
    :goto_2
    if-eqz v7, :cond_6

    .line 128
    .line 129
    iput v2, p0, Ly70/b;->e:I

    .line 130
    .line 131
    invoke-static {p1, v7, p0}, Ly70/f;->h(Ly70/f;Lcq0/i;Lrx0/c;)Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    if-ne p0, v0, :cond_7

    .line 136
    .line 137
    goto :goto_4

    .line 138
    :cond_6
    new-instance v2, Ljava/lang/IllegalStateException;

    .line 139
    .line 140
    const-string p0, "Mandatory fields are not filled"

    .line 141
    .line 142
    invoke-direct {v2, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    invoke-virtual {p1}, Lql0/j;->a()Lql0/h;

    .line 146
    .line 147
    .line 148
    move-result-object p0

    .line 149
    check-cast p0, Ly70/d;

    .line 150
    .line 151
    new-instance v1, Lne0/c;

    .line 152
    .line 153
    const/4 v5, 0x0

    .line 154
    const/16 v6, 0x1e

    .line 155
    .line 156
    const/4 v3, 0x0

    .line 157
    const/4 v4, 0x0

    .line 158
    invoke-direct/range {v1 .. v6}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 159
    .line 160
    .line 161
    iget-object v0, p1, Ly70/f;->m:Lij0/a;

    .line 162
    .line 163
    invoke-static {v1, v0}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 164
    .line 165
    .line 166
    move-result-object v4

    .line 167
    const/4 v12, 0x0

    .line 168
    const/16 v13, 0x1be

    .line 169
    .line 170
    const/4 v6, 0x0

    .line 171
    const/4 v7, 0x0

    .line 172
    const/4 v8, 0x0

    .line 173
    const/4 v9, 0x0

    .line 174
    const/4 v10, 0x0

    .line 175
    const/4 v11, 0x0

    .line 176
    move-object v3, p0

    .line 177
    invoke-static/range {v3 .. v13}, Ly70/d;->a(Ly70/d;Lql0/g;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;ZLjava/lang/String;Ljava/util/ArrayList;ZLqr0/d;Ljava/util/List;I)Ly70/d;

    .line 178
    .line 179
    .line 180
    move-result-object p0

    .line 181
    invoke-virtual {p1, p0}, Lql0/j;->g(Lql0/h;)V

    .line 182
    .line 183
    .line 184
    :cond_7
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 185
    .line 186
    :goto_4
    return-object v0

    .line 187
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 188
    .line 189
    iget v1, p0, Ly70/b;->e:I

    .line 190
    .line 191
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 192
    .line 193
    iget-object v3, p0, Ly70/b;->f:Ly70/f;

    .line 194
    .line 195
    const/4 v4, 0x2

    .line 196
    const/4 v5, 0x1

    .line 197
    if-eqz v1, :cond_b

    .line 198
    .line 199
    if-eq v1, v5, :cond_a

    .line 200
    .line 201
    if-ne v1, v4, :cond_9

    .line 202
    .line 203
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 204
    .line 205
    .line 206
    :cond_8
    move-object v0, v2

    .line 207
    goto :goto_6

    .line 208
    :cond_9
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
    :cond_a
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 217
    .line 218
    .line 219
    goto :goto_5

    .line 220
    :cond_b
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 221
    .line 222
    .line 223
    iget-object p1, v3, Ly70/f;->l:Lbq0/o;

    .line 224
    .line 225
    iput v5, p0, Ly70/b;->e:I

    .line 226
    .line 227
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 228
    .line 229
    .line 230
    invoke-virtual {p1, p0}, Lbq0/o;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 231
    .line 232
    .line 233
    move-result-object p1

    .line 234
    if-ne p1, v0, :cond_c

    .line 235
    .line 236
    goto :goto_6

    .line 237
    :cond_c
    :goto_5
    check-cast p1, Lyy0/i;

    .line 238
    .line 239
    new-instance v1, Ly70/a;

    .line 240
    .line 241
    const/4 v5, 0x0

    .line 242
    invoke-direct {v1, v3, v5}, Ly70/a;-><init>(Ly70/f;I)V

    .line 243
    .line 244
    .line 245
    iput v4, p0, Ly70/b;->e:I

    .line 246
    .line 247
    invoke-interface {p1, v1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    move-result-object p0

    .line 251
    if-ne p0, v0, :cond_8

    .line 252
    .line 253
    :goto_6
    return-object v0

    .line 254
    nop

    .line 255
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
