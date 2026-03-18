.class public final Lm80/a;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lm80/e;


# direct methods
.method public synthetic constructor <init>(Lm80/e;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lm80/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lm80/a;->f:Lm80/e;

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
    iget p1, p0, Lm80/a;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lm80/a;

    .line 7
    .line 8
    iget-object p0, p0, Lm80/a;->f:Lm80/e;

    .line 9
    .line 10
    const/4 v0, 0x3

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lm80/a;-><init>(Lm80/e;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lm80/a;

    .line 16
    .line 17
    iget-object p0, p0, Lm80/a;->f:Lm80/e;

    .line 18
    .line 19
    const/4 v0, 0x2

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lm80/a;-><init>(Lm80/e;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lm80/a;

    .line 25
    .line 26
    iget-object p0, p0, Lm80/a;->f:Lm80/e;

    .line 27
    .line 28
    const/4 v0, 0x1

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lm80/a;-><init>(Lm80/e;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Lm80/a;

    .line 34
    .line 35
    iget-object p0, p0, Lm80/a;->f:Lm80/e;

    .line 36
    .line 37
    const/4 v0, 0x0

    .line 38
    invoke-direct {p1, p0, p2, v0}, Lm80/a;-><init>(Lm80/e;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    nop

    .line 43
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lm80/a;->d:I

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
    invoke-virtual {p0, p1, p2}, Lm80/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lm80/a;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lm80/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lm80/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lm80/a;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lm80/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lm80/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lm80/a;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lm80/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lm80/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lm80/a;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lm80/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    nop

    .line 63
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Lm80/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lm80/a;->e:I

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
    iput v2, p0, Lm80/a;->e:I

    .line 31
    .line 32
    iget-object p1, p0, Lm80/a;->f:Lm80/e;

    .line 33
    .line 34
    invoke-static {p1, p0}, Lm80/e;->h(Lm80/e;Lrx0/c;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    if-ne p0, v0, :cond_2

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    :goto_1
    return-object v0

    .line 44
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 45
    .line 46
    iget v1, p0, Lm80/a;->e:I

    .line 47
    .line 48
    iget-object v2, p0, Lm80/a;->f:Lm80/e;

    .line 49
    .line 50
    const/4 v3, 0x2

    .line 51
    const/4 v4, 0x1

    .line 52
    if-eqz v1, :cond_5

    .line 53
    .line 54
    if-eq v1, v4, :cond_4

    .line 55
    .line 56
    if-ne v1, v3, :cond_3

    .line 57
    .line 58
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    goto :goto_3

    .line 62
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 63
    .line 64
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 65
    .line 66
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    throw p0

    .line 70
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    goto :goto_2

    .line 74
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    iget-object p1, v2, Lm80/e;->k:Lk80/g;

    .line 78
    .line 79
    iput v4, p0, Lm80/a;->e:I

    .line 80
    .line 81
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 82
    .line 83
    .line 84
    iget-object v1, p1, Lk80/g;->a:Lkf0/b0;

    .line 85
    .line 86
    invoke-virtual {v1}, Lkf0/b0;->invoke()Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v1

    .line 90
    check-cast v1, Lyy0/i;

    .line 91
    .line 92
    new-instance v4, Lk31/t;

    .line 93
    .line 94
    const/4 v5, 0x0

    .line 95
    const/4 v6, 0x7

    .line 96
    invoke-direct {v4, p1, v5, v6}, Lk31/t;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 97
    .line 98
    .line 99
    invoke-static {v4, v1}, Lyy0/u;->x(Lay0/n;Lyy0/i;)Lyy0/m;

    .line 100
    .line 101
    .line 102
    move-result-object v1

    .line 103
    new-instance v4, Lac/l;

    .line 104
    .line 105
    const/16 v5, 0x15

    .line 106
    .line 107
    invoke-direct {v4, v5, v1, p1}, Lac/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    if-ne v4, v0, :cond_6

    .line 111
    .line 112
    goto :goto_4

    .line 113
    :cond_6
    move-object p1, v4

    .line 114
    :goto_2
    check-cast p1, Lyy0/i;

    .line 115
    .line 116
    new-instance v1, Lm80/d;

    .line 117
    .line 118
    const/4 v4, 0x1

    .line 119
    invoke-direct {v1, v2, v4}, Lm80/d;-><init>(Lm80/e;I)V

    .line 120
    .line 121
    .line 122
    iput v3, p0, Lm80/a;->e:I

    .line 123
    .line 124
    invoke-interface {p1, v1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    if-ne p0, v0, :cond_7

    .line 129
    .line 130
    goto :goto_4

    .line 131
    :cond_7
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 132
    .line 133
    :goto_4
    return-object v0

    .line 134
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 135
    .line 136
    iget v1, p0, Lm80/a;->e:I

    .line 137
    .line 138
    const/4 v2, 0x1

    .line 139
    if-eqz v1, :cond_9

    .line 140
    .line 141
    if-ne v1, v2, :cond_8

    .line 142
    .line 143
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 144
    .line 145
    .line 146
    goto :goto_5

    .line 147
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 148
    .line 149
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 150
    .line 151
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 152
    .line 153
    .line 154
    throw p0

    .line 155
    :cond_9
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 156
    .line 157
    .line 158
    iget-object p1, p0, Lm80/a;->f:Lm80/e;

    .line 159
    .line 160
    iget-object v1, p1, Lm80/e;->m:Lrq0/f;

    .line 161
    .line 162
    new-instance v3, Lsq0/c;

    .line 163
    .line 164
    iget-object p1, p1, Lm80/e;->n:Lij0/a;

    .line 165
    .line 166
    const/4 v4, 0x0

    .line 167
    new-array v5, v4, [Ljava/lang/Object;

    .line 168
    .line 169
    check-cast p1, Ljj0/f;

    .line 170
    .line 171
    const v6, 0x7f1202bf

    .line 172
    .line 173
    .line 174
    invoke-virtual {p1, v6, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 175
    .line 176
    .line 177
    move-result-object p1

    .line 178
    const/4 v5, 0x6

    .line 179
    const/4 v6, 0x0

    .line 180
    invoke-direct {v3, v5, p1, v6, v6}, Lsq0/c;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 181
    .line 182
    .line 183
    iput v2, p0, Lm80/a;->e:I

    .line 184
    .line 185
    invoke-virtual {v1, v3, v4, p0}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 186
    .line 187
    .line 188
    move-result-object p0

    .line 189
    if-ne p0, v0, :cond_a

    .line 190
    .line 191
    goto :goto_6

    .line 192
    :cond_a
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 193
    .line 194
    :goto_6
    return-object v0

    .line 195
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 196
    .line 197
    iget v1, p0, Lm80/a;->e:I

    .line 198
    .line 199
    const/4 v2, 0x1

    .line 200
    if-eqz v1, :cond_c

    .line 201
    .line 202
    if-ne v1, v2, :cond_b

    .line 203
    .line 204
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 205
    .line 206
    .line 207
    goto :goto_7

    .line 208
    :cond_b
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
    :cond_c
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 217
    .line 218
    .line 219
    iput v2, p0, Lm80/a;->e:I

    .line 220
    .line 221
    iget-object p1, p0, Lm80/a;->f:Lm80/e;

    .line 222
    .line 223
    invoke-static {p1, p0}, Lm80/e;->h(Lm80/e;Lrx0/c;)Ljava/lang/Object;

    .line 224
    .line 225
    .line 226
    move-result-object p0

    .line 227
    if-ne p0, v0, :cond_d

    .line 228
    .line 229
    goto :goto_8

    .line 230
    :cond_d
    :goto_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 231
    .line 232
    :goto_8
    return-object v0

    .line 233
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
