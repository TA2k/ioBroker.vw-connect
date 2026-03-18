.class public final Ldv0/b;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ldv0/e;


# direct methods
.method public synthetic constructor <init>(Ldv0/e;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ldv0/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ldv0/b;->f:Ldv0/e;

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
    iget p1, p0, Ldv0/b;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Ldv0/b;

    .line 7
    .line 8
    iget-object p0, p0, Ldv0/b;->f:Ldv0/e;

    .line 9
    .line 10
    const/4 v0, 0x6

    .line 11
    invoke-direct {p1, p0, p2, v0}, Ldv0/b;-><init>(Ldv0/e;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Ldv0/b;

    .line 16
    .line 17
    iget-object p0, p0, Ldv0/b;->f:Ldv0/e;

    .line 18
    .line 19
    const/4 v0, 0x5

    .line 20
    invoke-direct {p1, p0, p2, v0}, Ldv0/b;-><init>(Ldv0/e;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Ldv0/b;

    .line 25
    .line 26
    iget-object p0, p0, Ldv0/b;->f:Ldv0/e;

    .line 27
    .line 28
    const/4 v0, 0x4

    .line 29
    invoke-direct {p1, p0, p2, v0}, Ldv0/b;-><init>(Ldv0/e;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Ldv0/b;

    .line 34
    .line 35
    iget-object p0, p0, Ldv0/b;->f:Ldv0/e;

    .line 36
    .line 37
    const/4 v0, 0x3

    .line 38
    invoke-direct {p1, p0, p2, v0}, Ldv0/b;-><init>(Ldv0/e;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    :pswitch_3
    new-instance p1, Ldv0/b;

    .line 43
    .line 44
    iget-object p0, p0, Ldv0/b;->f:Ldv0/e;

    .line 45
    .line 46
    const/4 v0, 0x2

    .line 47
    invoke-direct {p1, p0, p2, v0}, Ldv0/b;-><init>(Ldv0/e;Lkotlin/coroutines/Continuation;I)V

    .line 48
    .line 49
    .line 50
    return-object p1

    .line 51
    :pswitch_4
    new-instance p1, Ldv0/b;

    .line 52
    .line 53
    iget-object p0, p0, Ldv0/b;->f:Ldv0/e;

    .line 54
    .line 55
    const/4 v0, 0x1

    .line 56
    invoke-direct {p1, p0, p2, v0}, Ldv0/b;-><init>(Ldv0/e;Lkotlin/coroutines/Continuation;I)V

    .line 57
    .line 58
    .line 59
    return-object p1

    .line 60
    :pswitch_5
    new-instance p1, Ldv0/b;

    .line 61
    .line 62
    iget-object p0, p0, Ldv0/b;->f:Ldv0/e;

    .line 63
    .line 64
    const/4 v0, 0x0

    .line 65
    invoke-direct {p1, p0, p2, v0}, Ldv0/b;-><init>(Ldv0/e;Lkotlin/coroutines/Continuation;I)V

    .line 66
    .line 67
    .line 68
    return-object p1

    .line 69
    :pswitch_data_0
    .packed-switch 0x0
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
    iget v0, p0, Ldv0/b;->d:I

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
    invoke-virtual {p0, p1, p2}, Ldv0/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ldv0/b;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ldv0/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ldv0/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ldv0/b;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ldv0/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Ldv0/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Ldv0/b;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Ldv0/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Ldv0/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Ldv0/b;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Ldv0/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_3
    invoke-virtual {p0, p1, p2}, Ldv0/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Ldv0/b;

    .line 67
    .line 68
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    invoke-virtual {p0, p1}, Ldv0/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    return-object p0

    .line 75
    :pswitch_4
    invoke-virtual {p0, p1, p2}, Ldv0/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    check-cast p0, Ldv0/b;

    .line 80
    .line 81
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 82
    .line 83
    invoke-virtual {p0, p1}, Ldv0/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    return-object p0

    .line 88
    :pswitch_5
    invoke-virtual {p0, p1, p2}, Ldv0/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    check-cast p0, Ldv0/b;

    .line 93
    .line 94
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 95
    .line 96
    invoke-virtual {p0, p1}, Ldv0/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    return-object p0

    .line 101
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Ldv0/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Ldv0/b;->e:I

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
    iget-object p1, p0, Ldv0/b;->f:Ldv0/e;

    .line 31
    .line 32
    iget-object p1, p1, Ldv0/e;->k:Llp0/d;

    .line 33
    .line 34
    iput v2, p0, Ldv0/b;->e:I

    .line 35
    .line 36
    const/4 v1, 0x0

    .line 37
    invoke-virtual {p1, v1, p0}, Llp0/d;->b(Lmp0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    if-ne p0, v0, :cond_2

    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 45
    .line 46
    :goto_1
    return-object v0

    .line 47
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 48
    .line 49
    iget v1, p0, Ldv0/b;->e:I

    .line 50
    .line 51
    iget-object v2, p0, Ldv0/b;->f:Ldv0/e;

    .line 52
    .line 53
    const/4 v3, 0x2

    .line 54
    const/4 v4, 0x1

    .line 55
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    if-eqz v1, :cond_6

    .line 58
    .line 59
    if-eq v1, v4, :cond_5

    .line 60
    .line 61
    if-ne v1, v3, :cond_4

    .line 62
    .line 63
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    :cond_3
    move-object v0, v5

    .line 67
    goto :goto_3

    .line 68
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 69
    .line 70
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 71
    .line 72
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    throw p0

    .line 76
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    goto :goto_2

    .line 80
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    iget-object p1, v2, Ldv0/e;->p:Lub0/c;

    .line 84
    .line 85
    iput v4, p0, Ldv0/b;->e:I

    .line 86
    .line 87
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 88
    .line 89
    .line 90
    invoke-virtual {p1, p0}, Lub0/c;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object p1

    .line 94
    if-ne p1, v0, :cond_7

    .line 95
    .line 96
    goto :goto_3

    .line 97
    :cond_7
    :goto_2
    iget-object p1, v2, Ldv0/e;->r:Lee0/h;

    .line 98
    .line 99
    iput v3, p0, Ldv0/b;->e:I

    .line 100
    .line 101
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 102
    .line 103
    .line 104
    invoke-virtual {p1, p0}, Lee0/h;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    if-ne p0, v0, :cond_3

    .line 109
    .line 110
    :goto_3
    return-object v0

    .line 111
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 112
    .line 113
    iget v1, p0, Ldv0/b;->e:I

    .line 114
    .line 115
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 116
    .line 117
    const/4 v3, 0x1

    .line 118
    if-eqz v1, :cond_a

    .line 119
    .line 120
    if-ne v1, v3, :cond_9

    .line 121
    .line 122
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 123
    .line 124
    .line 125
    :cond_8
    move-object v0, v2

    .line 126
    goto :goto_5

    .line 127
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 128
    .line 129
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 130
    .line 131
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    throw p0

    .line 135
    :cond_a
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 136
    .line 137
    .line 138
    iget-object p1, p0, Ldv0/b;->f:Ldv0/e;

    .line 139
    .line 140
    iget-object v1, p1, Ldv0/e;->s:Lee0/b;

    .line 141
    .line 142
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object v1

    .line 146
    check-cast v1, Lyy0/i;

    .line 147
    .line 148
    new-instance v4, Ldv0/a;

    .line 149
    .line 150
    const/4 v5, 0x3

    .line 151
    invoke-direct {v4, p1, v5}, Ldv0/a;-><init>(Ldv0/e;I)V

    .line 152
    .line 153
    .line 154
    iput v3, p0, Ldv0/b;->e:I

    .line 155
    .line 156
    new-instance p1, Lcs0/s;

    .line 157
    .line 158
    const/4 v3, 0x6

    .line 159
    invoke-direct {p1, v4, v3}, Lcs0/s;-><init>(Lyy0/j;I)V

    .line 160
    .line 161
    .line 162
    invoke-interface {v1, p1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object p0

    .line 166
    if-ne p0, v0, :cond_b

    .line 167
    .line 168
    goto :goto_4

    .line 169
    :cond_b
    move-object p0, v2

    .line 170
    :goto_4
    if-ne p0, v0, :cond_8

    .line 171
    .line 172
    :goto_5
    return-object v0

    .line 173
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 174
    .line 175
    iget v1, p0, Ldv0/b;->e:I

    .line 176
    .line 177
    const/4 v2, 0x2

    .line 178
    const/4 v3, 0x1

    .line 179
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 180
    .line 181
    iget-object v5, p0, Ldv0/b;->f:Ldv0/e;

    .line 182
    .line 183
    if-eqz v1, :cond_e

    .line 184
    .line 185
    if-eq v1, v3, :cond_d

    .line 186
    .line 187
    if-ne v1, v2, :cond_c

    .line 188
    .line 189
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 190
    .line 191
    .line 192
    goto :goto_7

    .line 193
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 194
    .line 195
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 196
    .line 197
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 198
    .line 199
    .line 200
    throw p0

    .line 201
    :cond_d
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 202
    .line 203
    .line 204
    goto :goto_6

    .line 205
    :cond_e
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 206
    .line 207
    .line 208
    iget-object p1, v5, Ldv0/e;->n:Lwi0/f;

    .line 209
    .line 210
    iput v3, p0, Ldv0/b;->e:I

    .line 211
    .line 212
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 213
    .line 214
    .line 215
    invoke-virtual {p1, p0}, Lwi0/f;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 216
    .line 217
    .line 218
    move-result-object p1

    .line 219
    if-ne p1, v0, :cond_f

    .line 220
    .line 221
    goto :goto_a

    .line 222
    :cond_f
    :goto_6
    check-cast p1, Ljava/lang/Boolean;

    .line 223
    .line 224
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 225
    .line 226
    .line 227
    move-result p1

    .line 228
    if-nez p1, :cond_12

    .line 229
    .line 230
    iget-object p1, v5, Ldv0/e;->m:Lwi0/h;

    .line 231
    .line 232
    iput v2, p0, Ldv0/b;->e:I

    .line 233
    .line 234
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 235
    .line 236
    .line 237
    invoke-virtual {p1, p0}, Lwi0/h;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 238
    .line 239
    .line 240
    move-result-object p1

    .line 241
    if-ne p1, v0, :cond_10

    .line 242
    .line 243
    goto :goto_a

    .line 244
    :cond_10
    :goto_7
    check-cast p1, Ljava/lang/Boolean;

    .line 245
    .line 246
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 247
    .line 248
    .line 249
    move-result p0

    .line 250
    if-eqz p0, :cond_11

    .line 251
    .line 252
    goto :goto_9

    .line 253
    :cond_11
    :goto_8
    move-object v0, v4

    .line 254
    goto :goto_a

    .line 255
    :cond_12
    :goto_9
    iget-object p0, v5, Ldv0/e;->l:Lxu0/b;

    .line 256
    .line 257
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 258
    .line 259
    .line 260
    goto :goto_8

    .line 261
    :goto_a
    return-object v0

    .line 262
    :pswitch_3
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 263
    .line 264
    iget v1, p0, Ldv0/b;->e:I

    .line 265
    .line 266
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 267
    .line 268
    const/4 v3, 0x3

    .line 269
    const/4 v4, 0x2

    .line 270
    const/4 v5, 0x1

    .line 271
    iget-object v6, p0, Ldv0/b;->f:Ldv0/e;

    .line 272
    .line 273
    if-eqz v1, :cond_17

    .line 274
    .line 275
    if-eq v1, v5, :cond_16

    .line 276
    .line 277
    if-eq v1, v4, :cond_15

    .line 278
    .line 279
    if-ne v1, v3, :cond_14

    .line 280
    .line 281
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 282
    .line 283
    .line 284
    :cond_13
    move-object v0, v2

    .line 285
    goto :goto_d

    .line 286
    :cond_14
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 287
    .line 288
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 289
    .line 290
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 291
    .line 292
    .line 293
    throw p0

    .line 294
    :cond_15
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 295
    .line 296
    .line 297
    goto :goto_c

    .line 298
    :cond_16
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 299
    .line 300
    .line 301
    goto :goto_b

    .line 302
    :cond_17
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 303
    .line 304
    .line 305
    iget-object p1, v6, Ldv0/e;->q:Lhh0/a;

    .line 306
    .line 307
    sget-object v1, Lih0/a;->s:Lih0/a;

    .line 308
    .line 309
    iput v5, p0, Ldv0/b;->e:I

    .line 310
    .line 311
    invoke-virtual {p1, v1, p0}, Lhh0/a;->b(Lih0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 312
    .line 313
    .line 314
    move-result-object p1

    .line 315
    if-ne p1, v0, :cond_18

    .line 316
    .line 317
    goto :goto_d

    .line 318
    :cond_18
    :goto_b
    check-cast p1, Ljava/lang/Boolean;

    .line 319
    .line 320
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 321
    .line 322
    .line 323
    move-result p1

    .line 324
    if-eqz p1, :cond_13

    .line 325
    .line 326
    iget-object p1, v6, Ldv0/e;->o:Lub0/g;

    .line 327
    .line 328
    iput v4, p0, Ldv0/b;->e:I

    .line 329
    .line 330
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 331
    .line 332
    .line 333
    invoke-virtual {p1, p0}, Lub0/g;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 334
    .line 335
    .line 336
    move-result-object p1

    .line 337
    if-ne p1, v0, :cond_19

    .line 338
    .line 339
    goto :goto_d

    .line 340
    :cond_19
    :goto_c
    check-cast p1, Lyy0/i;

    .line 341
    .line 342
    new-instance v1, Ldv0/a;

    .line 343
    .line 344
    const/4 v4, 0x2

    .line 345
    invoke-direct {v1, v6, v4}, Ldv0/a;-><init>(Ldv0/e;I)V

    .line 346
    .line 347
    .line 348
    iput v3, p0, Ldv0/b;->e:I

    .line 349
    .line 350
    invoke-interface {p1, v1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 351
    .line 352
    .line 353
    move-result-object p0

    .line 354
    if-ne p0, v0, :cond_13

    .line 355
    .line 356
    :goto_d
    return-object v0

    .line 357
    :pswitch_4
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 358
    .line 359
    iget v1, p0, Ldv0/b;->e:I

    .line 360
    .line 361
    const/4 v2, 0x1

    .line 362
    if-eqz v1, :cond_1b

    .line 363
    .line 364
    if-ne v1, v2, :cond_1a

    .line 365
    .line 366
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 367
    .line 368
    .line 369
    goto :goto_e

    .line 370
    :cond_1a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 371
    .line 372
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 373
    .line 374
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 375
    .line 376
    .line 377
    throw p0

    .line 378
    :cond_1b
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 379
    .line 380
    .line 381
    iget-object p1, p0, Ldv0/b;->f:Ldv0/e;

    .line 382
    .line 383
    iget-object v1, p1, Ldv0/e;->j:Llp0/b;

    .line 384
    .line 385
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 386
    .line 387
    .line 388
    move-result-object v1

    .line 389
    check-cast v1, Lyy0/i;

    .line 390
    .line 391
    new-instance v3, Ldv0/a;

    .line 392
    .line 393
    const/4 v4, 0x1

    .line 394
    invoke-direct {v3, p1, v4}, Ldv0/a;-><init>(Ldv0/e;I)V

    .line 395
    .line 396
    .line 397
    iput v2, p0, Ldv0/b;->e:I

    .line 398
    .line 399
    invoke-interface {v1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 400
    .line 401
    .line 402
    move-result-object p0

    .line 403
    if-ne p0, v0, :cond_1c

    .line 404
    .line 405
    goto :goto_f

    .line 406
    :cond_1c
    :goto_e
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 407
    .line 408
    :goto_f
    return-object v0

    .line 409
    :pswitch_5
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 410
    .line 411
    iget v1, p0, Ldv0/b;->e:I

    .line 412
    .line 413
    const/4 v2, 0x1

    .line 414
    if-eqz v1, :cond_1e

    .line 415
    .line 416
    if-ne v1, v2, :cond_1d

    .line 417
    .line 418
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 419
    .line 420
    .line 421
    goto :goto_10

    .line 422
    :cond_1d
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 423
    .line 424
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 425
    .line 426
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 427
    .line 428
    .line 429
    throw p0

    .line 430
    :cond_1e
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 431
    .line 432
    .line 433
    iget-object p1, p0, Ldv0/b;->f:Ldv0/e;

    .line 434
    .line 435
    iget-object v1, p1, Ldv0/e;->h:Lrs0/g;

    .line 436
    .line 437
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 438
    .line 439
    .line 440
    move-result-object v1

    .line 441
    check-cast v1, Lyy0/i;

    .line 442
    .line 443
    invoke-static {v1}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 444
    .line 445
    .line 446
    move-result-object v1

    .line 447
    new-instance v3, Ldv0/a;

    .line 448
    .line 449
    const/4 v4, 0x0

    .line 450
    invoke-direct {v3, p1, v4}, Ldv0/a;-><init>(Ldv0/e;I)V

    .line 451
    .line 452
    .line 453
    iput v2, p0, Ldv0/b;->e:I

    .line 454
    .line 455
    invoke-interface {v1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 456
    .line 457
    .line 458
    move-result-object p0

    .line 459
    if-ne p0, v0, :cond_1f

    .line 460
    .line 461
    goto :goto_11

    .line 462
    :cond_1f
    :goto_10
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 463
    .line 464
    :goto_11
    return-object v0

    .line 465
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
