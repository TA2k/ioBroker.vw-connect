.class public final Lw40/q;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lw40/s;


# direct methods
.method public synthetic constructor <init>(Lw40/s;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lw40/q;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lw40/q;->f:Lw40/s;

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
    iget p1, p0, Lw40/q;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lw40/q;

    .line 7
    .line 8
    iget-object p0, p0, Lw40/q;->f:Lw40/s;

    .line 9
    .line 10
    const/4 v0, 0x7

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lw40/q;-><init>(Lw40/s;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lw40/q;

    .line 16
    .line 17
    iget-object p0, p0, Lw40/q;->f:Lw40/s;

    .line 18
    .line 19
    const/4 v0, 0x6

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lw40/q;-><init>(Lw40/s;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lw40/q;

    .line 25
    .line 26
    iget-object p0, p0, Lw40/q;->f:Lw40/s;

    .line 27
    .line 28
    const/4 v0, 0x5

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lw40/q;-><init>(Lw40/s;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Lw40/q;

    .line 34
    .line 35
    iget-object p0, p0, Lw40/q;->f:Lw40/s;

    .line 36
    .line 37
    const/4 v0, 0x4

    .line 38
    invoke-direct {p1, p0, p2, v0}, Lw40/q;-><init>(Lw40/s;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    :pswitch_3
    new-instance p1, Lw40/q;

    .line 43
    .line 44
    iget-object p0, p0, Lw40/q;->f:Lw40/s;

    .line 45
    .line 46
    const/4 v0, 0x3

    .line 47
    invoke-direct {p1, p0, p2, v0}, Lw40/q;-><init>(Lw40/s;Lkotlin/coroutines/Continuation;I)V

    .line 48
    .line 49
    .line 50
    return-object p1

    .line 51
    :pswitch_4
    new-instance p1, Lw40/q;

    .line 52
    .line 53
    iget-object p0, p0, Lw40/q;->f:Lw40/s;

    .line 54
    .line 55
    const/4 v0, 0x2

    .line 56
    invoke-direct {p1, p0, p2, v0}, Lw40/q;-><init>(Lw40/s;Lkotlin/coroutines/Continuation;I)V

    .line 57
    .line 58
    .line 59
    return-object p1

    .line 60
    :pswitch_5
    new-instance p1, Lw40/q;

    .line 61
    .line 62
    iget-object p0, p0, Lw40/q;->f:Lw40/s;

    .line 63
    .line 64
    const/4 v0, 0x1

    .line 65
    invoke-direct {p1, p0, p2, v0}, Lw40/q;-><init>(Lw40/s;Lkotlin/coroutines/Continuation;I)V

    .line 66
    .line 67
    .line 68
    return-object p1

    .line 69
    :pswitch_6
    new-instance p1, Lw40/q;

    .line 70
    .line 71
    iget-object p0, p0, Lw40/q;->f:Lw40/s;

    .line 72
    .line 73
    const/4 v0, 0x0

    .line 74
    invoke-direct {p1, p0, p2, v0}, Lw40/q;-><init>(Lw40/s;Lkotlin/coroutines/Continuation;I)V

    .line 75
    .line 76
    .line 77
    return-object p1

    .line 78
    nop

    .line 79
    :pswitch_data_0
    .packed-switch 0x0
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
    iget v0, p0, Lw40/q;->d:I

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
    invoke-virtual {p0, p1, p2}, Lw40/q;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lw40/q;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lw40/q;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lw40/q;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lw40/q;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lw40/q;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lw40/q;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lw40/q;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lw40/q;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lw40/q;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lw40/q;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lw40/q;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_3
    invoke-virtual {p0, p1, p2}, Lw40/q;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Lw40/q;

    .line 67
    .line 68
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    invoke-virtual {p0, p1}, Lw40/q;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    return-object p0

    .line 75
    :pswitch_4
    invoke-virtual {p0, p1, p2}, Lw40/q;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    check-cast p0, Lw40/q;

    .line 80
    .line 81
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 82
    .line 83
    invoke-virtual {p0, p1}, Lw40/q;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    return-object p0

    .line 88
    :pswitch_5
    invoke-virtual {p0, p1, p2}, Lw40/q;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    check-cast p0, Lw40/q;

    .line 93
    .line 94
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 95
    .line 96
    invoke-virtual {p0, p1}, Lw40/q;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    return-object p0

    .line 101
    :pswitch_6
    invoke-virtual {p0, p1, p2}, Lw40/q;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    check-cast p0, Lw40/q;

    .line 106
    .line 107
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 108
    .line 109
    invoke-virtual {p0, p1}, Lw40/q;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    return-object p0

    .line 114
    nop

    .line 115
    :pswitch_data_0
    .packed-switch 0x0
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
    .locals 12

    .line 1
    iget v0, p0, Lw40/q;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lw40/q;->e:I

    .line 9
    .line 10
    const/4 v2, 0x2

    .line 11
    const/4 v3, 0x1

    .line 12
    iget-object v4, p0, Lw40/q;->f:Lw40/s;

    .line 13
    .line 14
    if-eqz v1, :cond_2

    .line 15
    .line 16
    if-eq v1, v3, :cond_1

    .line 17
    .line 18
    if-ne v1, v2, :cond_0

    .line 19
    .line 20
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    goto :goto_1

    .line 24
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 25
    .line 26
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 27
    .line 28
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw p0

    .line 32
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    iget-object p1, v4, Lw40/s;->p:Lu40/v;

    .line 40
    .line 41
    new-instance v5, Lu40/t;

    .line 42
    .line 43
    invoke-virtual {v4}, Lql0/j;->a()Lql0/h;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    check-cast v1, Lw40/n;

    .line 48
    .line 49
    iget-object v6, v1, Lw40/n;->c:Ljava/lang/String;

    .line 50
    .line 51
    invoke-virtual {v4}, Lql0/j;->a()Lql0/h;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    check-cast v1, Lw40/n;

    .line 56
    .line 57
    iget-object v7, v1, Lw40/n;->j:Ljava/lang/String;

    .line 58
    .line 59
    iget-object v8, v4, Lw40/s;->H:Ljava/time/OffsetDateTime;

    .line 60
    .line 61
    const/4 v1, 0x0

    .line 62
    if-eqz v8, :cond_7

    .line 63
    .line 64
    invoke-virtual {v4}, Lql0/j;->a()Lql0/h;

    .line 65
    .line 66
    .line 67
    move-result-object v9

    .line 68
    check-cast v9, Lw40/n;

    .line 69
    .line 70
    iget-object v9, v9, Lw40/n;->k:Lon0/a0;

    .line 71
    .line 72
    if-eqz v9, :cond_3

    .line 73
    .line 74
    iget-object v1, v9, Lon0/a0;->d:Ljava/lang/String;

    .line 75
    .line 76
    :cond_3
    move-object v9, v1

    .line 77
    if-eqz v9, :cond_6

    .line 78
    .line 79
    invoke-virtual {v4}, Lql0/j;->a()Lql0/h;

    .line 80
    .line 81
    .line 82
    move-result-object v1

    .line 83
    check-cast v1, Lw40/n;

    .line 84
    .line 85
    iget-object v10, v1, Lw40/n;->u:Ljava/lang/String;

    .line 86
    .line 87
    invoke-virtual {v4}, Lql0/j;->a()Lql0/h;

    .line 88
    .line 89
    .line 90
    move-result-object v1

    .line 91
    check-cast v1, Lw40/n;

    .line 92
    .line 93
    iget-boolean v11, v1, Lw40/n;->v:Z

    .line 94
    .line 95
    invoke-direct/range {v5 .. v11}, Lu40/t;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 96
    .line 97
    .line 98
    iput v3, p0, Lw40/q;->e:I

    .line 99
    .line 100
    invoke-virtual {p1, v5, p0}, Lu40/v;->b(Lu40/t;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object p1

    .line 104
    if-ne p1, v0, :cond_4

    .line 105
    .line 106
    goto :goto_2

    .line 107
    :cond_4
    :goto_0
    check-cast p1, Lyy0/i;

    .line 108
    .line 109
    new-instance v1, Lw40/r;

    .line 110
    .line 111
    const/4 v3, 0x3

    .line 112
    invoke-direct {v1, v4, v3}, Lw40/r;-><init>(Lw40/s;I)V

    .line 113
    .line 114
    .line 115
    iput v2, p0, Lw40/q;->e:I

    .line 116
    .line 117
    invoke-interface {p1, v1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    if-ne p0, v0, :cond_5

    .line 122
    .line 123
    goto :goto_2

    .line 124
    :cond_5
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 125
    .line 126
    :goto_2
    return-object v0

    .line 127
    :cond_6
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 128
    .line 129
    const-string p1, "Required value was null."

    .line 130
    .line 131
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    throw p0

    .line 135
    :cond_7
    const-string p0, "stopTime"

    .line 136
    .line 137
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 138
    .line 139
    .line 140
    throw v1

    .line 141
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 142
    .line 143
    iget v1, p0, Lw40/q;->e:I

    .line 144
    .line 145
    const/4 v2, 0x1

    .line 146
    if-eqz v1, :cond_9

    .line 147
    .line 148
    if-ne v1, v2, :cond_8

    .line 149
    .line 150
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 151
    .line 152
    .line 153
    goto :goto_3

    .line 154
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 155
    .line 156
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 157
    .line 158
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 159
    .line 160
    .line 161
    throw p0

    .line 162
    :cond_9
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 163
    .line 164
    .line 165
    iget-object p1, p0, Lw40/q;->f:Lw40/s;

    .line 166
    .line 167
    iget-object v1, p1, Lw40/s;->A:Lrq0/f;

    .line 168
    .line 169
    new-instance v3, Lsq0/c;

    .line 170
    .line 171
    iget-object p1, p1, Lw40/s;->n:Lij0/a;

    .line 172
    .line 173
    const/4 v4, 0x0

    .line 174
    new-array v4, v4, [Ljava/lang/Object;

    .line 175
    .line 176
    check-cast p1, Ljj0/f;

    .line 177
    .line 178
    const v5, 0x7f120e1f

    .line 179
    .line 180
    .line 181
    invoke-virtual {p1, v5, v4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 182
    .line 183
    .line 184
    move-result-object p1

    .line 185
    const/4 v4, 0x6

    .line 186
    const/4 v5, 0x0

    .line 187
    invoke-direct {v3, v4, p1, v5, v5}, Lsq0/c;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 188
    .line 189
    .line 190
    iput v2, p0, Lw40/q;->e:I

    .line 191
    .line 192
    invoke-virtual {v1, v3, v2, p0}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 193
    .line 194
    .line 195
    move-result-object p0

    .line 196
    if-ne p0, v0, :cond_a

    .line 197
    .line 198
    goto :goto_4

    .line 199
    :cond_a
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 200
    .line 201
    :goto_4
    return-object v0

    .line 202
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 203
    .line 204
    iget v1, p0, Lw40/q;->e:I

    .line 205
    .line 206
    const/4 v2, 0x1

    .line 207
    if-eqz v1, :cond_c

    .line 208
    .line 209
    if-ne v1, v2, :cond_b

    .line 210
    .line 211
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 212
    .line 213
    .line 214
    goto :goto_5

    .line 215
    :cond_b
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 216
    .line 217
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 218
    .line 219
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 220
    .line 221
    .line 222
    throw p0

    .line 223
    :cond_c
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 224
    .line 225
    .line 226
    iget-object p1, p0, Lw40/q;->f:Lw40/s;

    .line 227
    .line 228
    iget-object v1, p1, Lw40/s;->o:Lu40/d;

    .line 229
    .line 230
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 231
    .line 232
    .line 233
    move-result-object v1

    .line 234
    check-cast v1, Lyy0/i;

    .line 235
    .line 236
    new-instance v3, Lw40/r;

    .line 237
    .line 238
    const/4 v4, 0x2

    .line 239
    invoke-direct {v3, p1, v4}, Lw40/r;-><init>(Lw40/s;I)V

    .line 240
    .line 241
    .line 242
    iput v2, p0, Lw40/q;->e:I

    .line 243
    .line 244
    invoke-interface {v1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 245
    .line 246
    .line 247
    move-result-object p0

    .line 248
    if-ne p0, v0, :cond_d

    .line 249
    .line 250
    goto :goto_6

    .line 251
    :cond_d
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 252
    .line 253
    :goto_6
    return-object v0

    .line 254
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 255
    .line 256
    iget v1, p0, Lw40/q;->e:I

    .line 257
    .line 258
    const/4 v2, 0x1

    .line 259
    if-eqz v1, :cond_f

    .line 260
    .line 261
    if-ne v1, v2, :cond_e

    .line 262
    .line 263
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 264
    .line 265
    .line 266
    goto :goto_7

    .line 267
    :cond_e
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 268
    .line 269
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 270
    .line 271
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 272
    .line 273
    .line 274
    throw p0

    .line 275
    :cond_f
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 276
    .line 277
    .line 278
    iget-object p1, p0, Lw40/q;->f:Lw40/s;

    .line 279
    .line 280
    iget-object v1, p1, Lw40/s;->A:Lrq0/f;

    .line 281
    .line 282
    new-instance v3, Lsq0/c;

    .line 283
    .line 284
    iget-object p1, p1, Lw40/s;->n:Lij0/a;

    .line 285
    .line 286
    const/4 v4, 0x0

    .line 287
    new-array v5, v4, [Ljava/lang/Object;

    .line 288
    .line 289
    check-cast p1, Ljj0/f;

    .line 290
    .line 291
    const v6, 0x7f12019c

    .line 292
    .line 293
    .line 294
    invoke-virtual {p1, v6, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 295
    .line 296
    .line 297
    move-result-object p1

    .line 298
    const/4 v5, 0x6

    .line 299
    const/4 v6, 0x0

    .line 300
    invoke-direct {v3, v5, p1, v6, v6}, Lsq0/c;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 301
    .line 302
    .line 303
    iput v2, p0, Lw40/q;->e:I

    .line 304
    .line 305
    invoke-virtual {v1, v3, v4, p0}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 306
    .line 307
    .line 308
    move-result-object p0

    .line 309
    if-ne p0, v0, :cond_10

    .line 310
    .line 311
    goto :goto_8

    .line 312
    :cond_10
    :goto_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 313
    .line 314
    :goto_8
    return-object v0

    .line 315
    :pswitch_3
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 316
    .line 317
    iget v1, p0, Lw40/q;->e:I

    .line 318
    .line 319
    const/4 v2, 0x1

    .line 320
    if-eqz v1, :cond_12

    .line 321
    .line 322
    if-ne v1, v2, :cond_11

    .line 323
    .line 324
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 325
    .line 326
    .line 327
    goto :goto_9

    .line 328
    :cond_11
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 329
    .line 330
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 331
    .line 332
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 333
    .line 334
    .line 335
    throw p0

    .line 336
    :cond_12
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 337
    .line 338
    .line 339
    iget-object p1, p0, Lw40/q;->f:Lw40/s;

    .line 340
    .line 341
    iget-object v1, p1, Lw40/s;->C:Lnn0/d;

    .line 342
    .line 343
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 344
    .line 345
    .line 346
    move-result-object v1

    .line 347
    check-cast v1, Lyy0/i;

    .line 348
    .line 349
    new-instance v3, Lw40/r;

    .line 350
    .line 351
    const/4 v4, 0x0

    .line 352
    invoke-direct {v3, p1, v4}, Lw40/r;-><init>(Lw40/s;I)V

    .line 353
    .line 354
    .line 355
    iput v2, p0, Lw40/q;->e:I

    .line 356
    .line 357
    invoke-interface {v1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 358
    .line 359
    .line 360
    move-result-object p0

    .line 361
    if-ne p0, v0, :cond_13

    .line 362
    .line 363
    goto :goto_a

    .line 364
    :cond_13
    :goto_9
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 365
    .line 366
    :goto_a
    return-object v0

    .line 367
    :pswitch_4
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 368
    .line 369
    iget v1, p0, Lw40/q;->e:I

    .line 370
    .line 371
    const/4 v2, 0x1

    .line 372
    if-eqz v1, :cond_15

    .line 373
    .line 374
    if-ne v1, v2, :cond_14

    .line 375
    .line 376
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 377
    .line 378
    .line 379
    goto :goto_b

    .line 380
    :cond_14
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 381
    .line 382
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 383
    .line 384
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 385
    .line 386
    .line 387
    throw p0

    .line 388
    :cond_15
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 389
    .line 390
    .line 391
    iget-object p1, p0, Lw40/q;->f:Lw40/s;

    .line 392
    .line 393
    iget-object v1, p1, Lw40/s;->q:Lnn0/u;

    .line 394
    .line 395
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 396
    .line 397
    .line 398
    move-result-object v1

    .line 399
    check-cast v1, Lyy0/i;

    .line 400
    .line 401
    new-instance v3, Lw40/p;

    .line 402
    .line 403
    const/4 v4, 0x2

    .line 404
    invoke-direct {v3, p1, v4}, Lw40/p;-><init>(Lw40/s;I)V

    .line 405
    .line 406
    .line 407
    iput v2, p0, Lw40/q;->e:I

    .line 408
    .line 409
    invoke-interface {v1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 410
    .line 411
    .line 412
    move-result-object p0

    .line 413
    if-ne p0, v0, :cond_16

    .line 414
    .line 415
    goto :goto_c

    .line 416
    :cond_16
    :goto_b
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 417
    .line 418
    :goto_c
    return-object v0

    .line 419
    :pswitch_5
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 420
    .line 421
    iget v1, p0, Lw40/q;->e:I

    .line 422
    .line 423
    const/4 v2, 0x1

    .line 424
    if-eqz v1, :cond_18

    .line 425
    .line 426
    if-ne v1, v2, :cond_17

    .line 427
    .line 428
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 429
    .line 430
    .line 431
    goto :goto_d

    .line 432
    :cond_17
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 433
    .line 434
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 435
    .line 436
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 437
    .line 438
    .line 439
    throw p0

    .line 440
    :cond_18
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 441
    .line 442
    .line 443
    iget-object p1, p0, Lw40/q;->f:Lw40/s;

    .line 444
    .line 445
    iget-object v1, p1, Lw40/s;->o:Lu40/d;

    .line 446
    .line 447
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 448
    .line 449
    .line 450
    move-result-object v1

    .line 451
    check-cast v1, Lyy0/i;

    .line 452
    .line 453
    new-instance v3, Lw40/p;

    .line 454
    .line 455
    const/4 v4, 0x1

    .line 456
    invoke-direct {v3, p1, v4}, Lw40/p;-><init>(Lw40/s;I)V

    .line 457
    .line 458
    .line 459
    iput v2, p0, Lw40/q;->e:I

    .line 460
    .line 461
    invoke-interface {v1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 462
    .line 463
    .line 464
    move-result-object p0

    .line 465
    if-ne p0, v0, :cond_19

    .line 466
    .line 467
    goto :goto_e

    .line 468
    :cond_19
    :goto_d
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 469
    .line 470
    :goto_e
    return-object v0

    .line 471
    :pswitch_6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 472
    .line 473
    iget v1, p0, Lw40/q;->e:I

    .line 474
    .line 475
    const/4 v2, 0x1

    .line 476
    if-eqz v1, :cond_1b

    .line 477
    .line 478
    if-ne v1, v2, :cond_1a

    .line 479
    .line 480
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 481
    .line 482
    .line 483
    goto :goto_f

    .line 484
    :cond_1a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 485
    .line 486
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 487
    .line 488
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 489
    .line 490
    .line 491
    throw p0

    .line 492
    :cond_1b
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 493
    .line 494
    .line 495
    iget-object p1, p0, Lw40/q;->f:Lw40/s;

    .line 496
    .line 497
    iget-object v1, p1, Lw40/s;->i:Lkf0/v;

    .line 498
    .line 499
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 500
    .line 501
    .line 502
    move-result-object v1

    .line 503
    check-cast v1, Lyy0/i;

    .line 504
    .line 505
    sget-object v3, Lss0/e;->s1:Lss0/e;

    .line 506
    .line 507
    new-instance v4, Ls10/a0;

    .line 508
    .line 509
    const/16 v5, 0x1b

    .line 510
    .line 511
    const/4 v6, 0x0

    .line 512
    invoke-direct {v4, p1, v6, v5}, Ls10/a0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 513
    .line 514
    .line 515
    invoke-static {v1, v3, v4}, Lkp/u6;->e(Lyy0/i;Lss0/e;Lay0/n;)Lzy0/j;

    .line 516
    .line 517
    .line 518
    move-result-object v1

    .line 519
    new-instance v3, Lqa0/a;

    .line 520
    .line 521
    const/16 v4, 0x16

    .line 522
    .line 523
    invoke-direct {v3, v6, p1, v4}, Lqa0/a;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 524
    .line 525
    .line 526
    invoke-static {v1, v3}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 527
    .line 528
    .line 529
    move-result-object v1

    .line 530
    new-instance v3, Lw40/p;

    .line 531
    .line 532
    const/4 v4, 0x0

    .line 533
    invoke-direct {v3, p1, v4}, Lw40/p;-><init>(Lw40/s;I)V

    .line 534
    .line 535
    .line 536
    iput v2, p0, Lw40/q;->e:I

    .line 537
    .line 538
    invoke-virtual {v1, v3, p0}, Lzy0/f;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 539
    .line 540
    .line 541
    move-result-object p0

    .line 542
    if-ne p0, v0, :cond_1c

    .line 543
    .line 544
    goto :goto_10

    .line 545
    :cond_1c
    :goto_f
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 546
    .line 547
    :goto_10
    return-object v0

    .line 548
    nop

    .line 549
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
