.class public final Liq0/c;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Liq0/e;


# direct methods
.method public synthetic constructor <init>(Liq0/e;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Liq0/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Liq0/c;->f:Liq0/e;

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
    iget p1, p0, Liq0/c;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Liq0/c;

    .line 7
    .line 8
    iget-object p0, p0, Liq0/c;->f:Liq0/e;

    .line 9
    .line 10
    const/4 v0, 0x4

    .line 11
    invoke-direct {p1, p0, p2, v0}, Liq0/c;-><init>(Liq0/e;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Liq0/c;

    .line 16
    .line 17
    iget-object p0, p0, Liq0/c;->f:Liq0/e;

    .line 18
    .line 19
    const/4 v0, 0x3

    .line 20
    invoke-direct {p1, p0, p2, v0}, Liq0/c;-><init>(Liq0/e;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Liq0/c;

    .line 25
    .line 26
    iget-object p0, p0, Liq0/c;->f:Liq0/e;

    .line 27
    .line 28
    const/4 v0, 0x2

    .line 29
    invoke-direct {p1, p0, p2, v0}, Liq0/c;-><init>(Liq0/e;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Liq0/c;

    .line 34
    .line 35
    iget-object p0, p0, Liq0/c;->f:Liq0/e;

    .line 36
    .line 37
    const/4 v0, 0x1

    .line 38
    invoke-direct {p1, p0, p2, v0}, Liq0/c;-><init>(Liq0/e;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    :pswitch_3
    new-instance p1, Liq0/c;

    .line 43
    .line 44
    iget-object p0, p0, Liq0/c;->f:Liq0/e;

    .line 45
    .line 46
    const/4 v0, 0x0

    .line 47
    invoke-direct {p1, p0, p2, v0}, Liq0/c;-><init>(Liq0/e;Lkotlin/coroutines/Continuation;I)V

    .line 48
    .line 49
    .line 50
    return-object p1

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Liq0/c;->d:I

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
    invoke-virtual {p0, p1, p2}, Liq0/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Liq0/c;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Liq0/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Liq0/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    check-cast p0, Liq0/c;

    .line 29
    .line 30
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 31
    .line 32
    invoke-virtual {p0, p1}, Liq0/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 36
    .line 37
    return-object p0

    .line 38
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Liq0/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    check-cast p0, Liq0/c;

    .line 43
    .line 44
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 45
    .line 46
    invoke-virtual {p0, p1}, Liq0/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 50
    .line 51
    return-object p0

    .line 52
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Liq0/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    check-cast p0, Liq0/c;

    .line 57
    .line 58
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 59
    .line 60
    invoke-virtual {p0, p1}, Liq0/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 64
    .line 65
    return-object p0

    .line 66
    :pswitch_3
    invoke-virtual {p0, p1, p2}, Liq0/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    check-cast p0, Liq0/c;

    .line 71
    .line 72
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 73
    .line 74
    invoke-virtual {p0, p1}, Liq0/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 78
    .line 79
    return-object p0

    .line 80
    nop

    .line 81
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Liq0/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Liq0/c;->e:I

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    if-eqz v1, :cond_1

    .line 12
    .line 13
    if-eq v1, v2, :cond_0

    .line 14
    .line 15
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 16
    .line 17
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 18
    .line 19
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    throw p0

    .line 23
    :cond_0
    invoke-static {p1}, Lc1/j0;->i(Ljava/lang/Object;)La8/r0;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    throw p0

    .line 28
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    iget-object p1, p0, Liq0/c;->f:Liq0/e;

    .line 32
    .line 33
    iget-object v1, p1, Liq0/e;->b:Lfq0/a;

    .line 34
    .line 35
    iget-object v1, v1, Lfq0/a;->e:Lyy0/q1;

    .line 36
    .line 37
    new-instance v3, Liq0/b;

    .line 38
    .line 39
    const/4 v4, 0x4

    .line 40
    invoke-direct {v3, p1, v4}, Liq0/b;-><init>(Liq0/e;I)V

    .line 41
    .line 42
    .line 43
    iput v2, p0, Liq0/c;->e:I

    .line 44
    .line 45
    invoke-virtual {v1, v3, p0}, Lyy0/q1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    return-object v0

    .line 49
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 50
    .line 51
    iget v1, p0, Liq0/c;->e:I

    .line 52
    .line 53
    const/4 v2, 0x1

    .line 54
    if-eqz v1, :cond_3

    .line 55
    .line 56
    if-eq v1, v2, :cond_2

    .line 57
    .line 58
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 59
    .line 60
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 61
    .line 62
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    throw p0

    .line 66
    :cond_2
    invoke-static {p1}, Lc1/j0;->i(Ljava/lang/Object;)La8/r0;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    throw p0

    .line 71
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    iget-object p1, p0, Liq0/c;->f:Liq0/e;

    .line 75
    .line 76
    iget-object v1, p1, Liq0/e;->b:Lfq0/a;

    .line 77
    .line 78
    iget-object v1, v1, Lfq0/a;->d:Lyy0/q1;

    .line 79
    .line 80
    new-instance v3, Liq0/b;

    .line 81
    .line 82
    const/4 v4, 0x3

    .line 83
    invoke-direct {v3, p1, v4}, Liq0/b;-><init>(Liq0/e;I)V

    .line 84
    .line 85
    .line 86
    iput v2, p0, Liq0/c;->e:I

    .line 87
    .line 88
    invoke-virtual {v1, v3, p0}, Lyy0/q1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    return-object v0

    .line 92
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 93
    .line 94
    iget v1, p0, Liq0/c;->e:I

    .line 95
    .line 96
    const/4 v2, 0x1

    .line 97
    if-eqz v1, :cond_5

    .line 98
    .line 99
    if-eq v1, v2, :cond_4

    .line 100
    .line 101
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 102
    .line 103
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 104
    .line 105
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    throw p0

    .line 109
    :cond_4
    invoke-static {p1}, Lc1/j0;->i(Ljava/lang/Object;)La8/r0;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    throw p0

    .line 114
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    iget-object p1, p0, Liq0/c;->f:Liq0/e;

    .line 118
    .line 119
    iget-object v1, p1, Liq0/e;->b:Lfq0/a;

    .line 120
    .line 121
    iget-object v1, v1, Lfq0/a;->c:Lyy0/q1;

    .line 122
    .line 123
    new-instance v3, Liq0/b;

    .line 124
    .line 125
    const/4 v4, 0x2

    .line 126
    invoke-direct {v3, p1, v4}, Liq0/b;-><init>(Liq0/e;I)V

    .line 127
    .line 128
    .line 129
    iput v2, p0, Liq0/c;->e:I

    .line 130
    .line 131
    invoke-virtual {v1, v3, p0}, Lyy0/q1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    return-object v0

    .line 135
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 136
    .line 137
    iget v1, p0, Liq0/c;->e:I

    .line 138
    .line 139
    const/4 v2, 0x1

    .line 140
    if-eqz v1, :cond_7

    .line 141
    .line 142
    if-eq v1, v2, :cond_6

    .line 143
    .line 144
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 145
    .line 146
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 147
    .line 148
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    throw p0

    .line 152
    :cond_6
    invoke-static {p1}, Lc1/j0;->i(Ljava/lang/Object;)La8/r0;

    .line 153
    .line 154
    .line 155
    move-result-object p0

    .line 156
    throw p0

    .line 157
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 158
    .line 159
    .line 160
    iget-object p1, p0, Liq0/c;->f:Liq0/e;

    .line 161
    .line 162
    iget-object v1, p1, Liq0/e;->b:Lfq0/a;

    .line 163
    .line 164
    iget-object v1, v1, Lfq0/a;->b:Lyy0/q1;

    .line 165
    .line 166
    new-instance v3, Liq0/b;

    .line 167
    .line 168
    const/4 v4, 0x1

    .line 169
    invoke-direct {v3, p1, v4}, Liq0/b;-><init>(Liq0/e;I)V

    .line 170
    .line 171
    .line 172
    iput v2, p0, Liq0/c;->e:I

    .line 173
    .line 174
    invoke-virtual {v1, v3, p0}, Lyy0/q1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    return-object v0

    .line 178
    :pswitch_3
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 179
    .line 180
    iget v1, p0, Liq0/c;->e:I

    .line 181
    .line 182
    const/4 v2, 0x1

    .line 183
    if-eqz v1, :cond_9

    .line 184
    .line 185
    if-eq v1, v2, :cond_8

    .line 186
    .line 187
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 188
    .line 189
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 190
    .line 191
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 192
    .line 193
    .line 194
    throw p0

    .line 195
    :cond_8
    invoke-static {p1}, Lc1/j0;->i(Ljava/lang/Object;)La8/r0;

    .line 196
    .line 197
    .line 198
    move-result-object p0

    .line 199
    throw p0

    .line 200
    :cond_9
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 201
    .line 202
    .line 203
    iget-object p1, p0, Liq0/c;->f:Liq0/e;

    .line 204
    .line 205
    iget-object v1, p1, Liq0/e;->b:Lfq0/a;

    .line 206
    .line 207
    iget-object v1, v1, Lfq0/a;->a:Lyy0/q1;

    .line 208
    .line 209
    new-instance v3, Liq0/b;

    .line 210
    .line 211
    const/4 v4, 0x0

    .line 212
    invoke-direct {v3, p1, v4}, Liq0/b;-><init>(Liq0/e;I)V

    .line 213
    .line 214
    .line 215
    iput v2, p0, Liq0/c;->e:I

    .line 216
    .line 217
    invoke-virtual {v1, v3, p0}, Lyy0/q1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 218
    .line 219
    .line 220
    return-object v0

    .line 221
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
