.class public final Lne/b;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lke/f;

.field public final synthetic h:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Lke/f;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lne/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lne/b;->g:Lke/f;

    .line 4
    .line 5
    iput-object p2, p0, Lne/b;->h:Ljava/lang/String;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    iget v0, p0, Lne/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lne/b;

    .line 7
    .line 8
    iget-object v1, p0, Lne/b;->h:Ljava/lang/String;

    .line 9
    .line 10
    const/4 v2, 0x3

    .line 11
    iget-object p0, p0, Lne/b;->g:Lke/f;

    .line 12
    .line 13
    invoke-direct {v0, p0, v1, p2, v2}, Lne/b;-><init>(Lke/f;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    iput-object p1, v0, Lne/b;->f:Ljava/lang/Object;

    .line 17
    .line 18
    return-object v0

    .line 19
    :pswitch_0
    new-instance v0, Lne/b;

    .line 20
    .line 21
    iget-object v1, p0, Lne/b;->h:Ljava/lang/String;

    .line 22
    .line 23
    const/4 v2, 0x2

    .line 24
    iget-object p0, p0, Lne/b;->g:Lke/f;

    .line 25
    .line 26
    invoke-direct {v0, p0, v1, p2, v2}, Lne/b;-><init>(Lke/f;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 27
    .line 28
    .line 29
    iput-object p1, v0, Lne/b;->f:Ljava/lang/Object;

    .line 30
    .line 31
    return-object v0

    .line 32
    :pswitch_1
    new-instance v0, Lne/b;

    .line 33
    .line 34
    iget-object v1, p0, Lne/b;->h:Ljava/lang/String;

    .line 35
    .line 36
    const/4 v2, 0x1

    .line 37
    iget-object p0, p0, Lne/b;->g:Lke/f;

    .line 38
    .line 39
    invoke-direct {v0, p0, v1, p2, v2}, Lne/b;-><init>(Lke/f;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 40
    .line 41
    .line 42
    iput-object p1, v0, Lne/b;->f:Ljava/lang/Object;

    .line 43
    .line 44
    return-object v0

    .line 45
    :pswitch_2
    new-instance v0, Lne/b;

    .line 46
    .line 47
    iget-object v1, p0, Lne/b;->h:Ljava/lang/String;

    .line 48
    .line 49
    const/4 v2, 0x0

    .line 50
    iget-object p0, p0, Lne/b;->g:Lke/f;

    .line 51
    .line 52
    invoke-direct {v0, p0, v1, p2, v2}, Lne/b;-><init>(Lke/f;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 53
    .line 54
    .line 55
    iput-object p1, v0, Lne/b;->f:Ljava/lang/Object;

    .line 56
    .line 57
    return-object v0

    .line 58
    nop

    .line 59
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
    iget v0, p0, Lne/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lje/z0;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lne/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lne/b;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lne/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p1, Lje/z0;

    .line 24
    .line 25
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 26
    .line 27
    invoke-virtual {p0, p1, p2}, Lne/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lne/b;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lne/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    :pswitch_1
    check-cast p1, Lje/z0;

    .line 41
    .line 42
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 43
    .line 44
    invoke-virtual {p0, p1, p2}, Lne/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    check-cast p0, Lne/b;

    .line 49
    .line 50
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    invoke-virtual {p0, p1}, Lne/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0

    .line 57
    :pswitch_2
    check-cast p1, Lje/f0;

    .line 58
    .line 59
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 60
    .line 61
    invoke-virtual {p0, p1, p2}, Lne/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    check-cast p0, Lne/b;

    .line 66
    .line 67
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    invoke-virtual {p0, p1}, Lne/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    return-object p0

    .line 74
    nop

    .line 75
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lne/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lne/b;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lje/z0;

    .line 9
    .line 10
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 11
    .line 12
    iget v2, p0, Lne/b;->e:I

    .line 13
    .line 14
    const/4 v3, 0x1

    .line 15
    if-eqz v2, :cond_1

    .line 16
    .line 17
    if-ne v2, v3, :cond_0

    .line 18
    .line 19
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    check-cast p1, Llx0/o;

    .line 23
    .line 24
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 28
    .line 29
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 30
    .line 31
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw p0

    .line 35
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    const/4 p1, 0x0

    .line 39
    iput-object p1, p0, Lne/b;->f:Ljava/lang/Object;

    .line 40
    .line 41
    iput v3, p0, Lne/b;->e:I

    .line 42
    .line 43
    iget-object p1, p0, Lne/b;->g:Lke/f;

    .line 44
    .line 45
    iget-object v2, p0, Lne/b;->h:Ljava/lang/String;

    .line 46
    .line 47
    invoke-virtual {p1, v2, v0, p0}, Lke/f;->e(Ljava/lang/String;Lje/z0;Lrx0/c;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    if-ne p0, v1, :cond_2

    .line 52
    .line 53
    goto :goto_1

    .line 54
    :cond_2
    :goto_0
    new-instance v1, Llx0/o;

    .line 55
    .line 56
    invoke-direct {v1, p0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    :goto_1
    return-object v1

    .line 60
    :pswitch_0
    iget-object v0, p0, Lne/b;->f:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast v0, Lje/z0;

    .line 63
    .line 64
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 65
    .line 66
    iget v2, p0, Lne/b;->e:I

    .line 67
    .line 68
    const/4 v3, 0x1

    .line 69
    if-eqz v2, :cond_4

    .line 70
    .line 71
    if-ne v2, v3, :cond_3

    .line 72
    .line 73
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    check-cast p1, Llx0/o;

    .line 77
    .line 78
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 79
    .line 80
    goto :goto_2

    .line 81
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 82
    .line 83
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 84
    .line 85
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    throw p0

    .line 89
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 90
    .line 91
    .line 92
    const/4 p1, 0x0

    .line 93
    iput-object p1, p0, Lne/b;->f:Ljava/lang/Object;

    .line 94
    .line 95
    iput v3, p0, Lne/b;->e:I

    .line 96
    .line 97
    iget-object p1, p0, Lne/b;->g:Lke/f;

    .line 98
    .line 99
    iget-object v2, p0, Lne/b;->h:Ljava/lang/String;

    .line 100
    .line 101
    invoke-virtual {p1, v2, v0, p0}, Lke/f;->e(Ljava/lang/String;Lje/z0;Lrx0/c;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    if-ne p0, v1, :cond_5

    .line 106
    .line 107
    goto :goto_3

    .line 108
    :cond_5
    :goto_2
    new-instance v1, Llx0/o;

    .line 109
    .line 110
    invoke-direct {v1, p0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    :goto_3
    return-object v1

    .line 114
    :pswitch_1
    iget-object v0, p0, Lne/b;->f:Ljava/lang/Object;

    .line 115
    .line 116
    check-cast v0, Lje/z0;

    .line 117
    .line 118
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 119
    .line 120
    iget v2, p0, Lne/b;->e:I

    .line 121
    .line 122
    const/4 v3, 0x1

    .line 123
    if-eqz v2, :cond_7

    .line 124
    .line 125
    if-ne v2, v3, :cond_6

    .line 126
    .line 127
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 128
    .line 129
    .line 130
    check-cast p1, Llx0/o;

    .line 131
    .line 132
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 133
    .line 134
    goto :goto_4

    .line 135
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 136
    .line 137
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 138
    .line 139
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 140
    .line 141
    .line 142
    throw p0

    .line 143
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 144
    .line 145
    .line 146
    const/4 p1, 0x0

    .line 147
    iput-object p1, p0, Lne/b;->f:Ljava/lang/Object;

    .line 148
    .line 149
    iput v3, p0, Lne/b;->e:I

    .line 150
    .line 151
    iget-object p1, p0, Lne/b;->g:Lke/f;

    .line 152
    .line 153
    iget-object v2, p0, Lne/b;->h:Ljava/lang/String;

    .line 154
    .line 155
    invoke-virtual {p1, v2, v0, p0}, Lke/f;->e(Ljava/lang/String;Lje/z0;Lrx0/c;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object p0

    .line 159
    if-ne p0, v1, :cond_8

    .line 160
    .line 161
    goto :goto_5

    .line 162
    :cond_8
    :goto_4
    new-instance v1, Llx0/o;

    .line 163
    .line 164
    invoke-direct {v1, p0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 165
    .line 166
    .line 167
    :goto_5
    return-object v1

    .line 168
    :pswitch_2
    iget-object v0, p0, Lne/b;->f:Ljava/lang/Object;

    .line 169
    .line 170
    check-cast v0, Lje/f0;

    .line 171
    .line 172
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 173
    .line 174
    iget v2, p0, Lne/b;->e:I

    .line 175
    .line 176
    const/4 v3, 0x1

    .line 177
    if-eqz v2, :cond_a

    .line 178
    .line 179
    if-ne v2, v3, :cond_9

    .line 180
    .line 181
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 182
    .line 183
    .line 184
    check-cast p1, Llx0/o;

    .line 185
    .line 186
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 187
    .line 188
    goto :goto_6

    .line 189
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 190
    .line 191
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 192
    .line 193
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 194
    .line 195
    .line 196
    throw p0

    .line 197
    :cond_a
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 198
    .line 199
    .line 200
    const/4 p1, 0x0

    .line 201
    iput-object p1, p0, Lne/b;->f:Ljava/lang/Object;

    .line 202
    .line 203
    iput v3, p0, Lne/b;->e:I

    .line 204
    .line 205
    iget-object p1, p0, Lne/b;->g:Lke/f;

    .line 206
    .line 207
    iget-object v2, p0, Lne/b;->h:Ljava/lang/String;

    .line 208
    .line 209
    invoke-virtual {p1, v2, v0, p0}, Lke/f;->d(Ljava/lang/String;Lje/f0;Lrx0/c;)Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    move-result-object p0

    .line 213
    if-ne p0, v1, :cond_b

    .line 214
    .line 215
    goto :goto_7

    .line 216
    :cond_b
    :goto_6
    new-instance v1, Llx0/o;

    .line 217
    .line 218
    invoke-direct {v1, p0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 219
    .line 220
    .line 221
    :goto_7
    return-object v1

    .line 222
    nop

    .line 223
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
