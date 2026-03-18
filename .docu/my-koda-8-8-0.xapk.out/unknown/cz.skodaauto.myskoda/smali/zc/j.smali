.class public final Lzc/j;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lzc/k;

.field public final synthetic g:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Lzc/k;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lzc/j;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lzc/j;->f:Lzc/k;

    .line 4
    .line 5
    iput-object p2, p0, Lzc/j;->g:Ljava/lang/String;

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
    .locals 2

    .line 1
    iget p1, p0, Lzc/j;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lzc/j;

    .line 7
    .line 8
    iget-object v0, p0, Lzc/j;->g:Ljava/lang/String;

    .line 9
    .line 10
    const/4 v1, 0x2

    .line 11
    iget-object p0, p0, Lzc/j;->f:Lzc/k;

    .line 12
    .line 13
    invoke-direct {p1, p0, v0, p2, v1}, Lzc/j;-><init>(Lzc/k;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Lzc/j;

    .line 18
    .line 19
    iget-object v0, p0, Lzc/j;->g:Ljava/lang/String;

    .line 20
    .line 21
    const/4 v1, 0x1

    .line 22
    iget-object p0, p0, Lzc/j;->f:Lzc/k;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, p2, v1}, Lzc/j;-><init>(Lzc/k;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    return-object p1

    .line 28
    :pswitch_1
    new-instance p1, Lzc/j;

    .line 29
    .line 30
    iget-object v0, p0, Lzc/j;->g:Ljava/lang/String;

    .line 31
    .line 32
    const/4 v1, 0x0

    .line 33
    iget-object p0, p0, Lzc/j;->f:Lzc/k;

    .line 34
    .line 35
    invoke-direct {p1, p0, v0, p2, v1}, Lzc/j;-><init>(Lzc/k;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 36
    .line 37
    .line 38
    return-object p1

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lzc/j;->d:I

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
    invoke-virtual {p0, p1, p2}, Lzc/j;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lzc/j;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lzc/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lzc/j;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lzc/j;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lzc/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lzc/j;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lzc/j;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lzc/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lzc/j;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lzc/j;->e:I

    .line 9
    .line 10
    iget-object v2, p0, Lzc/j;->f:Lzc/k;

    .line 11
    .line 12
    const/4 v3, 0x1

    .line 13
    if-eqz v1, :cond_1

    .line 14
    .line 15
    if-ne v1, v3, :cond_0

    .line 16
    .line 17
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 22
    .line 23
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 24
    .line 25
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw p0

    .line 29
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    iget-object p1, v2, Lzc/k;->i:Lth/b;

    .line 33
    .line 34
    new-instance v1, Ltc/n;

    .line 35
    .line 36
    iget-object v4, p0, Lzc/j;->g:Ljava/lang/String;

    .line 37
    .line 38
    invoke-direct {v1, v4, v3}, Ltc/n;-><init>(Ljava/lang/String;Z)V

    .line 39
    .line 40
    .line 41
    iput v3, p0, Lzc/j;->e:I

    .line 42
    .line 43
    invoke-virtual {p1, v1, p0}, Lth/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    if-ne p1, v0, :cond_2

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_2
    :goto_0
    check-cast p1, Llx0/o;

    .line 51
    .line 52
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 53
    .line 54
    instance-of p1, p0, Llx0/n;

    .line 55
    .line 56
    if-nez p1, :cond_3

    .line 57
    .line 58
    move-object p1, p0

    .line 59
    check-cast p1, Ltc/q;

    .line 60
    .line 61
    invoke-static {v2, p1}, Lzc/k;->b(Lzc/k;Ltc/q;)V

    .line 62
    .line 63
    .line 64
    :cond_3
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    if-eqz p0, :cond_4

    .line 69
    .line 70
    invoke-static {v2, p0}, Lzc/k;->a(Lzc/k;Ljava/lang/Throwable;)V

    .line 71
    .line 72
    .line 73
    :cond_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 74
    .line 75
    :goto_1
    return-object v0

    .line 76
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 77
    .line 78
    iget v1, p0, Lzc/j;->e:I

    .line 79
    .line 80
    const/4 v2, 0x1

    .line 81
    iget-object v3, p0, Lzc/j;->f:Lzc/k;

    .line 82
    .line 83
    if-eqz v1, :cond_6

    .line 84
    .line 85
    if-ne v1, v2, :cond_5

    .line 86
    .line 87
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    goto :goto_2

    .line 91
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 92
    .line 93
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 94
    .line 95
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    throw p0

    .line 99
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    iget-object p1, v3, Lzc/k;->g:Lth/b;

    .line 103
    .line 104
    iput v2, p0, Lzc/j;->e:I

    .line 105
    .line 106
    iget-object v1, p0, Lzc/j;->g:Ljava/lang/String;

    .line 107
    .line 108
    invoke-virtual {p1, v1, p0}, Lth/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object p1

    .line 112
    if-ne p1, v0, :cond_7

    .line 113
    .line 114
    goto :goto_3

    .line 115
    :cond_7
    :goto_2
    check-cast p1, Llx0/o;

    .line 116
    .line 117
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 118
    .line 119
    instance-of p1, p0, Llx0/n;

    .line 120
    .line 121
    if-nez p1, :cond_8

    .line 122
    .line 123
    move-object p1, p0

    .line 124
    check-cast p1, Ltc/q;

    .line 125
    .line 126
    invoke-static {v3, p1}, Lzc/k;->b(Lzc/k;Ltc/q;)V

    .line 127
    .line 128
    .line 129
    :cond_8
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 130
    .line 131
    .line 132
    move-result-object p0

    .line 133
    if-eqz p0, :cond_9

    .line 134
    .line 135
    invoke-static {v3, p0}, Lzc/k;->a(Lzc/k;Ljava/lang/Throwable;)V

    .line 136
    .line 137
    .line 138
    :cond_9
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 139
    .line 140
    :goto_3
    return-object v0

    .line 141
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 142
    .line 143
    iget v1, p0, Lzc/j;->e:I

    .line 144
    .line 145
    const/4 v2, 0x1

    .line 146
    iget-object v3, p0, Lzc/j;->f:Lzc/k;

    .line 147
    .line 148
    if-eqz v1, :cond_b

    .line 149
    .line 150
    if-ne v1, v2, :cond_a

    .line 151
    .line 152
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 153
    .line 154
    .line 155
    goto :goto_4

    .line 156
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 157
    .line 158
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 159
    .line 160
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 161
    .line 162
    .line 163
    throw p0

    .line 164
    :cond_b
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 165
    .line 166
    .line 167
    iget-object p1, v3, Lzc/k;->h:Lth/b;

    .line 168
    .line 169
    iput v2, p0, Lzc/j;->e:I

    .line 170
    .line 171
    iget-object v1, p0, Lzc/j;->g:Ljava/lang/String;

    .line 172
    .line 173
    invoke-virtual {p1, v1, p0}, Lth/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object p1

    .line 177
    if-ne p1, v0, :cond_c

    .line 178
    .line 179
    goto :goto_5

    .line 180
    :cond_c
    :goto_4
    check-cast p1, Llx0/o;

    .line 181
    .line 182
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 183
    .line 184
    instance-of p1, p0, Llx0/n;

    .line 185
    .line 186
    if-nez p1, :cond_d

    .line 187
    .line 188
    move-object p1, p0

    .line 189
    check-cast p1, Ltc/q;

    .line 190
    .line 191
    invoke-static {v3, p1}, Lzc/k;->b(Lzc/k;Ltc/q;)V

    .line 192
    .line 193
    .line 194
    :cond_d
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 195
    .line 196
    .line 197
    move-result-object p0

    .line 198
    if-eqz p0, :cond_e

    .line 199
    .line 200
    invoke-static {v3, p0}, Lzc/k;->a(Lzc/k;Ljava/lang/Throwable;)V

    .line 201
    .line 202
    .line 203
    :cond_e
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 204
    .line 205
    :goto_5
    return-object v0

    .line 206
    nop

    .line 207
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
