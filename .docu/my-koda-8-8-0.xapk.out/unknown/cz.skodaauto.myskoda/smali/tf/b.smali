.class public final Ltf/b;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ltf/c;


# direct methods
.method public synthetic constructor <init>(Ltf/c;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ltf/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltf/b;->f:Ltf/c;

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
    iget p1, p0, Ltf/b;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Ltf/b;

    .line 7
    .line 8
    iget-object p0, p0, Ltf/b;->f:Ltf/c;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Ltf/b;-><init>(Ltf/c;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Ltf/b;

    .line 16
    .line 17
    iget-object p0, p0, Ltf/b;->f:Ltf/c;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Ltf/b;-><init>(Ltf/c;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Ltf/b;->d:I

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
    invoke-virtual {p0, p1, p2}, Ltf/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ltf/b;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ltf/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ltf/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ltf/b;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ltf/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 12

    .line 1
    iget v0, p0, Ltf/b;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    const/4 v2, 0x3

    .line 6
    const/4 v3, 0x0

    .line 7
    const-string v4, "call to \'resume\' before \'invoke\' with coroutine"

    .line 8
    .line 9
    const/4 v5, 0x1

    .line 10
    iget-object v6, p0, Ltf/b;->f:Ltf/c;

    .line 11
    .line 12
    const/4 v7, 0x0

    .line 13
    packed-switch v0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 17
    .line 18
    iget v8, p0, Ltf/b;->e:I

    .line 19
    .line 20
    if-eqz v8, :cond_1

    .line 21
    .line 22
    if-ne v8, v5, :cond_0

    .line 23
    .line 24
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 29
    .line 30
    invoke-direct {p0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    throw p0

    .line 34
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    iget-object p1, v6, Ltf/c;->e:Ljd/b;

    .line 38
    .line 39
    iget-object v4, v6, Ltf/c;->d:Ljava/lang/String;

    .line 40
    .line 41
    iput v5, p0, Ltf/b;->e:I

    .line 42
    .line 43
    invoke-virtual {p1, v4, p0}, Ljd/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    if-ne p1, v0, :cond_2

    .line 48
    .line 49
    move-object v1, v0

    .line 50
    goto :goto_3

    .line 51
    :cond_2
    :goto_0
    check-cast p1, Llx0/o;

    .line 52
    .line 53
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 54
    .line 55
    instance-of p1, p0, Llx0/n;

    .line 56
    .line 57
    if-nez p1, :cond_5

    .line 58
    .line 59
    move-object p1, p0

    .line 60
    check-cast p1, Lof/p;

    .line 61
    .line 62
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 63
    .line 64
    .line 65
    iget-object p1, p1, Lof/p;->b:Lof/o;

    .line 66
    .line 67
    sget-object v0, Lof/o;->e:Lof/o;

    .line 68
    .line 69
    if-eq p1, v0, :cond_4

    .line 70
    .line 71
    sget-object v0, Lof/o;->f:Lof/o;

    .line 72
    .line 73
    if-ne p1, v0, :cond_3

    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_3
    iget-object p1, v6, Ltf/c;->f:Lyj/b;

    .line 77
    .line 78
    invoke-virtual {p1}, Lyj/b;->invoke()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    goto :goto_2

    .line 82
    :cond_4
    :goto_1
    invoke-static {v6}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    new-instance v0, Ltf/b;

    .line 87
    .line 88
    invoke-direct {v0, v6, v7, v3}, Ltf/b;-><init>(Ltf/c;Lkotlin/coroutines/Continuation;I)V

    .line 89
    .line 90
    .line 91
    invoke-static {p1, v7, v7, v0, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 92
    .line 93
    .line 94
    :cond_5
    :goto_2
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    if-eqz p0, :cond_6

    .line 99
    .line 100
    iget-object p1, v6, Ltf/c;->g:Lyy0/c2;

    .line 101
    .line 102
    invoke-static {p0}, Llc/c;->b(Ljava/lang/Throwable;)Llc/l;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    invoke-static {p0, p1, v7}, Lia/b;->v(Llc/l;Lyy0/c2;Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    :cond_6
    :goto_3
    return-object v1

    .line 110
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 111
    .line 112
    iget v8, p0, Ltf/b;->e:I

    .line 113
    .line 114
    const/4 v9, 0x2

    .line 115
    if-eqz v8, :cond_9

    .line 116
    .line 117
    if-eq v8, v5, :cond_8

    .line 118
    .line 119
    if-ne v8, v9, :cond_7

    .line 120
    .line 121
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 122
    .line 123
    .line 124
    goto :goto_6

    .line 125
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 126
    .line 127
    invoke-direct {p0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    throw p0

    .line 131
    :cond_8
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 132
    .line 133
    .line 134
    goto :goto_4

    .line 135
    :cond_9
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 136
    .line 137
    .line 138
    sget p1, Lmy0/c;->g:I

    .line 139
    .line 140
    const/16 p1, 0xf

    .line 141
    .line 142
    sget-object v4, Lmy0/e;->h:Lmy0/e;

    .line 143
    .line 144
    invoke-static {p1, v4}, Lmy0/h;->s(ILmy0/e;)J

    .line 145
    .line 146
    .line 147
    move-result-wide v10

    .line 148
    iput v5, p0, Ltf/b;->e:I

    .line 149
    .line 150
    invoke-static {v10, v11, p0}, Lvy0/e0;->q(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object p1

    .line 154
    if-ne p1, v0, :cond_a

    .line 155
    .line 156
    goto :goto_5

    .line 157
    :cond_a
    :goto_4
    iget-object p1, v6, Ltf/c;->e:Ljd/b;

    .line 158
    .line 159
    iget-object v4, v6, Ltf/c;->d:Ljava/lang/String;

    .line 160
    .line 161
    iput v9, p0, Ltf/b;->e:I

    .line 162
    .line 163
    invoke-virtual {p1, v4, p0}, Ljd/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object p1

    .line 167
    if-ne p1, v0, :cond_b

    .line 168
    .line 169
    :goto_5
    move-object v1, v0

    .line 170
    goto :goto_9

    .line 171
    :cond_b
    :goto_6
    check-cast p1, Llx0/o;

    .line 172
    .line 173
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 174
    .line 175
    instance-of p1, p0, Llx0/n;

    .line 176
    .line 177
    if-nez p1, :cond_e

    .line 178
    .line 179
    move-object p1, p0

    .line 180
    check-cast p1, Lof/p;

    .line 181
    .line 182
    iget-object p1, p1, Lof/p;->b:Lof/o;

    .line 183
    .line 184
    sget-object v0, Lof/o;->e:Lof/o;

    .line 185
    .line 186
    if-eq p1, v0, :cond_d

    .line 187
    .line 188
    sget-object v0, Lof/o;->f:Lof/o;

    .line 189
    .line 190
    if-ne p1, v0, :cond_c

    .line 191
    .line 192
    goto :goto_7

    .line 193
    :cond_c
    iget-object p1, v6, Ltf/c;->f:Lyj/b;

    .line 194
    .line 195
    invoke-virtual {p1}, Lyj/b;->invoke()Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    goto :goto_8

    .line 199
    :cond_d
    :goto_7
    invoke-static {v6}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 200
    .line 201
    .line 202
    move-result-object p1

    .line 203
    new-instance v0, Ltf/b;

    .line 204
    .line 205
    invoke-direct {v0, v6, v7, v3}, Ltf/b;-><init>(Ltf/c;Lkotlin/coroutines/Continuation;I)V

    .line 206
    .line 207
    .line 208
    invoke-static {p1, v7, v7, v0, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 209
    .line 210
    .line 211
    :cond_e
    :goto_8
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 212
    .line 213
    .line 214
    move-result-object p0

    .line 215
    if-eqz p0, :cond_f

    .line 216
    .line 217
    iget-object p1, v6, Ltf/c;->g:Lyy0/c2;

    .line 218
    .line 219
    invoke-static {p0}, Llc/c;->b(Ljava/lang/Throwable;)Llc/l;

    .line 220
    .line 221
    .line 222
    move-result-object p0

    .line 223
    invoke-static {p0, p1, v7}, Lia/b;->v(Llc/l;Lyy0/c2;Ljava/lang/Object;)V

    .line 224
    .line 225
    .line 226
    :cond_f
    :goto_9
    return-object v1

    .line 227
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
