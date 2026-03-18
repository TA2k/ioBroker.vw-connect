.class public final Liq0/d;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

.field public final synthetic g:Liq0/e;


# direct methods
.method public synthetic constructor <init>(Lcz/skodaauto/myskoda/app/main/system/MainActivity;Liq0/e;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Liq0/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Liq0/d;->f:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 4
    .line 5
    iput-object p2, p0, Liq0/d;->g:Liq0/e;

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
    iget p1, p0, Liq0/d;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Liq0/d;

    .line 7
    .line 8
    iget-object v0, p0, Liq0/d;->g:Liq0/e;

    .line 9
    .line 10
    const/4 v1, 0x4

    .line 11
    iget-object p0, p0, Liq0/d;->f:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 12
    .line 13
    invoke-direct {p1, p0, v0, p2, v1}, Liq0/d;-><init>(Lcz/skodaauto/myskoda/app/main/system/MainActivity;Liq0/e;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Liq0/d;

    .line 18
    .line 19
    iget-object v0, p0, Liq0/d;->g:Liq0/e;

    .line 20
    .line 21
    const/4 v1, 0x3

    .line 22
    iget-object p0, p0, Liq0/d;->f:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, p2, v1}, Liq0/d;-><init>(Lcz/skodaauto/myskoda/app/main/system/MainActivity;Liq0/e;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    return-object p1

    .line 28
    :pswitch_1
    new-instance p1, Liq0/d;

    .line 29
    .line 30
    iget-object v0, p0, Liq0/d;->g:Liq0/e;

    .line 31
    .line 32
    const/4 v1, 0x2

    .line 33
    iget-object p0, p0, Liq0/d;->f:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 34
    .line 35
    invoke-direct {p1, p0, v0, p2, v1}, Liq0/d;-><init>(Lcz/skodaauto/myskoda/app/main/system/MainActivity;Liq0/e;Lkotlin/coroutines/Continuation;I)V

    .line 36
    .line 37
    .line 38
    return-object p1

    .line 39
    :pswitch_2
    new-instance p1, Liq0/d;

    .line 40
    .line 41
    iget-object v0, p0, Liq0/d;->g:Liq0/e;

    .line 42
    .line 43
    const/4 v1, 0x1

    .line 44
    iget-object p0, p0, Liq0/d;->f:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 45
    .line 46
    invoke-direct {p1, p0, v0, p2, v1}, Liq0/d;-><init>(Lcz/skodaauto/myskoda/app/main/system/MainActivity;Liq0/e;Lkotlin/coroutines/Continuation;I)V

    .line 47
    .line 48
    .line 49
    return-object p1

    .line 50
    :pswitch_3
    new-instance p1, Liq0/d;

    .line 51
    .line 52
    iget-object v0, p0, Liq0/d;->g:Liq0/e;

    .line 53
    .line 54
    const/4 v1, 0x0

    .line 55
    iget-object p0, p0, Liq0/d;->f:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 56
    .line 57
    invoke-direct {p1, p0, v0, p2, v1}, Liq0/d;-><init>(Lcz/skodaauto/myskoda/app/main/system/MainActivity;Liq0/e;Lkotlin/coroutines/Continuation;I)V

    .line 58
    .line 59
    .line 60
    return-object p1

    .line 61
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
    iget v0, p0, Liq0/d;->d:I

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
    invoke-virtual {p0, p1, p2}, Liq0/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Liq0/d;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Liq0/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Liq0/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Liq0/d;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Liq0/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Liq0/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Liq0/d;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Liq0/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Liq0/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Liq0/d;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Liq0/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_3
    invoke-virtual {p0, p1, p2}, Liq0/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Liq0/d;

    .line 67
    .line 68
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    invoke-virtual {p0, p1}, Liq0/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    return-object p0

    .line 75
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Liq0/d;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    iget-object v3, p0, Liq0/d;->g:Liq0/e;

    .line 7
    .line 8
    iget-object v4, p0, Liq0/d;->f:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 9
    .line 10
    const-string v5, "call to \'resume\' before \'invoke\' with coroutine"

    .line 11
    .line 12
    const/4 v6, 0x1

    .line 13
    packed-switch v0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 17
    .line 18
    iget v7, p0, Liq0/d;->e:I

    .line 19
    .line 20
    if-eqz v7, :cond_1

    .line 21
    .line 22
    if-ne v7, v6, :cond_0

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
    invoke-direct {p0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

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
    sget-object p1, Landroidx/lifecycle/q;->d:Landroidx/lifecycle/q;

    .line 38
    .line 39
    new-instance p1, Liq0/c;

    .line 40
    .line 41
    const/4 v5, 0x4

    .line 42
    invoke-direct {p1, v3, v2, v5}, Liq0/c;-><init>(Liq0/e;Lkotlin/coroutines/Continuation;I)V

    .line 43
    .line 44
    .line 45
    iput v6, p0, Liq0/d;->e:I

    .line 46
    .line 47
    invoke-static {v4, p1, p0}, Landroidx/lifecycle/v0;->k(Landroidx/lifecycle/x;Lay0/n;Lrx0/i;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    if-ne p0, v0, :cond_2

    .line 52
    .line 53
    move-object v1, v0

    .line 54
    :cond_2
    :goto_0
    return-object v1

    .line 55
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 56
    .line 57
    iget v7, p0, Liq0/d;->e:I

    .line 58
    .line 59
    if-eqz v7, :cond_4

    .line 60
    .line 61
    if-ne v7, v6, :cond_3

    .line 62
    .line 63
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 68
    .line 69
    invoke-direct {p0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    throw p0

    .line 73
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    sget-object p1, Landroidx/lifecycle/q;->d:Landroidx/lifecycle/q;

    .line 77
    .line 78
    new-instance p1, Liq0/c;

    .line 79
    .line 80
    const/4 v5, 0x3

    .line 81
    invoke-direct {p1, v3, v2, v5}, Liq0/c;-><init>(Liq0/e;Lkotlin/coroutines/Continuation;I)V

    .line 82
    .line 83
    .line 84
    iput v6, p0, Liq0/d;->e:I

    .line 85
    .line 86
    invoke-static {v4, p1, p0}, Landroidx/lifecycle/v0;->k(Landroidx/lifecycle/x;Lay0/n;Lrx0/i;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    if-ne p0, v0, :cond_5

    .line 91
    .line 92
    move-object v1, v0

    .line 93
    :cond_5
    :goto_1
    return-object v1

    .line 94
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 95
    .line 96
    iget v7, p0, Liq0/d;->e:I

    .line 97
    .line 98
    if-eqz v7, :cond_7

    .line 99
    .line 100
    if-ne v7, v6, :cond_6

    .line 101
    .line 102
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    goto :goto_2

    .line 106
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 107
    .line 108
    invoke-direct {p0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    throw p0

    .line 112
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 113
    .line 114
    .line 115
    sget-object p1, Landroidx/lifecycle/q;->d:Landroidx/lifecycle/q;

    .line 116
    .line 117
    new-instance p1, Liq0/c;

    .line 118
    .line 119
    const/4 v5, 0x2

    .line 120
    invoke-direct {p1, v3, v2, v5}, Liq0/c;-><init>(Liq0/e;Lkotlin/coroutines/Continuation;I)V

    .line 121
    .line 122
    .line 123
    iput v6, p0, Liq0/d;->e:I

    .line 124
    .line 125
    invoke-static {v4, p1, p0}, Landroidx/lifecycle/v0;->k(Landroidx/lifecycle/x;Lay0/n;Lrx0/i;)Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    if-ne p0, v0, :cond_8

    .line 130
    .line 131
    move-object v1, v0

    .line 132
    :cond_8
    :goto_2
    return-object v1

    .line 133
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 134
    .line 135
    iget v7, p0, Liq0/d;->e:I

    .line 136
    .line 137
    if-eqz v7, :cond_a

    .line 138
    .line 139
    if-ne v7, v6, :cond_9

    .line 140
    .line 141
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 142
    .line 143
    .line 144
    goto :goto_3

    .line 145
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 146
    .line 147
    invoke-direct {p0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 148
    .line 149
    .line 150
    throw p0

    .line 151
    :cond_a
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 152
    .line 153
    .line 154
    sget-object p1, Landroidx/lifecycle/q;->d:Landroidx/lifecycle/q;

    .line 155
    .line 156
    new-instance p1, Liq0/c;

    .line 157
    .line 158
    invoke-direct {p1, v3, v2, v6}, Liq0/c;-><init>(Liq0/e;Lkotlin/coroutines/Continuation;I)V

    .line 159
    .line 160
    .line 161
    iput v6, p0, Liq0/d;->e:I

    .line 162
    .line 163
    invoke-static {v4, p1, p0}, Landroidx/lifecycle/v0;->k(Landroidx/lifecycle/x;Lay0/n;Lrx0/i;)Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object p0

    .line 167
    if-ne p0, v0, :cond_b

    .line 168
    .line 169
    move-object v1, v0

    .line 170
    :cond_b
    :goto_3
    return-object v1

    .line 171
    :pswitch_3
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 172
    .line 173
    iget v7, p0, Liq0/d;->e:I

    .line 174
    .line 175
    if-eqz v7, :cond_d

    .line 176
    .line 177
    if-ne v7, v6, :cond_c

    .line 178
    .line 179
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 180
    .line 181
    .line 182
    goto :goto_4

    .line 183
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 184
    .line 185
    invoke-direct {p0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 186
    .line 187
    .line 188
    throw p0

    .line 189
    :cond_d
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 190
    .line 191
    .line 192
    sget-object p1, Landroidx/lifecycle/q;->d:Landroidx/lifecycle/q;

    .line 193
    .line 194
    new-instance p1, Liq0/c;

    .line 195
    .line 196
    const/4 v5, 0x0

    .line 197
    invoke-direct {p1, v3, v2, v5}, Liq0/c;-><init>(Liq0/e;Lkotlin/coroutines/Continuation;I)V

    .line 198
    .line 199
    .line 200
    iput v6, p0, Liq0/d;->e:I

    .line 201
    .line 202
    invoke-static {v4, p1, p0}, Landroidx/lifecycle/v0;->k(Landroidx/lifecycle/x;Lay0/n;Lrx0/i;)Ljava/lang/Object;

    .line 203
    .line 204
    .line 205
    move-result-object p0

    .line 206
    if-ne p0, v0, :cond_e

    .line 207
    .line 208
    move-object v1, v0

    .line 209
    :cond_e
    :goto_4
    return-object v1

    .line 210
    nop

    .line 211
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
