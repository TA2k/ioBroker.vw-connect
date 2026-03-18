.class public final Lz20/k;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lh2/r8;

.field public final synthetic g:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lh2/r8;Lay0/a;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lz20/k;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lz20/k;->f:Lh2/r8;

    .line 4
    .line 5
    iput-object p2, p0, Lz20/k;->g:Lay0/a;

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
    iget p1, p0, Lz20/k;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lz20/k;

    .line 7
    .line 8
    iget-object v0, p0, Lz20/k;->g:Lay0/a;

    .line 9
    .line 10
    const/4 v1, 0x3

    .line 11
    iget-object p0, p0, Lz20/k;->f:Lh2/r8;

    .line 12
    .line 13
    invoke-direct {p1, p0, v0, p2, v1}, Lz20/k;-><init>(Lh2/r8;Lay0/a;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Lz20/k;

    .line 18
    .line 19
    iget-object v0, p0, Lz20/k;->g:Lay0/a;

    .line 20
    .line 21
    const/4 v1, 0x2

    .line 22
    iget-object p0, p0, Lz20/k;->f:Lh2/r8;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, p2, v1}, Lz20/k;-><init>(Lh2/r8;Lay0/a;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    return-object p1

    .line 28
    :pswitch_1
    new-instance p1, Lz20/k;

    .line 29
    .line 30
    iget-object v0, p0, Lz20/k;->g:Lay0/a;

    .line 31
    .line 32
    const/4 v1, 0x1

    .line 33
    iget-object p0, p0, Lz20/k;->f:Lh2/r8;

    .line 34
    .line 35
    invoke-direct {p1, p0, v0, p2, v1}, Lz20/k;-><init>(Lh2/r8;Lay0/a;Lkotlin/coroutines/Continuation;I)V

    .line 36
    .line 37
    .line 38
    return-object p1

    .line 39
    :pswitch_2
    new-instance p1, Lz20/k;

    .line 40
    .line 41
    iget-object v0, p0, Lz20/k;->g:Lay0/a;

    .line 42
    .line 43
    const/4 v1, 0x0

    .line 44
    iget-object p0, p0, Lz20/k;->f:Lh2/r8;

    .line 45
    .line 46
    invoke-direct {p1, p0, v0, p2, v1}, Lz20/k;-><init>(Lh2/r8;Lay0/a;Lkotlin/coroutines/Continuation;I)V

    .line 47
    .line 48
    .line 49
    return-object p1

    .line 50
    nop

    .line 51
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
    iget v0, p0, Lz20/k;->d:I

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
    invoke-virtual {p0, p1, p2}, Lz20/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lz20/k;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lz20/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lz20/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lz20/k;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lz20/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lz20/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lz20/k;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lz20/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lz20/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lz20/k;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lz20/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 3

    .line 1
    iget v0, p0, Lz20/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lz20/k;->e:I

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
    iput v2, p0, Lz20/k;->e:I

    .line 31
    .line 32
    iget-object p1, p0, Lz20/k;->f:Lh2/r8;

    .line 33
    .line 34
    invoke-virtual {p1, p0}, Lh2/r8;->d(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    if-ne p1, v0, :cond_2

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_2
    :goto_0
    iget-object p0, p0, Lz20/k;->g:Lay0/a;

    .line 42
    .line 43
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 47
    .line 48
    :goto_1
    return-object v0

    .line 49
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 50
    .line 51
    iget v1, p0, Lz20/k;->e:I

    .line 52
    .line 53
    const/4 v2, 0x1

    .line 54
    if-eqz v1, :cond_4

    .line 55
    .line 56
    if-ne v1, v2, :cond_3

    .line 57
    .line 58
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    goto :goto_2

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
    iput v2, p0, Lz20/k;->e:I

    .line 74
    .line 75
    iget-object p1, p0, Lz20/k;->f:Lh2/r8;

    .line 76
    .line 77
    invoke-virtual {p1, p0}, Lh2/r8;->d(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p1

    .line 81
    if-ne p1, v0, :cond_5

    .line 82
    .line 83
    goto :goto_3

    .line 84
    :cond_5
    :goto_2
    iget-object p0, p0, Lz20/k;->g:Lay0/a;

    .line 85
    .line 86
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 90
    .line 91
    :goto_3
    return-object v0

    .line 92
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 93
    .line 94
    iget v1, p0, Lz20/k;->e:I

    .line 95
    .line 96
    const/4 v2, 0x1

    .line 97
    if-eqz v1, :cond_7

    .line 98
    .line 99
    if-ne v1, v2, :cond_6

    .line 100
    .line 101
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    goto :goto_4

    .line 105
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 106
    .line 107
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 108
    .line 109
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    throw p0

    .line 113
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    iput v2, p0, Lz20/k;->e:I

    .line 117
    .line 118
    iget-object p1, p0, Lz20/k;->f:Lh2/r8;

    .line 119
    .line 120
    invoke-virtual {p1, p0}, Lh2/r8;->d(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object p1

    .line 124
    if-ne p1, v0, :cond_8

    .line 125
    .line 126
    goto :goto_5

    .line 127
    :cond_8
    :goto_4
    iget-object p0, p0, Lz20/k;->g:Lay0/a;

    .line 128
    .line 129
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 133
    .line 134
    :goto_5
    return-object v0

    .line 135
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 136
    .line 137
    iget v1, p0, Lz20/k;->e:I

    .line 138
    .line 139
    const/4 v2, 0x1

    .line 140
    if-eqz v1, :cond_a

    .line 141
    .line 142
    if-ne v1, v2, :cond_9

    .line 143
    .line 144
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 145
    .line 146
    .line 147
    goto :goto_6

    .line 148
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 149
    .line 150
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 151
    .line 152
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    throw p0

    .line 156
    :cond_a
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 157
    .line 158
    .line 159
    iput v2, p0, Lz20/k;->e:I

    .line 160
    .line 161
    iget-object p1, p0, Lz20/k;->f:Lh2/r8;

    .line 162
    .line 163
    invoke-virtual {p1, p0}, Lh2/r8;->d(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object p1

    .line 167
    if-ne p1, v0, :cond_b

    .line 168
    .line 169
    goto :goto_7

    .line 170
    :cond_b
    :goto_6
    iget-object p0, p0, Lz20/k;->g:Lay0/a;

    .line 171
    .line 172
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 176
    .line 177
    :goto_7
    return-object v0

    .line 178
    nop

    .line 179
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
