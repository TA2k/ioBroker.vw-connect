.class public final Lp1/k;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lp1/v;


# direct methods
.method public synthetic constructor <init>(Lp1/v;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lp1/k;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lp1/k;->f:Lp1/v;

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
    iget p1, p0, Lp1/k;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lp1/k;

    .line 7
    .line 8
    iget-object p0, p0, Lp1/k;->f:Lp1/v;

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lp1/k;-><init>(Lp1/v;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lp1/k;

    .line 16
    .line 17
    iget-object p0, p0, Lp1/k;->f:Lp1/v;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lp1/k;-><init>(Lp1/v;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lp1/k;

    .line 25
    .line 26
    iget-object p0, p0, Lp1/k;->f:Lp1/v;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lp1/k;-><init>(Lp1/v;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lp1/k;->d:I

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
    invoke-virtual {p0, p1, p2}, Lp1/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lp1/k;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lp1/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lp1/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lp1/k;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lp1/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lp1/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lp1/k;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lp1/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 7

    .line 1
    iget v0, p0, Lp1/k;->d:I

    .line 2
    .line 3
    iget-object v1, p0, Lp1/k;->f:Lp1/v;

    .line 4
    .line 5
    const-string v2, "call to \'resume\' before \'invoke\' with coroutine"

    .line 6
    .line 7
    const/4 v3, 0x1

    .line 8
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 9
    .line 10
    packed-switch v0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 14
    .line 15
    iget v5, p0, Lp1/k;->e:I

    .line 16
    .line 17
    if-eqz v5, :cond_1

    .line 18
    .line 19
    if-ne v5, v3, :cond_0

    .line 20
    .line 21
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    goto :goto_1

    .line 25
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 26
    .line 27
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    iput v3, p0, Lp1/k;->e:I

    .line 35
    .line 36
    sget-object p1, Le1/w0;->d:Le1/w0;

    .line 37
    .line 38
    new-instance v2, Lg1/d2;

    .line 39
    .line 40
    const/4 v3, 0x2

    .line 41
    const/4 v5, 0x0

    .line 42
    const/4 v6, 0x0

    .line 43
    invoke-direct {v2, v3, v6, v5}, Lg1/d2;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {v1, p1, v2, p0}, Lp1/v;->c(Le1/w0;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    if-ne p0, v0, :cond_2

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_2
    move-object p0, v4

    .line 54
    :goto_0
    if-ne p0, v0, :cond_3

    .line 55
    .line 56
    move-object v4, v0

    .line 57
    :cond_3
    :goto_1
    return-object v4

    .line 58
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 59
    .line 60
    iget v5, p0, Lp1/k;->e:I

    .line 61
    .line 62
    if-eqz v5, :cond_5

    .line 63
    .line 64
    if-ne v5, v3, :cond_4

    .line 65
    .line 66
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    goto :goto_3

    .line 70
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 71
    .line 72
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

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
    iput v3, p0, Lp1/k;->e:I

    .line 80
    .line 81
    sget p1, Lp1/y;->a:F

    .line 82
    .line 83
    invoke-virtual {v1}, Lp1/v;->k()I

    .line 84
    .line 85
    .line 86
    move-result p1

    .line 87
    add-int/2addr p1, v3

    .line 88
    invoke-virtual {v1}, Lp1/v;->m()I

    .line 89
    .line 90
    .line 91
    move-result v2

    .line 92
    if-ge p1, v2, :cond_6

    .line 93
    .line 94
    invoke-virtual {v1}, Lp1/v;->k()I

    .line 95
    .line 96
    .line 97
    move-result p1

    .line 98
    add-int/2addr p1, v3

    .line 99
    invoke-static {v1, p1, p0}, Lp1/v;->g(Lp1/v;ILrx0/i;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    if-ne p0, v0, :cond_6

    .line 104
    .line 105
    goto :goto_2

    .line 106
    :cond_6
    move-object p0, v4

    .line 107
    :goto_2
    if-ne p0, v0, :cond_7

    .line 108
    .line 109
    move-object v4, v0

    .line 110
    :cond_7
    :goto_3
    return-object v4

    .line 111
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 112
    .line 113
    iget v5, p0, Lp1/k;->e:I

    .line 114
    .line 115
    if-eqz v5, :cond_9

    .line 116
    .line 117
    if-ne v5, v3, :cond_8

    .line 118
    .line 119
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    goto :goto_5

    .line 123
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 124
    .line 125
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 126
    .line 127
    .line 128
    throw p0

    .line 129
    :cond_9
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 130
    .line 131
    .line 132
    iput v3, p0, Lp1/k;->e:I

    .line 133
    .line 134
    sget p1, Lp1/y;->a:F

    .line 135
    .line 136
    invoke-virtual {v1}, Lp1/v;->k()I

    .line 137
    .line 138
    .line 139
    move-result p1

    .line 140
    sub-int/2addr p1, v3

    .line 141
    if-ltz p1, :cond_a

    .line 142
    .line 143
    invoke-virtual {v1}, Lp1/v;->k()I

    .line 144
    .line 145
    .line 146
    move-result p1

    .line 147
    sub-int/2addr p1, v3

    .line 148
    invoke-static {v1, p1, p0}, Lp1/v;->g(Lp1/v;ILrx0/i;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object p0

    .line 152
    if-ne p0, v0, :cond_a

    .line 153
    .line 154
    goto :goto_4

    .line 155
    :cond_a
    move-object p0, v4

    .line 156
    :goto_4
    if-ne p0, v0, :cond_b

    .line 157
    .line 158
    move-object v4, v0

    .line 159
    :cond_b
    :goto_5
    return-object v4

    .line 160
    nop

    .line 161
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
