.class public final Lln0/j;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lln0/l;


# direct methods
.method public synthetic constructor <init>(Lln0/l;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lln0/j;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lln0/j;->f:Lln0/l;

    .line 4
    .line 5
    const/4 p1, 0x1

    .line 6
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget v0, p0, Lln0/j;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lln0/j;

    .line 7
    .line 8
    iget-object p0, p0, Lln0/j;->f:Lln0/l;

    .line 9
    .line 10
    const/4 v1, 0x2

    .line 11
    invoke-direct {v0, p0, p1, v1}, Lln0/j;-><init>(Lln0/l;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object v0

    .line 15
    :pswitch_0
    new-instance v0, Lln0/j;

    .line 16
    .line 17
    iget-object p0, p0, Lln0/j;->f:Lln0/l;

    .line 18
    .line 19
    const/4 v1, 0x1

    .line 20
    invoke-direct {v0, p0, p1, v1}, Lln0/j;-><init>(Lln0/l;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object v0

    .line 24
    :pswitch_1
    new-instance v0, Lln0/j;

    .line 25
    .line 26
    iget-object p0, p0, Lln0/j;->f:Lln0/l;

    .line 27
    .line 28
    const/4 v1, 0x0

    .line 29
    invoke-direct {v0, p0, p1, v1}, Lln0/j;-><init>(Lln0/l;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object v0

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lln0/j;->d:I

    .line 2
    .line 3
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lln0/j;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Lln0/j;

    .line 13
    .line 14
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Lln0/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_0
    invoke-virtual {p0, p1}, Lln0/j;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Lln0/j;

    .line 26
    .line 27
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Lln0/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    :pswitch_1
    invoke-virtual {p0, p1}, Lln0/j;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    check-cast p0, Lln0/j;

    .line 39
    .line 40
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    invoke-virtual {p0, p1}, Lln0/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0

    .line 47
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lln0/j;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lln0/j;->e:I

    .line 9
    .line 10
    const/4 v2, 0x2

    .line 11
    const/4 v3, 0x1

    .line 12
    if-eqz v1, :cond_2

    .line 13
    .line 14
    if-eq v1, v3, :cond_1

    .line 15
    .line 16
    if-ne v1, v2, :cond_0

    .line 17
    .line 18
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    goto :goto_2

    .line 22
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 23
    .line 24
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 25
    .line 26
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw p0

    .line 30
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    iget-object p1, p0, Lln0/j;->f:Lln0/l;

    .line 38
    .line 39
    iget-object p1, p1, Lln0/l;->b:Lti0/a;

    .line 40
    .line 41
    iput v3, p0, Lln0/j;->e:I

    .line 42
    .line 43
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    if-ne p1, v0, :cond_3

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_3
    :goto_0
    check-cast p1, Lcz/myskoda/api/bff/v1/UserApi;

    .line 51
    .line 52
    iput v2, p0, Lln0/j;->e:I

    .line 53
    .line 54
    invoke-interface {p1, p0}, Lcz/myskoda/api/bff/v1/UserApi;->getParkingAccount(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    if-ne p1, v0, :cond_4

    .line 59
    .line 60
    :goto_1
    move-object p1, v0

    .line 61
    :cond_4
    :goto_2
    return-object p1

    .line 62
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 63
    .line 64
    iget v1, p0, Lln0/j;->e:I

    .line 65
    .line 66
    const/4 v2, 0x2

    .line 67
    const/4 v3, 0x1

    .line 68
    if-eqz v1, :cond_7

    .line 69
    .line 70
    if-eq v1, v3, :cond_6

    .line 71
    .line 72
    if-ne v1, v2, :cond_5

    .line 73
    .line 74
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    goto :goto_5

    .line 78
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 79
    .line 80
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 81
    .line 82
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    throw p0

    .line 86
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    goto :goto_3

    .line 90
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    iget-object p1, p0, Lln0/j;->f:Lln0/l;

    .line 94
    .line 95
    iget-object p1, p1, Lln0/l;->c:Lti0/a;

    .line 96
    .line 97
    iput v3, p0, Lln0/j;->e:I

    .line 98
    .line 99
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    if-ne p1, v0, :cond_8

    .line 104
    .line 105
    goto :goto_4

    .line 106
    :cond_8
    :goto_3
    check-cast p1, Lcz/myskoda/api/bff/v1/ParkingApi;

    .line 107
    .line 108
    iput v2, p0, Lln0/j;->e:I

    .line 109
    .line 110
    invoke-interface {p1, p0}, Lcz/myskoda/api/bff/v1/ParkingApi;->getCardsManagementUrl(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object p1

    .line 114
    if-ne p1, v0, :cond_9

    .line 115
    .line 116
    :goto_4
    move-object p1, v0

    .line 117
    :cond_9
    :goto_5
    return-object p1

    .line 118
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 119
    .line 120
    iget v1, p0, Lln0/j;->e:I

    .line 121
    .line 122
    const/4 v2, 0x2

    .line 123
    const/4 v3, 0x1

    .line 124
    if-eqz v1, :cond_c

    .line 125
    .line 126
    if-eq v1, v3, :cond_b

    .line 127
    .line 128
    if-ne v1, v2, :cond_a

    .line 129
    .line 130
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 131
    .line 132
    .line 133
    goto :goto_8

    .line 134
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 135
    .line 136
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 137
    .line 138
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    throw p0

    .line 142
    :cond_b
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 143
    .line 144
    .line 145
    goto :goto_6

    .line 146
    :cond_c
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 147
    .line 148
    .line 149
    iget-object p1, p0, Lln0/j;->f:Lln0/l;

    .line 150
    .line 151
    iget-object p1, p1, Lln0/l;->b:Lti0/a;

    .line 152
    .line 153
    iput v3, p0, Lln0/j;->e:I

    .line 154
    .line 155
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object p1

    .line 159
    if-ne p1, v0, :cond_d

    .line 160
    .line 161
    goto :goto_7

    .line 162
    :cond_d
    :goto_6
    check-cast p1, Lcz/myskoda/api/bff/v1/UserApi;

    .line 163
    .line 164
    iput v2, p0, Lln0/j;->e:I

    .line 165
    .line 166
    invoke-interface {p1, p0}, Lcz/myskoda/api/bff/v1/UserApi;->deleteParkingAccount(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object p1

    .line 170
    if-ne p1, v0, :cond_e

    .line 171
    .line 172
    :goto_7
    move-object p1, v0

    .line 173
    :cond_e
    :goto_8
    return-object p1

    .line 174
    nop

    .line 175
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
