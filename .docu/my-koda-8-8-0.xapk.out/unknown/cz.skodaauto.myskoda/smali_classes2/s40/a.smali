.class public final Ls40/a;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ls40/d;

.field public final synthetic g:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Ls40/d;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Ls40/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ls40/a;->f:Ls40/d;

    .line 4
    .line 5
    iput-object p2, p0, Ls40/a;->g:Ljava/lang/String;

    .line 6
    .line 7
    const/4 p1, 0x1

    .line 8
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    iget v0, p0, Ls40/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Ls40/a;

    .line 7
    .line 8
    iget-object v1, p0, Ls40/a;->g:Ljava/lang/String;

    .line 9
    .line 10
    const/4 v2, 0x2

    .line 11
    iget-object p0, p0, Ls40/a;->f:Ls40/d;

    .line 12
    .line 13
    invoke-direct {v0, p0, v1, p1, v2}, Ls40/a;-><init>(Ls40/d;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Ls40/a;

    .line 18
    .line 19
    iget-object v1, p0, Ls40/a;->g:Ljava/lang/String;

    .line 20
    .line 21
    const/4 v2, 0x1

    .line 22
    iget-object p0, p0, Ls40/a;->f:Ls40/d;

    .line 23
    .line 24
    invoke-direct {v0, p0, v1, p1, v2}, Ls40/a;-><init>(Ls40/d;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    return-object v0

    .line 28
    :pswitch_1
    new-instance v0, Ls40/a;

    .line 29
    .line 30
    iget-object v1, p0, Ls40/a;->g:Ljava/lang/String;

    .line 31
    .line 32
    const/4 v2, 0x0

    .line 33
    iget-object p0, p0, Ls40/a;->f:Ls40/d;

    .line 34
    .line 35
    invoke-direct {v0, p0, v1, p1, v2}, Ls40/a;-><init>(Ls40/d;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 36
    .line 37
    .line 38
    return-object v0

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ls40/a;->d:I

    .line 2
    .line 3
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, p1}, Ls40/a;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Ls40/a;

    .line 13
    .line 14
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Ls40/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_0
    invoke-virtual {p0, p1}, Ls40/a;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Ls40/a;

    .line 26
    .line 27
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Ls40/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    :pswitch_1
    invoke-virtual {p0, p1}, Ls40/a;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    check-cast p0, Ls40/a;

    .line 39
    .line 40
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    invoke-virtual {p0, p1}, Ls40/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Ls40/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Ls40/a;->e:I

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
    iget-object p1, p0, Ls40/a;->f:Ls40/d;

    .line 38
    .line 39
    iget-object p1, p1, Ls40/d;->c:Lti0/a;

    .line 40
    .line 41
    iput v3, p0, Ls40/a;->e:I

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
    iget-object v1, p0, Ls40/a;->g:Ljava/lang/String;

    .line 53
    .line 54
    if-nez v1, :cond_4

    .line 55
    .line 56
    const/4 v1, 0x0

    .line 57
    :cond_4
    iput v2, p0, Ls40/a;->e:I

    .line 58
    .line 59
    invoke-interface {p1, v1, p0}, Lcz/myskoda/api/bff/v1/UserApi;->getParkingAccountPaymentSummary(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    if-ne p1, v0, :cond_5

    .line 64
    .line 65
    :goto_1
    move-object p1, v0

    .line 66
    :cond_5
    :goto_2
    return-object p1

    .line 67
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 68
    .line 69
    iget v1, p0, Ls40/a;->e:I

    .line 70
    .line 71
    const/4 v2, 0x2

    .line 72
    const/4 v3, 0x1

    .line 73
    if-eqz v1, :cond_8

    .line 74
    .line 75
    if-eq v1, v3, :cond_7

    .line 76
    .line 77
    if-ne v1, v2, :cond_6

    .line 78
    .line 79
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    goto :goto_5

    .line 83
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 84
    .line 85
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 86
    .line 87
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    throw p0

    .line 91
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    goto :goto_3

    .line 95
    :cond_8
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 96
    .line 97
    .line 98
    iget-object p1, p0, Ls40/a;->f:Ls40/d;

    .line 99
    .line 100
    iget-object p1, p1, Ls40/d;->b:Lti0/a;

    .line 101
    .line 102
    iput v3, p0, Ls40/a;->e:I

    .line 103
    .line 104
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object p1

    .line 108
    if-ne p1, v0, :cond_9

    .line 109
    .line 110
    goto :goto_4

    .line 111
    :cond_9
    :goto_3
    check-cast p1, Lcz/myskoda/api/bff/v1/ParkingApi;

    .line 112
    .line 113
    iput v2, p0, Ls40/a;->e:I

    .line 114
    .line 115
    iget-object v1, p0, Ls40/a;->g:Ljava/lang/String;

    .line 116
    .line 117
    invoke-interface {p1, v1, p0}, Lcz/myskoda/api/bff/v1/ParkingApi;->endParkingSession(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object p1

    .line 121
    if-ne p1, v0, :cond_a

    .line 122
    .line 123
    :goto_4
    move-object p1, v0

    .line 124
    :cond_a
    :goto_5
    return-object p1

    .line 125
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 126
    .line 127
    iget v1, p0, Ls40/a;->e:I

    .line 128
    .line 129
    const/4 v2, 0x2

    .line 130
    const/4 v3, 0x1

    .line 131
    if-eqz v1, :cond_d

    .line 132
    .line 133
    if-eq v1, v3, :cond_c

    .line 134
    .line 135
    if-ne v1, v2, :cond_b

    .line 136
    .line 137
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 138
    .line 139
    .line 140
    goto :goto_8

    .line 141
    :cond_b
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 142
    .line 143
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 144
    .line 145
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    throw p0

    .line 149
    :cond_c
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 150
    .line 151
    .line 152
    goto :goto_6

    .line 153
    :cond_d
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    iget-object p1, p0, Ls40/a;->f:Ls40/d;

    .line 157
    .line 158
    iget-object p1, p1, Ls40/d;->c:Lti0/a;

    .line 159
    .line 160
    iput v3, p0, Ls40/a;->e:I

    .line 161
    .line 162
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object p1

    .line 166
    if-ne p1, v0, :cond_e

    .line 167
    .line 168
    goto :goto_7

    .line 169
    :cond_e
    :goto_6
    check-cast p1, Lcz/myskoda/api/bff/v1/UserApi;

    .line 170
    .line 171
    new-instance v1, Lcz/myskoda/api/bff/v1/NewVehicleDto;

    .line 172
    .line 173
    iget-object v3, p0, Ls40/a;->g:Ljava/lang/String;

    .line 174
    .line 175
    invoke-direct {v1, v3}, Lcz/myskoda/api/bff/v1/NewVehicleDto;-><init>(Ljava/lang/String;)V

    .line 176
    .line 177
    .line 178
    iput v2, p0, Ls40/a;->e:I

    .line 179
    .line 180
    invoke-interface {p1, v1, p0}, Lcz/myskoda/api/bff/v1/UserApi;->addVehicleToParkingAccount(Lcz/myskoda/api/bff/v1/NewVehicleDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object p1

    .line 184
    if-ne p1, v0, :cond_f

    .line 185
    .line 186
    :goto_7
    move-object p1, v0

    .line 187
    :cond_f
    :goto_8
    return-object p1

    .line 188
    nop

    .line 189
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
