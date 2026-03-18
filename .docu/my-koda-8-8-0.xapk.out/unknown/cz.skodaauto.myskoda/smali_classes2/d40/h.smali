.class public final Ld40/h;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ld40/n;

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:Lg40/u;


# direct methods
.method public synthetic constructor <init>(Ld40/n;Ljava/lang/String;Lg40/u;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p5, p0, Ld40/h;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ld40/h;->f:Ld40/n;

    .line 4
    .line 5
    iput-object p2, p0, Ld40/h;->g:Ljava/lang/String;

    .line 6
    .line 7
    iput-object p3, p0, Ld40/h;->h:Lg40/u;

    .line 8
    .line 9
    const/4 p1, 0x1

    .line 10
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 8

    .line 1
    iget v0, p0, Ld40/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Ld40/h;

    .line 7
    .line 8
    iget-object v4, p0, Ld40/h;->h:Lg40/u;

    .line 9
    .line 10
    const/4 v6, 0x1

    .line 11
    iget-object v2, p0, Ld40/h;->f:Ld40/n;

    .line 12
    .line 13
    iget-object v3, p0, Ld40/h;->g:Ljava/lang/String;

    .line 14
    .line 15
    move-object v5, p1

    .line 16
    invoke-direct/range {v1 .. v6}, Ld40/h;-><init>(Ld40/n;Ljava/lang/String;Lg40/u;Lkotlin/coroutines/Continuation;I)V

    .line 17
    .line 18
    .line 19
    return-object v1

    .line 20
    :pswitch_0
    move-object v5, p1

    .line 21
    new-instance v2, Ld40/h;

    .line 22
    .line 23
    move-object v6, v5

    .line 24
    iget-object v5, p0, Ld40/h;->h:Lg40/u;

    .line 25
    .line 26
    const/4 v7, 0x0

    .line 27
    iget-object v3, p0, Ld40/h;->f:Ld40/n;

    .line 28
    .line 29
    iget-object v4, p0, Ld40/h;->g:Ljava/lang/String;

    .line 30
    .line 31
    invoke-direct/range {v2 .. v7}, Ld40/h;-><init>(Ld40/n;Ljava/lang/String;Lg40/u;Lkotlin/coroutines/Continuation;I)V

    .line 32
    .line 33
    .line 34
    return-object v2

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ld40/h;->d:I

    .line 2
    .line 3
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, p1}, Ld40/h;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Ld40/h;

    .line 13
    .line 14
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Ld40/h;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_0
    invoke-virtual {p0, p1}, Ld40/h;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Ld40/h;

    .line 26
    .line 27
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Ld40/h;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    nop

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Ld40/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Ld40/h;->e:I

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
    iget-object p1, p0, Ld40/h;->f:Ld40/n;

    .line 38
    .line 39
    iget-object p1, p1, Ld40/n;->b:Lti0/a;

    .line 40
    .line 41
    iput v3, p0, Ld40/h;->e:I

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
    check-cast p1, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi;

    .line 51
    .line 52
    iget-object v1, p0, Ld40/h;->h:Lg40/u;

    .line 53
    .line 54
    invoke-static {v1}, Ljp/hf;->b(Lg40/u;)Lcz/myskoda/api/bff_loyalty_program/v2/ClaimRewardRequestDto;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    iput v2, p0, Ld40/h;->e:I

    .line 59
    .line 60
    iget-object v2, p0, Ld40/h;->g:Ljava/lang/String;

    .line 61
    .line 62
    invoke-interface {p1, v2, v1, p0}, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi;->claimReward(Ljava/lang/String;Lcz/myskoda/api/bff_loyalty_program/v2/ClaimRewardRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    if-ne p1, v0, :cond_4

    .line 67
    .line 68
    :goto_1
    move-object p1, v0

    .line 69
    :cond_4
    :goto_2
    return-object p1

    .line 70
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 71
    .line 72
    iget v1, p0, Ld40/h;->e:I

    .line 73
    .line 74
    const/4 v2, 0x2

    .line 75
    const/4 v3, 0x1

    .line 76
    if-eqz v1, :cond_7

    .line 77
    .line 78
    if-eq v1, v3, :cond_6

    .line 79
    .line 80
    if-ne v1, v2, :cond_5

    .line 81
    .line 82
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    goto :goto_5

    .line 86
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 87
    .line 88
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 89
    .line 90
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    throw p0

    .line 94
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    goto :goto_3

    .line 98
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    iget-object p1, p0, Ld40/h;->f:Ld40/n;

    .line 102
    .line 103
    iget-object p1, p1, Ld40/n;->b:Lti0/a;

    .line 104
    .line 105
    iput v3, p0, Ld40/h;->e:I

    .line 106
    .line 107
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object p1

    .line 111
    if-ne p1, v0, :cond_8

    .line 112
    .line 113
    goto :goto_4

    .line 114
    :cond_8
    :goto_3
    check-cast p1, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi;

    .line 115
    .line 116
    iget-object v1, p0, Ld40/h;->h:Lg40/u;

    .line 117
    .line 118
    invoke-static {v1}, Ljp/hf;->b(Lg40/u;)Lcz/myskoda/api/bff_loyalty_program/v2/ClaimRewardRequestDto;

    .line 119
    .line 120
    .line 121
    move-result-object v1

    .line 122
    iput v2, p0, Ld40/h;->e:I

    .line 123
    .line 124
    iget-object v2, p0, Ld40/h;->g:Ljava/lang/String;

    .line 125
    .line 126
    invoke-interface {p1, v2, v1, p0}, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi;->claimReward(Ljava/lang/String;Lcz/myskoda/api/bff_loyalty_program/v2/ClaimRewardRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object p1

    .line 130
    if-ne p1, v0, :cond_9

    .line 131
    .line 132
    :goto_4
    move-object p1, v0

    .line 133
    :cond_9
    :goto_5
    return-object p1

    .line 134
    nop

    .line 135
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
