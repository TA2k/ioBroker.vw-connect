.class public final Lj80/c;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Z

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lj80/d;ZLjava/lang/String;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lj80/c;->d:I

    .line 1
    iput-object p1, p0, Lj80/c;->h:Ljava/lang/Object;

    iput-boolean p2, p0, Lj80/c;->g:Z

    iput-object p3, p0, Lj80/c;->f:Ljava/lang/String;

    const/4 p1, 0x1

    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Ls30/c;Ljava/lang/String;ZLkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lj80/c;->d:I

    .line 2
    iput-object p1, p0, Lj80/c;->h:Ljava/lang/Object;

    iput-object p2, p0, Lj80/c;->f:Ljava/lang/String;

    iput-boolean p3, p0, Lj80/c;->g:Z

    const/4 p1, 0x1

    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    iget v0, p0, Lj80/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lj80/c;

    .line 7
    .line 8
    iget-object v1, p0, Lj80/c;->h:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Ls30/c;

    .line 11
    .line 12
    iget-object v2, p0, Lj80/c;->f:Ljava/lang/String;

    .line 13
    .line 14
    iget-boolean p0, p0, Lj80/c;->g:Z

    .line 15
    .line 16
    invoke-direct {v0, v1, v2, p0, p1}, Lj80/c;-><init>(Ls30/c;Ljava/lang/String;ZLkotlin/coroutines/Continuation;)V

    .line 17
    .line 18
    .line 19
    return-object v0

    .line 20
    :pswitch_0
    new-instance v0, Lj80/c;

    .line 21
    .line 22
    iget-object v1, p0, Lj80/c;->h:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v1, Lj80/d;

    .line 25
    .line 26
    iget-boolean v2, p0, Lj80/c;->g:Z

    .line 27
    .line 28
    iget-object p0, p0, Lj80/c;->f:Ljava/lang/String;

    .line 29
    .line 30
    invoke-direct {v0, v1, v2, p0, p1}, Lj80/c;-><init>(Lj80/d;ZLjava/lang/String;Lkotlin/coroutines/Continuation;)V

    .line 31
    .line 32
    .line 33
    return-object v0

    .line 34
    nop

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lj80/c;->d:I

    .line 2
    .line 3
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lj80/c;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Lj80/c;

    .line 13
    .line 14
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Lj80/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_0
    invoke-virtual {p0, p1}, Lj80/c;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Lj80/c;

    .line 26
    .line 27
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Lj80/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Lj80/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lj80/c;->e:I

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
    iget-object p1, p0, Lj80/c;->h:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast p1, Ls30/c;

    .line 40
    .line 41
    iget-object p1, p1, Ls30/c;->b:Lti0/a;

    .line 42
    .line 43
    iput v3, p0, Lj80/c;->e:I

    .line 44
    .line 45
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    if-ne p1, v0, :cond_3

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_3
    :goto_0
    check-cast p1, Lcz/myskoda/api/bff_consents/v2/ConsentsApi;

    .line 53
    .line 54
    new-instance v1, Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;

    .line 55
    .line 56
    iget-boolean v3, p0, Lj80/c;->g:Z

    .line 57
    .line 58
    invoke-direct {v1, v3}, Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;-><init>(Z)V

    .line 59
    .line 60
    .line 61
    iput v2, p0, Lj80/c;->e:I

    .line 62
    .line 63
    iget-object v2, p0, Lj80/c;->f:Ljava/lang/String;

    .line 64
    .line 65
    invoke-interface {p1, v2, v1, p0}, Lcz/myskoda/api/bff_consents/v2/ConsentsApi;->setEprivacyConsentDecision(Ljava/lang/String;Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    if-ne p1, v0, :cond_4

    .line 70
    .line 71
    :goto_1
    move-object p1, v0

    .line 72
    :cond_4
    :goto_2
    return-object p1

    .line 73
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 74
    .line 75
    iget v1, p0, Lj80/c;->e:I

    .line 76
    .line 77
    const/4 v2, 0x2

    .line 78
    const/4 v3, 0x1

    .line 79
    if-eqz v1, :cond_7

    .line 80
    .line 81
    if-eq v1, v3, :cond_6

    .line 82
    .line 83
    if-ne v1, v2, :cond_5

    .line 84
    .line 85
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    goto :goto_5

    .line 89
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 90
    .line 91
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 92
    .line 93
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    throw p0

    .line 97
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    goto :goto_3

    .line 101
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    iget-object p1, p0, Lj80/c;->h:Ljava/lang/Object;

    .line 105
    .line 106
    check-cast p1, Lj80/d;

    .line 107
    .line 108
    iget-object p1, p1, Lj80/d;->b:Lti0/a;

    .line 109
    .line 110
    iput v3, p0, Lj80/c;->e:I

    .line 111
    .line 112
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object p1

    .line 116
    if-ne p1, v0, :cond_8

    .line 117
    .line 118
    goto :goto_4

    .line 119
    :cond_8
    :goto_3
    check-cast p1, Lcz/myskoda/api/bff_shop/v2/ShopApi;

    .line 120
    .line 121
    iput v2, p0, Lj80/c;->e:I

    .line 122
    .line 123
    iget-boolean v1, p0, Lj80/c;->g:Z

    .line 124
    .line 125
    iget-object v2, p0, Lj80/c;->f:Ljava/lang/String;

    .line 126
    .line 127
    invoke-interface {p1, v1, v2, p0}, Lcz/myskoda/api/bff_shop/v2/ShopApi;->getSkodaCubicTelecomLink(ZLjava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object p1

    .line 131
    if-ne p1, v0, :cond_9

    .line 132
    .line 133
    :goto_4
    move-object p1, v0

    .line 134
    :cond_9
    :goto_5
    return-object p1

    .line 135
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
