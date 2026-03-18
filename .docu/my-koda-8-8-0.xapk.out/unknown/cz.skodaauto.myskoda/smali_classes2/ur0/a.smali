.class public final Lur0/a;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lur0/b;

.field public final synthetic g:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Lur0/b;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lur0/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lur0/a;->f:Lur0/b;

    .line 4
    .line 5
    iput-object p2, p0, Lur0/a;->g:Ljava/lang/String;

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
    iget v0, p0, Lur0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lur0/a;

    .line 7
    .line 8
    iget-object v1, p0, Lur0/a;->g:Ljava/lang/String;

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    iget-object p0, p0, Lur0/a;->f:Lur0/b;

    .line 12
    .line 13
    invoke-direct {v0, p0, v1, p1, v2}, Lur0/a;-><init>(Lur0/b;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Lur0/a;

    .line 18
    .line 19
    iget-object v1, p0, Lur0/a;->g:Ljava/lang/String;

    .line 20
    .line 21
    const/4 v2, 0x0

    .line 22
    iget-object p0, p0, Lur0/a;->f:Lur0/b;

    .line 23
    .line 24
    invoke-direct {v0, p0, v1, p1, v2}, Lur0/a;-><init>(Lur0/b;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    return-object v0

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lur0/a;->d:I

    .line 2
    .line 3
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lur0/a;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Lur0/a;

    .line 13
    .line 14
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Lur0/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_0
    invoke-virtual {p0, p1}, Lur0/a;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Lur0/a;

    .line 26
    .line 27
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Lur0/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Lur0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lur0/a;->e:I

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
    iget-object p1, p0, Lur0/a;->f:Lur0/b;

    .line 38
    .line 39
    iget-object p1, p1, Lur0/b;->b:Lti0/a;

    .line 40
    .line 41
    iput v3, p0, Lur0/a;->e:I

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
    new-instance v1, Lcz/myskoda/api/bff/v1/ContactChannelDto;

    .line 53
    .line 54
    iget-object v3, p0, Lur0/a;->g:Ljava/lang/String;

    .line 55
    .line 56
    invoke-direct {v1, v3}, Lcz/myskoda/api/bff/v1/ContactChannelDto;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    iput v2, p0, Lur0/a;->e:I

    .line 60
    .line 61
    invoke-interface {p1, v1, p0}, Lcz/myskoda/api/bff/v1/UserApi;->updatePreferredContactChannel(Lcz/myskoda/api/bff/v1/ContactChannelDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    if-ne p1, v0, :cond_4

    .line 66
    .line 67
    :goto_1
    move-object p1, v0

    .line 68
    :cond_4
    :goto_2
    return-object p1

    .line 69
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 70
    .line 71
    iget v1, p0, Lur0/a;->e:I

    .line 72
    .line 73
    const/4 v2, 0x2

    .line 74
    const/4 v3, 0x1

    .line 75
    if-eqz v1, :cond_7

    .line 76
    .line 77
    if-eq v1, v3, :cond_6

    .line 78
    .line 79
    if-ne v1, v2, :cond_5

    .line 80
    .line 81
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    goto :goto_5

    .line 85
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 86
    .line 87
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 88
    .line 89
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    throw p0

    .line 93
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    goto :goto_3

    .line 97
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    iget-object p1, p0, Lur0/a;->f:Lur0/b;

    .line 101
    .line 102
    iget-object p1, p1, Lur0/b;->b:Lti0/a;

    .line 103
    .line 104
    iput v3, p0, Lur0/a;->e:I

    .line 105
    .line 106
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object p1

    .line 110
    if-ne p1, v0, :cond_8

    .line 111
    .line 112
    goto :goto_4

    .line 113
    :cond_8
    :goto_3
    check-cast p1, Lcz/myskoda/api/bff/v1/UserApi;

    .line 114
    .line 115
    iput v2, p0, Lur0/a;->e:I

    .line 116
    .line 117
    iget-object v1, p0, Lur0/a;->g:Ljava/lang/String;

    .line 118
    .line 119
    invoke-interface {p1, v1, p0}, Lcz/myskoda/api/bff/v1/UserApi;->deleteUser(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object p1

    .line 123
    if-ne p1, v0, :cond_9

    .line 124
    .line 125
    :goto_4
    move-object p1, v0

    .line 126
    :cond_9
    :goto_5
    return-object p1

    .line 127
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
