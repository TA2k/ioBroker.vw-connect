.class public final Lod0/z;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lod0/b0;

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:Lrd0/d;


# direct methods
.method public synthetic constructor <init>(Lod0/b0;Ljava/lang/String;Lrd0/d;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p5, p0, Lod0/z;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lod0/z;->f:Lod0/b0;

    .line 4
    .line 5
    iput-object p2, p0, Lod0/z;->g:Ljava/lang/String;

    .line 6
    .line 7
    iput-object p3, p0, Lod0/z;->h:Lrd0/d;

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
    iget v0, p0, Lod0/z;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Lod0/z;

    .line 7
    .line 8
    iget-object v4, p0, Lod0/z;->h:Lrd0/d;

    .line 9
    .line 10
    const/4 v6, 0x1

    .line 11
    iget-object v2, p0, Lod0/z;->f:Lod0/b0;

    .line 12
    .line 13
    iget-object v3, p0, Lod0/z;->g:Ljava/lang/String;

    .line 14
    .line 15
    move-object v5, p1

    .line 16
    invoke-direct/range {v1 .. v6}, Lod0/z;-><init>(Lod0/b0;Ljava/lang/String;Lrd0/d;Lkotlin/coroutines/Continuation;I)V

    .line 17
    .line 18
    .line 19
    return-object v1

    .line 20
    :pswitch_0
    move-object v5, p1

    .line 21
    new-instance v2, Lod0/z;

    .line 22
    .line 23
    move-object v6, v5

    .line 24
    iget-object v5, p0, Lod0/z;->h:Lrd0/d;

    .line 25
    .line 26
    const/4 v7, 0x0

    .line 27
    iget-object v3, p0, Lod0/z;->f:Lod0/b0;

    .line 28
    .line 29
    iget-object v4, p0, Lod0/z;->g:Ljava/lang/String;

    .line 30
    .line 31
    invoke-direct/range {v2 .. v7}, Lod0/z;-><init>(Lod0/b0;Ljava/lang/String;Lrd0/d;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lod0/z;->d:I

    .line 2
    .line 3
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lod0/z;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Lod0/z;

    .line 13
    .line 14
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Lod0/z;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_0
    invoke-virtual {p0, p1}, Lod0/z;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Lod0/z;

    .line 26
    .line 27
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Lod0/z;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Lod0/z;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lod0/z;->e:I

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
    iget-object p1, p0, Lod0/z;->f:Lod0/b0;

    .line 38
    .line 39
    iget-object p1, p1, Lod0/b0;->b:Lti0/a;

    .line 40
    .line 41
    iput v3, p0, Lod0/z;->e:I

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
    check-cast p1, Lcz/myskoda/api/bff/v1/ChargingApi;

    .line 51
    .line 52
    iget-object v1, p0, Lod0/z;->h:Lrd0/d;

    .line 53
    .line 54
    iget-object v1, v1, Lrd0/d;->a:Ljava/lang/String;

    .line 55
    .line 56
    iput v2, p0, Lod0/z;->e:I

    .line 57
    .line 58
    iget-object v2, p0, Lod0/z;->g:Ljava/lang/String;

    .line 59
    .line 60
    invoke-interface {p1, v2, v1, p0}, Lcz/myskoda/api/bff/v1/ChargingApi;->uninstallCertificate(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    if-ne p1, v0, :cond_4

    .line 65
    .line 66
    :goto_1
    move-object p1, v0

    .line 67
    :cond_4
    :goto_2
    return-object p1

    .line 68
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 69
    .line 70
    iget v1, p0, Lod0/z;->e:I

    .line 71
    .line 72
    const/4 v2, 0x2

    .line 73
    const/4 v3, 0x1

    .line 74
    if-eqz v1, :cond_7

    .line 75
    .line 76
    if-eq v1, v3, :cond_6

    .line 77
    .line 78
    if-ne v1, v2, :cond_5

    .line 79
    .line 80
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    goto :goto_5

    .line 84
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 85
    .line 86
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 87
    .line 88
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    throw p0

    .line 92
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    goto :goto_3

    .line 96
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    iget-object p1, p0, Lod0/z;->f:Lod0/b0;

    .line 100
    .line 101
    iget-object p1, p1, Lod0/b0;->b:Lti0/a;

    .line 102
    .line 103
    iput v3, p0, Lod0/z;->e:I

    .line 104
    .line 105
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object p1

    .line 109
    if-ne p1, v0, :cond_8

    .line 110
    .line 111
    goto :goto_4

    .line 112
    :cond_8
    :goto_3
    check-cast p1, Lcz/myskoda/api/bff/v1/ChargingApi;

    .line 113
    .line 114
    iget-object v1, p0, Lod0/z;->h:Lrd0/d;

    .line 115
    .line 116
    iget-object v1, v1, Lrd0/d;->a:Ljava/lang/String;

    .line 117
    .line 118
    iput v2, p0, Lod0/z;->e:I

    .line 119
    .line 120
    iget-object v2, p0, Lod0/z;->g:Ljava/lang/String;

    .line 121
    .line 122
    invoke-interface {p1, v2, v1, p0}, Lcz/myskoda/api/bff/v1/ChargingApi;->installCertificate(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object p1

    .line 126
    if-ne p1, v0, :cond_9

    .line 127
    .line 128
    :goto_4
    move-object p1, v0

    .line 129
    :cond_9
    :goto_5
    return-object p1

    .line 130
    nop

    .line 131
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
