.class public final Ltq0/j;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ltq0/k;

.field public final synthetic g:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Ltq0/k;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Ltq0/j;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltq0/j;->f:Ltq0/k;

    .line 4
    .line 5
    iput-object p2, p0, Ltq0/j;->g:Ljava/lang/String;

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
    iget v0, p0, Ltq0/j;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Ltq0/j;

    .line 7
    .line 8
    iget-object v1, p0, Ltq0/j;->g:Ljava/lang/String;

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    iget-object p0, p0, Ltq0/j;->f:Ltq0/k;

    .line 12
    .line 13
    invoke-direct {v0, p0, v1, p1, v2}, Ltq0/j;-><init>(Ltq0/k;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Ltq0/j;

    .line 18
    .line 19
    iget-object v1, p0, Ltq0/j;->g:Ljava/lang/String;

    .line 20
    .line 21
    const/4 v2, 0x0

    .line 22
    iget-object p0, p0, Ltq0/j;->f:Ltq0/k;

    .line 23
    .line 24
    invoke-direct {v0, p0, v1, p1, v2}, Ltq0/j;-><init>(Ltq0/k;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Ltq0/j;->d:I

    .line 2
    .line 3
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, p1}, Ltq0/j;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Ltq0/j;

    .line 13
    .line 14
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Ltq0/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_0
    invoke-virtual {p0, p1}, Ltq0/j;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Ltq0/j;

    .line 26
    .line 27
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Ltq0/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Ltq0/j;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Ltq0/j;->e:I

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
    iget-object p1, p0, Ltq0/j;->f:Ltq0/k;

    .line 38
    .line 39
    iget-object p1, p1, Ltq0/k;->b:Lti0/a;

    .line 40
    .line 41
    iput v3, p0, Ltq0/j;->e:I

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
    check-cast p1, Lcz/myskoda/api/bff/v1/SpinApi;

    .line 51
    .line 52
    const-string v1, "$v$c$cz-skodaauto-myskoda-library-spin-model-Spin$-$this$toDto$0"

    .line 53
    .line 54
    iget-object v3, p0, Ltq0/j;->g:Ljava/lang/String;

    .line 55
    .line 56
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    new-instance v1, Lcz/myskoda/api/bff/v1/SpinDto;

    .line 60
    .line 61
    invoke-direct {v1, v3}, Lcz/myskoda/api/bff/v1/SpinDto;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    iput v2, p0, Ltq0/j;->e:I

    .line 65
    .line 66
    invoke-interface {p1, v1, p0}, Lcz/myskoda/api/bff/v1/SpinApi;->verifySpin(Lcz/myskoda/api/bff/v1/SpinDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    if-ne p1, v0, :cond_4

    .line 71
    .line 72
    :goto_1
    move-object p1, v0

    .line 73
    :cond_4
    :goto_2
    return-object p1

    .line 74
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 75
    .line 76
    iget v1, p0, Ltq0/j;->e:I

    .line 77
    .line 78
    const/4 v2, 0x2

    .line 79
    const/4 v3, 0x1

    .line 80
    if-eqz v1, :cond_7

    .line 81
    .line 82
    if-eq v1, v3, :cond_6

    .line 83
    .line 84
    if-ne v1, v2, :cond_5

    .line 85
    .line 86
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    goto :goto_5

    .line 90
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 91
    .line 92
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 93
    .line 94
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    throw p0

    .line 98
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    goto :goto_3

    .line 102
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    iget-object p1, p0, Ltq0/j;->f:Ltq0/k;

    .line 106
    .line 107
    iget-object p1, p1, Ltq0/k;->b:Lti0/a;

    .line 108
    .line 109
    iput v3, p0, Ltq0/j;->e:I

    .line 110
    .line 111
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object p1

    .line 115
    if-ne p1, v0, :cond_8

    .line 116
    .line 117
    goto :goto_4

    .line 118
    :cond_8
    :goto_3
    check-cast p1, Lcz/myskoda/api/bff/v1/SpinApi;

    .line 119
    .line 120
    new-instance v1, Lcz/myskoda/api/bff/v1/NewSpinDto;

    .line 121
    .line 122
    iget-object v3, p0, Ltq0/j;->g:Ljava/lang/String;

    .line 123
    .line 124
    invoke-direct {v1, v3}, Lcz/myskoda/api/bff/v1/NewSpinDto;-><init>(Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    iput v2, p0, Ltq0/j;->e:I

    .line 128
    .line 129
    invoke-interface {p1, v1, p0}, Lcz/myskoda/api/bff/v1/SpinApi;->resetSPin(Lcz/myskoda/api/bff/v1/NewSpinDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object p1

    .line 133
    if-ne p1, v0, :cond_9

    .line 134
    .line 135
    :goto_4
    move-object p1, v0

    .line 136
    :cond_9
    :goto_5
    return-object p1

    .line 137
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
