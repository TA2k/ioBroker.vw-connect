.class public final Lh2/u5;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lh2/v5;

.field public final synthetic g:Lb/c;


# direct methods
.method public synthetic constructor <init>(Lh2/v5;Lb/c;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lh2/u5;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/u5;->f:Lh2/v5;

    .line 4
    .line 5
    iput-object p2, p0, Lh2/u5;->g:Lb/c;

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
    iget p1, p0, Lh2/u5;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lh2/u5;

    .line 7
    .line 8
    iget-object v0, p0, Lh2/u5;->g:Lb/c;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    iget-object p0, p0, Lh2/u5;->f:Lh2/v5;

    .line 12
    .line 13
    invoke-direct {p1, p0, v0, p2, v1}, Lh2/u5;-><init>(Lh2/v5;Lb/c;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Lh2/u5;

    .line 18
    .line 19
    iget-object v0, p0, Lh2/u5;->g:Lb/c;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    iget-object p0, p0, Lh2/u5;->f:Lh2/v5;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, p2, v1}, Lh2/u5;-><init>(Lh2/v5;Lb/c;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    return-object p1

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lh2/u5;->d:I

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
    invoke-virtual {p0, p1, p2}, Lh2/u5;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lh2/u5;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lh2/u5;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lh2/u5;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lh2/u5;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lh2/u5;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lh2/u5;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lh2/u5;->e:I

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
    iget-object p1, p0, Lh2/u5;->f:Lh2/v5;

    .line 31
    .line 32
    iget-object p1, p1, Lh2/v5;->c:Lc1/c;

    .line 33
    .line 34
    iget-object v1, p0, Lh2/u5;->g:Lb/c;

    .line 35
    .line 36
    iget v1, v1, Lb/c;->c:F

    .line 37
    .line 38
    sget-object v3, Li2/q;->a:Lc1/s;

    .line 39
    .line 40
    invoke-virtual {v3, v1}, Lc1/s;->b(F)F

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    new-instance v3, Ljava/lang/Float;

    .line 45
    .line 46
    invoke-direct {v3, v1}, Ljava/lang/Float;-><init>(F)V

    .line 47
    .line 48
    .line 49
    iput v2, p0, Lh2/u5;->e:I

    .line 50
    .line 51
    invoke-virtual {p1, v3, p0}, Lc1/c;->f(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    if-ne p0, v0, :cond_2

    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 59
    .line 60
    :goto_1
    return-object v0

    .line 61
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 62
    .line 63
    iget v1, p0, Lh2/u5;->e:I

    .line 64
    .line 65
    const/4 v2, 0x1

    .line 66
    if-eqz v1, :cond_4

    .line 67
    .line 68
    if-ne v1, v2, :cond_3

    .line 69
    .line 70
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    goto :goto_2

    .line 74
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 75
    .line 76
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 77
    .line 78
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    throw p0

    .line 82
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    iget-object p1, p0, Lh2/u5;->f:Lh2/v5;

    .line 86
    .line 87
    iget-object p1, p1, Lh2/v5;->c:Lc1/c;

    .line 88
    .line 89
    iget-object v1, p0, Lh2/u5;->g:Lb/c;

    .line 90
    .line 91
    iget v1, v1, Lb/c;->c:F

    .line 92
    .line 93
    sget-object v3, Li2/q;->a:Lc1/s;

    .line 94
    .line 95
    invoke-virtual {v3, v1}, Lc1/s;->b(F)F

    .line 96
    .line 97
    .line 98
    move-result v1

    .line 99
    new-instance v3, Ljava/lang/Float;

    .line 100
    .line 101
    invoke-direct {v3, v1}, Ljava/lang/Float;-><init>(F)V

    .line 102
    .line 103
    .line 104
    iput v2, p0, Lh2/u5;->e:I

    .line 105
    .line 106
    invoke-virtual {p1, v3, p0}, Lc1/c;->f(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    if-ne p0, v0, :cond_5

    .line 111
    .line 112
    goto :goto_3

    .line 113
    :cond_5
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 114
    .line 115
    :goto_3
    return-object v0

    .line 116
    nop

    .line 117
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
