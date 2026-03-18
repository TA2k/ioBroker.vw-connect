.class public final Lg1/i;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Lay0/n;


# direct methods
.method public synthetic constructor <init>(Lay0/a;Lay0/n;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lg1/i;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lg1/i;->g:Lay0/a;

    .line 4
    .line 5
    iput-object p2, p0, Lg1/i;->h:Lay0/n;

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
    .locals 3

    .line 1
    iget v0, p0, Lg1/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lg1/i;

    .line 7
    .line 8
    iget-object v1, p0, Lg1/i;->h:Lay0/n;

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    iget-object p0, p0, Lg1/i;->g:Lay0/a;

    .line 12
    .line 13
    invoke-direct {v0, p0, v1, p2, v2}, Lg1/i;-><init>(Lay0/a;Lay0/n;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    iput-object p1, v0, Lg1/i;->f:Ljava/lang/Object;

    .line 17
    .line 18
    return-object v0

    .line 19
    :pswitch_0
    new-instance v0, Lg1/i;

    .line 20
    .line 21
    iget-object v1, p0, Lg1/i;->h:Lay0/n;

    .line 22
    .line 23
    const/4 v2, 0x0

    .line 24
    iget-object p0, p0, Lg1/i;->g:Lay0/a;

    .line 25
    .line 26
    invoke-direct {v0, p0, v1, p2, v2}, Lg1/i;-><init>(Lay0/a;Lay0/n;Lkotlin/coroutines/Continuation;I)V

    .line 27
    .line 28
    .line 29
    iput-object p1, v0, Lg1/i;->f:Ljava/lang/Object;

    .line 30
    .line 31
    return-object v0

    .line 32
    nop

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lg1/i;->d:I

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
    invoke-virtual {p0, p1, p2}, Lg1/i;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lg1/i;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lg1/i;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lg1/i;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lg1/i;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lg1/i;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 7

    .line 1
    iget v0, p0, Lg1/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lg1/i;->e:I

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
    iget-object p1, p0, Lg1/i;->f:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p1, Lvy0/b0;

    .line 33
    .line 34
    new-instance v1, Lkotlin/jvm/internal/f0;

    .line 35
    .line 36
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 37
    .line 38
    .line 39
    iget-object v3, p0, Lg1/i;->g:Lay0/a;

    .line 40
    .line 41
    invoke-static {v3}, Ll2/b;->u(Lay0/a;)Lyy0/m1;

    .line 42
    .line 43
    .line 44
    move-result-object v3

    .line 45
    new-instance v4, Lg1/h;

    .line 46
    .line 47
    iget-object v5, p0, Lg1/i;->h:Lay0/n;

    .line 48
    .line 49
    const/4 v6, 0x1

    .line 50
    invoke-direct {v4, v1, p1, v5, v6}, Lg1/h;-><init>(Lkotlin/jvm/internal/f0;Lvy0/b0;Lay0/n;I)V

    .line 51
    .line 52
    .line 53
    iput v2, p0, Lg1/i;->e:I

    .line 54
    .line 55
    invoke-virtual {v3, v4, p0}, Lyy0/m1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    if-ne p0, v0, :cond_2

    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 63
    .line 64
    :goto_1
    return-object v0

    .line 65
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 66
    .line 67
    iget v1, p0, Lg1/i;->e:I

    .line 68
    .line 69
    const/4 v2, 0x1

    .line 70
    if-eqz v1, :cond_4

    .line 71
    .line 72
    if-ne v1, v2, :cond_3

    .line 73
    .line 74
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    goto :goto_2

    .line 78
    :cond_3
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
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    iget-object p1, p0, Lg1/i;->f:Ljava/lang/Object;

    .line 90
    .line 91
    check-cast p1, Lvy0/b0;

    .line 92
    .line 93
    new-instance v1, Lkotlin/jvm/internal/f0;

    .line 94
    .line 95
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 96
    .line 97
    .line 98
    iget-object v3, p0, Lg1/i;->g:Lay0/a;

    .line 99
    .line 100
    invoke-static {v3}, Ll2/b;->u(Lay0/a;)Lyy0/m1;

    .line 101
    .line 102
    .line 103
    move-result-object v3

    .line 104
    new-instance v4, Lg1/h;

    .line 105
    .line 106
    iget-object v5, p0, Lg1/i;->h:Lay0/n;

    .line 107
    .line 108
    const/4 v6, 0x0

    .line 109
    invoke-direct {v4, v1, p1, v5, v6}, Lg1/h;-><init>(Lkotlin/jvm/internal/f0;Lvy0/b0;Lay0/n;I)V

    .line 110
    .line 111
    .line 112
    iput v2, p0, Lg1/i;->e:I

    .line 113
    .line 114
    invoke-virtual {v3, v4, p0}, Lyy0/m1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    if-ne p0, v0, :cond_5

    .line 119
    .line 120
    goto :goto_3

    .line 121
    :cond_5
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 122
    .line 123
    :goto_3
    return-object v0

    .line 124
    nop

    .line 125
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
