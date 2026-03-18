.class public final Lnc0/d;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lyy0/i;

.field public final synthetic g:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lyy0/i;Lay0/k;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lnc0/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lnc0/d;->f:Lyy0/i;

    .line 4
    .line 5
    iput-object p2, p0, Lnc0/d;->g:Lay0/k;

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
    iget p1, p0, Lnc0/d;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lnc0/d;

    .line 7
    .line 8
    iget-object v0, p0, Lnc0/d;->g:Lay0/k;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    iget-object p0, p0, Lnc0/d;->f:Lyy0/i;

    .line 12
    .line 13
    invoke-direct {p1, p0, v0, p2, v1}, Lnc0/d;-><init>(Lyy0/i;Lay0/k;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Lnc0/d;

    .line 18
    .line 19
    iget-object v0, p0, Lnc0/d;->g:Lay0/k;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    iget-object p0, p0, Lnc0/d;->f:Lyy0/i;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, p2, v1}, Lnc0/d;-><init>(Lyy0/i;Lay0/k;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lnc0/d;->d:I

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
    invoke-virtual {p0, p1, p2}, Lnc0/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lnc0/d;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lnc0/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lnc0/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lnc0/d;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lnc0/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 5

    .line 1
    iget v0, p0, Lnc0/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lnc0/d;->e:I

    .line 9
    .line 10
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    const/4 v3, 0x1

    .line 13
    if-eqz v1, :cond_2

    .line 14
    .line 15
    if-ne v1, v3, :cond_1

    .line 16
    .line 17
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    :cond_0
    move-object v0, v2

    .line 21
    goto :goto_1

    .line 22
    :cond_1
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
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    new-instance p1, Li40/b0;

    .line 34
    .line 35
    iget-object v1, p0, Lnc0/d;->g:Lay0/k;

    .line 36
    .line 37
    const/4 v4, 0x5

    .line 38
    invoke-direct {p1, v4, v1}, Li40/b0;-><init>(ILay0/k;)V

    .line 39
    .line 40
    .line 41
    iput v3, p0, Lnc0/d;->e:I

    .line 42
    .line 43
    new-instance v1, Lpt0/i;

    .line 44
    .line 45
    const/16 v3, 0x1d

    .line 46
    .line 47
    invoke-direct {v1, p1, v3}, Lpt0/i;-><init>(Lyy0/j;I)V

    .line 48
    .line 49
    .line 50
    iget-object p1, p0, Lnc0/d;->f:Lyy0/i;

    .line 51
    .line 52
    invoke-interface {p1, v1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    if-ne p0, v0, :cond_3

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_3
    move-object p0, v2

    .line 60
    :goto_0
    if-ne p0, v0, :cond_0

    .line 61
    .line 62
    :goto_1
    return-object v0

    .line 63
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 64
    .line 65
    iget v1, p0, Lnc0/d;->e:I

    .line 66
    .line 67
    const/4 v2, 0x1

    .line 68
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    if-eqz v1, :cond_6

    .line 71
    .line 72
    if-ne v1, v2, :cond_5

    .line 73
    .line 74
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    :cond_4
    move-object v0, v3

    .line 78
    goto :goto_4

    .line 79
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 80
    .line 81
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 82
    .line 83
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    throw p0

    .line 87
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    new-instance p1, Li40/b0;

    .line 91
    .line 92
    iget-object v1, p0, Lnc0/d;->g:Lay0/k;

    .line 93
    .line 94
    const/4 v4, 0x3

    .line 95
    invoke-direct {p1, v4, v1}, Li40/b0;-><init>(ILay0/k;)V

    .line 96
    .line 97
    .line 98
    iput v2, p0, Lnc0/d;->e:I

    .line 99
    .line 100
    new-instance v1, Lwk0/o0;

    .line 101
    .line 102
    const/16 v2, 0x11

    .line 103
    .line 104
    invoke-direct {v1, p1, v2}, Lwk0/o0;-><init>(Lyy0/j;I)V

    .line 105
    .line 106
    .line 107
    new-instance p1, Ln50/a1;

    .line 108
    .line 109
    const/4 v2, 0x2

    .line 110
    invoke-direct {p1, v1, v2}, Ln50/a1;-><init>(Lyy0/j;I)V

    .line 111
    .line 112
    .line 113
    iget-object v1, p0, Lnc0/d;->f:Lyy0/i;

    .line 114
    .line 115
    invoke-interface {v1, p1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    if-ne p0, v0, :cond_7

    .line 120
    .line 121
    goto :goto_2

    .line 122
    :cond_7
    move-object p0, v3

    .line 123
    :goto_2
    if-ne p0, v0, :cond_8

    .line 124
    .line 125
    goto :goto_3

    .line 126
    :cond_8
    move-object p0, v3

    .line 127
    :goto_3
    if-ne p0, v0, :cond_4

    .line 128
    .line 129
    :goto_4
    return-object v0

    .line 130
    nop

    .line 131
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
