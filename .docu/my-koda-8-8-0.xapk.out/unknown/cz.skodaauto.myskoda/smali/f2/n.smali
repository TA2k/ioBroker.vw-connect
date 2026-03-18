.class public final Lf2/n;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Li1/l;

.field public final synthetic g:Lv2/o;


# direct methods
.method public synthetic constructor <init>(Li1/l;Lv2/o;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lf2/n;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lf2/n;->f:Li1/l;

    .line 4
    .line 5
    iput-object p2, p0, Lf2/n;->g:Lv2/o;

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
    iget p1, p0, Lf2/n;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lf2/n;

    .line 7
    .line 8
    iget-object v0, p0, Lf2/n;->g:Lv2/o;

    .line 9
    .line 10
    const/4 v1, 0x2

    .line 11
    iget-object p0, p0, Lf2/n;->f:Li1/l;

    .line 12
    .line 13
    invoke-direct {p1, p0, v0, p2, v1}, Lf2/n;-><init>(Li1/l;Lv2/o;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Lf2/n;

    .line 18
    .line 19
    iget-object v0, p0, Lf2/n;->g:Lv2/o;

    .line 20
    .line 21
    const/4 v1, 0x1

    .line 22
    iget-object p0, p0, Lf2/n;->f:Li1/l;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, p2, v1}, Lf2/n;-><init>(Li1/l;Lv2/o;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    return-object p1

    .line 28
    :pswitch_1
    new-instance p1, Lf2/n;

    .line 29
    .line 30
    iget-object v0, p0, Lf2/n;->g:Lv2/o;

    .line 31
    .line 32
    const/4 v1, 0x0

    .line 33
    iget-object p0, p0, Lf2/n;->f:Li1/l;

    .line 34
    .line 35
    invoke-direct {p1, p0, v0, p2, v1}, Lf2/n;-><init>(Li1/l;Lv2/o;Lkotlin/coroutines/Continuation;I)V

    .line 36
    .line 37
    .line 38
    return-object p1

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lf2/n;->d:I

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
    invoke-virtual {p0, p1, p2}, Lf2/n;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lf2/n;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lf2/n;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lf2/n;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lf2/n;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lf2/n;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lf2/n;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lf2/n;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lf2/n;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lf2/n;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lf2/n;->e:I

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
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 22
    .line 23
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 24
    .line 25
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw p0

    .line 29
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    iget-object p1, p0, Lf2/n;->f:Li1/l;

    .line 33
    .line 34
    iget-object p1, p1, Li1/l;->a:Lyy0/q1;

    .line 35
    .line 36
    new-instance v1, Lf2/m;

    .line 37
    .line 38
    iget-object v3, p0, Lf2/n;->g:Lv2/o;

    .line 39
    .line 40
    const/4 v4, 0x2

    .line 41
    invoke-direct {v1, v3, v4}, Lf2/m;-><init>(Lv2/o;I)V

    .line 42
    .line 43
    .line 44
    iput v2, p0, Lf2/n;->e:I

    .line 45
    .line 46
    invoke-virtual {p1, v1, p0}, Lyy0/q1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    :goto_0
    return-object v0

    .line 50
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 51
    .line 52
    iget v1, p0, Lf2/n;->e:I

    .line 53
    .line 54
    const/4 v2, 0x1

    .line 55
    if-eqz v1, :cond_3

    .line 56
    .line 57
    if-ne v1, v2, :cond_2

    .line 58
    .line 59
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 66
    .line 67
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 68
    .line 69
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    throw p0

    .line 73
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    iget-object p1, p0, Lf2/n;->f:Li1/l;

    .line 77
    .line 78
    iget-object p1, p1, Li1/l;->a:Lyy0/q1;

    .line 79
    .line 80
    new-instance v1, Lf2/m;

    .line 81
    .line 82
    iget-object v3, p0, Lf2/n;->g:Lv2/o;

    .line 83
    .line 84
    const/4 v4, 0x1

    .line 85
    invoke-direct {v1, v3, v4}, Lf2/m;-><init>(Lv2/o;I)V

    .line 86
    .line 87
    .line 88
    iput v2, p0, Lf2/n;->e:I

    .line 89
    .line 90
    invoke-virtual {p1, v1, p0}, Lyy0/q1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    :goto_1
    return-object v0

    .line 94
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 95
    .line 96
    iget v1, p0, Lf2/n;->e:I

    .line 97
    .line 98
    const/4 v2, 0x1

    .line 99
    if-eqz v1, :cond_5

    .line 100
    .line 101
    if-ne v1, v2, :cond_4

    .line 102
    .line 103
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 104
    .line 105
    .line 106
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 107
    .line 108
    goto :goto_2

    .line 109
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 110
    .line 111
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 112
    .line 113
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    throw p0

    .line 117
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 118
    .line 119
    .line 120
    iget-object p1, p0, Lf2/n;->f:Li1/l;

    .line 121
    .line 122
    iget-object p1, p1, Li1/l;->a:Lyy0/q1;

    .line 123
    .line 124
    new-instance v1, Lf2/m;

    .line 125
    .line 126
    iget-object v3, p0, Lf2/n;->g:Lv2/o;

    .line 127
    .line 128
    const/4 v4, 0x0

    .line 129
    invoke-direct {v1, v3, v4}, Lf2/m;-><init>(Lv2/o;I)V

    .line 130
    .line 131
    .line 132
    iput v2, p0, Lf2/n;->e:I

    .line 133
    .line 134
    invoke-virtual {p1, v1, p0}, Lyy0/q1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    :goto_2
    return-object v0

    .line 138
    nop

    .line 139
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
