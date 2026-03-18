.class public final Le1/d;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Li1/n;

.field public final synthetic g:Li1/l;


# direct methods
.method public constructor <init>(Li1/l;Li1/n;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Le1/d;->d:I

    .line 1
    iput-object p1, p0, Le1/d;->g:Li1/l;

    iput-object p2, p0, Le1/d;->f:Li1/n;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public synthetic constructor <init>(Li1/n;Li1/l;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 2
    iput p4, p0, Le1/d;->d:I

    iput-object p1, p0, Le1/d;->f:Li1/n;

    iput-object p2, p0, Le1/d;->g:Li1/l;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget p1, p0, Le1/d;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Le1/d;

    .line 7
    .line 8
    iget-object v0, p0, Le1/d;->g:Li1/l;

    .line 9
    .line 10
    iget-object p0, p0, Le1/d;->f:Li1/n;

    .line 11
    .line 12
    invoke-direct {p1, v0, p0, p2}, Le1/d;-><init>(Li1/l;Li1/n;Lkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    return-object p1

    .line 16
    :pswitch_0
    new-instance p1, Le1/d;

    .line 17
    .line 18
    iget-object v0, p0, Le1/d;->g:Li1/l;

    .line 19
    .line 20
    const/4 v1, 0x1

    .line 21
    iget-object p0, p0, Le1/d;->f:Li1/n;

    .line 22
    .line 23
    invoke-direct {p1, p0, v0, p2, v1}, Le1/d;-><init>(Li1/n;Li1/l;Lkotlin/coroutines/Continuation;I)V

    .line 24
    .line 25
    .line 26
    return-object p1

    .line 27
    :pswitch_1
    new-instance p1, Le1/d;

    .line 28
    .line 29
    iget-object v0, p0, Le1/d;->g:Li1/l;

    .line 30
    .line 31
    const/4 v1, 0x0

    .line 32
    iget-object p0, p0, Le1/d;->f:Li1/n;

    .line 33
    .line 34
    invoke-direct {p1, p0, v0, p2, v1}, Le1/d;-><init>(Li1/n;Li1/l;Lkotlin/coroutines/Continuation;I)V

    .line 35
    .line 36
    .line 37
    return-object p1

    .line 38
    nop

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
    iget v0, p0, Le1/d;->d:I

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
    invoke-virtual {p0, p1, p2}, Le1/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Le1/d;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Le1/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Le1/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Le1/d;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Le1/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Le1/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Le1/d;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Le1/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 3

    .line 1
    iget v0, p0, Le1/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Le1/d;->e:I

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
    iput v2, p0, Le1/d;->e:I

    .line 31
    .line 32
    iget-object p1, p0, Le1/d;->g:Li1/l;

    .line 33
    .line 34
    iget-object v1, p0, Le1/d;->f:Li1/n;

    .line 35
    .line 36
    invoke-virtual {p1, v1, p0}, Li1/l;->a(Li1/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    if-ne p0, v0, :cond_2

    .line 41
    .line 42
    goto :goto_1

    .line 43
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 44
    .line 45
    :goto_1
    return-object v0

    .line 46
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 47
    .line 48
    iget v1, p0, Le1/d;->e:I

    .line 49
    .line 50
    const/4 v2, 0x1

    .line 51
    if-eqz v1, :cond_4

    .line 52
    .line 53
    if-ne v1, v2, :cond_3

    .line 54
    .line 55
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    goto :goto_2

    .line 59
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 60
    .line 61
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 62
    .line 63
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    throw p0

    .line 67
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    new-instance p1, Li1/o;

    .line 71
    .line 72
    iget-object v1, p0, Le1/d;->f:Li1/n;

    .line 73
    .line 74
    invoke-direct {p1, v1}, Li1/o;-><init>(Li1/n;)V

    .line 75
    .line 76
    .line 77
    iput v2, p0, Le1/d;->e:I

    .line 78
    .line 79
    iget-object v1, p0, Le1/d;->g:Li1/l;

    .line 80
    .line 81
    invoke-virtual {v1, p1, p0}, Li1/l;->a(Li1/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    if-ne p0, v0, :cond_5

    .line 86
    .line 87
    goto :goto_3

    .line 88
    :cond_5
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 89
    .line 90
    :goto_3
    return-object v0

    .line 91
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 92
    .line 93
    iget v1, p0, Le1/d;->e:I

    .line 94
    .line 95
    const/4 v2, 0x1

    .line 96
    if-eqz v1, :cond_7

    .line 97
    .line 98
    if-ne v1, v2, :cond_6

    .line 99
    .line 100
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    goto :goto_4

    .line 104
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 105
    .line 106
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 107
    .line 108
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    throw p0

    .line 112
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 113
    .line 114
    .line 115
    new-instance p1, Li1/m;

    .line 116
    .line 117
    iget-object v1, p0, Le1/d;->f:Li1/n;

    .line 118
    .line 119
    invoke-direct {p1, v1}, Li1/m;-><init>(Li1/n;)V

    .line 120
    .line 121
    .line 122
    iput v2, p0, Le1/d;->e:I

    .line 123
    .line 124
    iget-object v1, p0, Le1/d;->g:Li1/l;

    .line 125
    .line 126
    invoke-virtual {v1, p1, p0}, Li1/l;->a(Li1/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    if-ne p0, v0, :cond_8

    .line 131
    .line 132
    goto :goto_5

    .line 133
    :cond_8
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 134
    .line 135
    :goto_5
    return-object v0

    .line 136
    nop

    .line 137
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
