.class public final Lm1/q;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:I

.field public final synthetic g:I

.field public synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public constructor <init>(IILkotlin/coroutines/Continuation;Lm1/t;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lm1/q;->d:I

    .line 1
    iput-object p4, p0, Lm1/q;->i:Ljava/lang/Object;

    iput p1, p0, Lm1/q;->f:I

    iput p2, p0, Lm1/q;->g:I

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lv50/d;IILandroid/content/Intent;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lm1/q;->d:I

    .line 2
    iput-object p1, p0, Lm1/q;->h:Ljava/lang/Object;

    iput p2, p0, Lm1/q;->f:I

    iput p3, p0, Lm1/q;->g:I

    iput-object p4, p0, Lm1/q;->i:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 7

    .line 1
    iget v0, p0, Lm1/q;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Lm1/q;

    .line 7
    .line 8
    iget-object p1, p0, Lm1/q;->h:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v2, p1

    .line 11
    check-cast v2, Lv50/d;

    .line 12
    .line 13
    iget-object p1, p0, Lm1/q;->i:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v5, p1

    .line 16
    check-cast v5, Landroid/content/Intent;

    .line 17
    .line 18
    iget v3, p0, Lm1/q;->f:I

    .line 19
    .line 20
    iget v4, p0, Lm1/q;->g:I

    .line 21
    .line 22
    move-object v6, p2

    .line 23
    invoke-direct/range {v1 .. v6}, Lm1/q;-><init>(Lv50/d;IILandroid/content/Intent;Lkotlin/coroutines/Continuation;)V

    .line 24
    .line 25
    .line 26
    return-object v1

    .line 27
    :pswitch_0
    move-object v6, p2

    .line 28
    new-instance p2, Lm1/q;

    .line 29
    .line 30
    iget-object v0, p0, Lm1/q;->i:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast v0, Lm1/t;

    .line 33
    .line 34
    iget v1, p0, Lm1/q;->f:I

    .line 35
    .line 36
    iget p0, p0, Lm1/q;->g:I

    .line 37
    .line 38
    invoke-direct {p2, v1, p0, v6, v0}, Lm1/q;-><init>(IILkotlin/coroutines/Continuation;Lm1/t;)V

    .line 39
    .line 40
    .line 41
    iput-object p1, p2, Lm1/q;->h:Ljava/lang/Object;

    .line 42
    .line 43
    return-object p2

    .line 44
    nop

    .line 45
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lm1/q;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lvy0/b0;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lm1/q;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lm1/q;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lm1/q;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p1, Lg1/e2;

    .line 24
    .line 25
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 26
    .line 27
    invoke-virtual {p0, p1, p2}, Lm1/q;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lm1/q;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lm1/q;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    nop

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lm1/q;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lm1/q;->e:I

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
    sget-object p1, Lge0/b;->b:Lwy0/c;

    .line 31
    .line 32
    new-instance v3, Lh50/r0;

    .line 33
    .line 34
    iget-object v1, p0, Lm1/q;->h:Ljava/lang/Object;

    .line 35
    .line 36
    move-object v4, v1

    .line 37
    check-cast v4, Lv50/d;

    .line 38
    .line 39
    iget-object v1, p0, Lm1/q;->i:Ljava/lang/Object;

    .line 40
    .line 41
    move-object v7, v1

    .line 42
    check-cast v7, Landroid/content/Intent;

    .line 43
    .line 44
    const/4 v8, 0x0

    .line 45
    iget v5, p0, Lm1/q;->f:I

    .line 46
    .line 47
    iget v6, p0, Lm1/q;->g:I

    .line 48
    .line 49
    invoke-direct/range {v3 .. v8}, Lh50/r0;-><init>(Lv50/d;IILandroid/content/Intent;Lkotlin/coroutines/Continuation;)V

    .line 50
    .line 51
    .line 52
    iput v2, p0, Lm1/q;->e:I

    .line 53
    .line 54
    invoke-static {p1, v3, p0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    if-ne p0, v0, :cond_2

    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 62
    .line 63
    :goto_1
    return-object v0

    .line 64
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 65
    .line 66
    iget v1, p0, Lm1/q;->e:I

    .line 67
    .line 68
    const/4 v2, 0x1

    .line 69
    if-eqz v1, :cond_4

    .line 70
    .line 71
    if-ne v1, v2, :cond_3

    .line 72
    .line 73
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    goto :goto_2

    .line 77
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 78
    .line 79
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 80
    .line 81
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    throw p0

    .line 85
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    iget-object p1, p0, Lm1/q;->h:Ljava/lang/Object;

    .line 89
    .line 90
    check-cast p1, Lg1/e2;

    .line 91
    .line 92
    iget-object v1, p0, Lm1/q;->i:Ljava/lang/Object;

    .line 93
    .line 94
    check-cast v1, Lm1/t;

    .line 95
    .line 96
    new-instance v3, Lm1/p;

    .line 97
    .line 98
    const/4 v4, 0x0

    .line 99
    invoke-direct {v3, p1, v1, v4}, Lm1/p;-><init>(Lg1/e2;Lg1/q2;I)V

    .line 100
    .line 101
    .line 102
    iget-object p1, v1, Lm1/t;->f:Ll2/j1;

    .line 103
    .line 104
    invoke-virtual {p1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object p1

    .line 108
    check-cast p1, Lm1/l;

    .line 109
    .line 110
    iget-object v7, p1, Lm1/l;->i:Lt4/c;

    .line 111
    .line 112
    iput v2, p0, Lm1/q;->e:I

    .line 113
    .line 114
    iget v4, p0, Lm1/q;->f:I

    .line 115
    .line 116
    iget v5, p0, Lm1/q;->g:I

    .line 117
    .line 118
    const/16 v6, 0x64

    .line 119
    .line 120
    move-object v8, p0

    .line 121
    invoke-static/range {v3 .. v8}, Lo1/q0;->a(Lm1/p;IIILt4/c;Lrx0/c;)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    if-ne p0, v0, :cond_5

    .line 126
    .line 127
    goto :goto_3

    .line 128
    :cond_5
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 129
    .line 130
    :goto_3
    return-object v0

    .line 131
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
