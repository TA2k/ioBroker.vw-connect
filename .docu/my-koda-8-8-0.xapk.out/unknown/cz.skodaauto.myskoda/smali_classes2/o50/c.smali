.class public final Lo50/c;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lc1/c;

.field public final synthetic g:Ln50/d;


# direct methods
.method public synthetic constructor <init>(Lc1/c;Ln50/d;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lo50/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lo50/c;->f:Lc1/c;

    .line 4
    .line 5
    iput-object p2, p0, Lo50/c;->g:Ln50/d;

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
    iget p1, p0, Lo50/c;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lo50/c;

    .line 7
    .line 8
    iget-object v0, p0, Lo50/c;->g:Ln50/d;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    iget-object p0, p0, Lo50/c;->f:Lc1/c;

    .line 12
    .line 13
    invoke-direct {p1, p0, v0, p2, v1}, Lo50/c;-><init>(Lc1/c;Ln50/d;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Lo50/c;

    .line 18
    .line 19
    iget-object v0, p0, Lo50/c;->g:Ln50/d;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    iget-object p0, p0, Lo50/c;->f:Lc1/c;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, p2, v1}, Lo50/c;-><init>(Lc1/c;Ln50/d;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lo50/c;->d:I

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
    invoke-virtual {p0, p1, p2}, Lo50/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lo50/c;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lo50/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lo50/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lo50/c;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lo50/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 10

    .line 1
    iget v0, p0, Lo50/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lo50/c;->e:I

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
    goto :goto_1

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
    iget-object p1, p0, Lo50/c;->g:Ln50/d;

    .line 31
    .line 32
    iget-boolean p1, p1, Ln50/d;->b:Z

    .line 33
    .line 34
    if-eqz p1, :cond_2

    .line 35
    .line 36
    const/4 p1, 0x0

    .line 37
    goto :goto_0

    .line 38
    :cond_2
    const/high16 p1, 0x3f800000    # 1.0f

    .line 39
    .line 40
    :goto_0
    new-instance v4, Ljava/lang/Float;

    .line 41
    .line 42
    invoke-direct {v4, p1}, Ljava/lang/Float;-><init>(F)V

    .line 43
    .line 44
    .line 45
    sget-object p1, Lo50/e;->c:Lc1/s;

    .line 46
    .line 47
    const/4 v1, 0x2

    .line 48
    const/16 v3, 0x3e8

    .line 49
    .line 50
    const/4 v5, 0x0

    .line 51
    invoke-static {v3, v5, p1, v1}, Lc1/d;->u(IILc1/w;I)Lc1/a2;

    .line 52
    .line 53
    .line 54
    move-result-object v5

    .line 55
    iput v2, p0, Lo50/c;->e:I

    .line 56
    .line 57
    iget-object v3, p0, Lo50/c;->f:Lc1/c;

    .line 58
    .line 59
    const/4 v6, 0x0

    .line 60
    const/4 v7, 0x0

    .line 61
    const/16 v9, 0xc

    .line 62
    .line 63
    move-object v8, p0

    .line 64
    invoke-static/range {v3 .. v9}, Lc1/c;->b(Lc1/c;Ljava/lang/Object;Lc1/j;Ljava/lang/Float;Lay0/k;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    if-ne p0, v0, :cond_3

    .line 69
    .line 70
    goto :goto_2

    .line 71
    :cond_3
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 72
    .line 73
    :goto_2
    return-object v0

    .line 74
    :pswitch_0
    move-object v6, p0

    .line 75
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 76
    .line 77
    iget v0, v6, Lo50/c;->e:I

    .line 78
    .line 79
    const/4 v1, 0x1

    .line 80
    if-eqz v0, :cond_5

    .line 81
    .line 82
    if-ne v0, v1, :cond_4

    .line 83
    .line 84
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    goto :goto_4

    .line 88
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 89
    .line 90
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 91
    .line 92
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    throw p0

    .line 96
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    iget-object p1, v6, Lo50/c;->g:Ln50/d;

    .line 100
    .line 101
    iget-boolean p1, p1, Ln50/d;->b:Z

    .line 102
    .line 103
    if-eqz p1, :cond_6

    .line 104
    .line 105
    sget p1, Lo50/e;->a:F

    .line 106
    .line 107
    goto :goto_3

    .line 108
    :cond_6
    sget p1, Lo50/e;->b:F

    .line 109
    .line 110
    :goto_3
    new-instance v2, Lt4/f;

    .line 111
    .line 112
    invoke-direct {v2, p1}, Lt4/f;-><init>(F)V

    .line 113
    .line 114
    .line 115
    sget-object p1, Lo50/e;->c:Lc1/s;

    .line 116
    .line 117
    const/4 v0, 0x2

    .line 118
    const/16 v3, 0x3e8

    .line 119
    .line 120
    const/4 v4, 0x0

    .line 121
    invoke-static {v3, v4, p1, v0}, Lc1/d;->u(IILc1/w;I)Lc1/a2;

    .line 122
    .line 123
    .line 124
    move-result-object v3

    .line 125
    iput v1, v6, Lo50/c;->e:I

    .line 126
    .line 127
    iget-object v1, v6, Lo50/c;->f:Lc1/c;

    .line 128
    .line 129
    const/4 v4, 0x0

    .line 130
    const/4 v5, 0x0

    .line 131
    const/16 v7, 0xc

    .line 132
    .line 133
    invoke-static/range {v1 .. v7}, Lc1/c;->b(Lc1/c;Ljava/lang/Object;Lc1/j;Ljava/lang/Float;Lay0/k;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object p1

    .line 137
    if-ne p1, p0, :cond_7

    .line 138
    .line 139
    goto :goto_5

    .line 140
    :cond_7
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 141
    .line 142
    :goto_5
    return-object p0

    .line 143
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
