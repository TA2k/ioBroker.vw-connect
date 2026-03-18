.class public final Lh90/b;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lxf0/d2;

.field public final synthetic g:Lay0/k;

.field public final synthetic h:I


# direct methods
.method public synthetic constructor <init>(Lxf0/d2;Lay0/k;ILkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p5, p0, Lh90/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh90/b;->f:Lxf0/d2;

    .line 4
    .line 5
    iput-object p2, p0, Lh90/b;->g:Lay0/k;

    .line 6
    .line 7
    iput p3, p0, Lh90/b;->h:I

    .line 8
    .line 9
    const/4 p1, 0x2

    .line 10
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 7

    .line 1
    iget p1, p0, Lh90/b;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lh90/b;

    .line 7
    .line 8
    iget v3, p0, Lh90/b;->h:I

    .line 9
    .line 10
    const/4 v5, 0x2

    .line 11
    iget-object v1, p0, Lh90/b;->f:Lxf0/d2;

    .line 12
    .line 13
    iget-object v2, p0, Lh90/b;->g:Lay0/k;

    .line 14
    .line 15
    move-object v4, p2

    .line 16
    invoke-direct/range {v0 .. v5}, Lh90/b;-><init>(Lxf0/d2;Lay0/k;ILkotlin/coroutines/Continuation;I)V

    .line 17
    .line 18
    .line 19
    return-object v0

    .line 20
    :pswitch_0
    move-object v5, p2

    .line 21
    new-instance v1, Lh90/b;

    .line 22
    .line 23
    iget v4, p0, Lh90/b;->h:I

    .line 24
    .line 25
    const/4 v6, 0x1

    .line 26
    iget-object v2, p0, Lh90/b;->f:Lxf0/d2;

    .line 27
    .line 28
    iget-object v3, p0, Lh90/b;->g:Lay0/k;

    .line 29
    .line 30
    invoke-direct/range {v1 .. v6}, Lh90/b;-><init>(Lxf0/d2;Lay0/k;ILkotlin/coroutines/Continuation;I)V

    .line 31
    .line 32
    .line 33
    return-object v1

    .line 34
    :pswitch_1
    move-object v5, p2

    .line 35
    new-instance v1, Lh90/b;

    .line 36
    .line 37
    iget v4, p0, Lh90/b;->h:I

    .line 38
    .line 39
    const/4 v6, 0x0

    .line 40
    iget-object v2, p0, Lh90/b;->f:Lxf0/d2;

    .line 41
    .line 42
    iget-object v3, p0, Lh90/b;->g:Lay0/k;

    .line 43
    .line 44
    invoke-direct/range {v1 .. v6}, Lh90/b;-><init>(Lxf0/d2;Lay0/k;ILkotlin/coroutines/Continuation;I)V

    .line 45
    .line 46
    .line 47
    return-object v1

    .line 48
    nop

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lh90/b;->d:I

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
    invoke-virtual {p0, p1, p2}, Lh90/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lh90/b;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lh90/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lh90/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lh90/b;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lh90/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lh90/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lh90/b;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lh90/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Lh90/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lh90/b;->e:I

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
    iput v2, p0, Lh90/b;->e:I

    .line 31
    .line 32
    iget-object p1, p0, Lh90/b;->f:Lxf0/d2;

    .line 33
    .line 34
    invoke-virtual {p1, p0}, Lxf0/d2;->a(Lrx0/i;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    if-ne p1, v0, :cond_2

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_2
    :goto_0
    new-instance p1, Ljava/lang/Integer;

    .line 42
    .line 43
    iget v0, p0, Lh90/b;->h:I

    .line 44
    .line 45
    invoke-direct {p1, v0}, Ljava/lang/Integer;-><init>(I)V

    .line 46
    .line 47
    .line 48
    iget-object p0, p0, Lh90/b;->g:Lay0/k;

    .line 49
    .line 50
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 54
    .line 55
    :goto_1
    return-object v0

    .line 56
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 57
    .line 58
    iget v1, p0, Lh90/b;->e:I

    .line 59
    .line 60
    const/4 v2, 0x1

    .line 61
    if-eqz v1, :cond_4

    .line 62
    .line 63
    if-ne v1, v2, :cond_3

    .line 64
    .line 65
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    goto :goto_2

    .line 69
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 70
    .line 71
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 72
    .line 73
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    throw p0

    .line 77
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    iput v2, p0, Lh90/b;->e:I

    .line 81
    .line 82
    iget-object p1, p0, Lh90/b;->f:Lxf0/d2;

    .line 83
    .line 84
    invoke-virtual {p1, p0}, Lxf0/d2;->a(Lrx0/i;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    if-ne p1, v0, :cond_5

    .line 89
    .line 90
    goto :goto_3

    .line 91
    :cond_5
    :goto_2
    new-instance p1, Ljava/lang/Integer;

    .line 92
    .line 93
    iget v0, p0, Lh90/b;->h:I

    .line 94
    .line 95
    invoke-direct {p1, v0}, Ljava/lang/Integer;-><init>(I)V

    .line 96
    .line 97
    .line 98
    iget-object p0, p0, Lh90/b;->g:Lay0/k;

    .line 99
    .line 100
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 104
    .line 105
    :goto_3
    return-object v0

    .line 106
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 107
    .line 108
    iget v1, p0, Lh90/b;->e:I

    .line 109
    .line 110
    const/4 v2, 0x1

    .line 111
    if-eqz v1, :cond_7

    .line 112
    .line 113
    if-ne v1, v2, :cond_6

    .line 114
    .line 115
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    goto :goto_4

    .line 119
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 120
    .line 121
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 122
    .line 123
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    throw p0

    .line 127
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 128
    .line 129
    .line 130
    iput v2, p0, Lh90/b;->e:I

    .line 131
    .line 132
    iget-object p1, p0, Lh90/b;->f:Lxf0/d2;

    .line 133
    .line 134
    invoke-virtual {p1, p0}, Lxf0/d2;->a(Lrx0/i;)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object p1

    .line 138
    if-ne p1, v0, :cond_8

    .line 139
    .line 140
    goto :goto_5

    .line 141
    :cond_8
    :goto_4
    new-instance p1, Ljava/lang/Integer;

    .line 142
    .line 143
    iget v0, p0, Lh90/b;->h:I

    .line 144
    .line 145
    invoke-direct {p1, v0}, Ljava/lang/Integer;-><init>(I)V

    .line 146
    .line 147
    .line 148
    iget-object p0, p0, Lh90/b;->g:Lay0/k;

    .line 149
    .line 150
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 154
    .line 155
    :goto_5
    return-object v0

    .line 156
    nop

    .line 157
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
