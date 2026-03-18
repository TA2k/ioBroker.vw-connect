.class public final Lhu/s0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lhu/w0;


# direct methods
.method public synthetic constructor <init>(Lhu/w0;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lhu/s0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lhu/s0;->f:Lhu/w0;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1

    .line 1
    iget p1, p0, Lhu/s0;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lhu/s0;

    .line 7
    .line 8
    iget-object p0, p0, Lhu/s0;->f:Lhu/w0;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lhu/s0;-><init>(Lhu/w0;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lhu/s0;

    .line 16
    .line 17
    iget-object p0, p0, Lhu/s0;->f:Lhu/w0;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lhu/s0;-><init>(Lhu/w0;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lhu/s0;->d:I

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
    invoke-virtual {p0, p1, p2}, Lhu/s0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lhu/s0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lhu/s0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lhu/s0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lhu/s0;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lhu/s0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 6

    .line 1
    iget v0, p0, Lhu/s0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lhu/s0;->e:I

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    const/4 v3, 0x1

    .line 12
    iget-object v4, p0, Lhu/s0;->f:Lhu/w0;

    .line 13
    .line 14
    if-eqz v1, :cond_1

    .line 15
    .line 16
    if-ne v1, v3, :cond_0

    .line 17
    .line 18
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 19
    .line 20
    .line 21
    goto :goto_1

    .line 22
    :catch_0
    move-exception p0

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 25
    .line 26
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 27
    .line 28
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw p0

    .line 32
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    :try_start_1
    iget-object p1, v4, Lhu/w0;->e:Lm6/g;

    .line 36
    .line 37
    new-instance v1, Lhu/u0;

    .line 38
    .line 39
    const/4 v5, 0x0

    .line 40
    invoke-direct {v1, v4, v2, v5}, Lhu/u0;-><init>(Lhu/w0;Lkotlin/coroutines/Continuation;I)V

    .line 41
    .line 42
    .line 43
    iput v3, p0, Lhu/s0;->e:I

    .line 44
    .line 45
    invoke-interface {p1, v1, p0}, Lm6/g;->a(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object p0
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 49
    if-ne p0, v0, :cond_2

    .line 50
    .line 51
    goto :goto_2

    .line 52
    :goto_0
    new-instance p1, Ljava/lang/StringBuilder;

    .line 53
    .line 54
    const-string v0, "App backgrounded, failed to update data. Message: "

    .line 55
    .line 56
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    const-string p1, "FirebaseSessions"

    .line 71
    .line 72
    invoke-static {p1, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 73
    .line 74
    .line 75
    iget-object p0, v4, Lhu/w0;->h:Lhu/e0;

    .line 76
    .line 77
    if-eqz p0, :cond_3

    .line 78
    .line 79
    iget-object p1, v4, Lhu/w0;->d:Lhu/a1;

    .line 80
    .line 81
    invoke-virtual {p1}, Lhu/a1;->a()Lhu/z0;

    .line 82
    .line 83
    .line 84
    move-result-object p1

    .line 85
    const/4 v0, 0x5

    .line 86
    invoke-static {p0, v2, p1, v2, v0}, Lhu/e0;->a(Lhu/e0;Lhu/j0;Lhu/z0;Ljava/util/Map;I)Lhu/e0;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    iput-object p0, v4, Lhu/w0;->h:Lhu/e0;

    .line 91
    .line 92
    :cond_2
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 93
    .line 94
    :goto_2
    return-object v0

    .line 95
    :cond_3
    const-string p0, "localSessionData"

    .line 96
    .line 97
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    throw v2

    .line 101
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 102
    .line 103
    iget v1, p0, Lhu/s0;->e:I

    .line 104
    .line 105
    const/4 v2, 0x1

    .line 106
    if-eqz v1, :cond_5

    .line 107
    .line 108
    if-ne v1, v2, :cond_4

    .line 109
    .line 110
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    goto :goto_3

    .line 114
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 115
    .line 116
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 117
    .line 118
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    throw p0

    .line 122
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 123
    .line 124
    .line 125
    iget-object p1, p0, Lhu/s0;->f:Lhu/w0;

    .line 126
    .line 127
    iget-object v1, p1, Lhu/w0;->e:Lm6/g;

    .line 128
    .line 129
    invoke-interface {v1}, Lm6/g;->getData()Lyy0/i;

    .line 130
    .line 131
    .line 132
    move-result-object v1

    .line 133
    new-instance v3, Lgb0/z;

    .line 134
    .line 135
    const/4 v4, 0x0

    .line 136
    const/4 v5, 0x5

    .line 137
    invoke-direct {v3, p1, v4, v5}, Lgb0/z;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 138
    .line 139
    .line 140
    new-instance v4, Lne0/n;

    .line 141
    .line 142
    invoke-direct {v4, v1, v3}, Lne0/n;-><init>(Lyy0/i;Lay0/o;)V

    .line 143
    .line 144
    .line 145
    new-instance v1, Lgt0/c;

    .line 146
    .line 147
    const/16 v3, 0xd

    .line 148
    .line 149
    invoke-direct {v1, p1, v3}, Lgt0/c;-><init>(Ljava/lang/Object;I)V

    .line 150
    .line 151
    .line 152
    iput v2, p0, Lhu/s0;->e:I

    .line 153
    .line 154
    invoke-virtual {v4, v1, p0}, Lne0/n;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object p0

    .line 158
    if-ne p0, v0, :cond_6

    .line 159
    .line 160
    goto :goto_4

    .line 161
    :cond_6
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 162
    .line 163
    :goto_4
    return-object v0

    .line 164
    nop

    .line 165
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
