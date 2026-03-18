.class public final Lg1/n2;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public synthetic e:J

.field public synthetic f:Ljava/lang/Object;


# direct methods
.method public constructor <init>(JLkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lg1/n2;->d:I

    .line 1
    iput-wide p1, p0, Lg1/n2;->e:J

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Ll2/b1;JLkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lg1/n2;->d:I

    .line 2
    iput-object p1, p0, Lg1/n2;->f:Ljava/lang/Object;

    iput-wide p2, p0, Lg1/n2;->e:J

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lq31/h;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lg1/n2;->d:I

    .line 3
    iput-object p1, p0, Lg1/n2;->f:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    iget v0, p0, Lg1/n2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lg1/n2;

    .line 7
    .line 8
    iget-object v0, p0, Lg1/n2;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Ll2/b1;

    .line 11
    .line 12
    iget-wide v1, p0, Lg1/n2;->e:J

    .line 13
    .line 14
    invoke-direct {p1, v0, v1, v2, p2}, Lg1/n2;-><init>(Ll2/b1;JLkotlin/coroutines/Continuation;)V

    .line 15
    .line 16
    .line 17
    return-object p1

    .line 18
    :pswitch_0
    new-instance v0, Lg1/n2;

    .line 19
    .line 20
    iget-object p0, p0, Lg1/n2;->f:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast p0, Lq31/h;

    .line 23
    .line 24
    invoke-direct {v0, p0, p2}, Lg1/n2;-><init>(Lq31/h;Lkotlin/coroutines/Continuation;)V

    .line 25
    .line 26
    .line 27
    check-cast p1, Ljava/lang/Number;

    .line 28
    .line 29
    invoke-virtual {p1}, Ljava/lang/Number;->longValue()J

    .line 30
    .line 31
    .line 32
    move-result-wide p0

    .line 33
    iput-wide p0, v0, Lg1/n2;->e:J

    .line 34
    .line 35
    return-object v0

    .line 36
    :pswitch_1
    new-instance v0, Lg1/n2;

    .line 37
    .line 38
    iget-wide v1, p0, Lg1/n2;->e:J

    .line 39
    .line 40
    invoke-direct {v0, v1, v2, p2}, Lg1/n2;-><init>(JLkotlin/coroutines/Continuation;)V

    .line 41
    .line 42
    .line 43
    iput-object p1, v0, Lg1/n2;->f:Ljava/lang/Object;

    .line 44
    .line 45
    return-object v0

    .line 46
    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lg1/n2;->d:I

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
    invoke-virtual {p0, p1, p2}, Lg1/n2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lg1/n2;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lg1/n2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-object p1

    .line 22
    :pswitch_0
    check-cast p1, Ljava/lang/Number;

    .line 23
    .line 24
    invoke-virtual {p1}, Ljava/lang/Number;->longValue()J

    .line 25
    .line 26
    .line 27
    move-result-wide v0

    .line 28
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 29
    .line 30
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    invoke-virtual {p0, p1, p2}, Lg1/n2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    check-cast p0, Lg1/n2;

    .line 39
    .line 40
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    invoke-virtual {p0, p1}, Lg1/n2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    return-object p1

    .line 46
    :pswitch_1
    check-cast p1, Lg1/t2;

    .line 47
    .line 48
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 49
    .line 50
    invoke-virtual {p0, p1, p2}, Lg1/n2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    check-cast p0, Lg1/n2;

    .line 55
    .line 56
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 57
    .line 58
    invoke-virtual {p0, p1}, Lg1/n2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    return-object p1

    .line 62
    nop

    .line 63
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Lg1/n2;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 9
    .line 10
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    iget-object p1, p0, Lg1/n2;->f:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p1, Ll2/b1;

    .line 16
    .line 17
    iget-wide v2, p0, Lg1/n2;->e:J

    .line 18
    .line 19
    new-instance p0, Le3/s;

    .line 20
    .line 21
    invoke-direct {p0, v2, v3}, Le3/s;-><init>(J)V

    .line 22
    .line 23
    .line 24
    invoke-interface {p1, p0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    return-object v1

    .line 28
    :pswitch_0
    iget-wide v2, p0, Lg1/n2;->e:J

    .line 29
    .line 30
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 31
    .line 32
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    iget-object p0, p0, Lg1/n2;->f:Ljava/lang/Object;

    .line 36
    .line 37
    move-object v0, p0

    .line 38
    check-cast v0, Lq31/h;

    .line 39
    .line 40
    iget-object v4, v0, Lq41/b;->d:Lyy0/c2;

    .line 41
    .line 42
    :cond_0
    invoke-virtual {v4}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    move-object p1, p0

    .line 47
    check-cast p1, Lq31/i;

    .line 48
    .line 49
    const/16 v5, 0x1e

    .line 50
    .line 51
    const/4 v6, 0x0

    .line 52
    invoke-static {p1, v2, v3, v6, v5}, Lq31/i;->a(Lq31/i;JLjava/util/ArrayList;I)Lq31/i;

    .line 53
    .line 54
    .line 55
    move-result-object p1

    .line 56
    invoke-virtual {v4, p0, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result p0

    .line 60
    if-eqz p0, :cond_0

    .line 61
    .line 62
    invoke-static {}, Ljava/util/Calendar;->getInstance()Ljava/util/Calendar;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    invoke-virtual {p0, v2, v3}, Ljava/util/Calendar;->setTimeInMillis(J)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {v0}, Lq41/b;->a()Lq41/a;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    check-cast p1, Lq31/i;

    .line 74
    .line 75
    iget-object p1, p1, Lq31/i;->e:Ljava/util/List;

    .line 76
    .line 77
    check-cast p1, Ljava/lang/Iterable;

    .line 78
    .line 79
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    :cond_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 84
    .line 85
    .line 86
    move-result v2

    .line 87
    if-eqz v2, :cond_3

    .line 88
    .line 89
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v2

    .line 93
    move-object v3, v2

    .line 94
    check-cast v3, Lp31/g;

    .line 95
    .line 96
    iget-object v3, v3, Lp31/g;->a:Ljava/lang/Object;

    .line 97
    .line 98
    instance-of v4, v3, Lp31/a;

    .line 99
    .line 100
    if-eqz v4, :cond_2

    .line 101
    .line 102
    check-cast v3, Lp31/a;

    .line 103
    .line 104
    goto :goto_0

    .line 105
    :cond_2
    move-object v3, v6

    .line 106
    :goto_0
    if-eqz v3, :cond_1

    .line 107
    .line 108
    iget v4, v3, Lp31/a;->a:I

    .line 109
    .line 110
    const/16 v5, 0xb

    .line 111
    .line 112
    invoke-virtual {p0, v5}, Ljava/util/Calendar;->get(I)I

    .line 113
    .line 114
    .line 115
    move-result v5

    .line 116
    if-ne v4, v5, :cond_1

    .line 117
    .line 118
    iget v3, v3, Lp31/a;->b:I

    .line 119
    .line 120
    const/16 v4, 0xc

    .line 121
    .line 122
    invoke-virtual {p0, v4}, Ljava/util/Calendar;->get(I)I

    .line 123
    .line 124
    .line 125
    move-result v4

    .line 126
    if-ne v3, v4, :cond_1

    .line 127
    .line 128
    move-object v6, v2

    .line 129
    :cond_3
    check-cast v6, Lp31/g;

    .line 130
    .line 131
    if-eqz v6, :cond_4

    .line 132
    .line 133
    invoke-virtual {v0, v6}, Lq31/h;->f(Lp31/g;)V

    .line 134
    .line 135
    .line 136
    :cond_4
    return-object v1

    .line 137
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 138
    .line 139
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 140
    .line 141
    .line 142
    iget-object p1, p0, Lg1/n2;->f:Ljava/lang/Object;

    .line 143
    .line 144
    check-cast p1, Lg1/t2;

    .line 145
    .line 146
    iget-wide v2, p0, Lg1/n2;->e:J

    .line 147
    .line 148
    iget-object p0, p1, Lg1/t2;->a:Lg1/u2;

    .line 149
    .line 150
    iget-object p1, p0, Lg1/u2;->k:Lg1/e2;

    .line 151
    .line 152
    const/4 v0, 0x1

    .line 153
    invoke-virtual {p0, p1, v2, v3, v0}, Lg1/u2;->c(Lg1/e2;JI)J

    .line 154
    .line 155
    .line 156
    return-object v1

    .line 157
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
