.class public final Lyy0/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lxy0/x;


# direct methods
.method public synthetic constructor <init>(Lxy0/x;I)V
    .locals 0

    .line 1
    iput p2, p0, Lyy0/p;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lyy0/p;->e:Lxy0/x;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lyy0/p;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    instance-of v0, p2, Lyy0/q;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    move-object v0, p2

    .line 11
    check-cast v0, Lyy0/q;

    .line 12
    .line 13
    iget v1, v0, Lyy0/q;->f:I

    .line 14
    .line 15
    const/high16 v2, -0x80000000

    .line 16
    .line 17
    and-int v3, v1, v2

    .line 18
    .line 19
    if-eqz v3, :cond_0

    .line 20
    .line 21
    sub-int/2addr v1, v2

    .line 22
    iput v1, v0, Lyy0/q;->f:I

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance v0, Lyy0/q;

    .line 26
    .line 27
    invoke-direct {v0, p0, p2}, Lyy0/q;-><init>(Lyy0/p;Lkotlin/coroutines/Continuation;)V

    .line 28
    .line 29
    .line 30
    :goto_0
    iget-object p2, v0, Lyy0/q;->d:Ljava/lang/Object;

    .line 31
    .line 32
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 33
    .line 34
    iget v2, v0, Lyy0/q;->f:I

    .line 35
    .line 36
    const/4 v3, 0x1

    .line 37
    if-eqz v2, :cond_2

    .line 38
    .line 39
    if-ne v2, v3, :cond_1

    .line 40
    .line 41
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 46
    .line 47
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 48
    .line 49
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    if-nez p1, :cond_3

    .line 57
    .line 58
    sget-object p1, Lzy0/c;->b:Lj51/i;

    .line 59
    .line 60
    :cond_3
    iput v3, v0, Lyy0/q;->f:I

    .line 61
    .line 62
    iget-object p0, p0, Lyy0/p;->e:Lxy0/x;

    .line 63
    .line 64
    check-cast p0, Lxy0/w;

    .line 65
    .line 66
    iget-object p0, p0, Lxy0/w;->g:Lxy0/j;

    .line 67
    .line 68
    invoke-interface {p0, p1, v0}, Lxy0/a0;->u(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    if-ne p0, v1, :cond_4

    .line 73
    .line 74
    goto :goto_2

    .line 75
    :cond_4
    :goto_1
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 76
    .line 77
    :goto_2
    return-object v1

    .line 78
    :pswitch_0
    instance-of v0, p2, Lyy0/o;

    .line 79
    .line 80
    if-eqz v0, :cond_5

    .line 81
    .line 82
    move-object v0, p2

    .line 83
    check-cast v0, Lyy0/o;

    .line 84
    .line 85
    iget v1, v0, Lyy0/o;->f:I

    .line 86
    .line 87
    const/high16 v2, -0x80000000

    .line 88
    .line 89
    and-int v3, v1, v2

    .line 90
    .line 91
    if-eqz v3, :cond_5

    .line 92
    .line 93
    sub-int/2addr v1, v2

    .line 94
    iput v1, v0, Lyy0/o;->f:I

    .line 95
    .line 96
    goto :goto_3

    .line 97
    :cond_5
    new-instance v0, Lyy0/o;

    .line 98
    .line 99
    invoke-direct {v0, p0, p2}, Lyy0/o;-><init>(Lyy0/p;Lkotlin/coroutines/Continuation;)V

    .line 100
    .line 101
    .line 102
    :goto_3
    iget-object p2, v0, Lyy0/o;->d:Ljava/lang/Object;

    .line 103
    .line 104
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 105
    .line 106
    iget v2, v0, Lyy0/o;->f:I

    .line 107
    .line 108
    const/4 v3, 0x1

    .line 109
    if-eqz v2, :cond_7

    .line 110
    .line 111
    if-ne v2, v3, :cond_6

    .line 112
    .line 113
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    goto :goto_4

    .line 117
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 118
    .line 119
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 120
    .line 121
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    throw p0

    .line 125
    :cond_7
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 126
    .line 127
    .line 128
    if-nez p1, :cond_8

    .line 129
    .line 130
    sget-object p1, Lzy0/c;->b:Lj51/i;

    .line 131
    .line 132
    :cond_8
    iput v3, v0, Lyy0/o;->f:I

    .line 133
    .line 134
    iget-object p0, p0, Lyy0/p;->e:Lxy0/x;

    .line 135
    .line 136
    check-cast p0, Lxy0/w;

    .line 137
    .line 138
    iget-object p0, p0, Lxy0/w;->g:Lxy0/j;

    .line 139
    .line 140
    invoke-interface {p0, p1, v0}, Lxy0/a0;->u(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object p0

    .line 144
    if-ne p0, v1, :cond_9

    .line 145
    .line 146
    goto :goto_5

    .line 147
    :cond_9
    :goto_4
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 148
    .line 149
    :goto_5
    return-object v1

    .line 150
    nop

    .line 151
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
