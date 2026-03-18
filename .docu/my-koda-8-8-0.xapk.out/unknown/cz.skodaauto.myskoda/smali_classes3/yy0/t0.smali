.class public final Lyy0/t0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/n;

.field public final synthetic f:Lkotlin/jvm/internal/f0;


# direct methods
.method public synthetic constructor <init>(Lay0/n;Lkotlin/jvm/internal/f0;I)V
    .locals 0

    .line 1
    iput p3, p0, Lyy0/t0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lyy0/t0;->e:Lay0/n;

    .line 4
    .line 5
    iput-object p2, p0, Lyy0/t0;->f:Lkotlin/jvm/internal/f0;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lyy0/t0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    instance-of v0, p2, Lyy0/w0;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    move-object v0, p2

    .line 11
    check-cast v0, Lyy0/w0;

    .line 12
    .line 13
    iget v1, v0, Lyy0/w0;->f:I

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
    iput v1, v0, Lyy0/w0;->f:I

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance v0, Lyy0/w0;

    .line 26
    .line 27
    invoke-direct {v0, p0, p2}, Lyy0/w0;-><init>(Lyy0/t0;Lkotlin/coroutines/Continuation;)V

    .line 28
    .line 29
    .line 30
    :goto_0
    iget-object p2, v0, Lyy0/w0;->e:Ljava/lang/Object;

    .line 31
    .line 32
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 33
    .line 34
    iget v2, v0, Lyy0/w0;->f:I

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
    iget-object p1, v0, Lyy0/w0;->h:Ljava/lang/Object;

    .line 42
    .line 43
    iget-object p0, v0, Lyy0/w0;->d:Lyy0/t0;

    .line 44
    .line 45
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 52
    .line 53
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iput-object p0, v0, Lyy0/w0;->d:Lyy0/t0;

    .line 61
    .line 62
    iput-object p1, v0, Lyy0/w0;->h:Ljava/lang/Object;

    .line 63
    .line 64
    iput v3, v0, Lyy0/w0;->f:I

    .line 65
    .line 66
    iget-object p2, p0, Lyy0/t0;->e:Lay0/n;

    .line 67
    .line 68
    invoke-interface {p2, p1, v0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object p2

    .line 72
    if-ne p2, v1, :cond_3

    .line 73
    .line 74
    goto :goto_2

    .line 75
    :cond_3
    :goto_1
    check-cast p2, Ljava/lang/Boolean;

    .line 76
    .line 77
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 78
    .line 79
    .line 80
    move-result p2

    .line 81
    if-nez p2, :cond_4

    .line 82
    .line 83
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 84
    .line 85
    :goto_2
    return-object v1

    .line 86
    :cond_4
    iget-object p2, p0, Lyy0/t0;->f:Lkotlin/jvm/internal/f0;

    .line 87
    .line 88
    iput-object p1, p2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 89
    .line 90
    new-instance p1, Lzy0/a;

    .line 91
    .line 92
    invoke-direct {p1, p0}, Lzy0/a;-><init>(Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    throw p1

    .line 96
    :pswitch_0
    instance-of v0, p2, Lyy0/s0;

    .line 97
    .line 98
    if-eqz v0, :cond_5

    .line 99
    .line 100
    move-object v0, p2

    .line 101
    check-cast v0, Lyy0/s0;

    .line 102
    .line 103
    iget v1, v0, Lyy0/s0;->f:I

    .line 104
    .line 105
    const/high16 v2, -0x80000000

    .line 106
    .line 107
    and-int v3, v1, v2

    .line 108
    .line 109
    if-eqz v3, :cond_5

    .line 110
    .line 111
    sub-int/2addr v1, v2

    .line 112
    iput v1, v0, Lyy0/s0;->f:I

    .line 113
    .line 114
    goto :goto_3

    .line 115
    :cond_5
    new-instance v0, Lyy0/s0;

    .line 116
    .line 117
    invoke-direct {v0, p0, p2}, Lyy0/s0;-><init>(Lyy0/t0;Lkotlin/coroutines/Continuation;)V

    .line 118
    .line 119
    .line 120
    :goto_3
    iget-object p2, v0, Lyy0/s0;->e:Ljava/lang/Object;

    .line 121
    .line 122
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 123
    .line 124
    iget v2, v0, Lyy0/s0;->f:I

    .line 125
    .line 126
    const/4 v3, 0x1

    .line 127
    if-eqz v2, :cond_7

    .line 128
    .line 129
    if-ne v2, v3, :cond_6

    .line 130
    .line 131
    iget-object p1, v0, Lyy0/s0;->h:Ljava/lang/Object;

    .line 132
    .line 133
    iget-object p0, v0, Lyy0/s0;->d:Lyy0/t0;

    .line 134
    .line 135
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 136
    .line 137
    .line 138
    goto :goto_4

    .line 139
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 140
    .line 141
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 142
    .line 143
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 144
    .line 145
    .line 146
    throw p0

    .line 147
    :cond_7
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 148
    .line 149
    .line 150
    iput-object p0, v0, Lyy0/s0;->d:Lyy0/t0;

    .line 151
    .line 152
    iput-object p1, v0, Lyy0/s0;->h:Ljava/lang/Object;

    .line 153
    .line 154
    iput v3, v0, Lyy0/s0;->f:I

    .line 155
    .line 156
    iget-object p2, p0, Lyy0/t0;->e:Lay0/n;

    .line 157
    .line 158
    invoke-interface {p2, p1, v0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object p2

    .line 162
    if-ne p2, v1, :cond_8

    .line 163
    .line 164
    goto :goto_5

    .line 165
    :cond_8
    :goto_4
    check-cast p2, Ljava/lang/Boolean;

    .line 166
    .line 167
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 168
    .line 169
    .line 170
    move-result p2

    .line 171
    if-nez p2, :cond_9

    .line 172
    .line 173
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 174
    .line 175
    :goto_5
    return-object v1

    .line 176
    :cond_9
    iget-object p2, p0, Lyy0/t0;->f:Lkotlin/jvm/internal/f0;

    .line 177
    .line 178
    iput-object p1, p2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 179
    .line 180
    new-instance p1, Lzy0/a;

    .line 181
    .line 182
    invoke-direct {p1, p0}, Lzy0/a;-><init>(Ljava/lang/Object;)V

    .line 183
    .line 184
    .line 185
    throw p1

    .line 186
    nop

    .line 187
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
