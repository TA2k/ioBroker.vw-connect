.class public final Lcp0/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/i;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lrz/k;


# direct methods
.method public synthetic constructor <init>(Lrz/k;I)V
    .locals 0

    .line 1
    iput p2, p0, Lcp0/j;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lcp0/j;->e:Lrz/k;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lcp0/j;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lsa0/n;

    .line 7
    .line 8
    const/16 v1, 0x11

    .line 9
    .line 10
    invoke-direct {v0, p1, v1}, Lsa0/n;-><init>(Lyy0/j;I)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lcp0/j;->e:Lrz/k;

    .line 14
    .line 15
    invoke-virtual {p0, v0, p2}, Lrz/k;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 20
    .line 21
    if-ne p0, p1, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 25
    .line 26
    :goto_0
    return-object p0

    .line 27
    :pswitch_0
    new-instance v0, Lpt0/i;

    .line 28
    .line 29
    const/16 v1, 0x16

    .line 30
    .line 31
    invoke-direct {v0, p1, v1}, Lpt0/i;-><init>(Lyy0/j;I)V

    .line 32
    .line 33
    .line 34
    iget-object p0, p0, Lcp0/j;->e:Lrz/k;

    .line 35
    .line 36
    invoke-virtual {p0, v0, p2}, Lrz/k;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 41
    .line 42
    if-ne p0, p1, :cond_1

    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 46
    .line 47
    :goto_1
    return-object p0

    .line 48
    :pswitch_1
    new-instance v0, Lpt0/i;

    .line 49
    .line 50
    const/4 v1, 0x0

    .line 51
    invoke-direct {v0, p1, v1}, Lpt0/i;-><init>(Lyy0/j;I)V

    .line 52
    .line 53
    .line 54
    iget-object p0, p0, Lcp0/j;->e:Lrz/k;

    .line 55
    .line 56
    invoke-virtual {p0, v0, p2}, Lrz/k;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 61
    .line 62
    if-ne p0, p1, :cond_2

    .line 63
    .line 64
    goto :goto_2

    .line 65
    :cond_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 66
    .line 67
    :goto_2
    return-object p0

    .line 68
    :pswitch_2
    new-instance v0, Ln50/a1;

    .line 69
    .line 70
    const/16 v1, 0x10

    .line 71
    .line 72
    invoke-direct {v0, p1, v1}, Ln50/a1;-><init>(Lyy0/j;I)V

    .line 73
    .line 74
    .line 75
    iget-object p0, p0, Lcp0/j;->e:Lrz/k;

    .line 76
    .line 77
    invoke-virtual {p0, v0, p2}, Lrz/k;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 82
    .line 83
    if-ne p0, p1, :cond_3

    .line 84
    .line 85
    goto :goto_3

    .line 86
    :cond_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 87
    .line 88
    :goto_3
    return-object p0

    .line 89
    :pswitch_3
    new-instance v0, Lhg/u;

    .line 90
    .line 91
    const/16 v1, 0x19

    .line 92
    .line 93
    invoke-direct {v0, p1, v1}, Lhg/u;-><init>(Lyy0/j;I)V

    .line 94
    .line 95
    .line 96
    iget-object p0, p0, Lcp0/j;->e:Lrz/k;

    .line 97
    .line 98
    invoke-virtual {p0, v0, p2}, Lrz/k;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 103
    .line 104
    if-ne p0, p1, :cond_4

    .line 105
    .line 106
    goto :goto_4

    .line 107
    :cond_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 108
    .line 109
    :goto_4
    return-object p0

    .line 110
    :pswitch_4
    new-instance v0, Lhg/u;

    .line 111
    .line 112
    const/16 v1, 0x16

    .line 113
    .line 114
    invoke-direct {v0, p1, v1}, Lhg/u;-><init>(Lyy0/j;I)V

    .line 115
    .line 116
    .line 117
    iget-object p0, p0, Lcp0/j;->e:Lrz/k;

    .line 118
    .line 119
    invoke-virtual {p0, v0, p2}, Lrz/k;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 124
    .line 125
    if-ne p0, p1, :cond_5

    .line 126
    .line 127
    goto :goto_5

    .line 128
    :cond_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 129
    .line 130
    :goto_5
    return-object p0

    .line 131
    :pswitch_5
    new-instance v0, Lhg/u;

    .line 132
    .line 133
    const/16 v1, 0x14

    .line 134
    .line 135
    invoke-direct {v0, p1, v1}, Lhg/u;-><init>(Lyy0/j;I)V

    .line 136
    .line 137
    .line 138
    iget-object p0, p0, Lcp0/j;->e:Lrz/k;

    .line 139
    .line 140
    invoke-virtual {p0, v0, p2}, Lrz/k;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object p0

    .line 144
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 145
    .line 146
    if-ne p0, p1, :cond_6

    .line 147
    .line 148
    goto :goto_6

    .line 149
    :cond_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 150
    .line 151
    :goto_6
    return-object p0

    .line 152
    :pswitch_6
    new-instance v0, Lhg/u;

    .line 153
    .line 154
    const/16 v1, 0xd

    .line 155
    .line 156
    invoke-direct {v0, p1, v1}, Lhg/u;-><init>(Lyy0/j;I)V

    .line 157
    .line 158
    .line 159
    iget-object p0, p0, Lcp0/j;->e:Lrz/k;

    .line 160
    .line 161
    invoke-virtual {p0, v0, p2}, Lrz/k;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    move-result-object p0

    .line 165
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 166
    .line 167
    if-ne p0, p1, :cond_7

    .line 168
    .line 169
    goto :goto_7

    .line 170
    :cond_7
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 171
    .line 172
    :goto_7
    return-object p0

    .line 173
    :pswitch_7
    new-instance v0, La50/g;

    .line 174
    .line 175
    const/16 v1, 0x1b

    .line 176
    .line 177
    invoke-direct {v0, p1, v1}, La50/g;-><init>(Lyy0/j;I)V

    .line 178
    .line 179
    .line 180
    iget-object p0, p0, Lcp0/j;->e:Lrz/k;

    .line 181
    .line 182
    invoke-virtual {p0, v0, p2}, Lrz/k;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object p0

    .line 186
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 187
    .line 188
    if-ne p0, p1, :cond_8

    .line 189
    .line 190
    goto :goto_8

    .line 191
    :cond_8
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 192
    .line 193
    :goto_8
    return-object p0

    .line 194
    nop

    .line 195
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
