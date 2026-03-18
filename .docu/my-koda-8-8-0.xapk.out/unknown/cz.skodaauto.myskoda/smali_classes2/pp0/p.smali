.class public final Lpp0/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lkotlin/jvm/internal/d0;ILyy0/j;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lpp0/p;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lpp0/p;->f:Ljava/lang/Object;

    iput p2, p0, Lpp0/p;->e:I

    iput-object p3, p0, Lpp0/p;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lqp0/b0;Lpp0/q;I)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lpp0/p;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lpp0/p;->f:Ljava/lang/Object;

    iput-object p2, p0, Lpp0/p;->g:Ljava/lang/Object;

    iput p3, p0, Lpp0/p;->e:I

    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lpp0/p;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    instance-of v0, p2, Lyy0/e0;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    move-object v0, p2

    .line 11
    check-cast v0, Lyy0/e0;

    .line 12
    .line 13
    iget v1, v0, Lyy0/e0;->f:I

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
    iput v1, v0, Lyy0/e0;->f:I

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance v0, Lyy0/e0;

    .line 26
    .line 27
    invoke-direct {v0, p0, p2}, Lyy0/e0;-><init>(Lpp0/p;Lkotlin/coroutines/Continuation;)V

    .line 28
    .line 29
    .line 30
    :goto_0
    iget-object p2, v0, Lyy0/e0;->d:Ljava/lang/Object;

    .line 31
    .line 32
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 33
    .line 34
    iget v2, v0, Lyy0/e0;->f:I

    .line 35
    .line 36
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    const/4 v4, 0x1

    .line 39
    if-eqz v2, :cond_3

    .line 40
    .line 41
    if-ne v2, v4, :cond_2

    .line 42
    .line 43
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    :cond_1
    :goto_1
    move-object v1, v3

    .line 47
    goto :goto_2

    .line 48
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    iget-object p2, p0, Lpp0/p;->f:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast p2, Lkotlin/jvm/internal/d0;

    .line 62
    .line 63
    iget v2, p2, Lkotlin/jvm/internal/d0;->d:I

    .line 64
    .line 65
    iget v5, p0, Lpp0/p;->e:I

    .line 66
    .line 67
    if-lt v2, v5, :cond_4

    .line 68
    .line 69
    iget-object p0, p0, Lpp0/p;->g:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast p0, Lyy0/j;

    .line 72
    .line 73
    iput v4, v0, Lyy0/e0;->f:I

    .line 74
    .line 75
    invoke-interface {p0, p1, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    if-ne p0, v1, :cond_1

    .line 80
    .line 81
    goto :goto_2

    .line 82
    :cond_4
    add-int/2addr v2, v4

    .line 83
    iput v2, p2, Lkotlin/jvm/internal/d0;->d:I

    .line 84
    .line 85
    goto :goto_1

    .line 86
    :goto_2
    return-object v1

    .line 87
    :pswitch_0
    check-cast p1, Lne0/s;

    .line 88
    .line 89
    instance-of p2, p1, Lne0/e;

    .line 90
    .line 91
    if-eqz p2, :cond_a

    .line 92
    .line 93
    check-cast p1, Lne0/e;

    .line 94
    .line 95
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 96
    .line 97
    check-cast p1, Lbl0/n;

    .line 98
    .line 99
    iget-object p2, p0, Lpp0/p;->f:Ljava/lang/Object;

    .line 100
    .line 101
    move-object v0, p2

    .line 102
    check-cast v0, Lqp0/b0;

    .line 103
    .line 104
    iget-object v1, p1, Lbl0/n;->a:Ljava/lang/String;

    .line 105
    .line 106
    iget-object v2, p1, Lbl0/n;->d:Ljava/lang/String;

    .line 107
    .line 108
    const/4 v5, 0x0

    .line 109
    const v6, 0xfffc

    .line 110
    .line 111
    .line 112
    const/4 v3, 0x0

    .line 113
    const/4 v4, 0x0

    .line 114
    invoke-static/range {v0 .. v6}, Lqp0/b0;->a(Lqp0/b0;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;Lqp0/n;I)Lqp0/b0;

    .line 115
    .line 116
    .line 117
    move-result-object p1

    .line 118
    iget-object p2, p0, Lpp0/p;->g:Ljava/lang/Object;

    .line 119
    .line 120
    check-cast p2, Lpp0/q;

    .line 121
    .line 122
    iget-object p2, p2, Lpp0/q;->a:Lpp0/c0;

    .line 123
    .line 124
    check-cast p2, Lnp0/b;

    .line 125
    .line 126
    iget-object p2, p2, Lnp0/b;->h:Lyy0/c2;

    .line 127
    .line 128
    :cond_5
    invoke-virtual {p2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v0

    .line 132
    move-object v1, v0

    .line 133
    check-cast v1, Lqp0/g;

    .line 134
    .line 135
    if-eqz v1, :cond_9

    .line 136
    .line 137
    iget-object v2, v1, Lqp0/g;->a:Ljava/util/List;

    .line 138
    .line 139
    check-cast v2, Ljava/util/Collection;

    .line 140
    .line 141
    invoke-static {v2}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 142
    .line 143
    .line 144
    move-result-object v2

    .line 145
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 146
    .line 147
    .line 148
    move-result-object v3

    .line 149
    const/4 v4, 0x0

    .line 150
    :goto_3
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 151
    .line 152
    .line 153
    move-result v5

    .line 154
    iget v6, p0, Lpp0/p;->e:I

    .line 155
    .line 156
    const/4 v7, -0x1

    .line 157
    if-eqz v5, :cond_7

    .line 158
    .line 159
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    move-result-object v5

    .line 163
    check-cast v5, Llx0/l;

    .line 164
    .line 165
    iget-object v5, v5, Llx0/l;->d:Ljava/lang/Object;

    .line 166
    .line 167
    check-cast v5, Ljava/lang/Number;

    .line 168
    .line 169
    invoke-virtual {v5}, Ljava/lang/Number;->intValue()I

    .line 170
    .line 171
    .line 172
    move-result v5

    .line 173
    if-ne v5, v6, :cond_6

    .line 174
    .line 175
    goto :goto_4

    .line 176
    :cond_6
    add-int/lit8 v4, v4, 0x1

    .line 177
    .line 178
    goto :goto_3

    .line 179
    :cond_7
    move v4, v7

    .line 180
    :goto_4
    if-eq v4, v7, :cond_8

    .line 181
    .line 182
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 183
    .line 184
    .line 185
    move-result-object v3

    .line 186
    new-instance v5, Llx0/l;

    .line 187
    .line 188
    invoke-direct {v5, v3, p1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 189
    .line 190
    .line 191
    invoke-virtual {v2, v4, v5}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    :cond_8
    invoke-static {v2}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 195
    .line 196
    .line 197
    move-result-object v2

    .line 198
    iget-object v3, v1, Lqp0/g;->b:Ljava/lang/Integer;

    .line 199
    .line 200
    iget-boolean v1, v1, Lqp0/g;->c:Z

    .line 201
    .line 202
    new-instance v4, Lqp0/g;

    .line 203
    .line 204
    invoke-direct {v4, v2, v3, v1}, Lqp0/g;-><init>(Ljava/util/List;Ljava/lang/Integer;Z)V

    .line 205
    .line 206
    .line 207
    goto :goto_5

    .line 208
    :cond_9
    const/4 v4, 0x0

    .line 209
    :goto_5
    invoke-virtual {p2, v0, v4}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 210
    .line 211
    .line 212
    move-result v0

    .line 213
    if-eqz v0, :cond_5

    .line 214
    .line 215
    :cond_a
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 216
    .line 217
    return-object p0

    .line 218
    nop

    .line 219
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
