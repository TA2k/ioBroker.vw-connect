.class public final Lpp0/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lpp0/c0;

.field public final b:Lal0/u;


# direct methods
.method public constructor <init>(Lpp0/c0;Lal0/u;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lpp0/q;->a:Lpp0/c0;

    .line 5
    .line 6
    iput-object p2, p0, Lpp0/q;->b:Lal0/u;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lpp0/q;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 11

    .line 1
    instance-of v0, p1, Lpp0/o;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lpp0/o;

    .line 7
    .line 8
    iget v1, v0, Lpp0/o;->i:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lpp0/o;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lpp0/o;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lpp0/o;-><init>(Lpp0/q;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lpp0/o;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lpp0/o;->i:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    if-eq v2, v4, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    iget v2, v0, Lpp0/o;->f:I

    .line 40
    .line 41
    iget v5, v0, Lpp0/o;->e:I

    .line 42
    .line 43
    iget-object v6, v0, Lpp0/o;->d:Ljava/util/Iterator;

    .line 44
    .line 45
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    goto :goto_3

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    iget-object p1, p0, Lpp0/q;->a:Lpp0/c0;

    .line 65
    .line 66
    check-cast p1, Lnp0/b;

    .line 67
    .line 68
    iget-object p1, p1, Lnp0/b;->i:Lyy0/l1;

    .line 69
    .line 70
    iput v4, v0, Lpp0/o;->i:I

    .line 71
    .line 72
    invoke-static {p1, v0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    if-ne p1, v1, :cond_4

    .line 77
    .line 78
    goto :goto_4

    .line 79
    :cond_4
    :goto_1
    check-cast p1, Lqp0/g;

    .line 80
    .line 81
    if-eqz p1, :cond_8

    .line 82
    .line 83
    iget-object p1, p1, Lqp0/g;->a:Ljava/util/List;

    .line 84
    .line 85
    check-cast p1, Ljava/lang/Iterable;

    .line 86
    .line 87
    new-instance v2, Ljava/util/ArrayList;

    .line 88
    .line 89
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 90
    .line 91
    .line 92
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 93
    .line 94
    .line 95
    move-result-object p1

    .line 96
    :cond_5
    :goto_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 97
    .line 98
    .line 99
    move-result v5

    .line 100
    if-eqz v5, :cond_6

    .line 101
    .line 102
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v5

    .line 106
    move-object v6, v5

    .line 107
    check-cast v6, Llx0/l;

    .line 108
    .line 109
    iget-object v6, v6, Llx0/l;->e:Ljava/lang/Object;

    .line 110
    .line 111
    check-cast v6, Lqp0/b0;

    .line 112
    .line 113
    iget-object v6, v6, Lqp0/b0;->a:Ljava/lang/String;

    .line 114
    .line 115
    if-nez v6, :cond_5

    .line 116
    .line 117
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 118
    .line 119
    .line 120
    goto :goto_2

    .line 121
    :cond_6
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 122
    .line 123
    .line 124
    move-result-object p1

    .line 125
    const/4 v2, 0x0

    .line 126
    move-object v6, p1

    .line 127
    move v5, v2

    .line 128
    :cond_7
    :goto_3
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 129
    .line 130
    .line 131
    move-result p1

    .line 132
    if-eqz p1, :cond_8

    .line 133
    .line 134
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object p1

    .line 138
    check-cast p1, Llx0/l;

    .line 139
    .line 140
    iget-object v7, p1, Llx0/l;->d:Ljava/lang/Object;

    .line 141
    .line 142
    check-cast v7, Ljava/lang/Number;

    .line 143
    .line 144
    invoke-virtual {v7}, Ljava/lang/Number;->intValue()I

    .line 145
    .line 146
    .line 147
    move-result v7

    .line 148
    iget-object p1, p1, Llx0/l;->e:Ljava/lang/Object;

    .line 149
    .line 150
    check-cast p1, Lqp0/b0;

    .line 151
    .line 152
    iget-object v8, p1, Lqp0/b0;->d:Lxj0/f;

    .line 153
    .line 154
    if-eqz v8, :cond_7

    .line 155
    .line 156
    new-instance v9, Lal0/s;

    .line 157
    .line 158
    const/4 v10, 0x0

    .line 159
    invoke-direct {v9, v8, v10, v4}, Lal0/s;-><init>(Lxj0/f;Ljava/util/List;Z)V

    .line 160
    .line 161
    .line 162
    iget-object v8, p0, Lpp0/q;->b:Lal0/u;

    .line 163
    .line 164
    invoke-virtual {v8, v9}, Lal0/u;->a(Lal0/s;)Lzy0/j;

    .line 165
    .line 166
    .line 167
    move-result-object v8

    .line 168
    new-instance v9, Lpp0/p;

    .line 169
    .line 170
    invoke-direct {v9, p1, p0, v7}, Lpp0/p;-><init>(Lqp0/b0;Lpp0/q;I)V

    .line 171
    .line 172
    .line 173
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 174
    .line 175
    .line 176
    iput-object v6, v0, Lpp0/o;->d:Ljava/util/Iterator;

    .line 177
    .line 178
    iput v5, v0, Lpp0/o;->e:I

    .line 179
    .line 180
    iput v2, v0, Lpp0/o;->f:I

    .line 181
    .line 182
    iput v3, v0, Lpp0/o;->i:I

    .line 183
    .line 184
    invoke-virtual {v8, v9, v0}, Lzy0/f;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    move-result-object p1

    .line 188
    if-ne p1, v1, :cond_7

    .line 189
    .line 190
    :goto_4
    return-object v1

    .line 191
    :cond_8
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 192
    .line 193
    return-object p0
.end method
