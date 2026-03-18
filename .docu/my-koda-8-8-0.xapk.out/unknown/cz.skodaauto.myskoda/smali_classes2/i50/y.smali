.class public final Li50/y;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public synthetic e:Ljava/lang/Object;

.field public synthetic f:Ljava/lang/Object;

.field public synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lay0/n;Ll2/b1;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Li50/y;->d:I

    .line 1
    iput-object p1, p0, Li50/y;->g:Ljava/lang/Object;

    iput-object p2, p0, Li50/y;->h:Ljava/lang/Object;

    const/4 p1, 0x4

    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 2
    iput p3, p0, Li50/y;->d:I

    iput-object p1, p0, Li50/y;->h:Ljava/lang/Object;

    const/4 p1, 0x4

    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Li50/y;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/util/List;

    .line 7
    .line 8
    check-cast p2, Ljava/util/List;

    .line 9
    .line 10
    check-cast p3, Lxj0/r;

    .line 11
    .line 12
    check-cast p4, Lkotlin/coroutines/Continuation;

    .line 13
    .line 14
    new-instance v0, Li50/y;

    .line 15
    .line 16
    iget-object p0, p0, Li50/y;->h:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Luk0/a0;

    .line 19
    .line 20
    const/4 v1, 0x2

    .line 21
    invoke-direct {v0, p0, p4, v1}, Li50/y;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 22
    .line 23
    .line 24
    check-cast p1, Ljava/util/List;

    .line 25
    .line 26
    iput-object p1, v0, Li50/y;->e:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast p2, Ljava/util/List;

    .line 29
    .line 30
    iput-object p2, v0, Li50/y;->f:Ljava/lang/Object;

    .line 31
    .line 32
    iput-object p3, v0, Li50/y;->g:Ljava/lang/Object;

    .line 33
    .line 34
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    invoke-virtual {v0, p0}, Li50/y;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0

    .line 41
    :pswitch_0
    check-cast p1, Llc0/g;

    .line 42
    .line 43
    const/4 v0, 0x0

    .line 44
    if-eqz p1, :cond_0

    .line 45
    .line 46
    iget-object p1, p1, Llc0/g;->a:Ljava/lang/String;

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_0
    move-object p1, v0

    .line 50
    :goto_0
    check-cast p2, Llc0/a;

    .line 51
    .line 52
    if-eqz p2, :cond_1

    .line 53
    .line 54
    iget-object p2, p2, Llc0/a;->a:Ljava/lang/String;

    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_1
    move-object p2, v0

    .line 58
    :goto_1
    check-cast p3, Llc0/d;

    .line 59
    .line 60
    if-eqz p3, :cond_2

    .line 61
    .line 62
    iget-object v0, p3, Llc0/d;->a:Ljava/lang/String;

    .line 63
    .line 64
    :cond_2
    check-cast p4, Lkotlin/coroutines/Continuation;

    .line 65
    .line 66
    new-instance p3, Li50/y;

    .line 67
    .line 68
    iget-object p0, p0, Li50/y;->h:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast p0, Lic0/p;

    .line 71
    .line 72
    const/4 v1, 0x1

    .line 73
    invoke-direct {p3, p0, p4, v1}, Li50/y;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 74
    .line 75
    .line 76
    iput-object p1, p3, Li50/y;->e:Ljava/lang/Object;

    .line 77
    .line 78
    iput-object p2, p3, Li50/y;->f:Ljava/lang/Object;

    .line 79
    .line 80
    iput-object v0, p3, Li50/y;->g:Ljava/lang/Object;

    .line 81
    .line 82
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 83
    .line 84
    invoke-virtual {p3, p0}, Li50/y;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    return-object p0

    .line 89
    :pswitch_1
    check-cast p1, Lvy0/b0;

    .line 90
    .line 91
    check-cast p2, Lm1/m;

    .line 92
    .line 93
    check-cast p3, Lm1/m;

    .line 94
    .line 95
    check-cast p4, Lkotlin/coroutines/Continuation;

    .line 96
    .line 97
    new-instance p1, Li50/y;

    .line 98
    .line 99
    iget-object v0, p0, Li50/y;->g:Ljava/lang/Object;

    .line 100
    .line 101
    check-cast v0, Lay0/n;

    .line 102
    .line 103
    iget-object p0, p0, Li50/y;->h:Ljava/lang/Object;

    .line 104
    .line 105
    check-cast p0, Ll2/b1;

    .line 106
    .line 107
    invoke-direct {p1, v0, p0, p4}, Li50/y;-><init>(Lay0/n;Ll2/b1;Lkotlin/coroutines/Continuation;)V

    .line 108
    .line 109
    .line 110
    iput-object p2, p1, Li50/y;->e:Ljava/lang/Object;

    .line 111
    .line 112
    iput-object p3, p1, Li50/y;->f:Ljava/lang/Object;

    .line 113
    .line 114
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 115
    .line 116
    invoke-virtual {p1, p0}, Li50/y;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    return-object p0

    .line 120
    nop

    .line 121
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Li50/y;->d:I

    .line 2
    .line 3
    iget-object v1, p0, Li50/y;->h:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Li50/y;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Ljava/util/List;

    .line 11
    .line 12
    check-cast v0, Ljava/util/List;

    .line 13
    .line 14
    iget-object v2, p0, Li50/y;->f:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v2, Ljava/util/List;

    .line 17
    .line 18
    check-cast v2, Ljava/util/List;

    .line 19
    .line 20
    iget-object p0, p0, Li50/y;->g:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast p0, Lxj0/r;

    .line 23
    .line 24
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 25
    .line 26
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    instance-of p1, p0, Lxj0/m;

    .line 30
    .line 31
    if-eqz p1, :cond_0

    .line 32
    .line 33
    move-object v0, v2

    .line 34
    :cond_0
    const/4 p1, 0x0

    .line 35
    if-eqz v0, :cond_4

    .line 36
    .line 37
    check-cast v0, Ljava/lang/Iterable;

    .line 38
    .line 39
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    :cond_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    if-eqz v2, :cond_3

    .line 48
    .line 49
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v2

    .line 53
    move-object v3, v2

    .line 54
    check-cast v3, Lbl0/g0;

    .line 55
    .line 56
    invoke-interface {v3}, Lbl0/g0;->getId()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v3

    .line 60
    if-eqz p0, :cond_2

    .line 61
    .line 62
    invoke-virtual {p0}, Lxj0/r;->b()Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v4

    .line 66
    goto :goto_0

    .line 67
    :cond_2
    move-object v4, p1

    .line 68
    :goto_0
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v3

    .line 72
    if-eqz v3, :cond_1

    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_3
    move-object v2, p1

    .line 76
    :goto_1
    check-cast v2, Lbl0/g0;

    .line 77
    .line 78
    goto :goto_2

    .line 79
    :cond_4
    move-object v2, p1

    .line 80
    :goto_2
    if-eqz p0, :cond_7

    .line 81
    .line 82
    check-cast v1, Luk0/a0;

    .line 83
    .line 84
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 85
    .line 86
    .line 87
    instance-of v0, p0, Lxj0/k;

    .line 88
    .line 89
    if-eqz v0, :cond_5

    .line 90
    .line 91
    check-cast p0, Lxj0/k;

    .line 92
    .line 93
    iget-object p1, p0, Lxj0/k;->j:Ljava/lang/String;

    .line 94
    .line 95
    goto :goto_3

    .line 96
    :cond_5
    instance-of v0, p0, Lxj0/p;

    .line 97
    .line 98
    if-eqz v0, :cond_6

    .line 99
    .line 100
    check-cast p0, Lxj0/p;

    .line 101
    .line 102
    iget-object p1, p0, Lxj0/p;->i:Ljava/lang/String;

    .line 103
    .line 104
    goto :goto_3

    .line 105
    :cond_6
    instance-of v0, p0, Lxj0/m;

    .line 106
    .line 107
    if-eqz v0, :cond_7

    .line 108
    .line 109
    check-cast p0, Lxj0/m;

    .line 110
    .line 111
    iget-object p1, p0, Lxj0/m;->h:Ljava/lang/String;

    .line 112
    .line 113
    :cond_7
    :goto_3
    new-instance p0, Llx0/l;

    .line 114
    .line 115
    invoke-direct {p0, v2, p1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    return-object p0

    .line 119
    :pswitch_0
    iget-object v0, p0, Li50/y;->e:Ljava/lang/Object;

    .line 120
    .line 121
    check-cast v0, Ljava/lang/String;

    .line 122
    .line 123
    iget-object v2, p0, Li50/y;->f:Ljava/lang/Object;

    .line 124
    .line 125
    check-cast v2, Ljava/lang/String;

    .line 126
    .line 127
    iget-object p0, p0, Li50/y;->g:Ljava/lang/Object;

    .line 128
    .line 129
    check-cast p0, Ljava/lang/String;

    .line 130
    .line 131
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 132
    .line 133
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    new-instance p1, Llc0/k;

    .line 137
    .line 138
    check-cast v1, Lic0/p;

    .line 139
    .line 140
    iget-object v1, v1, Lic0/p;->a:Llc0/l;

    .line 141
    .line 142
    invoke-direct {p1, v1, v2, v0, p0}, Llc0/k;-><init>(Llc0/l;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    return-object p1

    .line 146
    :pswitch_1
    iget-object v0, p0, Li50/y;->e:Ljava/lang/Object;

    .line 147
    .line 148
    check-cast v0, Lm1/m;

    .line 149
    .line 150
    iget-object v2, p0, Li50/y;->f:Ljava/lang/Object;

    .line 151
    .line 152
    check-cast v2, Lm1/m;

    .line 153
    .line 154
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 155
    .line 156
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 157
    .line 158
    .line 159
    check-cast v1, Ll2/b1;

    .line 160
    .line 161
    sget p1, Li50/z;->a:F

    .line 162
    .line 163
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object p1

    .line 167
    check-cast p1, Ljava/util/List;

    .line 168
    .line 169
    check-cast p1, Ljava/util/Collection;

    .line 170
    .line 171
    invoke-static {p1}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 172
    .line 173
    .line 174
    move-result-object p1

    .line 175
    iget v3, v2, Lm1/m;->a:I

    .line 176
    .line 177
    iget v4, v0, Lm1/m;->a:I

    .line 178
    .line 179
    invoke-virtual {p1, v4}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    move-result-object v4

    .line 183
    invoke-virtual {p1, v3, v4}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 184
    .line 185
    .line 186
    invoke-interface {v1, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 187
    .line 188
    .line 189
    iget-object p0, p0, Li50/y;->g:Ljava/lang/Object;

    .line 190
    .line 191
    check-cast p0, Lay0/n;

    .line 192
    .line 193
    iget p1, v0, Lm1/m;->a:I

    .line 194
    .line 195
    new-instance v0, Ljava/lang/Integer;

    .line 196
    .line 197
    invoke-direct {v0, p1}, Ljava/lang/Integer;-><init>(I)V

    .line 198
    .line 199
    .line 200
    iget p1, v2, Lm1/m;->a:I

    .line 201
    .line 202
    new-instance v1, Ljava/lang/Integer;

    .line 203
    .line 204
    invoke-direct {v1, p1}, Ljava/lang/Integer;-><init>(I)V

    .line 205
    .line 206
    .line 207
    invoke-interface {p0, v0, v1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 208
    .line 209
    .line 210
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 211
    .line 212
    return-object p0

    .line 213
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
