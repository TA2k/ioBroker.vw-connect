.class public final Lz81/j;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/q;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Lyy0/j;

.field public synthetic g:Ljava/util/List;

.field public synthetic h:Z

.field public synthetic i:Lz81/q;

.field public final synthetic j:Ljava/io/Closeable;


# direct methods
.method public synthetic constructor <init>(Ljava/io/Closeable;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lz81/j;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lz81/j;->j:Ljava/io/Closeable;

    .line 4
    .line 5
    const/4 p1, 0x5

    .line 6
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lz81/j;->d:I

    .line 2
    .line 3
    check-cast p1, Lyy0/j;

    .line 4
    .line 5
    check-cast p2, Ljava/util/List;

    .line 6
    .line 7
    check-cast p3, Ljava/lang/Boolean;

    .line 8
    .line 9
    invoke-virtual {p3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 10
    .line 11
    .line 12
    move-result p3

    .line 13
    check-cast p4, Lz81/q;

    .line 14
    .line 15
    check-cast p5, Lkotlin/coroutines/Continuation;

    .line 16
    .line 17
    packed-switch v0, :pswitch_data_0

    .line 18
    .line 19
    .line 20
    new-instance v0, Lz81/j;

    .line 21
    .line 22
    iget-object p0, p0, Lz81/j;->j:Ljava/io/Closeable;

    .line 23
    .line 24
    check-cast p0, Lz81/o;

    .line 25
    .line 26
    const/4 v1, 0x1

    .line 27
    invoke-direct {v0, p0, p5, v1}, Lz81/j;-><init>(Ljava/io/Closeable;Lkotlin/coroutines/Continuation;I)V

    .line 28
    .line 29
    .line 30
    iput-object p1, v0, Lz81/j;->f:Lyy0/j;

    .line 31
    .line 32
    check-cast p2, Ljava/util/List;

    .line 33
    .line 34
    iput-object p2, v0, Lz81/j;->g:Ljava/util/List;

    .line 35
    .line 36
    iput-boolean p3, v0, Lz81/j;->h:Z

    .line 37
    .line 38
    iput-object p4, v0, Lz81/j;->i:Lz81/q;

    .line 39
    .line 40
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    invoke-virtual {v0, p0}, Lz81/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0

    .line 47
    :pswitch_0
    new-instance v0, Lz81/j;

    .line 48
    .line 49
    iget-object p0, p0, Lz81/j;->j:Ljava/io/Closeable;

    .line 50
    .line 51
    check-cast p0, Lz81/l;

    .line 52
    .line 53
    const/4 v1, 0x0

    .line 54
    invoke-direct {v0, p0, p5, v1}, Lz81/j;-><init>(Ljava/io/Closeable;Lkotlin/coroutines/Continuation;I)V

    .line 55
    .line 56
    .line 57
    iput-object p1, v0, Lz81/j;->f:Lyy0/j;

    .line 58
    .line 59
    check-cast p2, Ljava/util/List;

    .line 60
    .line 61
    iput-object p2, v0, Lz81/j;->g:Ljava/util/List;

    .line 62
    .line 63
    iput-boolean p3, v0, Lz81/j;->h:Z

    .line 64
    .line 65
    iput-object p4, v0, Lz81/j;->i:Lz81/q;

    .line 66
    .line 67
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    invoke-virtual {v0, p0}, Lz81/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    return-object p0

    .line 74
    nop

    .line 75
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Lz81/j;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lz81/j;->f:Lyy0/j;

    .line 7
    .line 8
    iget-object v1, p0, Lz81/j;->g:Ljava/util/List;

    .line 9
    .line 10
    check-cast v1, Ljava/util/List;

    .line 11
    .line 12
    iget-boolean v2, p0, Lz81/j;->h:Z

    .line 13
    .line 14
    iget-object v3, p0, Lz81/j;->i:Lz81/q;

    .line 15
    .line 16
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 17
    .line 18
    iget v5, p0, Lz81/j;->e:I

    .line 19
    .line 20
    const/4 v6, 0x1

    .line 21
    if-eqz v5, :cond_1

    .line 22
    .line 23
    if-ne v5, v6, :cond_0

    .line 24
    .line 25
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 30
    .line 31
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 32
    .line 33
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    throw p0

    .line 37
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    iget-object p1, p0, Lz81/j;->j:Ljava/io/Closeable;

    .line 41
    .line 42
    check-cast p1, Lz81/o;

    .line 43
    .line 44
    iget-object p1, p1, Lz81/o;->j:Lro/f;

    .line 45
    .line 46
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 47
    .line 48
    .line 49
    sget-object v3, Lz81/f;->e:Lz81/f;

    .line 50
    .line 51
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 52
    .line 53
    .line 54
    iput-object v3, p1, Lro/f;->e:Ljava/lang/Object;

    .line 55
    .line 56
    if-eqz v2, :cond_2

    .line 57
    .line 58
    move-object p1, v1

    .line 59
    check-cast p1, Ljava/util/Collection;

    .line 60
    .line 61
    invoke-interface {p1}, Ljava/util/Collection;->isEmpty()Z

    .line 62
    .line 63
    .line 64
    move-result p1

    .line 65
    if-nez p1, :cond_2

    .line 66
    .line 67
    check-cast v1, Ljava/lang/Iterable;

    .line 68
    .line 69
    invoke-static {v1}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    const/4 v1, 0x0

    .line 74
    iput-object v1, p0, Lz81/j;->f:Lyy0/j;

    .line 75
    .line 76
    iput-object v1, p0, Lz81/j;->g:Ljava/util/List;

    .line 77
    .line 78
    iput-object v1, p0, Lz81/j;->i:Lz81/q;

    .line 79
    .line 80
    iput-boolean v2, p0, Lz81/j;->h:Z

    .line 81
    .line 82
    iput v6, p0, Lz81/j;->e:I

    .line 83
    .line 84
    invoke-interface {v0, p1, p0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    if-ne p0, v4, :cond_2

    .line 89
    .line 90
    goto :goto_1

    .line 91
    :cond_2
    :goto_0
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 92
    .line 93
    :goto_1
    return-object v4

    .line 94
    :pswitch_0
    iget-object v0, p0, Lz81/j;->f:Lyy0/j;

    .line 95
    .line 96
    iget-object v1, p0, Lz81/j;->g:Ljava/util/List;

    .line 97
    .line 98
    check-cast v1, Ljava/util/List;

    .line 99
    .line 100
    iget-boolean v2, p0, Lz81/j;->h:Z

    .line 101
    .line 102
    iget-object v3, p0, Lz81/j;->i:Lz81/q;

    .line 103
    .line 104
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 105
    .line 106
    iget v5, p0, Lz81/j;->e:I

    .line 107
    .line 108
    const/4 v6, 0x1

    .line 109
    if-eqz v5, :cond_4

    .line 110
    .line 111
    if-ne v5, v6, :cond_3

    .line 112
    .line 113
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    goto :goto_2

    .line 117
    :cond_3
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
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 126
    .line 127
    .line 128
    iget-object p1, p0, Lz81/j;->j:Ljava/io/Closeable;

    .line 129
    .line 130
    check-cast p1, Lz81/l;

    .line 131
    .line 132
    iget-object p1, p1, Lz81/l;->j:Lro/f;

    .line 133
    .line 134
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 135
    .line 136
    .line 137
    sget-object v3, Lz81/f;->e:Lz81/f;

    .line 138
    .line 139
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 140
    .line 141
    .line 142
    iput-object v3, p1, Lro/f;->e:Ljava/lang/Object;

    .line 143
    .line 144
    if-eqz v2, :cond_5

    .line 145
    .line 146
    move-object p1, v1

    .line 147
    check-cast p1, Ljava/util/Collection;

    .line 148
    .line 149
    invoke-interface {p1}, Ljava/util/Collection;->isEmpty()Z

    .line 150
    .line 151
    .line 152
    move-result p1

    .line 153
    if-nez p1, :cond_5

    .line 154
    .line 155
    check-cast v1, Ljava/lang/Iterable;

    .line 156
    .line 157
    invoke-static {v1}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 158
    .line 159
    .line 160
    move-result-object p1

    .line 161
    const/4 v1, 0x0

    .line 162
    iput-object v1, p0, Lz81/j;->f:Lyy0/j;

    .line 163
    .line 164
    iput-object v1, p0, Lz81/j;->g:Ljava/util/List;

    .line 165
    .line 166
    iput-object v1, p0, Lz81/j;->i:Lz81/q;

    .line 167
    .line 168
    iput-boolean v2, p0, Lz81/j;->h:Z

    .line 169
    .line 170
    iput v6, p0, Lz81/j;->e:I

    .line 171
    .line 172
    invoke-interface {v0, p1, p0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object p0

    .line 176
    if-ne p0, v4, :cond_5

    .line 177
    .line 178
    goto :goto_3

    .line 179
    :cond_5
    :goto_2
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 180
    .line 181
    :goto_3
    return-object v4

    .line 182
    nop

    .line 183
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
