.class public final Ltz/d2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lyy0/j;

.field public final synthetic f:Ltz/i2;


# direct methods
.method public synthetic constructor <init>(Lyy0/j;Ltz/i2;I)V
    .locals 0

    .line 1
    iput p3, p0, Ltz/d2;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltz/d2;->e:Lyy0/j;

    .line 4
    .line 5
    iput-object p2, p0, Ltz/d2;->f:Ltz/i2;

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
    .locals 9

    .line 1
    iget v0, p0, Ltz/d2;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    iget-object v2, p0, Ltz/d2;->f:Ltz/i2;

    .line 6
    .line 7
    iget-object v3, p0, Ltz/d2;->e:Lyy0/j;

    .line 8
    .line 9
    const-string v4, "call to \'resume\' before \'invoke\' with coroutine"

    .line 10
    .line 11
    const/high16 v5, -0x80000000

    .line 12
    .line 13
    const/4 v6, 0x1

    .line 14
    packed-switch v0, :pswitch_data_0

    .line 15
    .line 16
    .line 17
    instance-of v0, p2, Ltz/e2;

    .line 18
    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    move-object v0, p2

    .line 22
    check-cast v0, Ltz/e2;

    .line 23
    .line 24
    iget v7, v0, Ltz/e2;->e:I

    .line 25
    .line 26
    and-int v8, v7, v5

    .line 27
    .line 28
    if-eqz v8, :cond_0

    .line 29
    .line 30
    sub-int/2addr v7, v5

    .line 31
    iput v7, v0, Ltz/e2;->e:I

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    new-instance v0, Ltz/e2;

    .line 35
    .line 36
    invoke-direct {v0, p0, p2}, Ltz/e2;-><init>(Ltz/d2;Lkotlin/coroutines/Continuation;)V

    .line 37
    .line 38
    .line 39
    :goto_0
    iget-object p0, v0, Ltz/e2;->d:Ljava/lang/Object;

    .line 40
    .line 41
    sget-object p2, Lqx0/a;->d:Lqx0/a;

    .line 42
    .line 43
    iget v5, v0, Ltz/e2;->e:I

    .line 44
    .line 45
    if-eqz v5, :cond_2

    .line 46
    .line 47
    if-ne v5, v6, :cond_1

    .line 48
    .line 49
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 54
    .line 55
    invoke-direct {p0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw p0

    .line 59
    :cond_2
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    move-object p0, p1

    .line 63
    check-cast p0, Lxj0/b;

    .line 64
    .line 65
    sget-object v4, Ltz/i2;->v:Lhl0/b;

    .line 66
    .line 67
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 68
    .line 69
    .line 70
    move-result-object v2

    .line 71
    check-cast v2, Ltz/f2;

    .line 72
    .line 73
    iget-boolean v2, v2, Ltz/f2;->f:Z

    .line 74
    .line 75
    if-eqz v2, :cond_3

    .line 76
    .line 77
    iget-boolean p0, p0, Lxj0/b;->c:Z

    .line 78
    .line 79
    if-nez p0, :cond_3

    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_3
    iput v6, v0, Ltz/e2;->e:I

    .line 83
    .line 84
    invoke-interface {v3, p1, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    if-ne p0, p2, :cond_4

    .line 89
    .line 90
    move-object v1, p2

    .line 91
    :cond_4
    :goto_1
    return-object v1

    .line 92
    :pswitch_0
    instance-of v0, p2, Ltz/c2;

    .line 93
    .line 94
    if-eqz v0, :cond_5

    .line 95
    .line 96
    move-object v0, p2

    .line 97
    check-cast v0, Ltz/c2;

    .line 98
    .line 99
    iget v7, v0, Ltz/c2;->e:I

    .line 100
    .line 101
    and-int v8, v7, v5

    .line 102
    .line 103
    if-eqz v8, :cond_5

    .line 104
    .line 105
    sub-int/2addr v7, v5

    .line 106
    iput v7, v0, Ltz/c2;->e:I

    .line 107
    .line 108
    goto :goto_2

    .line 109
    :cond_5
    new-instance v0, Ltz/c2;

    .line 110
    .line 111
    invoke-direct {v0, p0, p2}, Ltz/c2;-><init>(Ltz/d2;Lkotlin/coroutines/Continuation;)V

    .line 112
    .line 113
    .line 114
    :goto_2
    iget-object p0, v0, Ltz/c2;->d:Ljava/lang/Object;

    .line 115
    .line 116
    sget-object p2, Lqx0/a;->d:Lqx0/a;

    .line 117
    .line 118
    iget v5, v0, Ltz/c2;->e:I

    .line 119
    .line 120
    if-eqz v5, :cond_7

    .line 121
    .line 122
    if-ne v5, v6, :cond_6

    .line 123
    .line 124
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 125
    .line 126
    .line 127
    goto :goto_3

    .line 128
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 129
    .line 130
    invoke-direct {p0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 131
    .line 132
    .line 133
    throw p0

    .line 134
    :cond_7
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 135
    .line 136
    .line 137
    move-object p0, p1

    .line 138
    check-cast p0, Lxj0/b;

    .line 139
    .line 140
    iget-object p0, p0, Lxj0/b;->a:Lxj0/f;

    .line 141
    .line 142
    sget-object v4, Ltz/i2;->v:Lhl0/b;

    .line 143
    .line 144
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 145
    .line 146
    .line 147
    move-result-object v2

    .line 148
    check-cast v2, Ltz/f2;

    .line 149
    .line 150
    iget-object v2, v2, Ltz/f2;->b:Lxj0/f;

    .line 151
    .line 152
    invoke-virtual {p0, v2}, Lxj0/f;->equals(Ljava/lang/Object;)Z

    .line 153
    .line 154
    .line 155
    move-result p0

    .line 156
    if-nez p0, :cond_8

    .line 157
    .line 158
    iput v6, v0, Ltz/c2;->e:I

    .line 159
    .line 160
    invoke-interface {v3, p1, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object p0

    .line 164
    if-ne p0, p2, :cond_8

    .line 165
    .line 166
    move-object v1, p2

    .line 167
    :cond_8
    :goto_3
    return-object v1

    .line 168
    nop

    .line 169
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
