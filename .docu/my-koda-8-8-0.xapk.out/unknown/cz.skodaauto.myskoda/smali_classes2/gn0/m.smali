.class public final Lgn0/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lgn0/f;

.field public final b:Lrs0/f;

.field public final c:Len0/s;

.field public final d:Lgn0/j;

.field public final e:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>(Lgn0/f;Lrs0/f;Len0/s;Lgn0/j;Ljava/util/ArrayList;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lgn0/m;->a:Lgn0/f;

    .line 5
    .line 6
    iput-object p2, p0, Lgn0/m;->b:Lrs0/f;

    .line 7
    .line 8
    iput-object p3, p0, Lgn0/m;->c:Len0/s;

    .line 9
    .line 10
    iput-object p4, p0, Lgn0/m;->d:Lgn0/j;

    .line 11
    .line 12
    iput-object p5, p0, Lgn0/m;->e:Ljava/util/ArrayList;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lgn0/m;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p1, Lgn0/l;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lgn0/l;

    .line 7
    .line 8
    iget v1, v0, Lgn0/l;->h:I

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
    iput v1, v0, Lgn0/l;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lgn0/l;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lgn0/l;-><init>(Lgn0/m;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lgn0/l;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lgn0/l;->h:I

    .line 30
    .line 31
    const/4 v3, 0x4

    .line 32
    const/4 v4, 0x3

    .line 33
    const/4 v5, 0x2

    .line 34
    const/4 v6, 0x1

    .line 35
    if-eqz v2, :cond_5

    .line 36
    .line 37
    if-eq v2, v6, :cond_4

    .line 38
    .line 39
    if-eq v2, v5, :cond_3

    .line 40
    .line 41
    if-eq v2, v4, :cond_2

    .line 42
    .line 43
    if-ne v2, v3, :cond_1

    .line 44
    .line 45
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    goto/16 :goto_5

    .line 49
    .line 50
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 51
    .line 52
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 53
    .line 54
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw p0

    .line 58
    :cond_2
    iget v2, v0, Lgn0/l;->e:I

    .line 59
    .line 60
    iget-object v3, v0, Lgn0/l;->d:Ljava/util/Iterator;

    .line 61
    .line 62
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    goto :goto_3

    .line 66
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    goto :goto_2

    .line 70
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    goto :goto_1

    .line 74
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    iput v6, v0, Lgn0/l;->h:I

    .line 78
    .line 79
    iget-object p1, p0, Lgn0/m;->a:Lgn0/f;

    .line 80
    .line 81
    invoke-virtual {p1, v0}, Lgn0/f;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p1

    .line 85
    if-ne p1, v1, :cond_6

    .line 86
    .line 87
    goto :goto_4

    .line 88
    :cond_6
    :goto_1
    check-cast p1, Lne0/t;

    .line 89
    .line 90
    instance-of v2, p1, Lne0/e;

    .line 91
    .line 92
    iget-object v6, p0, Lgn0/m;->b:Lrs0/f;

    .line 93
    .line 94
    if-eqz v2, :cond_a

    .line 95
    .line 96
    check-cast p1, Lne0/e;

    .line 97
    .line 98
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 99
    .line 100
    check-cast p1, Lss0/u;

    .line 101
    .line 102
    iget-object p1, p1, Lss0/u;->e:Ljava/lang/String;

    .line 103
    .line 104
    if-eqz p1, :cond_9

    .line 105
    .line 106
    new-instance v2, Lss0/j0;

    .line 107
    .line 108
    invoke-direct {v2, p1}, Lss0/j0;-><init>(Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    iput v5, v0, Lgn0/l;->h:I

    .line 112
    .line 113
    check-cast v6, Lps0/f;

    .line 114
    .line 115
    invoke-virtual {v6, v2, v0}, Lps0/f;->c(Lss0/d0;Lrx0/c;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object p1

    .line 119
    if-ne p1, v1, :cond_7

    .line 120
    .line 121
    goto :goto_4

    .line 122
    :cond_7
    :goto_2
    iget-object p1, p0, Lgn0/m;->c:Len0/s;

    .line 123
    .line 124
    iget-object p1, p1, Len0/s;->f:Lwe0/a;

    .line 125
    .line 126
    check-cast p1, Lwe0/c;

    .line 127
    .line 128
    invoke-virtual {p1}, Lwe0/c;->a()V

    .line 129
    .line 130
    .line 131
    iget-object p1, p0, Lgn0/m;->e:Ljava/util/ArrayList;

    .line 132
    .line 133
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 134
    .line 135
    .line 136
    move-result-object p1

    .line 137
    const/4 v2, 0x0

    .line 138
    move-object v3, p1

    .line 139
    :cond_8
    :goto_3
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 140
    .line 141
    .line 142
    move-result p1

    .line 143
    if-eqz p1, :cond_b

    .line 144
    .line 145
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object p1

    .line 149
    check-cast p1, Lme0/b;

    .line 150
    .line 151
    iput-object v3, v0, Lgn0/l;->d:Ljava/util/Iterator;

    .line 152
    .line 153
    iput v2, v0, Lgn0/l;->e:I

    .line 154
    .line 155
    iput v4, v0, Lgn0/l;->h:I

    .line 156
    .line 157
    invoke-interface {p1, v0}, Lme0/b;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object p1

    .line 161
    if-ne p1, v1, :cond_8

    .line 162
    .line 163
    goto :goto_4

    .line 164
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 165
    .line 166
    const-string p1, "Ordered vehicle doesn\'t have vin"

    .line 167
    .line 168
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    throw p0

    .line 172
    :cond_a
    instance-of v2, p1, Lne0/c;

    .line 173
    .line 174
    if-eqz v2, :cond_b

    .line 175
    .line 176
    check-cast p1, Lne0/c;

    .line 177
    .line 178
    iget-object p1, p1, Lne0/c;->a:Ljava/lang/Throwable;

    .line 179
    .line 180
    invoke-static {p0, p1}, Llp/nd;->j(Ljava/lang/Object;Ljava/lang/Throwable;)V

    .line 181
    .line 182
    .line 183
    iput v3, v0, Lgn0/l;->h:I

    .line 184
    .line 185
    check-cast v6, Lps0/f;

    .line 186
    .line 187
    invoke-virtual {v6, v0}, Lps0/f;->b(Lrx0/c;)Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object p1

    .line 191
    if-ne p1, v1, :cond_b

    .line 192
    .line 193
    :goto_4
    return-object v1

    .line 194
    :cond_b
    :goto_5
    iget-object p0, p0, Lgn0/m;->d:Lgn0/j;

    .line 195
    .line 196
    iget-object p0, p0, Lgn0/j;->a:Lgn0/k;

    .line 197
    .line 198
    check-cast p0, Liy/b;

    .line 199
    .line 200
    invoke-virtual {p0}, Liy/b;->e()V

    .line 201
    .line 202
    .line 203
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 204
    .line 205
    return-object p0
.end method
