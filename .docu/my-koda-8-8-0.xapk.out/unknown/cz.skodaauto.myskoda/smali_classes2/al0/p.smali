.class public final Lal0/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lkf0/m;

.field public final b:Lal0/v;

.field public final c:Lyk0/q;

.field public final d:Lal0/b0;


# direct methods
.method public constructor <init>(Lkf0/m;Lal0/v;Lyk0/q;Lal0/b0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lal0/p;->a:Lkf0/m;

    .line 5
    .line 6
    iput-object p2, p0, Lal0/p;->b:Lal0/v;

    .line 7
    .line 8
    iput-object p3, p0, Lal0/p;->c:Lyk0/q;

    .line 9
    .line 10
    iput-object p4, p0, Lal0/p;->d:Lal0/b0;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lal0/n;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lal0/p;->b(Lal0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lal0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 11

    .line 1
    instance-of v0, p2, Lal0/o;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lal0/o;

    .line 7
    .line 8
    iget v1, v0, Lal0/o;->i:I

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
    iput v1, v0, Lal0/o;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lal0/o;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lal0/o;-><init>(Lal0/p;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lal0/o;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lal0/o;->i:I

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
    iget-object p1, v0, Lal0/o;->f:Lyk0/q;

    .line 40
    .line 41
    iget-object v1, v0, Lal0/o;->e:Lne0/t;

    .line 42
    .line 43
    iget-object v0, v0, Lal0/o;->d:Lal0/n;

    .line 44
    .line 45
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    move-object v5, p1

    .line 49
    goto :goto_3

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
    iget-object p1, v0, Lal0/o;->d:Lal0/n;

    .line 59
    .line 60
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    iput-object p1, v0, Lal0/o;->d:Lal0/n;

    .line 68
    .line 69
    iput v4, v0, Lal0/o;->i:I

    .line 70
    .line 71
    iget-object p2, p0, Lal0/p;->a:Lkf0/m;

    .line 72
    .line 73
    invoke-virtual {p2, v0}, Lkf0/m;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object p2

    .line 77
    if-ne p2, v1, :cond_4

    .line 78
    .line 79
    goto :goto_2

    .line 80
    :cond_4
    :goto_1
    check-cast p2, Lne0/t;

    .line 81
    .line 82
    iput-object p1, v0, Lal0/o;->d:Lal0/n;

    .line 83
    .line 84
    iput-object p2, v0, Lal0/o;->e:Lne0/t;

    .line 85
    .line 86
    iget-object v2, p0, Lal0/p;->c:Lyk0/q;

    .line 87
    .line 88
    iput-object v2, v0, Lal0/o;->f:Lyk0/q;

    .line 89
    .line 90
    iput v3, v0, Lal0/o;->i:I

    .line 91
    .line 92
    iget-object v0, p0, Lal0/p;->b:Lal0/v;

    .line 93
    .line 94
    iget-object v0, v0, Lal0/v;->a:Lal0/b0;

    .line 95
    .line 96
    check-cast v0, Lyk0/e;

    .line 97
    .line 98
    iget-object v3, v0, Lyk0/e;->e:Ljava/util/UUID;

    .line 99
    .line 100
    if-nez v3, :cond_5

    .line 101
    .line 102
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 103
    .line 104
    .line 105
    move-result-object v3

    .line 106
    iput-object v3, v0, Lyk0/e;->e:Ljava/util/UUID;

    .line 107
    .line 108
    const-string v0, "also(...)"

    .line 109
    .line 110
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    :cond_5
    if-ne v3, v1, :cond_6

    .line 114
    .line 115
    :goto_2
    return-object v1

    .line 116
    :cond_6
    move-object v0, p1

    .line 117
    move-object v1, p2

    .line 118
    move-object v5, v2

    .line 119
    move-object p2, v3

    .line 120
    :goto_3
    move-object v8, p2

    .line 121
    check-cast v8, Ljava/util/UUID;

    .line 122
    .line 123
    instance-of p1, v1, Lne0/c;

    .line 124
    .line 125
    const/4 p2, 0x0

    .line 126
    if-eqz p1, :cond_7

    .line 127
    .line 128
    move-object p1, p2

    .line 129
    goto :goto_4

    .line 130
    :cond_7
    instance-of p1, v1, Lne0/e;

    .line 131
    .line 132
    if-eqz p1, :cond_9

    .line 133
    .line 134
    check-cast v1, Lne0/e;

    .line 135
    .line 136
    iget-object p1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 137
    .line 138
    :goto_4
    check-cast p1, Lss0/k;

    .line 139
    .line 140
    if-eqz p1, :cond_8

    .line 141
    .line 142
    iget-object p1, p1, Lss0/k;->a:Ljava/lang/String;

    .line 143
    .line 144
    move-object v9, p1

    .line 145
    goto :goto_5

    .line 146
    :cond_8
    move-object v9, p2

    .line 147
    :goto_5
    iget-object v6, v0, Lal0/n;->a:Lxj0/f;

    .line 148
    .line 149
    iget-object v7, v0, Lal0/n;->b:Lxj0/f;

    .line 150
    .line 151
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 152
    .line 153
    .line 154
    const-string p1, "sessionId"

    .line 155
    .line 156
    invoke-static {v8, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 157
    .line 158
    .line 159
    const-string p1, "bottomLeft"

    .line 160
    .line 161
    invoke-static {v6, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    const-string p1, "topRight"

    .line 165
    .line 166
    invoke-static {v7, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 167
    .line 168
    .line 169
    iget-object p1, v5, Lyk0/q;->a:Lxl0/f;

    .line 170
    .line 171
    new-instance v4, Li70/s;

    .line 172
    .line 173
    const/4 v10, 0x0

    .line 174
    invoke-direct/range {v4 .. v10}, Li70/s;-><init>(Lyk0/q;Lxj0/f;Lxj0/f;Ljava/util/UUID;Ljava/lang/String;Lkotlin/coroutines/Continuation;)V

    .line 175
    .line 176
    .line 177
    new-instance v1, Lxy/f;

    .line 178
    .line 179
    const/16 v2, 0xe

    .line 180
    .line 181
    invoke-direct {v1, v2}, Lxy/f;-><init>(I)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {p1, v4, v1, p2}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 185
    .line 186
    .line 187
    move-result-object p1

    .line 188
    new-instance v1, La7/o;

    .line 189
    .line 190
    const/4 v2, 0x6

    .line 191
    invoke-direct {v1, v2, p0, v0, p2}, La7/o;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 192
    .line 193
    .line 194
    invoke-static {v1, p1}, Lbb/j0;->f(Lay0/n;Lyy0/i;)Lne0/n;

    .line 195
    .line 196
    .line 197
    move-result-object p0

    .line 198
    return-object p0

    .line 199
    :cond_9
    new-instance p0, La8/r0;

    .line 200
    .line 201
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 202
    .line 203
    .line 204
    throw p0
.end method
