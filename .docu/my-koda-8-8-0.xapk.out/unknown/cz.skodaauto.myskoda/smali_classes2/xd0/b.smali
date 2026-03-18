.class public final Lxd0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lyy0/j1;

.field public final b:Lyy0/i1;

.field public final c:Lez0/c;

.field public final d:Lyy0/l1;


# direct methods
.method public constructor <init>()V
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 3
    .line 4
    .line 5
    move-result-object v1

    .line 6
    const/4 v2, 0x5

    .line 7
    const/4 v3, 0x1

    .line 8
    invoke-static {v3, v2, v0}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 13
    .line 14
    .line 15
    iput-object v1, p0, Lxd0/b;->a:Lyy0/j1;

    .line 16
    .line 17
    iput-object v0, p0, Lxd0/b;->b:Lyy0/i1;

    .line 18
    .line 19
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    iput-object v0, p0, Lxd0/b;->c:Lez0/c;

    .line 24
    .line 25
    new-instance v0, Lyy0/l1;

    .line 26
    .line 27
    invoke-direct {v0, v1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 28
    .line 29
    .line 30
    iput-object v0, p0, Lxd0/b;->d:Lyy0/l1;

    .line 31
    .line 32
    return-void
.end method


# virtual methods
.method public final a(Lae0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p2, Lxd0/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lxd0/a;

    .line 7
    .line 8
    iget v1, v0, Lxd0/a;->k:I

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
    iput v1, v0, Lxd0/a;->k:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lxd0/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lxd0/a;-><init>(Lxd0/b;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lxd0/a;->i:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lxd0/a;->k:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    const/4 v5, 0x0

    .line 34
    if-eqz v2, :cond_3

    .line 35
    .line 36
    if-eq v2, v4, :cond_2

    .line 37
    .line 38
    if-ne v2, v3, :cond_1

    .line 39
    .line 40
    iget-object p0, v0, Lxd0/a;->f:Lez0/a;

    .line 41
    .line 42
    iget-object p1, v0, Lxd0/a;->e:Lxd0/b;

    .line 43
    .line 44
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 45
    .line 46
    .line 47
    goto :goto_3

    .line 48
    :catchall_0
    move-exception v0

    .line 49
    move-object p1, v0

    .line 50
    goto/16 :goto_5

    .line 51
    .line 52
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 53
    .line 54
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 55
    .line 56
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw p0

    .line 60
    :cond_2
    iget p0, v0, Lxd0/a;->h:I

    .line 61
    .line 62
    iget p1, v0, Lxd0/a;->g:I

    .line 63
    .line 64
    iget-object v2, v0, Lxd0/a;->f:Lez0/a;

    .line 65
    .line 66
    iget-object v4, v0, Lxd0/a;->e:Lxd0/b;

    .line 67
    .line 68
    iget-object v6, v0, Lxd0/a;->d:Lae0/a;

    .line 69
    .line 70
    :try_start_1
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_3

    .line 71
    .line 72
    .line 73
    move-object p2, v2

    .line 74
    move v2, p0

    .line 75
    move-object p0, v4

    .line 76
    move v4, p1

    .line 77
    move-object p1, v6

    .line 78
    goto :goto_1

    .line 79
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    :try_start_2
    iget-object p2, p0, Lxd0/b;->c:Lez0/c;

    .line 83
    .line 84
    iput-object p1, v0, Lxd0/a;->d:Lae0/a;

    .line 85
    .line 86
    iput-object p0, v0, Lxd0/a;->e:Lxd0/b;

    .line 87
    .line 88
    iput-object p2, v0, Lxd0/a;->f:Lez0/a;

    .line 89
    .line 90
    const/4 v2, 0x0

    .line 91
    iput v2, v0, Lxd0/a;->g:I

    .line 92
    .line 93
    iput v2, v0, Lxd0/a;->h:I

    .line 94
    .line 95
    iput v4, v0, Lxd0/a;->k:I

    .line 96
    .line 97
    invoke-virtual {p2, v0}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v4
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_3

    .line 101
    if-ne v4, v1, :cond_4

    .line 102
    .line 103
    goto :goto_2

    .line 104
    :cond_4
    move v4, v2

    .line 105
    :goto_1
    :try_start_3
    iget-object v6, p0, Lxd0/b;->a:Lyy0/j1;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 106
    .line 107
    :try_start_4
    check-cast v6, Lyy0/c2;

    .line 108
    .line 109
    invoke-virtual {v6, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 110
    .line 111
    .line 112
    :try_start_5
    iget-object p1, p0, Lxd0/b;->b:Lyy0/i1;

    .line 113
    .line 114
    iput-object v5, v0, Lxd0/a;->d:Lae0/a;

    .line 115
    .line 116
    iput-object p0, v0, Lxd0/a;->e:Lxd0/b;

    .line 117
    .line 118
    iput-object p2, v0, Lxd0/a;->f:Lez0/a;

    .line 119
    .line 120
    iput v4, v0, Lxd0/a;->g:I

    .line 121
    .line 122
    iput v2, v0, Lxd0/a;->h:I

    .line 123
    .line 124
    iput v3, v0, Lxd0/a;->k:I

    .line 125
    .line 126
    invoke-static {p1, v0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object p1
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 130
    if-ne p1, v1, :cond_5

    .line 131
    .line 132
    :goto_2
    return-object v1

    .line 133
    :cond_5
    move-object v7, p1

    .line 134
    move-object p1, p0

    .line 135
    move-object p0, p2

    .line 136
    move-object p2, v7

    .line 137
    :goto_3
    :try_start_6
    check-cast p2, Lne0/t;

    .line 138
    .line 139
    iget-object p1, p1, Lxd0/b;->a:Lyy0/j1;

    .line 140
    .line 141
    check-cast p1, Lyy0/c2;

    .line 142
    .line 143
    invoke-virtual {p1, v5}, Lyy0/c2;->j(Ljava/lang/Object;)V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 144
    .line 145
    .line 146
    :try_start_7
    invoke-interface {p0, v5}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 147
    .line 148
    .line 149
    goto :goto_6

    .line 150
    :catchall_1
    move-exception v0

    .line 151
    move-object p1, v0

    .line 152
    :goto_4
    move-object p0, p2

    .line 153
    goto :goto_5

    .line 154
    :catchall_2
    move-exception v0

    .line 155
    move-object p0, v0

    .line 156
    move-object p1, p0

    .line 157
    goto :goto_4

    .line 158
    :goto_5
    invoke-interface {p0, v5}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 159
    .line 160
    .line 161
    throw p1
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_3

    .line 162
    :catchall_3
    move-exception v0

    .line 163
    move-object p0, v0

    .line 164
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 165
    .line 166
    .line 167
    move-result-object p2

    .line 168
    :goto_6
    invoke-static {p2}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 169
    .line 170
    .line 171
    move-result-object v1

    .line 172
    if-nez v1, :cond_6

    .line 173
    .line 174
    goto :goto_7

    .line 175
    :cond_6
    new-instance v0, Lne0/c;

    .line 176
    .line 177
    const/4 v4, 0x0

    .line 178
    const/16 v5, 0x1e

    .line 179
    .line 180
    const/4 v2, 0x0

    .line 181
    const/4 v3, 0x0

    .line 182
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 183
    .line 184
    .line 185
    move-object p2, v0

    .line 186
    :goto_7
    return-object p2
.end method
