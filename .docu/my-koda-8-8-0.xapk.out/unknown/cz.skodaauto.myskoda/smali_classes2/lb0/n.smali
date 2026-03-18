.class public final Llb0/n;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public synthetic d:Lne0/s;

.field public synthetic e:Lmb0/h;

.field public final synthetic f:Z

.field public final synthetic g:Llb0/p;


# direct methods
.method public constructor <init>(ZLlb0/p;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Llb0/n;->f:Z

    .line 2
    .line 3
    iput-object p2, p0, Llb0/n;->g:Llb0/p;

    .line 4
    .line 5
    const/4 p1, 0x3

    .line 6
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    check-cast p1, Lne0/s;

    .line 2
    .line 3
    check-cast p2, Lmb0/h;

    .line 4
    .line 5
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    new-instance v0, Llb0/n;

    .line 8
    .line 9
    iget-boolean v1, p0, Llb0/n;->f:Z

    .line 10
    .line 11
    iget-object p0, p0, Llb0/n;->g:Llb0/p;

    .line 12
    .line 13
    invoke-direct {v0, v1, p0, p3}, Llb0/n;-><init>(ZLlb0/p;Lkotlin/coroutines/Continuation;)V

    .line 14
    .line 15
    .line 16
    iput-object p1, v0, Llb0/n;->d:Lne0/s;

    .line 17
    .line 18
    iput-object p2, v0, Llb0/n;->e:Lmb0/h;

    .line 19
    .line 20
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 21
    .line 22
    invoke-virtual {v0, p0}, Llb0/n;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget-object v0, p0, Llb0/n;->d:Lne0/s;

    .line 2
    .line 3
    iget-object v1, p0, Llb0/n;->e:Lmb0/h;

    .line 4
    .line 5
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 6
    .line 7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    iget-object p1, p0, Llb0/n;->g:Llb0/p;

    .line 11
    .line 12
    iget-object v2, p1, Llb0/p;->e:Llb0/c0;

    .line 13
    .line 14
    instance-of v3, v0, Lne0/e;

    .line 15
    .line 16
    if-eqz v3, :cond_9

    .line 17
    .line 18
    :try_start_0
    move-object v3, v0

    .line 19
    check-cast v3, Lne0/e;

    .line 20
    .line 21
    iget-object v3, v3, Lne0/e;->a:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v3, Lmb0/f;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 24
    .line 25
    iget-boolean p0, p0, Llb0/n;->f:Z

    .line 26
    .line 27
    if-eqz p0, :cond_0

    .line 28
    .line 29
    :try_start_1
    invoke-static {p1, v3}, Llb0/p;->a(Llb0/p;Lmb0/f;)Lmb0/f;

    .line 30
    .line 31
    .line 32
    move-result-object v3

    .line 33
    :cond_0
    if-nez p0, :cond_1

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_1
    move-object p0, v0

    .line 37
    check-cast p0, Lne0/e;

    .line 38
    .line 39
    iget-object p0, p0, Lne0/e;->a:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast p0, Lmb0/f;

    .line 42
    .line 43
    iget-object p0, p0, Lmb0/f;->e:Lqr0/q;

    .line 44
    .line 45
    if-eqz p0, :cond_7

    .line 46
    .line 47
    const/4 p0, -0x1

    .line 48
    if-nez v1, :cond_2

    .line 49
    .line 50
    move p1, p0

    .line 51
    goto :goto_0

    .line 52
    :cond_2
    sget-object p1, Llb0/m;->a:[I

    .line 53
    .line 54
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 55
    .line 56
    .line 57
    move-result v1

    .line 58
    aget p1, p1, v1

    .line 59
    .line 60
    :goto_0
    if-eq p1, p0, :cond_7

    .line 61
    .line 62
    const/4 p0, 0x1

    .line 63
    const v1, 0xfffe

    .line 64
    .line 65
    .line 66
    const/4 v4, 0x0

    .line 67
    if-eq p1, p0, :cond_5

    .line 68
    .line 69
    const/4 p0, 0x2

    .line 70
    if-ne p1, p0, :cond_4

    .line 71
    .line 72
    iget-object p0, v3, Lmb0/f;->a:Lmb0/e;

    .line 73
    .line 74
    sget-object p1, Lmb0/e;->d:Lmb0/e;

    .line 75
    .line 76
    if-ne p0, p1, :cond_3

    .line 77
    .line 78
    invoke-virtual {v2, v4}, Llb0/c0;->a(Lmb0/h;)V

    .line 79
    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_3
    check-cast v0, Lne0/e;

    .line 83
    .line 84
    iget-object p0, v0, Lne0/e;->a:Ljava/lang/Object;

    .line 85
    .line 86
    check-cast p0, Lmb0/f;

    .line 87
    .line 88
    sget-object p1, Lmb0/e;->n:Lmb0/e;

    .line 89
    .line 90
    invoke-static {p0, p1, v4, v1}, Lmb0/f;->a(Lmb0/f;Lmb0/e;Lqr0/q;I)Lmb0/f;

    .line 91
    .line 92
    .line 93
    move-result-object v3

    .line 94
    goto :goto_1

    .line 95
    :cond_4
    new-instance p0, La8/r0;

    .line 96
    .line 97
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 98
    .line 99
    .line 100
    throw p0

    .line 101
    :cond_5
    iget-object p0, v3, Lmb0/f;->a:Lmb0/e;

    .line 102
    .line 103
    sget-object p1, Lmb0/e;->l:Lmb0/e;

    .line 104
    .line 105
    if-ne p0, p1, :cond_6

    .line 106
    .line 107
    invoke-virtual {v2, v4}, Llb0/c0;->a(Lmb0/h;)V

    .line 108
    .line 109
    .line 110
    goto :goto_1

    .line 111
    :cond_6
    check-cast v0, Lne0/e;

    .line 112
    .line 113
    iget-object p0, v0, Lne0/e;->a:Ljava/lang/Object;

    .line 114
    .line 115
    check-cast p0, Lmb0/f;

    .line 116
    .line 117
    sget-object p1, Lmb0/e;->m:Lmb0/e;

    .line 118
    .line 119
    invoke-static {p0, p1, v4, v1}, Lmb0/f;->a(Lmb0/f;Lmb0/e;Lqr0/q;I)Lmb0/f;

    .line 120
    .line 121
    .line 122
    move-result-object v3

    .line 123
    :cond_7
    :goto_1
    new-instance p0, Lne0/e;

    .line 124
    .line 125
    invoke-direct {p0, v3}, Lne0/e;-><init>(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 126
    .line 127
    .line 128
    goto :goto_2

    .line 129
    :catchall_0
    move-exception v0

    .line 130
    move-object p0, v0

    .line 131
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    :goto_2
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 136
    .line 137
    .line 138
    move-result-object v1

    .line 139
    if-nez v1, :cond_8

    .line 140
    .line 141
    goto :goto_3

    .line 142
    :cond_8
    new-instance v0, Lne0/c;

    .line 143
    .line 144
    const/4 v4, 0x0

    .line 145
    const/16 v5, 0x1e

    .line 146
    .line 147
    const/4 v2, 0x0

    .line 148
    const/4 v3, 0x0

    .line 149
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 150
    .line 151
    .line 152
    move-object p0, v0

    .line 153
    :goto_3
    check-cast p0, Lne0/s;

    .line 154
    .line 155
    return-object p0

    .line 156
    :cond_9
    instance-of p0, v0, Lne0/c;

    .line 157
    .line 158
    if-eqz p0, :cond_a

    .line 159
    .line 160
    goto :goto_4

    .line 161
    :cond_a
    instance-of p0, v0, Lne0/d;

    .line 162
    .line 163
    if-eqz p0, :cond_b

    .line 164
    .line 165
    :goto_4
    return-object v0

    .line 166
    :cond_b
    new-instance p0, La8/r0;

    .line 167
    .line 168
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 169
    .line 170
    .line 171
    throw p0
.end method
