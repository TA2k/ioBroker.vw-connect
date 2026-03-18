.class public final Lyy0/t;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public d:J

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public synthetic g:Ljava/lang/Object;

.field public final synthetic h:J

.field public final synthetic i:Lyy0/i;


# direct methods
.method public constructor <init>(JLyy0/i;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-wide p1, p0, Lyy0/t;->h:J

    .line 2
    .line 3
    iput-object p3, p0, Lyy0/t;->i:Lyy0/i;

    .line 4
    .line 5
    const/4 p1, 0x3

    .line 6
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    check-cast p1, Lvy0/b0;

    .line 2
    .line 3
    check-cast p2, Lyy0/j;

    .line 4
    .line 5
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    new-instance v0, Lyy0/t;

    .line 8
    .line 9
    iget-wide v1, p0, Lyy0/t;->h:J

    .line 10
    .line 11
    iget-object p0, p0, Lyy0/t;->i:Lyy0/i;

    .line 12
    .line 13
    invoke-direct {v0, v1, v2, p0, p3}, Lyy0/t;-><init>(JLyy0/i;Lkotlin/coroutines/Continuation;)V

    .line 14
    .line 15
    .line 16
    iput-object p1, v0, Lyy0/t;->f:Ljava/lang/Object;

    .line 17
    .line 18
    iput-object p2, v0, Lyy0/t;->g:Ljava/lang/Object;

    .line 19
    .line 20
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 21
    .line 22
    invoke-virtual {v0, p0}, Lyy0/t;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Lyy0/t;->e:I

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    const/4 v3, 0x0

    .line 7
    if-eqz v1, :cond_1

    .line 8
    .line 9
    if-ne v1, v2, :cond_0

    .line 10
    .line 11
    iget-wide v4, p0, Lyy0/t;->d:J

    .line 12
    .line 13
    iget-object v1, p0, Lyy0/t;->g:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v1, Lxy0/z;

    .line 16
    .line 17
    iget-object v6, p0, Lyy0/t;->f:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v6, Lyy0/j;

    .line 20
    .line 21
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    goto/16 :goto_2

    .line 25
    .line 26
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 27
    .line 28
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 29
    .line 30
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    throw p0

    .line 34
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    iget-object p1, p0, Lyy0/t;->f:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast p1, Lvy0/b0;

    .line 40
    .line 41
    iget-object v1, p0, Lyy0/t;->g:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast v1, Lyy0/j;

    .line 44
    .line 45
    const-wide/16 v4, 0x0

    .line 46
    .line 47
    iget-wide v6, p0, Lyy0/t;->h:J

    .line 48
    .line 49
    invoke-static {v6, v7, v4, v5}, Lmy0/c;->c(JJ)I

    .line 50
    .line 51
    .line 52
    move-result v4

    .line 53
    if-lez v4, :cond_7

    .line 54
    .line 55
    iget-object v4, p0, Lyy0/t;->i:Lyy0/i;

    .line 56
    .line 57
    const/4 v5, 0x0

    .line 58
    invoke-static {v4, v5}, Lyy0/u;->g(Lyy0/i;I)Lyy0/i;

    .line 59
    .line 60
    .line 61
    move-result-object v9

    .line 62
    instance-of v4, v9, Lzy0/e;

    .line 63
    .line 64
    if-eqz v4, :cond_2

    .line 65
    .line 66
    move-object v4, v9

    .line 67
    check-cast v4, Lzy0/e;

    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_2
    move-object v4, v3

    .line 71
    :goto_0
    if-nez v4, :cond_3

    .line 72
    .line 73
    new-instance v8, Lzy0/g;

    .line 74
    .line 75
    const/4 v12, 0x0

    .line 76
    const/16 v13, 0xe

    .line 77
    .line 78
    const/4 v10, 0x0

    .line 79
    const/4 v11, 0x0

    .line 80
    invoke-direct/range {v8 .. v13}, Lzy0/g;-><init>(Lyy0/i;Lpx0/g;ILxy0/a;I)V

    .line 81
    .line 82
    .line 83
    move-object v4, v8

    .line 84
    :cond_3
    invoke-virtual {v4, p1}, Lzy0/e;->h(Lvy0/b0;)Lxy0/z;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    move-wide v4, v6

    .line 89
    move-object v6, v1

    .line 90
    move-object v1, p1

    .line 91
    :cond_4
    new-instance p1, Ldz0/e;

    .line 92
    .line 93
    invoke-interface {p0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 94
    .line 95
    .line 96
    move-result-object v7

    .line 97
    invoke-direct {p1, v7}, Ldz0/e;-><init>(Lpx0/g;)V

    .line 98
    .line 99
    .line 100
    invoke-interface {v1}, Lxy0/z;->m()Lcom/google/firebase/messaging/w;

    .line 101
    .line 102
    .line 103
    move-result-object v7

    .line 104
    new-instance v8, Lyy0/r;

    .line 105
    .line 106
    const/4 v9, 0x0

    .line 107
    invoke-direct {v8, v6, v3, v9}, Lyy0/r;-><init>(Lyy0/j;Lkotlin/coroutines/Continuation;I)V

    .line 108
    .line 109
    .line 110
    invoke-virtual {p1, v7, v8}, Ldz0/e;->f(Lcom/google/firebase/messaging/w;Lay0/n;)V

    .line 111
    .line 112
    .line 113
    new-instance v7, Lyy0/s;

    .line 114
    .line 115
    invoke-direct {v7, v4, v5, v3}, Lyy0/s;-><init>(JLkotlin/coroutines/Continuation;)V

    .line 116
    .line 117
    .line 118
    invoke-static {v4, v5}, Lvy0/e0;->O(J)J

    .line 119
    .line 120
    .line 121
    move-result-wide v8

    .line 122
    invoke-static {p1, v8, v9, v7}, Ldz0/h;->a(Ldz0/e;JLay0/k;)V

    .line 123
    .line 124
    .line 125
    iput-object v6, p0, Lyy0/t;->f:Ljava/lang/Object;

    .line 126
    .line 127
    iput-object v1, p0, Lyy0/t;->g:Ljava/lang/Object;

    .line 128
    .line 129
    iput-wide v4, p0, Lyy0/t;->d:J

    .line 130
    .line 131
    iput v2, p0, Lyy0/t;->e:I

    .line 132
    .line 133
    sget-object v7, Ldz0/e;->i:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 134
    .line 135
    invoke-virtual {v7, p1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object v7

    .line 139
    instance-of v7, v7, Ldz0/c;

    .line 140
    .line 141
    if-eqz v7, :cond_5

    .line 142
    .line 143
    invoke-virtual {p1, p0}, Ldz0/e;->c(Lrx0/c;)Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object p1

    .line 147
    goto :goto_1

    .line 148
    :cond_5
    invoke-virtual {p1, p0}, Ldz0/e;->d(Lrx0/c;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object p1

    .line 152
    :goto_1
    if-ne p1, v0, :cond_6

    .line 153
    .line 154
    return-object v0

    .line 155
    :cond_6
    :goto_2
    check-cast p1, Ljava/lang/Boolean;

    .line 156
    .line 157
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 158
    .line 159
    .line 160
    move-result p1

    .line 161
    if-nez p1, :cond_4

    .line 162
    .line 163
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 164
    .line 165
    return-object p0

    .line 166
    :cond_7
    new-instance p0, Lvy0/e2;

    .line 167
    .line 168
    const-string p1, "Timed out immediately"

    .line 169
    .line 170
    invoke-direct {p0, p1, v3}, Lvy0/e2;-><init>(Ljava/lang/String;Lvy0/i1;)V

    .line 171
    .line 172
    .line 173
    throw p0
.end method
