.class public final Llm/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ld01/i;


# direct methods
.method public synthetic constructor <init>(Ld01/i;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Llm/b;->a:Ld01/i;

    .line 5
    .line 6
    return-void
.end method

.method public static a(Ld01/i;Lim/q;Lim/k;Lrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p3, Llm/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Llm/a;

    .line 7
    .line 8
    iget v1, v0, Llm/a;->g:I

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
    iput v1, v0, Llm/a;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Llm/a;

    .line 21
    .line 22
    invoke-direct {v0, p3}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Llm/a;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Llm/a;->g:I

    .line 30
    .line 31
    const/4 v3, 0x3

    .line 32
    const/4 v4, 0x2

    .line 33
    const/4 v5, 0x1

    .line 34
    const/4 v6, 0x0

    .line 35
    if-eqz v2, :cond_4

    .line 36
    .line 37
    if-eq v2, v5, :cond_3

    .line 38
    .line 39
    if-eq v2, v4, :cond_2

    .line 40
    .line 41
    if-ne v2, v3, :cond_1

    .line 42
    .line 43
    iget-object p0, v0, Llm/a;->e:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast p0, Ljava/io/Closeable;

    .line 46
    .line 47
    :try_start_0
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 48
    .line 49
    .line 50
    goto/16 :goto_4

    .line 51
    .line 52
    :catchall_0
    move-exception p1

    .line 53
    goto/16 :goto_5

    .line 54
    .line 55
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 56
    .line 57
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 58
    .line 59
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    throw p0

    .line 63
    :cond_2
    iget-object p0, v0, Llm/a;->d:Lay0/n;

    .line 64
    .line 65
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    goto :goto_2

    .line 69
    :cond_3
    iget-object p0, v0, Llm/a;->e:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast p0, Ld01/i;

    .line 72
    .line 73
    iget-object p2, v0, Llm/a;->d:Lay0/n;

    .line 74
    .line 75
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    goto :goto_1

    .line 79
    :cond_4
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    iput-object p2, v0, Llm/a;->d:Lay0/n;

    .line 83
    .line 84
    iput-object p0, v0, Llm/a;->e:Ljava/lang/Object;

    .line 85
    .line 86
    iput v5, v0, Llm/a;->g:I

    .line 87
    .line 88
    invoke-static {p1, v0}, Llp/vf;->b(Lim/q;Lrx0/c;)Ld01/k0;

    .line 89
    .line 90
    .line 91
    move-result-object p3

    .line 92
    if-ne p3, v1, :cond_5

    .line 93
    .line 94
    goto :goto_3

    .line 95
    :cond_5
    :goto_1
    check-cast p3, Ld01/k0;

    .line 96
    .line 97
    invoke-interface {p0, p3}, Ld01/i;->newCall(Ld01/k0;)Ld01/j;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    iput-object p2, v0, Llm/a;->d:Lay0/n;

    .line 102
    .line 103
    iput-object v6, v0, Llm/a;->e:Ljava/lang/Object;

    .line 104
    .line 105
    iput v4, v0, Llm/a;->g:I

    .line 106
    .line 107
    new-instance p1, Lvy0/l;

    .line 108
    .line 109
    invoke-static {v0}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 110
    .line 111
    .line 112
    move-result-object p3

    .line 113
    invoke-direct {p1, v5, p3}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {p1}, Lvy0/l;->q()V

    .line 117
    .line 118
    .line 119
    new-instance p3, Llm/c;

    .line 120
    .line 121
    const/4 v2, 0x0

    .line 122
    invoke-direct {p3, p0, p1, v2}, Llm/c;-><init>(Ld01/j;Lvy0/l;I)V

    .line 123
    .line 124
    .line 125
    invoke-static {p0, p3}, Lcom/google/firebase/perf/network/FirebasePerfOkHttpClient;->enqueue(Ld01/j;Ld01/k;)V

    .line 126
    .line 127
    .line 128
    invoke-virtual {p1, p3}, Lvy0/l;->s(Lay0/k;)V

    .line 129
    .line 130
    .line 131
    invoke-virtual {p1}, Lvy0/l;->p()Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object p3

    .line 135
    if-ne p3, v1, :cond_6

    .line 136
    .line 137
    goto :goto_3

    .line 138
    :cond_6
    move-object p0, p2

    .line 139
    :goto_2
    move-object p1, p3

    .line 140
    check-cast p1, Ljava/io/Closeable;

    .line 141
    .line 142
    :try_start_1
    move-object p2, p1

    .line 143
    check-cast p2, Ld01/t0;

    .line 144
    .line 145
    invoke-static {p2}, Llp/vf;->a(Ld01/t0;)Lim/r;

    .line 146
    .line 147
    .line 148
    move-result-object p2

    .line 149
    iput-object v6, v0, Llm/a;->d:Lay0/n;

    .line 150
    .line 151
    iput-object p1, v0, Llm/a;->e:Ljava/lang/Object;

    .line 152
    .line 153
    iput v3, v0, Llm/a;->g:I

    .line 154
    .line 155
    invoke-interface {p0, p2, v0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object p3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 159
    if-ne p3, v1, :cond_7

    .line 160
    .line 161
    :goto_3
    return-object v1

    .line 162
    :cond_7
    move-object p0, p1

    .line 163
    :goto_4
    invoke-static {p0, v6}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 164
    .line 165
    .line 166
    return-object p3

    .line 167
    :catchall_1
    move-exception p0

    .line 168
    move-object v7, p1

    .line 169
    move-object p1, p0

    .line 170
    move-object p0, v7

    .line 171
    :goto_5
    :try_start_2
    throw p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 172
    :catchall_2
    move-exception p2

    .line 173
    invoke-static {p0, p1}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 174
    .line 175
    .line 176
    throw p2
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Llm/b;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    check-cast p1, Llm/b;

    .line 7
    .line 8
    iget-object p1, p1, Llm/b;->a:Ld01/i;

    .line 9
    .line 10
    iget-object p0, p0, Llm/b;->a:Ld01/i;

    .line 11
    .line 12
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    if-nez p0, :cond_1

    .line 17
    .line 18
    :goto_0
    const/4 p0, 0x0

    .line 19
    return p0

    .line 20
    :cond_1
    const/4 p0, 0x1

    .line 21
    return p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Llm/b;->a:Ld01/i;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "CallFactoryNetworkClient(callFactory="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Llm/b;->a:Ld01/i;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const/16 p0, 0x29

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method
