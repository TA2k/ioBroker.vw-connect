.class public final Ldg/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkj/c;


# instance fields
.field public final a:Lag/c;


# direct methods
.method public constructor <init>(Lag/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ldg/f;->a:Lag/c;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Leg/c;Lrx0/c;)Ljava/lang/Object;
    .locals 9

    .line 1
    instance-of v0, p2, Ldg/d;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Ldg/d;

    .line 7
    .line 8
    iget v1, v0, Ldg/d;->f:I

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
    iput v1, v0, Ldg/d;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ldg/d;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Ldg/d;-><init>(Ldg/f;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Ldg/d;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ldg/d;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    iput v3, v0, Ldg/d;->f:I

    .line 52
    .line 53
    iget-object p0, p0, Ldg/f;->a:Lag/c;

    .line 54
    .line 55
    invoke-virtual {p0, p1, v0}, Lag/c;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p2

    .line 59
    if-ne p2, v1, :cond_3

    .line 60
    .line 61
    return-object v1

    .line 62
    :cond_3
    :goto_1
    check-cast p2, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;

    .line 63
    .line 64
    invoke-static {p2}, Lkp/j0;->b(Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    instance-of p1, p0, Llx0/n;

    .line 69
    .line 70
    if-nez p1, :cond_4

    .line 71
    .line 72
    :try_start_0
    check-cast p0, Leg/f;

    .line 73
    .line 74
    invoke-static {p0}, Ldg/g;->a(Leg/f;)Ldg/a;

    .line 75
    .line 76
    .line 77
    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 78
    goto :goto_2

    .line 79
    :catchall_0
    move-exception p0

    .line 80
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    :cond_4
    :goto_2
    instance-of p1, p0, Llx0/n;

    .line 85
    .line 86
    const/4 p2, 0x0

    .line 87
    const-string v0, "Kt"

    .line 88
    .line 89
    const/16 v1, 0x2e

    .line 90
    .line 91
    const/16 v2, 0x24

    .line 92
    .line 93
    const-class v3, Ldg/f;

    .line 94
    .line 95
    if-nez p1, :cond_6

    .line 96
    .line 97
    move-object p1, p0

    .line 98
    check-cast p1, Ldg/a;

    .line 99
    .line 100
    new-instance v4, Ldg/b;

    .line 101
    .line 102
    const/4 v5, 0x0

    .line 103
    invoke-direct {v4, p1, v5}, Ldg/b;-><init>(Ldg/a;I)V

    .line 104
    .line 105
    .line 106
    sget-object p1, Lgi/b;->e:Lgi/b;

    .line 107
    .line 108
    sget-object v5, Lgi/a;->e:Lgi/a;

    .line 109
    .line 110
    invoke-virtual {v3}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object v6

    .line 114
    invoke-static {v6, v2}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v7

    .line 118
    invoke-static {v1, v7, v7}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object v7

    .line 122
    invoke-virtual {v7}, Ljava/lang/String;->length()I

    .line 123
    .line 124
    .line 125
    move-result v8

    .line 126
    if-nez v8, :cond_5

    .line 127
    .line 128
    goto :goto_3

    .line 129
    :cond_5
    invoke-static {v7, v0}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 130
    .line 131
    .line 132
    move-result-object v6

    .line 133
    :goto_3
    invoke-static {v6, v5, p1, p2, v4}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 134
    .line 135
    .line 136
    :cond_6
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 137
    .line 138
    .line 139
    move-result-object p1

    .line 140
    if-eqz p1, :cond_8

    .line 141
    .line 142
    sget-object v4, Lgi/b;->h:Lgi/b;

    .line 143
    .line 144
    new-instance v5, Ldg/c;

    .line 145
    .line 146
    const/4 v6, 0x0

    .line 147
    invoke-direct {v5, p1, v6}, Ldg/c;-><init>(Ljava/lang/Throwable;I)V

    .line 148
    .line 149
    .line 150
    sget-object p1, Lgi/a;->e:Lgi/a;

    .line 151
    .line 152
    invoke-virtual {v3}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 153
    .line 154
    .line 155
    move-result-object v3

    .line 156
    invoke-static {v3, v2}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 157
    .line 158
    .line 159
    move-result-object v2

    .line 160
    invoke-static {v1, v2, v2}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 161
    .line 162
    .line 163
    move-result-object v1

    .line 164
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 165
    .line 166
    .line 167
    move-result v2

    .line 168
    if-nez v2, :cond_7

    .line 169
    .line 170
    goto :goto_4

    .line 171
    :cond_7
    invoke-static {v1, v0}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 172
    .line 173
    .line 174
    move-result-object v3

    .line 175
    :goto_4
    invoke-static {v3, p1, v4, p2, v5}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 176
    .line 177
    .line 178
    :cond_8
    return-object p0
.end method

.method public final b(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Ldg/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Ldg/e;

    .line 7
    .line 8
    iget v1, v0, Ldg/e;->f:I

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
    iput v1, v0, Ldg/e;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ldg/e;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Ldg/e;-><init>(Ldg/f;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Ldg/e;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ldg/e;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    check-cast p2, Llx0/o;

    .line 40
    .line 41
    iget-object p0, p2, Llx0/o;->d:Ljava/lang/Object;

    .line 42
    .line 43
    return-object p0

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    new-instance p2, Leg/c;

    .line 56
    .line 57
    invoke-direct {p2, p1}, Leg/c;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    iput v3, v0, Ldg/e;->f:I

    .line 61
    .line 62
    invoke-virtual {p0, p2, v0}, Ldg/f;->a(Leg/c;Lrx0/c;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    if-ne p0, v1, :cond_3

    .line 67
    .line 68
    return-object v1

    .line 69
    :cond_3
    return-object p0
.end method
