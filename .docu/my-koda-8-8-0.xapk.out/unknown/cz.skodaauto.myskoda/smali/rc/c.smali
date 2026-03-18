.class public abstract Lrc/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;)Ljava/lang/Object;
    .locals 8

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    check-cast p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;

    .line 11
    .line 12
    invoke-virtual {p0}, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;->getValue()Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0

    .line 17
    :cond_0
    instance-of v0, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;

    .line 18
    .line 19
    if-eqz v0, :cond_1

    .line 20
    .line 21
    new-instance v0, Lrc/a;

    .line 22
    .line 23
    check-cast p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;

    .line 24
    .line 25
    invoke-virtual {p0}, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->getCode()I

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    invoke-virtual {p0}, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->getError()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    check-cast v2, Ltb/c;

    .line 34
    .line 35
    invoke-virtual {p0}, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->getTraceContext()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    invoke-virtual {p0}, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->getMessage()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    invoke-direct {v0, v1, v2, v3, p0}, Lrc/a;-><init>(ILtb/c;Ljava/lang/String;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    return-object p0

    .line 51
    :cond_1
    instance-of v0, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$NetworkError;

    .line 52
    .line 53
    const-string v1, "Kt"

    .line 54
    .line 55
    const/16 v2, 0x2e

    .line 56
    .line 57
    const/16 v3, 0x24

    .line 58
    .line 59
    if-eqz v0, :cond_3

    .line 60
    .line 61
    sget-object v0, Lgi/b;->h:Lgi/b;

    .line 62
    .line 63
    move-object v4, p0

    .line 64
    check-cast v4, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$NetworkError;

    .line 65
    .line 66
    invoke-virtual {v4}, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$NetworkError;->getError()Ljava/io/IOException;

    .line 67
    .line 68
    .line 69
    move-result-object v5

    .line 70
    new-instance v6, Lr40/e;

    .line 71
    .line 72
    const/4 v7, 0x3

    .line 73
    invoke-direct {v6, v7}, Lr40/e;-><init>(I)V

    .line 74
    .line 75
    .line 76
    sget-object v7, Lgi/a;->e:Lgi/a;

    .line 77
    .line 78
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    invoke-static {p0, v3}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object v3

    .line 90
    invoke-static {v2, v3, v3}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object v2

    .line 94
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 95
    .line 96
    .line 97
    move-result v3

    .line 98
    if-nez v3, :cond_2

    .line 99
    .line 100
    goto :goto_0

    .line 101
    :cond_2
    invoke-static {v2, v1}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    :goto_0
    invoke-static {p0, v7, v0, v5, v6}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 106
    .line 107
    .line 108
    invoke-virtual {v4}, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$NetworkError;->getError()Ljava/io/IOException;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    return-object p0

    .line 117
    :cond_3
    instance-of v0, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$UnknownError;

    .line 118
    .line 119
    if-eqz v0, :cond_5

    .line 120
    .line 121
    sget-object v0, Lgi/b;->h:Lgi/b;

    .line 122
    .line 123
    move-object v4, p0

    .line 124
    check-cast v4, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$UnknownError;

    .line 125
    .line 126
    invoke-virtual {v4}, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$UnknownError;->getError()Ljava/lang/Throwable;

    .line 127
    .line 128
    .line 129
    move-result-object v5

    .line 130
    new-instance v6, Lr40/e;

    .line 131
    .line 132
    const/4 v7, 0x4

    .line 133
    invoke-direct {v6, v7}, Lr40/e;-><init>(I)V

    .line 134
    .line 135
    .line 136
    sget-object v7, Lgi/a;->e:Lgi/a;

    .line 137
    .line 138
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 143
    .line 144
    .line 145
    move-result-object p0

    .line 146
    invoke-static {p0, v3}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 147
    .line 148
    .line 149
    move-result-object v3

    .line 150
    invoke-static {v2, v3, v3}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 151
    .line 152
    .line 153
    move-result-object v2

    .line 154
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 155
    .line 156
    .line 157
    move-result v3

    .line 158
    if-nez v3, :cond_4

    .line 159
    .line 160
    goto :goto_1

    .line 161
    :cond_4
    invoke-static {v2, v1}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 162
    .line 163
    .line 164
    move-result-object p0

    .line 165
    :goto_1
    invoke-static {p0, v7, v0, v5, v6}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 166
    .line 167
    .line 168
    invoke-virtual {v4}, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$UnknownError;->getError()Ljava/lang/Throwable;

    .line 169
    .line 170
    .line 171
    move-result-object p0

    .line 172
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 173
    .line 174
    .line 175
    move-result-object p0

    .line 176
    return-object p0

    .line 177
    :cond_5
    new-instance p0, La8/r0;

    .line 178
    .line 179
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 180
    .line 181
    .line 182
    throw p0
.end method
