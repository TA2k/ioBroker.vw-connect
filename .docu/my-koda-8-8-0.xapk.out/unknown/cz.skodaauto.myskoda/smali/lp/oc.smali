.class public abstract Llp/oc;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lvy/d;Lij0/a;Z)Lvy/d;
    .locals 12

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "stringResource"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    new-array v0, v0, [Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p1, Ljj0/f;

    .line 15
    .line 16
    const v1, 0x7f120022

    .line 17
    .line 18
    .line 19
    invoke-virtual {p1, v1, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v5

    .line 23
    const/4 v10, 0x0

    .line 24
    const/16 v11, 0x38b

    .line 25
    .line 26
    const/4 v3, 0x0

    .line 27
    const/4 v4, 0x0

    .line 28
    const/4 v6, 0x0

    .line 29
    const/4 v8, 0x0

    .line 30
    const/4 v9, 0x0

    .line 31
    move-object v2, p0

    .line 32
    move v7, p2

    .line 33
    invoke-static/range {v2 .. v11}, Lvy/d;->a(Lvy/d;Llf0/i;Ljava/lang/String;Ljava/lang/String;ZZZZZI)Lvy/d;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    return-object p0
.end method

.method public static final b(Lvy/d;Luy/b;Lij0/a;Z)Lvy/d;
    .locals 11

    .line 1
    const-string v2, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v2, "status"

    .line 7
    .line 8
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v2, p1, Luy/b;->a:Ljava/time/OffsetDateTime;

    .line 12
    .line 13
    iget-object v3, p1, Luy/b;->b:Luy/a;

    .line 14
    .line 15
    const-string v4, "stringResource"

    .line 16
    .line 17
    invoke-static {p2, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    :try_start_0
    invoke-static {v3}, Llp/pa;->c(Luy/a;)Z

    .line 21
    .line 22
    .line 23
    move-result v4

    .line 24
    if-eqz v4, :cond_8

    .line 25
    .line 26
    invoke-static {v3}, Llp/pa;->b(Luy/a;)Z

    .line 27
    .line 28
    .line 29
    move-result v6

    .line 30
    if-eqz v6, :cond_0

    .line 31
    .line 32
    const/4 v0, 0x0

    .line 33
    if-eqz v2, :cond_1

    .line 34
    .line 35
    invoke-static {v2}, Lvo/a;->a(Ljava/time/OffsetDateTime;)J

    .line 36
    .line 37
    .line 38
    move-result-wide v4

    .line 39
    new-instance v7, Lmy0/c;

    .line 40
    .line 41
    invoke-direct {v7, v4, v5}, Lmy0/c;-><init>(J)V

    .line 42
    .line 43
    .line 44
    invoke-static {v4, v5}, Lmy0/c;->i(J)Z

    .line 45
    .line 46
    .line 47
    move-result v4

    .line 48
    if-eqz v4, :cond_1

    .line 49
    .line 50
    move-object v0, v7

    .line 51
    goto :goto_0

    .line 52
    :catchall_0
    move-exception v0

    .line 53
    goto/16 :goto_2

    .line 54
    .line 55
    :cond_0
    iget-wide v4, p1, Luy/b;->c:J

    .line 56
    .line 57
    new-instance v0, Lmy0/c;

    .line 58
    .line 59
    invoke-direct {v0, v4, v5}, Lmy0/c;-><init>(J)V

    .line 60
    .line 61
    .line 62
    :cond_1
    :goto_0
    if-eqz p3, :cond_2

    .line 63
    .line 64
    const v2, 0x7f120022

    .line 65
    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_2
    invoke-static {v3}, Llp/pa;->b(Luy/a;)Z

    .line 69
    .line 70
    .line 71
    move-result v3

    .line 72
    if-eqz v3, :cond_4

    .line 73
    .line 74
    if-eqz v2, :cond_3

    .line 75
    .line 76
    invoke-static {v2}, Lvo/a;->a(Ljava/time/OffsetDateTime;)J

    .line 77
    .line 78
    .line 79
    move-result-wide v2

    .line 80
    invoke-static {v2, v3}, Lmy0/c;->h(J)Z

    .line 81
    .line 82
    .line 83
    move-result v2

    .line 84
    if-eqz v2, :cond_4

    .line 85
    .line 86
    :cond_3
    const v2, 0x7f120023

    .line 87
    .line 88
    .line 89
    goto :goto_1

    .line 90
    :cond_4
    if-eqz v6, :cond_5

    .line 91
    .line 92
    const v2, 0x7f120025

    .line 93
    .line 94
    .line 95
    goto :goto_1

    .line 96
    :cond_5
    const v2, 0x7f120024

    .line 97
    .line 98
    .line 99
    :goto_1
    const/4 v3, 0x0

    .line 100
    if-eqz v0, :cond_6

    .line 101
    .line 102
    iget-wide v4, v0, Lmy0/c;->d:J

    .line 103
    .line 104
    invoke-static {v4, v5, p2}, Ljp/d1;->f(JLij0/a;)Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v0

    .line 108
    if-nez v0, :cond_7

    .line 109
    .line 110
    :cond_6
    new-array v0, v3, [Ljava/lang/Object;

    .line 111
    .line 112
    move-object v4, p2

    .line 113
    check-cast v4, Ljj0/f;

    .line 114
    .line 115
    const v5, 0x7f1201aa

    .line 116
    .line 117
    .line 118
    invoke-virtual {v4, v5, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object v0

    .line 122
    :cond_7
    sget-object v4, Llf0/i;->j:Llf0/i;

    .line 123
    .line 124
    new-array v3, v3, [Ljava/lang/Object;

    .line 125
    .line 126
    move-object v5, p2

    .line 127
    check-cast v5, Ljj0/f;

    .line 128
    .line 129
    invoke-virtual {v5, v2, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 130
    .line 131
    .line 132
    move-result-object v2

    .line 133
    xor-int/lit8 v5, p3, 0x1

    .line 134
    .line 135
    const/4 v9, 0x0

    .line 136
    const/16 v10, 0x3c0

    .line 137
    .line 138
    const/4 v7, 0x0

    .line 139
    const/4 v8, 0x0

    .line 140
    move-object v1, v4

    .line 141
    move-object v4, v2

    .line 142
    move-object v2, v1

    .line 143
    move-object v1, p0

    .line 144
    move-object v3, v0

    .line 145
    invoke-static/range {v1 .. v10}, Lvy/d;->a(Lvy/d;Llf0/i;Ljava/lang/String;Ljava/lang/String;ZZZZZI)Lvy/d;

    .line 146
    .line 147
    .line 148
    move-result-object v0

    .line 149
    goto :goto_3

    .line 150
    :cond_8
    const-string v0, "Failed requirement."

    .line 151
    .line 152
    new-instance v2, Ljava/lang/IllegalArgumentException;

    .line 153
    .line 154
    invoke-direct {v2, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 155
    .line 156
    .line 157
    throw v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 158
    :goto_2
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 159
    .line 160
    .line 161
    move-result-object v0

    .line 162
    :goto_3
    invoke-static {v0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 163
    .line 164
    .line 165
    move-result-object v2

    .line 166
    if-nez v2, :cond_9

    .line 167
    .line 168
    goto :goto_4

    .line 169
    :cond_9
    invoke-static {p0, p2}, Llp/oc;->d(Lvy/d;Lij0/a;)Lvy/d;

    .line 170
    .line 171
    .line 172
    move-result-object v0

    .line 173
    :goto_4
    check-cast v0, Lvy/d;

    .line 174
    .line 175
    return-object v0
.end method

.method public static c(II)I
    .locals 5

    .line 1
    int-to-long v0, p0

    .line 2
    int-to-long v2, p1

    .line 3
    add-long/2addr v0, v2

    .line 4
    long-to-int v2, v0

    .line 5
    int-to-long v3, v2

    .line 6
    cmp-long v0, v0, v3

    .line 7
    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 v0, 0x0

    .line 13
    :goto_0
    if-eqz v0, :cond_1

    .line 14
    .line 15
    return v2

    .line 16
    :cond_1
    new-instance v0, Ljava/lang/ArithmeticException;

    .line 17
    .line 18
    const-string v1, ", "

    .line 19
    .line 20
    const-string v2, ")"

    .line 21
    .line 22
    const-string v3, "overflow: checkedAdd("

    .line 23
    .line 24
    invoke-static {p0, p1, v3, v1, v2}, Lf2/m0;->f(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-direct {v0, p0}, Ljava/lang/ArithmeticException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw v0
.end method

.method public static final d(Lvy/d;Lij0/a;)Lvy/d;
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "stringResource"

    .line 7
    .line 8
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const/4 p0, 0x0

    .line 12
    new-array v0, p0, [Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p1, Ljj0/f;

    .line 15
    .line 16
    const v1, 0x7f1202bd

    .line 17
    .line 18
    .line 19
    invoke-virtual {p1, v1, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    const v1, 0x7f1201aa

    .line 24
    .line 25
    .line 26
    new-array p0, p0, [Ljava/lang/Object;

    .line 27
    .line 28
    invoke-virtual {p1, v1, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    sget-object p1, Llf0/i;->j:Llf0/i;

    .line 33
    .line 34
    new-instance v1, Lvy/d;

    .line 35
    .line 36
    const/16 v2, 0x3e0

    .line 37
    .line 38
    invoke-direct {v1, p1, v0, p0, v2}, Lvy/d;-><init>(Llf0/i;Ljava/lang/String;Ljava/lang/String;I)V

    .line 39
    .line 40
    .line 41
    return-object v1
.end method
