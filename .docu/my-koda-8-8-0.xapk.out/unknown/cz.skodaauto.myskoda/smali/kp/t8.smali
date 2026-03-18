.class public abstract Lkp/t8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lss0/b;Z)Lga0/v;
    .locals 11

    .line 1
    invoke-static {}, Lkp/t8;->c()Lga0/u;

    .line 2
    .line 3
    .line 4
    move-result-object v4

    .line 5
    invoke-static {}, Lkp/t8;->c()Lga0/u;

    .line 6
    .line 7
    .line 8
    move-result-object v5

    .line 9
    invoke-static {}, Lkp/t8;->c()Lga0/u;

    .line 10
    .line 11
    .line 12
    move-result-object v3

    .line 13
    invoke-static {}, Lkp/t8;->c()Lga0/u;

    .line 14
    .line 15
    .line 16
    move-result-object v8

    .line 17
    invoke-static {}, Lkp/t8;->c()Lga0/u;

    .line 18
    .line 19
    .line 20
    move-result-object v6

    .line 21
    invoke-static {}, Lkp/t8;->c()Lga0/u;

    .line 22
    .line 23
    .line 24
    move-result-object v7

    .line 25
    sget-object v0, Lga0/t;->d:Lga0/t;

    .line 26
    .line 27
    sget-object v0, Lss0/e;->G1:Lss0/e;

    .line 28
    .line 29
    invoke-static {p0, v0}, Lkp/u6;->d(Lss0/b;Lss0/e;)Ler0/g;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    invoke-static {p0, v0}, Llp/pf;->i(Lss0/b;Lss0/e;)Llf0/i;

    .line 34
    .line 35
    .line 36
    move-result-object v9

    .line 37
    new-instance v0, Lga0/v;

    .line 38
    .line 39
    const v10, 0x8010

    .line 40
    .line 41
    .line 42
    move v2, p1

    .line 43
    invoke-direct/range {v0 .. v10}, Lga0/v;-><init>(Ler0/g;ZLga0/u;Lga0/u;Lga0/u;Lga0/u;Lga0/u;Lga0/u;Llf0/i;I)V

    .line 44
    .line 45
    .line 46
    return-object v0
.end method

.method public static final b(Ljava/util/ArrayList;Lio/ktor/utils/io/t;Lzw0/a;Ljava/nio/charset/Charset;Lrx0/c;)Ljava/lang/Object;
    .locals 11

    .line 1
    instance-of v0, p4, Lsw0/d;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p4

    .line 6
    check-cast v0, Lsw0/d;

    .line 7
    .line 8
    iget v1, v0, Lsw0/d;->g:I

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
    iput v1, v0, Lsw0/d;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lsw0/d;

    .line 21
    .line 22
    invoke-direct {v0, p4}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p4, v0, Lsw0/d;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lsw0/d;->g:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    const/4 v4, 0x0

    .line 33
    if-eqz v2, :cond_2

    .line 34
    .line 35
    if-ne v2, v3, :cond_1

    .line 36
    .line 37
    iget-object p2, v0, Lsw0/d;->e:Lzw0/a;

    .line 38
    .line 39
    iget-object p1, v0, Lsw0/d;->d:Lio/ktor/utils/io/t;

    .line 40
    .line 41
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 46
    .line 47
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 48
    .line 49
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_2
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    new-instance v6, Lam0/i;

    .line 57
    .line 58
    const/16 p4, 0x1c

    .line 59
    .line 60
    invoke-direct {v6, p0, p4}, Lam0/i;-><init>(Ljava/lang/Object;I)V

    .line 61
    .line 62
    .line 63
    new-instance v5, Lsw0/c;

    .line 64
    .line 65
    const/4 v10, 0x0

    .line 66
    move-object v9, p1

    .line 67
    move-object v8, p2

    .line 68
    move-object v7, p3

    .line 69
    invoke-direct/range {v5 .. v10}, Lsw0/c;-><init>(Lyy0/i;Ljava/lang/Comparable;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 70
    .line 71
    .line 72
    new-instance p0, Lsw0/e;

    .line 73
    .line 74
    const/4 p1, 0x0

    .line 75
    invoke-direct {p0, v9, v4, p1}, Lsw0/e;-><init>(Lio/ktor/utils/io/t;Lkotlin/coroutines/Continuation;I)V

    .line 76
    .line 77
    .line 78
    iput-object v9, v0, Lsw0/d;->d:Lio/ktor/utils/io/t;

    .line 79
    .line 80
    iput-object v8, v0, Lsw0/d;->e:Lzw0/a;

    .line 81
    .line 82
    iput v3, v0, Lsw0/d;->g:I

    .line 83
    .line 84
    invoke-static {v5, p0, v0}, Lyy0/u;->v(Lyy0/i;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p4

    .line 88
    if-ne p4, v1, :cond_3

    .line 89
    .line 90
    return-object v1

    .line 91
    :cond_3
    move-object p2, v8

    .line 92
    move-object p1, v9

    .line 93
    :goto_1
    if-nez p4, :cond_6

    .line 94
    .line 95
    invoke-interface {p1}, Lio/ktor/utils/io/t;->g()Z

    .line 96
    .line 97
    .line 98
    move-result p0

    .line 99
    if-nez p0, :cond_4

    .line 100
    .line 101
    return-object p1

    .line 102
    :cond_4
    iget-object p0, p2, Lzw0/a;->b:Lhy0/a0;

    .line 103
    .line 104
    if-eqz p0, :cond_5

    .line 105
    .line 106
    invoke-interface {p0}, Lhy0/a0;->isMarkedNullable()Z

    .line 107
    .line 108
    .line 109
    move-result p0

    .line 110
    if-ne p0, v3, :cond_5

    .line 111
    .line 112
    sget-object p0, Lrw0/b;->a:Lrw0/b;

    .line 113
    .line 114
    return-object p0

    .line 115
    :cond_5
    new-instance p0, Lb0/l;

    .line 116
    .line 117
    new-instance p1, Ljava/lang/StringBuilder;

    .line 118
    .line 119
    const-string p3, "No suitable converter found for "

    .line 120
    .line 121
    invoke-direct {p1, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 125
    .line 126
    .line 127
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 128
    .line 129
    .line 130
    move-result-object p1

    .line 131
    const-string p2, "message"

    .line 132
    .line 133
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    invoke-direct {p0, p1, v4}, Ljava/lang/Exception;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 137
    .line 138
    .line 139
    throw p0

    .line 140
    :cond_6
    return-object p4
.end method

.method public static final c()Lga0/u;
    .locals 3

    .line 1
    new-instance v0, Lga0/u;

    .line 2
    .line 3
    sget-object v1, Lst0/n;->f:Lst0/n;

    .line 4
    .line 5
    const v2, 0x7f1201aa

    .line 6
    .line 7
    .line 8
    invoke-direct {v0, v1, v2}, Lga0/u;-><init>(Lst0/n;I)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method

.method public static final d(Lij0/a;)Lzt0/a;
    .locals 9

    .line 1
    const-string v0, "stringResource"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    new-array v1, v0, [Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Ljj0/f;

    .line 10
    .line 11
    const v2, 0x7f1214e0

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0, v2, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v4

    .line 18
    const v1, 0x7f1214de

    .line 19
    .line 20
    .line 21
    new-array v2, v0, [Ljava/lang/Object;

    .line 22
    .line 23
    invoke-virtual {p0, v1, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v6

    .line 27
    const v1, 0x7f12038c

    .line 28
    .line 29
    .line 30
    new-array v2, v0, [Ljava/lang/Object;

    .line 31
    .line 32
    invoke-virtual {p0, v1, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v8

    .line 36
    const v1, 0x7f1214df

    .line 37
    .line 38
    .line 39
    new-array v0, v0, [Ljava/lang/Object;

    .line 40
    .line 41
    invoke-virtual {p0, v1, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v7

    .line 45
    new-instance v3, Lzt0/a;

    .line 46
    .line 47
    const/16 v5, 0x28

    .line 48
    .line 49
    invoke-direct/range {v3 .. v8}, Lzt0/a;-><init>(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    return-object v3
.end method

.method public static final e(Lga0/v;)Lga0/v;
    .locals 17

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    move-object/from16 v1, p0

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object v3, Lga0/t;->e:Lga0/t;

    .line 9
    .line 10
    const/4 v15, 0x0

    .line 11
    const v16, 0xffeb

    .line 12
    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    const/4 v4, 0x0

    .line 16
    const/4 v5, 0x0

    .line 17
    const/4 v6, 0x0

    .line 18
    const/4 v7, 0x0

    .line 19
    const/4 v8, 0x0

    .line 20
    const/4 v9, 0x0

    .line 21
    const/4 v10, 0x0

    .line 22
    const/4 v11, 0x0

    .line 23
    const/4 v12, 0x0

    .line 24
    const/4 v13, 0x0

    .line 25
    const/4 v14, 0x0

    .line 26
    invoke-static/range {v1 .. v16}, Lga0/v;->a(Lga0/v;Landroid/net/Uri;Lga0/t;ZZZZZLga0/u;Lga0/u;Lga0/u;Lga0/u;Lga0/u;Lga0/u;Ljava/time/OffsetDateTime;I)Lga0/v;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    return-object v0
.end method

.method public static final f(Lga0/v;)Lga0/v;
    .locals 17

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    move-object/from16 v1, p0

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object v3, Lga0/t;->g:Lga0/t;

    .line 9
    .line 10
    const/4 v15, 0x0

    .line 11
    const v16, 0xffeb

    .line 12
    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    const/4 v4, 0x0

    .line 16
    const/4 v5, 0x0

    .line 17
    const/4 v6, 0x0

    .line 18
    const/4 v7, 0x0

    .line 19
    const/4 v8, 0x0

    .line 20
    const/4 v9, 0x0

    .line 21
    const/4 v10, 0x0

    .line 22
    const/4 v11, 0x0

    .line 23
    const/4 v12, 0x0

    .line 24
    const/4 v13, 0x0

    .line 25
    const/4 v14, 0x0

    .line 26
    invoke-static/range {v1 .. v16}, Lga0/v;->a(Lga0/v;Landroid/net/Uri;Lga0/t;ZZZZZLga0/u;Lga0/u;Lga0/u;Lga0/u;Lga0/u;Lga0/u;Ljava/time/OffsetDateTime;I)Lga0/v;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    return-object v0
.end method
