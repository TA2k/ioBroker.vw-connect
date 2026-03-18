.class public abstract Llp/q1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a()Lh21/b;
    .locals 1

    .line 1
    sget-object v0, Li21/b;->e:Lh21/b;

    .line 2
    .line 3
    return-object v0
.end method

.method public static b(Lkg/i;)Lug/d;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    const-string v1, "conditionsDetailElement"

    .line 4
    .line 5
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Lkg/i;->g:Ljava/lang/String;

    .line 9
    .line 10
    const-string v2, ""

    .line 11
    .line 12
    if-nez v1, :cond_0

    .line 13
    .line 14
    move-object v4, v2

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    move-object v4, v1

    .line 17
    :goto_0
    iget-object v3, v0, Lkg/i;->d:Ljava/util/List;

    .line 18
    .line 19
    check-cast v3, Ljava/lang/Iterable;

    .line 20
    .line 21
    new-instance v5, Ljava/util/ArrayList;

    .line 22
    .line 23
    const/16 v6, 0xa

    .line 24
    .line 25
    invoke-static {v3, v6}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 26
    .line 27
    .line 28
    move-result v6

    .line 29
    invoke-direct {v5, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 30
    .line 31
    .line 32
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 33
    .line 34
    .line 35
    move-result-object v3

    .line 36
    :goto_1
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 37
    .line 38
    .line 39
    move-result v6

    .line 40
    const/4 v7, 0x0

    .line 41
    const/4 v8, 0x1

    .line 42
    if-eqz v6, :cond_5

    .line 43
    .line 44
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v6

    .line 48
    check-cast v6, Lkg/f;

    .line 49
    .line 50
    const-string v9, "conditionsSummaryElement"

    .line 51
    .line 52
    invoke-static {v6, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    iget-object v11, v6, Lkg/f;->d:Ljava/lang/String;

    .line 56
    .line 57
    iget-object v9, v6, Lkg/f;->f:Ljava/lang/String;

    .line 58
    .line 59
    if-nez v9, :cond_1

    .line 60
    .line 61
    move-object v12, v2

    .line 62
    goto :goto_2

    .line 63
    :cond_1
    move-object v12, v9

    .line 64
    :goto_2
    if-eqz v9, :cond_2

    .line 65
    .line 66
    move v13, v8

    .line 67
    goto :goto_3

    .line 68
    :cond_2
    move v13, v7

    .line 69
    :goto_3
    iget-object v9, v6, Lkg/f;->g:Ljava/lang/String;

    .line 70
    .line 71
    if-nez v9, :cond_3

    .line 72
    .line 73
    move-object v15, v2

    .line 74
    goto :goto_4

    .line 75
    :cond_3
    move-object v15, v9

    .line 76
    :goto_4
    iget-object v14, v6, Lkg/f;->e:Ljava/lang/String;

    .line 77
    .line 78
    if-eqz v9, :cond_4

    .line 79
    .line 80
    move/from16 v16, v8

    .line 81
    .line 82
    goto :goto_5

    .line 83
    :cond_4
    move/from16 v16, v7

    .line 84
    .line 85
    :goto_5
    new-instance v10, Lug/c;

    .line 86
    .line 87
    invoke-direct/range {v10 .. v16}, Lug/c;-><init>(Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;Z)V

    .line 88
    .line 89
    .line 90
    invoke-virtual {v5, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    goto :goto_1

    .line 94
    :cond_5
    if-eqz v1, :cond_6

    .line 95
    .line 96
    move v6, v8

    .line 97
    goto :goto_6

    .line 98
    :cond_6
    move v6, v7

    .line 99
    :goto_6
    iget-object v0, v0, Lkg/i;->e:Ljava/lang/String;

    .line 100
    .line 101
    if-nez v0, :cond_7

    .line 102
    .line 103
    goto :goto_7

    .line 104
    :cond_7
    move-object v2, v0

    .line 105
    :goto_7
    if-eqz v0, :cond_8

    .line 106
    .line 107
    goto :goto_8

    .line 108
    :cond_8
    move v8, v7

    .line 109
    :goto_8
    new-instance v3, Lug/d;

    .line 110
    .line 111
    move-object v7, v2

    .line 112
    invoke-direct/range {v3 .. v8}, Lug/d;-><init>(Ljava/lang/String;Ljava/util/ArrayList;ZLjava/lang/String;Z)V

    .line 113
    .line 114
    .line 115
    return-object v3
.end method
