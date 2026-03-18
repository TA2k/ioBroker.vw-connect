.class public abstract Llp/ga;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Lqp/h;Lw3/g1;Ll2/r;)V
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0, p1, p2}, Llp/ga;->b(Lqp/h;Lw3/a;Ll2/r;)Luu/p0;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p0}, Luu/p0;->close()V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public static final b(Lqp/h;Lw3/a;Ll2/r;)Luu/p0;
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const v0, 0x7f0a01b4

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0, v0}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    check-cast v1, Luu/m1;

    .line 14
    .line 15
    if-nez v1, :cond_0

    .line 16
    .line 17
    new-instance v1, Luu/m1;

    .line 18
    .line 19
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    const-string v3, "getContext(...)"

    .line 24
    .line 25
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-direct {v1, v2}, Landroid/view/ViewGroup;-><init>(Landroid/content/Context;)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {v1, v0}, Landroid/view/View;->setId(I)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0, v1}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    .line 35
    .line 36
    .line 37
    :cond_0
    invoke-virtual {v1, p1}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {p1, p2}, Lw3/a;->setParentCompositionContext(Ll2/x;)V

    .line 41
    .line 42
    .line 43
    new-instance p0, Luu/p0;

    .line 44
    .line 45
    invoke-direct {p0, v1, p1}, Luu/p0;-><init>(Luu/m1;Lw3/a;)V

    .line 46
    .line 47
    .line 48
    return-object p0
.end method

.method public static final c(Lif0/p;)Lss0/l;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    const-string v1, "<this>"

    .line 4
    .line 5
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v3, v0, Lif0/p;->a:Ljava/lang/String;

    .line 9
    .line 10
    iget-object v4, v0, Lif0/p;->b:Ljava/lang/String;

    .line 11
    .line 12
    iget-object v5, v0, Lif0/p;->c:Ljava/lang/String;

    .line 13
    .line 14
    iget-object v6, v0, Lif0/p;->d:Ljava/lang/String;

    .line 15
    .line 16
    iget-object v7, v0, Lif0/p;->e:Ljava/time/LocalDate;

    .line 17
    .line 18
    iget-object v14, v0, Lif0/p;->h:Ljava/lang/String;

    .line 19
    .line 20
    iget-object v10, v0, Lif0/p;->i:Ljava/lang/String;

    .line 21
    .line 22
    iget-object v1, v0, Lif0/p;->g:Lif0/q;

    .line 23
    .line 24
    new-instance v8, Lss0/o;

    .line 25
    .line 26
    iget v2, v1, Lif0/q;->a:I

    .line 27
    .line 28
    int-to-double v11, v2

    .line 29
    iget-object v2, v1, Lif0/q;->b:Ljava/lang/String;

    .line 30
    .line 31
    iget-object v1, v1, Lif0/q;->c:Ljava/lang/Float;

    .line 32
    .line 33
    invoke-direct {v8, v11, v12, v2, v1}, Lss0/o;-><init>(DLjava/lang/String;Ljava/lang/Float;)V

    .line 34
    .line 35
    .line 36
    iget-object v1, v0, Lif0/p;->j:Ljava/lang/Integer;

    .line 37
    .line 38
    if-eqz v1, :cond_0

    .line 39
    .line 40
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    new-instance v9, Lqr0/h;

    .line 45
    .line 46
    invoke-direct {v9, v1}, Lqr0/h;-><init>(I)V

    .line 47
    .line 48
    .line 49
    move-object v11, v9

    .line 50
    goto :goto_0

    .line 51
    :cond_0
    const/4 v11, 0x0

    .line 52
    :goto_0
    iget-object v9, v0, Lif0/p;->f:Lss0/p;

    .line 53
    .line 54
    iget-object v12, v0, Lif0/p;->k:Ljava/lang/String;

    .line 55
    .line 56
    iget-object v1, v0, Lif0/p;->l:Ljava/lang/Integer;

    .line 57
    .line 58
    if-eqz v1, :cond_1

    .line 59
    .line 60
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    move-object v13, v3

    .line 65
    int-to-double v2, v1

    .line 66
    new-instance v1, Lqr0/n;

    .line 67
    .line 68
    invoke-direct {v1, v2, v3}, Lqr0/n;-><init>(D)V

    .line 69
    .line 70
    .line 71
    goto :goto_1

    .line 72
    :cond_1
    move-object v13, v3

    .line 73
    const/4 v1, 0x0

    .line 74
    :goto_1
    iget-object v2, v0, Lif0/p;->m:Ljava/lang/String;

    .line 75
    .line 76
    iget-object v3, v0, Lif0/p;->n:Ljava/lang/Integer;

    .line 77
    .line 78
    if-eqz v3, :cond_2

    .line 79
    .line 80
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 81
    .line 82
    .line 83
    move-result v3

    .line 84
    new-instance v15, Lqr0/b;

    .line 85
    .line 86
    invoke-direct {v15, v3}, Lqr0/b;-><init>(I)V

    .line 87
    .line 88
    .line 89
    goto :goto_2

    .line 90
    :cond_2
    const/4 v15, 0x0

    .line 91
    :goto_2
    iget-object v3, v0, Lif0/p;->o:Ljava/lang/Integer;

    .line 92
    .line 93
    if-eqz v3, :cond_3

    .line 94
    .line 95
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 96
    .line 97
    .line 98
    move-result v3

    .line 99
    move-object/from16 v17, v1

    .line 100
    .line 101
    new-instance v1, Lqr0/b;

    .line 102
    .line 103
    invoke-direct {v1, v3}, Lqr0/b;-><init>(I)V

    .line 104
    .line 105
    .line 106
    goto :goto_3

    .line 107
    :cond_3
    move-object/from16 v17, v1

    .line 108
    .line 109
    const/4 v1, 0x0

    .line 110
    :goto_3
    iget-object v0, v0, Lif0/p;->p:Ljava/lang/Integer;

    .line 111
    .line 112
    if-eqz v0, :cond_4

    .line 113
    .line 114
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 115
    .line 116
    .line 117
    move-result v0

    .line 118
    new-instance v3, Lqr0/b;

    .line 119
    .line 120
    invoke-direct {v3, v0}, Lqr0/b;-><init>(I)V

    .line 121
    .line 122
    .line 123
    goto :goto_4

    .line 124
    :cond_4
    const/4 v3, 0x0

    .line 125
    :goto_4
    new-instance v0, Lss0/b0;

    .line 126
    .line 127
    invoke-direct {v0, v15, v1, v3}, Lss0/b0;-><init>(Lqr0/b;Lqr0/b;Lqr0/b;)V

    .line 128
    .line 129
    .line 130
    move-object/from16 v16, v2

    .line 131
    .line 132
    new-instance v2, Lss0/l;

    .line 133
    .line 134
    move-object v15, v0

    .line 135
    move-object v3, v13

    .line 136
    move-object/from16 v13, v17

    .line 137
    .line 138
    invoke-direct/range {v2 .. v16}, Lss0/l;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/time/LocalDate;Lss0/o;Lss0/p;Ljava/lang/String;Lqr0/h;Ljava/lang/String;Lqr0/n;Ljava/lang/String;Lss0/b0;Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    return-object v2
.end method
