.class public abstract Li40/k3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lay0/a;Ll2/o;I)V
    .locals 18

    .line 1
    move-object/from16 v2, p0

    .line 2
    .line 3
    const-string v0, "onCancel"

    .line 4
    .line 5
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    move-object/from16 v14, p1

    .line 9
    .line 10
    check-cast v14, Ll2/t;

    .line 11
    .line 12
    const v0, 0x2cfcab3d

    .line 13
    .line 14
    .line 15
    invoke-virtual {v14, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 16
    .line 17
    .line 18
    and-int/lit8 v0, p2, 0x6

    .line 19
    .line 20
    const/4 v1, 0x2

    .line 21
    if-nez v0, :cond_1

    .line 22
    .line 23
    invoke-virtual {v14, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    const/4 v0, 0x4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    move v0, v1

    .line 32
    :goto_0
    or-int v0, p2, v0

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_1
    move/from16 v0, p2

    .line 36
    .line 37
    :goto_1
    and-int/lit8 v3, v0, 0x3

    .line 38
    .line 39
    if-eq v3, v1, :cond_2

    .line 40
    .line 41
    const/4 v1, 0x1

    .line 42
    goto :goto_2

    .line 43
    :cond_2
    const/4 v1, 0x0

    .line 44
    :goto_2
    and-int/lit8 v3, v0, 0x1

    .line 45
    .line 46
    invoke-virtual {v14, v3, v1}, Ll2/t;->O(IZ)Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-eqz v1, :cond_3

    .line 51
    .line 52
    const v1, 0x7f120ce8

    .line 53
    .line 54
    .line 55
    invoke-static {v14, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    const v3, 0x7f120ce9

    .line 60
    .line 61
    .line 62
    invoke-static {v14, v3}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v3

    .line 66
    const v4, 0x7f120373

    .line 67
    .line 68
    .line 69
    invoke-static {v14, v4}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object v4

    .line 73
    shl-int/lit8 v5, v0, 0x6

    .line 74
    .line 75
    and-int/lit16 v5, v5, 0x380

    .line 76
    .line 77
    const/high16 v6, 0x30000000

    .line 78
    .line 79
    or-int/2addr v5, v6

    .line 80
    shl-int/lit8 v0, v0, 0xf

    .line 81
    .line 82
    const/high16 v6, 0x70000

    .line 83
    .line 84
    and-int/2addr v0, v6

    .line 85
    or-int v15, v5, v0

    .line 86
    .line 87
    const/16 v16, 0x1b0

    .line 88
    .line 89
    const/16 v17, 0x25d0

    .line 90
    .line 91
    move-object v0, v1

    .line 92
    move-object v1, v3

    .line 93
    move-object v3, v4

    .line 94
    const/4 v4, 0x0

    .line 95
    const/4 v6, 0x0

    .line 96
    const/4 v7, 0x0

    .line 97
    const/4 v8, 0x0

    .line 98
    const-string v9, "global_button_cancel"

    .line 99
    .line 100
    const/4 v10, 0x0

    .line 101
    const-string v11, "myskodaclub_reward_voucher_validation_header"

    .line 102
    .line 103
    const-string v12, "myskodaclub_reward_voucher_validation_incompatible_car"

    .line 104
    .line 105
    const/4 v13, 0x0

    .line 106
    move-object/from16 v5, p0

    .line 107
    .line 108
    invoke-static/range {v0 .. v17}, Li91/j0;->d(Ljava/lang/String;Ljava/lang/String;Lay0/a;Ljava/lang/String;Lx2/s;Lay0/a;Ljava/lang/String;Lay0/a;Lx4/p;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ll2/o;III)V

    .line 109
    .line 110
    .line 111
    goto :goto_3

    .line 112
    :cond_3
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 113
    .line 114
    .line 115
    :goto_3
    invoke-virtual {v14}, Ll2/t;->s()Ll2/u1;

    .line 116
    .line 117
    .line 118
    move-result-object v0

    .line 119
    if-eqz v0, :cond_4

    .line 120
    .line 121
    new-instance v1, Lcz/s;

    .line 122
    .line 123
    const/16 v3, 0xa

    .line 124
    .line 125
    move/from16 v4, p2

    .line 126
    .line 127
    invoke-direct {v1, v2, v4, v3}, Lcz/s;-><init>(Lay0/a;II)V

    .line 128
    .line 129
    .line 130
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 131
    .line 132
    :cond_4
    return-void
.end method

.method public static final b(Lay0/a;Ll2/o;I)V
    .locals 18

    .line 1
    move-object/from16 v2, p0

    .line 2
    .line 3
    const-string v0, "onCancel"

    .line 4
    .line 5
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    move-object/from16 v14, p1

    .line 9
    .line 10
    check-cast v14, Ll2/t;

    .line 11
    .line 12
    const v0, -0xca6dc03

    .line 13
    .line 14
    .line 15
    invoke-virtual {v14, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 16
    .line 17
    .line 18
    and-int/lit8 v0, p2, 0x6

    .line 19
    .line 20
    const/4 v1, 0x2

    .line 21
    if-nez v0, :cond_1

    .line 22
    .line 23
    invoke-virtual {v14, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    const/4 v0, 0x4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    move v0, v1

    .line 32
    :goto_0
    or-int v0, p2, v0

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_1
    move/from16 v0, p2

    .line 36
    .line 37
    :goto_1
    and-int/lit8 v3, v0, 0x3

    .line 38
    .line 39
    if-eq v3, v1, :cond_2

    .line 40
    .line 41
    const/4 v1, 0x1

    .line 42
    goto :goto_2

    .line 43
    :cond_2
    const/4 v1, 0x0

    .line 44
    :goto_2
    and-int/lit8 v3, v0, 0x1

    .line 45
    .line 46
    invoke-virtual {v14, v3, v1}, Ll2/t;->O(IZ)Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-eqz v1, :cond_3

    .line 51
    .line 52
    const v1, 0x7f120ce8

    .line 53
    .line 54
    .line 55
    invoke-static {v14, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    const v3, 0x7f120cea

    .line 60
    .line 61
    .line 62
    invoke-static {v14, v3}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v3

    .line 66
    const v4, 0x7f120373

    .line 67
    .line 68
    .line 69
    invoke-static {v14, v4}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object v4

    .line 73
    shl-int/lit8 v5, v0, 0x6

    .line 74
    .line 75
    and-int/lit16 v5, v5, 0x380

    .line 76
    .line 77
    const/high16 v6, 0x30000000

    .line 78
    .line 79
    or-int/2addr v5, v6

    .line 80
    shl-int/lit8 v0, v0, 0xf

    .line 81
    .line 82
    const/high16 v6, 0x70000

    .line 83
    .line 84
    and-int/2addr v0, v6

    .line 85
    or-int v15, v5, v0

    .line 86
    .line 87
    const/16 v16, 0x1b0

    .line 88
    .line 89
    const/16 v17, 0x25d0

    .line 90
    .line 91
    move-object v0, v1

    .line 92
    move-object v1, v3

    .line 93
    move-object v3, v4

    .line 94
    const/4 v4, 0x0

    .line 95
    const/4 v6, 0x0

    .line 96
    const/4 v7, 0x0

    .line 97
    const/4 v8, 0x0

    .line 98
    const-string v9, "global_button_cancel"

    .line 99
    .line 100
    const/4 v10, 0x0

    .line 101
    const-string v11, "myskodaclub_reward_voucher_validation_header"

    .line 102
    .line 103
    const-string v12, "myskodaclub_reward_voucher_validation_no_car"

    .line 104
    .line 105
    const/4 v13, 0x0

    .line 106
    move-object/from16 v5, p0

    .line 107
    .line 108
    invoke-static/range {v0 .. v17}, Li91/j0;->d(Ljava/lang/String;Ljava/lang/String;Lay0/a;Ljava/lang/String;Lx2/s;Lay0/a;Ljava/lang/String;Lay0/a;Lx4/p;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ll2/o;III)V

    .line 109
    .line 110
    .line 111
    goto :goto_3

    .line 112
    :cond_3
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 113
    .line 114
    .line 115
    :goto_3
    invoke-virtual {v14}, Ll2/t;->s()Ll2/u1;

    .line 116
    .line 117
    .line 118
    move-result-object v0

    .line 119
    if-eqz v0, :cond_4

    .line 120
    .line 121
    new-instance v1, Lcz/s;

    .line 122
    .line 123
    const/16 v3, 0xb

    .line 124
    .line 125
    move/from16 v4, p2

    .line 126
    .line 127
    invoke-direct {v1, v2, v4, v3}, Lcz/s;-><init>(Lay0/a;II)V

    .line 128
    .line 129
    .line 130
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 131
    .line 132
    :cond_4
    return-void
.end method
