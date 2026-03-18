.class public final synthetic Lkg/n0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lkg/n0;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lkg/n0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lkg/n0;->a:Lkg/n0;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.kitten.subscription.models.Tariff"

    .line 11
    .line 12
    const/16 v3, 0xb

    .line 13
    .line 14
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 15
    .line 16
    .line 17
    const-string v0, "id"

    .line 18
    .line 19
    const/4 v2, 0x0

    .line 20
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 21
    .line 22
    .line 23
    const-string v0, "name"

    .line 24
    .line 25
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 26
    .line 27
    .line 28
    const-string v0, "legalDisclaimers"

    .line 29
    .line 30
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 31
    .line 32
    .line 33
    const-string v0, "subscriptionMonthlyFee"

    .line 34
    .line 35
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 36
    .line 37
    .line 38
    const-string v0, "conditionsSummary"

    .line 39
    .line 40
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 41
    .line 42
    .line 43
    const-string v0, "conditionsDetails"

    .line 44
    .line 45
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 46
    .line 47
    .line 48
    const-string v0, "canBeUsedForUpgrade"

    .line 49
    .line 50
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 51
    .line 52
    .line 53
    const-string v0, "canBeUsedForFollowUp"

    .line 54
    .line 55
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 56
    .line 57
    .line 58
    const-string v0, "localizedPdfLinkLabel"

    .line 59
    .line 60
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 61
    .line 62
    .line 63
    const-string v0, "promotionText"

    .line 64
    .line 65
    const/4 v2, 0x1

    .line 66
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 67
    .line 68
    .line 69
    const-string v0, "description"

    .line 70
    .line 71
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 72
    .line 73
    .line 74
    sput-object v1, Lkg/n0;->descriptor:Lsz0/g;

    .line 75
    .line 76
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 4

    .line 1
    sget-object p0, Lkg/p0;->o:[Llx0/i;

    .line 2
    .line 3
    const/16 v0, 0xb

    .line 4
    .line 5
    new-array v0, v0, [Lqz0/a;

    .line 6
    .line 7
    sget-object v1, Luz0/q1;->a:Luz0/q1;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    aput-object v1, v0, v2

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    aput-object v1, v0, v2

    .line 14
    .line 15
    const/4 v2, 0x2

    .line 16
    aget-object v3, p0, v2

    .line 17
    .line 18
    invoke-interface {v3}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v3

    .line 22
    aput-object v3, v0, v2

    .line 23
    .line 24
    const/4 v2, 0x3

    .line 25
    sget-object v3, Lkg/m;->a:Lkg/m;

    .line 26
    .line 27
    aput-object v3, v0, v2

    .line 28
    .line 29
    const/4 v2, 0x4

    .line 30
    aget-object v3, p0, v2

    .line 31
    .line 32
    invoke-interface {v3}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v3

    .line 36
    aput-object v3, v0, v2

    .line 37
    .line 38
    const/4 v2, 0x5

    .line 39
    aget-object p0, p0, v2

    .line 40
    .line 41
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    aput-object p0, v0, v2

    .line 46
    .line 47
    sget-object p0, Luz0/g;->a:Luz0/g;

    .line 48
    .line 49
    const/4 v2, 0x6

    .line 50
    aput-object p0, v0, v2

    .line 51
    .line 52
    const/4 v2, 0x7

    .line 53
    aput-object p0, v0, v2

    .line 54
    .line 55
    const/16 p0, 0x8

    .line 56
    .line 57
    aput-object v1, v0, p0

    .line 58
    .line 59
    const/16 p0, 0x9

    .line 60
    .line 61
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 62
    .line 63
    .line 64
    move-result-object v2

    .line 65
    aput-object v2, v0, p0

    .line 66
    .line 67
    const/16 p0, 0xa

    .line 68
    .line 69
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 70
    .line 71
    .line 72
    move-result-object v1

    .line 73
    aput-object v1, v0, p0

    .line 74
    .line 75
    return-object v0
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 19

    .line 1
    sget-object v0, Lkg/n0;->descriptor:Lsz0/g;

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    invoke-interface {v1, v0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    sget-object v2, Lkg/p0;->o:[Llx0/i;

    .line 10
    .line 11
    const/4 v5, 0x0

    .line 12
    move-object v6, v5

    .line 13
    move-object v8, v6

    .line 14
    move-object v9, v8

    .line 15
    move-object v10, v9

    .line 16
    move-object v11, v10

    .line 17
    move-object v12, v11

    .line 18
    move-object v13, v12

    .line 19
    move-object/from16 v16, v13

    .line 20
    .line 21
    const/4 v7, 0x1

    .line 22
    const/4 v14, 0x0

    .line 23
    const/4 v15, 0x0

    .line 24
    const/16 v17, 0x0

    .line 25
    .line 26
    :goto_0
    if-eqz v7, :cond_0

    .line 27
    .line 28
    invoke-interface {v1, v0}, Ltz0/a;->E(Lsz0/g;)I

    .line 29
    .line 30
    .line 31
    move-result v4

    .line 32
    packed-switch v4, :pswitch_data_0

    .line 33
    .line 34
    .line 35
    new-instance v0, Lqz0/k;

    .line 36
    .line 37
    invoke-direct {v0, v4}, Lqz0/k;-><init>(I)V

    .line 38
    .line 39
    .line 40
    throw v0

    .line 41
    :pswitch_0
    sget-object v4, Luz0/q1;->a:Luz0/q1;

    .line 42
    .line 43
    const/16 v3, 0xa

    .line 44
    .line 45
    invoke-interface {v1, v0, v3, v4, v6}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v3

    .line 49
    move-object v6, v3

    .line 50
    check-cast v6, Ljava/lang/String;

    .line 51
    .line 52
    or-int/lit16 v14, v14, 0x400

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :pswitch_1
    sget-object v3, Luz0/q1;->a:Luz0/q1;

    .line 56
    .line 57
    const/16 v4, 0x9

    .line 58
    .line 59
    invoke-interface {v1, v0, v4, v3, v5}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v3

    .line 63
    move-object v5, v3

    .line 64
    check-cast v5, Ljava/lang/String;

    .line 65
    .line 66
    or-int/lit16 v14, v14, 0x200

    .line 67
    .line 68
    goto :goto_0

    .line 69
    :pswitch_2
    const/16 v3, 0x8

    .line 70
    .line 71
    invoke-interface {v1, v0, v3}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object v16

    .line 75
    or-int/lit16 v14, v14, 0x100

    .line 76
    .line 77
    goto :goto_0

    .line 78
    :pswitch_3
    const/4 v3, 0x7

    .line 79
    invoke-interface {v1, v0, v3}, Ltz0/a;->w(Lsz0/g;I)Z

    .line 80
    .line 81
    .line 82
    move-result v17

    .line 83
    or-int/lit16 v14, v14, 0x80

    .line 84
    .line 85
    goto :goto_0

    .line 86
    :pswitch_4
    const/4 v3, 0x6

    .line 87
    invoke-interface {v1, v0, v3}, Ltz0/a;->w(Lsz0/g;I)Z

    .line 88
    .line 89
    .line 90
    move-result v15

    .line 91
    or-int/lit8 v14, v14, 0x40

    .line 92
    .line 93
    goto :goto_0

    .line 94
    :pswitch_5
    const/4 v3, 0x5

    .line 95
    aget-object v4, v2, v3

    .line 96
    .line 97
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v4

    .line 101
    check-cast v4, Lqz0/a;

    .line 102
    .line 103
    invoke-interface {v1, v0, v3, v4, v13}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v3

    .line 107
    move-object v13, v3

    .line 108
    check-cast v13, Ljava/util/List;

    .line 109
    .line 110
    or-int/lit8 v14, v14, 0x20

    .line 111
    .line 112
    goto :goto_0

    .line 113
    :pswitch_6
    const/4 v3, 0x4

    .line 114
    aget-object v4, v2, v3

    .line 115
    .line 116
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v4

    .line 120
    check-cast v4, Lqz0/a;

    .line 121
    .line 122
    invoke-interface {v1, v0, v3, v4, v12}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object v3

    .line 126
    move-object v12, v3

    .line 127
    check-cast v12, Ljava/util/List;

    .line 128
    .line 129
    or-int/lit8 v14, v14, 0x10

    .line 130
    .line 131
    goto :goto_0

    .line 132
    :pswitch_7
    sget-object v3, Lkg/m;->a:Lkg/m;

    .line 133
    .line 134
    const/4 v4, 0x3

    .line 135
    invoke-interface {v1, v0, v4, v3, v11}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object v3

    .line 139
    move-object v11, v3

    .line 140
    check-cast v11, Lkg/o;

    .line 141
    .line 142
    or-int/lit8 v14, v14, 0x8

    .line 143
    .line 144
    goto :goto_0

    .line 145
    :pswitch_8
    const/4 v3, 0x2

    .line 146
    aget-object v4, v2, v3

    .line 147
    .line 148
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object v4

    .line 152
    check-cast v4, Lqz0/a;

    .line 153
    .line 154
    invoke-interface {v1, v0, v3, v4, v10}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object v3

    .line 158
    move-object v10, v3

    .line 159
    check-cast v10, Ljava/util/List;

    .line 160
    .line 161
    or-int/lit8 v14, v14, 0x4

    .line 162
    .line 163
    goto/16 :goto_0

    .line 164
    .line 165
    :pswitch_9
    const/4 v3, 0x1

    .line 166
    invoke-interface {v1, v0, v3}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 167
    .line 168
    .line 169
    move-result-object v9

    .line 170
    or-int/lit8 v14, v14, 0x2

    .line 171
    .line 172
    goto/16 :goto_0

    .line 173
    .line 174
    :pswitch_a
    const/4 v3, 0x1

    .line 175
    const/4 v4, 0x0

    .line 176
    invoke-interface {v1, v0, v4}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 177
    .line 178
    .line 179
    move-result-object v8

    .line 180
    or-int/lit8 v14, v14, 0x1

    .line 181
    .line 182
    goto/16 :goto_0

    .line 183
    .line 184
    :pswitch_b
    const/4 v3, 0x1

    .line 185
    const/4 v4, 0x0

    .line 186
    move v7, v4

    .line 187
    goto/16 :goto_0

    .line 188
    .line 189
    :cond_0
    invoke-interface {v1, v0}, Ltz0/a;->b(Lsz0/g;)V

    .line 190
    .line 191
    .line 192
    move-object/from16 v18, v6

    .line 193
    .line 194
    new-instance v6, Lkg/p0;

    .line 195
    .line 196
    move v7, v14

    .line 197
    move v14, v15

    .line 198
    move/from16 v15, v17

    .line 199
    .line 200
    move-object/from16 v17, v5

    .line 201
    .line 202
    invoke-direct/range {v6 .. v18}, Lkg/p0;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/util/List;Lkg/o;Ljava/util/List;Ljava/util/List;ZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 203
    .line 204
    .line 205
    return-object v6

    .line 206
    nop

    .line 207
    :pswitch_data_0
    .packed-switch -0x1
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lkg/n0;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 6

    .line 1
    check-cast p2, Lkg/p0;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lkg/n0;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    sget-object v0, Lkg/p0;->o:[Llx0/i;

    .line 15
    .line 16
    iget-object v1, p2, Lkg/p0;->d:Ljava/lang/String;

    .line 17
    .line 18
    iget-object v2, p2, Lkg/p0;->n:Ljava/lang/String;

    .line 19
    .line 20
    iget-object v3, p2, Lkg/p0;->m:Ljava/lang/String;

    .line 21
    .line 22
    const/4 v4, 0x0

    .line 23
    invoke-interface {p1, p0, v4, v1}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const/4 v1, 0x1

    .line 27
    iget-object v4, p2, Lkg/p0;->e:Ljava/lang/String;

    .line 28
    .line 29
    invoke-interface {p1, p0, v1, v4}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 30
    .line 31
    .line 32
    const/4 v1, 0x2

    .line 33
    aget-object v4, v0, v1

    .line 34
    .line 35
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v4

    .line 39
    check-cast v4, Lqz0/a;

    .line 40
    .line 41
    iget-object v5, p2, Lkg/p0;->f:Ljava/util/List;

    .line 42
    .line 43
    invoke-interface {p1, p0, v1, v4, v5}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    sget-object v1, Lkg/m;->a:Lkg/m;

    .line 47
    .line 48
    iget-object v4, p2, Lkg/p0;->g:Lkg/o;

    .line 49
    .line 50
    const/4 v5, 0x3

    .line 51
    invoke-interface {p1, p0, v5, v1, v4}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    const/4 v1, 0x4

    .line 55
    aget-object v4, v0, v1

    .line 56
    .line 57
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v4

    .line 61
    check-cast v4, Lqz0/a;

    .line 62
    .line 63
    iget-object v5, p2, Lkg/p0;->h:Ljava/util/List;

    .line 64
    .line 65
    invoke-interface {p1, p0, v1, v4, v5}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    const/4 v1, 0x5

    .line 69
    aget-object v0, v0, v1

    .line 70
    .line 71
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    check-cast v0, Lqz0/a;

    .line 76
    .line 77
    iget-object v4, p2, Lkg/p0;->i:Ljava/util/List;

    .line 78
    .line 79
    invoke-interface {p1, p0, v1, v0, v4}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    const/4 v0, 0x6

    .line 83
    iget-boolean v1, p2, Lkg/p0;->j:Z

    .line 84
    .line 85
    invoke-interface {p1, p0, v0, v1}, Ltz0/b;->y(Lsz0/g;IZ)V

    .line 86
    .line 87
    .line 88
    const/4 v0, 0x7

    .line 89
    iget-boolean v1, p2, Lkg/p0;->k:Z

    .line 90
    .line 91
    invoke-interface {p1, p0, v0, v1}, Ltz0/b;->y(Lsz0/g;IZ)V

    .line 92
    .line 93
    .line 94
    const/16 v0, 0x8

    .line 95
    .line 96
    iget-object p2, p2, Lkg/p0;->l:Ljava/lang/String;

    .line 97
    .line 98
    invoke-interface {p1, p0, v0, p2}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 99
    .line 100
    .line 101
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 102
    .line 103
    .line 104
    move-result p2

    .line 105
    if-eqz p2, :cond_0

    .line 106
    .line 107
    goto :goto_0

    .line 108
    :cond_0
    if-eqz v3, :cond_1

    .line 109
    .line 110
    :goto_0
    sget-object p2, Luz0/q1;->a:Luz0/q1;

    .line 111
    .line 112
    const/16 v0, 0x9

    .line 113
    .line 114
    invoke-interface {p1, p0, v0, p2, v3}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    :cond_1
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 118
    .line 119
    .line 120
    move-result p2

    .line 121
    if-eqz p2, :cond_2

    .line 122
    .line 123
    goto :goto_1

    .line 124
    :cond_2
    if-eqz v2, :cond_3

    .line 125
    .line 126
    :goto_1
    sget-object p2, Luz0/q1;->a:Luz0/q1;

    .line 127
    .line 128
    const/16 v0, 0xa

    .line 129
    .line 130
    invoke-interface {p1, p0, v0, p2, v2}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 131
    .line 132
    .line 133
    :cond_3
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 134
    .line 135
    .line 136
    return-void
.end method
