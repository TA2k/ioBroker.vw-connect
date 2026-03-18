.class public final Lq31/h;
.super Lq41/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final f:Lz9/y;

.field public final g:Lk31/n;

.field public final h:Lk31/f0;

.field public final i:Lk31/l0;

.field public final j:Landroidx/lifecycle/s0;

.field public k:Lvy0/x1;


# direct methods
.method public constructor <init>(Lz9/y;Lk31/v;Lk31/n;Lk31/f0;Lk31/l0;Landroidx/lifecycle/s0;)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    new-instance v1, Lq31/i;

    .line 4
    .line 5
    const-wide/16 v2, -0x1

    .line 6
    .line 7
    const-wide/16 v4, -0x1

    .line 8
    .line 9
    const/4 v6, 0x0

    .line 10
    sget-object v7, Lmx0/s;->d:Lmx0/s;

    .line 11
    .line 12
    move-object v8, v7

    .line 13
    invoke-direct/range {v1 .. v8}, Lq31/i;-><init>(JJLjava/lang/Integer;Ljava/util/List;Ljava/util/List;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {v0, v1}, Lq41/b;-><init>(Lq41/a;)V

    .line 17
    .line 18
    .line 19
    move-object/from16 v1, p1

    .line 20
    .line 21
    iput-object v1, v0, Lq31/h;->f:Lz9/y;

    .line 22
    .line 23
    move-object/from16 v1, p3

    .line 24
    .line 25
    iput-object v1, v0, Lq31/h;->g:Lk31/n;

    .line 26
    .line 27
    move-object/from16 v1, p4

    .line 28
    .line 29
    iput-object v1, v0, Lq31/h;->h:Lk31/f0;

    .line 30
    .line 31
    move-object/from16 v1, p5

    .line 32
    .line 33
    iput-object v1, v0, Lq31/h;->i:Lk31/l0;

    .line 34
    .line 35
    move-object/from16 v1, p6

    .line 36
    .line 37
    iput-object v1, v0, Lq31/h;->j:Landroidx/lifecycle/s0;

    .line 38
    .line 39
    invoke-virtual/range {p2 .. p2}, Lk31/v;->a()Lp31/b;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    iget-object v2, v1, Lp31/b;->a:Ljava/util/GregorianCalendar;

    .line 44
    .line 45
    iget-object v9, v1, Lp31/b;->b:Ljava/util/List;

    .line 46
    .line 47
    :goto_0
    const/4 v3, 0x7

    .line 48
    invoke-virtual {v2, v3}, Ljava/util/Calendar;->get(I)I

    .line 49
    .line 50
    .line 51
    move-result v3

    .line 52
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 53
    .line 54
    .line 55
    move-result-object v3

    .line 56
    invoke-interface {v9, v3}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v3

    .line 60
    if-eqz v3, :cond_0

    .line 61
    .line 62
    const/4 v3, 0x5

    .line 63
    const/4 v4, 0x1

    .line 64
    invoke-virtual {v2, v3, v4}, Ljava/util/Calendar;->add(II)V

    .line 65
    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_0
    iget-object v11, v0, Lq41/b;->d:Lyy0/c2;

    .line 69
    .line 70
    :goto_1
    invoke-virtual {v11}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v12

    .line 74
    move-object v3, v12

    .line 75
    check-cast v3, Lq31/i;

    .line 76
    .line 77
    invoke-virtual {v2}, Ljava/util/Calendar;->getTimeInMillis()J

    .line 78
    .line 79
    .line 80
    move-result-wide v4

    .line 81
    invoke-virtual {v2}, Ljava/util/Calendar;->getTimeInMillis()J

    .line 82
    .line 83
    .line 84
    move-result-wide v6

    .line 85
    const/16 v8, 0x46

    .line 86
    .line 87
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 88
    .line 89
    .line 90
    move-result-object v8

    .line 91
    iget-object v10, v1, Lp31/b;->c:Ljava/util/List;

    .line 92
    .line 93
    check-cast v10, Ljava/lang/Iterable;

    .line 94
    .line 95
    new-instance v13, Ljava/util/ArrayList;

    .line 96
    .line 97
    const/16 v14, 0xa

    .line 98
    .line 99
    invoke-static {v10, v14}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 100
    .line 101
    .line 102
    move-result v14

    .line 103
    invoke-direct {v13, v14}, Ljava/util/ArrayList;-><init>(I)V

    .line 104
    .line 105
    .line 106
    invoke-interface {v10}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 107
    .line 108
    .line 109
    move-result-object v10

    .line 110
    :goto_2
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 111
    .line 112
    .line 113
    move-result v14

    .line 114
    if-eqz v14, :cond_1

    .line 115
    .line 116
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v14

    .line 120
    check-cast v14, Lp31/a;

    .line 121
    .line 122
    new-instance v15, Lp31/g;

    .line 123
    .line 124
    iget v0, v14, Lp31/a;->a:I

    .line 125
    .line 126
    invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object v0

    .line 130
    move-object/from16 p1, v1

    .line 131
    .line 132
    const/4 v1, 0x2

    .line 133
    invoke-static {v1, v0}, Lly0/p;->Q(ILjava/lang/String;)Ljava/lang/String;

    .line 134
    .line 135
    .line 136
    move-result-object v0

    .line 137
    move-object/from16 p2, v2

    .line 138
    .line 139
    iget v2, v14, Lp31/a;->b:I

    .line 140
    .line 141
    invoke-static {v2}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 142
    .line 143
    .line 144
    move-result-object v2

    .line 145
    invoke-static {v1, v2}, Lly0/p;->Q(ILjava/lang/String;)Ljava/lang/String;

    .line 146
    .line 147
    .line 148
    move-result-object v1

    .line 149
    const-string v2, ":"

    .line 150
    .line 151
    invoke-static {v0, v2, v1}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 152
    .line 153
    .line 154
    move-result-object v0

    .line 155
    const/4 v1, 0x0

    .line 156
    invoke-direct {v15, v14, v0, v1}, Lp31/g;-><init>(Ljava/lang/Object;Ljava/lang/String;Z)V

    .line 157
    .line 158
    .line 159
    invoke-virtual {v13, v15}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 160
    .line 161
    .line 162
    move-object/from16 v0, p0

    .line 163
    .line 164
    move-object/from16 v1, p1

    .line 165
    .line 166
    move-object/from16 v2, p2

    .line 167
    .line 168
    goto :goto_2

    .line 169
    :cond_1
    move-object/from16 p1, v1

    .line 170
    .line 171
    move-object/from16 p2, v2

    .line 172
    .line 173
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 174
    .line 175
    .line 176
    new-instance v3, Lq31/i;

    .line 177
    .line 178
    move-object v10, v13

    .line 179
    invoke-direct/range {v3 .. v10}, Lq31/i;-><init>(JJLjava/lang/Integer;Ljava/util/List;Ljava/util/List;)V

    .line 180
    .line 181
    .line 182
    invoke-virtual {v11, v12, v3}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 183
    .line 184
    .line 185
    move-result v0

    .line 186
    if-eqz v0, :cond_2

    .line 187
    .line 188
    invoke-virtual/range {p0 .. p0}, Lq31/h;->b()V

    .line 189
    .line 190
    .line 191
    return-void

    .line 192
    :cond_2
    move-object/from16 v0, p0

    .line 193
    .line 194
    move-object/from16 v1, p1

    .line 195
    .line 196
    move-object/from16 v2, p2

    .line 197
    .line 198
    goto/16 :goto_1
.end method


# virtual methods
.method public final b()V
    .locals 4

    .line 1
    iget-object v0, p0, Lq31/h;->k:Lvy0/x1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0}, Lvy0/p1;->a()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, 0x1

    .line 10
    if-ne v0, v1, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    invoke-virtual {p0}, Lq41/b;->a()Lq41/a;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    check-cast v0, Lq31/i;

    .line 18
    .line 19
    iget-wide v0, v0, Lq31/i;->b:J

    .line 20
    .line 21
    const-wide/16 v2, -0x1

    .line 22
    .line 23
    cmp-long v0, v0, v2

    .line 24
    .line 25
    if-nez v0, :cond_1

    .line 26
    .line 27
    :goto_0
    return-void

    .line 28
    :cond_1
    iget-object v0, p0, Lq31/h;->h:Lk31/f0;

    .line 29
    .line 30
    invoke-virtual {v0}, Lk31/f0;->a()Lyy0/i;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    new-instance v1, Lhg/q;

    .line 35
    .line 36
    const/16 v2, 0x1a

    .line 37
    .line 38
    invoke-direct {v1, v0, v2}, Lhg/q;-><init>(Lyy0/i;I)V

    .line 39
    .line 40
    .line 41
    invoke-static {v1}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    new-instance v1, Lg1/n2;

    .line 46
    .line 47
    const/4 v2, 0x0

    .line 48
    invoke-direct {v1, p0, v2}, Lg1/n2;-><init>(Lq31/h;Lkotlin/coroutines/Continuation;)V

    .line 49
    .line 50
    .line 51
    new-instance v2, Lne0/n;

    .line 52
    .line 53
    const/4 v3, 0x5

    .line 54
    invoke-direct {v2, v0, v1, v3}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 55
    .line 56
    .line 57
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    invoke-static {v2, v0}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    iput-object v0, p0, Lq31/h;->k:Lvy0/x1;

    .line 66
    .line 67
    return-void
.end method

.method public final d(Lq31/f;)V
    .locals 6

    .line 1
    const-string v0, "event"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Lq31/a;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    if-eqz v0, :cond_b

    .line 10
    .line 11
    iget-object p1, p0, Lq41/b;->e:Lyy0/l1;

    .line 12
    .line 13
    iget-object v0, p1, Lyy0/l1;->d:Lyy0/a2;

    .line 14
    .line 15
    invoke-interface {v0}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    check-cast v0, Lq31/i;

    .line 20
    .line 21
    iget-object v0, v0, Lq31/i;->e:Ljava/util/List;

    .line 22
    .line 23
    check-cast v0, Ljava/lang/Iterable;

    .line 24
    .line 25
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    if-eqz v2, :cond_1

    .line 34
    .line 35
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    move-object v3, v2

    .line 40
    check-cast v3, Lp31/g;

    .line 41
    .line 42
    iget-boolean v3, v3, Lp31/g;->c:Z

    .line 43
    .line 44
    if-eqz v3, :cond_0

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_1
    move-object v2, v1

    .line 48
    :goto_0
    check-cast v2, Lp31/g;

    .line 49
    .line 50
    invoke-static {}, Ljava/util/Calendar;->getInstance()Ljava/util/Calendar;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    iget-object p1, p1, Lyy0/l1;->d:Lyy0/a2;

    .line 55
    .line 56
    invoke-interface {p1}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    check-cast p1, Lq31/i;

    .line 61
    .line 62
    iget-wide v3, p1, Lq31/i;->a:J

    .line 63
    .line 64
    invoke-virtual {v0, v3, v4}, Ljava/util/Calendar;->setTimeInMillis(J)V

    .line 65
    .line 66
    .line 67
    if-eqz v2, :cond_2

    .line 68
    .line 69
    iget-object p1, v2, Lp31/g;->a:Ljava/lang/Object;

    .line 70
    .line 71
    goto :goto_1

    .line 72
    :cond_2
    move-object p1, v1

    .line 73
    :goto_1
    instance-of v3, p1, Lp31/a;

    .line 74
    .line 75
    if-eqz v3, :cond_3

    .line 76
    .line 77
    check-cast p1, Lp31/a;

    .line 78
    .line 79
    goto :goto_2

    .line 80
    :cond_3
    move-object p1, v1

    .line 81
    :goto_2
    const/4 v3, 0x0

    .line 82
    if-eqz p1, :cond_4

    .line 83
    .line 84
    iget p1, p1, Lp31/a;->a:I

    .line 85
    .line 86
    goto :goto_3

    .line 87
    :cond_4
    move p1, v3

    .line 88
    :goto_3
    const/16 v4, 0xb

    .line 89
    .line 90
    invoke-virtual {v0, v4, p1}, Ljava/util/Calendar;->set(II)V

    .line 91
    .line 92
    .line 93
    if-eqz v2, :cond_5

    .line 94
    .line 95
    iget-object p1, v2, Lp31/g;->a:Ljava/lang/Object;

    .line 96
    .line 97
    goto :goto_4

    .line 98
    :cond_5
    move-object p1, v1

    .line 99
    :goto_4
    instance-of v2, p1, Lp31/a;

    .line 100
    .line 101
    if-eqz v2, :cond_6

    .line 102
    .line 103
    check-cast p1, Lp31/a;

    .line 104
    .line 105
    goto :goto_5

    .line 106
    :cond_6
    move-object p1, v1

    .line 107
    :goto_5
    if-eqz p1, :cond_7

    .line 108
    .line 109
    iget p1, p1, Lp31/a;->b:I

    .line 110
    .line 111
    goto :goto_6

    .line 112
    :cond_7
    move p1, v3

    .line 113
    :goto_6
    const/16 v2, 0xc

    .line 114
    .line 115
    invoke-virtual {v0, v2, p1}, Ljava/util/Calendar;->set(II)V

    .line 116
    .line 117
    .line 118
    new-instance p1, Lpg/m;

    .line 119
    .line 120
    const/4 v2, 0x3

    .line 121
    invoke-direct {p1, v0, v2}, Lpg/m;-><init>(Ljava/lang/Object;I)V

    .line 122
    .line 123
    .line 124
    iget-object v0, p0, Lq31/h;->i:Lk31/l0;

    .line 125
    .line 126
    invoke-virtual {v0, p1}, Lk31/l0;->a(Lay0/k;)V

    .line 127
    .line 128
    .line 129
    iget-object p1, p0, Lq31/h;->g:Lk31/n;

    .line 130
    .line 131
    invoke-virtual {p1}, Lk31/n;->a()Li31/j;

    .line 132
    .line 133
    .line 134
    move-result-object p1

    .line 135
    if-eqz p1, :cond_8

    .line 136
    .line 137
    iget-object v1, p1, Li31/j;->a:Lz21/c;

    .line 138
    .line 139
    :cond_8
    sget-object p1, Lz21/c;->g:Lz21/c;

    .line 140
    .line 141
    iget-object v0, p0, Lq31/h;->f:Lz9/y;

    .line 142
    .line 143
    if-ne v1, p1, :cond_9

    .line 144
    .line 145
    const-class v2, Ll31/j;

    .line 146
    .line 147
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 148
    .line 149
    invoke-virtual {v4, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 150
    .line 151
    .line 152
    move-result-object v2

    .line 153
    iget-object p0, p0, Lq31/h;->j:Landroidx/lifecycle/s0;

    .line 154
    .line 155
    invoke-static {p0, v2}, Ljp/t0;->c(Landroidx/lifecycle/s0;Lhy0/d;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object p0

    .line 159
    check-cast p0, Ll31/j;

    .line 160
    .line 161
    iget-boolean p0, p0, Ll31/j;->a:Z

    .line 162
    .line 163
    if-eqz p0, :cond_9

    .line 164
    .line 165
    invoke-virtual {v0}, Lz9/y;->h()Z

    .line 166
    .line 167
    .line 168
    return-void

    .line 169
    :cond_9
    if-ne v1, p1, :cond_a

    .line 170
    .line 171
    new-instance p0, Ll31/t;

    .line 172
    .line 173
    invoke-direct {p0, v3}, Ll31/t;-><init>(Z)V

    .line 174
    .line 175
    .line 176
    invoke-static {v0, p0}, Lz9/y;->e(Lz9/y;Ljava/lang/Object;)V

    .line 177
    .line 178
    .line 179
    return-void

    .line 180
    :cond_a
    sget-object p0, Ll31/n;->INSTANCE:Ll31/n;

    .line 181
    .line 182
    invoke-static {v0, p0}, Lz9/y;->e(Lz9/y;Ljava/lang/Object;)V

    .line 183
    .line 184
    .line 185
    return-void

    .line 186
    :cond_b
    instance-of v0, p1, Lq31/b;

    .line 187
    .line 188
    if-eqz v0, :cond_d

    .line 189
    .line 190
    check-cast p1, Lq31/b;

    .line 191
    .line 192
    iget-wide v2, p1, Lq31/b;->a:J

    .line 193
    .line 194
    :cond_c
    iget-object p1, p0, Lq41/b;->d:Lyy0/c2;

    .line 195
    .line 196
    invoke-virtual {p1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 197
    .line 198
    .line 199
    move-result-object v0

    .line 200
    move-object v4, v0

    .line 201
    check-cast v4, Lq31/i;

    .line 202
    .line 203
    const/16 v5, 0x1e

    .line 204
    .line 205
    invoke-static {v4, v2, v3, v1, v5}, Lq31/i;->a(Lq31/i;JLjava/util/ArrayList;I)Lq31/i;

    .line 206
    .line 207
    .line 208
    move-result-object v4

    .line 209
    invoke-virtual {p1, v0, v4}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 210
    .line 211
    .line 212
    move-result p1

    .line 213
    if-eqz p1, :cond_c

    .line 214
    .line 215
    return-void

    .line 216
    :cond_d
    instance-of v0, p1, Lq31/e;

    .line 217
    .line 218
    if-eqz v0, :cond_e

    .line 219
    .line 220
    check-cast p1, Lq31/e;

    .line 221
    .line 222
    iget-object p1, p1, Lq31/e;->a:Lp31/g;

    .line 223
    .line 224
    invoke-virtual {p0, p1}, Lq31/h;->f(Lp31/g;)V

    .line 225
    .line 226
    .line 227
    return-void

    .line 228
    :cond_e
    instance-of v0, p1, Lq31/c;

    .line 229
    .line 230
    if-eqz v0, :cond_f

    .line 231
    .line 232
    invoke-virtual {p0}, Lq31/h;->b()V

    .line 233
    .line 234
    .line 235
    return-void

    .line 236
    :cond_f
    instance-of p1, p1, Lq31/d;

    .line 237
    .line 238
    if-eqz p1, :cond_11

    .line 239
    .line 240
    iget-object p1, p0, Lq31/h;->k:Lvy0/x1;

    .line 241
    .line 242
    if-eqz p1, :cond_10

    .line 243
    .line 244
    invoke-virtual {p1, v1}, Lvy0/p1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 245
    .line 246
    .line 247
    :cond_10
    iput-object v1, p0, Lq31/h;->k:Lvy0/x1;

    .line 248
    .line 249
    return-void

    .line 250
    :cond_11
    new-instance p0, La8/r0;

    .line 251
    .line 252
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 253
    .line 254
    .line 255
    throw p0
.end method

.method public final f(Lp31/g;)V
    .locals 8

    .line 1
    :cond_0
    iget-object v0, p0, Lq41/b;->d:Lyy0/c2;

    .line 2
    .line 3
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    move-object v2, v1

    .line 8
    check-cast v2, Lq31/i;

    .line 9
    .line 10
    iget-object v3, v2, Lq31/i;->e:Ljava/util/List;

    .line 11
    .line 12
    check-cast v3, Ljava/lang/Iterable;

    .line 13
    .line 14
    new-instance v4, Ljava/util/ArrayList;

    .line 15
    .line 16
    const/16 v5, 0xa

    .line 17
    .line 18
    invoke-static {v3, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 19
    .line 20
    .line 21
    move-result v5

    .line 22
    invoke-direct {v4, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 23
    .line 24
    .line 25
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 30
    .line 31
    .line 32
    move-result v5

    .line 33
    if-eqz v5, :cond_1

    .line 34
    .line 35
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v5

    .line 39
    check-cast v5, Lp31/g;

    .line 40
    .line 41
    iget-object v6, v5, Lp31/g;->a:Ljava/lang/Object;

    .line 42
    .line 43
    iget-object v7, p1, Lp31/g;->a:Ljava/lang/Object;

    .line 44
    .line 45
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v6

    .line 49
    invoke-static {v5, v6}, Lp31/g;->a(Lp31/g;Z)Lp31/g;

    .line 50
    .line 51
    .line 52
    move-result-object v5

    .line 53
    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_1
    const-wide/16 v5, 0x0

    .line 58
    .line 59
    const/16 v3, 0xf

    .line 60
    .line 61
    invoke-static {v2, v5, v6, v4, v3}, Lq31/i;->a(Lq31/i;JLjava/util/ArrayList;I)Lq31/i;

    .line 62
    .line 63
    .line 64
    move-result-object v2

    .line 65
    invoke-virtual {v0, v1, v2}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    if-eqz v0, :cond_0

    .line 70
    .line 71
    return-void
.end method
