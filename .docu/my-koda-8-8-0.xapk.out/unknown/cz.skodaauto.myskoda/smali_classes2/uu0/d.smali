.class public final Luu0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Luu0/x;


# direct methods
.method public synthetic constructor <init>(Luu0/x;I)V
    .locals 0

    .line 1
    iput p2, p0, Luu0/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Luu0/d;->e:Luu0/x;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public b(Lne0/s;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 30

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    instance-of v3, v2, Luu0/c;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, v2

    .line 12
    check-cast v3, Luu0/c;

    .line 13
    .line 14
    iget v4, v3, Luu0/c;->g:I

    .line 15
    .line 16
    const/high16 v5, -0x80000000

    .line 17
    .line 18
    and-int v6, v4, v5

    .line 19
    .line 20
    if-eqz v6, :cond_0

    .line 21
    .line 22
    sub-int/2addr v4, v5

    .line 23
    iput v4, v3, Luu0/c;->g:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Luu0/c;

    .line 27
    .line 28
    invoke-direct {v3, v0, v2}, Luu0/c;-><init>(Luu0/d;Lkotlin/coroutines/Continuation;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object v2, v3, Luu0/c;->e:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Luu0/c;->g:I

    .line 36
    .line 37
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 38
    .line 39
    iget-object v0, v0, Luu0/d;->e:Luu0/x;

    .line 40
    .line 41
    const/4 v7, 0x1

    .line 42
    if-eqz v5, :cond_2

    .line 43
    .line 44
    if-ne v5, v7, :cond_1

    .line 45
    .line 46
    iget-object v1, v3, Luu0/c;->d:Lne0/e;

    .line 47
    .line 48
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 53
    .line 54
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 55
    .line 56
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw v0

    .line 60
    :cond_2
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    instance-of v2, v1, Lne0/e;

    .line 64
    .line 65
    if-eqz v2, :cond_5

    .line 66
    .line 67
    iget-object v2, v0, Luu0/x;->W:Lgb0/f;

    .line 68
    .line 69
    move-object v5, v1

    .line 70
    check-cast v5, Lne0/e;

    .line 71
    .line 72
    iput-object v5, v3, Luu0/c;->d:Lne0/e;

    .line 73
    .line 74
    iput v7, v3, Luu0/c;->g:I

    .line 75
    .line 76
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 77
    .line 78
    .line 79
    invoke-virtual {v2, v3}, Lgb0/f;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v2

    .line 83
    if-ne v2, v4, :cond_3

    .line 84
    .line 85
    return-object v4

    .line 86
    :cond_3
    :goto_1
    check-cast v2, Lss0/b;

    .line 87
    .line 88
    sget-object v3, Lss0/e;->E1:Lss0/e;

    .line 89
    .line 90
    invoke-static {v2, v3}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 91
    .line 92
    .line 93
    move-result v2

    .line 94
    if-eqz v2, :cond_4

    .line 95
    .line 96
    check-cast v1, Lne0/e;

    .line 97
    .line 98
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 99
    .line 100
    check-cast v1, Lcq0/m;

    .line 101
    .line 102
    iget-object v1, v1, Lcq0/m;->b:Lcq0/n;

    .line 103
    .line 104
    if-nez v1, :cond_4

    .line 105
    .line 106
    :goto_2
    move/from16 v22, v7

    .line 107
    .line 108
    goto :goto_3

    .line 109
    :cond_4
    const/4 v7, 0x0

    .line 110
    goto :goto_2

    .line 111
    :goto_3
    sget-object v1, Luu0/x;->q1:Ljava/util/List;

    .line 112
    .line 113
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 114
    .line 115
    .line 116
    move-result-object v1

    .line 117
    move-object v8, v1

    .line 118
    check-cast v8, Luu0/r;

    .line 119
    .line 120
    const/16 v28, 0x0

    .line 121
    .line 122
    const v29, 0x1fbfff

    .line 123
    .line 124
    .line 125
    const/4 v9, 0x0

    .line 126
    const/4 v10, 0x0

    .line 127
    const/4 v11, 0x0

    .line 128
    const/4 v12, 0x0

    .line 129
    const/4 v13, 0x0

    .line 130
    const/4 v14, 0x0

    .line 131
    const/4 v15, 0x0

    .line 132
    const/16 v16, 0x0

    .line 133
    .line 134
    const/16 v17, 0x0

    .line 135
    .line 136
    const/16 v18, 0x0

    .line 137
    .line 138
    const/16 v19, 0x0

    .line 139
    .line 140
    const/16 v20, 0x0

    .line 141
    .line 142
    const/16 v21, 0x0

    .line 143
    .line 144
    const/16 v23, 0x0

    .line 145
    .line 146
    const/16 v24, 0x0

    .line 147
    .line 148
    const/16 v25, 0x0

    .line 149
    .line 150
    const/16 v26, 0x0

    .line 151
    .line 152
    const/16 v27, 0x0

    .line 153
    .line 154
    invoke-static/range {v8 .. v29}, Luu0/r;->a(Luu0/r;Ljava/lang/String;Ljava/util/List;Luu0/q;ZZLjava/lang/String;Lss0/n;ZZZLss0/m;ZLhp0/e;ZZZLjava/time/OffsetDateTime;Lra0/c;ZZI)Luu0/r;

    .line 155
    .line 156
    .line 157
    move-result-object v1

    .line 158
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 159
    .line 160
    .line 161
    :cond_5
    return-object v6
.end method

.method public c(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 29

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    instance-of v2, v1, Luu0/i;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Luu0/i;

    .line 11
    .line 12
    iget v3, v2, Luu0/i;->g:I

    .line 13
    .line 14
    const/high16 v4, -0x80000000

    .line 15
    .line 16
    and-int v5, v3, v4

    .line 17
    .line 18
    if-eqz v5, :cond_0

    .line 19
    .line 20
    sub-int/2addr v3, v4

    .line 21
    iput v3, v2, Luu0/i;->g:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Luu0/i;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, Luu0/i;-><init>(Luu0/d;Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v2, Luu0/i;->e:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Luu0/i;->g:I

    .line 34
    .line 35
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    const/4 v6, 0x1

    .line 38
    iget-object v0, v0, Luu0/d;->e:Luu0/x;

    .line 39
    .line 40
    if-eqz v4, :cond_2

    .line 41
    .line 42
    if-ne v4, v6, :cond_1

    .line 43
    .line 44
    iget-object v2, v2, Luu0/i;->d:Luu0/x;

    .line 45
    .line 46
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 51
    .line 52
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 53
    .line 54
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw v0

    .line 58
    :cond_2
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    sget-object v1, Luu0/x;->q1:Ljava/util/List;

    .line 62
    .line 63
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    move-object v7, v1

    .line 68
    check-cast v7, Luu0/r;

    .line 69
    .line 70
    sget-object v25, Lra0/c;->f:Lra0/c;

    .line 71
    .line 72
    const/16 v27, 0x0

    .line 73
    .line 74
    const v28, 0x1bfaf6

    .line 75
    .line 76
    .line 77
    const-string v8, ""

    .line 78
    .line 79
    const/4 v9, 0x0

    .line 80
    const/4 v10, 0x0

    .line 81
    const/4 v11, 0x1

    .line 82
    const/4 v12, 0x0

    .line 83
    const/4 v13, 0x0

    .line 84
    const/4 v14, 0x0

    .line 85
    const/4 v15, 0x0

    .line 86
    const/16 v16, 0x0

    .line 87
    .line 88
    const/16 v17, 0x0

    .line 89
    .line 90
    const/16 v18, 0x0

    .line 91
    .line 92
    const/16 v19, 0x0

    .line 93
    .line 94
    const/16 v20, 0x0

    .line 95
    .line 96
    const/16 v21, 0x0

    .line 97
    .line 98
    const/16 v22, 0x0

    .line 99
    .line 100
    const/16 v23, 0x0

    .line 101
    .line 102
    const/16 v24, 0x0

    .line 103
    .line 104
    const/16 v26, 0x0

    .line 105
    .line 106
    invoke-static/range {v7 .. v28}, Luu0/r;->a(Luu0/r;Ljava/lang/String;Ljava/util/List;Luu0/q;ZZLjava/lang/String;Lss0/n;ZZZLss0/m;ZLhp0/e;ZZZLjava/time/OffsetDateTime;Lra0/c;ZZI)Luu0/r;

    .line 107
    .line 108
    .line 109
    move-result-object v1

    .line 110
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 111
    .line 112
    .line 113
    if-nez p1, :cond_5

    .line 114
    .line 115
    iget-object v1, v0, Luu0/x;->Q:Lqf0/g;

    .line 116
    .line 117
    iput-object v0, v2, Luu0/i;->d:Luu0/x;

    .line 118
    .line 119
    iput v6, v2, Luu0/i;->g:I

    .line 120
    .line 121
    invoke-virtual {v1, v5, v2}, Lqf0/g;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v1

    .line 125
    if-ne v1, v3, :cond_3

    .line 126
    .line 127
    return-object v3

    .line 128
    :cond_3
    move-object v2, v0

    .line 129
    :goto_1
    check-cast v1, Ljava/lang/Boolean;

    .line 130
    .line 131
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 132
    .line 133
    .line 134
    move-result v1

    .line 135
    if-eqz v1, :cond_4

    .line 136
    .line 137
    sget-object v1, Luu0/x;->q1:Ljava/util/List;

    .line 138
    .line 139
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 140
    .line 141
    .line 142
    move-result-object v0

    .line 143
    move-object v6, v0

    .line 144
    check-cast v6, Luu0/r;

    .line 145
    .line 146
    const/16 v26, 0x0

    .line 147
    .line 148
    const v27, 0x1fff77

    .line 149
    .line 150
    .line 151
    const/4 v7, 0x0

    .line 152
    const/4 v8, 0x0

    .line 153
    const/4 v9, 0x0

    .line 154
    const/4 v10, 0x1

    .line 155
    const/4 v11, 0x0

    .line 156
    const/4 v12, 0x0

    .line 157
    const/4 v13, 0x0

    .line 158
    const/4 v14, 0x0

    .line 159
    const/4 v15, 0x0

    .line 160
    const/16 v16, 0x0

    .line 161
    .line 162
    const/16 v17, 0x0

    .line 163
    .line 164
    const/16 v18, 0x0

    .line 165
    .line 166
    const/16 v19, 0x0

    .line 167
    .line 168
    const/16 v20, 0x0

    .line 169
    .line 170
    const/16 v21, 0x0

    .line 171
    .line 172
    const/16 v22, 0x0

    .line 173
    .line 174
    const/16 v23, 0x0

    .line 175
    .line 176
    const/16 v24, 0x0

    .line 177
    .line 178
    const/16 v25, 0x0

    .line 179
    .line 180
    invoke-static/range {v6 .. v27}, Luu0/r;->a(Luu0/r;Ljava/lang/String;Ljava/util/List;Luu0/q;ZZLjava/lang/String;Lss0/n;ZZZLss0/m;ZLhp0/e;ZZZLjava/time/OffsetDateTime;Lra0/c;ZZI)Luu0/r;

    .line 181
    .line 182
    .line 183
    move-result-object v0

    .line 184
    goto :goto_2

    .line 185
    :cond_4
    sget-object v1, Luu0/x;->q1:Ljava/util/List;

    .line 186
    .line 187
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 188
    .line 189
    .line 190
    move-result-object v0

    .line 191
    move-object v6, v0

    .line 192
    check-cast v6, Luu0/r;

    .line 193
    .line 194
    const/16 v26, 0x0

    .line 195
    .line 196
    const v27, 0x1ff976

    .line 197
    .line 198
    .line 199
    const-string v7, ""

    .line 200
    .line 201
    const/4 v8, 0x0

    .line 202
    const/4 v9, 0x0

    .line 203
    const/4 v10, 0x0

    .line 204
    const/4 v11, 0x0

    .line 205
    const/4 v12, 0x0

    .line 206
    const/4 v13, 0x0

    .line 207
    const/4 v14, 0x1

    .line 208
    const/4 v15, 0x0

    .line 209
    const/16 v16, 0x1

    .line 210
    .line 211
    const/16 v17, 0x0

    .line 212
    .line 213
    const/16 v18, 0x0

    .line 214
    .line 215
    const/16 v19, 0x0

    .line 216
    .line 217
    const/16 v20, 0x0

    .line 218
    .line 219
    const/16 v21, 0x0

    .line 220
    .line 221
    const/16 v22, 0x0

    .line 222
    .line 223
    const/16 v23, 0x0

    .line 224
    .line 225
    const/16 v24, 0x0

    .line 226
    .line 227
    const/16 v25, 0x0

    .line 228
    .line 229
    invoke-static/range {v6 .. v27}, Luu0/r;->a(Luu0/r;Ljava/lang/String;Ljava/util/List;Luu0/q;ZZLjava/lang/String;Lss0/n;ZZZLss0/m;ZLhp0/e;ZZZLjava/time/OffsetDateTime;Lra0/c;ZZI)Luu0/r;

    .line 230
    .line 231
    .line 232
    move-result-object v0

    .line 233
    :goto_2
    invoke-virtual {v2, v0}, Lql0/j;->g(Lql0/h;)V

    .line 234
    .line 235
    .line 236
    :cond_5
    return-object v5
.end method

.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 28

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    iget v2, v0, Luu0/d;->d:I

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 9
    .line 10
    iget-object v5, v0, Luu0/d;->e:Luu0/x;

    .line 11
    .line 12
    packed-switch v2, :pswitch_data_0

    .line 13
    .line 14
    .line 15
    move-object/from16 v23, p1

    .line 16
    .line 17
    check-cast v23, Ljava/time/OffsetDateTime;

    .line 18
    .line 19
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    move-object v6, v0

    .line 24
    check-cast v6, Luu0/r;

    .line 25
    .line 26
    const/16 v26, 0x0

    .line 27
    .line 28
    const v27, 0x1dffff

    .line 29
    .line 30
    .line 31
    const/4 v7, 0x0

    .line 32
    const/4 v8, 0x0

    .line 33
    const/4 v9, 0x0

    .line 34
    const/4 v10, 0x0

    .line 35
    const/4 v11, 0x0

    .line 36
    const/4 v12, 0x0

    .line 37
    const/4 v13, 0x0

    .line 38
    const/4 v14, 0x0

    .line 39
    const/4 v15, 0x0

    .line 40
    const/16 v16, 0x0

    .line 41
    .line 42
    const/16 v17, 0x0

    .line 43
    .line 44
    const/16 v18, 0x0

    .line 45
    .line 46
    const/16 v19, 0x0

    .line 47
    .line 48
    const/16 v20, 0x0

    .line 49
    .line 50
    const/16 v21, 0x0

    .line 51
    .line 52
    const/16 v22, 0x0

    .line 53
    .line 54
    const/16 v24, 0x0

    .line 55
    .line 56
    const/16 v25, 0x0

    .line 57
    .line 58
    invoke-static/range {v6 .. v27}, Luu0/r;->a(Luu0/r;Ljava/lang/String;Ljava/util/List;Luu0/q;ZZLjava/lang/String;Lss0/n;ZZZLss0/m;ZLhp0/e;ZZZLjava/time/OffsetDateTime;Lra0/c;ZZI)Luu0/r;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    invoke-virtual {v5, v0}, Lql0/j;->g(Lql0/h;)V

    .line 63
    .line 64
    .line 65
    return-object v4

    .line 66
    :pswitch_0
    move-object/from16 v2, p1

    .line 67
    .line 68
    check-cast v2, Lss0/j0;

    .line 69
    .line 70
    if-eqz v2, :cond_0

    .line 71
    .line 72
    iget-object v3, v2, Lss0/j0;->d:Ljava/lang/String;

    .line 73
    .line 74
    :cond_0
    invoke-virtual {v0, v3, v1}, Luu0/d;->c(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    return-object v0

    .line 79
    :pswitch_1
    move-object/from16 v0, p1

    .line 80
    .line 81
    check-cast v0, Lzb0/a;

    .line 82
    .line 83
    sget-object v2, Luu0/x;->q1:Ljava/util/List;

    .line 84
    .line 85
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 86
    .line 87
    .line 88
    move-result-object v2

    .line 89
    check-cast v2, Luu0/r;

    .line 90
    .line 91
    iget-object v2, v2, Luu0/r;->g:Lss0/n;

    .line 92
    .line 93
    sget-object v3, Lss0/n;->f:Lss0/n;

    .line 94
    .line 95
    const/4 v6, 0x0

    .line 96
    const/4 v7, 0x1

    .line 97
    if-ne v2, v3, :cond_1

    .line 98
    .line 99
    iget-object v2, v0, Lzb0/a;->d:Ljava/lang/String;

    .line 100
    .line 101
    const-string v8, "profile-downloaded"

    .line 102
    .line 103
    invoke-static {v2, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 104
    .line 105
    .line 106
    move-result v2

    .line 107
    if-eqz v2, :cond_1

    .line 108
    .line 109
    move v2, v7

    .line 110
    goto :goto_0

    .line 111
    :cond_1
    move v2, v6

    .line 112
    :goto_0
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 113
    .line 114
    .line 115
    move-result-object v8

    .line 116
    check-cast v8, Luu0/r;

    .line 117
    .line 118
    iget-object v8, v8, Luu0/r;->g:Lss0/n;

    .line 119
    .line 120
    if-eq v8, v3, :cond_2

    .line 121
    .line 122
    iget-object v0, v0, Lzb0/a;->d:Ljava/lang/String;

    .line 123
    .line 124
    const-string v3, "owner-verified"

    .line 125
    .line 126
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 127
    .line 128
    .line 129
    move-result v0

    .line 130
    if-eqz v0, :cond_2

    .line 131
    .line 132
    move v6, v7

    .line 133
    :cond_2
    if-nez v2, :cond_3

    .line 134
    .line 135
    if-eqz v6, :cond_4

    .line 136
    .line 137
    :cond_3
    invoke-static {v5, v1}, Luu0/x;->h(Luu0/x;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object v0

    .line 141
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 142
    .line 143
    if-ne v0, v1, :cond_4

    .line 144
    .line 145
    move-object v4, v0

    .line 146
    :cond_4
    return-object v4

    .line 147
    :pswitch_2
    move-object/from16 v0, p1

    .line 148
    .line 149
    check-cast v0, Lcn0/c;

    .line 150
    .line 151
    invoke-static {v5, v0, v1}, Luu0/x;->k(Luu0/x;Lcn0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object v0

    .line 155
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 156
    .line 157
    if-ne v0, v1, :cond_5

    .line 158
    .line 159
    move-object v4, v0

    .line 160
    :cond_5
    return-object v4

    .line 161
    :pswitch_3
    move-object/from16 v0, p1

    .line 162
    .line 163
    check-cast v0, Ljava/lang/Boolean;

    .line 164
    .line 165
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 166
    .line 167
    .line 168
    move-result v0

    .line 169
    sget-object v1, Luu0/x;->q1:Ljava/util/List;

    .line 170
    .line 171
    if-eqz v0, :cond_6

    .line 172
    .line 173
    invoke-static {v5}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 174
    .line 175
    .line 176
    move-result-object v0

    .line 177
    new-instance v1, Luu0/g;

    .line 178
    .line 179
    const/4 v2, 0x3

    .line 180
    invoke-direct {v1, v5, v3, v2}, Luu0/g;-><init>(Luu0/x;Lkotlin/coroutines/Continuation;I)V

    .line 181
    .line 182
    .line 183
    invoke-static {v0, v3, v3, v1, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 184
    .line 185
    .line 186
    :cond_6
    return-object v4

    .line 187
    :pswitch_4
    move-object/from16 v19, p1

    .line 188
    .line 189
    check-cast v19, Lhp0/e;

    .line 190
    .line 191
    sget-object v0, Luu0/x;->q1:Ljava/util/List;

    .line 192
    .line 193
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 194
    .line 195
    .line 196
    move-result-object v0

    .line 197
    move-object v6, v0

    .line 198
    check-cast v6, Luu0/r;

    .line 199
    .line 200
    const/16 v26, 0x0

    .line 201
    .line 202
    const v27, 0x1fdfff

    .line 203
    .line 204
    .line 205
    const/4 v7, 0x0

    .line 206
    const/4 v8, 0x0

    .line 207
    const/4 v9, 0x0

    .line 208
    const/4 v10, 0x0

    .line 209
    const/4 v11, 0x0

    .line 210
    const/4 v12, 0x0

    .line 211
    const/4 v13, 0x0

    .line 212
    const/4 v14, 0x0

    .line 213
    const/4 v15, 0x0

    .line 214
    const/16 v16, 0x0

    .line 215
    .line 216
    const/16 v17, 0x0

    .line 217
    .line 218
    const/16 v18, 0x0

    .line 219
    .line 220
    const/16 v20, 0x0

    .line 221
    .line 222
    const/16 v21, 0x0

    .line 223
    .line 224
    const/16 v22, 0x0

    .line 225
    .line 226
    const/16 v23, 0x0

    .line 227
    .line 228
    const/16 v24, 0x0

    .line 229
    .line 230
    const/16 v25, 0x0

    .line 231
    .line 232
    invoke-static/range {v6 .. v27}, Luu0/r;->a(Luu0/r;Ljava/lang/String;Ljava/util/List;Luu0/q;ZZLjava/lang/String;Lss0/n;ZZZLss0/m;ZLhp0/e;ZZZLjava/time/OffsetDateTime;Lra0/c;ZZI)Luu0/r;

    .line 233
    .line 234
    .line 235
    move-result-object v0

    .line 236
    invoke-virtual {v5, v0}, Lql0/j;->g(Lql0/h;)V

    .line 237
    .line 238
    .line 239
    return-object v4

    .line 240
    :pswitch_5
    move-object/from16 v0, p1

    .line 241
    .line 242
    check-cast v0, Lne0/s;

    .line 243
    .line 244
    instance-of v1, v0, Lne0/e;

    .line 245
    .line 246
    if-eqz v1, :cond_7

    .line 247
    .line 248
    check-cast v0, Lne0/e;

    .line 249
    .line 250
    iget-object v0, v0, Lne0/e;->a:Ljava/lang/Object;

    .line 251
    .line 252
    check-cast v0, Lyr0/e;

    .line 253
    .line 254
    iget-object v0, v0, Lyr0/e;->n:Ljava/util/List;

    .line 255
    .line 256
    sget-object v1, Lyr0/f;->j:Lyr0/f;

    .line 257
    .line 258
    invoke-interface {v0, v1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 259
    .line 260
    .line 261
    move-result v25

    .line 262
    sget-object v0, Luu0/x;->q1:Ljava/util/List;

    .line 263
    .line 264
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 265
    .line 266
    .line 267
    move-result-object v0

    .line 268
    move-object v6, v0

    .line 269
    check-cast v6, Luu0/r;

    .line 270
    .line 271
    const/16 v26, 0x0

    .line 272
    .line 273
    const v27, 0x17ffff

    .line 274
    .line 275
    .line 276
    const/4 v7, 0x0

    .line 277
    const/4 v8, 0x0

    .line 278
    const/4 v9, 0x0

    .line 279
    const/4 v10, 0x0

    .line 280
    const/4 v11, 0x0

    .line 281
    const/4 v12, 0x0

    .line 282
    const/4 v13, 0x0

    .line 283
    const/4 v14, 0x0

    .line 284
    const/4 v15, 0x0

    .line 285
    const/16 v16, 0x0

    .line 286
    .line 287
    const/16 v17, 0x0

    .line 288
    .line 289
    const/16 v18, 0x0

    .line 290
    .line 291
    const/16 v19, 0x0

    .line 292
    .line 293
    const/16 v20, 0x0

    .line 294
    .line 295
    const/16 v21, 0x0

    .line 296
    .line 297
    const/16 v22, 0x0

    .line 298
    .line 299
    const/16 v23, 0x0

    .line 300
    .line 301
    const/16 v24, 0x0

    .line 302
    .line 303
    invoke-static/range {v6 .. v27}, Luu0/r;->a(Luu0/r;Ljava/lang/String;Ljava/util/List;Luu0/q;ZZLjava/lang/String;Lss0/n;ZZZLss0/m;ZLhp0/e;ZZZLjava/time/OffsetDateTime;Lra0/c;ZZI)Luu0/r;

    .line 304
    .line 305
    .line 306
    move-result-object v0

    .line 307
    invoke-virtual {v5, v0}, Lql0/j;->g(Lql0/h;)V

    .line 308
    .line 309
    .line 310
    :cond_7
    return-object v4

    .line 311
    :pswitch_6
    move-object/from16 v0, p1

    .line 312
    .line 313
    check-cast v0, Ljava/lang/Boolean;

    .line 314
    .line 315
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 316
    .line 317
    .line 318
    move-result v22

    .line 319
    sget-object v0, Luu0/x;->q1:Ljava/util/List;

    .line 320
    .line 321
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 322
    .line 323
    .line 324
    move-result-object v0

    .line 325
    move-object v6, v0

    .line 326
    check-cast v6, Luu0/r;

    .line 327
    .line 328
    const/16 v26, 0x0

    .line 329
    .line 330
    const v27, 0x1effff

    .line 331
    .line 332
    .line 333
    const/4 v7, 0x0

    .line 334
    const/4 v8, 0x0

    .line 335
    const/4 v9, 0x0

    .line 336
    const/4 v10, 0x0

    .line 337
    const/4 v11, 0x0

    .line 338
    const/4 v12, 0x0

    .line 339
    const/4 v13, 0x0

    .line 340
    const/4 v14, 0x0

    .line 341
    const/4 v15, 0x0

    .line 342
    const/16 v16, 0x0

    .line 343
    .line 344
    const/16 v17, 0x0

    .line 345
    .line 346
    const/16 v18, 0x0

    .line 347
    .line 348
    const/16 v19, 0x0

    .line 349
    .line 350
    const/16 v20, 0x0

    .line 351
    .line 352
    const/16 v21, 0x0

    .line 353
    .line 354
    const/16 v23, 0x0

    .line 355
    .line 356
    const/16 v24, 0x0

    .line 357
    .line 358
    const/16 v25, 0x0

    .line 359
    .line 360
    invoke-static/range {v6 .. v27}, Luu0/r;->a(Luu0/r;Ljava/lang/String;Ljava/util/List;Luu0/q;ZZLjava/lang/String;Lss0/n;ZZZLss0/m;ZLhp0/e;ZZZLjava/time/OffsetDateTime;Lra0/c;ZZI)Luu0/r;

    .line 361
    .line 362
    .line 363
    move-result-object v0

    .line 364
    invoke-virtual {v5, v0}, Lql0/j;->g(Lql0/h;)V

    .line 365
    .line 366
    .line 367
    return-object v4

    .line 368
    :pswitch_7
    move-object/from16 v2, p1

    .line 369
    .line 370
    check-cast v2, Lne0/s;

    .line 371
    .line 372
    invoke-virtual {v0, v2, v1}, Luu0/d;->b(Lne0/s;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 373
    .line 374
    .line 375
    move-result-object v0

    .line 376
    return-object v0

    .line 377
    :pswitch_data_0
    .packed-switch 0x0
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
