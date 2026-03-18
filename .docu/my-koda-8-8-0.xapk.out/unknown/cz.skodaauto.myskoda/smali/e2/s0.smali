.class public final Le2/s0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt1/w0;


# instance fields
.field public final synthetic a:I

.field public b:Z

.field public final synthetic c:Le2/w0;


# direct methods
.method public constructor <init>(Le2/w0;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Le2/s0;->a:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Le2/s0;->c:Le2/w0;

    const/4 p1, 0x1

    .line 3
    iput-boolean p1, p0, Le2/s0;->b:Z

    return-void
.end method

.method public constructor <init>(Le2/w0;Z)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Le2/s0;->a:I

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    iput-object p1, p0, Le2/s0;->c:Le2/w0;

    iput-boolean p2, p0, Le2/s0;->b:Z

    return-void
.end method

.method private final f()V
    .locals 0

    .line 1
    return-void
.end method

.method private final g()V
    .locals 0

    .line 1
    return-void
.end method

.method private final i(J)V
    .locals 0

    .line 1
    return-void
.end method

.method private final j()V
    .locals 0

    .line 1
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 3

    .line 1
    iget v0, p0, Le2/s0;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :pswitch_0
    iget-boolean v0, p0, Le2/s0;->b:Z

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    sget-object v1, Lt1/b0;->e:Lt1/b0;

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    sget-object v1, Lt1/b0;->f:Lt1/b0;

    .line 15
    .line 16
    :goto_0
    iget-object p0, p0, Le2/s0;->c:Le2/w0;

    .line 17
    .line 18
    iget-object v2, p0, Le2/w0;->q:Ll2/j1;

    .line 19
    .line 20
    invoke-virtual {v2, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0, v0}, Le2/w0;->k(Z)J

    .line 24
    .line 25
    .line 26
    move-result-wide v0

    .line 27
    invoke-static {v0, v1}, Le2/d0;->a(J)J

    .line 28
    .line 29
    .line 30
    move-result-wide v0

    .line 31
    iget-object v2, p0, Le2/w0;->d:Lt1/p0;

    .line 32
    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    invoke-virtual {v2}, Lt1/p0;->d()Lt1/j1;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    if-nez v2, :cond_1

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    invoke-virtual {v2, v0, v1}, Lt1/j1;->e(J)J

    .line 43
    .line 44
    .line 45
    move-result-wide v0

    .line 46
    iput-wide v0, p0, Le2/w0;->n:J

    .line 47
    .line 48
    new-instance v2, Ld3/b;

    .line 49
    .line 50
    invoke-direct {v2, v0, v1}, Ld3/b;-><init>(J)V

    .line 51
    .line 52
    .line 53
    iget-object v0, p0, Le2/w0;->r:Ll2/j1;

    .line 54
    .line 55
    invoke-virtual {v0, v2}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    const-wide/16 v0, 0x0

    .line 59
    .line 60
    iput-wide v0, p0, Le2/w0;->p:J

    .line 61
    .line 62
    const/4 v0, -0x1

    .line 63
    iput v0, p0, Le2/w0;->s:I

    .line 64
    .line 65
    iget-object v0, p0, Le2/w0;->d:Lt1/p0;

    .line 66
    .line 67
    if-eqz v0, :cond_2

    .line 68
    .line 69
    iget-object v0, v0, Lt1/p0;->q:Ll2/j1;

    .line 70
    .line 71
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 72
    .line 73
    invoke-virtual {v0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    :cond_2
    const/4 v0, 0x0

    .line 77
    invoke-virtual {p0, v0}, Le2/w0;->s(Z)V

    .line 78
    .line 79
    .line 80
    :cond_3
    :goto_1
    return-void

    .line 81
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final b(J)V
    .locals 11

    .line 1
    iget v0, p0, Le2/s0;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Le2/s0;->c:Le2/w0;

    .line 7
    .line 8
    iget-object v0, v1, Le2/w0;->q:Ll2/j1;

    .line 9
    .line 10
    invoke-virtual {v1}, Le2/w0;->j()Z

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    if-eqz v2, :cond_5

    .line 15
    .line 16
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    check-cast v2, Lt1/b0;

    .line 21
    .line 22
    if-eqz v2, :cond_0

    .line 23
    .line 24
    goto/16 :goto_1

    .line 25
    .line 26
    :cond_0
    sget-object v2, Lt1/b0;->f:Lt1/b0;

    .line 27
    .line 28
    invoke-virtual {v0, v2}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    const/4 v0, -0x1

    .line 32
    iput v0, v1, Le2/w0;->s:I

    .line 33
    .line 34
    const/4 v0, 0x1

    .line 35
    iput-boolean v0, p0, Le2/s0;->b:Z

    .line 36
    .line 37
    invoke-virtual {v1}, Le2/w0;->n()V

    .line 38
    .line 39
    .line 40
    iget-object v2, v1, Le2/w0;->d:Lt1/p0;

    .line 41
    .line 42
    const/4 v3, 0x0

    .line 43
    if-eqz v2, :cond_2

    .line 44
    .line 45
    invoke-virtual {v2}, Lt1/p0;->d()Lt1/j1;

    .line 46
    .line 47
    .line 48
    move-result-object v2

    .line 49
    if-eqz v2, :cond_2

    .line 50
    .line 51
    invoke-virtual {v2, p1, p2}, Lt1/j1;->c(J)Z

    .line 52
    .line 53
    .line 54
    move-result v2

    .line 55
    if-ne v2, v0, :cond_2

    .line 56
    .line 57
    invoke-virtual {v1}, Le2/w0;->m()Ll4/v;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    iget-object p0, p0, Ll4/v;->a:Lg4/g;

    .line 62
    .line 63
    iget-object p0, p0, Lg4/g;->e:Ljava/lang/String;

    .line 64
    .line 65
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 66
    .line 67
    .line 68
    move-result p0

    .line 69
    if-nez p0, :cond_1

    .line 70
    .line 71
    goto/16 :goto_1

    .line 72
    .line 73
    :cond_1
    invoke-virtual {v1, v3}, Le2/w0;->h(Z)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {v1}, Le2/w0;->m()Ll4/v;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    sget-wide v2, Lg4/o0;->b:J

    .line 81
    .line 82
    const/4 v0, 0x5

    .line 83
    const/4 v4, 0x0

    .line 84
    invoke-static {p0, v4, v2, v3, v0}, Ll4/v;->a(Ll4/v;Lg4/g;JI)Ll4/v;

    .line 85
    .line 86
    .line 87
    move-result-object v2

    .line 88
    sget-object v7, Le2/t;->e:Lc1/y;

    .line 89
    .line 90
    const/4 v8, 0x1

    .line 91
    const/4 v5, 0x1

    .line 92
    const/4 v6, 0x0

    .line 93
    move-wide v3, p1

    .line 94
    invoke-static/range {v1 .. v8}, Le2/w0;->c(Le2/w0;Ll4/v;JZZLc1/y;Z)J

    .line 95
    .line 96
    .line 97
    move-result-wide p0

    .line 98
    move-object p2, v1

    .line 99
    move-wide v1, v3

    .line 100
    new-instance v0, Lg4/o0;

    .line 101
    .line 102
    invoke-direct {v0, p0, p1}, Lg4/o0;-><init>(J)V

    .line 103
    .line 104
    .line 105
    iput-object v0, p2, Le2/w0;->o:Lg4/o0;

    .line 106
    .line 107
    goto :goto_0

    .line 108
    :cond_2
    move-wide v9, p1

    .line 109
    move-object p2, v1

    .line 110
    move-wide v1, v9

    .line 111
    iget-object p1, p2, Le2/w0;->d:Lt1/p0;

    .line 112
    .line 113
    if-eqz p1, :cond_4

    .line 114
    .line 115
    invoke-virtual {p1}, Lt1/p0;->d()Lt1/j1;

    .line 116
    .line 117
    .line 118
    move-result-object p1

    .line 119
    if-eqz p1, :cond_4

    .line 120
    .line 121
    invoke-virtual {p1, v1, v2, v0}, Lt1/j1;->b(JZ)I

    .line 122
    .line 123
    .line 124
    move-result p1

    .line 125
    iget-object v0, p2, Le2/w0;->b:Ll4/p;

    .line 126
    .line 127
    invoke-interface {v0, p1}, Ll4/p;->E(I)I

    .line 128
    .line 129
    .line 130
    move-result p1

    .line 131
    invoke-virtual {p2}, Le2/w0;->m()Ll4/v;

    .line 132
    .line 133
    .line 134
    move-result-object v0

    .line 135
    iget-object v0, v0, Ll4/v;->a:Lg4/g;

    .line 136
    .line 137
    invoke-static {p1, p1}, Lg4/f0;->b(II)J

    .line 138
    .line 139
    .line 140
    move-result-wide v4

    .line 141
    invoke-static {v0, v4, v5}, Le2/w0;->e(Lg4/g;J)Ll4/v;

    .line 142
    .line 143
    .line 144
    move-result-object p1

    .line 145
    invoke-virtual {p2, v3}, Le2/w0;->h(Z)V

    .line 146
    .line 147
    .line 148
    iget-object v0, p2, Le2/w0;->j:Ll3/a;

    .line 149
    .line 150
    if-eqz v0, :cond_3

    .line 151
    .line 152
    const/16 v4, 0x9

    .line 153
    .line 154
    invoke-interface {v0, v4}, Ll3/a;->a(I)V

    .line 155
    .line 156
    .line 157
    :cond_3
    iget-object v0, p2, Le2/w0;->c:Lay0/k;

    .line 158
    .line 159
    invoke-interface {v0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    iget-wide v4, p1, Ll4/v;->b:J

    .line 163
    .line 164
    new-instance p1, Lg4/o0;

    .line 165
    .line 166
    invoke-direct {p1, v4, v5}, Lg4/o0;-><init>(J)V

    .line 167
    .line 168
    .line 169
    iput-object p1, p2, Le2/w0;->v:Lg4/o0;

    .line 170
    .line 171
    :cond_4
    iput-boolean v3, p0, Le2/s0;->b:Z

    .line 172
    .line 173
    :goto_0
    sget-object p0, Lt1/c0;->d:Lt1/c0;

    .line 174
    .line 175
    invoke-virtual {p2, p0}, Le2/w0;->p(Lt1/c0;)V

    .line 176
    .line 177
    .line 178
    iput-wide v1, p2, Le2/w0;->n:J

    .line 179
    .line 180
    new-instance p0, Ld3/b;

    .line 181
    .line 182
    invoke-direct {p0, v1, v2}, Ld3/b;-><init>(J)V

    .line 183
    .line 184
    .line 185
    iget-object p1, p2, Le2/w0;->r:Ll2/j1;

    .line 186
    .line 187
    invoke-virtual {p1, p0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 188
    .line 189
    .line 190
    const-wide/16 p0, 0x0

    .line 191
    .line 192
    iput-wide p0, p2, Le2/w0;->p:J

    .line 193
    .line 194
    :cond_5
    :goto_1
    :pswitch_0
    return-void

    .line 195
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final c()V
    .locals 2

    .line 1
    iget v0, p0, Le2/s0;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Le2/s0;->h()V

    .line 7
    .line 8
    .line 9
    return-void

    .line 10
    :pswitch_0
    iget-object p0, p0, Le2/s0;->c:Le2/w0;

    .line 11
    .line 12
    iget-object v0, p0, Le2/w0;->q:Ll2/j1;

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    invoke-virtual {v0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    iget-object v0, p0, Le2/w0;->r:Ll2/j1;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    const/4 v0, 0x1

    .line 24
    invoke-virtual {p0, v0}, Le2/w0;->s(Z)V

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final d()V
    .locals 2

    .line 1
    iget v0, p0, Le2/s0;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :pswitch_0
    iget-object p0, p0, Le2/s0;->c:Le2/w0;

    .line 8
    .line 9
    iget-object v0, p0, Le2/w0;->q:Ll2/j1;

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    invoke-virtual {v0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    iget-object v0, p0, Le2/w0;->r:Ll2/j1;

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    const/4 v0, 0x1

    .line 21
    invoke-virtual {p0, v0}, Le2/w0;->s(Z)V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final e(J)V
    .locals 13

    .line 1
    iget v3, p0, Le2/s0;->a:I

    .line 2
    .line 3
    packed-switch v3, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v10, Le2/t;->e:Lc1/y;

    .line 7
    .line 8
    iget-object v4, p0, Le2/s0;->c:Le2/w0;

    .line 9
    .line 10
    invoke-virtual {v4}, Le2/w0;->j()Z

    .line 11
    .line 12
    .line 13
    move-result v3

    .line 14
    if-eqz v3, :cond_7

    .line 15
    .line 16
    invoke-virtual {v4}, Le2/w0;->m()Ll4/v;

    .line 17
    .line 18
    .line 19
    move-result-object v3

    .line 20
    iget-object v3, v3, Ll4/v;->a:Lg4/g;

    .line 21
    .line 22
    iget-object v3, v3, Lg4/g;->e:Ljava/lang/String;

    .line 23
    .line 24
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    if-nez v3, :cond_0

    .line 29
    .line 30
    goto/16 :goto_3

    .line 31
    .line 32
    :cond_0
    iget-wide v5, v4, Le2/w0;->p:J

    .line 33
    .line 34
    invoke-static {v5, v6, p1, p2}, Ld3/b;->h(JJ)J

    .line 35
    .line 36
    .line 37
    move-result-wide v1

    .line 38
    iput-wide v1, v4, Le2/w0;->p:J

    .line 39
    .line 40
    iget-object v1, v4, Le2/w0;->d:Lt1/p0;

    .line 41
    .line 42
    const/4 v12, 0x0

    .line 43
    if-eqz v1, :cond_5

    .line 44
    .line 45
    invoke-virtual {v1}, Lt1/p0;->d()Lt1/j1;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    if-eqz v1, :cond_5

    .line 50
    .line 51
    iget-wide v2, v4, Le2/w0;->n:J

    .line 52
    .line 53
    iget-wide v5, v4, Le2/w0;->p:J

    .line 54
    .line 55
    invoke-static {v2, v3, v5, v6}, Ld3/b;->h(JJ)J

    .line 56
    .line 57
    .line 58
    move-result-wide v2

    .line 59
    new-instance v5, Ld3/b;

    .line 60
    .line 61
    invoke-direct {v5, v2, v3}, Ld3/b;-><init>(J)V

    .line 62
    .line 63
    .line 64
    iget-object v2, v4, Le2/w0;->r:Ll2/j1;

    .line 65
    .line 66
    invoke-virtual {v2, v5}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    iget-object v2, v4, Le2/w0;->o:Lg4/o0;

    .line 70
    .line 71
    if-nez v2, :cond_2

    .line 72
    .line 73
    invoke-virtual {v4}, Le2/w0;->i()Ld3/b;

    .line 74
    .line 75
    .line 76
    move-result-object v2

    .line 77
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    iget-wide v2, v2, Ld3/b;->a:J

    .line 81
    .line 82
    invoke-virtual {v1, v2, v3}, Lt1/j1;->c(J)Z

    .line 83
    .line 84
    .line 85
    move-result v2

    .line 86
    if-nez v2, :cond_2

    .line 87
    .line 88
    iget-object v2, v4, Le2/w0;->b:Ll4/p;

    .line 89
    .line 90
    iget-wide v5, v4, Le2/w0;->n:J

    .line 91
    .line 92
    const/4 v3, 0x1

    .line 93
    invoke-virtual {v1, v5, v6, v3}, Lt1/j1;->b(JZ)I

    .line 94
    .line 95
    .line 96
    move-result v5

    .line 97
    invoke-interface {v2, v5}, Ll4/p;->E(I)I

    .line 98
    .line 99
    .line 100
    move-result v2

    .line 101
    iget-object v5, v4, Le2/w0;->b:Ll4/p;

    .line 102
    .line 103
    invoke-virtual {v4}, Le2/w0;->i()Ld3/b;

    .line 104
    .line 105
    .line 106
    move-result-object v6

    .line 107
    invoke-static {v6}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    iget-wide v6, v6, Ld3/b;->a:J

    .line 111
    .line 112
    invoke-virtual {v1, v6, v7, v3}, Lt1/j1;->b(JZ)I

    .line 113
    .line 114
    .line 115
    move-result v1

    .line 116
    invoke-interface {v5, v1}, Ll4/p;->E(I)I

    .line 117
    .line 118
    .line 119
    move-result v1

    .line 120
    if-ne v2, v1, :cond_1

    .line 121
    .line 122
    sget-object v10, Le2/t;->d:Lc1/y;

    .line 123
    .line 124
    :cond_1
    move-object v7, v10

    .line 125
    invoke-virtual {v4}, Le2/w0;->m()Ll4/v;

    .line 126
    .line 127
    .line 128
    move-result-object v2

    .line 129
    invoke-virtual {v4}, Le2/w0;->i()Ld3/b;

    .line 130
    .line 131
    .line 132
    move-result-object v1

    .line 133
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    iget-wide v5, v1, Ld3/b;->a:J

    .line 137
    .line 138
    move-object v1, v4

    .line 139
    move-wide v3, v5

    .line 140
    const/4 v6, 0x0

    .line 141
    const/4 v8, 0x1

    .line 142
    const/4 v5, 0x0

    .line 143
    invoke-static/range {v1 .. v8}, Le2/w0;->c(Le2/w0;Ll4/v;JZZLc1/y;Z)J

    .line 144
    .line 145
    .line 146
    move-result-wide v2

    .line 147
    goto :goto_1

    .line 148
    :cond_2
    iget-object v2, v4, Le2/w0;->o:Lg4/o0;

    .line 149
    .line 150
    if-eqz v2, :cond_3

    .line 151
    .line 152
    iget-wide v2, v2, Lg4/o0;->a:J

    .line 153
    .line 154
    const/16 v5, 0x20

    .line 155
    .line 156
    shr-long/2addr v2, v5

    .line 157
    long-to-int v2, v2

    .line 158
    goto :goto_0

    .line 159
    :cond_3
    iget-wide v2, v4, Le2/w0;->n:J

    .line 160
    .line 161
    invoke-virtual {v1, v2, v3, v12}, Lt1/j1;->b(JZ)I

    .line 162
    .line 163
    .line 164
    move-result v2

    .line 165
    :goto_0
    invoke-virtual {v4}, Le2/w0;->i()Ld3/b;

    .line 166
    .line 167
    .line 168
    move-result-object v3

    .line 169
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 170
    .line 171
    .line 172
    iget-wide v5, v3, Ld3/b;->a:J

    .line 173
    .line 174
    invoke-virtual {v1, v5, v6, v12}, Lt1/j1;->b(JZ)I

    .line 175
    .line 176
    .line 177
    move-result v1

    .line 178
    iget-object v3, v4, Le2/w0;->o:Lg4/o0;

    .line 179
    .line 180
    if-nez v3, :cond_4

    .line 181
    .line 182
    if-ne v2, v1, :cond_4

    .line 183
    .line 184
    goto :goto_3

    .line 185
    :cond_4
    invoke-virtual {v4}, Le2/w0;->m()Ll4/v;

    .line 186
    .line 187
    .line 188
    move-result-object v5

    .line 189
    invoke-virtual {v4}, Le2/w0;->i()Ld3/b;

    .line 190
    .line 191
    .line 192
    move-result-object v1

    .line 193
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 194
    .line 195
    .line 196
    iget-wide v6, v1, Ld3/b;->a:J

    .line 197
    .line 198
    const/4 v9, 0x0

    .line 199
    const/4 v11, 0x1

    .line 200
    const/4 v8, 0x0

    .line 201
    invoke-static/range {v4 .. v11}, Le2/w0;->c(Le2/w0;Ll4/v;JZZLc1/y;Z)J

    .line 202
    .line 203
    .line 204
    move-result-wide v2

    .line 205
    move-object v1, v4

    .line 206
    :goto_1
    iget-object v4, v1, Le2/w0;->o:Lg4/o0;

    .line 207
    .line 208
    invoke-static {v2, v3, v4}, Lg4/o0;->a(JLjava/lang/Object;)Z

    .line 209
    .line 210
    .line 211
    move-result v2

    .line 212
    if-nez v2, :cond_6

    .line 213
    .line 214
    iput-boolean v12, p0, Le2/s0;->b:Z

    .line 215
    .line 216
    goto :goto_2

    .line 217
    :cond_5
    move-object v1, v4

    .line 218
    :cond_6
    :goto_2
    invoke-virtual {v1, v12}, Le2/w0;->s(Z)V

    .line 219
    .line 220
    .line 221
    :cond_7
    :goto_3
    return-void

    .line 222
    :pswitch_0
    iget-object v3, p0, Le2/s0;->c:Le2/w0;

    .line 223
    .line 224
    iget-wide v4, v3, Le2/w0;->p:J

    .line 225
    .line 226
    invoke-static {v4, v5, p1, p2}, Ld3/b;->h(JJ)J

    .line 227
    .line 228
    .line 229
    move-result-wide v1

    .line 230
    iput-wide v1, v3, Le2/w0;->p:J

    .line 231
    .line 232
    iget-wide v4, v3, Le2/w0;->n:J

    .line 233
    .line 234
    invoke-static {v4, v5, v1, v2}, Ld3/b;->h(JJ)J

    .line 235
    .line 236
    .line 237
    move-result-wide v1

    .line 238
    new-instance v4, Ld3/b;

    .line 239
    .line 240
    invoke-direct {v4, v1, v2}, Ld3/b;-><init>(J)V

    .line 241
    .line 242
    .line 243
    iget-object v1, v3, Le2/w0;->r:Ll2/j1;

    .line 244
    .line 245
    invoke-virtual {v1, v4}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 246
    .line 247
    .line 248
    invoke-virtual {v3}, Le2/w0;->m()Ll4/v;

    .line 249
    .line 250
    .line 251
    move-result-object v4

    .line 252
    invoke-virtual {v3}, Le2/w0;->i()Ld3/b;

    .line 253
    .line 254
    .line 255
    move-result-object v1

    .line 256
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 257
    .line 258
    .line 259
    iget-wide v5, v1, Ld3/b;->a:J

    .line 260
    .line 261
    iget-boolean v8, p0, Le2/s0;->b:Z

    .line 262
    .line 263
    sget-object v9, Le2/t;->g:Lc1/y;

    .line 264
    .line 265
    const/4 v10, 0x1

    .line 266
    const/4 v7, 0x0

    .line 267
    invoke-static/range {v3 .. v10}, Le2/w0;->c(Le2/w0;Ll4/v;JZZLc1/y;Z)J

    .line 268
    .line 269
    .line 270
    const/4 v0, 0x0

    .line 271
    invoke-virtual {v3, v0}, Le2/w0;->s(Z)V

    .line 272
    .line 273
    .line 274
    return-void

    .line 275
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public h()V
    .locals 7

    .line 1
    iget-object v0, p0, Le2/s0;->c:Le2/w0;

    .line 2
    .line 3
    iget-object v1, v0, Le2/w0;->q:Ll2/j1;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-virtual {v1, v2}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    iget-object v1, v0, Le2/w0;->r:Ll2/j1;

    .line 10
    .line 11
    invoke-virtual {v1, v2}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    const/4 v1, 0x1

    .line 15
    invoke-virtual {v0, v1}, Le2/w0;->s(Z)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Le2/w0;->m()Ll4/v;

    .line 19
    .line 20
    .line 21
    move-result-object v3

    .line 22
    iget-wide v3, v3, Ll4/v;->b:J

    .line 23
    .line 24
    invoke-static {v3, v4}, Lg4/o0;->c(J)Z

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    if-eqz v3, :cond_0

    .line 29
    .line 30
    sget-object v4, Lt1/c0;->f:Lt1/c0;

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    sget-object v4, Lt1/c0;->e:Lt1/c0;

    .line 34
    .line 35
    :goto_0
    invoke-virtual {v0, v4}, Le2/w0;->p(Lt1/c0;)V

    .line 36
    .line 37
    .line 38
    iget-object v4, v0, Le2/w0;->d:Lt1/p0;

    .line 39
    .line 40
    const/4 v5, 0x0

    .line 41
    if-eqz v4, :cond_2

    .line 42
    .line 43
    if-nez v3, :cond_1

    .line 44
    .line 45
    invoke-static {v0, v1}, Lkp/w;->c(Le2/w0;Z)Z

    .line 46
    .line 47
    .line 48
    move-result v6

    .line 49
    if-eqz v6, :cond_1

    .line 50
    .line 51
    move v6, v1

    .line 52
    goto :goto_1

    .line 53
    :cond_1
    move v6, v5

    .line 54
    :goto_1
    iget-object v4, v4, Lt1/p0;->m:Ll2/j1;

    .line 55
    .line 56
    invoke-static {v6}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 57
    .line 58
    .line 59
    move-result-object v6

    .line 60
    invoke-virtual {v4, v6}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    :cond_2
    iget-object v4, v0, Le2/w0;->d:Lt1/p0;

    .line 64
    .line 65
    if-eqz v4, :cond_4

    .line 66
    .line 67
    if-nez v3, :cond_3

    .line 68
    .line 69
    invoke-static {v0, v5}, Lkp/w;->c(Le2/w0;Z)Z

    .line 70
    .line 71
    .line 72
    move-result v6

    .line 73
    if-eqz v6, :cond_3

    .line 74
    .line 75
    move v6, v1

    .line 76
    goto :goto_2

    .line 77
    :cond_3
    move v6, v5

    .line 78
    :goto_2
    iget-object v4, v4, Lt1/p0;->n:Ll2/j1;

    .line 79
    .line 80
    invoke-static {v6}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 81
    .line 82
    .line 83
    move-result-object v6

    .line 84
    invoke-virtual {v4, v6}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    :cond_4
    iget-object v4, v0, Le2/w0;->d:Lt1/p0;

    .line 88
    .line 89
    if-eqz v4, :cond_6

    .line 90
    .line 91
    if-eqz v3, :cond_5

    .line 92
    .line 93
    invoke-static {v0, v1}, Lkp/w;->c(Le2/w0;Z)Z

    .line 94
    .line 95
    .line 96
    move-result v3

    .line 97
    if-eqz v3, :cond_5

    .line 98
    .line 99
    goto :goto_3

    .line 100
    :cond_5
    move v1, v5

    .line 101
    :goto_3
    iget-object v3, v4, Lt1/p0;->o:Ll2/j1;

    .line 102
    .line 103
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 104
    .line 105
    .line 106
    move-result-object v1

    .line 107
    invoke-virtual {v3, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    :cond_6
    iget-boolean p0, p0, Le2/s0;->b:Z

    .line 111
    .line 112
    if-eqz p0, :cond_7

    .line 113
    .line 114
    iget-object p0, v0, Le2/w0;->o:Lg4/o0;

    .line 115
    .line 116
    invoke-static {v0, p0}, Le2/w0;->a(Le2/w0;Lg4/o0;)V

    .line 117
    .line 118
    .line 119
    :cond_7
    iput-object v2, v0, Le2/w0;->o:Lg4/o0;

    .line 120
    .line 121
    return-void
.end method

.method public final onCancel()V
    .locals 1

    .line 1
    iget v0, p0, Le2/s0;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Le2/s0;->h()V

    .line 7
    .line 8
    .line 9
    :pswitch_0
    return-void

    .line 10
    nop

    .line 11
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
