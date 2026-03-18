.class public final Lv9/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv9/h;


# instance fields
.field public final synthetic a:I

.field public b:Z

.field public c:J

.field public d:I

.field public e:I

.field public final f:Ljava/lang/Object;

.field public g:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 2

    const/4 v0, 0x1

    iput v0, p0, Lv9/g;->a:I

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    new-instance v0, Lw7/p;

    const/16 v1, 0xa

    invoke-direct {v0, v1}, Lw7/p;-><init>(I)V

    iput-object v0, p0, Lv9/g;->f:Ljava/lang/Object;

    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 7
    iput-wide v0, p0, Lv9/g;->c:J

    return-void
.end method

.method public constructor <init>(Ljava/util/List;)V
    .locals 2

    const/4 v0, 0x0

    iput v0, p0, Lv9/g;->a:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lv9/g;->f:Ljava/lang/Object;

    .line 3
    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result p1

    new-array p1, p1, [Lo8/i0;

    iput-object p1, p0, Lv9/g;->g:Ljava/lang/Object;

    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 4
    iput-wide v0, p0, Lv9/g;->c:J

    return-void
.end method


# virtual methods
.method public final b(Lw7/p;)V
    .locals 9

    .line 1
    iget v0, p0, Lv9/g;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lv9/g;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lw7/p;

    .line 9
    .line 10
    iget-object v1, p0, Lv9/g;->g:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lo8/i0;

    .line 13
    .line 14
    invoke-static {v1}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    iget-boolean v1, p0, Lv9/g;->b:Z

    .line 18
    .line 19
    if-nez v1, :cond_0

    .line 20
    .line 21
    goto :goto_2

    .line 22
    :cond_0
    invoke-virtual {p1}, Lw7/p;->a()I

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    iget v2, p0, Lv9/g;->e:I

    .line 27
    .line 28
    const/4 v3, 0x0

    .line 29
    const/16 v4, 0xa

    .line 30
    .line 31
    if-ge v2, v4, :cond_3

    .line 32
    .line 33
    rsub-int/lit8 v2, v2, 0xa

    .line 34
    .line 35
    invoke-static {v1, v2}, Ljava/lang/Math;->min(II)I

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    iget-object v5, p1, Lw7/p;->a:[B

    .line 40
    .line 41
    iget v6, p1, Lw7/p;->b:I

    .line 42
    .line 43
    iget-object v7, v0, Lw7/p;->a:[B

    .line 44
    .line 45
    iget v8, p0, Lv9/g;->e:I

    .line 46
    .line 47
    invoke-static {v5, v6, v7, v8, v2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 48
    .line 49
    .line 50
    iget v5, p0, Lv9/g;->e:I

    .line 51
    .line 52
    add-int/2addr v5, v2

    .line 53
    if-ne v5, v4, :cond_3

    .line 54
    .line 55
    invoke-virtual {v0, v3}, Lw7/p;->I(I)V

    .line 56
    .line 57
    .line 58
    const/16 v2, 0x49

    .line 59
    .line 60
    invoke-virtual {v0}, Lw7/p;->w()I

    .line 61
    .line 62
    .line 63
    move-result v5

    .line 64
    if-ne v2, v5, :cond_2

    .line 65
    .line 66
    const/16 v2, 0x44

    .line 67
    .line 68
    invoke-virtual {v0}, Lw7/p;->w()I

    .line 69
    .line 70
    .line 71
    move-result v5

    .line 72
    if-ne v2, v5, :cond_2

    .line 73
    .line 74
    const/16 v2, 0x33

    .line 75
    .line 76
    invoke-virtual {v0}, Lw7/p;->w()I

    .line 77
    .line 78
    .line 79
    move-result v5

    .line 80
    if-eq v2, v5, :cond_1

    .line 81
    .line 82
    goto :goto_0

    .line 83
    :cond_1
    const/4 v2, 0x3

    .line 84
    invoke-virtual {v0, v2}, Lw7/p;->J(I)V

    .line 85
    .line 86
    .line 87
    invoke-virtual {v0}, Lw7/p;->v()I

    .line 88
    .line 89
    .line 90
    move-result v0

    .line 91
    add-int/2addr v0, v4

    .line 92
    iput v0, p0, Lv9/g;->d:I

    .line 93
    .line 94
    goto :goto_1

    .line 95
    :cond_2
    :goto_0
    const-string p1, "Id3Reader"

    .line 96
    .line 97
    const-string v0, "Discarding invalid ID3 tag"

    .line 98
    .line 99
    invoke-static {p1, v0}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    iput-boolean v3, p0, Lv9/g;->b:Z

    .line 103
    .line 104
    goto :goto_2

    .line 105
    :cond_3
    :goto_1
    iget v0, p0, Lv9/g;->d:I

    .line 106
    .line 107
    iget v2, p0, Lv9/g;->e:I

    .line 108
    .line 109
    sub-int/2addr v0, v2

    .line 110
    invoke-static {v1, v0}, Ljava/lang/Math;->min(II)I

    .line 111
    .line 112
    .line 113
    move-result v0

    .line 114
    iget-object v1, p0, Lv9/g;->g:Ljava/lang/Object;

    .line 115
    .line 116
    check-cast v1, Lo8/i0;

    .line 117
    .line 118
    invoke-interface {v1, p1, v0, v3}, Lo8/i0;->a(Lw7/p;II)V

    .line 119
    .line 120
    .line 121
    iget p1, p0, Lv9/g;->e:I

    .line 122
    .line 123
    add-int/2addr p1, v0

    .line 124
    iput p1, p0, Lv9/g;->e:I

    .line 125
    .line 126
    :goto_2
    return-void

    .line 127
    :pswitch_0
    iget-boolean v0, p0, Lv9/g;->b:Z

    .line 128
    .line 129
    if-eqz v0, :cond_b

    .line 130
    .line 131
    iget v0, p0, Lv9/g;->d:I

    .line 132
    .line 133
    const/4 v1, 0x2

    .line 134
    const/4 v2, 0x1

    .line 135
    const/4 v3, 0x0

    .line 136
    if-ne v0, v1, :cond_6

    .line 137
    .line 138
    invoke-virtual {p1}, Lw7/p;->a()I

    .line 139
    .line 140
    .line 141
    move-result v0

    .line 142
    if-nez v0, :cond_4

    .line 143
    .line 144
    move v0, v3

    .line 145
    goto :goto_3

    .line 146
    :cond_4
    invoke-virtual {p1}, Lw7/p;->w()I

    .line 147
    .line 148
    .line 149
    move-result v0

    .line 150
    const/16 v1, 0x20

    .line 151
    .line 152
    if-eq v0, v1, :cond_5

    .line 153
    .line 154
    iput-boolean v3, p0, Lv9/g;->b:Z

    .line 155
    .line 156
    :cond_5
    iget v0, p0, Lv9/g;->d:I

    .line 157
    .line 158
    sub-int/2addr v0, v2

    .line 159
    iput v0, p0, Lv9/g;->d:I

    .line 160
    .line 161
    iget-boolean v0, p0, Lv9/g;->b:Z

    .line 162
    .line 163
    :goto_3
    if-nez v0, :cond_6

    .line 164
    .line 165
    goto :goto_6

    .line 166
    :cond_6
    iget v0, p0, Lv9/g;->d:I

    .line 167
    .line 168
    if-ne v0, v2, :cond_9

    .line 169
    .line 170
    invoke-virtual {p1}, Lw7/p;->a()I

    .line 171
    .line 172
    .line 173
    move-result v0

    .line 174
    if-nez v0, :cond_7

    .line 175
    .line 176
    move v0, v3

    .line 177
    goto :goto_4

    .line 178
    :cond_7
    invoke-virtual {p1}, Lw7/p;->w()I

    .line 179
    .line 180
    .line 181
    move-result v0

    .line 182
    if-eqz v0, :cond_8

    .line 183
    .line 184
    iput-boolean v3, p0, Lv9/g;->b:Z

    .line 185
    .line 186
    :cond_8
    iget v0, p0, Lv9/g;->d:I

    .line 187
    .line 188
    sub-int/2addr v0, v2

    .line 189
    iput v0, p0, Lv9/g;->d:I

    .line 190
    .line 191
    iget-boolean v0, p0, Lv9/g;->b:Z

    .line 192
    .line 193
    :goto_4
    if-nez v0, :cond_9

    .line 194
    .line 195
    goto :goto_6

    .line 196
    :cond_9
    iget v0, p1, Lw7/p;->b:I

    .line 197
    .line 198
    invoke-virtual {p1}, Lw7/p;->a()I

    .line 199
    .line 200
    .line 201
    move-result v1

    .line 202
    iget-object v2, p0, Lv9/g;->g:Ljava/lang/Object;

    .line 203
    .line 204
    check-cast v2, [Lo8/i0;

    .line 205
    .line 206
    array-length v4, v2

    .line 207
    move v5, v3

    .line 208
    :goto_5
    if-ge v5, v4, :cond_a

    .line 209
    .line 210
    aget-object v6, v2, v5

    .line 211
    .line 212
    invoke-virtual {p1, v0}, Lw7/p;->I(I)V

    .line 213
    .line 214
    .line 215
    invoke-interface {v6, p1, v1, v3}, Lo8/i0;->a(Lw7/p;II)V

    .line 216
    .line 217
    .line 218
    add-int/lit8 v5, v5, 0x1

    .line 219
    .line 220
    goto :goto_5

    .line 221
    :cond_a
    iget p1, p0, Lv9/g;->e:I

    .line 222
    .line 223
    add-int/2addr p1, v1

    .line 224
    iput p1, p0, Lv9/g;->e:I

    .line 225
    .line 226
    :cond_b
    :goto_6
    return-void

    .line 227
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final c()V
    .locals 2

    .line 1
    iget v0, p0, Lv9/g;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    iput-boolean v0, p0, Lv9/g;->b:Z

    .line 8
    .line 9
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 10
    .line 11
    .line 12
    .line 13
    .line 14
    iput-wide v0, p0, Lv9/g;->c:J

    .line 15
    .line 16
    return-void

    .line 17
    :pswitch_0
    const/4 v0, 0x0

    .line 18
    iput-boolean v0, p0, Lv9/g;->b:Z

    .line 19
    .line 20
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 21
    .line 22
    .line 23
    .line 24
    .line 25
    iput-wide v0, p0, Lv9/g;->c:J

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

.method public final d(Lo8/q;Lh11/h;)V
    .locals 6

    .line 1
    iget v0, p0, Lv9/g;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2}, Lh11/h;->d()V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p2}, Lh11/h;->i()V

    .line 10
    .line 11
    .line 12
    iget v0, p2, Lh11/h;->f:I

    .line 13
    .line 14
    const/4 v1, 0x5

    .line 15
    invoke-interface {p1, v0, v1}, Lo8/q;->q(II)Lo8/i0;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    iput-object p1, p0, Lv9/g;->g:Ljava/lang/Object;

    .line 20
    .line 21
    new-instance p0, Lt7/n;

    .line 22
    .line 23
    invoke-direct {p0}, Lt7/n;-><init>()V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p2}, Lh11/h;->i()V

    .line 27
    .line 28
    .line 29
    iget-object p2, p2, Lh11/h;->h:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast p2, Ljava/lang/String;

    .line 32
    .line 33
    iput-object p2, p0, Lt7/n;->a:Ljava/lang/String;

    .line 34
    .line 35
    const-string p2, "video/mp2t"

    .line 36
    .line 37
    invoke-static {p2}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p2

    .line 41
    iput-object p2, p0, Lt7/n;->l:Ljava/lang/String;

    .line 42
    .line 43
    const-string p2, "application/id3"

    .line 44
    .line 45
    invoke-static {p2}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p2

    .line 49
    iput-object p2, p0, Lt7/n;->m:Ljava/lang/String;

    .line 50
    .line 51
    invoke-static {p0, p1}, Lf2/m0;->x(Lt7/n;Lo8/i0;)V

    .line 52
    .line 53
    .line 54
    return-void

    .line 55
    :pswitch_0
    iget-object v0, p0, Lv9/g;->g:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast v0, [Lo8/i0;

    .line 58
    .line 59
    const/4 v1, 0x0

    .line 60
    :goto_0
    array-length v2, v0

    .line 61
    if-ge v1, v2, :cond_0

    .line 62
    .line 63
    iget-object v2, p0, Lv9/g;->f:Ljava/lang/Object;

    .line 64
    .line 65
    check-cast v2, Ljava/util/List;

    .line 66
    .line 67
    invoke-interface {v2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v2

    .line 71
    check-cast v2, Lv9/e0;

    .line 72
    .line 73
    invoke-virtual {p2}, Lh11/h;->d()V

    .line 74
    .line 75
    .line 76
    invoke-virtual {p2}, Lh11/h;->i()V

    .line 77
    .line 78
    .line 79
    iget v3, p2, Lh11/h;->f:I

    .line 80
    .line 81
    const/4 v4, 0x3

    .line 82
    invoke-interface {p1, v3, v4}, Lo8/q;->q(II)Lo8/i0;

    .line 83
    .line 84
    .line 85
    move-result-object v3

    .line 86
    new-instance v4, Lt7/n;

    .line 87
    .line 88
    invoke-direct {v4}, Lt7/n;-><init>()V

    .line 89
    .line 90
    .line 91
    invoke-virtual {p2}, Lh11/h;->i()V

    .line 92
    .line 93
    .line 94
    iget-object v5, p2, Lh11/h;->h:Ljava/lang/Object;

    .line 95
    .line 96
    check-cast v5, Ljava/lang/String;

    .line 97
    .line 98
    iput-object v5, v4, Lt7/n;->a:Ljava/lang/String;

    .line 99
    .line 100
    const-string v5, "video/mp2t"

    .line 101
    .line 102
    invoke-static {v5}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object v5

    .line 106
    iput-object v5, v4, Lt7/n;->l:Ljava/lang/String;

    .line 107
    .line 108
    const-string v5, "application/dvbsubs"

    .line 109
    .line 110
    invoke-static {v5}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object v5

    .line 114
    iput-object v5, v4, Lt7/n;->m:Ljava/lang/String;

    .line 115
    .line 116
    iget-object v5, v2, Lv9/e0;->b:[B

    .line 117
    .line 118
    invoke-static {v5}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 119
    .line 120
    .line 121
    move-result-object v5

    .line 122
    iput-object v5, v4, Lt7/n;->p:Ljava/util/List;

    .line 123
    .line 124
    iget-object v2, v2, Lv9/e0;->a:Ljava/lang/String;

    .line 125
    .line 126
    iput-object v2, v4, Lt7/n;->d:Ljava/lang/String;

    .line 127
    .line 128
    invoke-static {v4, v3}, Lf2/m0;->x(Lt7/n;Lo8/i0;)V

    .line 129
    .line 130
    .line 131
    aput-object v3, v0, v1

    .line 132
    .line 133
    add-int/lit8 v1, v1, 0x1

    .line 134
    .line 135
    goto :goto_0

    .line 136
    :cond_0
    return-void

    .line 137
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final e(Z)V
    .locals 10

    .line 1
    iget p1, p0, Lv9/g;->a:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Lv9/g;->g:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p1, Lo8/i0;

    .line 9
    .line 10
    invoke-static {p1}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    iget-boolean p1, p0, Lv9/g;->b:Z

    .line 14
    .line 15
    if-eqz p1, :cond_2

    .line 16
    .line 17
    iget p1, p0, Lv9/g;->d:I

    .line 18
    .line 19
    if-eqz p1, :cond_2

    .line 20
    .line 21
    iget v0, p0, Lv9/g;->e:I

    .line 22
    .line 23
    if-eq v0, p1, :cond_0

    .line 24
    .line 25
    goto :goto_1

    .line 26
    :cond_0
    iget-wide v0, p0, Lv9/g;->c:J

    .line 27
    .line 28
    const-wide v2, -0x7fffffffffffffffL    # -4.9E-324

    .line 29
    .line 30
    .line 31
    .line 32
    .line 33
    cmp-long p1, v0, v2

    .line 34
    .line 35
    const/4 v0, 0x0

    .line 36
    if-eqz p1, :cond_1

    .line 37
    .line 38
    const/4 p1, 0x1

    .line 39
    goto :goto_0

    .line 40
    :cond_1
    move p1, v0

    .line 41
    :goto_0
    invoke-static {p1}, Lw7/a;->j(Z)V

    .line 42
    .line 43
    .line 44
    iget-object p1, p0, Lv9/g;->g:Ljava/lang/Object;

    .line 45
    .line 46
    move-object v1, p1

    .line 47
    check-cast v1, Lo8/i0;

    .line 48
    .line 49
    iget-wide v2, p0, Lv9/g;->c:J

    .line 50
    .line 51
    iget v5, p0, Lv9/g;->d:I

    .line 52
    .line 53
    const/4 v6, 0x0

    .line 54
    const/4 v7, 0x0

    .line 55
    const/4 v4, 0x1

    .line 56
    invoke-interface/range {v1 .. v7}, Lo8/i0;->b(JIIILo8/h0;)V

    .line 57
    .line 58
    .line 59
    iput-boolean v0, p0, Lv9/g;->b:Z

    .line 60
    .line 61
    :cond_2
    :goto_1
    return-void

    .line 62
    :pswitch_0
    iget-boolean p1, p0, Lv9/g;->b:Z

    .line 63
    .line 64
    if-eqz p1, :cond_5

    .line 65
    .line 66
    iget-wide v0, p0, Lv9/g;->c:J

    .line 67
    .line 68
    const-wide v2, -0x7fffffffffffffffL    # -4.9E-324

    .line 69
    .line 70
    .line 71
    .line 72
    .line 73
    cmp-long p1, v0, v2

    .line 74
    .line 75
    const/4 v0, 0x0

    .line 76
    if-eqz p1, :cond_3

    .line 77
    .line 78
    const/4 p1, 0x1

    .line 79
    goto :goto_2

    .line 80
    :cond_3
    move p1, v0

    .line 81
    :goto_2
    invoke-static {p1}, Lw7/a;->j(Z)V

    .line 82
    .line 83
    .line 84
    iget-object p1, p0, Lv9/g;->g:Ljava/lang/Object;

    .line 85
    .line 86
    check-cast p1, [Lo8/i0;

    .line 87
    .line 88
    array-length v1, p1

    .line 89
    move v2, v0

    .line 90
    :goto_3
    if-ge v2, v1, :cond_4

    .line 91
    .line 92
    aget-object v3, p1, v2

    .line 93
    .line 94
    iget-wide v4, p0, Lv9/g;->c:J

    .line 95
    .line 96
    iget v7, p0, Lv9/g;->e:I

    .line 97
    .line 98
    const/4 v8, 0x0

    .line 99
    const/4 v9, 0x0

    .line 100
    const/4 v6, 0x1

    .line 101
    invoke-interface/range {v3 .. v9}, Lo8/i0;->b(JIIILo8/h0;)V

    .line 102
    .line 103
    .line 104
    add-int/lit8 v2, v2, 0x1

    .line 105
    .line 106
    goto :goto_3

    .line 107
    :cond_4
    iput-boolean v0, p0, Lv9/g;->b:Z

    .line 108
    .line 109
    :cond_5
    return-void

    .line 110
    nop

    .line 111
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final f(IJ)V
    .locals 1

    .line 1
    iget v0, p0, Lv9/g;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    and-int/lit8 p1, p1, 0x4

    .line 7
    .line 8
    if-nez p1, :cond_0

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    const/4 p1, 0x1

    .line 12
    iput-boolean p1, p0, Lv9/g;->b:Z

    .line 13
    .line 14
    iput-wide p2, p0, Lv9/g;->c:J

    .line 15
    .line 16
    const/4 p1, 0x0

    .line 17
    iput p1, p0, Lv9/g;->d:I

    .line 18
    .line 19
    iput p1, p0, Lv9/g;->e:I

    .line 20
    .line 21
    :goto_0
    return-void

    .line 22
    :pswitch_0
    and-int/lit8 p1, p1, 0x4

    .line 23
    .line 24
    if-nez p1, :cond_1

    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_1
    const/4 p1, 0x1

    .line 28
    iput-boolean p1, p0, Lv9/g;->b:Z

    .line 29
    .line 30
    iput-wide p2, p0, Lv9/g;->c:J

    .line 31
    .line 32
    const/4 p1, 0x0

    .line 33
    iput p1, p0, Lv9/g;->e:I

    .line 34
    .line 35
    const/4 p1, 0x2

    .line 36
    iput p1, p0, Lv9/g;->d:I

    .line 37
    .line 38
    :goto_1
    return-void

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
