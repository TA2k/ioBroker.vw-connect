.class public final Lr60/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lr60/l;


# direct methods
.method public synthetic constructor <init>(Lr60/l;I)V
    .locals 0

    .line 1
    iput p2, p0, Lr60/h;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lr60/h;->e:Lr60/l;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lr60/h;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Lne0/t;

    .line 11
    .line 12
    instance-of v2, v1, Lne0/c;

    .line 13
    .line 14
    iget-object v0, v0, Lr60/h;->e:Lr60/l;

    .line 15
    .line 16
    if-eqz v2, :cond_0

    .line 17
    .line 18
    check-cast v1, Lne0/c;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Lr60/l;->j(Lne0/c;)V

    .line 21
    .line 22
    .line 23
    goto :goto_1

    .line 24
    :cond_0
    instance-of v1, v1, Lne0/e;

    .line 25
    .line 26
    if-eqz v1, :cond_2

    .line 27
    .line 28
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    check-cast v1, Lr60/i;

    .line 33
    .line 34
    iget-boolean v1, v1, Lr60/i;->o:Z

    .line 35
    .line 36
    if-eqz v1, :cond_1

    .line 37
    .line 38
    iget-object v0, v0, Lr60/l;->k:Ltr0/b;

    .line 39
    .line 40
    :goto_0
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_1
    iget-object v0, v0, Lr60/l;->m:Lp60/u;

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 48
    .line 49
    return-object v0

    .line 50
    :cond_2
    new-instance v0, La8/r0;

    .line 51
    .line 52
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 53
    .line 54
    .line 55
    throw v0

    .line 56
    :pswitch_0
    move-object/from16 v1, p1

    .line 57
    .line 58
    check-cast v1, Lne0/s;

    .line 59
    .line 60
    instance-of v2, v1, Lne0/c;

    .line 61
    .line 62
    iget-object v0, v0, Lr60/h;->e:Lr60/l;

    .line 63
    .line 64
    if-eqz v2, :cond_4

    .line 65
    .line 66
    check-cast v1, Lne0/c;

    .line 67
    .line 68
    iget-object v2, v1, Lne0/c;->a:Ljava/lang/Throwable;

    .line 69
    .line 70
    invoke-static {v2}, Ljp/wa;->h(Ljava/lang/Throwable;)Z

    .line 71
    .line 72
    .line 73
    move-result v2

    .line 74
    if-eqz v2, :cond_3

    .line 75
    .line 76
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 77
    .line 78
    .line 79
    move-result-object v1

    .line 80
    new-instance v2, Lr60/k;

    .line 81
    .line 82
    const/4 v3, 0x0

    .line 83
    const/4 v4, 0x0

    .line 84
    invoke-direct {v2, v0, v4, v3}, Lr60/k;-><init>(Lr60/l;Lkotlin/coroutines/Continuation;I)V

    .line 85
    .line 86
    .line 87
    const/4 v0, 0x3

    .line 88
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 89
    .line 90
    .line 91
    goto/16 :goto_3

    .line 92
    .line 93
    :cond_3
    invoke-virtual {v0, v1}, Lr60/l;->j(Lne0/c;)V

    .line 94
    .line 95
    .line 96
    goto/16 :goto_3

    .line 97
    .line 98
    :cond_4
    instance-of v2, v1, Lne0/e;

    .line 99
    .line 100
    if-eqz v2, :cond_b

    .line 101
    .line 102
    check-cast v1, Lne0/e;

    .line 103
    .line 104
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 105
    .line 106
    move-object v13, v1

    .line 107
    check-cast v13, Lon0/q;

    .line 108
    .line 109
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 110
    .line 111
    .line 112
    move-result-object v1

    .line 113
    check-cast v1, Lr60/i;

    .line 114
    .line 115
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 116
    .line 117
    .line 118
    move-result-object v2

    .line 119
    check-cast v2, Lr60/i;

    .line 120
    .line 121
    iget-object v3, v13, Lon0/q;->e:Lon0/n;

    .line 122
    .line 123
    iget-object v4, v3, Lon0/n;->e:Ljava/lang/String;

    .line 124
    .line 125
    if-nez v4, :cond_5

    .line 126
    .line 127
    iget-object v4, v1, Lr60/i;->c:Ljava/lang/String;

    .line 128
    .line 129
    :cond_5
    move-object v5, v4

    .line 130
    iget-object v4, v3, Lon0/n;->c:Ljava/lang/String;

    .line 131
    .line 132
    if-nez v4, :cond_6

    .line 133
    .line 134
    iget-object v4, v1, Lr60/i;->d:Ljava/lang/String;

    .line 135
    .line 136
    :cond_6
    move-object v6, v4

    .line 137
    iget-object v4, v3, Lon0/n;->d:Ljava/lang/String;

    .line 138
    .line 139
    if-nez v4, :cond_7

    .line 140
    .line 141
    iget-object v4, v1, Lr60/i;->e:Ljava/lang/String;

    .line 142
    .line 143
    :cond_7
    move-object v7, v4

    .line 144
    iget-object v4, v3, Lon0/n;->a:Ljava/lang/String;

    .line 145
    .line 146
    if-nez v4, :cond_8

    .line 147
    .line 148
    iget-object v4, v1, Lr60/i;->f:Ljava/lang/String;

    .line 149
    .line 150
    :cond_8
    move-object v8, v4

    .line 151
    iget-object v3, v3, Lon0/n;->b:Ljava/lang/String;

    .line 152
    .line 153
    if-nez v3, :cond_9

    .line 154
    .line 155
    iget-object v4, v1, Lr60/i;->g:Ljava/lang/String;

    .line 156
    .line 157
    move-object v9, v4

    .line 158
    goto :goto_2

    .line 159
    :cond_9
    move-object v9, v3

    .line 160
    :goto_2
    if-nez v3, :cond_a

    .line 161
    .line 162
    iget-object v3, v1, Lr60/i;->g:Ljava/lang/String;

    .line 163
    .line 164
    :cond_a
    invoke-virtual {v0, v3}, Lr60/l;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 165
    .line 166
    .line 167
    move-result-object v10

    .line 168
    const/16 v17, 0x0

    .line 169
    .line 170
    const/16 v18, 0x7903

    .line 171
    .line 172
    const/4 v3, 0x0

    .line 173
    const/4 v4, 0x0

    .line 174
    const/4 v11, 0x0

    .line 175
    const/4 v12, 0x0

    .line 176
    const/4 v14, 0x0

    .line 177
    const/4 v15, 0x0

    .line 178
    const/16 v16, 0x0

    .line 179
    .line 180
    invoke-static/range {v2 .. v18}, Lr60/i;->a(Lr60/i;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZLon0/q;Ljava/util/ArrayList;Lql0/g;ZZI)Lr60/i;

    .line 181
    .line 182
    .line 183
    move-result-object v1

    .line 184
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 185
    .line 186
    .line 187
    invoke-virtual {v0}, Lr60/l;->k()V

    .line 188
    .line 189
    .line 190
    goto :goto_3

    .line 191
    :cond_b
    instance-of v1, v1, Lne0/d;

    .line 192
    .line 193
    if-eqz v1, :cond_c

    .line 194
    .line 195
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 196
    .line 197
    .line 198
    move-result-object v1

    .line 199
    move-object v2, v1

    .line 200
    check-cast v2, Lr60/i;

    .line 201
    .line 202
    const/16 v17, 0x0

    .line 203
    .line 204
    const/16 v18, 0x7dff

    .line 205
    .line 206
    const/4 v3, 0x0

    .line 207
    const/4 v4, 0x0

    .line 208
    const/4 v5, 0x0

    .line 209
    const/4 v6, 0x0

    .line 210
    const/4 v7, 0x0

    .line 211
    const/4 v8, 0x0

    .line 212
    const/4 v9, 0x0

    .line 213
    const/4 v10, 0x0

    .line 214
    const/4 v11, 0x0

    .line 215
    const/4 v12, 0x1

    .line 216
    const/4 v13, 0x0

    .line 217
    const/4 v14, 0x0

    .line 218
    const/4 v15, 0x0

    .line 219
    const/16 v16, 0x0

    .line 220
    .line 221
    invoke-static/range {v2 .. v18}, Lr60/i;->a(Lr60/i;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZLon0/q;Ljava/util/ArrayList;Lql0/g;ZZI)Lr60/i;

    .line 222
    .line 223
    .line 224
    move-result-object v1

    .line 225
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 226
    .line 227
    .line 228
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 229
    .line 230
    return-object v0

    .line 231
    :cond_c
    new-instance v0, La8/r0;

    .line 232
    .line 233
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 234
    .line 235
    .line 236
    throw v0

    .line 237
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
