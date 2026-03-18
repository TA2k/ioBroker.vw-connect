.class public final Lhk0/a;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public synthetic e:Ljava/lang/Object;

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lhk0/a;->d:I

    iput-object p1, p0, Lhk0/a;->g:Ljava/lang/Object;

    const/4 p1, 0x3

    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public synthetic constructor <init>(Ll2/b1;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 2
    iput p4, p0, Lhk0/a;->d:I

    iput-object p1, p0, Lhk0/a;->e:Ljava/lang/Object;

    iput-object p2, p0, Lhk0/a;->g:Ljava/lang/Object;

    const/4 p1, 0x3

    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lhk0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lvy0/b0;

    .line 7
    .line 8
    check-cast p2, Lqp/g;

    .line 9
    .line 10
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    new-instance p1, Lhk0/a;

    .line 13
    .line 14
    iget-object v0, p0, Lhk0/a;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v0, Ll2/b1;

    .line 17
    .line 18
    iget-object p0, p0, Lhk0/a;->g:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Lt4/m;

    .line 21
    .line 22
    const/4 v1, 0x7

    .line 23
    invoke-direct {p1, v0, p0, p3, v1}, Lhk0/a;-><init>(Ll2/b1;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 24
    .line 25
    .line 26
    iput-object p2, p1, Lhk0/a;->f:Ljava/lang/Object;

    .line 27
    .line 28
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    invoke-virtual {p1, p0}, Lhk0/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    return-object p0

    .line 34
    :pswitch_0
    check-cast p1, Lvy0/b0;

    .line 35
    .line 36
    check-cast p2, Lqp/g;

    .line 37
    .line 38
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 39
    .line 40
    new-instance p1, Lhk0/a;

    .line 41
    .line 42
    iget-object v0, p0, Lhk0/a;->e:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v0, Ll2/b1;

    .line 45
    .line 46
    iget-object p0, p0, Lhk0/a;->g:Ljava/lang/Object;

    .line 47
    .line 48
    check-cast p0, Landroid/content/Context;

    .line 49
    .line 50
    const/4 v1, 0x6

    .line 51
    invoke-direct {p1, v0, p0, p3, v1}, Lhk0/a;-><init>(Ll2/b1;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 52
    .line 53
    .line 54
    iput-object p2, p1, Lhk0/a;->f:Ljava/lang/Object;

    .line 55
    .line 56
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 57
    .line 58
    invoke-virtual {p1, p0}, Lhk0/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    return-object p0

    .line 62
    :pswitch_1
    check-cast p1, Lne0/t;

    .line 63
    .line 64
    check-cast p2, Lne0/s;

    .line 65
    .line 66
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 67
    .line 68
    new-instance v0, Lhk0/a;

    .line 69
    .line 70
    iget-object p0, p0, Lhk0/a;->g:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast p0, Lr60/p;

    .line 73
    .line 74
    const/4 v1, 0x5

    .line 75
    invoke-direct {v0, p0, p3, v1}, Lhk0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 76
    .line 77
    .line 78
    iput-object p1, v0, Lhk0/a;->f:Ljava/lang/Object;

    .line 79
    .line 80
    iput-object p2, v0, Lhk0/a;->e:Ljava/lang/Object;

    .line 81
    .line 82
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 83
    .line 84
    invoke-virtual {v0, p0}, Lhk0/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    return-object p0

    .line 89
    :pswitch_2
    check-cast p1, Lne0/t;

    .line 90
    .line 91
    check-cast p2, Lne0/s;

    .line 92
    .line 93
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 94
    .line 95
    new-instance v0, Lhk0/a;

    .line 96
    .line 97
    iget-object p0, p0, Lhk0/a;->g:Ljava/lang/Object;

    .line 98
    .line 99
    check-cast p0, Lr60/g;

    .line 100
    .line 101
    const/4 v1, 0x4

    .line 102
    invoke-direct {v0, p0, p3, v1}, Lhk0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 103
    .line 104
    .line 105
    iput-object p1, v0, Lhk0/a;->f:Ljava/lang/Object;

    .line 106
    .line 107
    iput-object p2, v0, Lhk0/a;->e:Ljava/lang/Object;

    .line 108
    .line 109
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 110
    .line 111
    invoke-virtual {v0, p0}, Lhk0/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    return-object p0

    .line 116
    :pswitch_3
    check-cast p1, Lne0/s;

    .line 117
    .line 118
    check-cast p2, Lun0/b;

    .line 119
    .line 120
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 121
    .line 122
    new-instance v0, Lhk0/a;

    .line 123
    .line 124
    iget-object p0, p0, Lhk0/a;->g:Ljava/lang/Object;

    .line 125
    .line 126
    check-cast p0, Ll60/e;

    .line 127
    .line 128
    const/4 v1, 0x3

    .line 129
    invoke-direct {v0, p0, p3, v1}, Lhk0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 130
    .line 131
    .line 132
    iput-object p1, v0, Lhk0/a;->f:Ljava/lang/Object;

    .line 133
    .line 134
    iput-object p2, v0, Lhk0/a;->e:Ljava/lang/Object;

    .line 135
    .line 136
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 137
    .line 138
    invoke-virtual {v0, p0}, Lhk0/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    return-object p0

    .line 142
    :pswitch_4
    check-cast p1, Liv0/f;

    .line 143
    .line 144
    check-cast p2, Lbl0/h0;

    .line 145
    .line 146
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 147
    .line 148
    new-instance v0, Lhk0/a;

    .line 149
    .line 150
    iget-object p0, p0, Lhk0/a;->g:Ljava/lang/Object;

    .line 151
    .line 152
    check-cast p0, Lhv0/t;

    .line 153
    .line 154
    const/4 v1, 0x2

    .line 155
    invoke-direct {v0, p0, p3, v1}, Lhk0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 156
    .line 157
    .line 158
    iput-object p1, v0, Lhk0/a;->f:Ljava/lang/Object;

    .line 159
    .line 160
    iput-object p2, v0, Lhk0/a;->e:Ljava/lang/Object;

    .line 161
    .line 162
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 163
    .line 164
    invoke-virtual {v0, p0}, Lhk0/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object p0

    .line 168
    return-object p0

    .line 169
    :pswitch_5
    check-cast p1, Lxj0/b;

    .line 170
    .line 171
    check-cast p2, Ljava/util/List;

    .line 172
    .line 173
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 174
    .line 175
    new-instance v0, Lhk0/a;

    .line 176
    .line 177
    iget-object p0, p0, Lhk0/a;->g:Ljava/lang/Object;

    .line 178
    .line 179
    check-cast p0, Lhv0/d;

    .line 180
    .line 181
    const/4 v1, 0x1

    .line 182
    invoke-direct {v0, p0, p3, v1}, Lhk0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 183
    .line 184
    .line 185
    iput-object p1, v0, Lhk0/a;->e:Ljava/lang/Object;

    .line 186
    .line 187
    check-cast p2, Ljava/util/List;

    .line 188
    .line 189
    iput-object p2, v0, Lhk0/a;->f:Ljava/lang/Object;

    .line 190
    .line 191
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 192
    .line 193
    invoke-virtual {v0, p0}, Lhk0/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 194
    .line 195
    .line 196
    return-object p0

    .line 197
    :pswitch_6
    check-cast p1, Ljava/util/List;

    .line 198
    .line 199
    check-cast p2, Lxj0/b;

    .line 200
    .line 201
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 202
    .line 203
    new-instance v0, Lhk0/a;

    .line 204
    .line 205
    iget-object p0, p0, Lhk0/a;->g:Ljava/lang/Object;

    .line 206
    .line 207
    check-cast p0, Lhk0/c;

    .line 208
    .line 209
    const/4 v1, 0x0

    .line 210
    invoke-direct {v0, p0, p3, v1}, Lhk0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 211
    .line 212
    .line 213
    check-cast p1, Ljava/util/List;

    .line 214
    .line 215
    iput-object p1, v0, Lhk0/a;->f:Ljava/lang/Object;

    .line 216
    .line 217
    iput-object p2, v0, Lhk0/a;->e:Ljava/lang/Object;

    .line 218
    .line 219
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 220
    .line 221
    invoke-virtual {v0, p0}, Lhk0/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    return-object p0

    .line 225
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lhk0/a;->d:I

    .line 4
    .line 5
    const-string v2, "url"

    .line 6
    .line 7
    const/16 v3, 0x1e

    .line 8
    .line 9
    const-string v4, "&redirect=myskoda://redirect/parkfuel/registration-success&cancel=myskoda://redirect/parkfuel/registration-cancel"

    .line 10
    .line 11
    const-string v5, "input"

    .line 12
    .line 13
    const/4 v6, 0x1

    .line 14
    const/4 v7, 0x0

    .line 15
    sget-object v8, Llx0/b0;->a:Llx0/b0;

    .line 16
    .line 17
    iget-object v9, v0, Lhk0/a;->g:Ljava/lang/Object;

    .line 18
    .line 19
    packed-switch v1, :pswitch_data_0

    .line 20
    .line 21
    .line 22
    iget-object v1, v0, Lhk0/a;->f:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v1, Lqp/g;

    .line 25
    .line 26
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 27
    .line 28
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    iget-object v0, v0, Lhk0/a;->e:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast v0, Ll2/b1;

    .line 34
    .line 35
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    check-cast v0, Lk1/z0;

    .line 40
    .line 41
    check-cast v9, Lt4/m;

    .line 42
    .line 43
    invoke-interface {v0, v9}, Lk1/z0;->b(Lt4/m;)F

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    invoke-static {v2}, Lxf0/i0;->O(F)I

    .line 48
    .line 49
    .line 50
    move-result v2

    .line 51
    invoke-interface {v0}, Lk1/z0;->d()F

    .line 52
    .line 53
    .line 54
    move-result v3

    .line 55
    invoke-static {v3}, Lxf0/i0;->O(F)I

    .line 56
    .line 57
    .line 58
    move-result v3

    .line 59
    invoke-interface {v0, v9}, Lk1/z0;->a(Lt4/m;)F

    .line 60
    .line 61
    .line 62
    move-result v4

    .line 63
    invoke-static {v4}, Lxf0/i0;->O(F)I

    .line 64
    .line 65
    .line 66
    move-result v4

    .line 67
    invoke-interface {v0}, Lk1/z0;->c()F

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    invoke-static {v0}, Lxf0/i0;->O(F)I

    .line 72
    .line 73
    .line 74
    move-result v0

    .line 75
    invoke-virtual {v1, v2, v3, v4, v0}, Lqp/g;->l(IIII)V

    .line 76
    .line 77
    .line 78
    return-object v8

    .line 79
    :pswitch_0
    iget-object v1, v0, Lhk0/a;->f:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast v1, Lqp/g;

    .line 82
    .line 83
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 84
    .line 85
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    iget-object v0, v0, Lhk0/a;->e:Ljava/lang/Object;

    .line 89
    .line 90
    check-cast v0, Ll2/b1;

    .line 91
    .line 92
    new-instance v2, Lqu/c;

    .line 93
    .line 94
    check-cast v9, Landroid/content/Context;

    .line 95
    .line 96
    invoke-direct {v2, v9, v1}, Lqu/c;-><init>(Landroid/content/Context;Lqp/g;)V

    .line 97
    .line 98
    .line 99
    invoke-interface {v0, v2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    return-object v8

    .line 103
    :pswitch_1
    check-cast v9, Lr60/p;

    .line 104
    .line 105
    iget-object v1, v0, Lhk0/a;->f:Ljava/lang/Object;

    .line 106
    .line 107
    check-cast v1, Lne0/t;

    .line 108
    .line 109
    iget-object v0, v0, Lhk0/a;->e:Ljava/lang/Object;

    .line 110
    .line 111
    check-cast v0, Lne0/s;

    .line 112
    .line 113
    sget-object v10, Lqx0/a;->d:Lqx0/a;

    .line 114
    .line 115
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    instance-of v10, v0, Lne0/e;

    .line 119
    .line 120
    if-eqz v10, :cond_0

    .line 121
    .line 122
    invoke-virtual {v9}, Lql0/j;->a()Lql0/h;

    .line 123
    .line 124
    .line 125
    move-result-object v10

    .line 126
    move-object v11, v10

    .line 127
    check-cast v11, Lr60/m;

    .line 128
    .line 129
    check-cast v0, Lne0/e;

    .line 130
    .line 131
    iget-object v0, v0, Lne0/e;->a:Ljava/lang/Object;

    .line 132
    .line 133
    check-cast v0, Lon0/q;

    .line 134
    .line 135
    iget-object v15, v0, Lon0/q;->g:Ljava/util/List;

    .line 136
    .line 137
    const/16 v17, 0x0

    .line 138
    .line 139
    const/16 v18, 0x37

    .line 140
    .line 141
    const/4 v12, 0x0

    .line 142
    const/4 v13, 0x0

    .line 143
    const/4 v14, 0x0

    .line 144
    const/16 v16, 0x0

    .line 145
    .line 146
    invoke-static/range {v11 .. v18}, Lr60/m;->a(Lr60/m;Ljava/lang/String;Ljava/lang/String;ZLjava/util/List;Lql0/g;Ljava/lang/String;I)Lr60/m;

    .line 147
    .line 148
    .line 149
    move-result-object v0

    .line 150
    invoke-virtual {v9, v0}, Lql0/j;->g(Lql0/h;)V

    .line 151
    .line 152
    .line 153
    goto :goto_0

    .line 154
    :cond_0
    instance-of v10, v0, Lne0/c;

    .line 155
    .line 156
    if-eqz v10, :cond_1

    .line 157
    .line 158
    check-cast v0, Lne0/c;

    .line 159
    .line 160
    invoke-virtual {v9}, Lql0/j;->a()Lql0/h;

    .line 161
    .line 162
    .line 163
    move-result-object v10

    .line 164
    move-object v11, v10

    .line 165
    check-cast v11, Lr60/m;

    .line 166
    .line 167
    iget-object v10, v9, Lr60/p;->p:Lij0/a;

    .line 168
    .line 169
    invoke-static {v0, v10}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 170
    .line 171
    .line 172
    move-result-object v16

    .line 173
    const/16 v17, 0x0

    .line 174
    .line 175
    const/16 v18, 0x2f

    .line 176
    .line 177
    const/4 v12, 0x0

    .line 178
    const/4 v13, 0x0

    .line 179
    const/4 v14, 0x0

    .line 180
    const/4 v15, 0x0

    .line 181
    invoke-static/range {v11 .. v18}, Lr60/m;->a(Lr60/m;Ljava/lang/String;Ljava/lang/String;ZLjava/util/List;Lql0/g;Ljava/lang/String;I)Lr60/m;

    .line 182
    .line 183
    .line 184
    move-result-object v0

    .line 185
    invoke-virtual {v9, v0}, Lql0/j;->g(Lql0/h;)V

    .line 186
    .line 187
    .line 188
    goto :goto_0

    .line 189
    :cond_1
    sget-object v10, Lne0/d;->a:Lne0/d;

    .line 190
    .line 191
    invoke-static {v0, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 192
    .line 193
    .line 194
    move-result v0

    .line 195
    if-eqz v0, :cond_8

    .line 196
    .line 197
    :goto_0
    instance-of v0, v1, Lne0/e;

    .line 198
    .line 199
    if-eqz v0, :cond_6

    .line 200
    .line 201
    iget-object v0, v9, Lr60/p;->o:Lbd0/c;

    .line 202
    .line 203
    iget-object v8, v9, Lr60/p;->m:Lp60/a;

    .line 204
    .line 205
    check-cast v1, Lne0/e;

    .line 206
    .line 207
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 208
    .line 209
    check-cast v1, Ljava/lang/String;

    .line 210
    .line 211
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 212
    .line 213
    .line 214
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 215
    .line 216
    .line 217
    sget-object v5, Lq60/c;->e:[Lq60/c;

    .line 218
    .line 219
    invoke-virtual {v1, v4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 220
    .line 221
    .line 222
    move-result-object v1

    .line 223
    and-int/lit8 v4, v3, 0x2

    .line 224
    .line 225
    if-eqz v4, :cond_2

    .line 226
    .line 227
    move v10, v6

    .line 228
    goto :goto_1

    .line 229
    :cond_2
    move v10, v7

    .line 230
    :goto_1
    and-int/lit8 v4, v3, 0x4

    .line 231
    .line 232
    if-eqz v4, :cond_3

    .line 233
    .line 234
    move v11, v6

    .line 235
    goto :goto_2

    .line 236
    :cond_3
    move v11, v7

    .line 237
    :goto_2
    and-int/lit8 v4, v3, 0x8

    .line 238
    .line 239
    if-eqz v4, :cond_4

    .line 240
    .line 241
    move v12, v7

    .line 242
    goto :goto_3

    .line 243
    :cond_4
    move v12, v6

    .line 244
    :goto_3
    and-int/lit8 v3, v3, 0x10

    .line 245
    .line 246
    if-eqz v3, :cond_5

    .line 247
    .line 248
    move v13, v7

    .line 249
    goto :goto_4

    .line 250
    :cond_5
    move v13, v6

    .line 251
    :goto_4
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 252
    .line 253
    .line 254
    iget-object v0, v0, Lbd0/c;->a:Lbd0/a;

    .line 255
    .line 256
    new-instance v9, Ljava/net/URL;

    .line 257
    .line 258
    invoke-direct {v9, v1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 259
    .line 260
    .line 261
    move-object v8, v0

    .line 262
    check-cast v8, Lzc0/b;

    .line 263
    .line 264
    invoke-virtual/range {v8 .. v13}, Lzc0/b;->b(Ljava/net/URL;ZZZZ)Lyy0/m1;

    .line 265
    .line 266
    .line 267
    move-result-object v8

    .line 268
    goto :goto_5

    .line 269
    :cond_6
    instance-of v0, v1, Lne0/c;

    .line 270
    .line 271
    if-eqz v0, :cond_7

    .line 272
    .line 273
    check-cast v1, Lne0/c;

    .line 274
    .line 275
    invoke-virtual {v9}, Lql0/j;->a()Lql0/h;

    .line 276
    .line 277
    .line 278
    move-result-object v0

    .line 279
    move-object v10, v0

    .line 280
    check-cast v10, Lr60/m;

    .line 281
    .line 282
    iget-object v0, v9, Lr60/p;->p:Lij0/a;

    .line 283
    .line 284
    invoke-static {v1, v0}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 285
    .line 286
    .line 287
    move-result-object v15

    .line 288
    const/16 v16, 0x0

    .line 289
    .line 290
    const/16 v17, 0x2f

    .line 291
    .line 292
    const/4 v11, 0x0

    .line 293
    const/4 v12, 0x0

    .line 294
    const/4 v13, 0x0

    .line 295
    const/4 v14, 0x0

    .line 296
    invoke-static/range {v10 .. v17}, Lr60/m;->a(Lr60/m;Ljava/lang/String;Ljava/lang/String;ZLjava/util/List;Lql0/g;Ljava/lang/String;I)Lr60/m;

    .line 297
    .line 298
    .line 299
    move-result-object v0

    .line 300
    invoke-virtual {v9, v0}, Lql0/j;->g(Lql0/h;)V

    .line 301
    .line 302
    .line 303
    :goto_5
    return-object v8

    .line 304
    :cond_7
    new-instance v0, La8/r0;

    .line 305
    .line 306
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 307
    .line 308
    .line 309
    throw v0

    .line 310
    :cond_8
    new-instance v0, La8/r0;

    .line 311
    .line 312
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 313
    .line 314
    .line 315
    throw v0

    .line 316
    :pswitch_2
    check-cast v9, Lr60/g;

    .line 317
    .line 318
    iget-object v1, v0, Lhk0/a;->f:Ljava/lang/Object;

    .line 319
    .line 320
    check-cast v1, Lne0/t;

    .line 321
    .line 322
    iget-object v0, v0, Lhk0/a;->e:Ljava/lang/Object;

    .line 323
    .line 324
    check-cast v0, Lne0/s;

    .line 325
    .line 326
    sget-object v10, Lqx0/a;->d:Lqx0/a;

    .line 327
    .line 328
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 329
    .line 330
    .line 331
    instance-of v10, v0, Lne0/e;

    .line 332
    .line 333
    if-eqz v10, :cond_9

    .line 334
    .line 335
    invoke-virtual {v9}, Lql0/j;->a()Lql0/h;

    .line 336
    .line 337
    .line 338
    move-result-object v10

    .line 339
    move-object v11, v10

    .line 340
    check-cast v11, Lr60/b;

    .line 341
    .line 342
    check-cast v0, Lne0/e;

    .line 343
    .line 344
    iget-object v0, v0, Lne0/e;->a:Ljava/lang/Object;

    .line 345
    .line 346
    check-cast v0, Lon0/q;

    .line 347
    .line 348
    iget-object v0, v0, Lon0/q;->g:Ljava/util/List;

    .line 349
    .line 350
    invoke-static {v0}, Lr60/g;->k(Ljava/util/List;)Lon0/a0;

    .line 351
    .line 352
    .line 353
    move-result-object v20

    .line 354
    const/16 v21, 0x0

    .line 355
    .line 356
    const/16 v22, 0x2d7

    .line 357
    .line 358
    const/4 v12, 0x0

    .line 359
    const/4 v13, 0x0

    .line 360
    const/4 v14, 0x0

    .line 361
    const/4 v15, 0x0

    .line 362
    const/16 v16, 0x0

    .line 363
    .line 364
    const/16 v18, 0x0

    .line 365
    .line 366
    const/16 v19, 0x0

    .line 367
    .line 368
    move-object/from16 v17, v0

    .line 369
    .line 370
    invoke-static/range {v11 .. v22}, Lr60/b;->a(Lr60/b;Ljava/lang/String;ZLql0/g;ZLjava/lang/String;Ljava/util/List;Ljava/lang/String;ZLon0/a0;Ljava/lang/String;I)Lr60/b;

    .line 371
    .line 372
    .line 373
    move-result-object v0

    .line 374
    invoke-virtual {v9, v0}, Lql0/j;->g(Lql0/h;)V

    .line 375
    .line 376
    .line 377
    goto :goto_6

    .line 378
    :cond_9
    instance-of v10, v0, Lne0/c;

    .line 379
    .line 380
    if-eqz v10, :cond_a

    .line 381
    .line 382
    check-cast v0, Lne0/c;

    .line 383
    .line 384
    invoke-static {v9, v0}, Lr60/g;->j(Lr60/g;Lne0/c;)V

    .line 385
    .line 386
    .line 387
    goto :goto_6

    .line 388
    :cond_a
    instance-of v0, v0, Lne0/d;

    .line 389
    .line 390
    if-eqz v0, :cond_11

    .line 391
    .line 392
    invoke-virtual {v9}, Lql0/j;->a()Lql0/h;

    .line 393
    .line 394
    .line 395
    move-result-object v0

    .line 396
    move-object v10, v0

    .line 397
    check-cast v10, Lr60/b;

    .line 398
    .line 399
    const/16 v20, 0x0

    .line 400
    .line 401
    const/16 v21, 0x3f7

    .line 402
    .line 403
    const/4 v11, 0x0

    .line 404
    const/4 v12, 0x0

    .line 405
    const/4 v13, 0x0

    .line 406
    const/4 v14, 0x1

    .line 407
    const/4 v15, 0x0

    .line 408
    const/16 v16, 0x0

    .line 409
    .line 410
    const/16 v17, 0x0

    .line 411
    .line 412
    const/16 v18, 0x0

    .line 413
    .line 414
    const/16 v19, 0x0

    .line 415
    .line 416
    invoke-static/range {v10 .. v21}, Lr60/b;->a(Lr60/b;Ljava/lang/String;ZLql0/g;ZLjava/lang/String;Ljava/util/List;Ljava/lang/String;ZLon0/a0;Ljava/lang/String;I)Lr60/b;

    .line 417
    .line 418
    .line 419
    move-result-object v0

    .line 420
    invoke-virtual {v9, v0}, Lql0/j;->g(Lql0/h;)V

    .line 421
    .line 422
    .line 423
    :goto_6
    instance-of v0, v1, Lne0/e;

    .line 424
    .line 425
    if-eqz v0, :cond_f

    .line 426
    .line 427
    iget-object v0, v9, Lr60/g;->v:Lbd0/c;

    .line 428
    .line 429
    iget-object v8, v9, Lr60/g;->h:Lp60/a;

    .line 430
    .line 431
    check-cast v1, Lne0/e;

    .line 432
    .line 433
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 434
    .line 435
    check-cast v1, Ljava/lang/String;

    .line 436
    .line 437
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 438
    .line 439
    .line 440
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 441
    .line 442
    .line 443
    sget-object v5, Lq60/c;->e:[Lq60/c;

    .line 444
    .line 445
    invoke-virtual {v1, v4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 446
    .line 447
    .line 448
    move-result-object v1

    .line 449
    and-int/lit8 v4, v3, 0x2

    .line 450
    .line 451
    if-eqz v4, :cond_b

    .line 452
    .line 453
    move v10, v6

    .line 454
    goto :goto_7

    .line 455
    :cond_b
    move v10, v7

    .line 456
    :goto_7
    and-int/lit8 v4, v3, 0x4

    .line 457
    .line 458
    if-eqz v4, :cond_c

    .line 459
    .line 460
    move v11, v6

    .line 461
    goto :goto_8

    .line 462
    :cond_c
    move v11, v7

    .line 463
    :goto_8
    and-int/lit8 v4, v3, 0x8

    .line 464
    .line 465
    if-eqz v4, :cond_d

    .line 466
    .line 467
    move v12, v7

    .line 468
    goto :goto_9

    .line 469
    :cond_d
    move v12, v6

    .line 470
    :goto_9
    and-int/lit8 v3, v3, 0x10

    .line 471
    .line 472
    if-eqz v3, :cond_e

    .line 473
    .line 474
    move v13, v7

    .line 475
    goto :goto_a

    .line 476
    :cond_e
    move v13, v6

    .line 477
    :goto_a
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 478
    .line 479
    .line 480
    iget-object v0, v0, Lbd0/c;->a:Lbd0/a;

    .line 481
    .line 482
    new-instance v9, Ljava/net/URL;

    .line 483
    .line 484
    invoke-direct {v9, v1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 485
    .line 486
    .line 487
    move-object v8, v0

    .line 488
    check-cast v8, Lzc0/b;

    .line 489
    .line 490
    invoke-virtual/range {v8 .. v13}, Lzc0/b;->b(Ljava/net/URL;ZZZZ)Lyy0/m1;

    .line 491
    .line 492
    .line 493
    move-result-object v8

    .line 494
    goto :goto_b

    .line 495
    :cond_f
    instance-of v0, v1, Lne0/c;

    .line 496
    .line 497
    if-eqz v0, :cond_10

    .line 498
    .line 499
    check-cast v1, Lne0/c;

    .line 500
    .line 501
    invoke-static {v9, v1}, Lr60/g;->j(Lr60/g;Lne0/c;)V

    .line 502
    .line 503
    .line 504
    :goto_b
    return-object v8

    .line 505
    :cond_10
    new-instance v0, La8/r0;

    .line 506
    .line 507
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 508
    .line 509
    .line 510
    throw v0

    .line 511
    :cond_11
    new-instance v0, La8/r0;

    .line 512
    .line 513
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 514
    .line 515
    .line 516
    throw v0

    .line 517
    :pswitch_3
    iget-object v1, v0, Lhk0/a;->f:Ljava/lang/Object;

    .line 518
    .line 519
    check-cast v1, Lne0/s;

    .line 520
    .line 521
    iget-object v0, v0, Lhk0/a;->e:Ljava/lang/Object;

    .line 522
    .line 523
    check-cast v0, Lun0/b;

    .line 524
    .line 525
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 526
    .line 527
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 528
    .line 529
    .line 530
    check-cast v9, Ll60/e;

    .line 531
    .line 532
    iget-boolean v0, v0, Lun0/b;->b:Z

    .line 533
    .line 534
    iget-object v2, v9, Ll60/e;->q:Lij0/a;

    .line 535
    .line 536
    instance-of v3, v1, Lne0/d;

    .line 537
    .line 538
    if-eqz v3, :cond_12

    .line 539
    .line 540
    invoke-virtual {v9}, Lql0/j;->a()Lql0/h;

    .line 541
    .line 542
    .line 543
    move-result-object v0

    .line 544
    move-object v10, v0

    .line 545
    check-cast v10, Ll60/c;

    .line 546
    .line 547
    const/16 v17, 0x0

    .line 548
    .line 549
    const/16 v18, 0x76

    .line 550
    .line 551
    const/4 v11, 0x1

    .line 552
    const/4 v12, 0x0

    .line 553
    const/4 v13, 0x0

    .line 554
    const/4 v14, 0x0

    .line 555
    const/4 v15, 0x0

    .line 556
    const/16 v16, 0x0

    .line 557
    .line 558
    invoke-static/range {v10 .. v18}, Ll60/c;->a(Ll60/c;ZLql0/g;Lql0/g;ZLjava/util/ArrayList;ZZI)Ll60/c;

    .line 559
    .line 560
    .line 561
    move-result-object v0

    .line 562
    goto/16 :goto_11

    .line 563
    .line 564
    :cond_12
    instance-of v3, v1, Lne0/e;

    .line 565
    .line 566
    if-eqz v3, :cond_15

    .line 567
    .line 568
    invoke-virtual {v9}, Lql0/j;->a()Lql0/h;

    .line 569
    .line 570
    .line 571
    move-result-object v3

    .line 572
    move-object v10, v3

    .line 573
    check-cast v10, Ll60/c;

    .line 574
    .line 575
    check-cast v1, Lne0/e;

    .line 576
    .line 577
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 578
    .line 579
    check-cast v1, Ljava/lang/Iterable;

    .line 580
    .line 581
    new-instance v15, Ljava/util/ArrayList;

    .line 582
    .line 583
    const/16 v3, 0xa

    .line 584
    .line 585
    invoke-static {v1, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 586
    .line 587
    .line 588
    move-result v3

    .line 589
    invoke-direct {v15, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 590
    .line 591
    .line 592
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 593
    .line 594
    .line 595
    move-result-object v1

    .line 596
    :goto_c
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 597
    .line 598
    .line 599
    move-result v3

    .line 600
    if-eqz v3, :cond_14

    .line 601
    .line 602
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 603
    .line 604
    .line 605
    move-result-object v3

    .line 606
    check-cast v3, Lap0/j;

    .line 607
    .line 608
    const-string v4, "<this>"

    .line 609
    .line 610
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 611
    .line 612
    .line 613
    iget-object v4, v3, Lap0/j;->a:Lap0/p;

    .line 614
    .line 615
    const-string v5, "stringResource"

    .line 616
    .line 617
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 618
    .line 619
    .line 620
    new-instance v16, Ll60/b;

    .line 621
    .line 622
    invoke-static {v3}, Llp/ze;->a(Lap0/j;)I

    .line 623
    .line 624
    .line 625
    move-result v5

    .line 626
    new-array v11, v7, [Ljava/lang/Object;

    .line 627
    .line 628
    move-object v12, v2

    .line 629
    check-cast v12, Ljj0/f;

    .line 630
    .line 631
    invoke-virtual {v12, v5, v11}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 632
    .line 633
    .line 634
    move-result-object v18

    .line 635
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 636
    .line 637
    .line 638
    move-result v5

    .line 639
    packed-switch v5, :pswitch_data_1

    .line 640
    .line 641
    .line 642
    new-instance v0, La8/r0;

    .line 643
    .line 644
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 645
    .line 646
    .line 647
    throw v0

    .line 648
    :pswitch_4
    const v5, 0x7f120d1a

    .line 649
    .line 650
    .line 651
    goto :goto_d

    .line 652
    :pswitch_5
    const v5, 0x7f120d34

    .line 653
    .line 654
    .line 655
    goto :goto_d

    .line 656
    :pswitch_6
    const v5, 0x7f120d36

    .line 657
    .line 658
    .line 659
    goto :goto_d

    .line 660
    :pswitch_7
    const v5, 0x7f120d38

    .line 661
    .line 662
    .line 663
    goto :goto_d

    .line 664
    :pswitch_8
    const v5, 0x7f120d28

    .line 665
    .line 666
    .line 667
    goto :goto_d

    .line 668
    :pswitch_9
    const v5, 0x7f120d1e

    .line 669
    .line 670
    .line 671
    goto :goto_d

    .line 672
    :pswitch_a
    const v5, 0x7f120d20

    .line 673
    .line 674
    .line 675
    goto :goto_d

    .line 676
    :pswitch_b
    const v5, 0x7f120d22

    .line 677
    .line 678
    .line 679
    goto :goto_d

    .line 680
    :pswitch_c
    const v5, 0x7f120d1c

    .line 681
    .line 682
    .line 683
    goto :goto_d

    .line 684
    :pswitch_d
    const v5, 0x7f120d2c

    .line 685
    .line 686
    .line 687
    goto :goto_d

    .line 688
    :pswitch_e
    const v5, 0x7f120d2a

    .line 689
    .line 690
    .line 691
    goto :goto_d

    .line 692
    :pswitch_f
    const v5, 0x7f120d24

    .line 693
    .line 694
    .line 695
    goto :goto_d

    .line 696
    :pswitch_10
    const v5, 0x7f120d26

    .line 697
    .line 698
    .line 699
    :goto_d
    new-array v11, v7, [Ljava/lang/Object;

    .line 700
    .line 701
    invoke-virtual {v12, v5, v11}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 702
    .line 703
    .line 704
    move-result-object v19

    .line 705
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 706
    .line 707
    .line 708
    move-result v5

    .line 709
    const v11, 0x7f0803ad

    .line 710
    .line 711
    .line 712
    packed-switch v5, :pswitch_data_2

    .line 713
    .line 714
    .line 715
    new-instance v0, La8/r0;

    .line 716
    .line 717
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 718
    .line 719
    .line 720
    throw v0

    .line 721
    :pswitch_11
    const v11, 0x7f080415

    .line 722
    .line 723
    .line 724
    :goto_e
    :pswitch_12
    move/from16 v20, v11

    .line 725
    .line 726
    goto :goto_f

    .line 727
    :pswitch_13
    const v11, 0x7f08046d

    .line 728
    .line 729
    .line 730
    goto :goto_e

    .line 731
    :pswitch_14
    const v11, 0x7f080476

    .line 732
    .line 733
    .line 734
    goto :goto_e

    .line 735
    :pswitch_15
    const v11, 0x7f08044b

    .line 736
    .line 737
    .line 738
    goto :goto_e

    .line 739
    :pswitch_16
    const v11, 0x7f0802b3

    .line 740
    .line 741
    .line 742
    goto :goto_e

    .line 743
    :pswitch_17
    const v11, 0x7f0803fb

    .line 744
    .line 745
    .line 746
    goto :goto_e

    .line 747
    :pswitch_18
    const v11, 0x7f080317

    .line 748
    .line 749
    .line 750
    goto :goto_e

    .line 751
    :pswitch_19
    const v11, 0x7f0802d5

    .line 752
    .line 753
    .line 754
    goto :goto_e

    .line 755
    :pswitch_1a
    const v11, 0x7f08051c

    .line 756
    .line 757
    .line 758
    goto :goto_e

    .line 759
    :goto_f
    iget-boolean v5, v3, Lap0/j;->c:Z

    .line 760
    .line 761
    if-eqz v5, :cond_13

    .line 762
    .line 763
    if-eqz v0, :cond_13

    .line 764
    .line 765
    move/from16 v21, v6

    .line 766
    .line 767
    goto :goto_10

    .line 768
    :cond_13
    move/from16 v21, v7

    .line 769
    .line 770
    :goto_10
    invoke-static {v3}, Llp/ze;->a(Lap0/j;)I

    .line 771
    .line 772
    .line 773
    move-result v3

    .line 774
    invoke-virtual {v12, v3}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 775
    .line 776
    .line 777
    move-result-object v22

    .line 778
    move-object/from16 v17, v4

    .line 779
    .line 780
    invoke-direct/range {v16 .. v22}, Ll60/b;-><init>(Lap0/p;Ljava/lang/String;Ljava/lang/String;IZLjava/lang/String;)V

    .line 781
    .line 782
    .line 783
    move-object/from16 v3, v16

    .line 784
    .line 785
    invoke-virtual {v15, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 786
    .line 787
    .line 788
    goto/16 :goto_c

    .line 789
    .line 790
    :cond_14
    const/16 v17, 0x0

    .line 791
    .line 792
    const/16 v18, 0x64

    .line 793
    .line 794
    const/4 v11, 0x0

    .line 795
    const/4 v12, 0x0

    .line 796
    const/4 v13, 0x0

    .line 797
    const/4 v14, 0x0

    .line 798
    const/16 v16, 0x0

    .line 799
    .line 800
    invoke-static/range {v10 .. v18}, Ll60/c;->a(Ll60/c;ZLql0/g;Lql0/g;ZLjava/util/ArrayList;ZZI)Ll60/c;

    .line 801
    .line 802
    .line 803
    move-result-object v0

    .line 804
    goto :goto_11

    .line 805
    :cond_15
    instance-of v0, v1, Lne0/c;

    .line 806
    .line 807
    if-eqz v0, :cond_16

    .line 808
    .line 809
    invoke-virtual {v9}, Lql0/j;->a()Lql0/h;

    .line 810
    .line 811
    .line 812
    move-result-object v0

    .line 813
    move-object v10, v0

    .line 814
    check-cast v10, Ll60/c;

    .line 815
    .line 816
    check-cast v1, Lne0/c;

    .line 817
    .line 818
    invoke-static {v1, v2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 819
    .line 820
    .line 821
    move-result-object v12

    .line 822
    const/16 v17, 0x0

    .line 823
    .line 824
    const/16 v18, 0x7c

    .line 825
    .line 826
    const/4 v11, 0x0

    .line 827
    const/4 v13, 0x0

    .line 828
    const/4 v14, 0x0

    .line 829
    const/4 v15, 0x0

    .line 830
    const/16 v16, 0x0

    .line 831
    .line 832
    invoke-static/range {v10 .. v18}, Ll60/c;->a(Ll60/c;ZLql0/g;Lql0/g;ZLjava/util/ArrayList;ZZI)Ll60/c;

    .line 833
    .line 834
    .line 835
    move-result-object v0

    .line 836
    :goto_11
    invoke-virtual {v9, v0}, Lql0/j;->g(Lql0/h;)V

    .line 837
    .line 838
    .line 839
    return-object v8

    .line 840
    :cond_16
    new-instance v0, La8/r0;

    .line 841
    .line 842
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 843
    .line 844
    .line 845
    throw v0

    .line 846
    :pswitch_1b
    check-cast v9, Lhv0/t;

    .line 847
    .line 848
    iget-object v1, v0, Lhk0/a;->f:Ljava/lang/Object;

    .line 849
    .line 850
    check-cast v1, Liv0/f;

    .line 851
    .line 852
    iget-object v0, v0, Lhk0/a;->e:Ljava/lang/Object;

    .line 853
    .line 854
    check-cast v0, Lbl0/h0;

    .line 855
    .line 856
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 857
    .line 858
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 859
    .line 860
    .line 861
    sget-object v2, Liv0/i;->a:Liv0/i;

    .line 862
    .line 863
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 864
    .line 865
    .line 866
    move-result v3

    .line 867
    if-eqz v3, :cond_18

    .line 868
    .line 869
    if-eqz v0, :cond_17

    .line 870
    .line 871
    invoke-static {v9, v0}, Lhv0/t;->a(Lhv0/t;Lbl0/h0;)Liv0/f;

    .line 872
    .line 873
    .line 874
    move-result-object v1

    .line 875
    if-eqz v1, :cond_17

    .line 876
    .line 877
    goto :goto_12

    .line 878
    :cond_17
    move-object v1, v2

    .line 879
    goto :goto_12

    .line 880
    :cond_18
    sget-object v2, Liv0/c;->a:Liv0/c;

    .line 881
    .line 882
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 883
    .line 884
    .line 885
    move-result v3

    .line 886
    if-eqz v3, :cond_19

    .line 887
    .line 888
    if-eqz v0, :cond_17

    .line 889
    .line 890
    invoke-static {v9, v0}, Lhv0/t;->a(Lhv0/t;Lbl0/h0;)Liv0/f;

    .line 891
    .line 892
    .line 893
    move-result-object v1

    .line 894
    if-eqz v1, :cond_17

    .line 895
    .line 896
    :cond_19
    :goto_12
    return-object v1

    .line 897
    :pswitch_1c
    iget-object v1, v0, Lhk0/a;->e:Ljava/lang/Object;

    .line 898
    .line 899
    check-cast v1, Lxj0/b;

    .line 900
    .line 901
    iget-object v0, v0, Lhk0/a;->f:Ljava/lang/Object;

    .line 902
    .line 903
    check-cast v0, Ljava/util/List;

    .line 904
    .line 905
    check-cast v0, Ljava/util/List;

    .line 906
    .line 907
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 908
    .line 909
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 910
    .line 911
    .line 912
    check-cast v0, Ljava/lang/Iterable;

    .line 913
    .line 914
    new-instance v2, Ljava/util/ArrayList;

    .line 915
    .line 916
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 917
    .line 918
    .line 919
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 920
    .line 921
    .line 922
    move-result-object v0

    .line 923
    :cond_1a
    :goto_13
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 924
    .line 925
    .line 926
    move-result v3

    .line 927
    if-eqz v3, :cond_1c

    .line 928
    .line 929
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 930
    .line 931
    .line 932
    move-result-object v3

    .line 933
    move-object v4, v3

    .line 934
    check-cast v4, Lxj0/s;

    .line 935
    .line 936
    iget-boolean v4, v4, Lxj0/s;->d:Z

    .line 937
    .line 938
    if-eqz v4, :cond_1b

    .line 939
    .line 940
    iget v4, v1, Lxj0/b;->b:F

    .line 941
    .line 942
    const/high16 v5, 0x41900000    # 18.0f

    .line 943
    .line 944
    cmpl-float v4, v4, v5

    .line 945
    .line 946
    if-ltz v4, :cond_1a

    .line 947
    .line 948
    goto :goto_14

    .line 949
    :cond_1b
    iget v4, v1, Lxj0/b;->b:F

    .line 950
    .line 951
    const/high16 v5, 0x41100000    # 9.0f

    .line 952
    .line 953
    cmpl-float v4, v4, v5

    .line 954
    .line 955
    if-ltz v4, :cond_1a

    .line 956
    .line 957
    :goto_14
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 958
    .line 959
    .line 960
    goto :goto_13

    .line 961
    :cond_1c
    check-cast v9, Lhv0/d;

    .line 962
    .line 963
    iget-object v0, v9, Lhv0/d;->c:Lwj0/b0;

    .line 964
    .line 965
    iget-object v0, v0, Lwj0/b0;->a:Luj0/h;

    .line 966
    .line 967
    iget-object v0, v0, Luj0/h;->a:Lyy0/c2;

    .line 968
    .line 969
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 970
    .line 971
    .line 972
    const/4 v1, 0x0

    .line 973
    invoke-virtual {v0, v1, v2}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 974
    .line 975
    .line 976
    return-object v8

    .line 977
    :pswitch_1d
    iget-object v1, v0, Lhk0/a;->f:Ljava/lang/Object;

    .line 978
    .line 979
    check-cast v1, Ljava/util/List;

    .line 980
    .line 981
    check-cast v1, Ljava/util/List;

    .line 982
    .line 983
    iget-object v0, v0, Lhk0/a;->e:Ljava/lang/Object;

    .line 984
    .line 985
    check-cast v0, Lxj0/b;

    .line 986
    .line 987
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 988
    .line 989
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 990
    .line 991
    .line 992
    check-cast v9, Lhk0/c;

    .line 993
    .line 994
    invoke-virtual {v9}, Lql0/j;->a()Lql0/h;

    .line 995
    .line 996
    .line 997
    move-result-object v2

    .line 998
    move-object v10, v2

    .line 999
    check-cast v10, Lhk0/b;

    .line 1000
    .line 1001
    if-eqz v1, :cond_1d

    .line 1002
    .line 1003
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 1004
    .line 1005
    .line 1006
    move-result v7

    .line 1007
    :cond_1d
    move v14, v7

    .line 1008
    iget v12, v0, Lxj0/b;->b:F

    .line 1009
    .line 1010
    iget v13, v0, Lxj0/b;->d:I

    .line 1011
    .line 1012
    const/4 v11, 0x0

    .line 1013
    const/4 v15, 0x1

    .line 1014
    invoke-static/range {v10 .. v15}, Lhk0/b;->a(Lhk0/b;ZFIII)Lhk0/b;

    .line 1015
    .line 1016
    .line 1017
    move-result-object v0

    .line 1018
    invoke-virtual {v9, v0}, Lql0/j;->g(Lql0/h;)V

    .line 1019
    .line 1020
    .line 1021
    return-object v8

    .line 1022
    nop

    .line 1023
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch

    .line 1024
    .line 1025
    .line 1026
    .line 1027
    .line 1028
    .line 1029
    .line 1030
    .line 1031
    .line 1032
    .line 1033
    .line 1034
    .line 1035
    .line 1036
    .line 1037
    .line 1038
    .line 1039
    .line 1040
    .line 1041
    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
    .end packed-switch

    .line 1042
    .line 1043
    .line 1044
    .line 1045
    .line 1046
    .line 1047
    .line 1048
    .line 1049
    .line 1050
    .line 1051
    .line 1052
    .line 1053
    .line 1054
    .line 1055
    .line 1056
    .line 1057
    .line 1058
    .line 1059
    .line 1060
    .line 1061
    .line 1062
    .line 1063
    .line 1064
    .line 1065
    .line 1066
    .line 1067
    .line 1068
    .line 1069
    .line 1070
    .line 1071
    :pswitch_data_2
    .packed-switch 0x0
        :pswitch_1a
        :pswitch_19
        :pswitch_12
        :pswitch_18
        :pswitch_17
        :pswitch_12
        :pswitch_12
        :pswitch_19
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_11
    .end packed-switch
.end method
