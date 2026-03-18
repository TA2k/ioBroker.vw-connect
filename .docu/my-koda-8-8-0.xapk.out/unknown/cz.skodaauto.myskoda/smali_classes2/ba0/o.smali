.class public final Lba0/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lba0/q;


# direct methods
.method public synthetic constructor <init>(Lba0/q;I)V
    .locals 0

    .line 1
    iput p2, p0, Lba0/o;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lba0/o;->e:Lba0/q;

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
    .locals 9

    .line 1
    instance-of v0, p2, Lba0/n;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lba0/n;

    .line 7
    .line 8
    iget v1, v0, Lba0/n;->g:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lba0/n;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lba0/n;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lba0/n;-><init>(Lba0/o;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lba0/n;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lba0/n;->g:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    iget-object p0, p0, Lba0/o;->e:Lba0/q;

    .line 33
    .line 34
    if-eqz v2, :cond_2

    .line 35
    .line 36
    if-ne v2, v3, :cond_1

    .line 37
    .line 38
    iget-object p1, v0, Lba0/n;->d:Lba0/q;

    .line 39
    .line 40
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    instance-of p2, p1, Lne0/e;

    .line 56
    .line 57
    if-eqz p2, :cond_3

    .line 58
    .line 59
    iget-object p0, p0, Lba0/q;->l:Ltr0/b;

    .line 60
    .line 61
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    goto :goto_3

    .line 65
    :cond_3
    instance-of p2, p1, Lne0/d;

    .line 66
    .line 67
    if-eqz p2, :cond_4

    .line 68
    .line 69
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    move-object v0, p1

    .line 74
    check-cast v0, Lba0/l;

    .line 75
    .line 76
    const/4 v6, 0x0

    .line 77
    const/16 v7, 0x2f

    .line 78
    .line 79
    const/4 v1, 0x0

    .line 80
    const/4 v2, 0x0

    .line 81
    const/4 v3, 0x0

    .line 82
    const/4 v4, 0x0

    .line 83
    const/4 v5, 0x1

    .line 84
    invoke-static/range {v0 .. v7}, Lba0/l;->a(Lba0/l;Lba0/k;Lql0/g;ZZZZI)Lba0/l;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 89
    .line 90
    .line 91
    goto :goto_3

    .line 92
    :cond_4
    instance-of p2, p1, Lne0/c;

    .line 93
    .line 94
    if-eqz p2, :cond_7

    .line 95
    .line 96
    check-cast p1, Lne0/c;

    .line 97
    .line 98
    invoke-static {p1}, Llp/ae;->b(Lne0/c;)Z

    .line 99
    .line 100
    .line 101
    move-result p2

    .line 102
    if-eqz p2, :cond_6

    .line 103
    .line 104
    iget-object p2, p0, Lba0/q;->h:Lko0/f;

    .line 105
    .line 106
    iput-object p0, v0, Lba0/n;->d:Lba0/q;

    .line 107
    .line 108
    iput v3, v0, Lba0/n;->g:I

    .line 109
    .line 110
    invoke-virtual {p2, p1, v0}, Lko0/f;->b(Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object p1

    .line 114
    if-ne p1, v1, :cond_5

    .line 115
    .line 116
    return-object v1

    .line 117
    :cond_5
    move-object p1, p0

    .line 118
    :goto_1
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    move-object v0, p0

    .line 123
    check-cast v0, Lba0/l;

    .line 124
    .line 125
    const/4 v6, 0x0

    .line 126
    const/16 v7, 0x2b

    .line 127
    .line 128
    const/4 v1, 0x0

    .line 129
    const/4 v2, 0x0

    .line 130
    const/4 v3, 0x0

    .line 131
    const/4 v4, 0x0

    .line 132
    const/4 v5, 0x0

    .line 133
    invoke-static/range {v0 .. v7}, Lba0/l;->a(Lba0/l;Lba0/k;Lql0/g;ZZZZI)Lba0/l;

    .line 134
    .line 135
    .line 136
    move-result-object p0

    .line 137
    move-object v8, p1

    .line 138
    move-object p1, p0

    .line 139
    move-object p0, v8

    .line 140
    goto :goto_2

    .line 141
    :cond_6
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 142
    .line 143
    .line 144
    move-result-object p2

    .line 145
    move-object v0, p2

    .line 146
    check-cast v0, Lba0/l;

    .line 147
    .line 148
    iget-object p2, p0, Lba0/q;->m:Lij0/a;

    .line 149
    .line 150
    invoke-static {p1, p2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 151
    .line 152
    .line 153
    move-result-object v2

    .line 154
    const/4 v6, 0x0

    .line 155
    const/16 v7, 0x29

    .line 156
    .line 157
    const/4 v1, 0x0

    .line 158
    const/4 v3, 0x0

    .line 159
    const/4 v4, 0x0

    .line 160
    const/4 v5, 0x0

    .line 161
    invoke-static/range {v0 .. v7}, Lba0/l;->a(Lba0/l;Lba0/k;Lql0/g;ZZZZI)Lba0/l;

    .line 162
    .line 163
    .line 164
    move-result-object p1

    .line 165
    :goto_2
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 166
    .line 167
    .line 168
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 169
    .line 170
    return-object p0

    .line 171
    :cond_7
    new-instance p0, La8/r0;

    .line 172
    .line 173
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 174
    .line 175
    .line 176
    throw p0
.end method

.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Lba0/o;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/s;

    .line 7
    .line 8
    instance-of p2, p1, Lne0/d;

    .line 9
    .line 10
    iget-object p0, p0, Lba0/o;->e:Lba0/q;

    .line 11
    .line 12
    if-eqz p2, :cond_0

    .line 13
    .line 14
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    move-object v0, p1

    .line 19
    check-cast v0, Lba0/l;

    .line 20
    .line 21
    const/4 v6, 0x1

    .line 22
    const/16 v7, 0x17

    .line 23
    .line 24
    const/4 v1, 0x0

    .line 25
    const/4 v2, 0x0

    .line 26
    const/4 v3, 0x0

    .line 27
    const/4 v4, 0x0

    .line 28
    const/4 v5, 0x0

    .line 29
    invoke-static/range {v0 .. v7}, Lba0/l;->a(Lba0/l;Lba0/k;Lql0/g;ZZZZI)Lba0/l;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 34
    .line 35
    .line 36
    goto/16 :goto_2

    .line 37
    .line 38
    :cond_0
    instance-of p2, p1, Lne0/e;

    .line 39
    .line 40
    if-eqz p2, :cond_1

    .line 41
    .line 42
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    move-object v0, p1

    .line 47
    check-cast v0, Lba0/l;

    .line 48
    .line 49
    const/4 v6, 0x0

    .line 50
    const/16 v7, 0x1f

    .line 51
    .line 52
    const/4 v1, 0x0

    .line 53
    const/4 v2, 0x0

    .line 54
    const/4 v3, 0x0

    .line 55
    const/4 v4, 0x0

    .line 56
    const/4 v5, 0x0

    .line 57
    invoke-static/range {v0 .. v7}, Lba0/l;->a(Lba0/l;Lba0/k;Lql0/g;ZZZZI)Lba0/l;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 62
    .line 63
    .line 64
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    new-instance p2, La50/a;

    .line 69
    .line 70
    const/16 v0, 0x8

    .line 71
    .line 72
    invoke-direct {p2, p0, v1, v0}, La50/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 73
    .line 74
    .line 75
    const/4 v0, 0x3

    .line 76
    invoke-static {p1, v1, v1, p2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 77
    .line 78
    .line 79
    iget-object p1, p0, Lba0/q;->o:Lz90/l;

    .line 80
    .line 81
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    iget-object p0, p0, Lba0/q;->l:Ltr0/b;

    .line 85
    .line 86
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    goto :goto_2

    .line 90
    :cond_1
    instance-of p2, p1, Lne0/c;

    .line 91
    .line 92
    if-eqz p2, :cond_3

    .line 93
    .line 94
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 95
    .line 96
    .line 97
    move-result-object p2

    .line 98
    move-object v0, p2

    .line 99
    check-cast v0, Lba0/l;

    .line 100
    .line 101
    move-object v1, p1

    .line 102
    check-cast v1, Lne0/c;

    .line 103
    .line 104
    iget-object p1, p0, Lba0/q;->m:Lij0/a;

    .line 105
    .line 106
    iget-object p2, v1, Lne0/c;->e:Lne0/b;

    .line 107
    .line 108
    sget-object v2, Lba0/m;->a:[I

    .line 109
    .line 110
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 111
    .line 112
    .line 113
    move-result p2

    .line 114
    aget p2, v2, p2

    .line 115
    .line 116
    const/4 v2, 0x1

    .line 117
    if-ne p2, v2, :cond_2

    .line 118
    .line 119
    invoke-static {v1, p1}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 120
    .line 121
    .line 122
    move-result-object p1

    .line 123
    :goto_0
    move-object v2, p1

    .line 124
    goto :goto_1

    .line 125
    :cond_2
    iget-object v2, p0, Lba0/q;->m:Lij0/a;

    .line 126
    .line 127
    const/4 p2, 0x0

    .line 128
    new-array v3, p2, [Ljava/lang/Object;

    .line 129
    .line 130
    move-object v4, v2

    .line 131
    check-cast v4, Ljj0/f;

    .line 132
    .line 133
    const v5, 0x7f12151d

    .line 134
    .line 135
    .line 136
    invoke-virtual {v4, v5, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 137
    .line 138
    .line 139
    move-result-object v3

    .line 140
    new-array v4, p2, [Ljava/lang/Object;

    .line 141
    .line 142
    check-cast p1, Ljj0/f;

    .line 143
    .line 144
    const v5, 0x7f12151c

    .line 145
    .line 146
    .line 147
    invoke-virtual {p1, v5, v4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 148
    .line 149
    .line 150
    move-result-object v4

    .line 151
    const v5, 0x7f12038c

    .line 152
    .line 153
    .line 154
    new-array p2, p2, [Ljava/lang/Object;

    .line 155
    .line 156
    invoke-virtual {p1, v5, p2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 157
    .line 158
    .line 159
    move-result-object v5

    .line 160
    const/4 v8, 0x0

    .line 161
    const/16 v9, 0x70

    .line 162
    .line 163
    const/4 v6, 0x0

    .line 164
    const/4 v7, 0x0

    .line 165
    invoke-static/range {v1 .. v9}, Ljp/rf;->d(Lne0/c;Lij0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLql0/f;I)Lql0/g;

    .line 166
    .line 167
    .line 168
    move-result-object p1

    .line 169
    goto :goto_0

    .line 170
    :goto_1
    const/4 v6, 0x0

    .line 171
    const/16 v7, 0x15

    .line 172
    .line 173
    const/4 v1, 0x0

    .line 174
    const/4 v3, 0x0

    .line 175
    const/4 v4, 0x0

    .line 176
    const/4 v5, 0x0

    .line 177
    invoke-static/range {v0 .. v7}, Lba0/l;->a(Lba0/l;Lba0/k;Lql0/g;ZZZZI)Lba0/l;

    .line 178
    .line 179
    .line 180
    move-result-object p1

    .line 181
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 182
    .line 183
    .line 184
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 185
    .line 186
    return-object p0

    .line 187
    :cond_3
    new-instance p0, La8/r0;

    .line 188
    .line 189
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 190
    .line 191
    .line 192
    throw p0

    .line 193
    :pswitch_0
    check-cast p1, Lne0/s;

    .line 194
    .line 195
    invoke-virtual {p0, p1, p2}, Lba0/o;->b(Lne0/s;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    move-result-object p0

    .line 199
    return-object p0

    .line 200
    nop

    .line 201
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
