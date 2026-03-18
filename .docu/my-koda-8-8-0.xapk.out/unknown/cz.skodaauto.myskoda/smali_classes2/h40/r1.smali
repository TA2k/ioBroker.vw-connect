.class public final Lh40/r1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh40/t1;


# direct methods
.method public synthetic constructor <init>(Lh40/t1;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh40/r1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh40/r1;->e:Lh40/t1;

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
    .locals 13

    .line 1
    iget p2, p0, Lh40/r1;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/s;

    .line 7
    .line 8
    instance-of p2, p1, Lne0/d;

    .line 9
    .line 10
    iget-object p0, p0, Lh40/r1;->e:Lh40/t1;

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
    check-cast v0, Lh40/q1;

    .line 20
    .line 21
    const/4 v11, 0x0

    .line 22
    const/16 v12, 0x7fb

    .line 23
    .line 24
    const/4 v1, 0x0

    .line 25
    const/4 v2, 0x0

    .line 26
    const/4 v3, 0x1

    .line 27
    const/4 v4, 0x0

    .line 28
    const/4 v5, 0x0

    .line 29
    const/4 v6, 0x0

    .line 30
    const/4 v7, 0x0

    .line 31
    const/4 v8, 0x0

    .line 32
    const/4 v9, 0x0

    .line 33
    const/4 v10, 0x0

    .line 34
    invoke-static/range {v0 .. v12}, Lh40/q1;->a(Lh40/q1;Lql0/g;ZZLjava/lang/Boolean;Lh40/g0;ZZLjava/lang/String;ZLjava/lang/String;Ljava/lang/String;I)Lh40/q1;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 39
    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    instance-of p2, p1, Lne0/e;

    .line 43
    .line 44
    if-eqz p2, :cond_1

    .line 45
    .line 46
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 47
    .line 48
    .line 49
    move-result-object p2

    .line 50
    move-object v0, p2

    .line 51
    check-cast v0, Lh40/q1;

    .line 52
    .line 53
    check-cast p1, Lne0/e;

    .line 54
    .line 55
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast p1, Lfe0/a;

    .line 58
    .line 59
    const-string p2, "<this>"

    .line 60
    .line 61
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    new-instance v5, Lh40/g0;

    .line 65
    .line 66
    iget-object p2, p1, Lfe0/a;->b:Ljava/lang/String;

    .line 67
    .line 68
    iget-object p1, p1, Lfe0/a;->c:Ljava/lang/String;

    .line 69
    .line 70
    invoke-direct {v5, p2, p1}, Lh40/g0;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    const/4 v11, 0x0

    .line 74
    const/16 v12, 0x7cb

    .line 75
    .line 76
    const/4 v1, 0x0

    .line 77
    const/4 v2, 0x0

    .line 78
    const/4 v3, 0x0

    .line 79
    const/4 v4, 0x0

    .line 80
    const/4 v6, 0x1

    .line 81
    const/4 v7, 0x0

    .line 82
    const/4 v8, 0x0

    .line 83
    const/4 v9, 0x0

    .line 84
    const/4 v10, 0x0

    .line 85
    invoke-static/range {v0 .. v12}, Lh40/q1;->a(Lh40/q1;Lql0/g;ZZLjava/lang/Boolean;Lh40/g0;ZZLjava/lang/String;ZLjava/lang/String;Ljava/lang/String;I)Lh40/q1;

    .line 86
    .line 87
    .line 88
    move-result-object p1

    .line 89
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 90
    .line 91
    .line 92
    goto :goto_0

    .line 93
    :cond_1
    instance-of p2, p1, Lne0/c;

    .line 94
    .line 95
    if-eqz p2, :cond_2

    .line 96
    .line 97
    check-cast p1, Lne0/c;

    .line 98
    .line 99
    invoke-virtual {p0, p1}, Lh40/t1;->h(Lne0/c;)V

    .line 100
    .line 101
    .line 102
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 103
    .line 104
    return-object p0

    .line 105
    :cond_2
    new-instance p0, La8/r0;

    .line 106
    .line 107
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 108
    .line 109
    .line 110
    throw p0

    .line 111
    :pswitch_0
    check-cast p1, Lne0/s;

    .line 112
    .line 113
    instance-of p2, p1, Lne0/d;

    .line 114
    .line 115
    iget-object p0, p0, Lh40/r1;->e:Lh40/t1;

    .line 116
    .line 117
    if-eqz p2, :cond_3

    .line 118
    .line 119
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 120
    .line 121
    .line 122
    move-result-object p1

    .line 123
    move-object v0, p1

    .line 124
    check-cast v0, Lh40/q1;

    .line 125
    .line 126
    const/4 v11, 0x0

    .line 127
    const/16 v12, 0x7fd

    .line 128
    .line 129
    const/4 v1, 0x0

    .line 130
    const/4 v2, 0x1

    .line 131
    const/4 v3, 0x0

    .line 132
    const/4 v4, 0x0

    .line 133
    const/4 v5, 0x0

    .line 134
    const/4 v6, 0x0

    .line 135
    const/4 v7, 0x0

    .line 136
    const/4 v8, 0x0

    .line 137
    const/4 v9, 0x0

    .line 138
    const/4 v10, 0x0

    .line 139
    invoke-static/range {v0 .. v12}, Lh40/q1;->a(Lh40/q1;Lql0/g;ZZLjava/lang/Boolean;Lh40/g0;ZZLjava/lang/String;ZLjava/lang/String;Ljava/lang/String;I)Lh40/q1;

    .line 140
    .line 141
    .line 142
    move-result-object p1

    .line 143
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 144
    .line 145
    .line 146
    goto :goto_1

    .line 147
    :cond_3
    instance-of p2, p1, Lne0/e;

    .line 148
    .line 149
    if-eqz p2, :cond_4

    .line 150
    .line 151
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 152
    .line 153
    .line 154
    move-result-object p1

    .line 155
    move-object v0, p1

    .line 156
    check-cast v0, Lh40/q1;

    .line 157
    .line 158
    const/4 v11, 0x0

    .line 159
    const/16 v12, 0x7fd

    .line 160
    .line 161
    const/4 v1, 0x0

    .line 162
    const/4 v2, 0x0

    .line 163
    const/4 v3, 0x0

    .line 164
    const/4 v4, 0x0

    .line 165
    const/4 v5, 0x0

    .line 166
    const/4 v6, 0x0

    .line 167
    const/4 v7, 0x0

    .line 168
    const/4 v8, 0x0

    .line 169
    const/4 v9, 0x0

    .line 170
    const/4 v10, 0x0

    .line 171
    invoke-static/range {v0 .. v12}, Lh40/q1;->a(Lh40/q1;Lql0/g;ZZLjava/lang/Boolean;Lh40/g0;ZZLjava/lang/String;ZLjava/lang/String;Ljava/lang/String;I)Lh40/q1;

    .line 172
    .line 173
    .line 174
    move-result-object p1

    .line 175
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 176
    .line 177
    .line 178
    iget-object p1, p0, Lh40/t1;->q:Lf40/p0;

    .line 179
    .line 180
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    iget-object p0, p0, Lh40/t1;->p:Lf40/o2;

    .line 184
    .line 185
    iget-object p0, p0, Lf40/o2;->a:Lf40/f1;

    .line 186
    .line 187
    check-cast p0, Liy/b;

    .line 188
    .line 189
    new-instance v0, Lul0/c;

    .line 190
    .line 191
    sget-object v1, Lly/b;->Y3:Lly/b;

    .line 192
    .line 193
    sget-object v3, Lly/b;->i:Lly/b;

    .line 194
    .line 195
    const/16 v5, 0x38

    .line 196
    .line 197
    const/4 v2, 0x1

    .line 198
    invoke-direct/range {v0 .. v5}, Lul0/c;-><init>(Lul0/f;ZLul0/f;Ljava/util/List;I)V

    .line 199
    .line 200
    .line 201
    invoke-virtual {p0, v0}, Liy/b;->b(Lul0/e;)V

    .line 202
    .line 203
    .line 204
    goto :goto_1

    .line 205
    :cond_4
    instance-of p2, p1, Lne0/c;

    .line 206
    .line 207
    if-eqz p2, :cond_5

    .line 208
    .line 209
    check-cast p1, Lne0/c;

    .line 210
    .line 211
    invoke-virtual {p0, p1}, Lh40/t1;->h(Lne0/c;)V

    .line 212
    .line 213
    .line 214
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 215
    .line 216
    return-object p0

    .line 217
    :cond_5
    new-instance p0, La8/r0;

    .line 218
    .line 219
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 220
    .line 221
    .line 222
    throw p0

    .line 223
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
