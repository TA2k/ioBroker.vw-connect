.class public final Lv00/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lv00/i;


# direct methods
.method public synthetic constructor <init>(Lv00/i;I)V
    .locals 0

    .line 1
    iput p2, p0, Lv00/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lv00/a;->e:Lv00/i;

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
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lv00/a;->d:I

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
    instance-of v2, v1, Lne0/e;

    .line 13
    .line 14
    iget-object v0, v0, Lv00/a;->e:Lv00/i;

    .line 15
    .line 16
    if-eqz v2, :cond_0

    .line 17
    .line 18
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    move-object v2, v1

    .line 23
    check-cast v2, Lv00/h;

    .line 24
    .line 25
    sget-object v13, Lv00/f;->a:Lv00/f;

    .line 26
    .line 27
    const/16 v14, 0x7ff

    .line 28
    .line 29
    const/4 v3, 0x0

    .line 30
    const/4 v4, 0x0

    .line 31
    const/4 v5, 0x0

    .line 32
    const/4 v6, 0x0

    .line 33
    const/4 v7, 0x0

    .line 34
    const/4 v8, 0x0

    .line 35
    const/4 v9, 0x0

    .line 36
    const/4 v10, 0x0

    .line 37
    const/4 v11, 0x0

    .line 38
    const/4 v12, 0x0

    .line 39
    invoke-static/range {v2 .. v14}, Lv00/h;->a(Lv00/h;Ljava/lang/String;ZZLjava/lang/String;ZLmh0/b;ILjava/util/List;ZZLv00/g;I)Lv00/h;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    goto :goto_1

    .line 44
    :cond_0
    instance-of v2, v1, Lne0/c;

    .line 45
    .line 46
    if-eqz v2, :cond_2

    .line 47
    .line 48
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    iget-object v3, v0, Lv00/i;->h:Lij0/a;

    .line 53
    .line 54
    move-object v4, v2

    .line 55
    check-cast v4, Lv00/h;

    .line 56
    .line 57
    new-instance v15, Lv00/c;

    .line 58
    .line 59
    sget-object v2, Lne0/b;->g:Lne0/b;

    .line 60
    .line 61
    sget-object v5, Lne0/b;->f:Lne0/b;

    .line 62
    .line 63
    filled-new-array {v2, v5}, [Lne0/b;

    .line 64
    .line 65
    .line 66
    move-result-object v2

    .line 67
    invoke-static {v2}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 68
    .line 69
    .line 70
    move-result-object v2

    .line 71
    move-object v5, v1

    .line 72
    check-cast v5, Lne0/c;

    .line 73
    .line 74
    iget-object v1, v5, Lne0/c;->e:Lne0/b;

    .line 75
    .line 76
    invoke-interface {v2, v1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result v1

    .line 80
    if-eqz v1, :cond_1

    .line 81
    .line 82
    invoke-static {v5, v3}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 83
    .line 84
    .line 85
    move-result-object v1

    .line 86
    goto :goto_0

    .line 87
    :cond_1
    iget-object v6, v0, Lv00/i;->h:Lij0/a;

    .line 88
    .line 89
    const/4 v1, 0x0

    .line 90
    new-array v2, v1, [Ljava/lang/Object;

    .line 91
    .line 92
    move-object v7, v6

    .line 93
    check-cast v7, Ljj0/f;

    .line 94
    .line 95
    const v8, 0x7f1202be

    .line 96
    .line 97
    .line 98
    invoke-virtual {v7, v8, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object v7

    .line 102
    new-array v2, v1, [Ljava/lang/Object;

    .line 103
    .line 104
    check-cast v3, Ljj0/f;

    .line 105
    .line 106
    const v8, 0x7f1202bc

    .line 107
    .line 108
    .line 109
    invoke-virtual {v3, v8, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 110
    .line 111
    .line 112
    move-result-object v8

    .line 113
    const v2, 0x7f12038b

    .line 114
    .line 115
    .line 116
    new-array v9, v1, [Ljava/lang/Object;

    .line 117
    .line 118
    invoke-virtual {v3, v2, v9}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object v9

    .line 122
    const v2, 0x7f120373

    .line 123
    .line 124
    .line 125
    new-array v1, v1, [Ljava/lang/Object;

    .line 126
    .line 127
    invoke-virtual {v3, v2, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 128
    .line 129
    .line 130
    move-result-object v10

    .line 131
    const/4 v12, 0x0

    .line 132
    const/16 v13, 0x60

    .line 133
    .line 134
    const/4 v11, 0x0

    .line 135
    invoke-static/range {v5 .. v13}, Ljp/rf;->d(Lne0/c;Lij0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLql0/f;I)Lql0/g;

    .line 136
    .line 137
    .line 138
    move-result-object v1

    .line 139
    :goto_0
    invoke-direct {v15, v1}, Lv00/c;-><init>(Lql0/g;)V

    .line 140
    .line 141
    .line 142
    const/16 v16, 0x7ff

    .line 143
    .line 144
    const/4 v5, 0x0

    .line 145
    const/4 v6, 0x0

    .line 146
    const/4 v7, 0x0

    .line 147
    const/4 v8, 0x0

    .line 148
    const/4 v9, 0x0

    .line 149
    const/4 v10, 0x0

    .line 150
    const/4 v11, 0x0

    .line 151
    const/4 v12, 0x0

    .line 152
    const/4 v13, 0x0

    .line 153
    const/4 v14, 0x0

    .line 154
    invoke-static/range {v4 .. v16}, Lv00/h;->a(Lv00/h;Ljava/lang/String;ZZLjava/lang/String;ZLmh0/b;ILjava/util/List;ZZLv00/g;I)Lv00/h;

    .line 155
    .line 156
    .line 157
    move-result-object v1

    .line 158
    :goto_1
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 159
    .line 160
    .line 161
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 162
    .line 163
    return-object v0

    .line 164
    :cond_2
    new-instance v0, La8/r0;

    .line 165
    .line 166
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 167
    .line 168
    .line 169
    throw v0

    .line 170
    :pswitch_0
    move-object/from16 v9, p1

    .line 171
    .line 172
    check-cast v9, Ljava/util/List;

    .line 173
    .line 174
    iget-object v0, v0, Lv00/a;->e:Lv00/i;

    .line 175
    .line 176
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 177
    .line 178
    .line 179
    move-result-object v1

    .line 180
    check-cast v1, Lv00/h;

    .line 181
    .line 182
    const/4 v12, 0x0

    .line 183
    const/16 v13, 0xeff

    .line 184
    .line 185
    const/4 v2, 0x0

    .line 186
    const/4 v3, 0x0

    .line 187
    const/4 v4, 0x0

    .line 188
    const/4 v5, 0x0

    .line 189
    const/4 v6, 0x0

    .line 190
    const/4 v7, 0x0

    .line 191
    const/4 v8, 0x0

    .line 192
    const/4 v10, 0x0

    .line 193
    const/4 v11, 0x0

    .line 194
    invoke-static/range {v1 .. v13}, Lv00/h;->a(Lv00/h;Ljava/lang/String;ZZLjava/lang/String;ZLmh0/b;ILjava/util/List;ZZLv00/g;I)Lv00/h;

    .line 195
    .line 196
    .line 197
    move-result-object v1

    .line 198
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 199
    .line 200
    .line 201
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 202
    .line 203
    return-object v0

    .line 204
    nop

    .line 205
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
