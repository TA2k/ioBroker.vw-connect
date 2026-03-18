.class public final Lh40/g4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh40/i4;


# direct methods
.method public synthetic constructor <init>(Lh40/i4;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh40/g4;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh40/g4;->e:Lh40/i4;

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
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    iget v2, v0, Lh40/g4;->d:I

    .line 6
    .line 7
    packed-switch v2, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    move-object/from16 v2, p1

    .line 11
    .line 12
    check-cast v2, Lne0/t;

    .line 13
    .line 14
    iget-object v0, v0, Lh40/g4;->e:Lh40/i4;

    .line 15
    .line 16
    invoke-static {v0, v1}, Lh40/i4;->h(Lh40/i4;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 21
    .line 22
    if-ne v0, v1, :cond_0

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    :goto_0
    return-object v0

    .line 28
    :pswitch_0
    move-object/from16 v2, p1

    .line 29
    .line 30
    check-cast v2, Lne0/s;

    .line 31
    .line 32
    instance-of v3, v2, Lne0/c;

    .line 33
    .line 34
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    iget-object v0, v0, Lh40/g4;->e:Lh40/i4;

    .line 37
    .line 38
    if-eqz v3, :cond_1

    .line 39
    .line 40
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    move-object v5, v1

    .line 45
    check-cast v5, Lh40/d4;

    .line 46
    .line 47
    const/16 v24, 0x0

    .line 48
    .line 49
    const v25, 0xfcfff

    .line 50
    .line 51
    .line 52
    const/4 v6, 0x0

    .line 53
    const/4 v7, 0x0

    .line 54
    const/4 v8, 0x0

    .line 55
    const/4 v9, 0x0

    .line 56
    const/4 v10, 0x0

    .line 57
    const/4 v11, 0x0

    .line 58
    const/4 v12, 0x0

    .line 59
    const/4 v13, 0x0

    .line 60
    const/4 v14, 0x0

    .line 61
    const/4 v15, 0x0

    .line 62
    const/16 v16, 0x0

    .line 63
    .line 64
    const/16 v17, 0x0

    .line 65
    .line 66
    const/16 v18, 0x0

    .line 67
    .line 68
    const/16 v19, 0x0

    .line 69
    .line 70
    const/16 v20, 0x0

    .line 71
    .line 72
    const/16 v21, 0x0

    .line 73
    .line 74
    const/16 v22, 0x0

    .line 75
    .line 76
    const/16 v23, 0x0

    .line 77
    .line 78
    invoke-static/range {v5 .. v25}, Lh40/d4;->a(Lh40/d4;IZZZLjava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/List;Lh40/b4;Lh40/a4;ZLjava/lang/String;ZZLql0/g;ZZZZI)Lh40/d4;

    .line 79
    .line 80
    .line 81
    move-result-object v1

    .line 82
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 83
    .line 84
    .line 85
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 86
    .line 87
    .line 88
    move-result-object v1

    .line 89
    new-instance v3, Lh40/w3;

    .line 90
    .line 91
    const/4 v5, 0x3

    .line 92
    const/4 v6, 0x0

    .line 93
    invoke-direct {v3, v5, v0, v2, v6}, Lh40/w3;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 94
    .line 95
    .line 96
    const/4 v0, 0x3

    .line 97
    invoke-static {v1, v6, v6, v3, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 98
    .line 99
    .line 100
    goto :goto_1

    .line 101
    :cond_1
    instance-of v3, v2, Lne0/e;

    .line 102
    .line 103
    if-eqz v3, :cond_2

    .line 104
    .line 105
    invoke-static {v0, v1}, Lh40/i4;->h(Lh40/i4;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v0

    .line 109
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 110
    .line 111
    if-ne v0, v1, :cond_3

    .line 112
    .line 113
    move-object v4, v0

    .line 114
    goto :goto_1

    .line 115
    :cond_2
    sget-object v1, Lne0/d;->a:Lne0/d;

    .line 116
    .line 117
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 118
    .line 119
    .line 120
    move-result v1

    .line 121
    if-eqz v1, :cond_4

    .line 122
    .line 123
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 124
    .line 125
    .line 126
    move-result-object v1

    .line 127
    move-object v5, v1

    .line 128
    check-cast v5, Lh40/d4;

    .line 129
    .line 130
    const/16 v24, 0x0

    .line 131
    .line 132
    const v25, 0xfdfff

    .line 133
    .line 134
    .line 135
    const/4 v6, 0x0

    .line 136
    const/4 v7, 0x0

    .line 137
    const/4 v8, 0x0

    .line 138
    const/4 v9, 0x0

    .line 139
    const/4 v10, 0x0

    .line 140
    const/4 v11, 0x0

    .line 141
    const/4 v12, 0x0

    .line 142
    const/4 v13, 0x0

    .line 143
    const/4 v14, 0x0

    .line 144
    const/4 v15, 0x0

    .line 145
    const/16 v16, 0x0

    .line 146
    .line 147
    const/16 v17, 0x0

    .line 148
    .line 149
    const/16 v18, 0x1

    .line 150
    .line 151
    const/16 v19, 0x0

    .line 152
    .line 153
    const/16 v20, 0x0

    .line 154
    .line 155
    const/16 v21, 0x0

    .line 156
    .line 157
    const/16 v22, 0x0

    .line 158
    .line 159
    const/16 v23, 0x0

    .line 160
    .line 161
    invoke-static/range {v5 .. v25}, Lh40/d4;->a(Lh40/d4;IZZZLjava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/List;Lh40/b4;Lh40/a4;ZLjava/lang/String;ZZLql0/g;ZZZZI)Lh40/d4;

    .line 162
    .line 163
    .line 164
    move-result-object v1

    .line 165
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 166
    .line 167
    .line 168
    :cond_3
    :goto_1
    return-object v4

    .line 169
    :cond_4
    new-instance v0, La8/r0;

    .line 170
    .line 171
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 172
    .line 173
    .line 174
    throw v0

    .line 175
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
