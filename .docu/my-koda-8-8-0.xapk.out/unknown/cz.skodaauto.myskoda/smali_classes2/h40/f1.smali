.class public final Lh40/f1;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lf40/w2;

.field public final i:Lbq0/k;

.field public final j:Ltr0/b;

.field public final k:Lf40/m2;

.field public final l:Lf40/y1;

.field public final m:Lf40/l4;

.field public final n:Lf40/o2;

.field public final o:Lf40/f;

.field public final p:Lij0/a;

.field public final q:Lbq0/j;

.field public final r:Lbq0/s;

.field public final s:Lf40/l1;


# direct methods
.method public constructor <init>(Lf40/w2;Lbq0/k;Ltr0/b;Lf40/m2;Lf40/y1;Lf40/l4;Lf40/o2;Lf40/f;Lij0/a;Lbq0/j;Lbq0/s;Lbq0/g;Lf40/h0;Lf40/l1;)V
    .locals 14

    .line 1
    move-object/from16 v0, p11

    .line 2
    .line 3
    new-instance v1, Lh40/e1;

    .line 4
    .line 5
    const/4 v8, 0x0

    .line 6
    const/4 v12, 0x1

    .line 7
    const/4 v2, 0x0

    .line 8
    const/4 v3, 0x0

    .line 9
    const-string v4, ""

    .line 10
    .line 11
    const/4 v6, 0x0

    .line 12
    const/4 v7, 0x0

    .line 13
    const/4 v9, 0x0

    .line 14
    const/4 v10, 0x0

    .line 15
    const/4 v11, 0x0

    .line 16
    const/4 v13, 0x0

    .line 17
    move-object v5, v4

    .line 18
    invoke-direct/range {v1 .. v13}, Lh40/e1;-><init>(Lql0/g;ZLjava/lang/String;Ljava/lang/String;Landroid/net/Uri;IZLjava/time/LocalDate;Lh40/d1;Ljava/lang/String;ZLjava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-direct {p0, v1}, Lql0/j;-><init>(Lql0/h;)V

    .line 22
    .line 23
    .line 24
    iput-object p1, p0, Lh40/f1;->h:Lf40/w2;

    .line 25
    .line 26
    move-object/from16 v1, p2

    .line 27
    .line 28
    iput-object v1, p0, Lh40/f1;->i:Lbq0/k;

    .line 29
    .line 30
    move-object/from16 v1, p3

    .line 31
    .line 32
    iput-object v1, p0, Lh40/f1;->j:Ltr0/b;

    .line 33
    .line 34
    move-object/from16 v1, p4

    .line 35
    .line 36
    iput-object v1, p0, Lh40/f1;->k:Lf40/m2;

    .line 37
    .line 38
    move-object/from16 v1, p5

    .line 39
    .line 40
    iput-object v1, p0, Lh40/f1;->l:Lf40/y1;

    .line 41
    .line 42
    move-object/from16 v1, p6

    .line 43
    .line 44
    iput-object v1, p0, Lh40/f1;->m:Lf40/l4;

    .line 45
    .line 46
    move-object/from16 v1, p7

    .line 47
    .line 48
    iput-object v1, p0, Lh40/f1;->n:Lf40/o2;

    .line 49
    .line 50
    move-object/from16 v1, p8

    .line 51
    .line 52
    iput-object v1, p0, Lh40/f1;->o:Lf40/f;

    .line 53
    .line 54
    move-object/from16 v1, p9

    .line 55
    .line 56
    iput-object v1, p0, Lh40/f1;->p:Lij0/a;

    .line 57
    .line 58
    move-object/from16 v1, p10

    .line 59
    .line 60
    iput-object v1, p0, Lh40/f1;->q:Lbq0/j;

    .line 61
    .line 62
    iput-object v0, p0, Lh40/f1;->r:Lbq0/s;

    .line 63
    .line 64
    move-object/from16 v1, p14

    .line 65
    .line 66
    iput-object v1, p0, Lh40/f1;->s:Lf40/l1;

    .line 67
    .line 68
    const/4 v1, 0x0

    .line 69
    invoke-virtual {v0, v1}, Lbq0/s;->a(Lcq0/n;)V

    .line 70
    .line 71
    .line 72
    invoke-virtual/range {p12 .. p12}, Lbq0/g;->invoke()Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    invoke-virtual/range {p13 .. p13}, Lf40/h0;->invoke()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    check-cast v0, Lg40/f;

    .line 80
    .line 81
    if-eqz v0, :cond_1

    .line 82
    .line 83
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 84
    .line 85
    .line 86
    move-result-object v2

    .line 87
    check-cast v2, Lh40/e1;

    .line 88
    .line 89
    iget-object v3, v0, Lg40/f;->a:Ljava/lang/String;

    .line 90
    .line 91
    iget-object v4, v0, Lg40/f;->b:Ljava/lang/String;

    .line 92
    .line 93
    iget-object v5, v0, Lg40/f;->f:Ljava/util/List;

    .line 94
    .line 95
    invoke-static {v5}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v5

    .line 99
    check-cast v5, Ljava/lang/String;

    .line 100
    .line 101
    if-eqz v5, :cond_0

    .line 102
    .line 103
    invoke-static {v5}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 104
    .line 105
    .line 106
    move-result-object v5

    .line 107
    goto :goto_0

    .line 108
    :cond_0
    move-object v5, v1

    .line 109
    :goto_0
    iget v0, v0, Lg40/f;->e:I

    .line 110
    .line 111
    const/4 v6, 0x0

    .line 112
    const/16 v7, 0xfc3

    .line 113
    .line 114
    const/4 v8, 0x0

    .line 115
    const/4 v9, 0x0

    .line 116
    const/4 v10, 0x0

    .line 117
    const/4 v11, 0x0

    .line 118
    const/4 v12, 0x0

    .line 119
    const/4 v13, 0x0

    .line 120
    move/from16 p7, v0

    .line 121
    .line 122
    move-object p1, v2

    .line 123
    move-object/from16 p4, v3

    .line 124
    .line 125
    move-object/from16 p5, v4

    .line 126
    .line 127
    move-object/from16 p6, v5

    .line 128
    .line 129
    move-object/from16 p12, v6

    .line 130
    .line 131
    move/from16 p13, v7

    .line 132
    .line 133
    move-object/from16 p2, v8

    .line 134
    .line 135
    move/from16 p3, v9

    .line 136
    .line 137
    move/from16 p8, v10

    .line 138
    .line 139
    move-object/from16 p9, v11

    .line 140
    .line 141
    move-object/from16 p10, v12

    .line 142
    .line 143
    move-object/from16 p11, v13

    .line 144
    .line 145
    invoke-static/range {p1 .. p13}, Lh40/e1;->a(Lh40/e1;Lql0/g;ZLjava/lang/String;Ljava/lang/String;Landroid/net/Uri;IZLjava/time/LocalDate;Lh40/d1;Ljava/lang/String;Ljava/lang/String;I)Lh40/e1;

    .line 146
    .line 147
    .line 148
    move-result-object v0

    .line 149
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 150
    .line 151
    .line 152
    :cond_1
    new-instance v0, Lh40/c1;

    .line 153
    .line 154
    const/4 v2, 0x0

    .line 155
    invoke-direct {v0, p0, v1, v2}, Lh40/c1;-><init>(Lh40/f1;Lkotlin/coroutines/Continuation;I)V

    .line 156
    .line 157
    .line 158
    invoke-virtual {p0, v0}, Lql0/j;->b(Lay0/n;)V

    .line 159
    .line 160
    .line 161
    new-instance v0, Lh40/c1;

    .line 162
    .line 163
    const/4 v2, 0x1

    .line 164
    invoke-direct {v0, p0, v1, v2}, Lh40/c1;-><init>(Lh40/f1;Lkotlin/coroutines/Continuation;I)V

    .line 165
    .line 166
    .line 167
    invoke-virtual {p0, v0}, Lql0/j;->b(Lay0/n;)V

    .line 168
    .line 169
    .line 170
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 171
    .line 172
    .line 173
    move-result-object v0

    .line 174
    new-instance v2, Lh40/c1;

    .line 175
    .line 176
    const/4 v3, 0x2

    .line 177
    invoke-direct {v2, p0, v1, v3}, Lh40/c1;-><init>(Lh40/f1;Lkotlin/coroutines/Continuation;I)V

    .line 178
    .line 179
    .line 180
    const/4 p0, 0x3

    .line 181
    invoke-static {v0, v1, v1, v2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 182
    .line 183
    .line 184
    return-void
.end method
