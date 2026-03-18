.class public final Lpv0/g;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lwr0/e;

.field public final i:Lov0/e;

.field public final j:Lov0/f;

.field public final k:Lov0/d;

.field public final l:Lkf0/v;

.field public final m:Lov0/b;

.field public final n:Lov0/c;

.field public final o:Lij0/a;

.field public final p:Lgb0/h;

.field public final q:Llp0/b;

.field public final r:Llp0/d;

.field public final s:Lov0/a;

.field public final t:Lhh0/a;


# direct methods
.method public constructor <init>(Lwr0/e;Lov0/e;Lov0/f;Lov0/d;Lkf0/v;Lov0/b;Lov0/c;Lij0/a;Lgb0/h;Llp0/b;Llp0/d;Lov0/a;Lhh0/a;)V
    .locals 11

    .line 1
    move-object/from16 v0, p8

    .line 2
    .line 3
    new-instance v1, Lpv0/f;

    .line 4
    .line 5
    const/16 v2, 0x1ff

    .line 6
    .line 7
    const/4 v3, 0x1

    .line 8
    and-int/2addr v2, v3

    .line 9
    const/4 v4, 0x0

    .line 10
    if-eqz v2, :cond_0

    .line 11
    .line 12
    move v2, v4

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    move v2, v3

    .line 15
    :goto_0
    const/16 v5, 0x1ff

    .line 16
    .line 17
    and-int/lit8 v6, v5, 0x4

    .line 18
    .line 19
    if-eqz v6, :cond_1

    .line 20
    .line 21
    move v6, v4

    .line 22
    goto :goto_1

    .line 23
    :cond_1
    move v6, v4

    .line 24
    move v4, v3

    .line 25
    :goto_1
    and-int/lit8 v7, v5, 0x8

    .line 26
    .line 27
    if-eqz v7, :cond_2

    .line 28
    .line 29
    move v3, v6

    .line 30
    :cond_2
    and-int/lit8 v5, v5, 0x40

    .line 31
    .line 32
    if-eqz v5, :cond_3

    .line 33
    .line 34
    const-string v5, ""

    .line 35
    .line 36
    :goto_2
    move-object v8, v5

    .line 37
    goto :goto_3

    .line 38
    :cond_3
    const-string v5, "1.0.0"

    .line 39
    .line 40
    goto :goto_2

    .line 41
    :goto_3
    const/4 v9, 0x0

    .line 42
    const/4 v10, 0x0

    .line 43
    move v5, v3

    .line 44
    const/4 v3, 0x0

    .line 45
    const/4 v6, 0x0

    .line 46
    const/4 v7, 0x0

    .line 47
    invoke-direct/range {v1 .. v10}, Lpv0/f;-><init>(ZZZZZZLjava/lang/String;ZZ)V

    .line 48
    .line 49
    .line 50
    invoke-direct {p0, v1}, Lql0/j;-><init>(Lql0/h;)V

    .line 51
    .line 52
    .line 53
    iput-object p1, p0, Lpv0/g;->h:Lwr0/e;

    .line 54
    .line 55
    iput-object p2, p0, Lpv0/g;->i:Lov0/e;

    .line 56
    .line 57
    iput-object p3, p0, Lpv0/g;->j:Lov0/f;

    .line 58
    .line 59
    iput-object p4, p0, Lpv0/g;->k:Lov0/d;

    .line 60
    .line 61
    move-object/from16 p1, p5

    .line 62
    .line 63
    iput-object p1, p0, Lpv0/g;->l:Lkf0/v;

    .line 64
    .line 65
    move-object/from16 p1, p6

    .line 66
    .line 67
    iput-object p1, p0, Lpv0/g;->m:Lov0/b;

    .line 68
    .line 69
    move-object/from16 p1, p7

    .line 70
    .line 71
    iput-object p1, p0, Lpv0/g;->n:Lov0/c;

    .line 72
    .line 73
    iput-object v0, p0, Lpv0/g;->o:Lij0/a;

    .line 74
    .line 75
    move-object/from16 p1, p9

    .line 76
    .line 77
    iput-object p1, p0, Lpv0/g;->p:Lgb0/h;

    .line 78
    .line 79
    move-object/from16 p1, p10

    .line 80
    .line 81
    iput-object p1, p0, Lpv0/g;->q:Llp0/b;

    .line 82
    .line 83
    move-object/from16 p1, p11

    .line 84
    .line 85
    iput-object p1, p0, Lpv0/g;->r:Llp0/d;

    .line 86
    .line 87
    move-object/from16 p1, p12

    .line 88
    .line 89
    iput-object p1, p0, Lpv0/g;->s:Lov0/a;

    .line 90
    .line 91
    move-object/from16 p1, p13

    .line 92
    .line 93
    iput-object p1, p0, Lpv0/g;->t:Lhh0/a;

    .line 94
    .line 95
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 96
    .line 97
    .line 98
    move-result-object p1

    .line 99
    move-object p2, p1

    .line 100
    check-cast p2, Lpv0/f;

    .line 101
    .line 102
    const/4 p1, 0x0

    .line 103
    new-array p1, p1, [Ljava/lang/Object;

    .line 104
    .line 105
    move-object p3, v0

    .line 106
    check-cast p3, Ljj0/f;

    .line 107
    .line 108
    const v0, 0x7f120194

    .line 109
    .line 110
    .line 111
    invoke-virtual {p3, v0, p1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object p1

    .line 115
    const-string p3, " 8.8.0"

    .line 116
    .line 117
    invoke-virtual {p1, p3}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object p1

    .line 121
    const/4 p3, 0x0

    .line 122
    const/16 v0, 0xbf

    .line 123
    .line 124
    const/4 v1, 0x0

    .line 125
    const/4 v2, 0x0

    .line 126
    const/4 v4, 0x0

    .line 127
    const/4 v5, 0x0

    .line 128
    move-object/from16 p9, p1

    .line 129
    .line 130
    move/from16 p10, p3

    .line 131
    .line 132
    move/from16 p11, v0

    .line 133
    .line 134
    move p3, v1

    .line 135
    move p4, v2

    .line 136
    move/from16 p5, v3

    .line 137
    .line 138
    move/from16 p6, v4

    .line 139
    .line 140
    move/from16 p7, v5

    .line 141
    .line 142
    move/from16 p8, v6

    .line 143
    .line 144
    invoke-static/range {p2 .. p11}, Lpv0/f;->a(Lpv0/f;ZZZZZZLjava/lang/String;ZI)Lpv0/f;

    .line 145
    .line 146
    .line 147
    move-result-object p1

    .line 148
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 149
    .line 150
    .line 151
    new-instance p1, Lpv0/a;

    .line 152
    .line 153
    const/4 p2, 0x0

    .line 154
    const/4 p3, 0x0

    .line 155
    invoke-direct {p1, p0, p3, p2}, Lpv0/a;-><init>(Lpv0/g;Lkotlin/coroutines/Continuation;I)V

    .line 156
    .line 157
    .line 158
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 159
    .line 160
    .line 161
    new-instance p1, Lpv0/e;

    .line 162
    .line 163
    invoke-direct {p1, p0, p3, p2}, Lpv0/e;-><init>(Lpv0/g;Lkotlin/coroutines/Continuation;I)V

    .line 164
    .line 165
    .line 166
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 167
    .line 168
    .line 169
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 170
    .line 171
    .line 172
    move-result-object p1

    .line 173
    new-instance p2, Lpv0/a;

    .line 174
    .line 175
    const/4 v0, 0x2

    .line 176
    invoke-direct {p2, p0, p3, v0}, Lpv0/a;-><init>(Lpv0/g;Lkotlin/coroutines/Continuation;I)V

    .line 177
    .line 178
    .line 179
    const/4 p0, 0x3

    .line 180
    invoke-static {p1, p3, p3, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 181
    .line 182
    .line 183
    return-void
.end method
