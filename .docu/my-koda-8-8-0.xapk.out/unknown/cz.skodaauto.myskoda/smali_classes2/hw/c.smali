.class public abstract Lhw/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ll2/u2;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lh50/p;

    .line 2
    .line 3
    const/16 v1, 0x1b

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lh50/p;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Ll2/u2;

    .line 9
    .line 10
    invoke-direct {v1, v0}, Ll2/s1;-><init>(Lay0/a;)V

    .line 11
    .line 12
    .line 13
    sput-object v1, Lhw/c;->a:Ll2/u2;

    .line 14
    .line 15
    return-void
.end method

.method public static final a(Ll2/o;)Lhw/b;
    .locals 10

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    const v0, 0x3369af08

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, v0}, Ll2/t;->Z(I)V

    .line 7
    .line 8
    .line 9
    sget-object v0, Lhw/c;->a:Ll2/u2;

    .line 10
    .line 11
    invoke-virtual {p0, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    check-cast v0, Lhw/b;

    .line 16
    .line 17
    const/4 v1, 0x0

    .line 18
    if-nez v0, :cond_4

    .line 19
    .line 20
    const v0, -0x35d5cc0e    # -2788604.5f

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0, v0}, Ll2/t;->Z(I)V

    .line 24
    .line 25
    .line 26
    invoke-static {p0}, Lkp/k;->c(Ll2/o;)Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-eqz v0, :cond_0

    .line 31
    .line 32
    sget-object v0, Lpw/b;->f:Lpw/b;

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    sget-object v0, Lpw/b;->e:Lpw/b;

    .line 36
    .line 37
    :goto_0
    invoke-virtual {p0, v1}, Ll2/t;->q(Z)V

    .line 38
    .line 39
    .line 40
    const v2, 0x4526e709

    .line 41
    .line 42
    .line 43
    invoke-virtual {p0, v2}, Ll2/t;->Z(I)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {p0, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    invoke-virtual {p0}, Ll2/t;->L()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v3

    .line 54
    if-nez v2, :cond_1

    .line 55
    .line 56
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 57
    .line 58
    if-ne v3, v2, :cond_3

    .line 59
    .line 60
    :cond_1
    const-string v2, "defaultColors"

    .line 61
    .line 62
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    new-instance v3, Lhw/a;

    .line 66
    .line 67
    const-wide v4, 0xff02c898L

    .line 68
    .line 69
    .line 70
    .line 71
    .line 72
    invoke-static {v4, v5}, Le3/j0;->e(J)J

    .line 73
    .line 74
    .line 75
    move-result-wide v4

    .line 76
    iget-wide v6, v0, Lpw/b;->a:J

    .line 77
    .line 78
    invoke-static {v6, v7}, Le3/j0;->e(J)J

    .line 79
    .line 80
    .line 81
    move-result-wide v6

    .line 82
    const-wide v8, 0xffea284bL

    .line 83
    .line 84
    .line 85
    .line 86
    .line 87
    invoke-static {v8, v9}, Le3/j0;->e(J)J

    .line 88
    .line 89
    .line 90
    move-result-wide v8

    .line 91
    invoke-direct/range {v3 .. v9}, Lhw/a;-><init>(JJJ)V

    .line 92
    .line 93
    .line 94
    iget-object v2, v0, Lpw/b;->b:Ljava/util/List;

    .line 95
    .line 96
    check-cast v2, Ljava/lang/Iterable;

    .line 97
    .line 98
    new-instance v5, Ljava/util/ArrayList;

    .line 99
    .line 100
    const/16 v4, 0xa

    .line 101
    .line 102
    invoke-static {v2, v4}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 103
    .line 104
    .line 105
    move-result v4

    .line 106
    invoke-direct {v5, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 107
    .line 108
    .line 109
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 110
    .line 111
    .line 112
    move-result-object v2

    .line 113
    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 114
    .line 115
    .line 116
    move-result v4

    .line 117
    if-eqz v4, :cond_2

    .line 118
    .line 119
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object v4

    .line 123
    check-cast v4, Ljava/lang/Number;

    .line 124
    .line 125
    invoke-virtual {v4}, Ljava/lang/Number;->longValue()J

    .line 126
    .line 127
    .line 128
    move-result-wide v6

    .line 129
    invoke-static {v6, v7}, Le3/j0;->e(J)J

    .line 130
    .line 131
    .line 132
    move-result-wide v6

    .line 133
    new-instance v4, Le3/s;

    .line 134
    .line 135
    invoke-direct {v4, v6, v7}, Le3/s;-><init>(J)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {v5, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    goto :goto_1

    .line 142
    :cond_2
    iget-wide v6, v0, Lpw/b;->c:J

    .line 143
    .line 144
    invoke-static {v6, v7}, Le3/j0;->e(J)J

    .line 145
    .line 146
    .line 147
    move-result-wide v6

    .line 148
    iget-wide v8, v0, Lpw/b;->d:J

    .line 149
    .line 150
    invoke-static {v8, v9}, Le3/j0;->e(J)J

    .line 151
    .line 152
    .line 153
    move-result-wide v8

    .line 154
    move-object v4, v3

    .line 155
    new-instance v3, Lhw/b;

    .line 156
    .line 157
    invoke-direct/range {v3 .. v9}, Lhw/b;-><init>(Lhw/a;Ljava/util/ArrayList;JJ)V

    .line 158
    .line 159
    .line 160
    invoke-virtual {p0, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 161
    .line 162
    .line 163
    :cond_3
    move-object v0, v3

    .line 164
    check-cast v0, Lhw/b;

    .line 165
    .line 166
    invoke-virtual {p0, v1}, Ll2/t;->q(Z)V

    .line 167
    .line 168
    .line 169
    :cond_4
    invoke-virtual {p0, v1}, Ll2/t;->q(Z)V

    .line 170
    .line 171
    .line 172
    return-object v0
.end method
