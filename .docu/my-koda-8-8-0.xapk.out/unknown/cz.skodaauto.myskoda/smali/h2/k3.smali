.class public final Lh2/k3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:Lgy0/j;

.field public final synthetic e:Li2/z;

.field public final synthetic f:I

.field public final synthetic g:I

.field public final synthetic h:Lay0/k;

.field public final synthetic i:Lh2/e8;

.field public final synthetic j:Lh2/z1;


# direct methods
.method public constructor <init>(Lgy0/j;Li2/z;IILay0/k;Lh2/e8;Lh2/z1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/k3;->d:Lgy0/j;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/k3;->e:Li2/z;

    .line 7
    .line 8
    iput p3, p0, Lh2/k3;->f:I

    .line 9
    .line 10
    iput p4, p0, Lh2/k3;->g:I

    .line 11
    .line 12
    iput-object p5, p0, Lh2/k3;->h:Lay0/k;

    .line 13
    .line 14
    iput-object p6, p0, Lh2/k3;->i:Lh2/e8;

    .line 15
    .line 16
    iput-object p7, p0, Lh2/k3;->j:Lh2/z1;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Ln1/i;

    .line 6
    .line 7
    move-object/from16 v1, p2

    .line 8
    .line 9
    check-cast v1, Ljava/lang/Number;

    .line 10
    .line 11
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    move-object/from16 v2, p3

    .line 16
    .line 17
    check-cast v2, Ll2/o;

    .line 18
    .line 19
    move-object/from16 v3, p4

    .line 20
    .line 21
    check-cast v3, Ljava/lang/Number;

    .line 22
    .line 23
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    and-int/lit8 v4, v3, 0x30

    .line 28
    .line 29
    if-nez v4, :cond_1

    .line 30
    .line 31
    move-object v4, v2

    .line 32
    check-cast v4, Ll2/t;

    .line 33
    .line 34
    invoke-virtual {v4, v1}, Ll2/t;->e(I)Z

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    if-eqz v4, :cond_0

    .line 39
    .line 40
    const/16 v4, 0x20

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_0
    const/16 v4, 0x10

    .line 44
    .line 45
    :goto_0
    or-int/2addr v3, v4

    .line 46
    :cond_1
    and-int/lit16 v4, v3, 0x91

    .line 47
    .line 48
    const/16 v5, 0x90

    .line 49
    .line 50
    const/4 v6, 0x0

    .line 51
    const/4 v7, 0x1

    .line 52
    if-eq v4, v5, :cond_2

    .line 53
    .line 54
    move v4, v7

    .line 55
    goto :goto_1

    .line 56
    :cond_2
    move v4, v6

    .line 57
    :goto_1
    and-int/2addr v3, v7

    .line 58
    check-cast v2, Ll2/t;

    .line 59
    .line 60
    invoke-virtual {v2, v3, v4}, Ll2/t;->O(IZ)Z

    .line 61
    .line 62
    .line 63
    move-result v3

    .line 64
    if-eqz v3, :cond_7

    .line 65
    .line 66
    iget-object v3, v0, Lh2/k3;->d:Lgy0/j;

    .line 67
    .line 68
    iget v3, v3, Lgy0/h;->d:I

    .line 69
    .line 70
    add-int/2addr v1, v3

    .line 71
    iget-object v3, v0, Lh2/k3;->e:Li2/z;

    .line 72
    .line 73
    iget-object v3, v3, Li2/z;->a:Ljava/util/Locale;

    .line 74
    .line 75
    invoke-static {v1, v3}, Lh2/v0;->a(ILjava/util/Locale;)Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object v8

    .line 79
    sget v3, Lk2/m;->D:F

    .line 80
    .line 81
    sget v4, Lk2/m;->C:F

    .line 82
    .line 83
    sget-object v5, Lx2/p;->b:Lx2/p;

    .line 84
    .line 85
    invoke-static {v5, v3, v4}, Landroidx/compose/foundation/layout/d;->k(Lx2/s;FF)Lx2/s;

    .line 86
    .line 87
    .line 88
    move-result-object v9

    .line 89
    iget v3, v0, Lh2/k3;->f:I

    .line 90
    .line 91
    if-ne v1, v3, :cond_3

    .line 92
    .line 93
    move v10, v7

    .line 94
    goto :goto_2

    .line 95
    :cond_3
    move v10, v6

    .line 96
    :goto_2
    iget v3, v0, Lh2/k3;->g:I

    .line 97
    .line 98
    if-ne v1, v3, :cond_4

    .line 99
    .line 100
    move v11, v7

    .line 101
    goto :goto_3

    .line 102
    :cond_4
    move v11, v6

    .line 103
    :goto_3
    iget-object v3, v0, Lh2/k3;->h:Lay0/k;

    .line 104
    .line 105
    invoke-virtual {v2, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    move-result v4

    .line 109
    invoke-virtual {v2, v1}, Ll2/t;->e(I)Z

    .line 110
    .line 111
    .line 112
    move-result v5

    .line 113
    or-int/2addr v4, v5

    .line 114
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object v5

    .line 118
    if-nez v4, :cond_5

    .line 119
    .line 120
    sget-object v4, Ll2/n;->a:Ll2/x0;

    .line 121
    .line 122
    if-ne v5, v4, :cond_6

    .line 123
    .line 124
    :cond_5
    new-instance v5, Lcz/k;

    .line 125
    .line 126
    const/4 v4, 0x1

    .line 127
    invoke-direct {v5, v1, v4, v3}, Lcz/k;-><init>(IILay0/k;)V

    .line 128
    .line 129
    .line 130
    invoke-virtual {v2, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 131
    .line 132
    .line 133
    :cond_6
    move-object v12, v5

    .line 134
    check-cast v12, Lay0/a;

    .line 135
    .line 136
    iget-object v3, v0, Lh2/k3;->i:Lh2/e8;

    .line 137
    .line 138
    invoke-interface {v3, v1}, Lh2/e8;->a(I)Z

    .line 139
    .line 140
    .line 141
    move-result v13

    .line 142
    const v1, 0x7f12059d

    .line 143
    .line 144
    .line 145
    invoke-static {v2, v1}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 146
    .line 147
    .line 148
    move-result-object v1

    .line 149
    filled-new-array {v8}, [Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object v3

    .line 153
    invoke-static {v3, v7}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 154
    .line 155
    .line 156
    move-result-object v3

    .line 157
    invoke-static {v1, v3}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 158
    .line 159
    .line 160
    move-result-object v14

    .line 161
    iget-object v15, v0, Lh2/k3;->j:Lh2/z1;

    .line 162
    .line 163
    const/16 v17, 0x30

    .line 164
    .line 165
    move-object/from16 v16, v2

    .line 166
    .line 167
    invoke-static/range {v8 .. v17}, Lh2/m3;->m(Ljava/lang/String;Lx2/s;ZZLay0/a;ZLjava/lang/String;Lh2/z1;Ll2/o;I)V

    .line 168
    .line 169
    .line 170
    goto :goto_4

    .line 171
    :cond_7
    move-object/from16 v16, v2

    .line 172
    .line 173
    invoke-virtual/range {v16 .. v16}, Ll2/t;->R()V

    .line 174
    .line 175
    .line 176
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 177
    .line 178
    return-object v0
.end method
