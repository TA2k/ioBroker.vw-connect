.class public final Lh2/i1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# static fields
.field public static final e:Lh2/i1;

.field public static final f:Lh2/i1;

.field public static final g:Lh2/i1;

.field public static final h:Lh2/i1;


# instance fields
.field public final synthetic d:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lh2/i1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lh2/i1;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lh2/i1;->e:Lh2/i1;

    .line 8
    .line 9
    new-instance v0, Lh2/i1;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1}, Lh2/i1;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lh2/i1;->f:Lh2/i1;

    .line 16
    .line 17
    new-instance v0, Lh2/i1;

    .line 18
    .line 19
    const/4 v1, 0x2

    .line 20
    invoke-direct {v0, v1}, Lh2/i1;-><init>(I)V

    .line 21
    .line 22
    .line 23
    sput-object v0, Lh2/i1;->g:Lh2/i1;

    .line 24
    .line 25
    new-instance v0, Lh2/i1;

    .line 26
    .line 27
    const/4 v1, 0x3

    .line 28
    invoke-direct {v0, v1}, Lh2/i1;-><init>(I)V

    .line 29
    .line 30
    .line 31
    sput-object v0, Lh2/i1;->h:Lh2/i1;

    .line 32
    .line 33
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lh2/i1;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v0, v0, Lh2/i1;->d:I

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    const/16 v2, 0x12

    .line 7
    .line 8
    const/4 v3, 0x2

    .line 9
    const/4 v4, 0x4

    .line 10
    const/4 v5, 0x1

    .line 11
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    packed-switch v0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    move-object/from16 v7, p1

    .line 17
    .line 18
    check-cast v7, Lg3/d;

    .line 19
    .line 20
    move-object/from16 v0, p2

    .line 21
    .line 22
    check-cast v0, Ld3/b;

    .line 23
    .line 24
    iget-wide v8, v0, Ld3/b;->a:J

    .line 25
    .line 26
    move-object/from16 v0, p3

    .line 27
    .line 28
    check-cast v0, Le3/s;

    .line 29
    .line 30
    iget-wide v11, v0, Le3/s;->a:J

    .line 31
    .line 32
    sget-object v0, Lh2/a9;->a:Lh2/a9;

    .line 33
    .line 34
    sget v10, Lh2/a9;->c:F

    .line 35
    .line 36
    invoke-static/range {v7 .. v12}, Lh2/a9;->f(Lg3/d;JFJ)V

    .line 37
    .line 38
    .line 39
    return-object v6

    .line 40
    :pswitch_0
    move-object/from16 v0, p1

    .line 41
    .line 42
    check-cast v0, Lg3/d;

    .line 43
    .line 44
    move-object/from16 v1, p2

    .line 45
    .line 46
    check-cast v1, Ld3/b;

    .line 47
    .line 48
    iget-wide v1, v1, Ld3/b;->a:J

    .line 49
    .line 50
    move-object/from16 v3, p3

    .line 51
    .line 52
    check-cast v3, Le3/s;

    .line 53
    .line 54
    iget-wide v4, v3, Le3/s;->a:J

    .line 55
    .line 56
    sget-object v3, Lh2/a9;->a:Lh2/a9;

    .line 57
    .line 58
    sget v3, Lh2/a9;->c:F

    .line 59
    .line 60
    invoke-static/range {v0 .. v5}, Lh2/a9;->f(Lg3/d;JFJ)V

    .line 61
    .line 62
    .line 63
    return-object v6

    .line 64
    :pswitch_1
    move-object/from16 v7, p1

    .line 65
    .line 66
    check-cast v7, Lh2/t9;

    .line 67
    .line 68
    move-object/from16 v0, p2

    .line 69
    .line 70
    check-cast v0, Ll2/o;

    .line 71
    .line 72
    move-object/from16 v8, p3

    .line 73
    .line 74
    check-cast v8, Ljava/lang/Number;

    .line 75
    .line 76
    invoke-virtual {v8}, Ljava/lang/Number;->intValue()I

    .line 77
    .line 78
    .line 79
    move-result v8

    .line 80
    and-int/lit8 v9, v8, 0x6

    .line 81
    .line 82
    if-nez v9, :cond_1

    .line 83
    .line 84
    move-object v9, v0

    .line 85
    check-cast v9, Ll2/t;

    .line 86
    .line 87
    invoke-virtual {v9, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    move-result v9

    .line 91
    if-eqz v9, :cond_0

    .line 92
    .line 93
    move v3, v4

    .line 94
    :cond_0
    or-int/2addr v8, v3

    .line 95
    :cond_1
    and-int/lit8 v3, v8, 0x13

    .line 96
    .line 97
    if-eq v3, v2, :cond_2

    .line 98
    .line 99
    move v1, v5

    .line 100
    :cond_2
    and-int/lit8 v2, v8, 0x1

    .line 101
    .line 102
    check-cast v0, Ll2/t;

    .line 103
    .line 104
    invoke-virtual {v0, v2, v1}, Ll2/t;->O(IZ)Z

    .line 105
    .line 106
    .line 107
    move-result v1

    .line 108
    if-eqz v1, :cond_3

    .line 109
    .line 110
    const-wide/16 v18, 0x0

    .line 111
    .line 112
    and-int/lit8 v21, v8, 0xe

    .line 113
    .line 114
    const/4 v8, 0x0

    .line 115
    const/4 v9, 0x0

    .line 116
    const-wide/16 v10, 0x0

    .line 117
    .line 118
    const-wide/16 v12, 0x0

    .line 119
    .line 120
    const-wide/16 v14, 0x0

    .line 121
    .line 122
    const-wide/16 v16, 0x0

    .line 123
    .line 124
    move-object/from16 v20, v0

    .line 125
    .line 126
    invoke-static/range {v7 .. v21}, Lh2/ja;->c(Lh2/t9;Lx2/s;Le3/n0;JJJJJLl2/o;I)V

    .line 127
    .line 128
    .line 129
    goto :goto_0

    .line 130
    :cond_3
    move-object/from16 v20, v0

    .line 131
    .line 132
    invoke-virtual/range {v20 .. v20}, Ll2/t;->R()V

    .line 133
    .line 134
    .line 135
    :goto_0
    return-object v6

    .line 136
    :pswitch_2
    move-object/from16 v0, p1

    .line 137
    .line 138
    check-cast v0, Lh2/aa;

    .line 139
    .line 140
    move-object/from16 v7, p2

    .line 141
    .line 142
    check-cast v7, Ll2/o;

    .line 143
    .line 144
    move-object/from16 v8, p3

    .line 145
    .line 146
    check-cast v8, Ljava/lang/Number;

    .line 147
    .line 148
    invoke-virtual {v8}, Ljava/lang/Number;->intValue()I

    .line 149
    .line 150
    .line 151
    move-result v8

    .line 152
    and-int/lit8 v9, v8, 0x6

    .line 153
    .line 154
    if-nez v9, :cond_5

    .line 155
    .line 156
    move-object v9, v7

    .line 157
    check-cast v9, Ll2/t;

    .line 158
    .line 159
    invoke-virtual {v9, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 160
    .line 161
    .line 162
    move-result v9

    .line 163
    if-eqz v9, :cond_4

    .line 164
    .line 165
    move v3, v4

    .line 166
    :cond_4
    or-int/2addr v8, v3

    .line 167
    :cond_5
    and-int/lit8 v3, v8, 0x13

    .line 168
    .line 169
    if-eq v3, v2, :cond_6

    .line 170
    .line 171
    move v1, v5

    .line 172
    :cond_6
    and-int/lit8 v2, v8, 0x1

    .line 173
    .line 174
    move-object v3, v7

    .line 175
    check-cast v3, Ll2/t;

    .line 176
    .line 177
    invoke-virtual {v3, v2, v1}, Ll2/t;->O(IZ)Z

    .line 178
    .line 179
    .line 180
    move-result v1

    .line 181
    if-eqz v1, :cond_7

    .line 182
    .line 183
    and-int/lit8 v4, v8, 0xe

    .line 184
    .line 185
    const/4 v5, 0x6

    .line 186
    const/4 v1, 0x0

    .line 187
    const/4 v2, 0x0

    .line 188
    invoke-static/range {v0 .. v5}, Lh2/r;->p(Lh2/aa;Lx2/s;Lay0/o;Ll2/o;II)V

    .line 189
    .line 190
    .line 191
    goto :goto_1

    .line 192
    :cond_7
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 193
    .line 194
    .line 195
    :goto_1
    return-object v6

    .line 196
    nop

    .line 197
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
