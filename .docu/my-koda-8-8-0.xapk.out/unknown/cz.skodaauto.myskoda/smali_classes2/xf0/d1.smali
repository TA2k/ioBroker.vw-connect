.class public final synthetic Lxf0/d1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Z

.field public final synthetic e:Lc1/c;

.field public final synthetic f:F

.field public final synthetic g:F

.field public final synthetic h:Lxf0/w0;

.field public final synthetic i:I


# direct methods
.method public synthetic constructor <init>(ZLc1/c;FFLxf0/w0;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lxf0/d1;->d:Z

    .line 5
    .line 6
    iput-object p2, p0, Lxf0/d1;->e:Lc1/c;

    .line 7
    .line 8
    iput p3, p0, Lxf0/d1;->f:F

    .line 9
    .line 10
    iput p4, p0, Lxf0/d1;->g:F

    .line 11
    .line 12
    iput-object p5, p0, Lxf0/d1;->h:Lxf0/w0;

    .line 13
    .line 14
    iput p6, p0, Lxf0/d1;->i:I

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 33

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Lg3/d;

    .line 6
    .line 7
    const-string v2, "$this$drawHatchBackground"

    .line 8
    .line 9
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    iget-boolean v2, v0, Lxf0/d1;->d:Z

    .line 13
    .line 14
    if-eqz v2, :cond_1

    .line 15
    .line 16
    iget-object v2, v0, Lxf0/d1;->h:Lxf0/w0;

    .line 17
    .line 18
    iget-wide v2, v2, Lxf0/w0;->d:J

    .line 19
    .line 20
    iget-object v4, v0, Lxf0/d1;->e:Lc1/c;

    .line 21
    .line 22
    invoke-virtual {v4}, Lc1/c;->d()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    check-cast v4, Ljava/lang/Number;

    .line 27
    .line 28
    invoke-virtual {v4}, Ljava/lang/Number;->floatValue()F

    .line 29
    .line 30
    .line 31
    move-result v12

    .line 32
    const/4 v4, 0x0

    .line 33
    cmpl-float v4, v12, v4

    .line 34
    .line 35
    if-lez v4, :cond_1

    .line 36
    .line 37
    iget v4, v0, Lxf0/d1;->i:I

    .line 38
    .line 39
    int-to-float v4, v4

    .line 40
    cmpg-float v5, v12, v4

    .line 41
    .line 42
    if-gtz v5, :cond_1

    .line 43
    .line 44
    const/high16 v6, 0x43900000    # 288.0f

    .line 45
    .line 46
    div-float v13, v6, v4

    .line 47
    .line 48
    iget v14, v0, Lxf0/d1;->f:F

    .line 49
    .line 50
    invoke-static {v14}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 51
    .line 52
    .line 53
    move-result v4

    .line 54
    int-to-long v7, v4

    .line 55
    invoke-static {v14}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 56
    .line 57
    .line 58
    move-result v4

    .line 59
    int-to-long v9, v4

    .line 60
    const/16 v15, 0x20

    .line 61
    .line 62
    shl-long/2addr v7, v15

    .line 63
    const-wide v16, 0xffffffffL

    .line 64
    .line 65
    .line 66
    .line 67
    .line 68
    and-long v9, v9, v16

    .line 69
    .line 70
    or-long/2addr v7, v9

    .line 71
    const/high16 v18, 0x40a00000    # 5.0f

    .line 72
    .line 73
    if-nez v5, :cond_0

    .line 74
    .line 75
    move v4, v6

    .line 76
    goto :goto_0

    .line 77
    :cond_0
    move/from16 v4, v18

    .line 78
    .line 79
    :goto_0
    new-instance v19, Lg3/h;

    .line 80
    .line 81
    const/16 v24, 0x0

    .line 82
    .line 83
    const/16 v25, 0x1a

    .line 84
    .line 85
    iget v0, v0, Lxf0/d1;->g:F

    .line 86
    .line 87
    const/16 v21, 0x0

    .line 88
    .line 89
    const/16 v22, 0x0

    .line 90
    .line 91
    const/16 v23, 0x0

    .line 92
    .line 93
    move/from16 v20, v0

    .line 94
    .line 95
    invoke-direct/range {v19 .. v25}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 96
    .line 97
    .line 98
    const/4 v9, 0x0

    .line 99
    const/16 v11, 0x350

    .line 100
    .line 101
    move-object v0, v1

    .line 102
    move-wide v1, v2

    .line 103
    const/high16 v3, 0x42fc0000    # 126.0f

    .line 104
    .line 105
    const-wide/16 v5, 0x0

    .line 106
    .line 107
    move-object/from16 v10, v19

    .line 108
    .line 109
    invoke-static/range {v0 .. v11}, Lg3/d;->o(Lg3/d;JFFJJFLg3/e;I)V

    .line 110
    .line 111
    .line 112
    invoke-static {v14}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 113
    .line 114
    .line 115
    move-result v3

    .line 116
    int-to-long v3, v3

    .line 117
    invoke-static {v14}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 118
    .line 119
    .line 120
    move-result v5

    .line 121
    int-to-long v5, v5

    .line 122
    shl-long/2addr v3, v15

    .line 123
    and-long v5, v5, v16

    .line 124
    .line 125
    or-long v7, v3, v5

    .line 126
    .line 127
    mul-float/2addr v13, v12

    .line 128
    const/4 v3, 0x2

    .line 129
    int-to-float v3, v3

    .line 130
    mul-float v3, v3, v18

    .line 131
    .line 132
    sub-float v4, v13, v3

    .line 133
    .line 134
    new-instance v26, Lg3/h;

    .line 135
    .line 136
    const/16 v31, 0x0

    .line 137
    .line 138
    const/16 v32, 0x1a

    .line 139
    .line 140
    const/16 v28, 0x0

    .line 141
    .line 142
    const/16 v29, 0x1

    .line 143
    .line 144
    const/16 v30, 0x0

    .line 145
    .line 146
    move/from16 v27, v20

    .line 147
    .line 148
    invoke-direct/range {v26 .. v32}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 149
    .line 150
    .line 151
    const/high16 v3, 0x43030000    # 131.0f

    .line 152
    .line 153
    const-wide/16 v5, 0x0

    .line 154
    .line 155
    move-object/from16 v10, v26

    .line 156
    .line 157
    invoke-static/range {v0 .. v11}, Lg3/d;->o(Lg3/d;JFFJJFLg3/e;I)V

    .line 158
    .line 159
    .line 160
    :cond_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 161
    .line 162
    return-object v0
.end method
