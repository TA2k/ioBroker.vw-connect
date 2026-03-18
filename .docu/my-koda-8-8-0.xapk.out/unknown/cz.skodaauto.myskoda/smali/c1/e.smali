.class public abstract Lc1/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lc1/f1;

.field public static final b:Lc1/f1;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x7

    .line 3
    const/4 v2, 0x0

    .line 4
    invoke-static {v2, v2, v0, v1}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    sput-object v0, Lc1/e;->a:Lc1/f1;

    .line 9
    .line 10
    sget-object v0, Lc1/n2;->a:Ljava/lang/Object;

    .line 11
    .line 12
    new-instance v0, Lt4/f;

    .line 13
    .line 14
    const v1, 0x3dcccccd    # 0.1f

    .line 15
    .line 16
    .line 17
    invoke-direct {v0, v1}, Lt4/f;-><init>(F)V

    .line 18
    .line 19
    .line 20
    const/4 v1, 0x3

    .line 21
    invoke-static {v2, v2, v0, v1}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    sput-object v0, Lc1/e;->b:Lc1/f1;

    .line 26
    .line 27
    const/high16 v0, 0x3f000000    # 0.5f

    .line 28
    .line 29
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 30
    .line 31
    .line 32
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 33
    .line 34
    .line 35
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 36
    .line 37
    .line 38
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 39
    .line 40
    .line 41
    return-void
.end method

.method public static final a(FLc1/a0;Lay0/k;Ll2/o;II)Ll2/t2;
    .locals 9

    .line 1
    and-int/lit8 v0, p5, 0x2

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    sget-object p1, Lc1/e;->b:Lc1/f1;

    .line 6
    .line 7
    :cond_0
    move-object v2, p1

    .line 8
    and-int/lit8 p1, p5, 0x4

    .line 9
    .line 10
    if-eqz p1, :cond_1

    .line 11
    .line 12
    const-string p1, "DpAnimation"

    .line 13
    .line 14
    :goto_0
    move-object v4, p1

    .line 15
    goto :goto_1

    .line 16
    :cond_1
    const-string p1, "blur"

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :goto_1
    and-int/lit8 p1, p5, 0x8

    .line 20
    .line 21
    if-eqz p1, :cond_2

    .line 22
    .line 23
    const/4 p2, 0x0

    .line 24
    :cond_2
    move-object v5, p2

    .line 25
    new-instance v0, Lt4/f;

    .line 26
    .line 27
    invoke-direct {v0, p0}, Lt4/f;-><init>(F)V

    .line 28
    .line 29
    .line 30
    sget-object v1, Lc1/d;->l:Lc1/b2;

    .line 31
    .line 32
    shl-int/lit8 p0, p4, 0x3

    .line 33
    .line 34
    and-int/lit16 p0, p0, 0x380

    .line 35
    .line 36
    shl-int/lit8 p1, p4, 0x6

    .line 37
    .line 38
    const p2, 0xe000

    .line 39
    .line 40
    .line 41
    and-int/2addr p2, p1

    .line 42
    or-int/2addr p0, p2

    .line 43
    const/high16 p2, 0x70000

    .line 44
    .line 45
    and-int/2addr p1, p2

    .line 46
    or-int v7, p0, p1

    .line 47
    .line 48
    const/16 v8, 0x8

    .line 49
    .line 50
    const/4 v3, 0x0

    .line 51
    move-object v6, p3

    .line 52
    invoke-static/range {v0 .. v8}, Lc1/e;->c(Ljava/lang/Object;Lc1/b2;Lc1/j;Ljava/lang/Float;Ljava/lang/String;Lay0/k;Ll2/o;II)Ll2/t2;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0
.end method

.method public static final b(FLc1/a0;Ljava/lang/String;Ll2/o;II)Ll2/t2;
    .locals 11

    .line 1
    and-int/lit8 v0, p5, 0x2

    .line 2
    .line 3
    sget-object v1, Lc1/e;->a:Lc1/f1;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    move-object p1, v1

    .line 8
    :cond_0
    and-int/lit8 v0, p5, 0x8

    .line 9
    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    const-string p2, "FloatAnimation"

    .line 13
    .line 14
    :cond_1
    move-object v6, p2

    .line 15
    const/4 p2, 0x3

    .line 16
    const/4 v0, 0x0

    .line 17
    const v2, 0x3c23d70a    # 0.01f

    .line 18
    .line 19
    .line 20
    if-ne p1, v1, :cond_4

    .line 21
    .line 22
    move-object p1, p3

    .line 23
    check-cast p1, Ll2/t;

    .line 24
    .line 25
    const v1, 0x4431b71f

    .line 26
    .line 27
    .line 28
    invoke-virtual {p1, v1}, Ll2/t;->Y(I)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p1, v2}, Ll2/t;->d(F)Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    if-nez v1, :cond_2

    .line 40
    .line 41
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 42
    .line 43
    if-ne v3, v1, :cond_3

    .line 44
    .line 45
    :cond_2
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    const/4 v3, 0x0

    .line 50
    invoke-static {v3, v3, v1, p2}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 51
    .line 52
    .line 53
    move-result-object v3

    .line 54
    invoke-virtual {p1, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    :cond_3
    move-object v1, v3

    .line 58
    check-cast v1, Lc1/f1;

    .line 59
    .line 60
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 61
    .line 62
    .line 63
    move-object v4, v1

    .line 64
    goto :goto_0

    .line 65
    :cond_4
    move-object v1, p3

    .line 66
    check-cast v1, Ll2/t;

    .line 67
    .line 68
    const v3, 0x44336485

    .line 69
    .line 70
    .line 71
    invoke-virtual {v1, v3}, Ll2/t;->Y(I)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {v1, v0}, Ll2/t;->q(Z)V

    .line 75
    .line 76
    .line 77
    move-object v4, p1

    .line 78
    :goto_0
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    sget-object v3, Lc1/d;->j:Lc1/b2;

    .line 83
    .line 84
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 85
    .line 86
    .line 87
    move-result-object v5

    .line 88
    shl-int/lit8 p1, p4, 0x3

    .line 89
    .line 90
    const p2, 0xe000

    .line 91
    .line 92
    .line 93
    and-int v9, p1, p2

    .line 94
    .line 95
    const/4 v10, 0x0

    .line 96
    const/4 v7, 0x0

    .line 97
    move-object v2, p0

    .line 98
    move-object v8, p3

    .line 99
    invoke-static/range {v2 .. v10}, Lc1/e;->c(Ljava/lang/Object;Lc1/b2;Lc1/j;Ljava/lang/Float;Ljava/lang/String;Lay0/k;Ll2/o;II)Ll2/t2;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    return-object p0
.end method

.method public static final c(Ljava/lang/Object;Lc1/b2;Lc1/j;Ljava/lang/Float;Ljava/lang/String;Lay0/k;Ll2/o;II)Ll2/t2;
    .locals 11

    .line 1
    and-int/lit8 p4, p8, 0x8

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    if-eqz p4, :cond_0

    .line 5
    .line 6
    move-object p3, v0

    .line 7
    :cond_0
    move-object/from16 p4, p6

    .line 8
    .line 9
    check-cast p4, Ll2/t;

    .line 10
    .line 11
    invoke-virtual {p4}, Ll2/t;->L()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 16
    .line 17
    if-ne v1, v2, :cond_1

    .line 18
    .line 19
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    invoke-virtual {p4, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    :cond_1
    check-cast v1, Ll2/b1;

    .line 27
    .line 28
    invoke-virtual {p4}, Ll2/t;->L()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v3

    .line 32
    if-ne v3, v2, :cond_2

    .line 33
    .line 34
    new-instance v3, Lc1/c;

    .line 35
    .line 36
    invoke-direct {v3, p0, p1, p3}, Lc1/c;-><init>(Ljava/lang/Object;Lc1/b2;Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p4, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    :cond_2
    move-object v6, v3

    .line 43
    check-cast v6, Lc1/c;

    .line 44
    .line 45
    move-object/from16 p1, p5

    .line 46
    .line 47
    invoke-static {p1, p4}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 48
    .line 49
    .line 50
    move-result-object v8

    .line 51
    if-eqz p3, :cond_3

    .line 52
    .line 53
    instance-of p1, p2, Lc1/f1;

    .line 54
    .line 55
    if-eqz p1, :cond_3

    .line 56
    .line 57
    move-object p1, p2

    .line 58
    check-cast p1, Lc1/f1;

    .line 59
    .line 60
    iget-object v3, p1, Lc1/f1;->c:Ljava/lang/Object;

    .line 61
    .line 62
    invoke-static {v3, p3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result v3

    .line 66
    if-nez v3, :cond_3

    .line 67
    .line 68
    iget p2, p1, Lc1/f1;->a:F

    .line 69
    .line 70
    iget p1, p1, Lc1/f1;->b:F

    .line 71
    .line 72
    new-instance v3, Lc1/f1;

    .line 73
    .line 74
    invoke-direct {v3, p2, p1, p3}, Lc1/f1;-><init>(FFLjava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    move-object p2, v3

    .line 78
    :cond_3
    invoke-static {p2, p4}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 79
    .line 80
    .line 81
    move-result-object v7

    .line 82
    invoke-virtual {p4}, Ll2/t;->L()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    if-ne p1, v2, :cond_4

    .line 87
    .line 88
    const/4 p1, -0x1

    .line 89
    const/4 p2, 0x6

    .line 90
    invoke-static {p1, p2, v0}, Llp/jf;->a(IILxy0/a;)Lxy0/j;

    .line 91
    .line 92
    .line 93
    move-result-object p1

    .line 94
    invoke-virtual {p4, p1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    :cond_4
    move-object v5, p1

    .line 98
    check-cast v5, Lxy0/n;

    .line 99
    .line 100
    invoke-virtual {p4, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    move-result p1

    .line 104
    invoke-virtual {p4, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    move-result p2

    .line 108
    or-int/2addr p1, p2

    .line 109
    invoke-virtual {p4}, Ll2/t;->L()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object p2

    .line 113
    if-nez p1, :cond_5

    .line 114
    .line 115
    if-ne p2, v2, :cond_6

    .line 116
    .line 117
    :cond_5
    new-instance p2, Laa/k;

    .line 118
    .line 119
    const/16 p1, 0xc

    .line 120
    .line 121
    invoke-direct {p2, p1, v5, p0}, Laa/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {p4, p2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 125
    .line 126
    .line 127
    :cond_6
    check-cast p2, Lay0/a;

    .line 128
    .line 129
    invoke-static {p2, p4}, Ll2/l0;->g(Lay0/a;Ll2/o;)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {p4, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    move-result p0

    .line 136
    invoke-virtual {p4, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    move-result p1

    .line 140
    or-int/2addr p0, p1

    .line 141
    invoke-virtual {p4, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 142
    .line 143
    .line 144
    move-result p1

    .line 145
    or-int/2addr p0, p1

    .line 146
    invoke-virtual {p4, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 147
    .line 148
    .line 149
    move-result p1

    .line 150
    or-int/2addr p0, p1

    .line 151
    invoke-virtual {p4}, Ll2/t;->L()Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object p1

    .line 155
    if-nez p0, :cond_7

    .line 156
    .line 157
    if-ne p1, v2, :cond_8

    .line 158
    .line 159
    :cond_7
    new-instance v4, La7/k0;

    .line 160
    .line 161
    const/4 v9, 0x0

    .line 162
    const/4 v10, 0x2

    .line 163
    invoke-direct/range {v4 .. v10}, La7/k0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 164
    .line 165
    .line 166
    invoke-virtual {p4, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 167
    .line 168
    .line 169
    move-object p1, v4

    .line 170
    :cond_8
    check-cast p1, Lay0/n;

    .line 171
    .line 172
    invoke-static {p1, v5, p4}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 173
    .line 174
    .line 175
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    move-result-object p0

    .line 179
    check-cast p0, Ll2/t2;

    .line 180
    .line 181
    if-nez p0, :cond_9

    .line 182
    .line 183
    iget-object p0, v6, Lc1/c;->c:Lc1/k;

    .line 184
    .line 185
    :cond_9
    return-object p0
.end method
