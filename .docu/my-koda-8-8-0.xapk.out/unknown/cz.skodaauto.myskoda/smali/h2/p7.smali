.class public final synthetic Lh2/p7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ll2/t2;

.field public final synthetic f:Ll2/t2;


# direct methods
.method public synthetic constructor <init>(Ll2/t2;Ll2/t2;I)V
    .locals 0

    .line 1
    iput p3, p0, Lh2/p7;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/p7;->e:Ll2/t2;

    .line 4
    .line 5
    iput-object p2, p0, Lh2/p7;->f:Ll2/t2;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget v0, p0, Lh2/p7;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Le3/k0;

    .line 7
    .line 8
    const-string v0, "$this$graphicsLayer"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object v0, p0, Lh2/p7;->e:Ll2/t2;

    .line 14
    .line 15
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    check-cast v0, Lt4/f;

    .line 20
    .line 21
    iget v0, v0, Lt4/f;->d:F

    .line 22
    .line 23
    iget-object v1, p1, Le3/k0;->u:Lt4/c;

    .line 24
    .line 25
    invoke-interface {v1}, Lt4/c;->a()F

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    mul-float/2addr v1, v0

    .line 30
    invoke-virtual {p1, v1}, Le3/k0;->D(F)V

    .line 31
    .line 32
    .line 33
    iget-object p0, p0, Lh2/p7;->f:Ll2/t2;

    .line 34
    .line 35
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    check-cast p0, Ljava/lang/Number;

    .line 40
    .line 41
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    invoke-virtual {p1, p0}, Le3/k0;->b(F)V

    .line 46
    .line 47
    .line 48
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_0
    check-cast p1, Le3/k0;

    .line 52
    .line 53
    const-string v0, "$this$graphicsLayer"

    .line 54
    .line 55
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    iget-object v0, p0, Lh2/p7;->e:Ll2/t2;

    .line 59
    .line 60
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    check-cast v0, Lt4/f;

    .line 65
    .line 66
    iget v0, v0, Lt4/f;->d:F

    .line 67
    .line 68
    iget-object v1, p1, Le3/k0;->u:Lt4/c;

    .line 69
    .line 70
    invoke-interface {v1}, Lt4/c;->a()F

    .line 71
    .line 72
    .line 73
    move-result v1

    .line 74
    mul-float/2addr v1, v0

    .line 75
    invoke-virtual {p1, v1}, Le3/k0;->D(F)V

    .line 76
    .line 77
    .line 78
    iget-object p0, p0, Lh2/p7;->f:Ll2/t2;

    .line 79
    .line 80
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    check-cast p0, Ljava/lang/Number;

    .line 85
    .line 86
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 87
    .line 88
    .line 89
    move-result p0

    .line 90
    invoke-virtual {p1, p0}, Le3/k0;->b(F)V

    .line 91
    .line 92
    .line 93
    goto :goto_0

    .line 94
    :pswitch_1
    move-object v0, p1

    .line 95
    check-cast v0, Lg3/d;

    .line 96
    .line 97
    sget p1, Lh2/r7;->c:F

    .line 98
    .line 99
    invoke-interface {v0, p1}, Lt4/c;->w0(F)F

    .line 100
    .line 101
    .line 102
    move-result v2

    .line 103
    iget-object p1, p0, Lh2/p7;->e:Ll2/t2;

    .line 104
    .line 105
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v1

    .line 109
    check-cast v1, Le3/s;

    .line 110
    .line 111
    iget-wide v8, v1, Le3/s;->a:J

    .line 112
    .line 113
    sget v1, Lk2/d0;->c:F

    .line 114
    .line 115
    const/4 v3, 0x2

    .line 116
    int-to-float v3, v3

    .line 117
    div-float/2addr v1, v3

    .line 118
    invoke-interface {v0, v1}, Lt4/c;->w0(F)F

    .line 119
    .line 120
    .line 121
    move-result v1

    .line 122
    div-float v10, v2, v3

    .line 123
    .line 124
    sub-float v11, v1, v10

    .line 125
    .line 126
    new-instance v1, Lg3/h;

    .line 127
    .line 128
    const/4 v6, 0x0

    .line 129
    const/16 v7, 0x1e

    .line 130
    .line 131
    const/4 v3, 0x0

    .line 132
    const/4 v4, 0x0

    .line 133
    const/4 v5, 0x0

    .line 134
    invoke-direct/range {v1 .. v7}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 135
    .line 136
    .line 137
    const/16 v7, 0x6c

    .line 138
    .line 139
    const-wide/16 v4, 0x0

    .line 140
    .line 141
    move-object v6, v1

    .line 142
    move-wide v1, v8

    .line 143
    move v3, v11

    .line 144
    invoke-static/range {v0 .. v7}, Lg3/d;->u0(Lg3/d;JFJLg3/e;I)V

    .line 145
    .line 146
    .line 147
    iget-object p0, p0, Lh2/p7;->f:Ll2/t2;

    .line 148
    .line 149
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object v1

    .line 153
    check-cast v1, Lt4/f;

    .line 154
    .line 155
    iget v1, v1, Lt4/f;->d:F

    .line 156
    .line 157
    const/4 v2, 0x0

    .line 158
    int-to-float v2, v2

    .line 159
    invoke-static {v1, v2}, Ljava/lang/Float;->compare(FF)I

    .line 160
    .line 161
    .line 162
    move-result v1

    .line 163
    if-lez v1, :cond_0

    .line 164
    .line 165
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object p1

    .line 169
    check-cast p1, Le3/s;

    .line 170
    .line 171
    iget-wide v1, p1, Le3/s;->a:J

    .line 172
    .line 173
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object p0

    .line 177
    check-cast p0, Lt4/f;

    .line 178
    .line 179
    iget p0, p0, Lt4/f;->d:F

    .line 180
    .line 181
    invoke-interface {v0, p0}, Lt4/c;->w0(F)F

    .line 182
    .line 183
    .line 184
    move-result p0

    .line 185
    sub-float v3, p0, v10

    .line 186
    .line 187
    sget-object v6, Lg3/g;->a:Lg3/g;

    .line 188
    .line 189
    const/16 v7, 0x6c

    .line 190
    .line 191
    const-wide/16 v4, 0x0

    .line 192
    .line 193
    invoke-static/range {v0 .. v7}, Lg3/d;->u0(Lg3/d;JFJLg3/e;I)V

    .line 194
    .line 195
    .line 196
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 197
    .line 198
    return-object p0

    .line 199
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
