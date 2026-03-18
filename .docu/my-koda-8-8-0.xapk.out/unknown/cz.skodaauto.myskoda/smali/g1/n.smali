.class public final synthetic Lg1/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lg1/q;


# direct methods
.method public synthetic constructor <init>(Lg1/q;I)V
    .locals 0

    .line 1
    iput p2, p0, Lg1/n;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lg1/n;->e:Lg1/q;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lg1/n;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lg1/n;->e:Lg1/q;

    .line 7
    .line 8
    invoke-virtual {p0}, Lg1/q;->g()Lg1/z;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iget-object p0, p0, Lg1/q;->h:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Ll2/h0;

    .line 15
    .line 16
    invoke-virtual {p0}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    new-instance v1, Llx0/l;

    .line 21
    .line 22
    invoke-direct {v1, v0, p0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    return-object v1

    .line 26
    :pswitch_0
    iget-object p0, p0, Lg1/n;->e:Lg1/q;

    .line 27
    .line 28
    invoke-virtual {p0}, Lg1/q;->g()Lg1/z;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0

    .line 33
    :pswitch_1
    iget-object p0, p0, Lg1/n;->e:Lg1/q;

    .line 34
    .line 35
    invoke-virtual {p0}, Lg1/q;->g()Lg1/z;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    iget-object v1, p0, Lg1/q;->e:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v1, Ll2/j1;

    .line 42
    .line 43
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    invoke-virtual {v0, v1}, Lg1/z;->c(Ljava/lang/Object;)F

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    invoke-virtual {p0}, Lg1/q;->g()Lg1/z;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    iget-object v2, p0, Lg1/q;->h:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast v2, Ll2/h0;

    .line 58
    .line 59
    invoke-virtual {v2}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    invoke-virtual {v1, v2}, Lg1/z;->c(Ljava/lang/Object;)F

    .line 64
    .line 65
    .line 66
    move-result v1

    .line 67
    sub-float/2addr v1, v0

    .line 68
    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    .line 69
    .line 70
    .line 71
    move-result v2

    .line 72
    invoke-static {v2}, Ljava/lang/Float;->isNaN(F)Z

    .line 73
    .line 74
    .line 75
    move-result v3

    .line 76
    if-nez v3, :cond_1

    .line 77
    .line 78
    const v3, 0x358637bd    # 1.0E-6f

    .line 79
    .line 80
    .line 81
    cmpl-float v2, v2, v3

    .line 82
    .line 83
    if-lez v2, :cond_1

    .line 84
    .line 85
    invoke-virtual {p0}, Lg1/q;->k()F

    .line 86
    .line 87
    .line 88
    move-result p0

    .line 89
    sub-float/2addr p0, v0

    .line 90
    div-float/2addr p0, v1

    .line 91
    cmpg-float v0, p0, v3

    .line 92
    .line 93
    if-gez v0, :cond_0

    .line 94
    .line 95
    const/4 p0, 0x0

    .line 96
    goto :goto_0

    .line 97
    :cond_0
    const v0, 0x3f7fffef    # 0.999999f

    .line 98
    .line 99
    .line 100
    cmpl-float v0, p0, v0

    .line 101
    .line 102
    if-lez v0, :cond_2

    .line 103
    .line 104
    :cond_1
    const/high16 p0, 0x3f800000    # 1.0f

    .line 105
    .line 106
    :cond_2
    :goto_0
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    return-object p0

    .line 111
    :pswitch_2
    iget-object p0, p0, Lg1/n;->e:Lg1/q;

    .line 112
    .line 113
    iget-object v0, p0, Lg1/q;->i:Ljava/lang/Object;

    .line 114
    .line 115
    check-cast v0, Ll2/f1;

    .line 116
    .line 117
    iget-object v1, p0, Lg1/q;->f:Ljava/lang/Object;

    .line 118
    .line 119
    check-cast v1, Ll2/j1;

    .line 120
    .line 121
    iget-object v2, p0, Lg1/q;->d:Ljava/lang/Object;

    .line 122
    .line 123
    check-cast v2, Ll2/j1;

    .line 124
    .line 125
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v1

    .line 129
    if-nez v1, :cond_4

    .line 130
    .line 131
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 132
    .line 133
    .line 134
    move-result v1

    .line 135
    invoke-static {v1}, Ljava/lang/Float;->isNaN(F)Z

    .line 136
    .line 137
    .line 138
    move-result v1

    .line 139
    if-nez v1, :cond_3

    .line 140
    .line 141
    invoke-virtual {p0}, Lg1/q;->g()Lg1/z;

    .line 142
    .line 143
    .line 144
    move-result-object p0

    .line 145
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 146
    .line 147
    .line 148
    move-result v0

    .line 149
    invoke-virtual {p0, v0}, Lg1/z;->a(F)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object v1

    .line 153
    if-nez v1, :cond_4

    .line 154
    .line 155
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object v1

    .line 159
    goto :goto_1

    .line 160
    :cond_3
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object v1

    .line 164
    :cond_4
    :goto_1
    return-object v1

    .line 165
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
