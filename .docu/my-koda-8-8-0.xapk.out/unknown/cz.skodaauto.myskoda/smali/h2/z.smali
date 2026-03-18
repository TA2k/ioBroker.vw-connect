.class public final synthetic Lh2/z;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh2/r8;


# direct methods
.method public synthetic constructor <init>(Lh2/r8;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh2/z;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/z;->e:Lh2/r8;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Lh2/z;->d:I

    .line 2
    .line 3
    check-cast p1, Le3/k0;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lh2/z;->e:Lh2/r8;

    .line 9
    .line 10
    iget-object v0, p0, Lh2/r8;->e:Li2/p;

    .line 11
    .line 12
    iget-object v0, v0, Li2/p;->j:Ll2/f1;

    .line 13
    .line 14
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    iget-object p0, p0, Lh2/r8;->e:Li2/p;

    .line 19
    .line 20
    invoke-virtual {p0}, Li2/p;->d()Li2/u0;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-virtual {p0}, Li2/u0;->c()F

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    cmpg-float v1, v0, p0

    .line 29
    .line 30
    const/4 v2, 0x0

    .line 31
    if-gez v1, :cond_0

    .line 32
    .line 33
    sub-float/2addr p0, v0

    .line 34
    goto :goto_0

    .line 35
    :cond_0
    move p0, v2

    .line 36
    :goto_0
    cmpl-float v0, p0, v2

    .line 37
    .line 38
    if-lez v0, :cond_1

    .line 39
    .line 40
    iget-wide v0, p1, Le3/k0;->t:J

    .line 41
    .line 42
    const-wide v3, 0xffffffffL

    .line 43
    .line 44
    .line 45
    .line 46
    .line 47
    and-long/2addr v0, v3

    .line 48
    long-to-int v0, v0

    .line 49
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    add-float/2addr v0, p0

    .line 54
    iget-wide v5, p1, Le3/k0;->t:J

    .line 55
    .line 56
    and-long/2addr v3, v5

    .line 57
    long-to-int p0, v3

    .line 58
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 59
    .line 60
    .line 61
    move-result p0

    .line 62
    div-float/2addr v0, p0

    .line 63
    goto :goto_1

    .line 64
    :cond_1
    const/high16 v0, 0x3f800000    # 1.0f

    .line 65
    .line 66
    :goto_1
    invoke-virtual {p1, v0}, Le3/k0;->p(F)V

    .line 67
    .line 68
    .line 69
    const/high16 p0, 0x3f000000    # 0.5f

    .line 70
    .line 71
    invoke-static {p0, v2}, Le3/j0;->i(FF)J

    .line 72
    .line 73
    .line 74
    move-result-wide v0

    .line 75
    invoke-virtual {p1, v0, v1}, Le3/k0;->A(J)V

    .line 76
    .line 77
    .line 78
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 79
    .line 80
    return-object p0

    .line 81
    :pswitch_0
    iget-object p0, p0, Lh2/z;->e:Lh2/r8;

    .line 82
    .line 83
    iget-object v0, p0, Lh2/r8;->e:Li2/p;

    .line 84
    .line 85
    iget-object v0, v0, Li2/p;->j:Ll2/f1;

    .line 86
    .line 87
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 88
    .line 89
    .line 90
    move-result v0

    .line 91
    iget-object p0, p0, Lh2/r8;->e:Li2/p;

    .line 92
    .line 93
    invoke-virtual {p0}, Li2/p;->d()Li2/u0;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    invoke-virtual {p0}, Li2/u0;->c()F

    .line 98
    .line 99
    .line 100
    move-result p0

    .line 101
    cmpg-float v1, v0, p0

    .line 102
    .line 103
    const/4 v2, 0x0

    .line 104
    if-gez v1, :cond_2

    .line 105
    .line 106
    sub-float/2addr p0, v0

    .line 107
    goto :goto_3

    .line 108
    :cond_2
    move p0, v2

    .line 109
    :goto_3
    cmpl-float v0, p0, v2

    .line 110
    .line 111
    if-lez v0, :cond_3

    .line 112
    .line 113
    const/4 v0, 0x1

    .line 114
    int-to-float v0, v0

    .line 115
    iget-wide v3, p1, Le3/k0;->t:J

    .line 116
    .line 117
    const-wide v5, 0xffffffffL

    .line 118
    .line 119
    .line 120
    .line 121
    .line 122
    and-long/2addr v3, v5

    .line 123
    long-to-int v1, v3

    .line 124
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 125
    .line 126
    .line 127
    move-result v1

    .line 128
    add-float/2addr v1, p0

    .line 129
    iget-wide v3, p1, Le3/k0;->t:J

    .line 130
    .line 131
    and-long/2addr v3, v5

    .line 132
    long-to-int p0, v3

    .line 133
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 134
    .line 135
    .line 136
    move-result p0

    .line 137
    div-float/2addr v1, p0

    .line 138
    div-float/2addr v0, v1

    .line 139
    goto :goto_4

    .line 140
    :cond_3
    const/high16 v0, 0x3f800000    # 1.0f

    .line 141
    .line 142
    :goto_4
    invoke-virtual {p1, v0}, Le3/k0;->p(F)V

    .line 143
    .line 144
    .line 145
    const/high16 p0, 0x3f000000    # 0.5f

    .line 146
    .line 147
    invoke-static {p0, v2}, Le3/j0;->i(FF)J

    .line 148
    .line 149
    .line 150
    move-result-wide v0

    .line 151
    invoke-virtual {p1, v0, v1}, Le3/k0;->A(J)V

    .line 152
    .line 153
    .line 154
    goto :goto_2

    .line 155
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
