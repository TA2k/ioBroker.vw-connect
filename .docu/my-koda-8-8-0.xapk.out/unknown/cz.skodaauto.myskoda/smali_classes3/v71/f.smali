.class public final Lv71/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lw71/c;

.field public final b:D

.field public final c:Lv71/e;

.field public final d:Lv71/g;

.field public final e:Lv71/g;

.field public final f:Lv71/g;

.field public final g:Lw71/c;


# direct methods
.method public constructor <init>(Lw71/c;DLv71/e;)V
    .locals 7

    .line 1
    const-string v0, "vehicleDimensions"

    .line 2
    .line 3
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lv71/f;->a:Lw71/c;

    .line 10
    .line 11
    iput-wide p2, p0, Lv71/f;->b:D

    .line 12
    .line 13
    iput-object p4, p0, Lv71/f;->c:Lv71/e;

    .line 14
    .line 15
    const-wide/high16 v0, 0x3ff0000000000000L    # 1.0

    .line 16
    .line 17
    invoke-static {p2, p3, v0, v1}, Lw71/d;->c(DD)Lw71/c;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    const/4 v1, 0x1

    .line 22
    invoke-virtual {p0, p2, p3, v1}, Lv71/f;->a(DZ)Lw71/c;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    const/4 v2, 0x0

    .line 27
    invoke-virtual {p0, p2, p3, v2}, Lv71/f;->a(DZ)Lw71/c;

    .line 28
    .line 29
    .line 30
    move-result-object v2

    .line 31
    const-wide v3, -0x4011eb851eb851ecL    # -0.94

    .line 32
    .line 33
    .line 34
    .line 35
    .line 36
    invoke-static {v0, v3, v4}, Lw71/d;->j(Lw71/c;D)Lw71/c;

    .line 37
    .line 38
    .line 39
    move-result-object v3

    .line 40
    invoke-static {p1, v3}, Lw71/d;->h(Lw71/c;Lw71/c;)Lw71/c;

    .line 41
    .line 42
    .line 43
    move-result-object v3

    .line 44
    const-wide v4, 0x400fd916872b020cL    # 3.981

    .line 45
    .line 46
    .line 47
    .line 48
    .line 49
    invoke-static {v0, v4, v5}, Lw71/d;->j(Lw71/c;D)Lw71/c;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    invoke-static {p1, v0}, Lw71/d;->h(Lw71/c;Lw71/c;)Lw71/c;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    new-instance v4, Lv71/g;

    .line 58
    .line 59
    invoke-static {v0, v1}, Lw71/d;->h(Lw71/c;Lw71/c;)Lw71/c;

    .line 60
    .line 61
    .line 62
    move-result-object v5

    .line 63
    const/16 v6, 0xa

    .line 64
    .line 65
    invoke-static {v5, v6}, Lw71/d;->i(Lw71/c;I)Lw71/c;

    .line 66
    .line 67
    .line 68
    move-result-object v5

    .line 69
    invoke-static {v0, v2}, Lw71/d;->h(Lw71/c;Lw71/c;)Lw71/c;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    invoke-static {v0, v6}, Lw71/d;->i(Lw71/c;I)Lw71/c;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    invoke-direct {v4, v5, v0}, Lv71/g;-><init>(Lw71/c;Lw71/c;)V

    .line 78
    .line 79
    .line 80
    iput-object v4, p0, Lv71/f;->d:Lv71/g;

    .line 81
    .line 82
    new-instance v0, Lv71/g;

    .line 83
    .line 84
    invoke-static {v3, v1}, Lw71/d;->h(Lw71/c;Lw71/c;)Lw71/c;

    .line 85
    .line 86
    .line 87
    move-result-object v4

    .line 88
    invoke-static {v4, v6}, Lw71/d;->i(Lw71/c;I)Lw71/c;

    .line 89
    .line 90
    .line 91
    move-result-object v4

    .line 92
    invoke-static {v3, v2}, Lw71/d;->h(Lw71/c;Lw71/c;)Lw71/c;

    .line 93
    .line 94
    .line 95
    move-result-object v3

    .line 96
    invoke-static {v3, v6}, Lw71/d;->i(Lw71/c;I)Lw71/c;

    .line 97
    .line 98
    .line 99
    move-result-object v3

    .line 100
    invoke-direct {v0, v4, v3}, Lv71/g;-><init>(Lw71/c;Lw71/c;)V

    .line 101
    .line 102
    .line 103
    iput-object v0, p0, Lv71/f;->e:Lv71/g;

    .line 104
    .line 105
    new-instance v0, Lv71/g;

    .line 106
    .line 107
    invoke-static {p1, v1}, Lw71/d;->h(Lw71/c;Lw71/c;)Lw71/c;

    .line 108
    .line 109
    .line 110
    move-result-object v1

    .line 111
    invoke-static {v1, v6}, Lw71/d;->i(Lw71/c;I)Lw71/c;

    .line 112
    .line 113
    .line 114
    move-result-object v1

    .line 115
    invoke-static {p1, v2}, Lw71/d;->h(Lw71/c;Lw71/c;)Lw71/c;

    .line 116
    .line 117
    .line 118
    move-result-object v2

    .line 119
    invoke-static {v2, v6}, Lw71/d;->i(Lw71/c;I)Lw71/c;

    .line 120
    .line 121
    .line 122
    move-result-object v2

    .line 123
    invoke-direct {v0, v1, v2}, Lv71/g;-><init>(Lw71/c;Lw71/c;)V

    .line 124
    .line 125
    .line 126
    iput-object v0, p0, Lv71/f;->f:Lv71/g;

    .line 127
    .line 128
    iget-wide v0, p4, Lv71/e;->a:D

    .line 129
    .line 130
    const/4 p4, 0x2

    .line 131
    int-to-double v2, p4

    .line 132
    div-double/2addr v0, v2

    .line 133
    const-wide v2, 0x3fee147ae147ae14L    # 0.94

    .line 134
    .line 135
    .line 136
    .line 137
    .line 138
    sub-double/2addr v0, v2

    .line 139
    invoke-static {v0, v1}, Ljava/lang/Math;->abs(D)D

    .line 140
    .line 141
    .line 142
    move-result-wide v0

    .line 143
    const-wide v2, 0x4062c00000000000L    # 150.0

    .line 144
    .line 145
    .line 146
    .line 147
    .line 148
    invoke-static {p2, p3, v2, v3}, Lw71/d;->c(DD)Lw71/c;

    .line 149
    .line 150
    .line 151
    move-result-object p2

    .line 152
    invoke-static {p1, p2}, Lw71/d;->h(Lw71/c;Lw71/c;)Lw71/c;

    .line 153
    .line 154
    .line 155
    move-result-object p2

    .line 156
    invoke-static {p1, p2}, Lw71/d;->f(Lw71/c;Lw71/c;)Lw71/c;

    .line 157
    .line 158
    .line 159
    move-result-object p3

    .line 160
    invoke-static {p2, p3}, Lmb/e;->o(Lw71/c;Lw71/c;)Lw71/a;

    .line 161
    .line 162
    .line 163
    move-result-object p2

    .line 164
    if-eqz p2, :cond_0

    .line 165
    .line 166
    invoke-virtual {p2}, Lw71/a;->a()D

    .line 167
    .line 168
    .line 169
    move-result-wide p2

    .line 170
    invoke-static {p2, p3, v0, v1}, Lw71/d;->c(DD)Lw71/c;

    .line 171
    .line 172
    .line 173
    move-result-object p2

    .line 174
    goto :goto_0

    .line 175
    :cond_0
    new-instance p2, Lw71/c;

    .line 176
    .line 177
    const-wide/16 p3, 0x0

    .line 178
    .line 179
    invoke-direct {p2, v0, v1, p3, p4}, Lw71/c;-><init>(DD)V

    .line 180
    .line 181
    .line 182
    :goto_0
    invoke-static {p1, p2}, Lw71/d;->f(Lw71/c;Lw71/c;)Lw71/c;

    .line 183
    .line 184
    .line 185
    move-result-object p1

    .line 186
    iput-object p1, p0, Lv71/f;->g:Lw71/c;

    .line 187
    .line 188
    invoke-static {p1, v6}, Lw71/d;->i(Lw71/c;I)Lw71/c;

    .line 189
    .line 190
    .line 191
    return-void
.end method


# virtual methods
.method public final a(DZ)Lw71/c;
    .locals 6

    .line 1
    if-eqz p3, :cond_0

    .line 2
    .line 3
    const-wide v0, 0x3ff921fb54442d18L    # 1.5707963267948966

    .line 4
    .line 5
    .line 6
    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    const-wide v0, -0x4006de04abbbd2e8L    # -1.5707963267948966

    .line 10
    .line 11
    .line 12
    .line 13
    .line 14
    :goto_0
    add-double/2addr p1, v0

    .line 15
    invoke-static {p1, p2}, Ljava/lang/Math;->cos(D)D

    .line 16
    .line 17
    .line 18
    move-result-wide v0

    .line 19
    invoke-static {p1, p2}, Ljava/lang/Math;->sin(D)D

    .line 20
    .line 21
    .line 22
    move-result-wide p1

    .line 23
    iget-object p0, p0, Lv71/f;->c:Lv71/e;

    .line 24
    .line 25
    iget-wide v2, p0, Lv71/e;->b:D

    .line 26
    .line 27
    const/4 p0, 0x2

    .line 28
    int-to-double v4, p0

    .line 29
    div-double/2addr v2, v4

    .line 30
    new-instance p0, Lw71/c;

    .line 31
    .line 32
    mul-double/2addr v0, v2

    .line 33
    mul-double/2addr p1, v2

    .line 34
    invoke-direct {p0, v0, v1, p1, p2}, Lw71/c;-><init>(DD)V

    .line 35
    .line 36
    .line 37
    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "["

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lv71/f;->e:Lv71/g;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", "

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v2, p0, Lv71/f;->f:Lv71/g;

    .line 19
    .line 20
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    iget-object p0, p0, Lv71/f;->d:Lv71/g;

    .line 27
    .line 28
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string p0, "]"

    .line 32
    .line 33
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0
.end method
