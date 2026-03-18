.class public final Lc3/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Comparator;


# static fields
.field public static final d:Lc3/w;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lc3/w;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lc3/w;->d:Lc3/w;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final compare(Ljava/lang/Object;Ljava/lang/Object;)I
    .locals 7

    .line 1
    check-cast p1, Lc3/v;

    .line 2
    .line 3
    check-cast p2, Lc3/v;

    .line 4
    .line 5
    invoke-static {p1}, Lc3/f;->r(Lc3/v;)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    const/4 v0, 0x0

    .line 10
    const/4 v1, 0x1

    .line 11
    if-eqz p0, :cond_a

    .line 12
    .line 13
    invoke-static {p2}, Lc3/f;->r(Lc3/v;)Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    if-nez p0, :cond_0

    .line 18
    .line 19
    goto/16 :goto_3

    .line 20
    .line 21
    :cond_0
    invoke-static {p1}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-static {p2}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result p2

    .line 33
    if-eqz p2, :cond_1

    .line 34
    .line 35
    goto/16 :goto_4

    .line 36
    .line 37
    :cond_1
    const/16 p2, 0x10

    .line 38
    .line 39
    new-array v2, p2, [Lv3/h0;

    .line 40
    .line 41
    move v3, v0

    .line 42
    :goto_0
    if-eqz p0, :cond_4

    .line 43
    .line 44
    add-int/lit8 v4, v3, 0x1

    .line 45
    .line 46
    array-length v5, v2

    .line 47
    if-ge v5, v4, :cond_2

    .line 48
    .line 49
    array-length v5, v2

    .line 50
    mul-int/lit8 v6, v5, 0x2

    .line 51
    .line 52
    invoke-static {v4, v6}, Ljava/lang/Math;->max(II)I

    .line 53
    .line 54
    .line 55
    move-result v4

    .line 56
    new-array v4, v4, [Ljava/lang/Object;

    .line 57
    .line 58
    invoke-static {v2, v0, v4, v0, v5}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 59
    .line 60
    .line 61
    move-object v2, v4

    .line 62
    :cond_2
    if-eqz v3, :cond_3

    .line 63
    .line 64
    const/4 v4, 0x0

    .line 65
    add-int/2addr v4, v1

    .line 66
    add-int/lit8 v5, v3, 0x0

    .line 67
    .line 68
    invoke-static {v2, v0, v2, v4, v5}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 69
    .line 70
    .line 71
    :cond_3
    aput-object p0, v2, v0

    .line 72
    .line 73
    add-int/lit8 v3, v3, 0x1

    .line 74
    .line 75
    invoke-virtual {p0}, Lv3/h0;->v()Lv3/h0;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    goto :goto_0

    .line 80
    :cond_4
    new-array p0, p2, [Lv3/h0;

    .line 81
    .line 82
    move p2, v0

    .line 83
    :goto_1
    if-eqz p1, :cond_7

    .line 84
    .line 85
    add-int/lit8 v4, p2, 0x1

    .line 86
    .line 87
    array-length v5, p0

    .line 88
    if-ge v5, v4, :cond_5

    .line 89
    .line 90
    array-length v5, p0

    .line 91
    mul-int/lit8 v6, v5, 0x2

    .line 92
    .line 93
    invoke-static {v4, v6}, Ljava/lang/Math;->max(II)I

    .line 94
    .line 95
    .line 96
    move-result v4

    .line 97
    new-array v4, v4, [Ljava/lang/Object;

    .line 98
    .line 99
    invoke-static {p0, v0, v4, v0, v5}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 100
    .line 101
    .line 102
    move-object p0, v4

    .line 103
    :cond_5
    if-eqz p2, :cond_6

    .line 104
    .line 105
    const/4 v4, 0x0

    .line 106
    add-int/2addr v4, v1

    .line 107
    add-int/lit8 v5, p2, 0x0

    .line 108
    .line 109
    invoke-static {p0, v0, p0, v4, v5}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 110
    .line 111
    .line 112
    :cond_6
    aput-object p1, p0, v0

    .line 113
    .line 114
    add-int/lit8 p2, p2, 0x1

    .line 115
    .line 116
    invoke-virtual {p1}, Lv3/h0;->v()Lv3/h0;

    .line 117
    .line 118
    .line 119
    move-result-object p1

    .line 120
    goto :goto_1

    .line 121
    :cond_7
    sub-int/2addr v3, v1

    .line 122
    sub-int/2addr p2, v1

    .line 123
    invoke-static {v3, p2}, Ljava/lang/Math;->min(II)I

    .line 124
    .line 125
    .line 126
    move-result p1

    .line 127
    if-ltz p1, :cond_9

    .line 128
    .line 129
    :goto_2
    aget-object p2, v2, v0

    .line 130
    .line 131
    aget-object v1, p0, v0

    .line 132
    .line 133
    invoke-static {p2, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 134
    .line 135
    .line 136
    move-result p2

    .line 137
    if-nez p2, :cond_8

    .line 138
    .line 139
    aget-object p1, v2, v0

    .line 140
    .line 141
    check-cast p1, Lv3/h0;

    .line 142
    .line 143
    invoke-virtual {p1}, Lv3/h0;->w()I

    .line 144
    .line 145
    .line 146
    move-result p1

    .line 147
    aget-object p0, p0, v0

    .line 148
    .line 149
    check-cast p0, Lv3/h0;

    .line 150
    .line 151
    invoke-virtual {p0}, Lv3/h0;->w()I

    .line 152
    .line 153
    .line 154
    move-result p0

    .line 155
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->g(II)I

    .line 156
    .line 157
    .line 158
    move-result p0

    .line 159
    return p0

    .line 160
    :cond_8
    if-eq v0, p1, :cond_9

    .line 161
    .line 162
    add-int/lit8 v0, v0, 0x1

    .line 163
    .line 164
    goto :goto_2

    .line 165
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 166
    .line 167
    const-string p1, "Could not find a common ancestor between the two FocusModifiers."

    .line 168
    .line 169
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 170
    .line 171
    .line 172
    throw p0

    .line 173
    :cond_a
    :goto_3
    invoke-static {p1}, Lc3/f;->r(Lc3/v;)Z

    .line 174
    .line 175
    .line 176
    move-result p0

    .line 177
    if-eqz p0, :cond_b

    .line 178
    .line 179
    const/4 p0, -0x1

    .line 180
    return p0

    .line 181
    :cond_b
    invoke-static {p2}, Lc3/f;->r(Lc3/v;)Z

    .line 182
    .line 183
    .line 184
    move-result p0

    .line 185
    if-eqz p0, :cond_c

    .line 186
    .line 187
    return v1

    .line 188
    :cond_c
    :goto_4
    return v0
.end method
