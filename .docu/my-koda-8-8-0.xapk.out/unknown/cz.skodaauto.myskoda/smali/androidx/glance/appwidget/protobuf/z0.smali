.class public final Landroidx/glance/appwidget/protobuf/z0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Ljava/lang/Object;)Landroidx/glance/appwidget/protobuf/y0;
    .locals 5

    .line 1
    check-cast p0, Landroidx/glance/appwidget/protobuf/u;

    .line 2
    .line 3
    iget-object v0, p0, Landroidx/glance/appwidget/protobuf/u;->unknownFields:Landroidx/glance/appwidget/protobuf/y0;

    .line 4
    .line 5
    sget-object v1, Landroidx/glance/appwidget/protobuf/y0;->f:Landroidx/glance/appwidget/protobuf/y0;

    .line 6
    .line 7
    if-ne v0, v1, :cond_0

    .line 8
    .line 9
    new-instance v0, Landroidx/glance/appwidget/protobuf/y0;

    .line 10
    .line 11
    const/16 v1, 0x8

    .line 12
    .line 13
    new-array v2, v1, [I

    .line 14
    .line 15
    new-array v1, v1, [Ljava/lang/Object;

    .line 16
    .line 17
    const/4 v3, 0x1

    .line 18
    const/4 v4, 0x0

    .line 19
    invoke-direct {v0, v4, v2, v1, v3}, Landroidx/glance/appwidget/protobuf/y0;-><init>(I[I[Ljava/lang/Object;Z)V

    .line 20
    .line 21
    .line 22
    iput-object v0, p0, Landroidx/glance/appwidget/protobuf/u;->unknownFields:Landroidx/glance/appwidget/protobuf/y0;

    .line 23
    .line 24
    :cond_0
    return-object v0
.end method

.method public static b(ILandroidx/collection/h;Ljava/lang/Object;)Z
    .locals 8

    .line 1
    iget v0, p1, Landroidx/collection/h;->e:I

    .line 2
    .line 3
    iget-object v1, p1, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Landroidx/datastore/preferences/protobuf/k;

    .line 6
    .line 7
    ushr-int/lit8 v2, v0, 0x3

    .line 8
    .line 9
    and-int/lit8 v0, v0, 0x7

    .line 10
    .line 11
    const/4 v3, 0x0

    .line 12
    const/4 v4, 0x1

    .line 13
    const/4 v5, 0x3

    .line 14
    if-eqz v0, :cond_a

    .line 15
    .line 16
    if-eq v0, v4, :cond_9

    .line 17
    .line 18
    const/4 v6, 0x2

    .line 19
    if-eq v0, v6, :cond_8

    .line 20
    .line 21
    if-eq v0, v5, :cond_2

    .line 22
    .line 23
    const/4 p0, 0x4

    .line 24
    if-eq v0, p0, :cond_1

    .line 25
    .line 26
    const/4 p0, 0x5

    .line 27
    if-ne v0, p0, :cond_0

    .line 28
    .line 29
    invoke-virtual {p1, p0}, Landroidx/collection/h;->J0(I)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v1}, Landroidx/datastore/preferences/protobuf/k;->r()I

    .line 33
    .line 34
    .line 35
    move-result p1

    .line 36
    check-cast p2, Landroidx/glance/appwidget/protobuf/y0;

    .line 37
    .line 38
    shl-int/lit8 v0, v2, 0x3

    .line 39
    .line 40
    or-int/2addr p0, v0

    .line 41
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    invoke-virtual {p2, p0, p1}, Landroidx/glance/appwidget/protobuf/y0;->c(ILjava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    return v4

    .line 49
    :cond_0
    invoke-static {}, Landroidx/glance/appwidget/protobuf/a0;->b()Landroidx/glance/appwidget/protobuf/z;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    throw p0

    .line 54
    :cond_1
    return v3

    .line 55
    :cond_2
    new-instance v0, Landroidx/glance/appwidget/protobuf/y0;

    .line 56
    .line 57
    const/16 v1, 0x8

    .line 58
    .line 59
    new-array v6, v1, [I

    .line 60
    .line 61
    new-array v1, v1, [Ljava/lang/Object;

    .line 62
    .line 63
    invoke-direct {v0, v3, v6, v1, v4}, Landroidx/glance/appwidget/protobuf/y0;-><init>(I[I[Ljava/lang/Object;Z)V

    .line 64
    .line 65
    .line 66
    shl-int/lit8 v1, v2, 0x3

    .line 67
    .line 68
    or-int/lit8 v2, v1, 0x4

    .line 69
    .line 70
    add-int/2addr p0, v4

    .line 71
    const/16 v6, 0x64

    .line 72
    .line 73
    if-ge p0, v6, :cond_7

    .line 74
    .line 75
    :cond_3
    invoke-virtual {p1}, Landroidx/collection/h;->e()I

    .line 76
    .line 77
    .line 78
    move-result v6

    .line 79
    const v7, 0x7fffffff

    .line 80
    .line 81
    .line 82
    if-eq v6, v7, :cond_4

    .line 83
    .line 84
    invoke-static {p0, p1, v0}, Landroidx/glance/appwidget/protobuf/z0;->b(ILandroidx/collection/h;Ljava/lang/Object;)Z

    .line 85
    .line 86
    .line 87
    move-result v6

    .line 88
    if-nez v6, :cond_3

    .line 89
    .line 90
    :cond_4
    iget p0, p1, Landroidx/collection/h;->e:I

    .line 91
    .line 92
    if-ne v2, p0, :cond_6

    .line 93
    .line 94
    iget-boolean p0, v0, Landroidx/glance/appwidget/protobuf/y0;->e:Z

    .line 95
    .line 96
    if-eqz p0, :cond_5

    .line 97
    .line 98
    iput-boolean v3, v0, Landroidx/glance/appwidget/protobuf/y0;->e:Z

    .line 99
    .line 100
    :cond_5
    check-cast p2, Landroidx/glance/appwidget/protobuf/y0;

    .line 101
    .line 102
    or-int/lit8 p0, v1, 0x3

    .line 103
    .line 104
    invoke-virtual {p2, p0, v0}, Landroidx/glance/appwidget/protobuf/y0;->c(ILjava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    return v4

    .line 108
    :cond_6
    new-instance p0, Landroidx/glance/appwidget/protobuf/a0;

    .line 109
    .line 110
    const-string p1, "Protocol message end-group tag did not match expected tag."

    .line 111
    .line 112
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    throw p0

    .line 116
    :cond_7
    new-instance p0, Landroidx/glance/appwidget/protobuf/a0;

    .line 117
    .line 118
    const-string p1, "Protocol message had too many levels of nesting.  May be malicious.  Use setRecursionLimit() to increase the recursion depth limit."

    .line 119
    .line 120
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    throw p0

    .line 124
    :cond_8
    invoke-virtual {p1}, Landroidx/collection/h;->r()Landroidx/glance/appwidget/protobuf/g;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    check-cast p2, Landroidx/glance/appwidget/protobuf/y0;

    .line 129
    .line 130
    shl-int/lit8 p1, v2, 0x3

    .line 131
    .line 132
    or-int/2addr p1, v6

    .line 133
    invoke-virtual {p2, p1, p0}, Landroidx/glance/appwidget/protobuf/y0;->c(ILjava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    return v4

    .line 137
    :cond_9
    invoke-virtual {p1, v4}, Landroidx/collection/h;->J0(I)V

    .line 138
    .line 139
    .line 140
    invoke-virtual {v1}, Landroidx/datastore/preferences/protobuf/k;->s()J

    .line 141
    .line 142
    .line 143
    move-result-wide p0

    .line 144
    check-cast p2, Landroidx/glance/appwidget/protobuf/y0;

    .line 145
    .line 146
    shl-int/lit8 v0, v2, 0x3

    .line 147
    .line 148
    or-int/2addr v0, v4

    .line 149
    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 150
    .line 151
    .line 152
    move-result-object p0

    .line 153
    invoke-virtual {p2, v0, p0}, Landroidx/glance/appwidget/protobuf/y0;->c(ILjava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    return v4

    .line 157
    :cond_a
    invoke-virtual {p1, v3}, Landroidx/collection/h;->J0(I)V

    .line 158
    .line 159
    .line 160
    invoke-virtual {v1}, Landroidx/datastore/preferences/protobuf/k;->v()J

    .line 161
    .line 162
    .line 163
    move-result-wide p0

    .line 164
    check-cast p2, Landroidx/glance/appwidget/protobuf/y0;

    .line 165
    .line 166
    shl-int/lit8 v0, v2, 0x3

    .line 167
    .line 168
    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 169
    .line 170
    .line 171
    move-result-object p0

    .line 172
    invoke-virtual {p2, v0, p0}, Landroidx/glance/appwidget/protobuf/y0;->c(ILjava/lang/Object;)V

    .line 173
    .line 174
    .line 175
    return v4
.end method
