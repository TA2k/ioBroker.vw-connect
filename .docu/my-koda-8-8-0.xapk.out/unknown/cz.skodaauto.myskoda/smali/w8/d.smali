.class public abstract Lw8/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:[Ljava/lang/String;

.field public static final b:[Ljava/lang/String;

.field public static final c:[Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    const-string v0, "Camera:MicroVideo"

    .line 2
    .line 3
    const-string v1, "GCamera:MicroVideo"

    .line 4
    .line 5
    const-string v2, "Camera:MotionPhoto"

    .line 6
    .line 7
    const-string v3, "GCamera:MotionPhoto"

    .line 8
    .line 9
    filled-new-array {v2, v3, v0, v1}, [Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    sput-object v0, Lw8/d;->a:[Ljava/lang/String;

    .line 14
    .line 15
    const-string v0, "Camera:MicroVideoPresentationTimestampUs"

    .line 16
    .line 17
    const-string v1, "GCamera:MicroVideoPresentationTimestampUs"

    .line 18
    .line 19
    const-string v2, "Camera:MotionPhotoPresentationTimestampUs"

    .line 20
    .line 21
    const-string v3, "GCamera:MotionPhotoPresentationTimestampUs"

    .line 22
    .line 23
    filled-new-array {v2, v3, v0, v1}, [Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    sput-object v0, Lw8/d;->b:[Ljava/lang/String;

    .line 28
    .line 29
    const-string v0, "Camera:MicroVideoOffset"

    .line 30
    .line 31
    const-string v1, "GCamera:MicroVideoOffset"

    .line 32
    .line 33
    filled-new-array {v0, v1}, [Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    sput-object v0, Lw8/d;->c:[Ljava/lang/String;

    .line 38
    .line 39
    return-void
.end method

.method public static a(Ljava/lang/String;)Lg1/i3;
    .locals 18

    .line 1
    invoke-static {}, Lorg/xmlpull/v1/XmlPullParserFactory;->newInstance()Lorg/xmlpull/v1/XmlPullParserFactory;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Lorg/xmlpull/v1/XmlPullParserFactory;->newPullParser()Lorg/xmlpull/v1/XmlPullParser;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    new-instance v1, Ljava/io/StringReader;

    .line 10
    .line 11
    move-object/from16 v2, p0

    .line 12
    .line 13
    invoke-direct {v1, v2}, Ljava/io/StringReader;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-interface {v0, v1}, Lorg/xmlpull/v1/XmlPullParser;->setInput(Ljava/io/Reader;)V

    .line 17
    .line 18
    .line 19
    invoke-interface {v0}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    .line 20
    .line 21
    .line 22
    const-string v1, "x:xmpmeta"

    .line 23
    .line 24
    invoke-static {v0, v1}, Lw7/a;->v(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Z

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    const/4 v3, 0x0

    .line 29
    if-eqz v2, :cond_c

    .line 30
    .line 31
    sget-object v2, Lhr/h0;->e:Lhr/f0;

    .line 32
    .line 33
    sget-object v2, Lhr/x0;->h:Lhr/x0;

    .line 34
    .line 35
    const-wide v4, -0x7fffffffffffffffL    # -4.9E-324

    .line 36
    .line 37
    .line 38
    .line 39
    .line 40
    move-wide v6, v4

    .line 41
    :cond_0
    invoke-interface {v0}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    .line 42
    .line 43
    .line 44
    const-string v8, "rdf:Description"

    .line 45
    .line 46
    invoke-static {v0, v8}, Lw7/a;->v(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Z

    .line 47
    .line 48
    .line 49
    move-result v8

    .line 50
    if-eqz v8, :cond_7

    .line 51
    .line 52
    const/4 v2, 0x0

    .line 53
    move v6, v2

    .line 54
    :goto_0
    const/4 v7, 0x4

    .line 55
    if-ge v6, v7, :cond_a

    .line 56
    .line 57
    sget-object v8, Lw8/d;->a:[Ljava/lang/String;

    .line 58
    .line 59
    aget-object v8, v8, v6

    .line 60
    .line 61
    invoke-static {v0, v8}, Lw7/a;->r(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v8

    .line 65
    if-eqz v8, :cond_6

    .line 66
    .line 67
    invoke-static {v8}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 68
    .line 69
    .line 70
    move-result v6

    .line 71
    const/4 v8, 0x1

    .line 72
    if-ne v6, v8, :cond_a

    .line 73
    .line 74
    move v6, v2

    .line 75
    :goto_1
    if-ge v6, v7, :cond_1

    .line 76
    .line 77
    sget-object v8, Lw8/d;->b:[Ljava/lang/String;

    .line 78
    .line 79
    aget-object v8, v8, v6

    .line 80
    .line 81
    invoke-static {v0, v8}, Lw7/a;->r(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v8

    .line 85
    if-eqz v8, :cond_2

    .line 86
    .line 87
    invoke-static {v8}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 88
    .line 89
    .line 90
    move-result-wide v6

    .line 91
    const-wide/16 v8, -0x1

    .line 92
    .line 93
    cmp-long v8, v6, v8

    .line 94
    .line 95
    if-nez v8, :cond_3

    .line 96
    .line 97
    :cond_1
    move-wide v6, v4

    .line 98
    goto :goto_2

    .line 99
    :cond_2
    add-int/lit8 v6, v6, 0x1

    .line 100
    .line 101
    goto :goto_1

    .line 102
    :cond_3
    :goto_2
    const/4 v8, 0x2

    .line 103
    if-ge v2, v8, :cond_5

    .line 104
    .line 105
    sget-object v8, Lw8/d;->c:[Ljava/lang/String;

    .line 106
    .line 107
    aget-object v8, v8, v2

    .line 108
    .line 109
    invoke-static {v0, v8}, Lw7/a;->r(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Ljava/lang/String;

    .line 110
    .line 111
    .line 112
    move-result-object v8

    .line 113
    if-eqz v8, :cond_4

    .line 114
    .line 115
    invoke-static {v8}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 116
    .line 117
    .line 118
    move-result-wide v10

    .line 119
    new-instance v12, Lw8/b;

    .line 120
    .line 121
    const-wide/16 v13, 0x0

    .line 122
    .line 123
    const-wide/16 v16, 0x0

    .line 124
    .line 125
    const-string v15, "image/jpeg"

    .line 126
    .line 127
    invoke-direct/range {v12 .. v17}, Lw8/b;-><init>(JLjava/lang/String;J)V

    .line 128
    .line 129
    .line 130
    move-object v2, v12

    .line 131
    new-instance v9, Lw8/b;

    .line 132
    .line 133
    const-string v12, "video/mp4"

    .line 134
    .line 135
    invoke-direct/range {v9 .. v14}, Lw8/b;-><init>(JLjava/lang/String;J)V

    .line 136
    .line 137
    .line 138
    invoke-static {v2, v9}, Lhr/h0;->v(Ljava/lang/Object;Ljava/lang/Object;)Lhr/x0;

    .line 139
    .line 140
    .line 141
    move-result-object v2

    .line 142
    goto :goto_3

    .line 143
    :cond_4
    add-int/lit8 v2, v2, 0x1

    .line 144
    .line 145
    goto :goto_2

    .line 146
    :cond_5
    sget-object v2, Lhr/h0;->e:Lhr/f0;

    .line 147
    .line 148
    sget-object v2, Lhr/x0;->h:Lhr/x0;

    .line 149
    .line 150
    goto :goto_3

    .line 151
    :cond_6
    add-int/lit8 v6, v6, 0x1

    .line 152
    .line 153
    goto :goto_0

    .line 154
    :cond_7
    const-string v8, "Container:Directory"

    .line 155
    .line 156
    invoke-static {v0, v8}, Lw7/a;->v(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Z

    .line 157
    .line 158
    .line 159
    move-result v8

    .line 160
    if-eqz v8, :cond_8

    .line 161
    .line 162
    const-string v2, "Container"

    .line 163
    .line 164
    const-string v8, "Item"

    .line 165
    .line 166
    invoke-static {v0, v2, v8}, Lw8/d;->b(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;Ljava/lang/String;)Lhr/x0;

    .line 167
    .line 168
    .line 169
    move-result-object v2

    .line 170
    goto :goto_3

    .line 171
    :cond_8
    const-string v8, "GContainer:Directory"

    .line 172
    .line 173
    invoke-static {v0, v8}, Lw7/a;->v(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Z

    .line 174
    .line 175
    .line 176
    move-result v8

    .line 177
    if-eqz v8, :cond_9

    .line 178
    .line 179
    const-string v2, "GContainer"

    .line 180
    .line 181
    const-string v8, "GContainerItem"

    .line 182
    .line 183
    invoke-static {v0, v2, v8}, Lw8/d;->b(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;Ljava/lang/String;)Lhr/x0;

    .line 184
    .line 185
    .line 186
    move-result-object v2

    .line 187
    :cond_9
    :goto_3
    invoke-static {v0, v1}, Lw7/a;->t(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Z

    .line 188
    .line 189
    .line 190
    move-result v8

    .line 191
    if-eqz v8, :cond_0

    .line 192
    .line 193
    invoke-virtual {v2}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 194
    .line 195
    .line 196
    move-result v0

    .line 197
    if-eqz v0, :cond_b

    .line 198
    .line 199
    :cond_a
    return-object v3

    .line 200
    :cond_b
    new-instance v0, Lg1/i3;

    .line 201
    .line 202
    const/4 v1, 0x7

    .line 203
    invoke-direct {v0, v6, v7, v2, v1}, Lg1/i3;-><init>(JLjava/lang/Object;I)V

    .line 204
    .line 205
    .line 206
    return-object v0

    .line 207
    :cond_c
    const-string v0, "Couldn\'t find xmp metadata"

    .line 208
    .line 209
    invoke-static {v3, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 210
    .line 211
    .line 212
    move-result-object v0

    .line 213
    throw v0
.end method

.method public static b(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;Ljava/lang/String;)Lhr/x0;
    .locals 12

    .line 1
    invoke-static {}, Lhr/h0;->o()Lhr/e0;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const-string v1, ":Item"

    .line 6
    .line 7
    invoke-virtual {p1, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    const-string v2, ":Directory"

    .line 12
    .line 13
    invoke-virtual {p1, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    :cond_0
    invoke-interface {p0}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    .line 18
    .line 19
    .line 20
    invoke-static {p0, v1}, Lw7/a;->v(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    if-eqz v2, :cond_5

    .line 25
    .line 26
    const-string v2, ":Mime"

    .line 27
    .line 28
    invoke-virtual {p2, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    const-string v3, ":Semantic"

    .line 33
    .line 34
    invoke-virtual {p2, v3}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v3

    .line 38
    const-string v4, ":Length"

    .line 39
    .line 40
    invoke-virtual {p2, v4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v4

    .line 44
    const-string v5, ":Padding"

    .line 45
    .line 46
    invoke-virtual {p2, v5}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v5

    .line 50
    invoke-static {p0, v2}, Lw7/a;->r(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v9

    .line 54
    invoke-static {p0, v3}, Lw7/a;->r(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    invoke-static {p0, v4}, Lw7/a;->r(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object v3

    .line 62
    invoke-static {p0, v5}, Lw7/a;->r(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v4

    .line 66
    if-eqz v9, :cond_4

    .line 67
    .line 68
    if-nez v2, :cond_1

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_1
    new-instance v6, Lw8/b;

    .line 72
    .line 73
    const-wide/16 v7, 0x0

    .line 74
    .line 75
    if-eqz v3, :cond_2

    .line 76
    .line 77
    invoke-static {v3}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 78
    .line 79
    .line 80
    move-result-wide v2

    .line 81
    goto :goto_0

    .line 82
    :cond_2
    move-wide v2, v7

    .line 83
    :goto_0
    if-eqz v4, :cond_3

    .line 84
    .line 85
    invoke-static {v4}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 86
    .line 87
    .line 88
    move-result-wide v7

    .line 89
    :cond_3
    move-wide v10, v7

    .line 90
    move-wide v7, v2

    .line 91
    invoke-direct/range {v6 .. v11}, Lw8/b;-><init>(JLjava/lang/String;J)V

    .line 92
    .line 93
    .line 94
    invoke-virtual {v0, v6}, Lhr/b0;->a(Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    goto :goto_2

    .line 98
    :cond_4
    :goto_1
    sget-object p0, Lhr/x0;->h:Lhr/x0;

    .line 99
    .line 100
    return-object p0

    .line 101
    :cond_5
    :goto_2
    invoke-static {p0, p1}, Lw7/a;->t(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Z

    .line 102
    .line 103
    .line 104
    move-result v2

    .line 105
    if-eqz v2, :cond_0

    .line 106
    .line 107
    invoke-virtual {v0}, Lhr/e0;->i()Lhr/x0;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    return-object p0
.end method
