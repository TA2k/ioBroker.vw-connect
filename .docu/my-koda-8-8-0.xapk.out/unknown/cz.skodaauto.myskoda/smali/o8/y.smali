.class public final Lo8/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll9/j;


# instance fields
.field public final d:Lw7/p;


# direct methods
.method public constructor <init>(I)V
    .locals 1

    .line 1
    packed-switch p1, :pswitch_data_0

    .line 2
    .line 3
    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    .line 6
    .line 7
    new-instance p1, Lw7/p;

    .line 8
    .line 9
    const/16 v0, 0xa

    .line 10
    .line 11
    invoke-direct {p1, v0}, Lw7/p;-><init>(I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lo8/y;->d:Lw7/p;

    .line 15
    .line 16
    return-void

    .line 17
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 18
    .line 19
    .line 20
    new-instance p1, Lw7/p;

    .line 21
    .line 22
    invoke-direct {p1}, Lw7/p;-><init>()V

    .line 23
    .line 24
    .line 25
    iput-object p1, p0, Lo8/y;->d:Lw7/p;

    .line 26
    .line 27
    return-void

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public g([BIILl9/i;Lw7/f;)V
    .locals 10

    .line 1
    add-int/2addr p3, p2

    .line 2
    iget-object p0, p0, Lo8/y;->d:Lw7/p;

    .line 3
    .line 4
    invoke-virtual {p0, p3, p1}, Lw7/p;->G(I[B)V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0, p2}, Lw7/p;->I(I)V

    .line 8
    .line 9
    .line 10
    new-instance v5, Ljava/util/ArrayList;

    .line 11
    .line 12
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 13
    .line 14
    .line 15
    :goto_0
    invoke-virtual {p0}, Lw7/p;->a()I

    .line 16
    .line 17
    .line 18
    move-result p1

    .line 19
    if-lez p1, :cond_8

    .line 20
    .line 21
    invoke-virtual {p0}, Lw7/p;->a()I

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    const/4 p2, 0x0

    .line 26
    const/4 p3, 0x1

    .line 27
    const/16 p4, 0x8

    .line 28
    .line 29
    if-lt p1, p4, :cond_0

    .line 30
    .line 31
    move p1, p3

    .line 32
    goto :goto_1

    .line 33
    :cond_0
    move p1, p2

    .line 34
    :goto_1
    const-string v0, "Incomplete Mp4Webvtt Top Level box header found."

    .line 35
    .line 36
    invoke-static {p1, v0}, Lw7/a;->d(ZLjava/lang/String;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p0}, Lw7/p;->j()I

    .line 40
    .line 41
    .line 42
    move-result p1

    .line 43
    invoke-virtual {p0}, Lw7/p;->j()I

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    const v1, 0x76747463

    .line 48
    .line 49
    .line 50
    if-ne v0, v1, :cond_7

    .line 51
    .line 52
    add-int/lit8 p1, p1, -0x8

    .line 53
    .line 54
    const/4 v0, 0x0

    .line 55
    move-object v1, v0

    .line 56
    move-object v2, v1

    .line 57
    :cond_1
    :goto_2
    if-lez p1, :cond_4

    .line 58
    .line 59
    if-lt p1, p4, :cond_2

    .line 60
    .line 61
    move v3, p3

    .line 62
    goto :goto_3

    .line 63
    :cond_2
    move v3, p2

    .line 64
    :goto_3
    const-string v4, "Incomplete vtt cue box header found."

    .line 65
    .line 66
    invoke-static {v3, v4}, Lw7/a;->d(ZLjava/lang/String;)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {p0}, Lw7/p;->j()I

    .line 70
    .line 71
    .line 72
    move-result v3

    .line 73
    invoke-virtual {p0}, Lw7/p;->j()I

    .line 74
    .line 75
    .line 76
    move-result v4

    .line 77
    add-int/lit8 p1, p1, -0x8

    .line 78
    .line 79
    sub-int/2addr v3, p4

    .line 80
    iget-object v6, p0, Lw7/p;->a:[B

    .line 81
    .line 82
    iget v7, p0, Lw7/p;->b:I

    .line 83
    .line 84
    sget-object v8, Lw7/w;->a:Ljava/lang/String;

    .line 85
    .line 86
    new-instance v8, Ljava/lang/String;

    .line 87
    .line 88
    sget-object v9, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 89
    .line 90
    invoke-direct {v8, v6, v7, v3, v9}, Ljava/lang/String;-><init>([BIILjava/nio/charset/Charset;)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {p0, v3}, Lw7/p;->J(I)V

    .line 94
    .line 95
    .line 96
    sub-int/2addr p1, v3

    .line 97
    const v3, 0x73747467

    .line 98
    .line 99
    .line 100
    if-ne v4, v3, :cond_3

    .line 101
    .line 102
    new-instance v2, Lu9/g;

    .line 103
    .line 104
    invoke-direct {v2}, Lu9/g;-><init>()V

    .line 105
    .line 106
    .line 107
    invoke-static {v8, v2}, Lu9/h;->e(Ljava/lang/String;Lu9/g;)V

    .line 108
    .line 109
    .line 110
    invoke-virtual {v2}, Lu9/g;->a()Lv7/a;

    .line 111
    .line 112
    .line 113
    move-result-object v2

    .line 114
    goto :goto_2

    .line 115
    :cond_3
    const v3, 0x7061796c

    .line 116
    .line 117
    .line 118
    if-ne v4, v3, :cond_1

    .line 119
    .line 120
    invoke-virtual {v8}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object v1

    .line 124
    sget-object v3, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 125
    .line 126
    invoke-static {v0, v1, v3}, Lu9/h;->f(Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)Landroid/text/SpannedString;

    .line 127
    .line 128
    .line 129
    move-result-object v1

    .line 130
    goto :goto_2

    .line 131
    :cond_4
    if-nez v1, :cond_5

    .line 132
    .line 133
    const-string v1, ""

    .line 134
    .line 135
    :cond_5
    if-eqz v2, :cond_6

    .line 136
    .line 137
    iput-object v1, v2, Lv7/a;->a:Ljava/lang/CharSequence;

    .line 138
    .line 139
    iput-object v0, v2, Lv7/a;->b:Landroid/graphics/Bitmap;

    .line 140
    .line 141
    invoke-virtual {v2}, Lv7/a;->a()Lv7/b;

    .line 142
    .line 143
    .line 144
    move-result-object p1

    .line 145
    goto :goto_4

    .line 146
    :cond_6
    sget-object p1, Lu9/h;->a:Ljava/util/regex/Pattern;

    .line 147
    .line 148
    new-instance p1, Lu9/g;

    .line 149
    .line 150
    invoke-direct {p1}, Lu9/g;-><init>()V

    .line 151
    .line 152
    .line 153
    iput-object v1, p1, Lu9/g;->c:Ljava/lang/CharSequence;

    .line 154
    .line 155
    invoke-virtual {p1}, Lu9/g;->a()Lv7/a;

    .line 156
    .line 157
    .line 158
    move-result-object p1

    .line 159
    invoke-virtual {p1}, Lv7/a;->a()Lv7/b;

    .line 160
    .line 161
    .line 162
    move-result-object p1

    .line 163
    :goto_4
    invoke-virtual {v5, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 164
    .line 165
    .line 166
    goto/16 :goto_0

    .line 167
    .line 168
    :cond_7
    add-int/lit8 p1, p1, -0x8

    .line 169
    .line 170
    invoke-virtual {p0, p1}, Lw7/p;->J(I)V

    .line 171
    .line 172
    .line 173
    goto/16 :goto_0

    .line 174
    .line 175
    :cond_8
    new-instance v0, Ll9/a;

    .line 176
    .line 177
    const-wide v1, -0x7fffffffffffffffL    # -4.9E-324

    .line 178
    .line 179
    .line 180
    .line 181
    .line 182
    const-wide v3, -0x7fffffffffffffffL    # -4.9E-324

    .line 183
    .line 184
    .line 185
    .line 186
    .line 187
    invoke-direct/range {v0 .. v5}, Ll9/a;-><init>(JJLjava/util/List;)V

    .line 188
    .line 189
    .line 190
    invoke-interface {p5, v0}, Lw7/f;->accept(Ljava/lang/Object;)V

    .line 191
    .line 192
    .line 193
    return-void
.end method
