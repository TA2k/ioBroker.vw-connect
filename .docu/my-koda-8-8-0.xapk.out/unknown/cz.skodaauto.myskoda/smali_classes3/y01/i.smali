.class public final Ly01/i;
.super Ly01/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final c:Ljava/util/EnumSet;


# instance fields
.field public final b:Ljava/util/EnumSet;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Ly01/h;->d:Ly01/h;

    .line 2
    .line 3
    invoke-static {v0}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {v0}, Ljava/util/EnumSet;->copyOf(Ljava/util/Collection;)Ljava/util/EnumSet;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Ly01/i;->c:Ljava/util/EnumSet;

    .line 12
    .line 13
    return-void
.end method

.method public varargs constructor <init>([Ly01/h;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Ljava/lang/reflect/Array;->getLength(Ljava/lang/Object;)I

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    sget-object p1, Ly01/i;->c:Ljava/util/EnumSet;

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    invoke-static {p1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    invoke-static {p1}, Ljava/util/EnumSet;->copyOf(Ljava/util/Collection;)Ljava/util/EnumSet;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    :goto_0
    iput-object p1, p0, Ly01/i;->b:Ljava/util/EnumSet;

    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;ILjava/io/StringWriter;)I
    .locals 7

    .line 1
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p1, p2}, Ljava/lang/String;->charAt(I)C

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const/16 v2, 0x26

    .line 10
    .line 11
    const/4 v3, 0x0

    .line 12
    if-ne v1, v2, :cond_d

    .line 13
    .line 14
    add-int/lit8 v1, v0, -0x2

    .line 15
    .line 16
    if-ge p2, v1, :cond_d

    .line 17
    .line 18
    add-int/lit8 v1, p2, 0x1

    .line 19
    .line 20
    invoke-virtual {p1, v1}, Ljava/lang/String;->charAt(I)C

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    const/16 v2, 0x23

    .line 25
    .line 26
    if-ne v1, v2, :cond_d

    .line 27
    .line 28
    add-int/lit8 v1, p2, 0x2

    .line 29
    .line 30
    invoke-virtual {p1, v1}, Ljava/lang/String;->charAt(I)C

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    const/16 v4, 0x78

    .line 35
    .line 36
    const/4 v5, 0x1

    .line 37
    if-eq v2, v4, :cond_1

    .line 38
    .line 39
    const/16 v4, 0x58

    .line 40
    .line 41
    if-ne v2, v4, :cond_0

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_0
    move p2, v3

    .line 45
    goto :goto_1

    .line 46
    :cond_1
    :goto_0
    add-int/lit8 v1, p2, 0x3

    .line 47
    .line 48
    if-ne v1, v0, :cond_2

    .line 49
    .line 50
    goto/16 :goto_7

    .line 51
    .line 52
    :cond_2
    move p2, v5

    .line 53
    :goto_1
    move v2, v1

    .line 54
    :goto_2
    if-ge v2, v0, :cond_6

    .line 55
    .line 56
    invoke-virtual {p1, v2}, Ljava/lang/String;->charAt(I)C

    .line 57
    .line 58
    .line 59
    move-result v4

    .line 60
    const/16 v6, 0x30

    .line 61
    .line 62
    if-lt v4, v6, :cond_3

    .line 63
    .line 64
    invoke-virtual {p1, v2}, Ljava/lang/String;->charAt(I)C

    .line 65
    .line 66
    .line 67
    move-result v4

    .line 68
    const/16 v6, 0x39

    .line 69
    .line 70
    if-le v4, v6, :cond_5

    .line 71
    .line 72
    :cond_3
    invoke-virtual {p1, v2}, Ljava/lang/String;->charAt(I)C

    .line 73
    .line 74
    .line 75
    move-result v4

    .line 76
    const/16 v6, 0x61

    .line 77
    .line 78
    if-lt v4, v6, :cond_4

    .line 79
    .line 80
    invoke-virtual {p1, v2}, Ljava/lang/String;->charAt(I)C

    .line 81
    .line 82
    .line 83
    move-result v4

    .line 84
    const/16 v6, 0x66

    .line 85
    .line 86
    if-le v4, v6, :cond_5

    .line 87
    .line 88
    :cond_4
    invoke-virtual {p1, v2}, Ljava/lang/String;->charAt(I)C

    .line 89
    .line 90
    .line 91
    move-result v4

    .line 92
    const/16 v6, 0x41

    .line 93
    .line 94
    if-lt v4, v6, :cond_6

    .line 95
    .line 96
    invoke-virtual {p1, v2}, Ljava/lang/String;->charAt(I)C

    .line 97
    .line 98
    .line 99
    move-result v4

    .line 100
    const/16 v6, 0x46

    .line 101
    .line 102
    if-gt v4, v6, :cond_6

    .line 103
    .line 104
    :cond_5
    add-int/lit8 v2, v2, 0x1

    .line 105
    .line 106
    goto :goto_2

    .line 107
    :cond_6
    if-eq v2, v0, :cond_7

    .line 108
    .line 109
    invoke-virtual {p1, v2}, Ljava/lang/String;->charAt(I)C

    .line 110
    .line 111
    .line 112
    move-result v0

    .line 113
    const/16 v4, 0x3b

    .line 114
    .line 115
    if-ne v0, v4, :cond_7

    .line 116
    .line 117
    move v0, v5

    .line 118
    goto :goto_3

    .line 119
    :cond_7
    move v0, v3

    .line 120
    :goto_3
    if-nez v0, :cond_a

    .line 121
    .line 122
    sget-object v4, Ly01/h;->d:Ly01/h;

    .line 123
    .line 124
    iget-object p0, p0, Ly01/i;->b:Ljava/util/EnumSet;

    .line 125
    .line 126
    invoke-virtual {p0, v4}, Ljava/util/AbstractCollection;->contains(Ljava/lang/Object;)Z

    .line 127
    .line 128
    .line 129
    move-result v4

    .line 130
    if-eqz v4, :cond_8

    .line 131
    .line 132
    goto :goto_7

    .line 133
    :cond_8
    sget-object v4, Ly01/h;->e:Ly01/h;

    .line 134
    .line 135
    invoke-virtual {p0, v4}, Ljava/util/AbstractCollection;->contains(Ljava/lang/Object;)Z

    .line 136
    .line 137
    .line 138
    move-result p0

    .line 139
    if-nez p0, :cond_9

    .line 140
    .line 141
    goto :goto_4

    .line 142
    :cond_9
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 143
    .line 144
    const-string p1, "Semi-colon required at end of numeric entity"

    .line 145
    .line 146
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 147
    .line 148
    .line 149
    throw p0

    .line 150
    :cond_a
    :goto_4
    if-eqz p2, :cond_b

    .line 151
    .line 152
    :try_start_0
    invoke-virtual {p1, v1, v2}, Ljava/lang/String;->subSequence(II)Ljava/lang/CharSequence;

    .line 153
    .line 154
    .line 155
    move-result-object p0

    .line 156
    invoke-interface {p0}, Ljava/lang/CharSequence;->toString()Ljava/lang/String;

    .line 157
    .line 158
    .line 159
    move-result-object p0

    .line 160
    const/16 p1, 0x10

    .line 161
    .line 162
    invoke-static {p0, p1}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;I)I

    .line 163
    .line 164
    .line 165
    move-result p0

    .line 166
    goto :goto_5

    .line 167
    :cond_b
    invoke-virtual {p1, v1, v2}, Ljava/lang/String;->subSequence(II)Ljava/lang/CharSequence;

    .line 168
    .line 169
    .line 170
    move-result-object p0

    .line 171
    invoke-interface {p0}, Ljava/lang/CharSequence;->toString()Ljava/lang/String;

    .line 172
    .line 173
    .line 174
    move-result-object p0

    .line 175
    const/16 p1, 0xa

    .line 176
    .line 177
    invoke-static {p0, p1}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;I)I

    .line 178
    .line 179
    .line 180
    move-result p0
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 181
    :goto_5
    const p1, 0xffff

    .line 182
    .line 183
    .line 184
    if-le p0, p1, :cond_c

    .line 185
    .line 186
    invoke-static {p0}, Ljava/lang/Character;->toChars(I)[C

    .line 187
    .line 188
    .line 189
    move-result-object p0

    .line 190
    aget-char p1, p0, v3

    .line 191
    .line 192
    invoke-virtual {p3, p1}, Ljava/io/Writer;->write(I)V

    .line 193
    .line 194
    .line 195
    aget-char p0, p0, v5

    .line 196
    .line 197
    invoke-virtual {p3, p0}, Ljava/io/Writer;->write(I)V

    .line 198
    .line 199
    .line 200
    goto :goto_6

    .line 201
    :cond_c
    invoke-virtual {p3, p0}, Ljava/io/Writer;->write(I)V

    .line 202
    .line 203
    .line 204
    :goto_6
    add-int/lit8 v2, v2, 0x2

    .line 205
    .line 206
    sub-int/2addr v2, v1

    .line 207
    add-int/2addr v2, p2

    .line 208
    add-int/2addr v2, v0

    .line 209
    return v2

    .line 210
    :catch_0
    :cond_d
    :goto_7
    return v3
.end method
