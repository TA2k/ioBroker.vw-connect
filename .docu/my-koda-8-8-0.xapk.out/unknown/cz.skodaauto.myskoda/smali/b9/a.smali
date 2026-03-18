.class public final Lb9/a;
.super Llp/je;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final c:Ljava/util/regex/Pattern;


# instance fields
.field public final a:Ljava/nio/charset/CharsetDecoder;

.field public final b:Ljava/nio/charset/CharsetDecoder;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-string v0, "(.+?)=\'(.*?)\';"

    .line 2
    .line 3
    const/16 v1, 0x20

    .line 4
    .line 5
    invoke-static {v0, v1}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;I)Ljava/util/regex/Pattern;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sput-object v0, Lb9/a;->c:Ljava/util/regex/Pattern;

    .line 10
    .line 11
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 5
    .line 6
    invoke-virtual {v0}, Ljava/nio/charset/Charset;->newDecoder()Ljava/nio/charset/CharsetDecoder;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    iput-object v0, p0, Lb9/a;->a:Ljava/nio/charset/CharsetDecoder;

    .line 11
    .line 12
    sget-object v0, Ljava/nio/charset/StandardCharsets;->ISO_8859_1:Ljava/nio/charset/Charset;

    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/nio/charset/Charset;->newDecoder()Ljava/nio/charset/CharsetDecoder;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    iput-object v0, p0, Lb9/a;->b:Ljava/nio/charset/CharsetDecoder;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final b(Lx8/a;Ljava/nio/ByteBuffer;)Lt7/c0;
    .locals 6

    .line 1
    iget-object p1, p0, Lb9/a;->b:Ljava/nio/charset/CharsetDecoder;

    .line 2
    .line 3
    iget-object p0, p0, Lb9/a;->a:Ljava/nio/charset/CharsetDecoder;

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    :try_start_0
    invoke-virtual {p0, p2}, Ljava/nio/charset/CharsetDecoder;->decode(Ljava/nio/ByteBuffer;)Ljava/nio/CharBuffer;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-virtual {v1}, Ljava/nio/CharBuffer;->toString()Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p1
    :try_end_0
    .catch Ljava/nio/charset/CharacterCodingException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 14
    invoke-virtual {p0}, Ljava/nio/charset/CharsetDecoder;->reset()Ljava/nio/charset/CharsetDecoder;

    .line 15
    .line 16
    .line 17
    invoke-virtual {p2}, Ljava/nio/ByteBuffer;->rewind()Ljava/nio/Buffer;

    .line 18
    .line 19
    .line 20
    goto :goto_0

    .line 21
    :catchall_0
    move-exception p1

    .line 22
    invoke-virtual {p0}, Ljava/nio/charset/CharsetDecoder;->reset()Ljava/nio/charset/CharsetDecoder;

    .line 23
    .line 24
    .line 25
    invoke-virtual {p2}, Ljava/nio/ByteBuffer;->rewind()Ljava/nio/Buffer;

    .line 26
    .line 27
    .line 28
    throw p1

    .line 29
    :catch_0
    invoke-virtual {p0}, Ljava/nio/charset/CharsetDecoder;->reset()Ljava/nio/charset/CharsetDecoder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {p2}, Ljava/nio/ByteBuffer;->rewind()Ljava/nio/Buffer;

    .line 33
    .line 34
    .line 35
    :try_start_1
    invoke-virtual {p1, p2}, Ljava/nio/charset/CharsetDecoder;->decode(Ljava/nio/ByteBuffer;)Ljava/nio/CharBuffer;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-virtual {p0}, Ljava/nio/CharBuffer;->toString()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p0
    :try_end_1
    .catch Ljava/nio/charset/CharacterCodingException; {:try_start_1 .. :try_end_1} :catch_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 43
    invoke-virtual {p1}, Ljava/nio/charset/CharsetDecoder;->reset()Ljava/nio/charset/CharsetDecoder;

    .line 44
    .line 45
    .line 46
    invoke-virtual {p2}, Ljava/nio/ByteBuffer;->rewind()Ljava/nio/Buffer;

    .line 47
    .line 48
    .line 49
    move-object p1, p0

    .line 50
    goto :goto_0

    .line 51
    :catchall_1
    move-exception p0

    .line 52
    invoke-virtual {p1}, Ljava/nio/charset/CharsetDecoder;->reset()Ljava/nio/charset/CharsetDecoder;

    .line 53
    .line 54
    .line 55
    invoke-virtual {p2}, Ljava/nio/ByteBuffer;->rewind()Ljava/nio/Buffer;

    .line 56
    .line 57
    .line 58
    throw p0

    .line 59
    :catch_1
    invoke-virtual {p1}, Ljava/nio/charset/CharsetDecoder;->reset()Ljava/nio/charset/CharsetDecoder;

    .line 60
    .line 61
    .line 62
    invoke-virtual {p2}, Ljava/nio/ByteBuffer;->rewind()Ljava/nio/Buffer;

    .line 63
    .line 64
    .line 65
    move-object p1, v0

    .line 66
    :goto_0
    invoke-virtual {p2}, Ljava/nio/Buffer;->limit()I

    .line 67
    .line 68
    .line 69
    move-result p0

    .line 70
    new-array p0, p0, [B

    .line 71
    .line 72
    invoke-virtual {p2, p0}, Ljava/nio/ByteBuffer;->get([B)Ljava/nio/ByteBuffer;

    .line 73
    .line 74
    .line 75
    const/4 p2, 0x0

    .line 76
    const/4 v1, 0x1

    .line 77
    if-nez p1, :cond_0

    .line 78
    .line 79
    new-instance p1, Lt7/c0;

    .line 80
    .line 81
    new-instance v2, Lb9/c;

    .line 82
    .line 83
    invoke-direct {v2, v0, v0, p0}, Lb9/c;-><init>(Ljava/lang/String;Ljava/lang/String;[B)V

    .line 84
    .line 85
    .line 86
    new-array p0, v1, [Lt7/b0;

    .line 87
    .line 88
    aput-object v2, p0, p2

    .line 89
    .line 90
    invoke-direct {p1, p0}, Lt7/c0;-><init>([Lt7/b0;)V

    .line 91
    .line 92
    .line 93
    return-object p1

    .line 94
    :cond_0
    sget-object v2, Lb9/a;->c:Ljava/util/regex/Pattern;

    .line 95
    .line 96
    invoke-virtual {v2, p1}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 97
    .line 98
    .line 99
    move-result-object p1

    .line 100
    move v3, p2

    .line 101
    move-object v2, v0

    .line 102
    :goto_1
    invoke-virtual {p1, v3}, Ljava/util/regex/Matcher;->find(I)Z

    .line 103
    .line 104
    .line 105
    move-result v3

    .line 106
    if-eqz v3, :cond_4

    .line 107
    .line 108
    invoke-virtual {p1, v1}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object v3

    .line 112
    const/4 v4, 0x2

    .line 113
    invoke-virtual {p1, v4}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object v4

    .line 117
    if-eqz v3, :cond_3

    .line 118
    .line 119
    invoke-static {v3}, Lkp/g9;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 120
    .line 121
    .line 122
    move-result-object v3

    .line 123
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 124
    .line 125
    .line 126
    const-string v5, "streamurl"

    .line 127
    .line 128
    invoke-virtual {v3, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 129
    .line 130
    .line 131
    move-result v5

    .line 132
    if-nez v5, :cond_2

    .line 133
    .line 134
    const-string v5, "streamtitle"

    .line 135
    .line 136
    invoke-virtual {v3, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    move-result v3

    .line 140
    if-nez v3, :cond_1

    .line 141
    .line 142
    goto :goto_2

    .line 143
    :cond_1
    move-object v0, v4

    .line 144
    goto :goto_2

    .line 145
    :cond_2
    move-object v2, v4

    .line 146
    :cond_3
    :goto_2
    invoke-virtual {p1}, Ljava/util/regex/Matcher;->end()I

    .line 147
    .line 148
    .line 149
    move-result v3

    .line 150
    goto :goto_1

    .line 151
    :cond_4
    new-instance p1, Lt7/c0;

    .line 152
    .line 153
    new-instance v3, Lb9/c;

    .line 154
    .line 155
    invoke-direct {v3, v0, v2, p0}, Lb9/c;-><init>(Ljava/lang/String;Ljava/lang/String;[B)V

    .line 156
    .line 157
    .line 158
    new-array p0, v1, [Lt7/b0;

    .line 159
    .line 160
    aput-object v3, p0, p2

    .line 161
    .line 162
    invoke-direct {p1, p0}, Lt7/c0;-><init>([Lt7/b0;)V

    .line 163
    .line 164
    .line 165
    return-object p1
.end method
