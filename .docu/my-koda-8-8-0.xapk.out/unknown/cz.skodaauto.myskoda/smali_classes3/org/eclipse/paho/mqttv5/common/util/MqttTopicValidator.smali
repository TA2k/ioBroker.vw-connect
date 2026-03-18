.class public Lorg/eclipse/paho/mqttv5/common/util/MqttTopicValidator;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final MAX_TOPIC_LEN:I = 0xffff

.field private static final MIN_TOPIC_LEN:I = 0x1

.field public static final MULTI_LEVEL_WILDCARD:Ljava/lang/String; = "#"

.field public static final MULTI_LEVEL_WILDCARD_PATTERN:Ljava/lang/String; = "/#"

.field private static final NUL:C = '\u0000'

.field public static final SINGLE_LEVEL_WILDCARD:Ljava/lang/String; = "+"

.field public static final TOPIC_LEVEL_SEPARATOR:Ljava/lang/String; = "/"

.field public static final TOPIC_WILDCARDS:Ljava/lang/String; = "#+"


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static isMatched(Ljava/lang/String;Ljava/lang/String;)Z
    .locals 12

    .line 1
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const/4 v2, 0x1

    .line 10
    invoke-static {p0, v2, v2}, Lorg/eclipse/paho/mqttv5/common/util/MqttTopicValidator;->validate(Ljava/lang/String;ZZ)V

    .line 11
    .line 12
    .line 13
    const/4 v3, 0x0

    .line 14
    invoke-static {p1, v3, v2}, Lorg/eclipse/paho/mqttv5/common/util/MqttTopicValidator;->validate(Ljava/lang/String;ZZ)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v4

    .line 21
    if-eqz v4, :cond_0

    .line 22
    .line 23
    return v2

    .line 24
    :cond_0
    move v4, v3

    .line 25
    move v5, v4

    .line 26
    :goto_0
    const/16 v6, 0x2f

    .line 27
    .line 28
    const/16 v7, 0x23

    .line 29
    .line 30
    if-ge v4, v1, :cond_8

    .line 31
    .line 32
    if-lt v5, v0, :cond_1

    .line 33
    .line 34
    goto :goto_3

    .line 35
    :cond_1
    invoke-virtual {p0, v4}, Ljava/lang/String;->charAt(I)C

    .line 36
    .line 37
    .line 38
    move-result v8

    .line 39
    if-ne v8, v7, :cond_2

    .line 40
    .line 41
    move v5, v0

    .line 42
    move v4, v1

    .line 43
    goto :goto_3

    .line 44
    :cond_2
    invoke-virtual {p1, v5}, Ljava/lang/String;->charAt(I)C

    .line 45
    .line 46
    .line 47
    move-result v8

    .line 48
    if-ne v8, v6, :cond_3

    .line 49
    .line 50
    invoke-virtual {p0, v4}, Ljava/lang/String;->charAt(I)C

    .line 51
    .line 52
    .line 53
    move-result v8

    .line 54
    if-eq v8, v6, :cond_3

    .line 55
    .line 56
    goto :goto_3

    .line 57
    :cond_3
    invoke-virtual {p0, v4}, Ljava/lang/String;->charAt(I)C

    .line 58
    .line 59
    .line 60
    move-result v8

    .line 61
    const/16 v9, 0x2b

    .line 62
    .line 63
    if-eq v8, v9, :cond_4

    .line 64
    .line 65
    invoke-virtual {p0, v4}, Ljava/lang/String;->charAt(I)C

    .line 66
    .line 67
    .line 68
    move-result v8

    .line 69
    if-eq v8, v7, :cond_4

    .line 70
    .line 71
    invoke-virtual {p0, v4}, Ljava/lang/String;->charAt(I)C

    .line 72
    .line 73
    .line 74
    move-result v8

    .line 75
    invoke-virtual {p1, v5}, Ljava/lang/String;->charAt(I)C

    .line 76
    .line 77
    .line 78
    move-result v10

    .line 79
    if-eq v8, v10, :cond_4

    .line 80
    .line 81
    goto :goto_3

    .line 82
    :cond_4
    invoke-virtual {p0, v4}, Ljava/lang/String;->charAt(I)C

    .line 83
    .line 84
    .line 85
    move-result v8

    .line 86
    if-ne v8, v9, :cond_6

    .line 87
    .line 88
    add-int/lit8 v7, v5, 0x1

    .line 89
    .line 90
    :goto_1
    if-ge v7, v0, :cond_7

    .line 91
    .line 92
    invoke-virtual {p1, v7}, Ljava/lang/String;->charAt(I)C

    .line 93
    .line 94
    .line 95
    move-result v7

    .line 96
    if-ne v7, v6, :cond_5

    .line 97
    .line 98
    goto :goto_2

    .line 99
    :cond_5
    add-int/lit8 v7, v5, 0x1

    .line 100
    .line 101
    add-int/lit8 v5, v5, 0x2

    .line 102
    .line 103
    move v11, v7

    .line 104
    move v7, v5

    .line 105
    move v5, v11

    .line 106
    goto :goto_1

    .line 107
    :cond_6
    invoke-virtual {p0, v4}, Ljava/lang/String;->charAt(I)C

    .line 108
    .line 109
    .line 110
    move-result v6

    .line 111
    if-ne v6, v7, :cond_7

    .line 112
    .line 113
    add-int/lit8 v5, v0, -0x1

    .line 114
    .line 115
    :cond_7
    :goto_2
    add-int/lit8 v4, v4, 0x1

    .line 116
    .line 117
    add-int/2addr v5, v2

    .line 118
    goto :goto_0

    .line 119
    :cond_8
    :goto_3
    if-ne v5, v0, :cond_9

    .line 120
    .line 121
    if-ne v4, v1, :cond_9

    .line 122
    .line 123
    return v2

    .line 124
    :cond_9
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 125
    .line 126
    .line 127
    move-result v1

    .line 128
    sub-int/2addr v1, v4

    .line 129
    if-lez v1, :cond_b

    .line 130
    .line 131
    if-ne v5, v0, :cond_b

    .line 132
    .line 133
    sub-int/2addr v5, v2

    .line 134
    invoke-virtual {p1, v5}, Ljava/lang/String;->charAt(I)C

    .line 135
    .line 136
    .line 137
    move-result v0

    .line 138
    if-ne v0, v6, :cond_a

    .line 139
    .line 140
    invoke-virtual {p0, v4}, Ljava/lang/String;->charAt(I)C

    .line 141
    .line 142
    .line 143
    move-result v0

    .line 144
    if-ne v0, v7, :cond_a

    .line 145
    .line 146
    return v2

    .line 147
    :cond_a
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 148
    .line 149
    .line 150
    move-result v0

    .line 151
    sub-int/2addr v0, v4

    .line 152
    if-le v0, v2, :cond_b

    .line 153
    .line 154
    add-int/lit8 v0, v4, 0x2

    .line 155
    .line 156
    invoke-virtual {p0, v4, v0}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 157
    .line 158
    .line 159
    move-result-object v0

    .line 160
    const-string v1, "/#"

    .line 161
    .line 162
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 163
    .line 164
    .line 165
    move-result v0

    .line 166
    if-eqz v0, :cond_b

    .line 167
    .line 168
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 169
    .line 170
    .line 171
    move-result v0

    .line 172
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 173
    .line 174
    .line 175
    move-result p1

    .line 176
    sub-int/2addr v0, p1

    .line 177
    const/4 p1, 0x2

    .line 178
    if-ne v0, p1, :cond_b

    .line 179
    .line 180
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 181
    .line 182
    .line 183
    move-result v0

    .line 184
    sub-int/2addr v0, p1

    .line 185
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 186
    .line 187
    .line 188
    move-result p1

    .line 189
    invoke-virtual {p0, v0, p1}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 190
    .line 191
    .line 192
    move-result-object p0

    .line 193
    invoke-virtual {p0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 194
    .line 195
    .line 196
    move-result p0

    .line 197
    if-eqz p0, :cond_b

    .line 198
    .line 199
    return v2

    .line 200
    :cond_b
    return v3
.end method

.method public static validate(Ljava/lang/String;ZZ)V
    .locals 3

    .line 1
    :try_start_0
    const-string v0, "UTF-8"

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Ljava/lang/String;->getBytes(Ljava/lang/String;)[B

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    array-length v0, v0
    :try_end_0
    .catch Ljava/io/UnsupportedEncodingException; {:try_start_0 .. :try_end_0} :catch_0

    .line 8
    const v1, 0xffff

    .line 9
    .line 10
    .line 11
    const/4 v2, 0x1

    .line 12
    if-lt v0, v2, :cond_7

    .line 13
    .line 14
    if-gt v0, v1, :cond_7

    .line 15
    .line 16
    if-eqz p1, :cond_3

    .line 17
    .line 18
    const-string p1, "+"

    .line 19
    .line 20
    const-string p2, "#"

    .line 21
    .line 22
    filled-new-array {p2, p1}, [Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    invoke-static {p0, p1}, Lorg/eclipse/paho/mqttv5/common/util/Strings;->equalsAny(Ljava/lang/CharSequence;[Ljava/lang/CharSequence;)Z

    .line 27
    .line 28
    .line 29
    move-result p1

    .line 30
    if-eqz p1, :cond_0

    .line 31
    .line 32
    goto :goto_1

    .line 33
    :cond_0
    invoke-static {p0, p2}, Lorg/eclipse/paho/mqttv5/common/util/Strings;->countMatches(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)I

    .line 34
    .line 35
    .line 36
    move-result p1

    .line 37
    if-gt p1, v2, :cond_2

    .line 38
    .line 39
    invoke-virtual {p0, p2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 40
    .line 41
    .line 42
    move-result p1

    .line 43
    if-eqz p1, :cond_1

    .line 44
    .line 45
    const-string p1, "/#"

    .line 46
    .line 47
    invoke-virtual {p0, p1}, Ljava/lang/String;->endsWith(Ljava/lang/String;)Z

    .line 48
    .line 49
    .line 50
    move-result p1

    .line 51
    if-eqz p1, :cond_2

    .line 52
    .line 53
    :cond_1
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/common/util/MqttTopicValidator;->validateSingleLevelWildcard(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    return-void

    .line 57
    :cond_2
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 58
    .line 59
    const-string p2, "Invalid usage of multi-level wildcard in topic string: "

    .line 60
    .line 61
    invoke-virtual {p2, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw p1

    .line 69
    :cond_3
    if-nez p2, :cond_5

    .line 70
    .line 71
    const-string p1, "$share/"

    .line 72
    .line 73
    invoke-virtual {p0, p1}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 74
    .line 75
    .line 76
    move-result p1

    .line 77
    if-nez p1, :cond_4

    .line 78
    .line 79
    goto :goto_0

    .line 80
    :cond_4
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 81
    .line 82
    const-string p1, "Shared Subscriptions are not allowed."

    .line 83
    .line 84
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    throw p0

    .line 88
    :cond_5
    :goto_0
    const-string p1, "#+"

    .line 89
    .line 90
    invoke-static {p0, p1}, Lorg/eclipse/paho/mqttv5/common/util/Strings;->containsAny(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Z

    .line 91
    .line 92
    .line 93
    move-result p0

    .line 94
    if-nez p0, :cond_6

    .line 95
    .line 96
    :goto_1
    return-void

    .line 97
    :cond_6
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 98
    .line 99
    const-string p1, "The topic name MUST NOT contain any wildcard characters (#+)"

    .line 100
    .line 101
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    throw p0

    .line 105
    :cond_7
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 106
    .line 107
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 108
    .line 109
    .line 110
    move-result-object p1

    .line 111
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 112
    .line 113
    .line 114
    move-result-object p2

    .line 115
    filled-new-array {p1, p2}, [Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object p1

    .line 119
    const-string p2, "Invalid topic length, should be in range[%d, %d]!"

    .line 120
    .line 121
    invoke-static {p2, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 122
    .line 123
    .line 124
    move-result-object p1

    .line 125
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 126
    .line 127
    .line 128
    throw p0

    .line 129
    :catch_0
    move-exception p0

    .line 130
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 131
    .line 132
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    throw p1
.end method

.method private static validateSingleLevelWildcard(Ljava/lang/String;)V
    .locals 9

    .line 1
    const-string v0, "+"

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-virtual {v0, v1}, Ljava/lang/String;->charAt(I)C

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    const-string v2, "/"

    .line 9
    .line 10
    invoke-virtual {v2, v1}, Ljava/lang/String;->charAt(I)C

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    invoke-virtual {p0}, Ljava/lang/String;->toCharArray()[C

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    array-length v4, v3

    .line 19
    move v5, v1

    .line 20
    :goto_0
    if-lt v5, v4, :cond_0

    .line 21
    .line 22
    return-void

    .line 23
    :cond_0
    add-int/lit8 v6, v5, -0x1

    .line 24
    .line 25
    if-ltz v6, :cond_1

    .line 26
    .line 27
    aget-char v6, v3, v6

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_1
    move v6, v1

    .line 31
    :goto_1
    add-int/lit8 v7, v5, 0x1

    .line 32
    .line 33
    if-ge v7, v4, :cond_2

    .line 34
    .line 35
    aget-char v8, v3, v7

    .line 36
    .line 37
    goto :goto_2

    .line 38
    :cond_2
    move v8, v1

    .line 39
    :goto_2
    aget-char v5, v3, v5

    .line 40
    .line 41
    if-ne v5, v0, :cond_5

    .line 42
    .line 43
    if-eq v6, v2, :cond_3

    .line 44
    .line 45
    if-nez v6, :cond_4

    .line 46
    .line 47
    :cond_3
    if-eq v8, v2, :cond_5

    .line 48
    .line 49
    if-nez v8, :cond_4

    .line 50
    .line 51
    goto :goto_3

    .line 52
    :cond_4
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 53
    .line 54
    const-string v1, "Invalid usage of single-level wildcard in topic string \'"

    .line 55
    .line 56
    const-string v2, "\'!"

    .line 57
    .line 58
    invoke-static {v1, p0, v2}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    throw v0

    .line 66
    :cond_5
    :goto_3
    move v5, v7

    .line 67
    goto :goto_0
.end method
