.class public abstract Lf91/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lw51/b;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lw51/b;

    .line 2
    .line 3
    const-string v1, "Utility"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lw51/b;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lf91/b;->a:Lw51/b;

    .line 9
    .line 10
    return-void
.end method

.method public static final varargs a(Lorg/json/JSONObject;[Ljava/lang/String;)I
    .locals 6

    .line 1
    array-length v0, p1

    .line 2
    invoke-static {p1, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 3
    .line 4
    .line 5
    move-result-object v0

    .line 6
    check-cast v0, [Ljava/lang/String;

    .line 7
    .line 8
    array-length v1, v0

    .line 9
    const-string v2, "version"

    .line 10
    .line 11
    if-nez v1, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0, v2}, Lorg/json/JSONObject;->getInt(Ljava/lang/String;)I

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    :goto_0
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    goto/16 :goto_5

    .line 22
    .line 23
    :cond_0
    invoke-virtual {p0, v2}, Lorg/json/JSONObject;->opt(Ljava/lang/String;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    const/4 v1, 0x0

    .line 28
    if-eqz p0, :cond_7

    .line 29
    .line 30
    sget-object v3, Lorg/json/JSONObject;->NULL:Ljava/lang/Object;

    .line 31
    .line 32
    invoke-virtual {p0, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v3

    .line 36
    if-nez v3, :cond_1

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_1
    move-object p0, v1

    .line 40
    :goto_1
    if-eqz p0, :cond_7

    .line 41
    .line 42
    instance-of v3, p0, Lorg/json/JSONObject;

    .line 43
    .line 44
    const-string v4, " is not a JSONObject"

    .line 45
    .line 46
    if-eqz v3, :cond_6

    .line 47
    .line 48
    check-cast p0, Lorg/json/JSONObject;

    .line 49
    .line 50
    const/4 v2, 0x0

    .line 51
    :goto_2
    if-eqz p0, :cond_5

    .line 52
    .line 53
    array-length v3, v0

    .line 54
    add-int/lit8 v3, v3, -0x1

    .line 55
    .line 56
    if-ge v2, v3, :cond_5

    .line 57
    .line 58
    aget-object v3, v0, v2

    .line 59
    .line 60
    invoke-virtual {p0, v3}, Lorg/json/JSONObject;->opt(Ljava/lang/String;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    instance-of v3, p0, Lorg/json/JSONObject;

    .line 65
    .line 66
    if-eqz v3, :cond_2

    .line 67
    .line 68
    check-cast p0, Lorg/json/JSONObject;

    .line 69
    .line 70
    goto :goto_4

    .line 71
    :cond_2
    sget-object v3, Lorg/json/JSONObject;->NULL:Ljava/lang/Object;

    .line 72
    .line 73
    invoke-static {p0, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    move-result v3

    .line 77
    if-nez v3, :cond_4

    .line 78
    .line 79
    if-nez p0, :cond_3

    .line 80
    .line 81
    goto :goto_3

    .line 82
    :cond_3
    new-instance p0, Lorg/json/JSONException;

    .line 83
    .line 84
    aget-object p1, v0, v2

    .line 85
    .line 86
    invoke-static {p1, v4}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object p1

    .line 90
    invoke-direct {p0, p1}, Lorg/json/JSONException;-><init>(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    throw p0

    .line 94
    :cond_4
    :goto_3
    move-object p0, v1

    .line 95
    :goto_4
    add-int/lit8 v2, v2, 0x1

    .line 96
    .line 97
    goto :goto_2

    .line 98
    :cond_5
    if-eqz p0, :cond_7

    .line 99
    .line 100
    invoke-static {v0}, Lmx0/n;->I([Ljava/lang/Object;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v0

    .line 104
    check-cast v0, Ljava/lang/String;

    .line 105
    .line 106
    invoke-virtual {p0, v0}, Lorg/json/JSONObject;->getInt(Ljava/lang/String;)I

    .line 107
    .line 108
    .line 109
    move-result p0

    .line 110
    goto :goto_0

    .line 111
    :cond_6
    new-instance p0, Lorg/json/JSONException;

    .line 112
    .line 113
    invoke-virtual {v2, v4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object p1

    .line 117
    invoke-direct {p0, p1}, Lorg/json/JSONException;-><init>(Ljava/lang/String;)V

    .line 118
    .line 119
    .line 120
    throw p0

    .line 121
    :cond_7
    move-object p0, v1

    .line 122
    :goto_5
    if-eqz p0, :cond_8

    .line 123
    .line 124
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 125
    .line 126
    .line 127
    move-result p0

    .line 128
    return p0

    .line 129
    :cond_8
    new-instance p0, Lorg/json/JSONException;

    .line 130
    .line 131
    const/4 v4, 0x0

    .line 132
    const/16 v5, 0x3e

    .line 133
    .line 134
    const-string v1, ","

    .line 135
    .line 136
    const/4 v2, 0x0

    .line 137
    const/4 v3, 0x0

    .line 138
    move-object v0, p1

    .line 139
    invoke-static/range {v0 .. v5}, Lmx0/n;->H([Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 140
    .line 141
    .line 142
    move-result-object p1

    .line 143
    const-string v0, "version,"

    .line 144
    .line 145
    const-string v1, " not found."

    .line 146
    .line 147
    invoke-static {v0, p1, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 148
    .line 149
    .line 150
    move-result-object p1

    .line 151
    invoke-direct {p0, p1}, Lorg/json/JSONException;-><init>(Ljava/lang/String;)V

    .line 152
    .line 153
    .line 154
    throw p0
.end method

.method public static final varargs b(Lorg/json/JSONObject;[Ljava/lang/String;)J
    .locals 6

    .line 1
    array-length v0, p1

    .line 2
    invoke-static {p1, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 3
    .line 4
    .line 5
    move-result-object v0

    .line 6
    check-cast v0, [Ljava/lang/String;

    .line 7
    .line 8
    array-length v1, v0

    .line 9
    const-string v2, "keyId"

    .line 10
    .line 11
    if-nez v1, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0, v2}, Lorg/json/JSONObject;->getLong(Ljava/lang/String;)J

    .line 14
    .line 15
    .line 16
    move-result-wide v0

    .line 17
    :goto_0
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    goto/16 :goto_5

    .line 22
    .line 23
    :cond_0
    invoke-virtual {p0, v2}, Lorg/json/JSONObject;->opt(Ljava/lang/String;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    const/4 v1, 0x0

    .line 28
    if-eqz p0, :cond_7

    .line 29
    .line 30
    sget-object v3, Lorg/json/JSONObject;->NULL:Ljava/lang/Object;

    .line 31
    .line 32
    invoke-virtual {p0, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v3

    .line 36
    if-nez v3, :cond_1

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_1
    move-object p0, v1

    .line 40
    :goto_1
    if-eqz p0, :cond_7

    .line 41
    .line 42
    instance-of v3, p0, Lorg/json/JSONObject;

    .line 43
    .line 44
    const-string v4, " is not a JSONObject"

    .line 45
    .line 46
    if-eqz v3, :cond_6

    .line 47
    .line 48
    check-cast p0, Lorg/json/JSONObject;

    .line 49
    .line 50
    const/4 v2, 0x0

    .line 51
    :goto_2
    if-eqz p0, :cond_5

    .line 52
    .line 53
    array-length v3, v0

    .line 54
    add-int/lit8 v3, v3, -0x1

    .line 55
    .line 56
    if-ge v2, v3, :cond_5

    .line 57
    .line 58
    aget-object v3, v0, v2

    .line 59
    .line 60
    invoke-virtual {p0, v3}, Lorg/json/JSONObject;->opt(Ljava/lang/String;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    instance-of v3, p0, Lorg/json/JSONObject;

    .line 65
    .line 66
    if-eqz v3, :cond_2

    .line 67
    .line 68
    check-cast p0, Lorg/json/JSONObject;

    .line 69
    .line 70
    goto :goto_4

    .line 71
    :cond_2
    sget-object v3, Lorg/json/JSONObject;->NULL:Ljava/lang/Object;

    .line 72
    .line 73
    invoke-static {p0, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    move-result v3

    .line 77
    if-nez v3, :cond_4

    .line 78
    .line 79
    if-nez p0, :cond_3

    .line 80
    .line 81
    goto :goto_3

    .line 82
    :cond_3
    new-instance p0, Lorg/json/JSONException;

    .line 83
    .line 84
    aget-object p1, v0, v2

    .line 85
    .line 86
    invoke-static {p1, v4}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object p1

    .line 90
    invoke-direct {p0, p1}, Lorg/json/JSONException;-><init>(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    throw p0

    .line 94
    :cond_4
    :goto_3
    move-object p0, v1

    .line 95
    :goto_4
    add-int/lit8 v2, v2, 0x1

    .line 96
    .line 97
    goto :goto_2

    .line 98
    :cond_5
    if-eqz p0, :cond_7

    .line 99
    .line 100
    invoke-static {v0}, Lmx0/n;->I([Ljava/lang/Object;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v0

    .line 104
    check-cast v0, Ljava/lang/String;

    .line 105
    .line 106
    invoke-virtual {p0, v0}, Lorg/json/JSONObject;->getLong(Ljava/lang/String;)J

    .line 107
    .line 108
    .line 109
    move-result-wide v0

    .line 110
    goto :goto_0

    .line 111
    :cond_6
    new-instance p0, Lorg/json/JSONException;

    .line 112
    .line 113
    invoke-virtual {v2, v4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object p1

    .line 117
    invoke-direct {p0, p1}, Lorg/json/JSONException;-><init>(Ljava/lang/String;)V

    .line 118
    .line 119
    .line 120
    throw p0

    .line 121
    :cond_7
    move-object p0, v1

    .line 122
    :goto_5
    if-eqz p0, :cond_8

    .line 123
    .line 124
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 125
    .line 126
    .line 127
    move-result-wide p0

    .line 128
    return-wide p0

    .line 129
    :cond_8
    new-instance p0, Lorg/json/JSONException;

    .line 130
    .line 131
    const/4 v4, 0x0

    .line 132
    const/16 v5, 0x3e

    .line 133
    .line 134
    const-string v1, ","

    .line 135
    .line 136
    const/4 v2, 0x0

    .line 137
    const/4 v3, 0x0

    .line 138
    move-object v0, p1

    .line 139
    invoke-static/range {v0 .. v5}, Lmx0/n;->H([Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 140
    .line 141
    .line 142
    move-result-object p1

    .line 143
    const-string v0, "keyId,"

    .line 144
    .line 145
    const-string v1, " not found."

    .line 146
    .line 147
    invoke-static {v0, p1, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 148
    .line 149
    .line 150
    move-result-object p1

    .line 151
    invoke-direct {p0, p1}, Lorg/json/JSONException;-><init>(Ljava/lang/String;)V

    .line 152
    .line 153
    .line 154
    throw p0
.end method

.method public static c(Ljava/lang/String;)Ljava/lang/String;
    .locals 5

    .line 1
    sget-object v0, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 2
    .line 3
    const-string v1, "<this>"

    .line 4
    .line 5
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string v1, "charset"

    .line 9
    .line 10
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0, v0}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    const-string v0, "getBytes(...)"

    .line 18
    .line 19
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    const-string v0, "SHA-256"

    .line 23
    .line 24
    invoke-static {v0}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    invoke-virtual {v0, p0}, Ljava/security/MessageDigest;->digest([B)[B

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    const-string v0, "digest(...)"

    .line 33
    .line 34
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    array-length v0, p0

    .line 38
    const/4 v1, 0x0

    .line 39
    const-string v2, ""

    .line 40
    .line 41
    :goto_0
    if-ge v1, v0, :cond_0

    .line 42
    .line 43
    aget-byte v3, p0, v1

    .line 44
    .line 45
    const-string v4, "%02x"

    .line 46
    .line 47
    invoke-virtual {v2, v4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v2

    .line 51
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 52
    .line 53
    .line 54
    move-result-object v3

    .line 55
    filled-new-array {v3}, [Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v3

    .line 59
    const/4 v4, 0x1

    .line 60
    invoke-static {v3, v4}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v3

    .line 64
    invoke-static {v2, v3}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v2

    .line 68
    add-int/lit8 v1, v1, 0x1

    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_0
    return-object v2
.end method

.method public static final varargs d(Lorg/json/JSONObject;Ljava/lang/String;[Ljava/lang/String;)Ljava/lang/String;
    .locals 9

    .line 1
    array-length v0, p2

    .line 2
    invoke-static {p2, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 3
    .line 4
    .line 5
    move-result-object v0

    .line 6
    move-object v1, v0

    .line 7
    check-cast v1, [Ljava/lang/String;

    .line 8
    .line 9
    const-string v0, "additionalKeys"

    .line 10
    .line 11
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    array-length v0, v1

    .line 15
    invoke-static {v1, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    check-cast v0, [Ljava/lang/String;

    .line 20
    .line 21
    array-length v2, v0

    .line 22
    const-string v7, " no String, Number, Boolean or Date."

    .line 23
    .line 24
    const-string v8, ","

    .line 25
    .line 26
    const/4 v3, 0x0

    .line 27
    if-nez v2, :cond_4

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Lorg/json/JSONObject;->opt(Ljava/lang/String;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    if-eqz p0, :cond_e

    .line 34
    .line 35
    sget-object v0, Lorg/json/JSONObject;->NULL:Ljava/lang/Object;

    .line 36
    .line 37
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-eqz v0, :cond_0

    .line 42
    .line 43
    goto/16 :goto_6

    .line 44
    .line 45
    :cond_0
    instance-of v0, p0, Ljava/lang/String;

    .line 46
    .line 47
    if-eqz v0, :cond_1

    .line 48
    .line 49
    :goto_0
    move-object v3, p0

    .line 50
    check-cast v3, Ljava/lang/String;

    .line 51
    .line 52
    goto/16 :goto_6

    .line 53
    .line 54
    :cond_1
    instance-of v0, p0, Ljava/lang/Number;

    .line 55
    .line 56
    if-nez v0, :cond_3

    .line 57
    .line 58
    instance-of v0, p0, Ljava/lang/Boolean;

    .line 59
    .line 60
    if-nez v0, :cond_3

    .line 61
    .line 62
    instance-of v0, p0, Ljava/util/Date;

    .line 63
    .line 64
    if-eqz v0, :cond_2

    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_2
    new-instance p0, Lorg/json/JSONException;

    .line 68
    .line 69
    const/4 v5, 0x0

    .line 70
    const/16 v6, 0x3e

    .line 71
    .line 72
    const-string v2, ","

    .line 73
    .line 74
    const/4 v3, 0x0

    .line 75
    const/4 v4, 0x0

    .line 76
    invoke-static/range {v1 .. v6}, Lmx0/n;->H([Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object p2

    .line 80
    invoke-static {p1, v8, p2, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->l(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object p1

    .line 84
    invoke-direct {p0, p1}, Lorg/json/JSONException;-><init>(Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    throw p0

    .line 88
    :cond_3
    :goto_1
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object v3

    .line 92
    goto/16 :goto_6

    .line 93
    .line 94
    :cond_4
    invoke-virtual {p0, p1}, Lorg/json/JSONObject;->opt(Ljava/lang/String;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    if-eqz p0, :cond_e

    .line 99
    .line 100
    sget-object v2, Lorg/json/JSONObject;->NULL:Ljava/lang/Object;

    .line 101
    .line 102
    invoke-virtual {p0, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    move-result v2

    .line 106
    if-nez v2, :cond_5

    .line 107
    .line 108
    goto :goto_2

    .line 109
    :cond_5
    move-object p0, v3

    .line 110
    :goto_2
    if-eqz p0, :cond_e

    .line 111
    .line 112
    instance-of v2, p0, Lorg/json/JSONObject;

    .line 113
    .line 114
    const-string v4, " is not a JSONObject"

    .line 115
    .line 116
    if-eqz v2, :cond_d

    .line 117
    .line 118
    check-cast p0, Lorg/json/JSONObject;

    .line 119
    .line 120
    const/4 v2, 0x0

    .line 121
    :goto_3
    if-eqz p0, :cond_9

    .line 122
    .line 123
    array-length v5, v0

    .line 124
    add-int/lit8 v5, v5, -0x1

    .line 125
    .line 126
    if-ge v2, v5, :cond_9

    .line 127
    .line 128
    aget-object v5, v0, v2

    .line 129
    .line 130
    invoke-virtual {p0, v5}, Lorg/json/JSONObject;->opt(Ljava/lang/String;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    instance-of v5, p0, Lorg/json/JSONObject;

    .line 135
    .line 136
    if-eqz v5, :cond_6

    .line 137
    .line 138
    check-cast p0, Lorg/json/JSONObject;

    .line 139
    .line 140
    goto :goto_5

    .line 141
    :cond_6
    sget-object v5, Lorg/json/JSONObject;->NULL:Ljava/lang/Object;

    .line 142
    .line 143
    invoke-static {p0, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 144
    .line 145
    .line 146
    move-result v5

    .line 147
    if-nez v5, :cond_8

    .line 148
    .line 149
    if-nez p0, :cond_7

    .line 150
    .line 151
    goto :goto_4

    .line 152
    :cond_7
    new-instance p0, Lorg/json/JSONException;

    .line 153
    .line 154
    aget-object p1, v0, v2

    .line 155
    .line 156
    invoke-static {p1, v4}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 157
    .line 158
    .line 159
    move-result-object p1

    .line 160
    invoke-direct {p0, p1}, Lorg/json/JSONException;-><init>(Ljava/lang/String;)V

    .line 161
    .line 162
    .line 163
    throw p0

    .line 164
    :cond_8
    :goto_4
    move-object p0, v3

    .line 165
    :goto_5
    add-int/lit8 v2, v2, 0x1

    .line 166
    .line 167
    goto :goto_3

    .line 168
    :cond_9
    if-eqz p0, :cond_e

    .line 169
    .line 170
    invoke-static {v0}, Lmx0/n;->I([Ljava/lang/Object;)Ljava/lang/Object;

    .line 171
    .line 172
    .line 173
    move-result-object v0

    .line 174
    check-cast v0, Ljava/lang/String;

    .line 175
    .line 176
    invoke-virtual {p0, v0}, Lorg/json/JSONObject;->opt(Ljava/lang/String;)Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object p0

    .line 180
    if-eqz p0, :cond_e

    .line 181
    .line 182
    sget-object v0, Lorg/json/JSONObject;->NULL:Ljava/lang/Object;

    .line 183
    .line 184
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 185
    .line 186
    .line 187
    move-result v0

    .line 188
    if-eqz v0, :cond_a

    .line 189
    .line 190
    goto :goto_6

    .line 191
    :cond_a
    instance-of v0, p0, Ljava/lang/String;

    .line 192
    .line 193
    if-eqz v0, :cond_b

    .line 194
    .line 195
    goto/16 :goto_0

    .line 196
    .line 197
    :cond_b
    instance-of v0, p0, Ljava/lang/Number;

    .line 198
    .line 199
    if-nez v0, :cond_3

    .line 200
    .line 201
    instance-of v0, p0, Ljava/lang/Boolean;

    .line 202
    .line 203
    if-nez v0, :cond_3

    .line 204
    .line 205
    instance-of v0, p0, Ljava/util/Date;

    .line 206
    .line 207
    if-eqz v0, :cond_c

    .line 208
    .line 209
    goto :goto_1

    .line 210
    :cond_c
    new-instance p0, Lorg/json/JSONException;

    .line 211
    .line 212
    const/4 v5, 0x0

    .line 213
    const/16 v6, 0x3e

    .line 214
    .line 215
    const-string v2, ","

    .line 216
    .line 217
    const/4 v3, 0x0

    .line 218
    const/4 v4, 0x0

    .line 219
    invoke-static/range {v1 .. v6}, Lmx0/n;->H([Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 220
    .line 221
    .line 222
    move-result-object p2

    .line 223
    invoke-static {p1, v8, p2, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->l(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 224
    .line 225
    .line 226
    move-result-object p1

    .line 227
    invoke-direct {p0, p1}, Lorg/json/JSONException;-><init>(Ljava/lang/String;)V

    .line 228
    .line 229
    .line 230
    throw p0

    .line 231
    :cond_d
    new-instance p0, Lorg/json/JSONException;

    .line 232
    .line 233
    invoke-virtual {p1, v4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 234
    .line 235
    .line 236
    move-result-object p1

    .line 237
    invoke-direct {p0, p1}, Lorg/json/JSONException;-><init>(Ljava/lang/String;)V

    .line 238
    .line 239
    .line 240
    throw p0

    .line 241
    :cond_e
    :goto_6
    if-eqz v3, :cond_f

    .line 242
    .line 243
    return-object v3

    .line 244
    :cond_f
    new-instance p0, Lorg/json/JSONException;

    .line 245
    .line 246
    const/4 v4, 0x0

    .line 247
    const/16 v5, 0x3e

    .line 248
    .line 249
    const-string v1, ","

    .line 250
    .line 251
    const/4 v2, 0x0

    .line 252
    const/4 v3, 0x0

    .line 253
    move-object v0, p2

    .line 254
    invoke-static/range {v0 .. v5}, Lmx0/n;->H([Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 255
    .line 256
    .line 257
    move-result-object p2

    .line 258
    const-string v0, " not found."

    .line 259
    .line 260
    invoke-static {p1, v8, p2, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->l(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 261
    .line 262
    .line 263
    move-result-object p1

    .line 264
    invoke-direct {p0, p1}, Lorg/json/JSONException;-><init>(Ljava/lang/String;)V

    .line 265
    .line 266
    .line 267
    throw p0
.end method

.method public static final e(Ljava/lang/Object;)Ljava/lang/Throwable;
    .locals 8

    .line 1
    const/4 v0, 0x0

    .line 2
    if-nez p0, :cond_0

    .line 3
    .line 4
    goto/16 :goto_4

    .line 5
    .line 6
    :cond_0
    instance-of v1, p0, Lg91/a;

    .line 7
    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    check-cast p0, Lg91/a;

    .line 11
    .line 12
    iget-object p0, p0, Lg91/a;->a:Lq51/p;

    .line 13
    .line 14
    invoke-static {p0}, Lf91/b;->e(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :cond_1
    instance-of v1, p0, Ljava/lang/Throwable;

    .line 20
    .line 21
    if-eqz v1, :cond_2

    .line 22
    .line 23
    check-cast p0, Ljava/lang/Throwable;

    .line 24
    .line 25
    return-object p0

    .line 26
    :cond_2
    instance-of v1, p0, Le91/a;

    .line 27
    .line 28
    sget-object v2, Le91/c;->c:Le91/c;

    .line 29
    .line 30
    if-eqz v1, :cond_5

    .line 31
    .line 32
    check-cast p0, Le91/a;

    .line 33
    .line 34
    invoke-static {p0}, Lkp/z5;->a(Le91/a;)Ljava/lang/Throwable;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    if-nez v1, :cond_4

    .line 39
    .line 40
    invoke-interface {p0}, Le91/a;->getContext()Le91/b;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    iget-object p0, p0, Le91/b;->a:Ljava/util/Map;

    .line 45
    .line 46
    invoke-interface {p0, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    instance-of v1, p0, Le91/d;

    .line 51
    .line 52
    if-eqz v1, :cond_3

    .line 53
    .line 54
    move-object v0, p0

    .line 55
    check-cast v0, Le91/d;

    .line 56
    .line 57
    :cond_3
    invoke-static {v0}, Lf91/b;->e(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :cond_4
    return-object v1

    .line 63
    :cond_5
    :try_start_0
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    invoke-virtual {v1}, Ljava/lang/Class;->getDeclaredMethods()[Ljava/lang/reflect/Method;

    .line 68
    .line 69
    .line 70
    move-result-object v1

    .line 71
    const-string v3, "getDeclaredMethods(...)"

    .line 72
    .line 73
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    array-length v3, v1

    .line 77
    const/4 v4, 0x0

    .line 78
    :goto_0
    if-ge v4, v3, :cond_b

    .line 79
    .line 80
    aget-object v5, v1, v4

    .line 81
    .line 82
    invoke-virtual {v5}, Ljava/lang/reflect/Method;->getParameterTypes()[Ljava/lang/Class;

    .line 83
    .line 84
    .line 85
    move-result-object v6

    .line 86
    const-string v7, "getParameterTypes(...)"

    .line 87
    .line 88
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    array-length v6, v6

    .line 92
    if-nez v6, :cond_a

    .line 93
    .line 94
    const-class v6, Le91/a;

    .line 95
    .line 96
    invoke-virtual {v5}, Ljava/lang/reflect/Method;->getReturnType()Ljava/lang/Class;

    .line 97
    .line 98
    .line 99
    move-result-object v7

    .line 100
    invoke-virtual {v6, v7}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 101
    .line 102
    .line 103
    move-result v6

    .line 104
    if-eqz v6, :cond_7

    .line 105
    .line 106
    invoke-virtual {v5, p0, v0}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v1

    .line 110
    check-cast v1, Le91/a;

    .line 111
    .line 112
    if-eqz v1, :cond_6

    .line 113
    .line 114
    invoke-static {v1}, Lkp/z5;->a(Le91/a;)Ljava/lang/Throwable;

    .line 115
    .line 116
    .line 117
    move-result-object v3

    .line 118
    goto :goto_1

    .line 119
    :catch_0
    move-exception v1

    .line 120
    goto :goto_5

    .line 121
    :cond_6
    move-object v3, v0

    .line 122
    :goto_1
    if-eqz v1, :cond_9

    .line 123
    .line 124
    invoke-interface {v1}, Le91/a;->getContext()Le91/b;

    .line 125
    .line 126
    .line 127
    move-result-object v1

    .line 128
    iget-object v1, v1, Le91/b;->a:Ljava/util/Map;

    .line 129
    .line 130
    invoke-interface {v1, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v1

    .line 134
    instance-of v2, v1, Le91/d;

    .line 135
    .line 136
    if-eqz v2, :cond_9

    .line 137
    .line 138
    check-cast v1, Le91/d;

    .line 139
    .line 140
    goto :goto_2

    .line 141
    :cond_7
    const-class v6, Le91/d;

    .line 142
    .line 143
    invoke-virtual {v5}, Ljava/lang/reflect/Method;->getReturnType()Ljava/lang/Class;

    .line 144
    .line 145
    .line 146
    move-result-object v7

    .line 147
    invoke-virtual {v6, v7}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 148
    .line 149
    .line 150
    move-result v6

    .line 151
    if-eqz v6, :cond_8

    .line 152
    .line 153
    invoke-virtual {v5, p0, v0}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 154
    .line 155
    .line 156
    move-result-object v1

    .line 157
    check-cast v1, Le91/d;

    .line 158
    .line 159
    move-object v3, v0

    .line 160
    goto :goto_2

    .line 161
    :cond_8
    const-class v6, Ljava/lang/Throwable;

    .line 162
    .line 163
    invoke-virtual {v5}, Ljava/lang/reflect/Method;->getReturnType()Ljava/lang/Class;

    .line 164
    .line 165
    .line 166
    move-result-object v7

    .line 167
    invoke-virtual {v6, v7}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 168
    .line 169
    .line 170
    move-result v6

    .line 171
    if-eqz v6, :cond_a

    .line 172
    .line 173
    invoke-virtual {v5, p0, v0}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object v1

    .line 177
    move-object v3, v1

    .line 178
    check-cast v3, Ljava/lang/Throwable;

    .line 179
    .line 180
    :cond_9
    move-object v1, v0

    .line 181
    goto :goto_2

    .line 182
    :cond_a
    add-int/lit8 v4, v4, 0x1

    .line 183
    .line 184
    goto :goto_0

    .line 185
    :cond_b
    move-object v1, v0

    .line 186
    move-object v3, v1

    .line 187
    :goto_2
    if-nez v3, :cond_e

    .line 188
    .line 189
    if-eqz v1, :cond_d

    .line 190
    .line 191
    invoke-virtual {v1, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 192
    .line 193
    .line 194
    move-result v2

    .line 195
    if-nez v2, :cond_c

    .line 196
    .line 197
    goto :goto_3

    .line 198
    :cond_c
    move-object v1, v0

    .line 199
    :goto_3
    if-eqz v1, :cond_d

    .line 200
    .line 201
    invoke-static {v1}, Lf91/b;->e(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 202
    .line 203
    .line 204
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 205
    return-object p0

    .line 206
    :cond_d
    :goto_4
    return-object v0

    .line 207
    :cond_e
    return-object v3

    .line 208
    :goto_5
    new-instance v2, Lf91/a;

    .line 209
    .line 210
    const/4 v3, 0x0

    .line 211
    invoke-direct {v2, p0, v3}, Lf91/a;-><init>(Ljava/lang/Object;I)V

    .line 212
    .line 213
    .line 214
    sget-object p0, Lf91/b;->a:Lw51/b;

    .line 215
    .line 216
    invoke-static {p0, v1, v2}, Lw51/c;->f(Lw51/b;Ljava/lang/Throwable;Lay0/a;)V

    .line 217
    .line 218
    .line 219
    return-object v0
.end method
