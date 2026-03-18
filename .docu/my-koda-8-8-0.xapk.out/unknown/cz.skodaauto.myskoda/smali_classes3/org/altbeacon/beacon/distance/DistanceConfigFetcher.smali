.class public Lorg/altbeacon/beacon/distance/DistanceConfigFetcher;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final TAG:Ljava/lang/String; = "DistanceConfigFetcher"


# instance fields
.field protected mException:Ljava/lang/Exception;

.field protected mResponse:Ljava/lang/String;

.field private mResponseCode:I

.field private mUrlString:Ljava/lang/String;

.field private mUserAgentString:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, -0x1

    .line 5
    iput v0, p0, Lorg/altbeacon/beacon/distance/DistanceConfigFetcher;->mResponseCode:I

    .line 6
    .line 7
    iput-object p1, p0, Lorg/altbeacon/beacon/distance/DistanceConfigFetcher;->mUrlString:Ljava/lang/String;

    .line 8
    .line 9
    iput-object p2, p0, Lorg/altbeacon/beacon/distance/DistanceConfigFetcher;->mUserAgentString:Ljava/lang/String;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public getException()Ljava/lang/Exception;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/distance/DistanceConfigFetcher;->mException:Ljava/lang/Exception;

    .line 2
    .line 3
    return-object p0
.end method

.method public getResponseCode()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/altbeacon/beacon/distance/DistanceConfigFetcher;->mResponseCode:I

    .line 2
    .line 3
    return p0
.end method

.method public getResponseString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/distance/DistanceConfigFetcher;->mResponse:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public request()V
    .locals 11

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Lorg/altbeacon/beacon/distance/DistanceConfigFetcher;->mResponse:Ljava/lang/String;

    .line 3
    .line 4
    iget-object v1, p0, Lorg/altbeacon/beacon/distance/DistanceConfigFetcher;->mUrlString:Ljava/lang/String;

    .line 5
    .line 6
    new-instance v2, Ljava/lang/StringBuilder;

    .line 7
    .line 8
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 9
    .line 10
    .line 11
    const/4 v3, 0x0

    .line 12
    move-object v5, v0

    .line 13
    move v4, v3

    .line 14
    :cond_0
    const-string v6, "DistanceConfigFetcher"

    .line 15
    .line 16
    if-eqz v4, :cond_1

    .line 17
    .line 18
    iget-object v1, p0, Lorg/altbeacon/beacon/distance/DistanceConfigFetcher;->mUrlString:Ljava/lang/String;

    .line 19
    .line 20
    const-string v7, "Location"

    .line 21
    .line 22
    invoke-virtual {v5, v7}, Ljava/net/URLConnection;->getHeaderField(Ljava/lang/String;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v8

    .line 26
    filled-new-array {v1, v8}, [Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    const-string v8, "Following redirect from %s to %s"

    .line 31
    .line 32
    invoke-static {v6, v8, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {v5, v7}, Ljava/net/URLConnection;->getHeaderField(Ljava/lang/String;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    :cond_1
    add-int/lit8 v4, v4, 0x1

    .line 40
    .line 41
    const/4 v7, -0x1

    .line 42
    iput v7, p0, Lorg/altbeacon/beacon/distance/DistanceConfigFetcher;->mResponseCode:I

    .line 43
    .line 44
    :try_start_0
    new-instance v7, Ljava/net/URL;

    .line 45
    .line 46
    invoke-direct {v7, v1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 47
    .line 48
    .line 49
    goto :goto_0

    .line 50
    :catch_0
    move-exception v7

    .line 51
    iget-object v8, p0, Lorg/altbeacon/beacon/distance/DistanceConfigFetcher;->mUrlString:Ljava/lang/String;

    .line 52
    .line 53
    filled-new-array {v8}, [Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v8

    .line 57
    const-string v9, "Can\'t construct URL from: %s"

    .line 58
    .line 59
    invoke-static {v6, v9, v8}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    iput-object v7, p0, Lorg/altbeacon/beacon/distance/DistanceConfigFetcher;->mException:Ljava/lang/Exception;

    .line 63
    .line 64
    move-object v7, v0

    .line 65
    :goto_0
    if-nez v7, :cond_2

    .line 66
    .line 67
    const-string v7, "URL is null.  Cannot make request"

    .line 68
    .line 69
    new-array v8, v3, [Ljava/lang/Object;

    .line 70
    .line 71
    invoke-static {v6, v7, v8}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    goto/16 :goto_5

    .line 75
    .line 76
    :cond_2
    :try_start_1
    invoke-virtual {v7}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;

    .line 77
    .line 78
    .line 79
    move-result-object v7

    .line 80
    invoke-static {v7}, Lcom/google/firebase/perf/network/FirebasePerfUrlConnection;->instrument(Ljava/lang/Object;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v7

    .line 84
    check-cast v7, Ljava/net/URLConnection;

    .line 85
    .line 86
    check-cast v7, Ljava/net/HttpURLConnection;
    :try_end_1
    .catch Ljava/lang/SecurityException; {:try_start_1 .. :try_end_1} :catch_6
    .catch Ljava/io/FileNotFoundException; {:try_start_1 .. :try_end_1} :catch_5
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_4

    .line 87
    .line 88
    :try_start_2
    const-string v5, "User-Agent"

    .line 89
    .line 90
    iget-object v8, p0, Lorg/altbeacon/beacon/distance/DistanceConfigFetcher;->mUserAgentString:Ljava/lang/String;

    .line 91
    .line 92
    invoke-virtual {v7, v5, v8}, Ljava/net/URLConnection;->addRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {v7}, Ljava/net/HttpURLConnection;->getResponseCode()I

    .line 96
    .line 97
    .line 98
    move-result v5

    .line 99
    iput v5, p0, Lorg/altbeacon/beacon/distance/DistanceConfigFetcher;->mResponseCode:I

    .line 100
    .line 101
    const-string v5, "response code is %s"

    .line 102
    .line 103
    invoke-virtual {v7}, Ljava/net/HttpURLConnection;->getResponseCode()I

    .line 104
    .line 105
    .line 106
    move-result v8

    .line 107
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 108
    .line 109
    .line 110
    move-result-object v8

    .line 111
    filled-new-array {v8}, [Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v8

    .line 115
    invoke-static {v6, v5, v8}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_2
    .catch Ljava/lang/SecurityException; {:try_start_2 .. :try_end_2} :catch_3
    .catch Ljava/io/FileNotFoundException; {:try_start_2 .. :try_end_2} :catch_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_1

    .line 116
    .line 117
    .line 118
    :goto_1
    move-object v5, v7

    .line 119
    goto :goto_5

    .line 120
    :catch_1
    move-exception v5

    .line 121
    goto :goto_2

    .line 122
    :catch_2
    move-exception v5

    .line 123
    goto :goto_3

    .line 124
    :catch_3
    move-exception v5

    .line 125
    goto :goto_4

    .line 126
    :catch_4
    move-exception v7

    .line 127
    move-object v10, v7

    .line 128
    move-object v7, v5

    .line 129
    move-object v5, v10

    .line 130
    goto :goto_2

    .line 131
    :catch_5
    move-exception v7

    .line 132
    move-object v10, v7

    .line 133
    move-object v7, v5

    .line 134
    move-object v5, v10

    .line 135
    goto :goto_3

    .line 136
    :catch_6
    move-exception v7

    .line 137
    move-object v10, v7

    .line 138
    move-object v7, v5

    .line 139
    move-object v5, v10

    .line 140
    goto :goto_4

    .line 141
    :goto_2
    const-string v8, "Can\'t reach server"

    .line 142
    .line 143
    new-array v9, v3, [Ljava/lang/Object;

    .line 144
    .line 145
    invoke-static {v5, v6, v8, v9}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 146
    .line 147
    .line 148
    iput-object v5, p0, Lorg/altbeacon/beacon/distance/DistanceConfigFetcher;->mException:Ljava/lang/Exception;

    .line 149
    .line 150
    goto :goto_1

    .line 151
    :goto_3
    const-string v8, "No data exists at \"+urlString"

    .line 152
    .line 153
    new-array v9, v3, [Ljava/lang/Object;

    .line 154
    .line 155
    invoke-static {v5, v6, v8, v9}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 156
    .line 157
    .line 158
    iput-object v5, p0, Lorg/altbeacon/beacon/distance/DistanceConfigFetcher;->mException:Ljava/lang/Exception;

    .line 159
    .line 160
    goto :goto_1

    .line 161
    :goto_4
    const-string v8, "Can\'t reach sever.  Have you added android.permission.INTERNET to your manifest?"

    .line 162
    .line 163
    new-array v9, v3, [Ljava/lang/Object;

    .line 164
    .line 165
    invoke-static {v5, v6, v8, v9}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 166
    .line 167
    .line 168
    iput-object v5, p0, Lorg/altbeacon/beacon/distance/DistanceConfigFetcher;->mException:Ljava/lang/Exception;

    .line 169
    .line 170
    goto :goto_1

    .line 171
    :goto_5
    const/16 v7, 0xa

    .line 172
    .line 173
    if-ge v4, v7, :cond_3

    .line 174
    .line 175
    iget v7, p0, Lorg/altbeacon/beacon/distance/DistanceConfigFetcher;->mResponseCode:I

    .line 176
    .line 177
    const/16 v8, 0x12e

    .line 178
    .line 179
    if-eq v7, v8, :cond_0

    .line 180
    .line 181
    const/16 v8, 0x12d

    .line 182
    .line 183
    if-eq v7, v8, :cond_0

    .line 184
    .line 185
    const/16 v8, 0x12f

    .line 186
    .line 187
    if-eq v7, v8, :cond_0

    .line 188
    .line 189
    :cond_3
    iget-object v0, p0, Lorg/altbeacon/beacon/distance/DistanceConfigFetcher;->mException:Ljava/lang/Exception;

    .line 190
    .line 191
    if-nez v0, :cond_5

    .line 192
    .line 193
    :try_start_3
    new-instance v0, Ljava/io/BufferedReader;

    .line 194
    .line 195
    new-instance v1, Ljava/io/InputStreamReader;

    .line 196
    .line 197
    invoke-virtual {v5}, Ljava/net/URLConnection;->getInputStream()Ljava/io/InputStream;

    .line 198
    .line 199
    .line 200
    move-result-object v4

    .line 201
    invoke-direct {v1, v4}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;)V

    .line 202
    .line 203
    .line 204
    invoke-direct {v0, v1}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V

    .line 205
    .line 206
    .line 207
    :goto_6
    invoke-virtual {v0}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    .line 208
    .line 209
    .line 210
    move-result-object v1

    .line 211
    if-eqz v1, :cond_4

    .line 212
    .line 213
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 214
    .line 215
    .line 216
    goto :goto_6

    .line 217
    :catch_7
    move-exception v0

    .line 218
    goto :goto_7

    .line 219
    :cond_4
    invoke-virtual {v0}, Ljava/io/BufferedReader;->close()V

    .line 220
    .line 221
    .line 222
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 223
    .line 224
    .line 225
    move-result-object v0

    .line 226
    iput-object v0, p0, Lorg/altbeacon/beacon/distance/DistanceConfigFetcher;->mResponse:Ljava/lang/String;
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_7

    .line 227
    .line 228
    goto :goto_8

    .line 229
    :goto_7
    iput-object v0, p0, Lorg/altbeacon/beacon/distance/DistanceConfigFetcher;->mException:Ljava/lang/Exception;

    .line 230
    .line 231
    const-string p0, "error reading beacon data"

    .line 232
    .line 233
    new-array v1, v3, [Ljava/lang/Object;

    .line 234
    .line 235
    invoke-static {v0, v6, p0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 236
    .line 237
    .line 238
    :cond_5
    :goto_8
    return-void
.end method
