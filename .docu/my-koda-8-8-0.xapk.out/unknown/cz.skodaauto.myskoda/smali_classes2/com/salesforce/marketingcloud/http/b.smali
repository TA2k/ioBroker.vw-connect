.class public final enum Lcom/salesforce/marketingcloud/http/b;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/http/b$a;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/salesforce/marketingcloud/http/b;",
        ">;"
    }
.end annotation


# static fields
.field private static final A:Ljava/lang/String;

.field private static final B:J = 0x5265c00L

.field private static final synthetic C:[Lcom/salesforce/marketingcloud/http/b;

.field public static final enum i:Lcom/salesforce/marketingcloud/http/b;

.field public static final enum j:Lcom/salesforce/marketingcloud/http/b;

.field public static final enum k:Lcom/salesforce/marketingcloud/http/b;

.field public static final enum l:Lcom/salesforce/marketingcloud/http/b;

.field public static final enum m:Lcom/salesforce/marketingcloud/http/b;

.field public static final enum n:Lcom/salesforce/marketingcloud/http/b;

.field public static final enum o:Lcom/salesforce/marketingcloud/http/b;

.field public static final enum p:Lcom/salesforce/marketingcloud/http/b;

.field public static final enum q:Lcom/salesforce/marketingcloud/http/b;

.field public static final enum r:Lcom/salesforce/marketingcloud/http/b;

.field public static final enum s:Lcom/salesforce/marketingcloud/http/b;

.field public static final t:Ljava/lang/String; = "x-subscriber-token"

.field public static final u:Ljava/lang/String; = "user-agent"

.field public static final v:Ljava/lang/String; = "authorization"

.field public static final w:Ljava/lang/String; = "accept"

.field public static final x:Ljava/lang/String; = "x-sdk-version"

.field public static final y:Ljava/lang/String; = "retry-after"

.field private static final z:Ljava/lang/String; = "Bearer %s"


# instance fields
.field public final b:I

.field public final c:Ljava/lang/String;

.field public final d:Ljava/lang/String;

.field public final e:Ljava/lang/String;

.field public final f:Ljava/lang/String;

.field public final g:Ljava/lang/String;

.field public final h:J


# direct methods
.method static constructor <clinit>()V
    .locals 18

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/http/b;

    .line 2
    .line 3
    const-string v8, "analytics_next_retry_time"

    .line 4
    .line 5
    const-wide/16 v9, 0x2710

    .line 6
    .line 7
    const-string v1, "ET_ANALYTICS"

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    const-string v3, "POST"

    .line 11
    .line 12
    const/4 v4, 0x1

    .line 13
    const-string v5, "/device/v1/event/analytic"

    .line 14
    .line 15
    const-string v6, "application/json"

    .line 16
    .line 17
    const-string v7, "application/json"

    .line 18
    .line 19
    invoke-direct/range {v0 .. v10}, Lcom/salesforce/marketingcloud/http/b;-><init>(Ljava/lang/String;ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;J)V

    .line 20
    .line 21
    .line 22
    sput-object v0, Lcom/salesforce/marketingcloud/http/b;->i:Lcom/salesforce/marketingcloud/http/b;

    .line 23
    .line 24
    new-instance v1, Lcom/salesforce/marketingcloud/http/b;

    .line 25
    .line 26
    const-string v8, "application/json"

    .line 27
    .line 28
    const-string v9, "piwama_next_retry_time"

    .line 29
    .line 30
    const-string v2, "PI_ANALYTICS"

    .line 31
    .line 32
    const/4 v3, 0x1

    .line 33
    const-string v4, "POST"

    .line 34
    .line 35
    const/4 v5, 0x2

    .line 36
    const-string v6, "{0}"

    .line 37
    .line 38
    const-string v7, "application/json"

    .line 39
    .line 40
    invoke-direct/range {v1 .. v9}, Lcom/salesforce/marketingcloud/http/b;-><init>(Ljava/lang/String;ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    sput-object v1, Lcom/salesforce/marketingcloud/http/b;->j:Lcom/salesforce/marketingcloud/http/b;

    .line 44
    .line 45
    new-instance v2, Lcom/salesforce/marketingcloud/http/b;

    .line 46
    .line 47
    const-string v9, "application/json"

    .line 48
    .line 49
    const-string v10, "inbox_next_retry_time"

    .line 50
    .line 51
    const-string v3, "INBOX_MESSAGE"

    .line 52
    .line 53
    const/4 v4, 0x2

    .line 54
    const-string v5, "GET"

    .line 55
    .line 56
    const/4 v6, 0x1

    .line 57
    const-string v7, "/device/v1/{0}/message/?deviceid={1}&wm={2}"

    .line 58
    .line 59
    const-string v8, "application/json"

    .line 60
    .line 61
    invoke-direct/range {v2 .. v10}, Lcom/salesforce/marketingcloud/http/b;-><init>(Ljava/lang/String;ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    sput-object v2, Lcom/salesforce/marketingcloud/http/b;->k:Lcom/salesforce/marketingcloud/http/b;

    .line 65
    .line 66
    new-instance v3, Lcom/salesforce/marketingcloud/http/b;

    .line 67
    .line 68
    iget-object v6, v2, Lcom/salesforce/marketingcloud/http/b;->g:Ljava/lang/String;

    .line 69
    .line 70
    iget v7, v2, Lcom/salesforce/marketingcloud/http/b;->b:I

    .line 71
    .line 72
    iget-object v8, v2, Lcom/salesforce/marketingcloud/http/b;->c:Ljava/lang/String;

    .line 73
    .line 74
    iget-object v9, v2, Lcom/salesforce/marketingcloud/http/b;->e:Ljava/lang/String;

    .line 75
    .line 76
    iget-object v10, v2, Lcom/salesforce/marketingcloud/http/b;->f:Ljava/lang/String;

    .line 77
    .line 78
    iget-object v11, v2, Lcom/salesforce/marketingcloud/http/b;->d:Ljava/lang/String;

    .line 79
    .line 80
    const/4 v5, 0x3

    .line 81
    const-wide/32 v12, 0xea60

    .line 82
    .line 83
    .line 84
    const-string v4, "USER_INITIATED_INBOX_MESSAGE"

    .line 85
    .line 86
    invoke-direct/range {v3 .. v13}, Lcom/salesforce/marketingcloud/http/b;-><init>(Ljava/lang/String;ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;J)V

    .line 87
    .line 88
    .line 89
    sput-object v3, Lcom/salesforce/marketingcloud/http/b;->l:Lcom/salesforce/marketingcloud/http/b;

    .line 90
    .line 91
    new-instance v4, Lcom/salesforce/marketingcloud/http/b;

    .line 92
    .line 93
    const-string v11, "application/json"

    .line 94
    .line 95
    const-string v12, "inbox_status_next_retry_time"

    .line 96
    .line 97
    const-string v5, "INBOX_STATUS"

    .line 98
    .line 99
    const/4 v6, 0x4

    .line 100
    const-string v7, "PATCH"

    .line 101
    .line 102
    const/4 v8, 0x1

    .line 103
    const-string v9, "/device/v1/{0}/message"

    .line 104
    .line 105
    const-string v10, "application/json"

    .line 106
    .line 107
    invoke-direct/range {v4 .. v12}, Lcom/salesforce/marketingcloud/http/b;-><init>(Ljava/lang/String;ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    sput-object v4, Lcom/salesforce/marketingcloud/http/b;->m:Lcom/salesforce/marketingcloud/http/b;

    .line 111
    .line 112
    new-instance v5, Lcom/salesforce/marketingcloud/http/b;

    .line 113
    .line 114
    const-string v12, "application/json"

    .line 115
    .line 116
    const-string v13, "geofence_next_retry_time"

    .line 117
    .line 118
    const-string v6, "GEOFENCE_MESSAGE"

    .line 119
    .line 120
    const/4 v7, 0x5

    .line 121
    const-string v8, "GET"

    .line 122
    .line 123
    const/4 v9, 0x1

    .line 124
    const-string v10, "/device/v1/location/{0}/fence/?latitude={1,number,#.########}&longitude={2,number,#.########}&deviceid={3}"

    .line 125
    .line 126
    const-string v11, "application/json"

    .line 127
    .line 128
    invoke-direct/range {v5 .. v13}, Lcom/salesforce/marketingcloud/http/b;-><init>(Ljava/lang/String;ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    sput-object v5, Lcom/salesforce/marketingcloud/http/b;->n:Lcom/salesforce/marketingcloud/http/b;

    .line 132
    .line 133
    new-instance v6, Lcom/salesforce/marketingcloud/http/b;

    .line 134
    .line 135
    const-string v13, "application/json"

    .line 136
    .line 137
    const-string v14, "proximity_next_retry_time"

    .line 138
    .line 139
    const-string v7, "PROXIMITY_MESSAGES"

    .line 140
    .line 141
    const/4 v8, 0x6

    .line 142
    const-string v9, "GET"

    .line 143
    .line 144
    const/4 v10, 0x1

    .line 145
    const-string v11, "/device/v1/location/{0}/proximity/?latitude={1,number,#.########}&longitude={2,number,#.########}&deviceid={3}"

    .line 146
    .line 147
    const-string v12, "application/json"

    .line 148
    .line 149
    invoke-direct/range {v6 .. v14}, Lcom/salesforce/marketingcloud/http/b;-><init>(Ljava/lang/String;ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    sput-object v6, Lcom/salesforce/marketingcloud/http/b;->o:Lcom/salesforce/marketingcloud/http/b;

    .line 153
    .line 154
    new-instance v7, Lcom/salesforce/marketingcloud/http/b;

    .line 155
    .line 156
    const-string v15, "registration_next_retry_time"

    .line 157
    .line 158
    const-wide/32 v16, 0xea60

    .line 159
    .line 160
    .line 161
    const-string v8, "REGISTRATION"

    .line 162
    .line 163
    const/4 v9, 0x7

    .line 164
    const-string v10, "POST"

    .line 165
    .line 166
    const/4 v11, 0x1

    .line 167
    const-string v12, "/device/v1/registration"

    .line 168
    .line 169
    const-string v13, "application/json"

    .line 170
    .line 171
    const-string v14, "application/json"

    .line 172
    .line 173
    invoke-direct/range {v7 .. v17}, Lcom/salesforce/marketingcloud/http/b;-><init>(Ljava/lang/String;ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;J)V

    .line 174
    .line 175
    .line 176
    sput-object v7, Lcom/salesforce/marketingcloud/http/b;->p:Lcom/salesforce/marketingcloud/http/b;

    .line 177
    .line 178
    new-instance v8, Lcom/salesforce/marketingcloud/http/b;

    .line 179
    .line 180
    const-string v15, "application/json"

    .line 181
    .line 182
    const-string v16, "sync_next_retry_time"

    .line 183
    .line 184
    const-string v9, "SYNC"

    .line 185
    .line 186
    const/16 v10, 0x8

    .line 187
    .line 188
    const-string v11, "POST"

    .line 189
    .line 190
    const/4 v12, 0x1

    .line 191
    const-string v13, "/device/v1/{0}/sync/{1}"

    .line 192
    .line 193
    const-string v14, "application/json"

    .line 194
    .line 195
    invoke-direct/range {v8 .. v16}, Lcom/salesforce/marketingcloud/http/b;-><init>(Ljava/lang/String;ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 196
    .line 197
    .line 198
    sput-object v8, Lcom/salesforce/marketingcloud/http/b;->q:Lcom/salesforce/marketingcloud/http/b;

    .line 199
    .line 200
    new-instance v9, Lcom/salesforce/marketingcloud/http/b;

    .line 201
    .line 202
    const-string v16, "application/json"

    .line 203
    .line 204
    const-string v17, "et_device_stats_retry_after"

    .line 205
    .line 206
    const-string v10, "DEVICE_STATS"

    .line 207
    .line 208
    const/16 v11, 0x9

    .line 209
    .line 210
    const-string v12, "POST"

    .line 211
    .line 212
    const/4 v13, 0x1

    .line 213
    const-string v14, "/devicestatistics/v1/analytic"

    .line 214
    .line 215
    const-string v15, "application/json"

    .line 216
    .line 217
    invoke-direct/range {v9 .. v17}, Lcom/salesforce/marketingcloud/http/b;-><init>(Ljava/lang/String;ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 218
    .line 219
    .line 220
    sput-object v9, Lcom/salesforce/marketingcloud/http/b;->r:Lcom/salesforce/marketingcloud/http/b;

    .line 221
    .line 222
    new-instance v0, Lcom/salesforce/marketingcloud/http/b;

    .line 223
    .line 224
    const-string v7, "application/json"

    .line 225
    .line 226
    const-string v8, "et_events_retry_after"

    .line 227
    .line 228
    const-string v1, "EVENTS"

    .line 229
    .line 230
    const/16 v2, 0xa

    .line 231
    .line 232
    const-string v3, "POST"

    .line 233
    .line 234
    const/4 v4, 0x1

    .line 235
    const-string v5, "/devicestatistics/v1/event"

    .line 236
    .line 237
    const-string v6, "application/json"

    .line 238
    .line 239
    invoke-direct/range {v0 .. v8}, Lcom/salesforce/marketingcloud/http/b;-><init>(Ljava/lang/String;ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 240
    .line 241
    .line 242
    sput-object v0, Lcom/salesforce/marketingcloud/http/b;->s:Lcom/salesforce/marketingcloud/http/b;

    .line 243
    .line 244
    invoke-static {}, Lcom/salesforce/marketingcloud/http/b;->a()[Lcom/salesforce/marketingcloud/http/b;

    .line 245
    .line 246
    .line 247
    move-result-object v0

    .line 248
    sput-object v0, Lcom/salesforce/marketingcloud/http/b;->C:[Lcom/salesforce/marketingcloud/http/b;

    .line 249
    .line 250
    sget-object v0, Lcom/salesforce/marketingcloud/util/j;->a:Ljava/util/Locale;

    .line 251
    .line 252
    invoke-static {}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->getSdkVersionName()Ljava/lang/String;

    .line 253
    .line 254
    .line 255
    move-result-object v0

    .line 256
    sget-object v1, Landroid/os/Build$VERSION;->RELEASE:Ljava/lang/String;

    .line 257
    .line 258
    sget-object v2, Landroid/os/Build;->MANUFACTURER:Ljava/lang/String;

    .line 259
    .line 260
    sget-object v3, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 261
    .line 262
    const-string v4, " (Android "

    .line 263
    .line 264
    const-string v5, "; %s; "

    .line 265
    .line 266
    const-string v6, "MarketingCloudSdk/"

    .line 267
    .line 268
    invoke-static {v6, v0, v4, v1, v5}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 269
    .line 270
    .line 271
    move-result-object v0

    .line 272
    const-string v1, "/"

    .line 273
    .line 274
    const-string v4, ") %s/%s"

    .line 275
    .line 276
    invoke-static {v0, v2, v1, v3, v4}, Lvj/b;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 277
    .line 278
    .line 279
    move-result-object v0

    .line 280
    sput-object v0, Lcom/salesforce/marketingcloud/http/b;->A:Ljava/lang/String;

    .line 281
    .line 282
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 11
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "I",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ")V"
        }
    .end annotation

    const-wide/16 v9, 0x0

    move-object v0, p0

    move-object v1, p1

    move v2, p2

    move-object v3, p3

    move v4, p4

    move-object/from16 v5, p5

    move-object/from16 v6, p6

    move-object/from16 v7, p7

    move-object/from16 v8, p8

    .line 1
    invoke-direct/range {v0 .. v10}, Lcom/salesforce/marketingcloud/http/b;-><init>(Ljava/lang/String;ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;J)V

    return-void
.end method

.method private constructor <init>(Ljava/lang/String;ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;J)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "I",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "J)V"
        }
    .end annotation

    .line 2
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 3
    iput-object p3, p0, Lcom/salesforce/marketingcloud/http/b;->g:Ljava/lang/String;

    .line 4
    iput p4, p0, Lcom/salesforce/marketingcloud/http/b;->b:I

    .line 5
    iput-object p5, p0, Lcom/salesforce/marketingcloud/http/b;->c:Ljava/lang/String;

    .line 6
    iput-object p6, p0, Lcom/salesforce/marketingcloud/http/b;->e:Ljava/lang/String;

    .line 7
    iput-object p7, p0, Lcom/salesforce/marketingcloud/http/b;->f:Ljava/lang/String;

    .line 8
    iput-object p8, p0, Lcom/salesforce/marketingcloud/http/b;->d:Ljava/lang/String;

    const-wide/16 p1, 0x0

    cmp-long p3, p9, p1

    if-gez p3, :cond_0

    move-wide p9, p1

    .line 9
    :cond_0
    iput-wide p9, p0, Lcom/salesforce/marketingcloud/http/b;->h:J

    return-void
.end method

.method private a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/b;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;)Lcom/salesforce/marketingcloud/http/c;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/MarketingCloudConfig;",
            "Lcom/salesforce/marketingcloud/storage/b;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;)",
            "Lcom/salesforce/marketingcloud/http/c;"
        }
    .end annotation

    const-string v0, "MCRequest"

    const-string v1, "Bearer "

    const/4 v2, 0x0

    .line 61
    :try_start_0
    invoke-direct {p0, p3, p4}, Lcom/salesforce/marketingcloud/http/b;->a(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p3

    .line 62
    const-string p4, "Executing %s request ..."

    filled-new-array {p3}, [Ljava/lang/Object;

    move-result-object v3

    invoke-static {v0, p4, v3}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 63
    invoke-static {}, Lcom/salesforce/marketingcloud/http/c;->b()Lcom/salesforce/marketingcloud/http/c$a;

    move-result-object p4

    iget-object v3, p0, Lcom/salesforce/marketingcloud/http/b;->g:Ljava/lang/String;

    invoke-virtual {p4, v3}, Lcom/salesforce/marketingcloud/http/c$a;->b(Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/c$a;

    move-result-object p4

    invoke-virtual {p4, p0}, Lcom/salesforce/marketingcloud/http/c$a;->a(Lcom/salesforce/marketingcloud/http/b;)Lcom/salesforce/marketingcloud/http/c$a;

    move-result-object p4

    iget-object v3, p0, Lcom/salesforce/marketingcloud/http/b;->e:Ljava/lang/String;

    invoke-virtual {p4, v3}, Lcom/salesforce/marketingcloud/http/c$a;->a(Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/c$a;

    move-result-object p4

    invoke-virtual {p4, p3}, Lcom/salesforce/marketingcloud/http/c$a;->d(Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/c$a;

    move-result-object p3

    if-eqz p5, :cond_0

    .line 64
    invoke-virtual {p3, p5}, Lcom/salesforce/marketingcloud/http/c$a;->c(Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/c$a;

    goto :goto_0

    :catch_0
    move-exception p0

    goto :goto_2

    .line 65
    :cond_0
    :goto_0
    const-string p4, "user-agent"

    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/http/b;->b(Lcom/salesforce/marketingcloud/MarketingCloudConfig;)Ljava/lang/String;

    move-result-object p5

    invoke-virtual {p3, p4, p5}, Lcom/salesforce/marketingcloud/http/c$a;->a(Ljava/lang/String;Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/c$a;

    .line 66
    const-string p4, "authorization"

    sget-object p5, Lcom/salesforce/marketingcloud/util/j;->a:Ljava/util/Locale;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->accessToken()Ljava/lang/String;

    move-result-object p1

    new-instance p5, Ljava/lang/StringBuilder;

    invoke-direct {p5, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p5, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p3, p4, p1}, Lcom/salesforce/marketingcloud/http/c$a;->a(Ljava/lang/String;Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/c$a;

    .line 67
    const-string p1, "accept"

    iget-object p0, p0, Lcom/salesforce/marketingcloud/http/b;->f:Ljava/lang/String;

    invoke-virtual {p3, p1, p0}, Lcom/salesforce/marketingcloud/http/c$a;->a(Ljava/lang/String;Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/c$a;

    .line 68
    const-string p0, "x-sdk-version"

    invoke-static {}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->getSdkVersionName()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p3, p0, p1}, Lcom/salesforce/marketingcloud/http/c$a;->a(Ljava/lang/String;Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/c$a;

    .line 69
    const-string p0, "subscriber_jwt"

    invoke-interface {p2, p0, v2}, Lcom/salesforce/marketingcloud/storage/b;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    if-eqz p0, :cond_1

    .line 70
    const-string p1, "x-subscriber-token"

    invoke-virtual {p3, p1, p0}, Lcom/salesforce/marketingcloud/http/c$a;->a(Ljava/lang/String;Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/c$a;

    :cond_1
    if-eqz p6, :cond_2

    .line 71
    invoke-interface {p6}, Ljava/util/Map;->isEmpty()Z

    move-result p0

    if-nez p0, :cond_2

    .line 72
    invoke-interface {p6}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    move-result-object p0

    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result p1

    if-eqz p1, :cond_2

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/Map$Entry;

    .line 73
    invoke-interface {p1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/lang/String;

    invoke-interface {p1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/String;

    invoke-virtual {p3, p2, p1}, Lcom/salesforce/marketingcloud/http/c$a;->a(Ljava/lang/String;Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/c$a;

    goto :goto_1

    .line 74
    :cond_2
    invoke-virtual {p3}, Lcom/salesforce/marketingcloud/http/c$a;->a()Lcom/salesforce/marketingcloud/http/c;

    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object p0

    :goto_2
    const/4 p1, 0x0

    .line 75
    new-array p1, p1, [Ljava/lang/Object;

    const-string p2, "Failed to execute request."

    invoke-static {v0, p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-object v2
.end method

.method private a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;)Ljava/lang/String;
    .locals 1

    .line 59
    iget p0, p0, Lcom/salesforce/marketingcloud/http/b;->b:I

    const/4 v0, 0x1

    if-ne p0, v0, :cond_0

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->marketingCloudServerUrl()Ljava/lang/String;

    move-result-object p0

    return-object p0

    .line 60
    :cond_0
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->predictiveIntelligenceServerUrl()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method private a(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 38
    const-string p0, "/"

    invoke-virtual {p1, p0}, Ljava/lang/String;->endsWith(Ljava/lang/String;)Z

    move-result p0

    if-eqz p0, :cond_0

    .line 39
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result p0

    add-int/lit8 p0, p0, -0x1

    const/4 v0, 0x0

    invoke-virtual {p1, v0, p0}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object p1

    .line 40
    :cond_0
    new-instance p0, Ljava/net/URL;

    sget-object v0, Lcom/salesforce/marketingcloud/util/j;->a:Ljava/util/Locale;

    .line 41
    invoke-static {p1, p2}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    .line 42
    invoke-direct {p0, p1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0}, Ljava/net/URL;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method private static a(Ljava/util/Map;Ljava/lang/String;)Ljava/util/List;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;>;",
            "Ljava/lang/String;",
            ")",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 11
    invoke-interface {p0}, Ljava/util/Map;->keySet()Ljava/util/Set;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    if-eqz v1, :cond_0

    .line 12
    invoke-virtual {v1, p1}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    move-result v2

    if-eqz v2, :cond_0

    .line 13
    invoke-interface {p0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ljava/util/List;

    return-object p0

    :cond_1
    const/4 p0, 0x0

    return-object p0
.end method

.method public static a(Ljava/util/Map;Lcom/salesforce/marketingcloud/storage/b;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;>;",
            "Lcom/salesforce/marketingcloud/storage/b;",
            ")V"
        }
    .end annotation

    if-eqz p0, :cond_2

    .line 5
    invoke-interface {p0}, Ljava/util/Map;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    .line 6
    :cond_0
    const-string v0, "x-subscriber-token"

    invoke-static {p0, v0}, Lcom/salesforce/marketingcloud/http/b;->a(Ljava/util/Map;Ljava/lang/String;)Ljava/util/List;

    move-result-object p0

    if-eqz p0, :cond_2

    .line 7
    invoke-interface {p0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_2

    const/4 v0, 0x0

    invoke-interface {p0, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ljava/lang/String;

    if-eqz p0, :cond_2

    .line 8
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_1

    goto :goto_0

    .line 9
    :cond_1
    const-string v0, "subscriber_jwt"

    invoke-interface {p1, v0, p0}, Lcom/salesforce/marketingcloud/storage/b;->a(Ljava/lang/String;Ljava/lang/String;)V

    :cond_2
    :goto_0
    return-void
.end method

.method public static a(Lcom/salesforce/marketingcloud/storage/h;)Z
    .locals 2

    .line 10
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    move-result-object p0

    const-string v0, "subscriber_jwt"

    const/4 v1, 0x0

    invoke-interface {p0, v0, v1}, Lcom/salesforce/marketingcloud/storage/b;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    if-eqz p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method private static synthetic a()[Lcom/salesforce/marketingcloud/http/b;
    .locals 11

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/http/b;->i:Lcom/salesforce/marketingcloud/http/b;

    sget-object v1, Lcom/salesforce/marketingcloud/http/b;->j:Lcom/salesforce/marketingcloud/http/b;

    sget-object v2, Lcom/salesforce/marketingcloud/http/b;->k:Lcom/salesforce/marketingcloud/http/b;

    sget-object v3, Lcom/salesforce/marketingcloud/http/b;->l:Lcom/salesforce/marketingcloud/http/b;

    sget-object v4, Lcom/salesforce/marketingcloud/http/b;->m:Lcom/salesforce/marketingcloud/http/b;

    sget-object v5, Lcom/salesforce/marketingcloud/http/b;->n:Lcom/salesforce/marketingcloud/http/b;

    sget-object v6, Lcom/salesforce/marketingcloud/http/b;->o:Lcom/salesforce/marketingcloud/http/b;

    sget-object v7, Lcom/salesforce/marketingcloud/http/b;->p:Lcom/salesforce/marketingcloud/http/b;

    sget-object v8, Lcom/salesforce/marketingcloud/http/b;->q:Lcom/salesforce/marketingcloud/http/b;

    sget-object v9, Lcom/salesforce/marketingcloud/http/b;->r:Lcom/salesforce/marketingcloud/http/b;

    sget-object v10, Lcom/salesforce/marketingcloud/http/b;->s:Lcom/salesforce/marketingcloud/http/b;

    filled-new-array/range {v0 .. v10}, [Lcom/salesforce/marketingcloud/http/b;

    move-result-object v0

    return-object v0
.end method

.method public static a(Ljava/lang/String;)[Ljava/lang/Object;
    .locals 0

    .line 4
    filled-new-array {p0}, [Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public static a(Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/location/LatLon;)[Ljava/lang/Object;
    .locals 3

    .line 2
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/location/LatLon;->latitude()D

    move-result-wide v0

    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v0

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/location/LatLon;->longitude()D

    move-result-wide v1

    invoke-static {v1, v2}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object p2

    filled-new-array {p0, v0, p2, p1}, [Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public static a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)[Ljava/lang/Object;
    .locals 0

    .line 3
    filled-new-array {p0, p1, p2}, [Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method private b(Lcom/salesforce/marketingcloud/MarketingCloudConfig;)Ljava/lang/String;
    .locals 3

    .line 9
    sget-object p0, Lcom/salesforce/marketingcloud/util/j;->a:Ljava/util/Locale;

    sget-object v0, Lcom/salesforce/marketingcloud/http/b;->A:Ljava/lang/String;

    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    move-result-object v1

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->appPackageName()Ljava/lang/String;

    move-result-object v2

    .line 10
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->appVersionName()Ljava/lang/String;

    move-result-object p1

    filled-new-array {v1, v2, p1}, [Ljava/lang/Object;

    move-result-object p1

    .line 11
    invoke-static {p0, v0, p1}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static b(Ljava/lang/String;Ljava/lang/String;)[Ljava/lang/Object;
    .locals 0

    .line 1
    filled-new-array {p0, p1}, [Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public static valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/b;
    .locals 1

    .line 1
    const-class v0, Lcom/salesforce/marketingcloud/http/b;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/salesforce/marketingcloud/http/b;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcom/salesforce/marketingcloud/http/b;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/http/b;->C:[Lcom/salesforce/marketingcloud/http/b;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lcom/salesforce/marketingcloud/http/b;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/salesforce/marketingcloud/http/b;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public a(Landroid/content/SharedPreferences;)J
    .locals 4

    .line 32
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/http/b;->h:J

    const-wide/16 v2, 0x0

    cmp-long v0, v0, v2

    if-lez v0, :cond_0

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    iget-object p0, p0, Lcom/salesforce/marketingcloud/http/b;->d:Ljava/lang/String;

    const-string v1, "_device"

    .line 33
    invoke-static {v0, p0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    .line 34
    invoke-interface {p1, p0, v2, v3}, Landroid/content/SharedPreferences;->getLong(Ljava/lang/String;J)J

    move-result-wide p0

    return-wide p0

    :cond_0
    return-wide v2
.end method

.method public a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/b;Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/c;
    .locals 7

    .line 51
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/http/b;->a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;)Ljava/lang/String;

    move-result-object v3

    iget-object v4, p0, Lcom/salesforce/marketingcloud/http/b;->c:Ljava/lang/String;

    const/4 v6, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v5, p3

    invoke-direct/range {v0 .. v6}, Lcom/salesforce/marketingcloud/http/b;->a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/b;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;)Lcom/salesforce/marketingcloud/http/c;

    move-result-object p0

    return-object p0
.end method

.method public a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/b;Ljava/lang/String;Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/c;
    .locals 7

    .line 52
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/http/b;->a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;)Ljava/lang/String;

    move-result-object v3

    if-eqz p4, :cond_0

    :goto_0
    move-object v4, p4

    goto :goto_1

    :cond_0
    iget-object p4, p0, Lcom/salesforce/marketingcloud/http/b;->c:Ljava/lang/String;

    goto :goto_0

    :goto_1
    const/4 v6, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v5, p3

    invoke-direct/range {v0 .. v6}, Lcom/salesforce/marketingcloud/http/b;->a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/b;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;)Lcom/salesforce/marketingcloud/http/c;

    move-result-object p0

    return-object p0
.end method

.method public a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/b;[Ljava/lang/Object;)Lcom/salesforce/marketingcloud/http/c;
    .locals 7

    .line 48
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/http/b;->a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;)Ljava/lang/String;

    move-result-object v3

    new-instance v0, Ljava/text/MessageFormat;

    iget-object v1, p0, Lcom/salesforce/marketingcloud/http/b;->c:Ljava/lang/String;

    sget-object v2, Lcom/salesforce/marketingcloud/util/j;->a:Ljava/util/Locale;

    invoke-direct {v0, v1, v2}, Ljava/text/MessageFormat;-><init>(Ljava/lang/String;Ljava/util/Locale;)V

    .line 49
    invoke-virtual {v0, p3}, Ljava/text/Format;->format(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v4

    const/4 v5, 0x0

    const/4 v6, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    .line 50
    invoke-direct/range {v0 .. v6}, Lcom/salesforce/marketingcloud/http/b;->a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/b;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;)Lcom/salesforce/marketingcloud/http/c;

    move-result-object p0

    return-object p0
.end method

.method public a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/b;[Ljava/lang/Object;Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/c;
    .locals 7

    .line 53
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/http/b;->a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;)Ljava/lang/String;

    move-result-object v3

    new-instance v0, Ljava/text/MessageFormat;

    iget-object v1, p0, Lcom/salesforce/marketingcloud/http/b;->c:Ljava/lang/String;

    sget-object v2, Lcom/salesforce/marketingcloud/util/j;->a:Ljava/util/Locale;

    invoke-direct {v0, v1, v2}, Ljava/text/MessageFormat;-><init>(Ljava/lang/String;Ljava/util/Locale;)V

    .line 54
    invoke-virtual {v0, p3}, Ljava/text/Format;->format(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v4

    const/4 v6, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v5, p4

    .line 55
    invoke-direct/range {v0 .. v6}, Lcom/salesforce/marketingcloud/http/b;->a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/b;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;)Lcom/salesforce/marketingcloud/http/c;

    move-result-object p0

    return-object p0
.end method

.method public a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/b;[Ljava/lang/Object;Ljava/lang/String;Ljava/util/Map;)Lcom/salesforce/marketingcloud/http/c;
    .locals 7
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/MarketingCloudConfig;",
            "Lcom/salesforce/marketingcloud/storage/b;",
            "[",
            "Ljava/lang/Object;",
            "Ljava/lang/String;",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;)",
            "Lcom/salesforce/marketingcloud/http/c;"
        }
    .end annotation

    .line 56
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/http/b;->a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;)Ljava/lang/String;

    move-result-object v3

    new-instance v0, Ljava/text/MessageFormat;

    iget-object v1, p0, Lcom/salesforce/marketingcloud/http/b;->c:Ljava/lang/String;

    sget-object v2, Lcom/salesforce/marketingcloud/util/j;->a:Ljava/util/Locale;

    invoke-direct {v0, v1, v2}, Ljava/text/MessageFormat;-><init>(Ljava/lang/String;Ljava/util/Locale;)V

    .line 57
    invoke-virtual {v0, p3}, Ljava/text/Format;->format(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v4

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v5, p4

    move-object v6, p5

    .line 58
    invoke-direct/range {v0 .. v6}, Lcom/salesforce/marketingcloud/http/b;->a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/b;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;)Lcom/salesforce/marketingcloud/http/c;

    move-result-object p0

    return-object p0
.end method

.method public a(Landroid/content/SharedPreferences;Lcom/salesforce/marketingcloud/http/f;)V
    .locals 8

    .line 14
    invoke-interface {p1}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object p1

    .line 15
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->p()Z

    move-result v0

    if-eqz v0, :cond_0

    iget-wide v0, p0, Lcom/salesforce/marketingcloud/http/b;->h:J

    const-wide/16 v2, 0x0

    cmp-long v0, v0, v2

    if-lez v0, :cond_0

    .line 16
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v1, p0, Lcom/salesforce/marketingcloud/http/b;->d:Ljava/lang/String;

    const-string v2, "_device"

    .line 17
    invoke-static {v0, v1, v2}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    .line 18
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->l()J

    move-result-wide v1

    iget-wide v3, p0, Lcom/salesforce/marketingcloud/http/b;->h:J

    add-long/2addr v1, v3

    invoke-interface {p1, v0, v1, v2}, Landroid/content/SharedPreferences$Editor;->putLong(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;

    .line 19
    :cond_0
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->m()Ljava/util/Map;

    move-result-object v0

    .line 20
    const-string v1, "retry-after"

    invoke-static {v0, v1}, Lcom/salesforce/marketingcloud/http/b;->a(Ljava/util/Map;Ljava/lang/String;)Ljava/util/List;

    move-result-object v0

    if-eqz v0, :cond_2

    .line 21
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_2

    const/4 v1, 0x0

    .line 22
    invoke-interface {v0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    .line 23
    :try_start_0
    invoke-static {v0}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    move-result-wide v2

    const-wide/16 v4, 0x3e8

    mul-long/2addr v2, v4

    .line 24
    iget-object p0, p0, Lcom/salesforce/marketingcloud/http/b;->d:Ljava/lang/String;

    .line 25
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->l()J

    move-result-wide v4

    const-wide/32 v6, 0x5265c00

    cmp-long p2, v2, v6

    if-lez p2, :cond_1

    move-wide v2, v6

    :cond_1
    add-long/2addr v4, v2

    .line 26
    invoke-interface {p1, p0, v4, v5}, Landroid/content/SharedPreferences$Editor;->putLong(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p0

    .line 27
    new-array p2, v1, [Ljava/lang/Object;

    const-string v0, "MCRequest"

    const-string v1, "Unable to parse Retry-After value."

    invoke-static {v0, p0, v1, p2}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 28
    :cond_2
    :goto_0
    invoke-interface {p1}, Landroid/content/SharedPreferences$Editor;->apply()V

    return-void
.end method

.method public b(Landroid/content/SharedPreferences;)V
    .locals 5

    .line 2
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/http/b;->h:J

    const-wide/16 v2, 0x0

    cmp-long v0, v0, v2

    if-lez v0, :cond_0

    .line 3
    invoke-interface {p1}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object p1

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v1, p0, Lcom/salesforce/marketingcloud/http/b;->d:Ljava/lang/String;

    const-string v2, "_device"

    .line 4
    invoke-static {v0, v1, v2}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    .line 5
    iget-wide v1, p0, Lcom/salesforce/marketingcloud/http/b;->h:J

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v3

    add-long/2addr v3, v1

    invoke-interface {p1, v0, v3, v4}, Landroid/content/SharedPreferences$Editor;->putLong(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;

    move-result-object p0

    invoke-interface {p0}, Landroid/content/SharedPreferences$Editor;->apply()V

    :cond_0
    return-void
.end method

.method public c(Landroid/content/SharedPreferences;)J
    .locals 2

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/http/b;->d:Ljava/lang/String;

    .line 2
    .line 3
    const-wide/16 v0, 0x0

    .line 4
    .line 5
    invoke-interface {p1, p0, v0, v1}, Landroid/content/SharedPreferences;->getLong(Ljava/lang/String;J)J

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    return-wide p0
.end method
