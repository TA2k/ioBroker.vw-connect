.class public final enum Lio/opentelemetry/api/logs/Severity;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lio/opentelemetry/api/logs/Severity;",
        ">;"
    }
.end annotation


# static fields
.field private static final synthetic $VALUES:[Lio/opentelemetry/api/logs/Severity;

.field public static final enum DEBUG:Lio/opentelemetry/api/logs/Severity;

.field public static final enum DEBUG2:Lio/opentelemetry/api/logs/Severity;

.field public static final enum DEBUG3:Lio/opentelemetry/api/logs/Severity;

.field public static final enum DEBUG4:Lio/opentelemetry/api/logs/Severity;

.field public static final enum ERROR:Lio/opentelemetry/api/logs/Severity;

.field public static final enum ERROR2:Lio/opentelemetry/api/logs/Severity;

.field public static final enum ERROR3:Lio/opentelemetry/api/logs/Severity;

.field public static final enum ERROR4:Lio/opentelemetry/api/logs/Severity;

.field public static final enum FATAL:Lio/opentelemetry/api/logs/Severity;

.field public static final enum FATAL2:Lio/opentelemetry/api/logs/Severity;

.field public static final enum FATAL3:Lio/opentelemetry/api/logs/Severity;

.field public static final enum FATAL4:Lio/opentelemetry/api/logs/Severity;

.field public static final enum INFO:Lio/opentelemetry/api/logs/Severity;

.field public static final enum INFO2:Lio/opentelemetry/api/logs/Severity;

.field public static final enum INFO3:Lio/opentelemetry/api/logs/Severity;

.field public static final enum INFO4:Lio/opentelemetry/api/logs/Severity;

.field public static final enum TRACE:Lio/opentelemetry/api/logs/Severity;

.field public static final enum TRACE2:Lio/opentelemetry/api/logs/Severity;

.field public static final enum TRACE3:Lio/opentelemetry/api/logs/Severity;

.field public static final enum TRACE4:Lio/opentelemetry/api/logs/Severity;

.field public static final enum UNDEFINED_SEVERITY_NUMBER:Lio/opentelemetry/api/logs/Severity;

.field public static final enum WARN:Lio/opentelemetry/api/logs/Severity;

.field public static final enum WARN2:Lio/opentelemetry/api/logs/Severity;

.field public static final enum WARN3:Lio/opentelemetry/api/logs/Severity;

.field public static final enum WARN4:Lio/opentelemetry/api/logs/Severity;


# instance fields
.field private final severityNumber:I


# direct methods
.method private static synthetic $values()[Lio/opentelemetry/api/logs/Severity;
    .locals 26

    .line 1
    sget-object v1, Lio/opentelemetry/api/logs/Severity;->UNDEFINED_SEVERITY_NUMBER:Lio/opentelemetry/api/logs/Severity;

    .line 2
    .line 3
    sget-object v2, Lio/opentelemetry/api/logs/Severity;->TRACE:Lio/opentelemetry/api/logs/Severity;

    .line 4
    .line 5
    sget-object v3, Lio/opentelemetry/api/logs/Severity;->TRACE2:Lio/opentelemetry/api/logs/Severity;

    .line 6
    .line 7
    sget-object v4, Lio/opentelemetry/api/logs/Severity;->TRACE3:Lio/opentelemetry/api/logs/Severity;

    .line 8
    .line 9
    sget-object v5, Lio/opentelemetry/api/logs/Severity;->TRACE4:Lio/opentelemetry/api/logs/Severity;

    .line 10
    .line 11
    sget-object v6, Lio/opentelemetry/api/logs/Severity;->DEBUG:Lio/opentelemetry/api/logs/Severity;

    .line 12
    .line 13
    sget-object v7, Lio/opentelemetry/api/logs/Severity;->DEBUG2:Lio/opentelemetry/api/logs/Severity;

    .line 14
    .line 15
    sget-object v8, Lio/opentelemetry/api/logs/Severity;->DEBUG3:Lio/opentelemetry/api/logs/Severity;

    .line 16
    .line 17
    sget-object v9, Lio/opentelemetry/api/logs/Severity;->DEBUG4:Lio/opentelemetry/api/logs/Severity;

    .line 18
    .line 19
    sget-object v10, Lio/opentelemetry/api/logs/Severity;->INFO:Lio/opentelemetry/api/logs/Severity;

    .line 20
    .line 21
    sget-object v11, Lio/opentelemetry/api/logs/Severity;->INFO2:Lio/opentelemetry/api/logs/Severity;

    .line 22
    .line 23
    sget-object v12, Lio/opentelemetry/api/logs/Severity;->INFO3:Lio/opentelemetry/api/logs/Severity;

    .line 24
    .line 25
    sget-object v13, Lio/opentelemetry/api/logs/Severity;->INFO4:Lio/opentelemetry/api/logs/Severity;

    .line 26
    .line 27
    sget-object v14, Lio/opentelemetry/api/logs/Severity;->WARN:Lio/opentelemetry/api/logs/Severity;

    .line 28
    .line 29
    sget-object v15, Lio/opentelemetry/api/logs/Severity;->WARN2:Lio/opentelemetry/api/logs/Severity;

    .line 30
    .line 31
    sget-object v16, Lio/opentelemetry/api/logs/Severity;->WARN3:Lio/opentelemetry/api/logs/Severity;

    .line 32
    .line 33
    sget-object v17, Lio/opentelemetry/api/logs/Severity;->WARN4:Lio/opentelemetry/api/logs/Severity;

    .line 34
    .line 35
    sget-object v18, Lio/opentelemetry/api/logs/Severity;->ERROR:Lio/opentelemetry/api/logs/Severity;

    .line 36
    .line 37
    sget-object v19, Lio/opentelemetry/api/logs/Severity;->ERROR2:Lio/opentelemetry/api/logs/Severity;

    .line 38
    .line 39
    sget-object v20, Lio/opentelemetry/api/logs/Severity;->ERROR3:Lio/opentelemetry/api/logs/Severity;

    .line 40
    .line 41
    sget-object v21, Lio/opentelemetry/api/logs/Severity;->ERROR4:Lio/opentelemetry/api/logs/Severity;

    .line 42
    .line 43
    sget-object v22, Lio/opentelemetry/api/logs/Severity;->FATAL:Lio/opentelemetry/api/logs/Severity;

    .line 44
    .line 45
    sget-object v23, Lio/opentelemetry/api/logs/Severity;->FATAL2:Lio/opentelemetry/api/logs/Severity;

    .line 46
    .line 47
    sget-object v24, Lio/opentelemetry/api/logs/Severity;->FATAL3:Lio/opentelemetry/api/logs/Severity;

    .line 48
    .line 49
    sget-object v25, Lio/opentelemetry/api/logs/Severity;->FATAL4:Lio/opentelemetry/api/logs/Severity;

    .line 50
    .line 51
    filled-new-array/range {v1 .. v25}, [Lio/opentelemetry/api/logs/Severity;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lio/opentelemetry/api/logs/Severity;

    .line 2
    .line 3
    const-string v1, "UNDEFINED_SEVERITY_NUMBER"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v2}, Lio/opentelemetry/api/logs/Severity;-><init>(Ljava/lang/String;II)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lio/opentelemetry/api/logs/Severity;->UNDEFINED_SEVERITY_NUMBER:Lio/opentelemetry/api/logs/Severity;

    .line 10
    .line 11
    new-instance v0, Lio/opentelemetry/api/logs/Severity;

    .line 12
    .line 13
    const-string v1, "TRACE"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2, v2}, Lio/opentelemetry/api/logs/Severity;-><init>(Ljava/lang/String;II)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Lio/opentelemetry/api/logs/Severity;->TRACE:Lio/opentelemetry/api/logs/Severity;

    .line 20
    .line 21
    new-instance v0, Lio/opentelemetry/api/logs/Severity;

    .line 22
    .line 23
    const-string v1, "TRACE2"

    .line 24
    .line 25
    const/4 v2, 0x2

    .line 26
    invoke-direct {v0, v1, v2, v2}, Lio/opentelemetry/api/logs/Severity;-><init>(Ljava/lang/String;II)V

    .line 27
    .line 28
    .line 29
    sput-object v0, Lio/opentelemetry/api/logs/Severity;->TRACE2:Lio/opentelemetry/api/logs/Severity;

    .line 30
    .line 31
    new-instance v0, Lio/opentelemetry/api/logs/Severity;

    .line 32
    .line 33
    const-string v1, "TRACE3"

    .line 34
    .line 35
    const/4 v2, 0x3

    .line 36
    invoke-direct {v0, v1, v2, v2}, Lio/opentelemetry/api/logs/Severity;-><init>(Ljava/lang/String;II)V

    .line 37
    .line 38
    .line 39
    sput-object v0, Lio/opentelemetry/api/logs/Severity;->TRACE3:Lio/opentelemetry/api/logs/Severity;

    .line 40
    .line 41
    new-instance v0, Lio/opentelemetry/api/logs/Severity;

    .line 42
    .line 43
    const-string v1, "TRACE4"

    .line 44
    .line 45
    const/4 v2, 0x4

    .line 46
    invoke-direct {v0, v1, v2, v2}, Lio/opentelemetry/api/logs/Severity;-><init>(Ljava/lang/String;II)V

    .line 47
    .line 48
    .line 49
    sput-object v0, Lio/opentelemetry/api/logs/Severity;->TRACE4:Lio/opentelemetry/api/logs/Severity;

    .line 50
    .line 51
    new-instance v0, Lio/opentelemetry/api/logs/Severity;

    .line 52
    .line 53
    const-string v1, "DEBUG"

    .line 54
    .line 55
    const/4 v2, 0x5

    .line 56
    invoke-direct {v0, v1, v2, v2}, Lio/opentelemetry/api/logs/Severity;-><init>(Ljava/lang/String;II)V

    .line 57
    .line 58
    .line 59
    sput-object v0, Lio/opentelemetry/api/logs/Severity;->DEBUG:Lio/opentelemetry/api/logs/Severity;

    .line 60
    .line 61
    new-instance v0, Lio/opentelemetry/api/logs/Severity;

    .line 62
    .line 63
    const-string v1, "DEBUG2"

    .line 64
    .line 65
    const/4 v2, 0x6

    .line 66
    invoke-direct {v0, v1, v2, v2}, Lio/opentelemetry/api/logs/Severity;-><init>(Ljava/lang/String;II)V

    .line 67
    .line 68
    .line 69
    sput-object v0, Lio/opentelemetry/api/logs/Severity;->DEBUG2:Lio/opentelemetry/api/logs/Severity;

    .line 70
    .line 71
    new-instance v0, Lio/opentelemetry/api/logs/Severity;

    .line 72
    .line 73
    const-string v1, "DEBUG3"

    .line 74
    .line 75
    const/4 v2, 0x7

    .line 76
    invoke-direct {v0, v1, v2, v2}, Lio/opentelemetry/api/logs/Severity;-><init>(Ljava/lang/String;II)V

    .line 77
    .line 78
    .line 79
    sput-object v0, Lio/opentelemetry/api/logs/Severity;->DEBUG3:Lio/opentelemetry/api/logs/Severity;

    .line 80
    .line 81
    new-instance v0, Lio/opentelemetry/api/logs/Severity;

    .line 82
    .line 83
    const-string v1, "DEBUG4"

    .line 84
    .line 85
    const/16 v2, 0x8

    .line 86
    .line 87
    invoke-direct {v0, v1, v2, v2}, Lio/opentelemetry/api/logs/Severity;-><init>(Ljava/lang/String;II)V

    .line 88
    .line 89
    .line 90
    sput-object v0, Lio/opentelemetry/api/logs/Severity;->DEBUG4:Lio/opentelemetry/api/logs/Severity;

    .line 91
    .line 92
    new-instance v0, Lio/opentelemetry/api/logs/Severity;

    .line 93
    .line 94
    const-string v1, "INFO"

    .line 95
    .line 96
    const/16 v2, 0x9

    .line 97
    .line 98
    invoke-direct {v0, v1, v2, v2}, Lio/opentelemetry/api/logs/Severity;-><init>(Ljava/lang/String;II)V

    .line 99
    .line 100
    .line 101
    sput-object v0, Lio/opentelemetry/api/logs/Severity;->INFO:Lio/opentelemetry/api/logs/Severity;

    .line 102
    .line 103
    new-instance v0, Lio/opentelemetry/api/logs/Severity;

    .line 104
    .line 105
    const-string v1, "INFO2"

    .line 106
    .line 107
    const/16 v2, 0xa

    .line 108
    .line 109
    invoke-direct {v0, v1, v2, v2}, Lio/opentelemetry/api/logs/Severity;-><init>(Ljava/lang/String;II)V

    .line 110
    .line 111
    .line 112
    sput-object v0, Lio/opentelemetry/api/logs/Severity;->INFO2:Lio/opentelemetry/api/logs/Severity;

    .line 113
    .line 114
    new-instance v0, Lio/opentelemetry/api/logs/Severity;

    .line 115
    .line 116
    const-string v1, "INFO3"

    .line 117
    .line 118
    const/16 v2, 0xb

    .line 119
    .line 120
    invoke-direct {v0, v1, v2, v2}, Lio/opentelemetry/api/logs/Severity;-><init>(Ljava/lang/String;II)V

    .line 121
    .line 122
    .line 123
    sput-object v0, Lio/opentelemetry/api/logs/Severity;->INFO3:Lio/opentelemetry/api/logs/Severity;

    .line 124
    .line 125
    new-instance v0, Lio/opentelemetry/api/logs/Severity;

    .line 126
    .line 127
    const-string v1, "INFO4"

    .line 128
    .line 129
    const/16 v2, 0xc

    .line 130
    .line 131
    invoke-direct {v0, v1, v2, v2}, Lio/opentelemetry/api/logs/Severity;-><init>(Ljava/lang/String;II)V

    .line 132
    .line 133
    .line 134
    sput-object v0, Lio/opentelemetry/api/logs/Severity;->INFO4:Lio/opentelemetry/api/logs/Severity;

    .line 135
    .line 136
    new-instance v0, Lio/opentelemetry/api/logs/Severity;

    .line 137
    .line 138
    const-string v1, "WARN"

    .line 139
    .line 140
    const/16 v2, 0xd

    .line 141
    .line 142
    invoke-direct {v0, v1, v2, v2}, Lio/opentelemetry/api/logs/Severity;-><init>(Ljava/lang/String;II)V

    .line 143
    .line 144
    .line 145
    sput-object v0, Lio/opentelemetry/api/logs/Severity;->WARN:Lio/opentelemetry/api/logs/Severity;

    .line 146
    .line 147
    new-instance v0, Lio/opentelemetry/api/logs/Severity;

    .line 148
    .line 149
    const-string v1, "WARN2"

    .line 150
    .line 151
    const/16 v2, 0xe

    .line 152
    .line 153
    invoke-direct {v0, v1, v2, v2}, Lio/opentelemetry/api/logs/Severity;-><init>(Ljava/lang/String;II)V

    .line 154
    .line 155
    .line 156
    sput-object v0, Lio/opentelemetry/api/logs/Severity;->WARN2:Lio/opentelemetry/api/logs/Severity;

    .line 157
    .line 158
    new-instance v0, Lio/opentelemetry/api/logs/Severity;

    .line 159
    .line 160
    const-string v1, "WARN3"

    .line 161
    .line 162
    const/16 v2, 0xf

    .line 163
    .line 164
    invoke-direct {v0, v1, v2, v2}, Lio/opentelemetry/api/logs/Severity;-><init>(Ljava/lang/String;II)V

    .line 165
    .line 166
    .line 167
    sput-object v0, Lio/opentelemetry/api/logs/Severity;->WARN3:Lio/opentelemetry/api/logs/Severity;

    .line 168
    .line 169
    new-instance v0, Lio/opentelemetry/api/logs/Severity;

    .line 170
    .line 171
    const-string v1, "WARN4"

    .line 172
    .line 173
    const/16 v2, 0x10

    .line 174
    .line 175
    invoke-direct {v0, v1, v2, v2}, Lio/opentelemetry/api/logs/Severity;-><init>(Ljava/lang/String;II)V

    .line 176
    .line 177
    .line 178
    sput-object v0, Lio/opentelemetry/api/logs/Severity;->WARN4:Lio/opentelemetry/api/logs/Severity;

    .line 179
    .line 180
    new-instance v0, Lio/opentelemetry/api/logs/Severity;

    .line 181
    .line 182
    const-string v1, "ERROR"

    .line 183
    .line 184
    const/16 v2, 0x11

    .line 185
    .line 186
    invoke-direct {v0, v1, v2, v2}, Lio/opentelemetry/api/logs/Severity;-><init>(Ljava/lang/String;II)V

    .line 187
    .line 188
    .line 189
    sput-object v0, Lio/opentelemetry/api/logs/Severity;->ERROR:Lio/opentelemetry/api/logs/Severity;

    .line 190
    .line 191
    new-instance v0, Lio/opentelemetry/api/logs/Severity;

    .line 192
    .line 193
    const-string v1, "ERROR2"

    .line 194
    .line 195
    const/16 v2, 0x12

    .line 196
    .line 197
    invoke-direct {v0, v1, v2, v2}, Lio/opentelemetry/api/logs/Severity;-><init>(Ljava/lang/String;II)V

    .line 198
    .line 199
    .line 200
    sput-object v0, Lio/opentelemetry/api/logs/Severity;->ERROR2:Lio/opentelemetry/api/logs/Severity;

    .line 201
    .line 202
    new-instance v0, Lio/opentelemetry/api/logs/Severity;

    .line 203
    .line 204
    const-string v1, "ERROR3"

    .line 205
    .line 206
    const/16 v2, 0x13

    .line 207
    .line 208
    invoke-direct {v0, v1, v2, v2}, Lio/opentelemetry/api/logs/Severity;-><init>(Ljava/lang/String;II)V

    .line 209
    .line 210
    .line 211
    sput-object v0, Lio/opentelemetry/api/logs/Severity;->ERROR3:Lio/opentelemetry/api/logs/Severity;

    .line 212
    .line 213
    new-instance v0, Lio/opentelemetry/api/logs/Severity;

    .line 214
    .line 215
    const-string v1, "ERROR4"

    .line 216
    .line 217
    const/16 v2, 0x14

    .line 218
    .line 219
    invoke-direct {v0, v1, v2, v2}, Lio/opentelemetry/api/logs/Severity;-><init>(Ljava/lang/String;II)V

    .line 220
    .line 221
    .line 222
    sput-object v0, Lio/opentelemetry/api/logs/Severity;->ERROR4:Lio/opentelemetry/api/logs/Severity;

    .line 223
    .line 224
    new-instance v0, Lio/opentelemetry/api/logs/Severity;

    .line 225
    .line 226
    const-string v1, "FATAL"

    .line 227
    .line 228
    const/16 v2, 0x15

    .line 229
    .line 230
    invoke-direct {v0, v1, v2, v2}, Lio/opentelemetry/api/logs/Severity;-><init>(Ljava/lang/String;II)V

    .line 231
    .line 232
    .line 233
    sput-object v0, Lio/opentelemetry/api/logs/Severity;->FATAL:Lio/opentelemetry/api/logs/Severity;

    .line 234
    .line 235
    new-instance v0, Lio/opentelemetry/api/logs/Severity;

    .line 236
    .line 237
    const/16 v1, 0x16

    .line 238
    .line 239
    const/16 v2, 0x16

    .line 240
    .line 241
    const-string v3, "FATAL2"

    .line 242
    .line 243
    invoke-direct {v0, v3, v1, v2}, Lio/opentelemetry/api/logs/Severity;-><init>(Ljava/lang/String;II)V

    .line 244
    .line 245
    .line 246
    sput-object v0, Lio/opentelemetry/api/logs/Severity;->FATAL2:Lio/opentelemetry/api/logs/Severity;

    .line 247
    .line 248
    new-instance v0, Lio/opentelemetry/api/logs/Severity;

    .line 249
    .line 250
    const/16 v1, 0x17

    .line 251
    .line 252
    const/16 v2, 0x17

    .line 253
    .line 254
    const-string v3, "FATAL3"

    .line 255
    .line 256
    invoke-direct {v0, v3, v1, v2}, Lio/opentelemetry/api/logs/Severity;-><init>(Ljava/lang/String;II)V

    .line 257
    .line 258
    .line 259
    sput-object v0, Lio/opentelemetry/api/logs/Severity;->FATAL3:Lio/opentelemetry/api/logs/Severity;

    .line 260
    .line 261
    new-instance v0, Lio/opentelemetry/api/logs/Severity;

    .line 262
    .line 263
    const/16 v1, 0x18

    .line 264
    .line 265
    const/16 v2, 0x18

    .line 266
    .line 267
    const-string v3, "FATAL4"

    .line 268
    .line 269
    invoke-direct {v0, v3, v1, v2}, Lio/opentelemetry/api/logs/Severity;-><init>(Ljava/lang/String;II)V

    .line 270
    .line 271
    .line 272
    sput-object v0, Lio/opentelemetry/api/logs/Severity;->FATAL4:Lio/opentelemetry/api/logs/Severity;

    .line 273
    .line 274
    invoke-static {}, Lio/opentelemetry/api/logs/Severity;->$values()[Lio/opentelemetry/api/logs/Severity;

    .line 275
    .line 276
    .line 277
    move-result-object v0

    .line 278
    sput-object v0, Lio/opentelemetry/api/logs/Severity;->$VALUES:[Lio/opentelemetry/api/logs/Severity;

    .line 279
    .line 280
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;II)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(I)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Lio/opentelemetry/api/logs/Severity;->severityNumber:I

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lio/opentelemetry/api/logs/Severity;
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/api/logs/Severity;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/api/logs/Severity;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lio/opentelemetry/api/logs/Severity;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/api/logs/Severity;->$VALUES:[Lio/opentelemetry/api/logs/Severity;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lio/opentelemetry/api/logs/Severity;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lio/opentelemetry/api/logs/Severity;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public getSeverityNumber()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/api/logs/Severity;->severityNumber:I

    .line 2
    .line 3
    return p0
.end method
