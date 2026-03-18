.class public Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final EMPTY_BYTES:[B

.field private static final EMPTY_REPEATED:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

.field private static final INCUBATOR_AVAILABLE:Z


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    sput-boolean v0, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil;->INCUBATOR_AVAILABLE:Z

    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    new-array v1, v0, [B

    .line 6
    .line 7
    sput-object v1, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil;->EMPTY_BYTES:[B

    .line 8
    .line 9
    new-array v0, v0, [Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 10
    .line 11
    sput-object v0, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil;->EMPTY_REPEATED:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 12
    .line 13
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic access$000(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil;->create(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static create(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
            "*>;",
            "Ljava/lang/Object;",
            ")",
            "Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;"
        }
    .end annotation

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->getKey()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    sget-object v0, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil;->EMPTY_BYTES:[B

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    instance-of v0, p0, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;

    .line 15
    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    move-object v0, p0

    .line 19
    check-cast v0, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;

    .line 20
    .line 21
    invoke-virtual {v0}, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->getKeyUtf8()[B

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    goto :goto_0

    .line 26
    :cond_1
    invoke-interface {p0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->getKey()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    sget-object v1, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    :goto_0
    sget-object v1, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil$2;->$SwitchMap$io$opentelemetry$api$incubator$common$ExtendedAttributeType:[I

    .line 37
    .line 38
    invoke-interface {p0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->getType()Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    aget p0, v1, p0

    .line 47
    .line 48
    packed-switch p0, :pswitch_data_0

    .line 49
    .line 50
    .line 51
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 52
    .line 53
    const-string p1, "Unsupported attribute type."

    .line 54
    .line 55
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw p0

    .line 59
    :pswitch_0
    new-instance p0, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 60
    .line 61
    new-instance v1, Lio/opentelemetry/exporter/internal/otlp/KeyValueListAnyValueMarshaler;

    .line 62
    .line 63
    new-instance v2, Lio/opentelemetry/exporter/internal/otlp/KeyValueListAnyValueMarshaler$KeyValueListMarshaler;

    .line 64
    .line 65
    check-cast p1, Lio/opentelemetry/api/incubator/common/ExtendedAttributes;

    .line 66
    .line 67
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil;->createForExtendedAttributes(Lio/opentelemetry/api/incubator/common/ExtendedAttributes;)[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    invoke-direct {v2, p1}, Lio/opentelemetry/exporter/internal/otlp/KeyValueListAnyValueMarshaler$KeyValueListMarshaler;-><init>([Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;)V

    .line 72
    .line 73
    .line 74
    invoke-direct {v1, v2}, Lio/opentelemetry/exporter/internal/otlp/KeyValueListAnyValueMarshaler;-><init>(Lio/opentelemetry/exporter/internal/otlp/KeyValueListAnyValueMarshaler$KeyValueListMarshaler;)V

    .line 75
    .line 76
    .line 77
    invoke-direct {p0, v0, v1}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;-><init>([BLio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 78
    .line 79
    .line 80
    return-object p0

    .line 81
    :pswitch_1
    new-instance p0, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 82
    .line 83
    check-cast p1, Ljava/util/List;

    .line 84
    .line 85
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/otlp/ArrayAnyValueMarshaler;->createDouble(Ljava/util/List;)Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;

    .line 86
    .line 87
    .line 88
    move-result-object p1

    .line 89
    invoke-direct {p0, v0, p1}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;-><init>([BLio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 90
    .line 91
    .line 92
    return-object p0

    .line 93
    :pswitch_2
    new-instance p0, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 94
    .line 95
    check-cast p1, Ljava/util/List;

    .line 96
    .line 97
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/otlp/ArrayAnyValueMarshaler;->createBool(Ljava/util/List;)Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;

    .line 98
    .line 99
    .line 100
    move-result-object p1

    .line 101
    invoke-direct {p0, v0, p1}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;-><init>([BLio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 102
    .line 103
    .line 104
    return-object p0

    .line 105
    :pswitch_3
    new-instance p0, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 106
    .line 107
    check-cast p1, Ljava/util/List;

    .line 108
    .line 109
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/otlp/ArrayAnyValueMarshaler;->createInt(Ljava/util/List;)Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;

    .line 110
    .line 111
    .line 112
    move-result-object p1

    .line 113
    invoke-direct {p0, v0, p1}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;-><init>([BLio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 114
    .line 115
    .line 116
    return-object p0

    .line 117
    :pswitch_4
    new-instance p0, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 118
    .line 119
    check-cast p1, Ljava/util/List;

    .line 120
    .line 121
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/otlp/ArrayAnyValueMarshaler;->createString(Ljava/util/List;)Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;

    .line 122
    .line 123
    .line 124
    move-result-object p1

    .line 125
    invoke-direct {p0, v0, p1}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;-><init>([BLio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 126
    .line 127
    .line 128
    return-object p0

    .line 129
    :pswitch_5
    new-instance p0, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 130
    .line 131
    check-cast p1, Ljava/lang/Double;

    .line 132
    .line 133
    invoke-virtual {p1}, Ljava/lang/Double;->doubleValue()D

    .line 134
    .line 135
    .line 136
    move-result-wide v1

    .line 137
    invoke-static {v1, v2}, Lio/opentelemetry/exporter/internal/otlp/DoubleAnyValueMarshaler;->create(D)Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;

    .line 138
    .line 139
    .line 140
    move-result-object p1

    .line 141
    invoke-direct {p0, v0, p1}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;-><init>([BLio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 142
    .line 143
    .line 144
    return-object p0

    .line 145
    :pswitch_6
    new-instance p0, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 146
    .line 147
    check-cast p1, Ljava/lang/Boolean;

    .line 148
    .line 149
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 150
    .line 151
    .line 152
    move-result p1

    .line 153
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/otlp/BoolAnyValueMarshaler;->create(Z)Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;

    .line 154
    .line 155
    .line 156
    move-result-object p1

    .line 157
    invoke-direct {p0, v0, p1}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;-><init>([BLio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 158
    .line 159
    .line 160
    return-object p0

    .line 161
    :pswitch_7
    new-instance p0, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 162
    .line 163
    check-cast p1, Ljava/lang/Long;

    .line 164
    .line 165
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 166
    .line 167
    .line 168
    move-result-wide v1

    .line 169
    invoke-static {v1, v2}, Lio/opentelemetry/exporter/internal/otlp/IntAnyValueMarshaler;->create(J)Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;

    .line 170
    .line 171
    .line 172
    move-result-object p1

    .line 173
    invoke-direct {p0, v0, p1}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;-><init>([BLio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 174
    .line 175
    .line 176
    return-object p0

    .line 177
    :pswitch_8
    new-instance p0, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 178
    .line 179
    check-cast p1, Ljava/lang/String;

    .line 180
    .line 181
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/otlp/StringAnyValueMarshaler;->create(Ljava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;

    .line 182
    .line 183
    .line 184
    move-result-object p1

    .line 185
    invoke-direct {p0, v0, p1}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;-><init>([BLio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 186
    .line 187
    .line 188
    return-object p0

    .line 189
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method private static createForExtendedAttributes(Lio/opentelemetry/api/incubator/common/ExtendedAttributes;)[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;
    .locals 2

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributes;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    sget-object p0, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil;->EMPTY_REPEATED:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    invoke-interface {p0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributes;->size()I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    new-array v0, v0, [Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 15
    .line 16
    new-instance v1, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil$1;

    .line 17
    .line 18
    invoke-direct {v1, v0}, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil$1;-><init>([Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;)V

    .line 19
    .line 20
    .line 21
    invoke-interface {p0, v1}, Lio/opentelemetry/api/incubator/common/ExtendedAttributes;->forEach(Ljava/util/function/BiConsumer;)V

    .line 22
    .line 23
    .line 24
    return-object v0
.end method

.method public static createdExtendedAttributesMarhsalers(Lio/opentelemetry/sdk/logs/data/LogRecordData;)[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil;->getExtendedAttributes(Lio/opentelemetry/sdk/logs/data/LogRecordData;)Lio/opentelemetry/api/incubator/common/ExtendedAttributes;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0}, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil;->createForExtendedAttributes(Lio/opentelemetry/api/incubator/common/ExtendedAttributes;)[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public static extendedAttributesSize(Lio/opentelemetry/sdk/logs/data/LogRecordData;)I
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil;->getExtendedAttributes(Lio/opentelemetry/sdk/logs/data/LogRecordData;)Lio/opentelemetry/api/incubator/common/ExtendedAttributes;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributes;->size()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method private static getExtendedAttributes(Lio/opentelemetry/sdk/logs/data/LogRecordData;)Lio/opentelemetry/api/incubator/common/ExtendedAttributes;
    .locals 1

    .line 1
    instance-of v0, p0, Lio/opentelemetry/sdk/logs/data/internal/ExtendedLogRecordData;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p0, Lio/opentelemetry/sdk/logs/data/internal/ExtendedLogRecordData;

    .line 6
    .line 7
    invoke-interface {p0}, Lio/opentelemetry/sdk/logs/data/internal/ExtendedLogRecordData;->getExtendedAttributes()Lio/opentelemetry/api/incubator/common/ExtendedAttributes;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 13
    .line 14
    const-string v0, "logRecordData must be ExtendedLogRecordData"

    .line 15
    .line 16
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    throw p0
.end method

.method public static isExtendedLogRecordData(Lio/opentelemetry/sdk/logs/data/LogRecordData;)Z
    .locals 1

    .line 1
    sget-boolean v0, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil;->INCUBATOR_AVAILABLE:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    instance-of p0, p0, Lio/opentelemetry/sdk/logs/data/internal/ExtendedLogRecordData;

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x1

    .line 10
    return p0

    .line 11
    :cond_0
    const/4 p0, 0x0

    .line 12
    return p0
.end method

.method public static serializeExtendedAttributes(Lio/opentelemetry/exporter/internal/marshal/Serializer;Lio/opentelemetry/sdk/logs/data/LogRecordData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil;->getExtendedAttributes(Lio/opentelemetry/sdk/logs/data/LogRecordData;)Lio/opentelemetry/api/incubator/common/ExtendedAttributes;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-static {p0, v0, p1, p2}, Lio/opentelemetry/exporter/internal/otlp/ExtendedAttributeKeyValueStatelessMarshaler;->serializeExtendedAttributes(Lio/opentelemetry/exporter/internal/marshal/Serializer;Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/api/incubator/common/ExtendedAttributes;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public static sizeExtendedAttributes(Lio/opentelemetry/sdk/logs/data/LogRecordData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    invoke-static {p0}, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil;->getExtendedAttributes(Lio/opentelemetry/sdk/logs/data/LogRecordData;)Lio/opentelemetry/api/incubator/common/ExtendedAttributes;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-static {v0, p0, p1}, Lio/opentelemetry/exporter/internal/otlp/ExtendedAttributeKeyValueStatelessMarshaler;->sizeExtendedAttributes(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/api/incubator/common/ExtendedAttributes;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method
