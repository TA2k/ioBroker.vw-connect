.class public final Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;
.super Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final EMPTY_BYTES:[B

.field private static final EMPTY_REPEATED:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;


# instance fields
.field private final keyUtf8:[B

.field private final value:Lio/opentelemetry/exporter/internal/marshal/Marshaler;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v1, v0, [B

    .line 3
    .line 4
    sput-object v1, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;->EMPTY_BYTES:[B

    .line 5
    .line 6
    new-array v0, v0, [Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 7
    .line 8
    sput-object v0, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;->EMPTY_REPEATED:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>([BLio/opentelemetry/exporter/internal/marshal/Marshaler;)V
    .locals 1

    .line 1
    invoke-static {p1, p2}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;->calculateSize([BLio/opentelemetry/exporter/internal/marshal/Marshaler;)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;-><init>(I)V

    .line 6
    .line 7
    .line 8
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;->keyUtf8:[B

    .line 9
    .line 10
    iput-object p2, p0, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;->value:Lio/opentelemetry/exporter/internal/marshal/Marshaler;

    .line 11
    .line 12
    return-void
.end method

.method public static synthetic a([Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValue;)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;->lambda$createRepeated$0([Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValue;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic access$000(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;->create(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static calculateSize([BLio/opentelemetry/exporter/internal/marshal/Marshaler;)I
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/proto/common/v1/internal/KeyValue;->KEY:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    invoke-static {v0, p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeBytes(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    sget-object v0, Lio/opentelemetry/proto/common/v1/internal/KeyValue;->VALUE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 8
    .line 9
    invoke-static {v0, p1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/Marshaler;)I

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    add-int/2addr p1, p0

    .line 14
    return p1
.end method

.method private static create(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "*>;",
            "Ljava/lang/Object;",
            ")",
            "Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;"
        }
    .end annotation

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

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
    sget-object v0, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;->EMPTY_BYTES:[B

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    instance-of v0, p0, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;

    .line 15
    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    move-object v0, p0

    .line 19
    check-cast v0, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;

    .line 20
    .line 21
    invoke-virtual {v0}, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;->getKeyUtf8()[B

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    goto :goto_0

    .line 26
    :cond_1
    invoke-interface {p0}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

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
    sget-object v1, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler$3;->$SwitchMap$io$opentelemetry$api$common$AttributeType:[I

    .line 37
    .line 38
    invoke-interface {p0}, Lio/opentelemetry/api/common/AttributeKey;->getType()Lio/opentelemetry/api/common/AttributeType;

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
    check-cast p1, Ljava/util/List;

    .line 62
    .line 63
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/otlp/ArrayAnyValueMarshaler;->createDouble(Ljava/util/List;)Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    invoke-direct {p0, v0, p1}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;-><init>([BLio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 68
    .line 69
    .line 70
    return-object p0

    .line 71
    :pswitch_1
    new-instance p0, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 72
    .line 73
    check-cast p1, Ljava/util/List;

    .line 74
    .line 75
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/otlp/ArrayAnyValueMarshaler;->createBool(Ljava/util/List;)Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;

    .line 76
    .line 77
    .line 78
    move-result-object p1

    .line 79
    invoke-direct {p0, v0, p1}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;-><init>([BLio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 80
    .line 81
    .line 82
    return-object p0

    .line 83
    :pswitch_2
    new-instance p0, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 84
    .line 85
    check-cast p1, Ljava/util/List;

    .line 86
    .line 87
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/otlp/ArrayAnyValueMarshaler;->createInt(Ljava/util/List;)Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;

    .line 88
    .line 89
    .line 90
    move-result-object p1

    .line 91
    invoke-direct {p0, v0, p1}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;-><init>([BLio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 92
    .line 93
    .line 94
    return-object p0

    .line 95
    :pswitch_3
    new-instance p0, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 96
    .line 97
    check-cast p1, Ljava/util/List;

    .line 98
    .line 99
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/otlp/ArrayAnyValueMarshaler;->createString(Ljava/util/List;)Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    invoke-direct {p0, v0, p1}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;-><init>([BLio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 104
    .line 105
    .line 106
    return-object p0

    .line 107
    :pswitch_4
    new-instance p0, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 108
    .line 109
    check-cast p1, Ljava/lang/Double;

    .line 110
    .line 111
    invoke-virtual {p1}, Ljava/lang/Double;->doubleValue()D

    .line 112
    .line 113
    .line 114
    move-result-wide v1

    .line 115
    invoke-static {v1, v2}, Lio/opentelemetry/exporter/internal/otlp/DoubleAnyValueMarshaler;->create(D)Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;

    .line 116
    .line 117
    .line 118
    move-result-object p1

    .line 119
    invoke-direct {p0, v0, p1}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;-><init>([BLio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 120
    .line 121
    .line 122
    return-object p0

    .line 123
    :pswitch_5
    new-instance p0, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 124
    .line 125
    check-cast p1, Ljava/lang/Boolean;

    .line 126
    .line 127
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 128
    .line 129
    .line 130
    move-result p1

    .line 131
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/otlp/BoolAnyValueMarshaler;->create(Z)Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;

    .line 132
    .line 133
    .line 134
    move-result-object p1

    .line 135
    invoke-direct {p0, v0, p1}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;-><init>([BLio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 136
    .line 137
    .line 138
    return-object p0

    .line 139
    :pswitch_6
    new-instance p0, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 140
    .line 141
    check-cast p1, Ljava/lang/Long;

    .line 142
    .line 143
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 144
    .line 145
    .line 146
    move-result-wide v1

    .line 147
    invoke-static {v1, v2}, Lio/opentelemetry/exporter/internal/otlp/IntAnyValueMarshaler;->create(J)Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;

    .line 148
    .line 149
    .line 150
    move-result-object p1

    .line 151
    invoke-direct {p0, v0, p1}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;-><init>([BLio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 152
    .line 153
    .line 154
    return-object p0

    .line 155
    :pswitch_7
    new-instance p0, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 156
    .line 157
    check-cast p1, Ljava/lang/String;

    .line 158
    .line 159
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/otlp/StringAnyValueMarshaler;->create(Ljava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;

    .line 160
    .line 161
    .line 162
    move-result-object p1

    .line 163
    invoke-direct {p0, v0, p1}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;-><init>([BLio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 164
    .line 165
    .line 166
    return-object p0

    .line 167
    :pswitch_data_0
    .packed-switch 0x1
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

.method public static createForAttributes(Lio/opentelemetry/api/common/Attributes;)[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;
    .locals 2

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/api/common/Attributes;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    sget-object p0, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;->EMPTY_REPEATED:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    invoke-interface {p0}, Lio/opentelemetry/api/common/Attributes;->size()I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    new-array v0, v0, [Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 15
    .line 16
    new-instance v1, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler$1;

    .line 17
    .line 18
    invoke-direct {v1, v0}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler$1;-><init>([Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;)V

    .line 19
    .line 20
    .line 21
    invoke-interface {p0, v1}, Lio/opentelemetry/api/common/Attributes;->forEach(Ljava/util/function/BiConsumer;)V

    .line 22
    .line 23
    .line 24
    return-object v0
.end method

.method public static createForKeyValue(Lio/opentelemetry/api/common/KeyValue;)Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;
    .locals 3

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/api/common/KeyValue;->getKey()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    sget-object v2, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 8
    .line 9
    invoke-virtual {v1, v2}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    invoke-interface {p0}, Lio/opentelemetry/api/common/KeyValue;->getValue()Lio/opentelemetry/api/common/Value;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-static {p0}, Lio/opentelemetry/exporter/internal/otlp/AnyValueMarshaler;->create(Lio/opentelemetry/api/common/Value;)Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    invoke-direct {v0, v1, p0}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;-><init>([BLio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 22
    .line 23
    .line 24
    return-object v0
.end method

.method public static createRepeated(Ljava/util/List;)[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValue<",
            "*>;>;)[",
            "Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;"
        }
    .end annotation

    .line 1
    invoke-interface {p0}, Ljava/util/List;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    sget-object p0, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;->EMPTY_REPEATED:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    new-array v0, v0, [Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 15
    .line 16
    new-instance v1, Lex0/a;

    .line 17
    .line 18
    const/4 v2, 0x2

    .line 19
    invoke-direct {v1, v0, v2}, Lex0/a;-><init>(Ljava/lang/Object;I)V

    .line 20
    .line 21
    .line 22
    invoke-interface {p0, v1}, Ljava/lang/Iterable;->forEach(Ljava/util/function/Consumer;)V

    .line 23
    .line 24
    .line 25
    return-object v0
.end method

.method private static synthetic lambda$createRepeated$0([Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValue;)V
    .locals 0

    .line 1
    new-instance p1, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler$2;

    .line 2
    .line 3
    invoke-direct {p1, p0}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler$2;-><init>([Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;)V
    .locals 2

    .line 1
    sget-object v0, Lio/opentelemetry/proto/common/v1/internal/KeyValue;->KEY:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;->keyUtf8:[B

    .line 4
    .line 5
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeString(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)V

    .line 6
    .line 7
    .line 8
    sget-object v0, Lio/opentelemetry/proto/common/v1/internal/KeyValue;->VALUE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 9
    .line 10
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;->value:Lio/opentelemetry/exporter/internal/marshal/Marshaler;

    .line 11
    .line 12
    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method
