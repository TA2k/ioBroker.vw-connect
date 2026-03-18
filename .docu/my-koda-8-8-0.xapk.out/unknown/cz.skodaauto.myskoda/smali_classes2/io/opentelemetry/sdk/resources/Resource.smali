.class public abstract Lio/opentelemetry/sdk/resources/Resource;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# static fields
.field private static final DEFAULT:Lio/opentelemetry/sdk/resources/Resource;

.field private static final EMPTY:Lio/opentelemetry/sdk/resources/Resource;

.field private static final ERROR_MESSAGE_INVALID_CHARS:Ljava/lang/String; = " should be a ASCII string with a length greater than 0 and not exceed 255 characters."

.field private static final ERROR_MESSAGE_INVALID_VALUE:Ljava/lang/String; = " should be a ASCII string with a length not exceed 255 characters."

.field private static final MANDATORY:Lio/opentelemetry/sdk/resources/Resource;

.field private static final MAX_LENGTH:I = 0xff

.field private static final SERVICE_NAME:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private static final TELEMETRY_SDK:Lio/opentelemetry/sdk/resources/Resource;

.field private static final TELEMETRY_SDK_LANGUAGE:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private static final TELEMETRY_SDK_NAME:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private static final TELEMETRY_SDK_VERSION:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private static final logger:Ljava/util/logging/Logger;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    const-class v0, Lio/opentelemetry/sdk/resources/Resource;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {v0}, Ljava/util/logging/Logger;->getLogger(Ljava/lang/String;)Ljava/util/logging/Logger;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lio/opentelemetry/sdk/resources/Resource;->logger:Ljava/util/logging/Logger;

    .line 12
    .line 13
    const-string v0, "service.name"

    .line 14
    .line 15
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    sput-object v0, Lio/opentelemetry/sdk/resources/Resource;->SERVICE_NAME:Lio/opentelemetry/api/common/AttributeKey;

    .line 20
    .line 21
    const-string v1, "telemetry.sdk.language"

    .line 22
    .line 23
    invoke-static {v1}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    sput-object v1, Lio/opentelemetry/sdk/resources/Resource;->TELEMETRY_SDK_LANGUAGE:Lio/opentelemetry/api/common/AttributeKey;

    .line 28
    .line 29
    const-string v2, "telemetry.sdk.name"

    .line 30
    .line 31
    invoke-static {v2}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    sput-object v2, Lio/opentelemetry/sdk/resources/Resource;->TELEMETRY_SDK_NAME:Lio/opentelemetry/api/common/AttributeKey;

    .line 36
    .line 37
    const-string v3, "telemetry.sdk.version"

    .line 38
    .line 39
    invoke-static {v3}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    sput-object v3, Lio/opentelemetry/sdk/resources/Resource;->TELEMETRY_SDK_VERSION:Lio/opentelemetry/api/common/AttributeKey;

    .line 44
    .line 45
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    .line 46
    .line 47
    .line 48
    move-result-object v4

    .line 49
    invoke-static {v4}, Lio/opentelemetry/sdk/resources/Resource;->create(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/sdk/resources/Resource;

    .line 50
    .line 51
    .line 52
    move-result-object v4

    .line 53
    sput-object v4, Lio/opentelemetry/sdk/resources/Resource;->EMPTY:Lio/opentelemetry/sdk/resources/Resource;

    .line 54
    .line 55
    const-string v4, "unknown_service:java"

    .line 56
    .line 57
    invoke-static {v0, v4}, Lio/opentelemetry/api/common/Attributes;->of(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/Attributes;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    invoke-static {v0}, Lio/opentelemetry/sdk/resources/Resource;->create(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/sdk/resources/Resource;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    sput-object v0, Lio/opentelemetry/sdk/resources/Resource;->MANDATORY:Lio/opentelemetry/sdk/resources/Resource;

    .line 66
    .line 67
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->builder()Lio/opentelemetry/api/common/AttributesBuilder;

    .line 68
    .line 69
    .line 70
    move-result-object v4

    .line 71
    const-string v5, "opentelemetry"

    .line 72
    .line 73
    invoke-interface {v4, v2, v5}, Lio/opentelemetry/api/common/AttributesBuilder;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 74
    .line 75
    .line 76
    move-result-object v2

    .line 77
    const-string v4, "java"

    .line 78
    .line 79
    invoke-interface {v2, v1, v4}, Lio/opentelemetry/api/common/AttributesBuilder;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 80
    .line 81
    .line 82
    move-result-object v1

    .line 83
    const-string v2, "1.56.0"

    .line 84
    .line 85
    invoke-interface {v1, v3, v2}, Lio/opentelemetry/api/common/AttributesBuilder;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 86
    .line 87
    .line 88
    move-result-object v1

    .line 89
    invoke-interface {v1}, Lio/opentelemetry/api/common/AttributesBuilder;->build()Lio/opentelemetry/api/common/Attributes;

    .line 90
    .line 91
    .line 92
    move-result-object v1

    .line 93
    invoke-static {v1}, Lio/opentelemetry/sdk/resources/Resource;->create(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/sdk/resources/Resource;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    sput-object v1, Lio/opentelemetry/sdk/resources/Resource;->TELEMETRY_SDK:Lio/opentelemetry/sdk/resources/Resource;

    .line 98
    .line 99
    invoke-virtual {v0, v1}, Lio/opentelemetry/sdk/resources/Resource;->merge(Lio/opentelemetry/sdk/resources/Resource;)Lio/opentelemetry/sdk/resources/Resource;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    sput-object v0, Lio/opentelemetry/sdk/resources/Resource;->DEFAULT:Lio/opentelemetry/sdk/resources/Resource;

    .line 104
    .line 105
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic a(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lio/opentelemetry/sdk/resources/Resource;->lambda$checkAttributes$0(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static builder()Lio/opentelemetry/sdk/resources/ResourceBuilder;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/resources/ResourceBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/sdk/resources/ResourceBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method private static checkAttributes(Lio/opentelemetry/api/common/Attributes;)V
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/okhttp/v3_0/a;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/okhttp/v3_0/a;-><init>(I)V

    .line 5
    .line 6
    .line 7
    invoke-interface {p0, v0}, Lio/opentelemetry/api/common/Attributes;->forEach(Ljava/util/function/BiConsumer;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public static create(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/sdk/resources/Resource;
    .locals 1

    const/4 v0, 0x0

    .line 1
    invoke-static {p0, v0}, Lio/opentelemetry/sdk/resources/Resource;->create(Lio/opentelemetry/api/common/Attributes;Ljava/lang/String;)Lio/opentelemetry/sdk/resources/Resource;

    move-result-object p0

    return-object p0
.end method

.method public static create(Lio/opentelemetry/api/common/Attributes;Ljava/lang/String;)Lio/opentelemetry/sdk/resources/Resource;
    .locals 1
    .param p1    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 2
    const-string v0, "attributes"

    invoke-static {p0, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    move-object v0, p0

    check-cast v0, Lio/opentelemetry/api/common/Attributes;

    invoke-static {v0}, Lio/opentelemetry/sdk/resources/Resource;->checkAttributes(Lio/opentelemetry/api/common/Attributes;)V

    .line 3
    new-instance v0, Lio/opentelemetry/sdk/resources/AutoValue_Resource;

    invoke-direct {v0, p1, p0}, Lio/opentelemetry/sdk/resources/AutoValue_Resource;-><init>(Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;)V

    return-object v0
.end method

.method public static empty()Lio/opentelemetry/sdk/resources/Resource;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/resources/Resource;->EMPTY:Lio/opentelemetry/sdk/resources/Resource;

    .line 2
    .line 3
    return-object v0
.end method

.method public static getDefault()Lio/opentelemetry/sdk/resources/Resource;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/resources/Resource;->DEFAULT:Lio/opentelemetry/sdk/resources/Resource;

    .line 2
    .line 3
    return-object v0
.end method

.method private static isValid(Ljava/lang/String;)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/16 v1, 0xff

    .line 6
    .line 7
    if-gt v0, v1, :cond_0

    .line 8
    .line 9
    invoke-static {p0}, Lio/opentelemetry/api/internal/StringUtils;->isPrintableString(Ljava/lang/String;)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    const/4 p0, 0x1

    .line 16
    return p0

    .line 17
    :cond_0
    const/4 p0, 0x0

    .line 18
    return p0
.end method

.method private static isValidAndNotEmpty(Lio/opentelemetry/api/common/AttributeKey;)Z
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "*>;)Z"
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
    if-nez v0, :cond_0

    .line 10
    .line 11
    invoke-interface {p0}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-static {p0}, Lio/opentelemetry/sdk/resources/Resource;->isValid(Ljava/lang/String;)Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    if-eqz p0, :cond_0

    .line 20
    .line 21
    const/4 p0, 0x1

    .line 22
    return p0

    .line 23
    :cond_0
    const/4 p0, 0x0

    .line 24
    return p0
.end method

.method private static synthetic lambda$checkAttributes$0(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V
    .locals 1

    .line 1
    invoke-static {p0}, Lio/opentelemetry/sdk/resources/Resource;->isValidAndNotEmpty(Lio/opentelemetry/api/common/AttributeKey;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    const-string v0, "Attribute key should be a ASCII string with a length greater than 0 and not exceed 255 characters."

    .line 6
    .line 7
    invoke-static {p0, v0}, Lio/opentelemetry/api/internal/Utils;->checkArgument(ZLjava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string p0, "Attribute value should be a ASCII string with a length not exceed 255 characters."

    .line 11
    .line 12
    invoke-static {p1, p0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public getAttribute(Lio/opentelemetry/api/common/AttributeKey;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;)TT;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/sdk/resources/Resource;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p0, p1}, Lio/opentelemetry/api/common/Attributes;->get(Lio/opentelemetry/api/common/AttributeKey;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public abstract getAttributes()Lio/opentelemetry/api/common/Attributes;
.end method

.method public abstract getSchemaUrl()Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end method

.method public merge(Lio/opentelemetry/sdk/resources/Resource;)Lio/opentelemetry/sdk/resources/Resource;
    .locals 4
    .param p1    # Lio/opentelemetry/sdk/resources/Resource;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    if-eqz p1, :cond_4

    .line 2
    .line 3
    sget-object v0, Lio/opentelemetry/sdk/resources/Resource;->EMPTY:Lio/opentelemetry/sdk/resources/Resource;

    .line 4
    .line 5
    if-ne p1, v0, :cond_0

    .line 6
    .line 7
    goto/16 :goto_0

    .line 8
    .line 9
    :cond_0
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->builder()Lio/opentelemetry/api/common/AttributesBuilder;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    invoke-virtual {p0}, Lio/opentelemetry/sdk/resources/Resource;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-interface {v0, v1}, Lio/opentelemetry/api/common/AttributesBuilder;->putAll(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {p1}, Lio/opentelemetry/sdk/resources/Resource;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    invoke-interface {v0, v1}, Lio/opentelemetry/api/common/AttributesBuilder;->putAll(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {p1}, Lio/opentelemetry/sdk/resources/Resource;->getSchemaUrl()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    if-nez v1, :cond_1

    .line 32
    .line 33
    invoke-interface {v0}, Lio/opentelemetry/api/common/AttributesBuilder;->build()Lio/opentelemetry/api/common/Attributes;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    invoke-virtual {p0}, Lio/opentelemetry/sdk/resources/Resource;->getSchemaUrl()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-static {p1, p0}, Lio/opentelemetry/sdk/resources/Resource;->create(Lio/opentelemetry/api/common/Attributes;Ljava/lang/String;)Lio/opentelemetry/sdk/resources/Resource;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    return-object p0

    .line 46
    :cond_1
    invoke-virtual {p0}, Lio/opentelemetry/sdk/resources/Resource;->getSchemaUrl()Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    if-nez v1, :cond_2

    .line 51
    .line 52
    invoke-interface {v0}, Lio/opentelemetry/api/common/AttributesBuilder;->build()Lio/opentelemetry/api/common/Attributes;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    invoke-virtual {p1}, Lio/opentelemetry/sdk/resources/Resource;->getSchemaUrl()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    invoke-static {p0, p1}, Lio/opentelemetry/sdk/resources/Resource;->create(Lio/opentelemetry/api/common/Attributes;Ljava/lang/String;)Lio/opentelemetry/sdk/resources/Resource;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    return-object p0

    .line 65
    :cond_2
    invoke-virtual {p1}, Lio/opentelemetry/sdk/resources/Resource;->getSchemaUrl()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    invoke-virtual {p0}, Lio/opentelemetry/sdk/resources/Resource;->getSchemaUrl()Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object v2

    .line 73
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    move-result v1

    .line 77
    if-nez v1, :cond_3

    .line 78
    .line 79
    sget-object v1, Lio/opentelemetry/sdk/resources/Resource;->logger:Ljava/util/logging/Logger;

    .line 80
    .line 81
    new-instance v2, Ljava/lang/StringBuilder;

    .line 82
    .line 83
    const-string v3, "Attempting to merge Resources with different schemaUrls. The resulting Resource will have no schemaUrl assigned. Schema 1: "

    .line 84
    .line 85
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    invoke-virtual {p0}, Lio/opentelemetry/sdk/resources/Resource;->getSchemaUrl()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    const-string p0, " Schema 2: "

    .line 96
    .line 97
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    invoke-virtual {p1}, Lio/opentelemetry/sdk/resources/Resource;->getSchemaUrl()Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 105
    .line 106
    .line 107
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    invoke-virtual {v1, p0}, Ljava/util/logging/Logger;->info(Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    invoke-interface {v0}, Lio/opentelemetry/api/common/AttributesBuilder;->build()Lio/opentelemetry/api/common/Attributes;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    const/4 p1, 0x0

    .line 119
    invoke-static {p0, p1}, Lio/opentelemetry/sdk/resources/Resource;->create(Lio/opentelemetry/api/common/Attributes;Ljava/lang/String;)Lio/opentelemetry/sdk/resources/Resource;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    return-object p0

    .line 124
    :cond_3
    invoke-interface {v0}, Lio/opentelemetry/api/common/AttributesBuilder;->build()Lio/opentelemetry/api/common/Attributes;

    .line 125
    .line 126
    .line 127
    move-result-object p1

    .line 128
    invoke-virtual {p0}, Lio/opentelemetry/sdk/resources/Resource;->getSchemaUrl()Ljava/lang/String;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    invoke-static {p1, p0}, Lio/opentelemetry/sdk/resources/Resource;->create(Lio/opentelemetry/api/common/Attributes;Ljava/lang/String;)Lio/opentelemetry/sdk/resources/Resource;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    :cond_4
    :goto_0
    return-object p0
.end method

.method public toBuilder()Lio/opentelemetry/sdk/resources/ResourceBuilder;
    .locals 2

    .line 1
    invoke-static {}, Lio/opentelemetry/sdk/resources/Resource;->builder()Lio/opentelemetry/sdk/resources/ResourceBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0, p0}, Lio/opentelemetry/sdk/resources/ResourceBuilder;->putAll(Lio/opentelemetry/sdk/resources/Resource;)Lio/opentelemetry/sdk/resources/ResourceBuilder;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-virtual {p0}, Lio/opentelemetry/sdk/resources/Resource;->getSchemaUrl()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    invoke-virtual {p0}, Lio/opentelemetry/sdk/resources/Resource;->getSchemaUrl()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-virtual {v0, p0}, Lio/opentelemetry/sdk/resources/ResourceBuilder;->setSchemaUrl(Ljava/lang/String;)Lio/opentelemetry/sdk/resources/ResourceBuilder;

    .line 20
    .line 21
    .line 22
    :cond_0
    return-object v0
.end method
