.class public final Lio/opentelemetry/sdk/logs/LogLimitsBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final DEFAULT_LOG_MAX_ATTRIBUTE_LENGTH:I = 0x7fffffff

.field private static final DEFAULT_LOG_MAX_NUM_ATTRIBUTES:I = 0x80


# instance fields
.field private maxAttributeValueLength:I

.field private maxNumAttributes:I


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/16 v0, 0x80

    .line 5
    .line 6
    iput v0, p0, Lio/opentelemetry/sdk/logs/LogLimitsBuilder;->maxNumAttributes:I

    .line 7
    .line 8
    const v0, 0x7fffffff

    .line 9
    .line 10
    .line 11
    iput v0, p0, Lio/opentelemetry/sdk/logs/LogLimitsBuilder;->maxAttributeValueLength:I

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public build()Lio/opentelemetry/sdk/logs/LogLimits;
    .locals 1

    .line 1
    iget v0, p0, Lio/opentelemetry/sdk/logs/LogLimitsBuilder;->maxNumAttributes:I

    .line 2
    .line 3
    iget p0, p0, Lio/opentelemetry/sdk/logs/LogLimitsBuilder;->maxAttributeValueLength:I

    .line 4
    .line 5
    invoke-static {v0, p0}, Lio/opentelemetry/sdk/logs/LogLimits;->create(II)Lio/opentelemetry/sdk/logs/LogLimits;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public setMaxAttributeValueLength(I)Lio/opentelemetry/sdk/logs/LogLimitsBuilder;
    .locals 2

    .line 1
    if-ltz p1, :cond_0

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    goto :goto_0

    .line 5
    :cond_0
    const/4 v0, 0x0

    .line 6
    :goto_0
    const-string v1, "maxAttributeValueLength must be non-negative"

    .line 7
    .line 8
    invoke-static {v0, v1}, Lio/opentelemetry/api/internal/Utils;->checkArgument(ZLjava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iput p1, p0, Lio/opentelemetry/sdk/logs/LogLimitsBuilder;->maxAttributeValueLength:I

    .line 12
    .line 13
    return-object p0
.end method

.method public setMaxNumberOfAttributes(I)Lio/opentelemetry/sdk/logs/LogLimitsBuilder;
    .locals 2

    .line 1
    if-ltz p1, :cond_0

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    goto :goto_0

    .line 5
    :cond_0
    const/4 v0, 0x0

    .line 6
    :goto_0
    const-string v1, "maxNumberOfAttributes must be non-negative"

    .line 7
    .line 8
    invoke-static {v0, v1}, Lio/opentelemetry/api/internal/Utils;->checkArgument(ZLjava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iput p1, p0, Lio/opentelemetry/sdk/logs/LogLimitsBuilder;->maxNumAttributes:I

    .line 12
    .line 13
    return-object p0
.end method
