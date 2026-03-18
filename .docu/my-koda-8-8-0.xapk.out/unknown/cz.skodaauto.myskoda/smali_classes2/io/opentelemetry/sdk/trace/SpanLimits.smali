.class public abstract Lio/opentelemetry/sdk/trace/SpanLimits;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/sdk/trace/SpanLimits$SpanLimitsValue;
    }
.end annotation


# static fields
.field private static final DEFAULT:Lio/opentelemetry/sdk/trace/SpanLimits;

.field static final DEFAULT_SPAN_MAX_ATTRIBUTE_LENGTH:I = 0x7fffffff


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/trace/SpanLimitsBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/sdk/trace/SpanLimitsBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {v0}, Lio/opentelemetry/sdk/trace/SpanLimitsBuilder;->build()Lio/opentelemetry/sdk/trace/SpanLimits;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    sput-object v0, Lio/opentelemetry/sdk/trace/SpanLimits;->DEFAULT:Lio/opentelemetry/sdk/trace/SpanLimits;

    .line 11
    .line 12
    return-void
.end method

.method public constructor <init>()V
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static builder()Lio/opentelemetry/sdk/trace/SpanLimitsBuilder;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/trace/SpanLimitsBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/sdk/trace/SpanLimitsBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static create(IIIIII)Lio/opentelemetry/sdk/trace/SpanLimits;
    .locals 7

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;

    .line 2
    .line 3
    move v1, p0

    .line 4
    move v2, p1

    .line 5
    move v3, p2

    .line 6
    move v4, p3

    .line 7
    move v5, p4

    .line 8
    move v6, p5

    .line 9
    invoke-direct/range {v0 .. v6}, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;-><init>(IIIIII)V

    .line 10
    .line 11
    .line 12
    return-object v0
.end method

.method public static getDefault()Lio/opentelemetry/sdk/trace/SpanLimits;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/trace/SpanLimits;->DEFAULT:Lio/opentelemetry/sdk/trace/SpanLimits;

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public getMaxAttributeValueLength()I
    .locals 0

    .line 1
    const p0, 0x7fffffff

    .line 2
    .line 3
    .line 4
    return p0
.end method

.method public abstract getMaxNumberOfAttributes()I
.end method

.method public abstract getMaxNumberOfAttributesPerEvent()I
.end method

.method public abstract getMaxNumberOfAttributesPerLink()I
.end method

.method public abstract getMaxNumberOfEvents()I
.end method

.method public abstract getMaxNumberOfLinks()I
.end method

.method public toBuilder()Lio/opentelemetry/sdk/trace/SpanLimitsBuilder;
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/trace/SpanLimitsBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/sdk/trace/SpanLimitsBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/SpanLimits;->getMaxNumberOfAttributes()I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    invoke-virtual {v0, v1}, Lio/opentelemetry/sdk/trace/SpanLimitsBuilder;->setMaxNumberOfAttributes(I)Lio/opentelemetry/sdk/trace/SpanLimitsBuilder;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/SpanLimits;->getMaxNumberOfEvents()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    invoke-virtual {v0, v1}, Lio/opentelemetry/sdk/trace/SpanLimitsBuilder;->setMaxNumberOfEvents(I)Lio/opentelemetry/sdk/trace/SpanLimitsBuilder;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/SpanLimits;->getMaxNumberOfLinks()I

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    invoke-virtual {v0, v1}, Lio/opentelemetry/sdk/trace/SpanLimitsBuilder;->setMaxNumberOfLinks(I)Lio/opentelemetry/sdk/trace/SpanLimitsBuilder;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/SpanLimits;->getMaxNumberOfAttributesPerEvent()I

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    invoke-virtual {v0, v1}, Lio/opentelemetry/sdk/trace/SpanLimitsBuilder;->setMaxNumberOfAttributesPerEvent(I)Lio/opentelemetry/sdk/trace/SpanLimitsBuilder;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/SpanLimits;->getMaxNumberOfAttributesPerLink()I

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    invoke-virtual {v0, v1}, Lio/opentelemetry/sdk/trace/SpanLimitsBuilder;->setMaxNumberOfAttributesPerLink(I)Lio/opentelemetry/sdk/trace/SpanLimitsBuilder;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/SpanLimits;->getMaxAttributeValueLength()I

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    invoke-virtual {v0, p0}, Lio/opentelemetry/sdk/trace/SpanLimitsBuilder;->setMaxAttributeValueLength(I)Lio/opentelemetry/sdk/trace/SpanLimitsBuilder;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    return-object p0
.end method
