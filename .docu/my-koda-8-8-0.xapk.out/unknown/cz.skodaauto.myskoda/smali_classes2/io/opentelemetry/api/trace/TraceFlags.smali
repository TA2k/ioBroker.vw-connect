.class public interface abstract Lio/opentelemetry/api/trace/TraceFlags;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# direct methods
.method public static fromByte(B)Lio/opentelemetry/api/trace/TraceFlags;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/api/trace/ImmutableTraceFlags;->fromByte(B)Lio/opentelemetry/api/trace/ImmutableTraceFlags;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static fromHex(Ljava/lang/CharSequence;I)Lio/opentelemetry/api/trace/TraceFlags;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lio/opentelemetry/api/trace/ImmutableTraceFlags;->fromHex(Ljava/lang/CharSequence;I)Lio/opentelemetry/api/trace/ImmutableTraceFlags;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static getDefault()Lio/opentelemetry/api/trace/TraceFlags;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/api/trace/ImmutableTraceFlags;->DEFAULT:Lio/opentelemetry/api/trace/ImmutableTraceFlags;

    .line 2
    .line 3
    return-object v0
.end method

.method public static getLength()I
    .locals 1

    .line 1
    const/4 v0, 0x2

    .line 2
    return v0
.end method

.method public static getSampled()Lio/opentelemetry/api/trace/TraceFlags;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/api/trace/ImmutableTraceFlags;->SAMPLED:Lio/opentelemetry/api/trace/ImmutableTraceFlags;

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public abstract asByte()B
.end method

.method public abstract asHex()Ljava/lang/String;
.end method

.method public abstract isSampled()Z
.end method
