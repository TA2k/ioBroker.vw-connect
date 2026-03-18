.class public final synthetic Lio/opentelemetry/sdk/logs/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver$AttributeSetter;


# instance fields
.field public final synthetic a:Lio/opentelemetry/sdk/logs/ExtendedSdkLogRecordBuilder;


# direct methods
.method public synthetic constructor <init>(Lio/opentelemetry/sdk/logs/ExtendedSdkLogRecordBuilder;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/sdk/logs/a;->a:Lio/opentelemetry/sdk/logs/ExtendedSdkLogRecordBuilder;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/a;->a:Lio/opentelemetry/sdk/logs/ExtendedSdkLogRecordBuilder;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/sdk/logs/ExtendedSdkLogRecordBuilder;->setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/sdk/logs/ExtendedSdkLogRecordBuilder;

    .line 4
    .line 5
    .line 6
    return-void
.end method
