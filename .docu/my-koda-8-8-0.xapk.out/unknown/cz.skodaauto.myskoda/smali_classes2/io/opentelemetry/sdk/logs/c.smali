.class public final synthetic Lio/opentelemetry/sdk/logs/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/Consumer;


# instance fields
.field public final synthetic a:Lio/opentelemetry/sdk/logs/SdkLoggerProvider;


# direct methods
.method public synthetic constructor <init>(Lio/opentelemetry/sdk/logs/SdkLoggerProvider;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/sdk/logs/c;->a:Lio/opentelemetry/sdk/logs/SdkLoggerProvider;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final accept(Ljava/lang/Object;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/c;->a:Lio/opentelemetry/sdk/logs/SdkLoggerProvider;

    .line 2
    .line 3
    check-cast p1, Lio/opentelemetry/sdk/logs/SdkLogger;

    .line 4
    .line 5
    invoke-static {p0, p1}, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;->b(Lio/opentelemetry/sdk/logs/SdkLoggerProvider;Lio/opentelemetry/sdk/logs/SdkLogger;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
