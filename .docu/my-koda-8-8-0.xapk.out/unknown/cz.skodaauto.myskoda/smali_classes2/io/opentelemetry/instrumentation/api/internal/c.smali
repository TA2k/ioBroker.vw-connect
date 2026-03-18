.class public final synthetic Lio/opentelemetry/instrumentation/api/internal/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/Function;


# instance fields
.field public final synthetic a:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lio/opentelemetry/instrumentation/api/internal/c;->a:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final apply(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/instrumentation/api/internal/c;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/String;

    .line 7
    .line 8
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->f(Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics$KindCounters;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :pswitch_0
    check-cast p1, Ljava/lang/String;

    .line 14
    .line 15
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->a(Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicLong;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0

    .line 20
    :pswitch_1
    check-cast p1, Ljava/lang/Class;

    .line 21
    .line 22
    invoke-static {p1}, Ljava/util/ServiceLoader;->load(Ljava/lang/Class;)Ljava/util/ServiceLoader;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0

    .line 27
    :pswitch_2
    check-cast p1, Ljava/lang/String;

    .line 28
    .line 29
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/internal/EmbeddedInstrumentationProperties;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    :pswitch_3
    check-cast p1, Ljava/lang/String;

    .line 35
    .line 36
    invoke-virtual {p1}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0

    .line 41
    :pswitch_4
    check-cast p1, Ljava/lang/Class;

    .line 42
    .line 43
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/internal/ClassNames;->a(Ljava/lang/Class;)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0

    .line 48
    :pswitch_5
    check-cast p1, Ljava/lang/Class;

    .line 49
    .line 50
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$CacheBasedVirtualFieldSupplier;->a(Ljava/lang/Class;)Lio/opentelemetry/instrumentation/api/util/VirtualField;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    return-object p0

    .line 55
    :pswitch_6
    check-cast p1, Ljava/lang/Class;

    .line 56
    .line 57
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$CacheBasedVirtualFieldSupplier;->b(Ljava/lang/Class;)Lio/opentelemetry/instrumentation/api/internal/cache/Cache;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    nop

    .line 63
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
