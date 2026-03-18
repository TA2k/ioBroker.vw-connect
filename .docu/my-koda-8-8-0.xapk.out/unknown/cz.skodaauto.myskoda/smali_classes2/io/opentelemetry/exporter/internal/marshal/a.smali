.class public final synthetic Lio/opentelemetry/exporter/internal/marshal/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/Supplier;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lio/opentelemetry/exporter/internal/marshal/a;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final get()Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/exporter/internal/marshal/a;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->b()Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    invoke-static {}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->d()Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$Grouper;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :pswitch_1
    invoke-static {}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->c()Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_2
    invoke-static {}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->a()Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementSizeCalculator;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0

    .line 26
    :pswitch_3
    invoke-static {}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->b()Lio/opentelemetry/exporter/internal/marshal/Serializer$RepeatedElementPairWriter;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0

    .line 31
    :pswitch_4
    invoke-static {}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->a()Lio/opentelemetry/exporter/internal/marshal/Serializer$RepeatedElementWriter;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_5
    invoke-static {}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->d()Lio/opentelemetry/exporter/internal/marshal/Serializer$RepeatedElementPairWriter;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0

    .line 41
    :pswitch_6
    new-instance p0, Ljava/util/ArrayList;

    .line 42
    .line 43
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 44
    .line 45
    .line 46
    return-object p0

    .line 47
    :pswitch_7
    new-instance p0, Ljava/util/IdentityHashMap;

    .line 48
    .line 49
    invoke-direct {p0}, Ljava/util/IdentityHashMap;-><init>()V

    .line 50
    .line 51
    .line 52
    return-object p0

    .line 53
    :pswitch_data_0
    .packed-switch 0x0
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
