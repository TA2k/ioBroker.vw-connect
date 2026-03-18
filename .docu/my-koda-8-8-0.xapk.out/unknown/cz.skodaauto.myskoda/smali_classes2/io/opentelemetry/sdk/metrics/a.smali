.class public final synthetic Lio/opentelemetry/sdk/metrics/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/InstrumentBuilder$SynchronousInstrumentConstructor;
.implements Lio/opentelemetry/sdk/metrics/InstrumentBuilder$SwapBuilder;


# instance fields
.field public final synthetic a:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lio/opentelemetry/sdk/metrics/a;->a:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public createInstrument(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Lio/opentelemetry/sdk/metrics/SdkMeter;Lio/opentelemetry/sdk/metrics/internal/state/WriteableMetricStorage;)Lio/opentelemetry/sdk/metrics/AbstractInstrument;
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/metrics/a;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    :pswitch_0
    new-instance p0, Lio/opentelemetry/sdk/metrics/SdkLongUpDownCounter;

    .line 7
    .line 8
    invoke-direct {p0, p1, p2, p3}, Lio/opentelemetry/sdk/metrics/SdkLongUpDownCounter;-><init>(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Lio/opentelemetry/sdk/metrics/SdkMeter;Lio/opentelemetry/sdk/metrics/internal/state/WriteableMetricStorage;)V

    .line 9
    .line 10
    .line 11
    return-object p0

    .line 12
    :pswitch_1
    new-instance p0, Lio/opentelemetry/sdk/metrics/SdkLongHistogram;

    .line 13
    .line 14
    invoke-direct {p0, p1, p2, p3}, Lio/opentelemetry/sdk/metrics/SdkLongHistogram;-><init>(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Lio/opentelemetry/sdk/metrics/SdkMeter;Lio/opentelemetry/sdk/metrics/internal/state/WriteableMetricStorage;)V

    .line 15
    .line 16
    .line 17
    return-object p0

    .line 18
    :pswitch_2
    new-instance p0, Lio/opentelemetry/sdk/metrics/SdkLongGauge;

    .line 19
    .line 20
    invoke-direct {p0, p1, p2, p3}, Lio/opentelemetry/sdk/metrics/SdkLongGauge;-><init>(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Lio/opentelemetry/sdk/metrics/SdkMeter;Lio/opentelemetry/sdk/metrics/internal/state/WriteableMetricStorage;)V

    .line 21
    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_3
    new-instance p0, Lio/opentelemetry/sdk/metrics/SdkLongCounter;

    .line 25
    .line 26
    invoke-direct {p0, p1, p2, p3}, Lio/opentelemetry/sdk/metrics/SdkLongCounter;-><init>(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Lio/opentelemetry/sdk/metrics/SdkMeter;Lio/opentelemetry/sdk/metrics/internal/state/WriteableMetricStorage;)V

    .line 27
    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_4
    new-instance p0, Lio/opentelemetry/sdk/metrics/SdkDoubleUpDownCounter;

    .line 31
    .line 32
    invoke-direct {p0, p1, p2, p3}, Lio/opentelemetry/sdk/metrics/SdkDoubleUpDownCounter;-><init>(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Lio/opentelemetry/sdk/metrics/SdkMeter;Lio/opentelemetry/sdk/metrics/internal/state/WriteableMetricStorage;)V

    .line 33
    .line 34
    .line 35
    return-object p0

    .line 36
    :pswitch_5
    new-instance p0, Lio/opentelemetry/sdk/metrics/SdkDoubleHistogram;

    .line 37
    .line 38
    invoke-direct {p0, p1, p2, p3}, Lio/opentelemetry/sdk/metrics/SdkDoubleHistogram;-><init>(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Lio/opentelemetry/sdk/metrics/SdkMeter;Lio/opentelemetry/sdk/metrics/internal/state/WriteableMetricStorage;)V

    .line 39
    .line 40
    .line 41
    return-object p0

    .line 42
    :pswitch_6
    new-instance p0, Lio/opentelemetry/sdk/metrics/SdkDoubleGauge;

    .line 43
    .line 44
    invoke-direct {p0, p1, p2, p3}, Lio/opentelemetry/sdk/metrics/SdkDoubleGauge;-><init>(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Lio/opentelemetry/sdk/metrics/SdkMeter;Lio/opentelemetry/sdk/metrics/internal/state/WriteableMetricStorage;)V

    .line 45
    .line 46
    .line 47
    return-object p0

    .line 48
    :pswitch_7
    new-instance p0, Lio/opentelemetry/sdk/metrics/SdkDoubleCounter;

    .line 49
    .line 50
    invoke-direct {p0, p1, p2, p3}, Lio/opentelemetry/sdk/metrics/SdkDoubleCounter;-><init>(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Lio/opentelemetry/sdk/metrics/SdkMeter;Lio/opentelemetry/sdk/metrics/internal/state/WriteableMetricStorage;)V

    .line 51
    .line 52
    .line 53
    return-object p0

    .line 54
    :pswitch_8
    invoke-static {p1, p2, p3}, Lio/opentelemetry/sdk/metrics/ExtendedSdkLongUpDownCounter$ExtendedSdkLongUpDownCounterBuilder;->a(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Lio/opentelemetry/sdk/metrics/SdkMeter;Lio/opentelemetry/sdk/metrics/internal/state/WriteableMetricStorage;)Lio/opentelemetry/sdk/metrics/ExtendedSdkLongUpDownCounter;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    return-object p0

    .line 59
    :pswitch_9
    invoke-static {p1, p2, p3}, Lio/opentelemetry/sdk/metrics/ExtendedSdkLongHistogram$ExtendedSdkLongHistogramBuilder;->a(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Lio/opentelemetry/sdk/metrics/SdkMeter;Lio/opentelemetry/sdk/metrics/internal/state/WriteableMetricStorage;)Lio/opentelemetry/sdk/metrics/ExtendedSdkLongHistogram;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    return-object p0

    .line 64
    :pswitch_a
    invoke-static {p1, p2, p3}, Lio/opentelemetry/sdk/metrics/ExtendedSdkLongGauge$ExtendedSdkLongGaugeBuilder;->a(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Lio/opentelemetry/sdk/metrics/SdkMeter;Lio/opentelemetry/sdk/metrics/internal/state/WriteableMetricStorage;)Lio/opentelemetry/sdk/metrics/ExtendedSdkLongGauge;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    return-object p0

    .line 69
    :pswitch_b
    invoke-static {p1, p2, p3}, Lio/opentelemetry/sdk/metrics/ExtendedSdkLongCounter$ExtendedSdkLongCounterBuilder;->a(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Lio/opentelemetry/sdk/metrics/SdkMeter;Lio/opentelemetry/sdk/metrics/internal/state/WriteableMetricStorage;)Lio/opentelemetry/sdk/metrics/ExtendedSdkLongCounter;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    return-object p0

    .line 74
    :pswitch_c
    invoke-static {p1, p2, p3}, Lio/opentelemetry/sdk/metrics/ExtendedSdkDoubleUpDownCounter$ExtendedSdkDoubleUpDownCounterBuilder;->a(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Lio/opentelemetry/sdk/metrics/SdkMeter;Lio/opentelemetry/sdk/metrics/internal/state/WriteableMetricStorage;)Lio/opentelemetry/sdk/metrics/ExtendedSdkDoubleUpDownCounter;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    return-object p0

    .line 79
    :pswitch_d
    new-instance p0, Lio/opentelemetry/sdk/metrics/ExtendedSdkDoubleHistogram;

    .line 80
    .line 81
    invoke-direct {p0, p1, p2, p3}, Lio/opentelemetry/sdk/metrics/ExtendedSdkDoubleHistogram;-><init>(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Lio/opentelemetry/sdk/metrics/SdkMeter;Lio/opentelemetry/sdk/metrics/internal/state/WriteableMetricStorage;)V

    .line 82
    .line 83
    .line 84
    return-object p0

    .line 85
    :pswitch_e
    invoke-static {p1, p2, p3}, Lio/opentelemetry/sdk/metrics/ExtendedSdkDoubleGauge$ExtendedSdkDoubleGaugeBuilder;->a(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Lio/opentelemetry/sdk/metrics/SdkMeter;Lio/opentelemetry/sdk/metrics/internal/state/WriteableMetricStorage;)Lio/opentelemetry/sdk/metrics/ExtendedSdkDoubleGauge;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    return-object p0

    .line 90
    :pswitch_f
    invoke-static {p1, p2, p3}, Lio/opentelemetry/sdk/metrics/ExtendedSdkDoubleCounter$ExtendedSdkDoubleCounterBuilder;->a(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Lio/opentelemetry/sdk/metrics/SdkMeter;Lio/opentelemetry/sdk/metrics/internal/state/WriteableMetricStorage;)Lio/opentelemetry/sdk/metrics/ExtendedSdkDoubleCounter;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    return-object p0

    .line 95
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_f
        :pswitch_e
        :pswitch_0
        :pswitch_0
        :pswitch_d
        :pswitch_c
        :pswitch_0
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_0
        :pswitch_8
        :pswitch_7
        :pswitch_0
        :pswitch_6
        :pswitch_0
        :pswitch_5
        :pswitch_4
        :pswitch_0
        :pswitch_3
        :pswitch_2
        :pswitch_1
    .end packed-switch
.end method

.method public newBuilder(Lio/opentelemetry/sdk/metrics/SdkMeter;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/metrics/a;->a:I

    .line 2
    .line 3
    sparse-switch p0, :sswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lio/opentelemetry/sdk/metrics/SdkDoubleUpDownCounter$SdkDoubleUpDownCounterBuilder;

    .line 7
    .line 8
    move-object v1, p1

    .line 9
    move-object v2, p2

    .line 10
    move-object v3, p3

    .line 11
    move-object v4, p4

    .line 12
    move-object v5, p5

    .line 13
    invoke-direct/range {v0 .. v5}, Lio/opentelemetry/sdk/metrics/SdkDoubleUpDownCounter$SdkDoubleUpDownCounterBuilder;-><init>(Lio/opentelemetry/sdk/metrics/SdkMeter;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;)V

    .line 14
    .line 15
    .line 16
    return-object v0

    .line 17
    :sswitch_0
    new-instance p0, Lio/opentelemetry/sdk/metrics/SdkDoubleCounter$SdkDoubleCounterBuilder;

    .line 18
    .line 19
    invoke-direct/range {p0 .. p5}, Lio/opentelemetry/sdk/metrics/SdkDoubleCounter$SdkDoubleCounterBuilder;-><init>(Lio/opentelemetry/sdk/metrics/SdkMeter;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;)V

    .line 20
    .line 21
    .line 22
    return-object p0

    .line 23
    :sswitch_1
    new-instance p0, Lio/opentelemetry/sdk/metrics/SdkLongHistogram$SdkLongHistogramBuilder;

    .line 24
    .line 25
    invoke-direct/range {p0 .. p5}, Lio/opentelemetry/sdk/metrics/SdkLongHistogram$SdkLongHistogramBuilder;-><init>(Lio/opentelemetry/sdk/metrics/SdkMeter;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;)V

    .line 26
    .line 27
    .line 28
    return-object p0

    .line 29
    :sswitch_2
    new-instance p0, Lio/opentelemetry/sdk/metrics/SdkLongGauge$SdkLongGaugeBuilder;

    .line 30
    .line 31
    invoke-direct/range {p0 .. p5}, Lio/opentelemetry/sdk/metrics/SdkLongGauge$SdkLongGaugeBuilder;-><init>(Lio/opentelemetry/sdk/metrics/SdkMeter;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;)V

    .line 32
    .line 33
    .line 34
    return-object p0

    .line 35
    :sswitch_3
    new-instance p0, Lio/opentelemetry/sdk/metrics/ExtendedSdkDoubleUpDownCounter$ExtendedSdkDoubleUpDownCounterBuilder;

    .line 36
    .line 37
    invoke-direct/range {p0 .. p5}, Lio/opentelemetry/sdk/metrics/ExtendedSdkDoubleUpDownCounter$ExtendedSdkDoubleUpDownCounterBuilder;-><init>(Lio/opentelemetry/sdk/metrics/SdkMeter;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;)V

    .line 38
    .line 39
    .line 40
    return-object p0

    .line 41
    :sswitch_4
    new-instance p0, Lio/opentelemetry/sdk/metrics/ExtendedSdkDoubleCounter$ExtendedSdkDoubleCounterBuilder;

    .line 42
    .line 43
    invoke-direct/range {p0 .. p5}, Lio/opentelemetry/sdk/metrics/ExtendedSdkDoubleCounter$ExtendedSdkDoubleCounterBuilder;-><init>(Lio/opentelemetry/sdk/metrics/SdkMeter;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;)V

    .line 44
    .line 45
    .line 46
    return-object p0

    .line 47
    :sswitch_5
    new-instance p0, Lio/opentelemetry/sdk/metrics/ExtendedSdkLongHistogram$ExtendedSdkLongHistogramBuilder;

    .line 48
    .line 49
    invoke-direct/range {p0 .. p5}, Lio/opentelemetry/sdk/metrics/ExtendedSdkLongHistogram$ExtendedSdkLongHistogramBuilder;-><init>(Lio/opentelemetry/sdk/metrics/SdkMeter;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;)V

    .line 50
    .line 51
    .line 52
    return-object p0

    .line 53
    :sswitch_6
    new-instance p0, Lio/opentelemetry/sdk/metrics/ExtendedSdkLongGauge$ExtendedSdkLongGaugeBuilder;

    .line 54
    .line 55
    invoke-direct/range {p0 .. p5}, Lio/opentelemetry/sdk/metrics/ExtendedSdkLongGauge$ExtendedSdkLongGaugeBuilder;-><init>(Lio/opentelemetry/sdk/metrics/SdkMeter;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;)V

    .line 56
    .line 57
    .line 58
    return-object p0

    .line 59
    :sswitch_data_0
    .sparse-switch
        0x2 -> :sswitch_6
        0x3 -> :sswitch_5
        0x6 -> :sswitch_4
        0xa -> :sswitch_3
        0xd -> :sswitch_2
        0xf -> :sswitch_1
        0x12 -> :sswitch_0
    .end sparse-switch
.end method
