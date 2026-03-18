.class public final Lio/opentelemetry/exporter/internal/grpc/GrpcExporterUtil;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final GRPC_STATUS_ABORTED:I = 0xa

.field public static final GRPC_STATUS_CANCELLED:I = 0x1

.field public static final GRPC_STATUS_DATA_LOSS:I = 0xf

.field public static final GRPC_STATUS_DEADLINE_EXCEEDED:I = 0x4

.field public static final GRPC_STATUS_OUT_OF_RANGE:I = 0xb

.field public static final GRPC_STATUS_RESOURCE_EXHAUSTED:I = 0x8

.field public static final GRPC_STATUS_UNAVAILABLE:I = 0xe

.field public static final GRPC_STATUS_UNIMPLEMENTED:I = 0xc

.field public static final GRPC_STATUS_UNKNOWN:I = 0x2


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static getStatusMessage([B)Ljava/lang/String;
    .locals 3

    .line 1
    invoke-static {p0}, Lio/opentelemetry/exporter/internal/marshal/CodedInputStream;->newInstance([B)Lio/opentelemetry/exporter/internal/marshal/CodedInputStream;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const/4 v0, 0x0

    .line 6
    :goto_0
    if-nez v0, :cond_2

    .line 7
    .line 8
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/CodedInputStream;->readTag()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    if-eqz v1, :cond_1

    .line 13
    .line 14
    const/16 v2, 0x12

    .line 15
    .line 16
    if-eq v1, v2, :cond_0

    .line 17
    .line 18
    invoke-virtual {p0, v1}, Lio/opentelemetry/exporter/internal/marshal/CodedInputStream;->skipField(I)Z

    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/CodedInputStream;->readStringRequireUtf8()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0

    .line 27
    :cond_1
    const/4 v0, 0x1

    .line 28
    goto :goto_0

    .line 29
    :cond_2
    const-string p0, ""

    .line 30
    .line 31
    return-object p0
.end method

.method public static logUnimplemented(Ljava/util/logging/Logger;Ljava/lang/String;Ljava/lang/String;)V
    .locals 5
    .param p2    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    const-string v0, "profile"

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    sget-object p1, Ljava/util/logging/Level;->SEVERE:Ljava/util/logging/Level;

    .line 10
    .line 11
    new-instance v0, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    const-string v1, "Failed to export profile. The profile signal type is still under development and the endpoint you are connecting to may not support it yet, or may support a different version. Full error message: "

    .line 14
    .line 15
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p2

    .line 25
    invoke-virtual {p0, p1, p2}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    return-void

    .line 29
    :cond_0
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 30
    .line 31
    .line 32
    invoke-virtual {p1}, Ljava/lang/String;->hashCode()I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    const/4 v1, -0x1

    .line 37
    sparse-switch v0, :sswitch_data_0

    .line 38
    .line 39
    .line 40
    goto :goto_0

    .line 41
    :sswitch_0
    const-string v0, "span"

    .line 42
    .line 43
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    if-nez v0, :cond_1

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_1
    const/4 v1, 0x2

    .line 51
    goto :goto_0

    .line 52
    :sswitch_1
    const-string v0, "log"

    .line 53
    .line 54
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    if-nez v0, :cond_2

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_2
    const/4 v1, 0x1

    .line 62
    goto :goto_0

    .line 63
    :sswitch_2
    const-string v0, "metric"

    .line 64
    .line 65
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    if-nez v0, :cond_3

    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_3
    const/4 v1, 0x0

    .line 73
    :goto_0
    packed-switch v1, :pswitch_data_0

    .line 74
    .line 75
    .line 76
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 77
    .line 78
    const-string p1, "Unrecognized type, this is a programming bug in the OpenTelemetry SDK"

    .line 79
    .line 80
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    throw p0

    .line 84
    :pswitch_0
    const-string v0, "OTEL_TRACES_EXPORTER"

    .line 85
    .line 86
    goto :goto_1

    .line 87
    :pswitch_1
    const-string v0, "OTEL_LOGS_EXPORTER"

    .line 88
    .line 89
    goto :goto_1

    .line 90
    :pswitch_2
    const-string v0, "OTEL_METRICS_EXPORTER"

    .line 91
    .line 92
    :goto_1
    sget-object v1, Ljava/util/logging/Level;->SEVERE:Ljava/util/logging/Level;

    .line 93
    .line 94
    const-string v2, "s. Server responded with UNIMPLEMENTED. This usually means that your collector is not configured with an otlp receiver in the \"pipelines\" section of the configuration. If export is not desired and you are using OpenTelemetry autoconfiguration or the javaagent, disable export by setting "

    .line 95
    .line 96
    const-string v3, "=none. Full error message: "

    .line 97
    .line 98
    const-string v4, "Failed to export "

    .line 99
    .line 100
    invoke-static {v4, p1, v2, v0, v3}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    move-result-object p1

    .line 104
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 105
    .line 106
    .line 107
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object p1

    .line 111
    invoke-virtual {p0, v1, p1}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    return-void

    :sswitch_data_0
    .sparse-switch
        -0x403a0a50 -> :sswitch_2
        0x1a344 -> :sswitch_1
        0x35f74a -> :sswitch_0
    .end sparse-switch

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
