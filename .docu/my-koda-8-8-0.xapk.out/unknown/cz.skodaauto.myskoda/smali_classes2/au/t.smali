.class public final Lau/t;
.super Lcom/google/protobuf/p;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lau/u;


# static fields
.field public static final APPLICATION_INFO_FIELD_NUMBER:I = 0x1

.field private static final DEFAULT_INSTANCE:Lau/t;

.field public static final GAUGE_METRIC_FIELD_NUMBER:I = 0x4

.field public static final NETWORK_REQUEST_METRIC_FIELD_NUMBER:I = 0x3

.field private static volatile PARSER:Lcom/google/protobuf/r0; = null
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lcom/google/protobuf/r0;"
        }
    .end annotation
.end field

.field public static final TRACE_METRIC_FIELD_NUMBER:I = 0x2

.field public static final TRANSPORT_INFO_FIELD_NUMBER:I = 0x5


# instance fields
.field private applicationInfo_:Lau/g;

.field private bitField0_:I

.field private gaugeMetric_:Lau/o;

.field private networkRequestMetric_:Lau/r;

.field private traceMetric_:Lau/a0;

.field private transportInfo_:Lau/c0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lau/t;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/protobuf/p;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lau/t;->DEFAULT_INSTANCE:Lau/t;

    .line 7
    .line 8
    const-class v1, Lau/t;

    .line 9
    .line 10
    invoke-static {v1, v0}, Lcom/google/protobuf/p;->q(Ljava/lang/Class;Lcom/google/protobuf/p;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public static s(Lau/t;Lau/g;)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lau/t;->applicationInfo_:Lau/g;

    .line 5
    .line 6
    iget p1, p0, Lau/t;->bitField0_:I

    .line 7
    .line 8
    or-int/lit8 p1, p1, 0x1

    .line 9
    .line 10
    iput p1, p0, Lau/t;->bitField0_:I

    .line 11
    .line 12
    return-void
.end method

.method public static t(Lau/t;Lau/o;)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lau/t;->gaugeMetric_:Lau/o;

    .line 5
    .line 6
    iget p1, p0, Lau/t;->bitField0_:I

    .line 7
    .line 8
    or-int/lit8 p1, p1, 0x8

    .line 9
    .line 10
    iput p1, p0, Lau/t;->bitField0_:I

    .line 11
    .line 12
    return-void
.end method

.method public static u(Lau/t;Lau/a0;)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lau/t;->traceMetric_:Lau/a0;

    .line 5
    .line 6
    iget p1, p0, Lau/t;->bitField0_:I

    .line 7
    .line 8
    or-int/lit8 p1, p1, 0x2

    .line 9
    .line 10
    iput p1, p0, Lau/t;->bitField0_:I

    .line 11
    .line 12
    return-void
.end method

.method public static v(Lau/t;Lau/r;)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lau/t;->networkRequestMetric_:Lau/r;

    .line 5
    .line 6
    iget p1, p0, Lau/t;->bitField0_:I

    .line 7
    .line 8
    or-int/lit8 p1, p1, 0x4

    .line 9
    .line 10
    iput p1, p0, Lau/t;->bitField0_:I

    .line 11
    .line 12
    return-void
.end method

.method public static y()Lau/s;
    .locals 1

    .line 1
    sget-object v0, Lau/t;->DEFAULT_INSTANCE:Lau/t;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/protobuf/p;->j()Lcom/google/protobuf/n;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lau/s;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final a()Z
    .locals 0

    .line 1
    iget p0, p0, Lau/t;->bitField0_:I

    .line 2
    .line 3
    and-int/lit8 p0, p0, 0x8

    .line 4
    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 p0, 0x0

    .line 10
    return p0
.end method

.method public final b()Z
    .locals 0

    .line 1
    iget p0, p0, Lau/t;->bitField0_:I

    .line 2
    .line 3
    and-int/lit8 p0, p0, 0x4

    .line 4
    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 p0, 0x0

    .line 10
    return p0
.end method

.method public final c()Lau/r;
    .locals 0

    .line 1
    iget-object p0, p0, Lau/t;->networkRequestMetric_:Lau/r;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lau/r;->G()Lau/r;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :cond_0
    return-object p0
.end method

.method public final d()Z
    .locals 0

    .line 1
    iget p0, p0, Lau/t;->bitField0_:I

    .line 2
    .line 3
    and-int/lit8 p0, p0, 0x2

    .line 4
    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 p0, 0x0

    .line 10
    return p0
.end method

.method public final e()Lau/a0;
    .locals 0

    .line 1
    iget-object p0, p0, Lau/t;->traceMetric_:Lau/a0;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lau/a0;->F()Lau/a0;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :cond_0
    return-object p0
.end method

.method public final f()Lau/o;
    .locals 0

    .line 1
    iget-object p0, p0, Lau/t;->gaugeMetric_:Lau/o;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lau/o;->y()Lau/o;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :cond_0
    return-object p0
.end method

.method public final k(I)Ljava/lang/Object;
    .locals 6

    .line 1
    invoke-static {p1}, Lu/w;->o(I)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    packed-switch p0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 9
    .line 10
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 11
    .line 12
    .line 13
    throw p0

    .line 14
    :pswitch_0
    sget-object p0, Lau/t;->PARSER:Lcom/google/protobuf/r0;

    .line 15
    .line 16
    if-nez p0, :cond_1

    .line 17
    .line 18
    const-class p1, Lau/t;

    .line 19
    .line 20
    monitor-enter p1

    .line 21
    :try_start_0
    sget-object p0, Lau/t;->PARSER:Lcom/google/protobuf/r0;

    .line 22
    .line 23
    if-nez p0, :cond_0

    .line 24
    .line 25
    new-instance p0, Lcom/google/protobuf/o;

    .line 26
    .line 27
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 28
    .line 29
    .line 30
    sput-object p0, Lau/t;->PARSER:Lcom/google/protobuf/r0;

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :catchall_0
    move-exception v0

    .line 34
    move-object p0, v0

    .line 35
    goto :goto_1

    .line 36
    :cond_0
    :goto_0
    monitor-exit p1

    .line 37
    return-object p0

    .line 38
    :goto_1
    monitor-exit p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 39
    throw p0

    .line 40
    :cond_1
    return-object p0

    .line 41
    :pswitch_1
    sget-object p0, Lau/t;->DEFAULT_INSTANCE:Lau/t;

    .line 42
    .line 43
    return-object p0

    .line 44
    :pswitch_2
    new-instance p0, Lau/s;

    .line 45
    .line 46
    sget-object p1, Lau/t;->DEFAULT_INSTANCE:Lau/t;

    .line 47
    .line 48
    invoke-direct {p0, p1}, Lcom/google/protobuf/n;-><init>(Lcom/google/protobuf/p;)V

    .line 49
    .line 50
    .line 51
    return-object p0

    .line 52
    :pswitch_3
    new-instance p0, Lau/t;

    .line 53
    .line 54
    invoke-direct {p0}, Lcom/google/protobuf/p;-><init>()V

    .line 55
    .line 56
    .line 57
    return-object p0

    .line 58
    :pswitch_4
    const-string v0, "bitField0_"

    .line 59
    .line 60
    const-string v1, "applicationInfo_"

    .line 61
    .line 62
    const-string v2, "traceMetric_"

    .line 63
    .line 64
    const-string v3, "networkRequestMetric_"

    .line 65
    .line 66
    const-string v4, "gaugeMetric_"

    .line 67
    .line 68
    const-string v5, "transportInfo_"

    .line 69
    .line 70
    filled-new-array/range {v0 .. v5}, [Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    const-string p1, "\u0001\u0005\u0000\u0001\u0001\u0005\u0005\u0000\u0000\u0000\u0001\u1009\u0000\u0002\u1009\u0001\u0003\u1009\u0002\u0004\u1009\u0003\u0005\u1009\u0004"

    .line 75
    .line 76
    sget-object v0, Lau/t;->DEFAULT_INSTANCE:Lau/t;

    .line 77
    .line 78
    new-instance v1, Lcom/google/protobuf/v0;

    .line 79
    .line 80
    invoke-direct {v1, v0, p1, p0}, Lcom/google/protobuf/v0;-><init>(Lcom/google/protobuf/a;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    return-object v1

    .line 84
    :pswitch_5
    const/4 p0, 0x0

    .line 85
    return-object p0

    .line 86
    :pswitch_6
    const/4 p0, 0x1

    .line 87
    invoke-static {p0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    return-object p0

    .line 92
    nop

    .line 93
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

.method public final w()Lau/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lau/t;->applicationInfo_:Lau/g;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lau/g;->y()Lau/g;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :cond_0
    return-object p0
.end method

.method public final x()Z
    .locals 1

    .line 1
    iget p0, p0, Lau/t;->bitField0_:I

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    and-int/2addr p0, v0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    return v0

    .line 8
    :cond_0
    const/4 p0, 0x0

    .line 9
    return p0
.end method
