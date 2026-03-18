.class public final Lau/r;
.super Lcom/google/protobuf/p;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CLIENT_START_TIME_US_FIELD_NUMBER:I = 0x7

.field public static final CUSTOM_ATTRIBUTES_FIELD_NUMBER:I = 0xc

.field private static final DEFAULT_INSTANCE:Lau/r;

.field public static final HTTP_METHOD_FIELD_NUMBER:I = 0x2

.field public static final HTTP_RESPONSE_CODE_FIELD_NUMBER:I = 0x5

.field public static final NETWORK_CLIENT_ERROR_REASON_FIELD_NUMBER:I = 0xb

.field private static volatile PARSER:Lcom/google/protobuf/r0; = null
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lcom/google/protobuf/r0;"
        }
    .end annotation
.end field

.field public static final PERF_SESSIONS_FIELD_NUMBER:I = 0xd

.field public static final REQUEST_PAYLOAD_BYTES_FIELD_NUMBER:I = 0x3

.field public static final RESPONSE_CONTENT_TYPE_FIELD_NUMBER:I = 0x6

.field public static final RESPONSE_PAYLOAD_BYTES_FIELD_NUMBER:I = 0x4

.field public static final TIME_TO_REQUEST_COMPLETED_US_FIELD_NUMBER:I = 0x8

.field public static final TIME_TO_RESPONSE_COMPLETED_US_FIELD_NUMBER:I = 0xa

.field public static final TIME_TO_RESPONSE_INITIATED_US_FIELD_NUMBER:I = 0x9

.field public static final URL_FIELD_NUMBER:I = 0x1


# instance fields
.field private bitField0_:I

.field private clientStartTimeUs_:J

.field private customAttributes_:Lcom/google/protobuf/i0;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lcom/google/protobuf/i0;"
        }
    .end annotation
.end field

.field private httpMethod_:I

.field private httpResponseCode_:I

.field private networkClientErrorReason_:I

.field private perfSessions_:Lcom/google/protobuf/t;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lcom/google/protobuf/t;"
        }
    .end annotation
.end field

.field private requestPayloadBytes_:J

.field private responseContentType_:Ljava/lang/String;

.field private responsePayloadBytes_:J

.field private timeToRequestCompletedUs_:J

.field private timeToResponseCompletedUs_:J

.field private timeToResponseInitiatedUs_:J

.field private url_:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lau/r;

    .line 2
    .line 3
    invoke-direct {v0}, Lau/r;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lau/r;->DEFAULT_INSTANCE:Lau/r;

    .line 7
    .line 8
    const-class v1, Lau/r;

    .line 9
    .line 10
    invoke-static {v1, v0}, Lcom/google/protobuf/p;->q(Ljava/lang/Class;Lcom/google/protobuf/p;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Lcom/google/protobuf/p;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lcom/google/protobuf/i0;->e:Lcom/google/protobuf/i0;

    .line 5
    .line 6
    iput-object v0, p0, Lau/r;->customAttributes_:Lcom/google/protobuf/i0;

    .line 7
    .line 8
    const-string v0, ""

    .line 9
    .line 10
    iput-object v0, p0, Lau/r;->url_:Ljava/lang/String;

    .line 11
    .line 12
    iput-object v0, p0, Lau/r;->responseContentType_:Ljava/lang/String;

    .line 13
    .line 14
    sget-object v0, Lcom/google/protobuf/u0;->g:Lcom/google/protobuf/u0;

    .line 15
    .line 16
    iput-object v0, p0, Lau/r;->perfSessions_:Lcom/google/protobuf/t;

    .line 17
    .line 18
    return-void
.end method

.method public static A(Lau/r;J)V
    .locals 1

    .line 1
    iget v0, p0, Lau/r;->bitField0_:I

    .line 2
    .line 3
    or-int/lit16 v0, v0, 0x400

    .line 4
    .line 5
    iput v0, p0, Lau/r;->bitField0_:I

    .line 6
    .line 7
    iput-wide p1, p0, Lau/r;->timeToResponseCompletedUs_:J

    .line 8
    .line 9
    return-void
.end method

.method public static B(Lau/r;Ljava/util/List;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lau/r;->perfSessions_:Lcom/google/protobuf/t;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lcom/google/protobuf/b;

    .line 5
    .line 6
    iget-boolean v1, v1, Lcom/google/protobuf/b;->d:Z

    .line 7
    .line 8
    if-nez v1, :cond_0

    .line 9
    .line 10
    invoke-static {v0}, Lcom/google/protobuf/p;->p(Lcom/google/protobuf/t;)Lcom/google/protobuf/t;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iput-object v0, p0, Lau/r;->perfSessions_:Lcom/google/protobuf/t;

    .line 15
    .line 16
    :cond_0
    iget-object p0, p0, Lau/r;->perfSessions_:Lcom/google/protobuf/t;

    .line 17
    .line 18
    invoke-static {p1, p0}, Lcom/google/protobuf/a;->g(Ljava/lang/Iterable;Ljava/util/List;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public static C(Lau/r;I)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Lu/w;->o(I)I

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    iput p1, p0, Lau/r;->httpMethod_:I

    .line 9
    .line 10
    iget p1, p0, Lau/r;->bitField0_:I

    .line 11
    .line 12
    or-int/lit8 p1, p1, 0x2

    .line 13
    .line 14
    iput p1, p0, Lau/r;->bitField0_:I

    .line 15
    .line 16
    return-void
.end method

.method public static D(Lau/r;J)V
    .locals 1

    .line 1
    iget v0, p0, Lau/r;->bitField0_:I

    .line 2
    .line 3
    or-int/lit8 v0, v0, 0x4

    .line 4
    .line 5
    iput v0, p0, Lau/r;->bitField0_:I

    .line 6
    .line 7
    iput-wide p1, p0, Lau/r;->requestPayloadBytes_:J

    .line 8
    .line 9
    return-void
.end method

.method public static E(Lau/r;J)V
    .locals 1

    .line 1
    iget v0, p0, Lau/r;->bitField0_:I

    .line 2
    .line 3
    or-int/lit8 v0, v0, 0x8

    .line 4
    .line 5
    iput v0, p0, Lau/r;->bitField0_:I

    .line 6
    .line 7
    iput-wide p1, p0, Lau/r;->responsePayloadBytes_:J

    .line 8
    .line 9
    return-void
.end method

.method public static G()Lau/r;
    .locals 1

    .line 1
    sget-object v0, Lau/r;->DEFAULT_INSTANCE:Lau/r;

    .line 2
    .line 3
    return-object v0
.end method

.method public static Y()Lau/p;
    .locals 1

    .line 1
    sget-object v0, Lau/r;->DEFAULT_INSTANCE:Lau/r;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/protobuf/p;->j()Lcom/google/protobuf/n;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lau/p;

    .line 8
    .line 9
    return-object v0
.end method

.method public static s(Lau/r;Ljava/lang/String;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 5
    .line 6
    .line 7
    iget v0, p0, Lau/r;->bitField0_:I

    .line 8
    .line 9
    or-int/lit8 v0, v0, 0x1

    .line 10
    .line 11
    iput v0, p0, Lau/r;->bitField0_:I

    .line 12
    .line 13
    iput-object p1, p0, Lau/r;->url_:Ljava/lang/String;

    .line 14
    .line 15
    return-void
.end method

.method public static t(Lau/r;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x2

    .line 5
    invoke-static {v0}, Lu/w;->o(I)I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    iput v0, p0, Lau/r;->networkClientErrorReason_:I

    .line 10
    .line 11
    iget v0, p0, Lau/r;->bitField0_:I

    .line 12
    .line 13
    or-int/lit8 v0, v0, 0x10

    .line 14
    .line 15
    iput v0, p0, Lau/r;->bitField0_:I

    .line 16
    .line 17
    return-void
.end method

.method public static u(Lau/r;I)V
    .locals 1

    .line 1
    iget v0, p0, Lau/r;->bitField0_:I

    .line 2
    .line 3
    or-int/lit8 v0, v0, 0x20

    .line 4
    .line 5
    iput v0, p0, Lau/r;->bitField0_:I

    .line 6
    .line 7
    iput p1, p0, Lau/r;->httpResponseCode_:I

    .line 8
    .line 9
    return-void
.end method

.method public static v(Lau/r;Ljava/lang/String;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 5
    .line 6
    .line 7
    iget v0, p0, Lau/r;->bitField0_:I

    .line 8
    .line 9
    or-int/lit8 v0, v0, 0x40

    .line 10
    .line 11
    iput v0, p0, Lau/r;->bitField0_:I

    .line 12
    .line 13
    iput-object p1, p0, Lau/r;->responseContentType_:Ljava/lang/String;

    .line 14
    .line 15
    return-void
.end method

.method public static w(Lau/r;)V
    .locals 1

    .line 1
    iget v0, p0, Lau/r;->bitField0_:I

    .line 2
    .line 3
    and-int/lit8 v0, v0, -0x41

    .line 4
    .line 5
    iput v0, p0, Lau/r;->bitField0_:I

    .line 6
    .line 7
    sget-object v0, Lau/r;->DEFAULT_INSTANCE:Lau/r;

    .line 8
    .line 9
    iget-object v0, v0, Lau/r;->responseContentType_:Ljava/lang/String;

    .line 10
    .line 11
    iput-object v0, p0, Lau/r;->responseContentType_:Ljava/lang/String;

    .line 12
    .line 13
    return-void
.end method

.method public static x(Lau/r;J)V
    .locals 1

    .line 1
    iget v0, p0, Lau/r;->bitField0_:I

    .line 2
    .line 3
    or-int/lit16 v0, v0, 0x80

    .line 4
    .line 5
    iput v0, p0, Lau/r;->bitField0_:I

    .line 6
    .line 7
    iput-wide p1, p0, Lau/r;->clientStartTimeUs_:J

    .line 8
    .line 9
    return-void
.end method

.method public static y(Lau/r;J)V
    .locals 1

    .line 1
    iget v0, p0, Lau/r;->bitField0_:I

    .line 2
    .line 3
    or-int/lit16 v0, v0, 0x100

    .line 4
    .line 5
    iput v0, p0, Lau/r;->bitField0_:I

    .line 6
    .line 7
    iput-wide p1, p0, Lau/r;->timeToRequestCompletedUs_:J

    .line 8
    .line 9
    return-void
.end method

.method public static z(Lau/r;J)V
    .locals 1

    .line 1
    iget v0, p0, Lau/r;->bitField0_:I

    .line 2
    .line 3
    or-int/lit16 v0, v0, 0x200

    .line 4
    .line 5
    iput v0, p0, Lau/r;->bitField0_:I

    .line 6
    .line 7
    iput-wide p1, p0, Lau/r;->timeToResponseInitiatedUs_:J

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final F()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lau/r;->clientStartTimeUs_:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final H()I
    .locals 1

    .line 1
    iget p0, p0, Lau/r;->httpMethod_:I

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    packed-switch p0, :pswitch_data_0

    .line 5
    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    goto :goto_0

    .line 9
    :pswitch_0
    const/16 p0, 0xa

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :pswitch_1
    const/16 p0, 0x9

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :pswitch_2
    const/16 p0, 0x8

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :pswitch_3
    const/4 p0, 0x7

    .line 19
    goto :goto_0

    .line 20
    :pswitch_4
    const/4 p0, 0x6

    .line 21
    goto :goto_0

    .line 22
    :pswitch_5
    const/4 p0, 0x5

    .line 23
    goto :goto_0

    .line 24
    :pswitch_6
    const/4 p0, 0x4

    .line 25
    goto :goto_0

    .line 26
    :pswitch_7
    const/4 p0, 0x3

    .line 27
    goto :goto_0

    .line 28
    :pswitch_8
    const/4 p0, 0x2

    .line 29
    goto :goto_0

    .line 30
    :pswitch_9
    move p0, v0

    .line 31
    :goto_0
    if-nez p0, :cond_0

    .line 32
    .line 33
    return v0

    .line 34
    :cond_0
    return p0

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_9
        :pswitch_8
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

.method public final I()I
    .locals 0

    .line 1
    iget p0, p0, Lau/r;->httpResponseCode_:I

    .line 2
    .line 3
    return p0
.end method

.method public final J()Lcom/google/protobuf/t;
    .locals 0

    .line 1
    iget-object p0, p0, Lau/r;->perfSessions_:Lcom/google/protobuf/t;

    .line 2
    .line 3
    return-object p0
.end method

.method public final K()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lau/r;->requestPayloadBytes_:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final L()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lau/r;->responsePayloadBytes_:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final M()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lau/r;->timeToRequestCompletedUs_:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final N()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lau/r;->timeToResponseCompletedUs_:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final O()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lau/r;->timeToResponseInitiatedUs_:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final P()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lau/r;->url_:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final Q()Z
    .locals 0

    .line 1
    iget p0, p0, Lau/r;->bitField0_:I

    .line 2
    .line 3
    and-int/lit16 p0, p0, 0x80

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

.method public final R()Z
    .locals 0

    .line 1
    iget p0, p0, Lau/r;->bitField0_:I

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

.method public final S()Z
    .locals 0

    .line 1
    iget p0, p0, Lau/r;->bitField0_:I

    .line 2
    .line 3
    and-int/lit8 p0, p0, 0x20

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

.method public final T()Z
    .locals 0

    .line 1
    iget p0, p0, Lau/r;->bitField0_:I

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

.method public final U()Z
    .locals 0

    .line 1
    iget p0, p0, Lau/r;->bitField0_:I

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

.method public final V()Z
    .locals 0

    .line 1
    iget p0, p0, Lau/r;->bitField0_:I

    .line 2
    .line 3
    and-int/lit16 p0, p0, 0x100

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

.method public final W()Z
    .locals 0

    .line 1
    iget p0, p0, Lau/r;->bitField0_:I

    .line 2
    .line 3
    and-int/lit16 p0, p0, 0x400

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

.method public final X()Z
    .locals 0

    .line 1
    iget p0, p0, Lau/r;->bitField0_:I

    .line 2
    .line 3
    and-int/lit16 p0, p0, 0x200

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

.method public final k(I)Ljava/lang/Object;
    .locals 20

    .line 1
    invoke-static/range {p1 .. p1}, Lu/w;->o(I)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 9
    .line 10
    invoke-direct {v0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 11
    .line 12
    .line 13
    throw v0

    .line 14
    :pswitch_0
    sget-object v0, Lau/r;->PARSER:Lcom/google/protobuf/r0;

    .line 15
    .line 16
    if-nez v0, :cond_1

    .line 17
    .line 18
    const-class v1, Lau/r;

    .line 19
    .line 20
    monitor-enter v1

    .line 21
    :try_start_0
    sget-object v0, Lau/r;->PARSER:Lcom/google/protobuf/r0;

    .line 22
    .line 23
    if-nez v0, :cond_0

    .line 24
    .line 25
    new-instance v0, Lcom/google/protobuf/o;

    .line 26
    .line 27
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 28
    .line 29
    .line 30
    sput-object v0, Lau/r;->PARSER:Lcom/google/protobuf/r0;

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :catchall_0
    move-exception v0

    .line 34
    goto :goto_1

    .line 35
    :cond_0
    :goto_0
    monitor-exit v1

    .line 36
    return-object v0

    .line 37
    :goto_1
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 38
    throw v0

    .line 39
    :cond_1
    return-object v0

    .line 40
    :pswitch_1
    sget-object v0, Lau/r;->DEFAULT_INSTANCE:Lau/r;

    .line 41
    .line 42
    return-object v0

    .line 43
    :pswitch_2
    new-instance v0, Lau/p;

    .line 44
    .line 45
    sget-object v1, Lau/r;->DEFAULT_INSTANCE:Lau/r;

    .line 46
    .line 47
    invoke-direct {v0, v1}, Lcom/google/protobuf/n;-><init>(Lcom/google/protobuf/p;)V

    .line 48
    .line 49
    .line 50
    return-object v0

    .line 51
    :pswitch_3
    new-instance v0, Lau/r;

    .line 52
    .line 53
    invoke-direct {v0}, Lau/r;-><init>()V

    .line 54
    .line 55
    .line 56
    return-object v0

    .line 57
    :pswitch_4
    const-string v2, "bitField0_"

    .line 58
    .line 59
    const-string v3, "url_"

    .line 60
    .line 61
    const-string v4, "httpMethod_"

    .line 62
    .line 63
    sget-object v5, Lau/h;->b:Lau/h;

    .line 64
    .line 65
    const-string v6, "requestPayloadBytes_"

    .line 66
    .line 67
    const-string v7, "responsePayloadBytes_"

    .line 68
    .line 69
    const-string v8, "httpResponseCode_"

    .line 70
    .line 71
    const-string v9, "responseContentType_"

    .line 72
    .line 73
    const-string v10, "clientStartTimeUs_"

    .line 74
    .line 75
    const-string v11, "timeToRequestCompletedUs_"

    .line 76
    .line 77
    const-string v12, "timeToResponseInitiatedUs_"

    .line 78
    .line 79
    const-string v13, "timeToResponseCompletedUs_"

    .line 80
    .line 81
    const-string v14, "networkClientErrorReason_"

    .line 82
    .line 83
    sget-object v15, Lau/h;->c:Lau/h;

    .line 84
    .line 85
    const-string v16, "customAttributes_"

    .line 86
    .line 87
    sget-object v17, Lau/q;->a:Lcom/google/protobuf/h0;

    .line 88
    .line 89
    const-string v18, "perfSessions_"

    .line 90
    .line 91
    const-class v19, Lau/w;

    .line 92
    .line 93
    filled-new-array/range {v2 .. v19}, [Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    const-string v1, "\u0001\r\u0000\u0001\u0001\r\r\u0001\u0001\u0000\u0001\u1008\u0000\u0002\u180c\u0001\u0003\u1002\u0002\u0004\u1002\u0003\u0005\u1004\u0005\u0006\u1008\u0006\u0007\u1002\u0007\u0008\u1002\u0008\t\u1002\t\n\u1002\n\u000b\u180c\u0004\u000c2\r\u001b"

    .line 98
    .line 99
    sget-object v2, Lau/r;->DEFAULT_INSTANCE:Lau/r;

    .line 100
    .line 101
    new-instance v3, Lcom/google/protobuf/v0;

    .line 102
    .line 103
    invoke-direct {v3, v2, v1, v0}, Lcom/google/protobuf/v0;-><init>(Lcom/google/protobuf/a;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 104
    .line 105
    .line 106
    return-object v3

    .line 107
    :pswitch_5
    const/4 v0, 0x0

    .line 108
    return-object v0

    .line 109
    :pswitch_6
    const/4 v0, 0x1

    .line 110
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 111
    .line 112
    .line 113
    move-result-object v0

    .line 114
    return-object v0

    .line 115
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
