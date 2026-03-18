.class public final Lau/g;
.super Lcom/google/protobuf/p;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final ANDROID_APP_INFO_FIELD_NUMBER:I = 0x3

.field public static final APPLICATION_PROCESS_STATE_FIELD_NUMBER:I = 0x5

.field public static final APP_INSTANCE_ID_FIELD_NUMBER:I = 0x2

.field public static final CUSTOM_ATTRIBUTES_FIELD_NUMBER:I = 0x6

.field private static final DEFAULT_INSTANCE:Lau/g;

.field public static final GOOGLE_APP_ID_FIELD_NUMBER:I = 0x1

.field private static volatile PARSER:Lcom/google/protobuf/r0;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lcom/google/protobuf/r0;"
        }
    .end annotation
.end field


# instance fields
.field private androidAppInfo_:Lau/b;

.field private appInstanceId_:Ljava/lang/String;

.field private applicationProcessState_:I

.field private bitField0_:I

.field private customAttributes_:Lcom/google/protobuf/i0;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lcom/google/protobuf/i0;"
        }
    .end annotation
.end field

.field private googleAppId_:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lau/g;

    .line 2
    .line 3
    invoke-direct {v0}, Lau/g;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lau/g;->DEFAULT_INSTANCE:Lau/g;

    .line 7
    .line 8
    const-class v1, Lau/g;

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
    iput-object v0, p0, Lau/g;->customAttributes_:Lcom/google/protobuf/i0;

    .line 7
    .line 8
    const-string v0, ""

    .line 9
    .line 10
    iput-object v0, p0, Lau/g;->googleAppId_:Ljava/lang/String;

    .line 11
    .line 12
    iput-object v0, p0, Lau/g;->appInstanceId_:Ljava/lang/String;

    .line 13
    .line 14
    return-void
.end method

.method public static D()Lau/e;
    .locals 1

    .line 1
    sget-object v0, Lau/g;->DEFAULT_INSTANCE:Lau/g;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/protobuf/p;->j()Lcom/google/protobuf/n;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lau/e;

    .line 8
    .line 9
    return-object v0
.end method

.method public static s(Lau/g;Ljava/lang/String;)V
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
    iget v0, p0, Lau/g;->bitField0_:I

    .line 8
    .line 9
    or-int/lit8 v0, v0, 0x1

    .line 10
    .line 11
    iput v0, p0, Lau/g;->bitField0_:I

    .line 12
    .line 13
    iput-object p1, p0, Lau/g;->googleAppId_:Ljava/lang/String;

    .line 14
    .line 15
    return-void
.end method

.method public static t(Lau/g;Lau/i;)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    iget p1, p1, Lau/i;->d:I

    .line 5
    .line 6
    iput p1, p0, Lau/g;->applicationProcessState_:I

    .line 7
    .line 8
    iget p1, p0, Lau/g;->bitField0_:I

    .line 9
    .line 10
    or-int/lit8 p1, p1, 0x8

    .line 11
    .line 12
    iput p1, p0, Lau/g;->bitField0_:I

    .line 13
    .line 14
    return-void
.end method

.method public static u(Lau/g;)Lcom/google/protobuf/i0;
    .locals 2

    .line 1
    iget-object v0, p0, Lau/g;->customAttributes_:Lcom/google/protobuf/i0;

    .line 2
    .line 3
    iget-boolean v1, v0, Lcom/google/protobuf/i0;->d:Z

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    invoke-virtual {v0}, Lcom/google/protobuf/i0;->c()Lcom/google/protobuf/i0;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iput-object v0, p0, Lau/g;->customAttributes_:Lcom/google/protobuf/i0;

    .line 12
    .line 13
    :cond_0
    iget-object p0, p0, Lau/g;->customAttributes_:Lcom/google/protobuf/i0;

    .line 14
    .line 15
    return-object p0
.end method

.method public static v(Lau/g;Ljava/lang/String;)V
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
    iget v0, p0, Lau/g;->bitField0_:I

    .line 8
    .line 9
    or-int/lit8 v0, v0, 0x2

    .line 10
    .line 11
    iput v0, p0, Lau/g;->bitField0_:I

    .line 12
    .line 13
    iput-object p1, p0, Lau/g;->appInstanceId_:Ljava/lang/String;

    .line 14
    .line 15
    return-void
.end method

.method public static w(Lau/g;Lau/b;)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lau/g;->androidAppInfo_:Lau/b;

    .line 5
    .line 6
    iget p1, p0, Lau/g;->bitField0_:I

    .line 7
    .line 8
    or-int/lit8 p1, p1, 0x4

    .line 9
    .line 10
    iput p1, p0, Lau/g;->bitField0_:I

    .line 11
    .line 12
    return-void
.end method

.method public static y()Lau/g;
    .locals 1

    .line 1
    sget-object v0, Lau/g;->DEFAULT_INSTANCE:Lau/g;

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public final A()Z
    .locals 0

    .line 1
    iget p0, p0, Lau/g;->bitField0_:I

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

.method public final B()Z
    .locals 0

    .line 1
    iget p0, p0, Lau/g;->bitField0_:I

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

.method public final C()Z
    .locals 1

    .line 1
    iget p0, p0, Lau/g;->bitField0_:I

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

.method public final k(I)Ljava/lang/Object;
    .locals 8

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
    sget-object p0, Lau/g;->PARSER:Lcom/google/protobuf/r0;

    .line 15
    .line 16
    if-nez p0, :cond_1

    .line 17
    .line 18
    const-class p1, Lau/g;

    .line 19
    .line 20
    monitor-enter p1

    .line 21
    :try_start_0
    sget-object p0, Lau/g;->PARSER:Lcom/google/protobuf/r0;

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
    sput-object p0, Lau/g;->PARSER:Lcom/google/protobuf/r0;

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
    sget-object p0, Lau/g;->DEFAULT_INSTANCE:Lau/g;

    .line 42
    .line 43
    return-object p0

    .line 44
    :pswitch_2
    new-instance p0, Lau/e;

    .line 45
    .line 46
    sget-object p1, Lau/g;->DEFAULT_INSTANCE:Lau/g;

    .line 47
    .line 48
    invoke-direct {p0, p1}, Lcom/google/protobuf/n;-><init>(Lcom/google/protobuf/p;)V

    .line 49
    .line 50
    .line 51
    return-object p0

    .line 52
    :pswitch_3
    new-instance p0, Lau/g;

    .line 53
    .line 54
    invoke-direct {p0}, Lau/g;-><init>()V

    .line 55
    .line 56
    .line 57
    return-object p0

    .line 58
    :pswitch_4
    const-string v0, "bitField0_"

    .line 59
    .line 60
    const-string v1, "googleAppId_"

    .line 61
    .line 62
    const-string v2, "appInstanceId_"

    .line 63
    .line 64
    const-string v3, "androidAppInfo_"

    .line 65
    .line 66
    const-string v4, "applicationProcessState_"

    .line 67
    .line 68
    sget-object v5, Lau/h;->a:Lau/h;

    .line 69
    .line 70
    const-string v6, "customAttributes_"

    .line 71
    .line 72
    sget-object v7, Lau/f;->a:Lcom/google/protobuf/h0;

    .line 73
    .line 74
    filled-new-array/range {v0 .. v7}, [Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    const-string p1, "\u0001\u0005\u0000\u0001\u0001\u0006\u0005\u0001\u0000\u0000\u0001\u1008\u0000\u0002\u1008\u0001\u0003\u1009\u0002\u0005\u180c\u0003\u00062"

    .line 79
    .line 80
    sget-object v0, Lau/g;->DEFAULT_INSTANCE:Lau/g;

    .line 81
    .line 82
    new-instance v1, Lcom/google/protobuf/v0;

    .line 83
    .line 84
    invoke-direct {v1, v0, p1, p0}, Lcom/google/protobuf/v0;-><init>(Lcom/google/protobuf/a;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    return-object v1

    .line 88
    :pswitch_5
    const/4 p0, 0x0

    .line 89
    return-object p0

    .line 90
    :pswitch_6
    const/4 p0, 0x1

    .line 91
    invoke-static {p0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    return-object p0

    .line 96
    nop

    .line 97
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

.method public final x()Lau/b;
    .locals 0

    .line 1
    iget-object p0, p0, Lau/g;->androidAppInfo_:Lau/b;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lau/b;->v()Lau/b;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :cond_0
    return-object p0
.end method

.method public final z()Z
    .locals 0

    .line 1
    iget p0, p0, Lau/g;->bitField0_:I

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
