.class public Lio/getlime/security/powerauth/core/EciesEncryptor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private handle:J

.field private metadata:Lio/getlime/security/powerauth/ecies/EciesMetadata;

.field private final timeService:Lio/getlime/security/powerauth/core/ICoreTimeService;

.field private timeSynchronizationTask:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "PowerAuth2Module"

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method private constructor <init>(JLio/getlime/security/powerauth/core/ICoreTimeService;)V
    .locals 0

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    iput-wide p1, p0, Lio/getlime/security/powerauth/core/EciesEncryptor;->handle:J

    .line 6
    iput-object p3, p0, Lio/getlime/security/powerauth/core/EciesEncryptor;->timeService:Lio/getlime/security/powerauth/core/ICoreTimeService;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;[B[BLio/getlime/security/powerauth/core/ICoreTimeService;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    invoke-direct {p0, p1, p2, p3}, Lio/getlime/security/powerauth/core/EciesEncryptor;->init(Ljava/lang/String;[B[B)J

    move-result-wide p1

    iput-wide p1, p0, Lio/getlime/security/powerauth/core/EciesEncryptor;->handle:J

    .line 3
    iput-object p4, p0, Lio/getlime/security/powerauth/core/EciesEncryptor;->timeService:Lio/getlime/security/powerauth/core/ICoreTimeService;

    return-void
.end method

.method private native destroy(J)V
.end method

.method private native init(Ljava/lang/String;[B[B)J
.end method


# virtual methods
.method public final finalize()V
    .locals 5

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-wide v0, p0, Lio/getlime/security/powerauth/core/EciesEncryptor;->handle:J

    .line 3
    .line 4
    const-wide/16 v2, 0x0

    .line 5
    .line 6
    cmp-long v4, v0, v2

    .line 7
    .line 8
    if-eqz v4, :cond_0

    .line 9
    .line 10
    invoke-direct {p0, v0, v1}, Lio/getlime/security/powerauth/core/EciesEncryptor;->destroy(J)V

    .line 11
    .line 12
    .line 13
    iput-wide v2, p0, Lio/getlime/security/powerauth/core/EciesEncryptor;->handle:J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :catchall_0
    move-exception v0

    .line 17
    goto :goto_1

    .line 18
    :cond_0
    :goto_0
    monitor-exit p0

    .line 19
    return-void

    .line 20
    :goto_1
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 21
    throw v0
.end method
