.class public Lio/getlime/security/powerauth/core/Password;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/getlime/security/powerauth/core/Password$IPasswordComplexityValidator;
    }
.end annotation


# instance fields
.field private handle:J


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

.method public constructor <init>()V
    .locals 2

    const/4 v0, 0x0

    .line 3
    invoke-static {v0, v0, v0}, Lio/getlime/security/powerauth/core/Password;->initPassword(Ljava/lang/String;[BLio/getlime/security/powerauth/core/Password;)J

    move-result-wide v0

    invoke-direct {p0, v0, v1}, Lio/getlime/security/powerauth/core/Password;-><init>(J)V

    return-void
.end method

.method private constructor <init>(J)V
    .locals 0

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    iput-wide p1, p0, Lio/getlime/security/powerauth/core/Password;->handle:J

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;)V
    .locals 2

    const/4 v0, 0x0

    .line 1
    invoke-static {p1, v0, v0}, Lio/getlime/security/powerauth/core/Password;->initPassword(Ljava/lang/String;[BLio/getlime/security/powerauth/core/Password;)J

    move-result-wide v0

    invoke-direct {p0, v0, v1}, Lio/getlime/security/powerauth/core/Password;-><init>(J)V

    return-void
.end method

.method public constructor <init>([B)V
    .locals 2

    const/4 v0, 0x0

    .line 2
    invoke-static {v0, p1, v0}, Lio/getlime/security/powerauth/core/Password;->initPassword(Ljava/lang/String;[BLio/getlime/security/powerauth/core/Password;)J

    move-result-wide v0

    invoke-direct {p0, v0, v1}, Lio/getlime/security/powerauth/core/Password;-><init>(J)V

    return-void
.end method

.method private native destroy(J)V
.end method

.method private static native initPassword(Ljava/lang/String;[BLio/getlime/security/powerauth/core/Password;)J
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    return p0

    .line 5
    :cond_0
    instance-of v0, p1, Lio/getlime/security/powerauth/core/Password;

    .line 6
    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    check-cast p1, Lio/getlime/security/powerauth/core/Password;

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Lio/getlime/security/powerauth/core/Password;->isEqualToPassword(Lio/getlime/security/powerauth/core/Password;)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0

    .line 16
    :cond_1
    const/4 p0, 0x0

    .line 17
    return p0
.end method

.method public final finalize()V
    .locals 5

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-wide v0, p0, Lio/getlime/security/powerauth/core/Password;->handle:J

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
    invoke-direct {p0, v0, v1}, Lio/getlime/security/powerauth/core/Password;->destroy(J)V

    .line 11
    .line 12
    .line 13
    iput-wide v2, p0, Lio/getlime/security/powerauth/core/Password;->handle:J
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

.method public native isEqualToPassword(Lio/getlime/security/powerauth/core/Password;)Z
.end method
