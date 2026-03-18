.class public Lio/getlime/security/powerauth/core/EciesCryptogram;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final body:[B

.field public final key:[B

.field public final mac:[B

.field public final nonce:[B

.field public final temporaryKeyId:Ljava/lang/String;

.field public final timestamp:J


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Lio/getlime/security/powerauth/core/EciesCryptogram;->temporaryKeyId:Ljava/lang/String;

    .line 3
    iput-object v0, p0, Lio/getlime/security/powerauth/core/EciesCryptogram;->body:[B

    .line 4
    iput-object v0, p0, Lio/getlime/security/powerauth/core/EciesCryptogram;->mac:[B

    .line 5
    iput-object v0, p0, Lio/getlime/security/powerauth/core/EciesCryptogram;->key:[B

    .line 6
    iput-object v0, p0, Lio/getlime/security/powerauth/core/EciesCryptogram;->nonce:[B

    const-wide/16 v0, 0x0

    .line 7
    iput-wide v0, p0, Lio/getlime/security/powerauth/core/EciesCryptogram;->timestamp:J

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;J)V
    .locals 1

    .line 15
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 16
    iput-object p1, p0, Lio/getlime/security/powerauth/core/EciesCryptogram;->temporaryKeyId:Ljava/lang/String;

    const/4 p1, 0x0

    const/4 v0, 0x2

    if-eqz p2, :cond_0

    .line 17
    invoke-static {p2, v0}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    move-result-object p2

    goto :goto_0

    :cond_0
    move-object p2, p1

    :goto_0
    iput-object p2, p0, Lio/getlime/security/powerauth/core/EciesCryptogram;->body:[B

    if-eqz p3, :cond_1

    .line 18
    invoke-static {p3, v0}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    move-result-object p2

    goto :goto_1

    :cond_1
    move-object p2, p1

    :goto_1
    iput-object p2, p0, Lio/getlime/security/powerauth/core/EciesCryptogram;->mac:[B

    if-eqz p4, :cond_2

    .line 19
    invoke-static {p4, v0}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    move-result-object p2

    goto :goto_2

    :cond_2
    move-object p2, p1

    :goto_2
    iput-object p2, p0, Lio/getlime/security/powerauth/core/EciesCryptogram;->key:[B

    if-eqz p5, :cond_3

    .line 20
    invoke-static {p5, v0}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    move-result-object p1

    :cond_3
    iput-object p1, p0, Lio/getlime/security/powerauth/core/EciesCryptogram;->nonce:[B

    .line 21
    iput-wide p6, p0, Lio/getlime/security/powerauth/core/EciesCryptogram;->timestamp:J

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;[B[B[B[BJ)V
    .locals 0

    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    iput-object p1, p0, Lio/getlime/security/powerauth/core/EciesCryptogram;->temporaryKeyId:Ljava/lang/String;

    .line 10
    iput-object p2, p0, Lio/getlime/security/powerauth/core/EciesCryptogram;->body:[B

    .line 11
    iput-object p3, p0, Lio/getlime/security/powerauth/core/EciesCryptogram;->mac:[B

    .line 12
    iput-object p4, p0, Lio/getlime/security/powerauth/core/EciesCryptogram;->key:[B

    .line 13
    iput-object p5, p0, Lio/getlime/security/powerauth/core/EciesCryptogram;->nonce:[B

    .line 14
    iput-wide p6, p0, Lio/getlime/security/powerauth/core/EciesCryptogram;->timestamp:J

    return-void
.end method
