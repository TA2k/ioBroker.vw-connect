.class public final Lx41/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lqz0/g;
.end annotation


# static fields
.field public static final Companion:Lx41/e;


# instance fields
.field public final a:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

.field public final b:S

.field public final c:S


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lx41/e;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lx41/f;->Companion:Lx41/e;

    .line 7
    .line 8
    return-void
.end method

.method public synthetic constructor <init>(ILtechnology/cariad/cat/genx/crypto/RemoteCredentials;Llx0/z;Llx0/z;)V
    .locals 2

    and-int/lit8 v0, p1, 0x7

    const/4 v1, 0x7

    if-ne v1, v0, :cond_0

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lx41/f;->a:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 7
    iget-short p1, p3, Llx0/z;->d:S

    .line 8
    iput-short p1, p0, Lx41/f;->b:S

    .line 9
    iget-short p1, p4, Llx0/z;->d:S

    .line 10
    iput-short p1, p0, Lx41/f;->c:S

    return-void

    :cond_0
    sget-object p0, Lx41/d;->a:Lx41/d;

    invoke-virtual {p0}, Lx41/d;->getDescriptor()Lsz0/g;

    move-result-object p0

    invoke-static {p1, v1, p0}, Luz0/b1;->l(IILsz0/g;)V

    const/4 p0, 0x0

    throw p0
.end method

.method public constructor <init>(Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;SS)V
    .locals 1

    .line 1
    const-string v0, "remoteCredentials"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lx41/f;->a:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 4
    iput-short p2, p0, Lx41/f;->b:S

    .line 5
    iput-short p3, p0, Lx41/f;->c:S

    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lx41/f;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lx41/f;

    .line 12
    .line 13
    iget-object v1, p0, Lx41/f;->a:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 14
    .line 15
    iget-object v3, p1, Lx41/f;->a:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-short v1, p0, Lx41/f;->b:S

    .line 25
    .line 26
    iget-short v3, p1, Lx41/f;->b:S

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-short p0, p0, Lx41/f;->c:S

    .line 32
    .line 33
    iget-short p1, p1, Lx41/f;->c:S

    .line 34
    .line 35
    if-eq p0, p1, :cond_4

    .line 36
    .line 37
    return v2

    .line 38
    :cond_4
    return v0
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    iget-object v0, p0, Lx41/f;->a:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 2
    .line 3
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-short v1, p0, Lx41/f;->b:S

    .line 10
    .line 11
    invoke-static {v1}, Ljava/lang/Short;->hashCode(S)I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    add-int/2addr v1, v0

    .line 16
    mul-int/lit8 v1, v1, 0x1f

    .line 17
    .line 18
    iget-short p0, p0, Lx41/f;->c:S

    .line 19
    .line 20
    invoke-static {p0}, Ljava/lang/Short;->hashCode(S)I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    add-int/2addr p0, v1

    .line 25
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 4

    .line 1
    iget-short v0, p0, Lx41/f;->b:S

    .line 2
    .line 3
    invoke-static {v0}, Llx0/z;->a(S)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-short v1, p0, Lx41/f;->c:S

    .line 8
    .line 9
    invoke-static {v1}, Llx0/z;->a(S)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    new-instance v2, Ljava/lang/StringBuilder;

    .line 14
    .line 15
    const-string v3, "AntennaInformation(remoteCredentials="

    .line 16
    .line 17
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    iget-object p0, p0, Lx41/f;->a:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 21
    .line 22
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string p0, ", beaconMajor="

    .line 26
    .line 27
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string p0, ", beaconMinor="

    .line 34
    .line 35
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    const-string p0, ")"

    .line 39
    .line 40
    invoke-static {v2, v1, p0}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    return-object p0
.end method
