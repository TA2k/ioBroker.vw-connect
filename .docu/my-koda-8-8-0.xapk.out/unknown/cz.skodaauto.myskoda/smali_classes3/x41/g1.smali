.class public final Lx41/g1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lx41/h1;


# annotations
.annotation runtime Llx0/c;
.end annotation

.annotation runtime Lqz0/g;
.end annotation


# static fields
.field public static final Companion:Lx41/f1;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

.field public final c:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

.field public final d:S

.field public final e:S


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lx41/f1;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lx41/g1;->Companion:Lx41/f1;

    .line 7
    .line 8
    return-void
.end method

.method public synthetic constructor <init>(ILjava/lang/String;Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;Llx0/z;Llx0/z;)V
    .locals 2

    .line 1
    and-int/lit8 v0, p1, 0x1f

    .line 2
    .line 3
    const/16 v1, 0x1f

    .line 4
    .line 5
    if-ne v1, v0, :cond_0

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object p2, p0, Lx41/g1;->a:Ljava/lang/String;

    .line 11
    .line 12
    iput-object p3, p0, Lx41/g1;->b:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 13
    .line 14
    iput-object p4, p0, Lx41/g1;->c:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 15
    .line 16
    iget-short p1, p5, Llx0/z;->d:S

    .line 17
    .line 18
    iput-short p1, p0, Lx41/g1;->d:S

    .line 19
    .line 20
    iget-short p1, p6, Llx0/z;->d:S

    .line 21
    .line 22
    iput-short p1, p0, Lx41/g1;->e:S

    .line 23
    .line 24
    return-void

    .line 25
    :cond_0
    sget-object p0, Lx41/e1;->a:Lx41/e1;

    .line 26
    .line 27
    invoke-virtual {p0}, Lx41/e1;->getDescriptor()Lsz0/g;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-static {p1, v1, p0}, Luz0/b1;->l(IILsz0/g;)V

    .line 32
    .line 33
    .line 34
    const/4 p0, 0x0

    .line 35
    throw p0
.end method


# virtual methods
.method public final a()Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;
    .locals 0

    .line 1
    iget-object p0, p0, Lx41/g1;->c:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 2
    .line 3
    return-object p0
.end method

.method public final b()Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;
    .locals 0

    .line 1
    iget-object p0, p0, Lx41/g1;->b:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 2
    .line 3
    return-object p0
.end method

.method public final c()Lt41/b;
    .locals 3

    .line 1
    new-instance v0, Lt41/b;

    .line 2
    .line 3
    sget-object v1, Ltechnology/cariad/cat/genx/VehicleManager;->Companion:Ltechnology/cariad/cat/genx/VehicleManager$Companion;

    .line 4
    .line 5
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/VehicleManager$Companion;->getLegacyBeaconUUID()Ljava/util/UUID;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    iget-short v2, p0, Lx41/g1;->d:S

    .line 10
    .line 11
    iget-short p0, p0, Lx41/g1;->e:S

    .line 12
    .line 13
    invoke-direct {v0, v1, v2, p0}, Lt41/b;-><init>(Ljava/util/UUID;SS)V

    .line 14
    .line 15
    .line 16
    return-object v0
.end method

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
    instance-of v1, p1, Lx41/g1;

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
    check-cast p1, Lx41/g1;

    .line 12
    .line 13
    iget-object v1, p0, Lx41/g1;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lx41/g1;->a:Ljava/lang/String;

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
    iget-object v1, p0, Lx41/g1;->b:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 25
    .line 26
    iget-object v3, p1, Lx41/g1;->b:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 27
    .line 28
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget-object v1, p0, Lx41/g1;->c:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 36
    .line 37
    iget-object v3, p1, Lx41/g1;->c:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 38
    .line 39
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-nez v1, :cond_4

    .line 44
    .line 45
    return v2

    .line 46
    :cond_4
    iget-short v1, p0, Lx41/g1;->d:S

    .line 47
    .line 48
    iget-short v3, p1, Lx41/g1;->d:S

    .line 49
    .line 50
    if-eq v1, v3, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    iget-short p0, p0, Lx41/g1;->e:S

    .line 54
    .line 55
    iget-short p1, p1, Lx41/g1;->e:S

    .line 56
    .line 57
    if-eq p0, p1, :cond_6

    .line 58
    .line 59
    return v2

    .line 60
    :cond_6
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lx41/g1;->a:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    iget-object v2, p0, Lx41/g1;->b:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 11
    .line 12
    if-nez v2, :cond_0

    .line 13
    .line 14
    move v2, v1

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    invoke-virtual {v2}, Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;->hashCode()I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    :goto_0
    add-int/2addr v0, v2

    .line 21
    mul-int/lit8 v0, v0, 0x1f

    .line 22
    .line 23
    iget-object v2, p0, Lx41/g1;->c:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 24
    .line 25
    if-nez v2, :cond_1

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_1
    invoke-virtual {v2}, Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;->hashCode()I

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    :goto_1
    add-int/2addr v0, v1

    .line 33
    mul-int/lit8 v0, v0, 0x1f

    .line 34
    .line 35
    iget-short v1, p0, Lx41/g1;->d:S

    .line 36
    .line 37
    invoke-static {v1}, Ljava/lang/Short;->hashCode(S)I

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    add-int/2addr v1, v0

    .line 42
    mul-int/lit8 v1, v1, 0x1f

    .line 43
    .line 44
    iget-short p0, p0, Lx41/g1;->e:S

    .line 45
    .line 46
    invoke-static {p0}, Ljava/lang/Short;->hashCode(S)I

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    add-int/2addr p0, v1

    .line 51
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 4

    .line 1
    iget-short v0, p0, Lx41/g1;->d:S

    .line 2
    .line 3
    invoke-static {v0}, Llx0/z;->a(S)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-short v1, p0, Lx41/g1;->e:S

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
    const-string v3, "Online(vin="

    .line 16
    .line 17
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    iget-object v3, p0, Lx41/g1;->a:Ljava/lang/String;

    .line 21
    .line 22
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string v3, ", innerAntennaCredentials="

    .line 26
    .line 27
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    iget-object v3, p0, Lx41/g1;->b:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 31
    .line 32
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v3, ", outerAntennaCredentials="

    .line 36
    .line 37
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    iget-object p0, p0, Lx41/g1;->c:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 41
    .line 42
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    const-string p0, ", major="

    .line 46
    .line 47
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string p0, ", minor="

    .line 54
    .line 55
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    const-string p0, ")"

    .line 59
    .line 60
    invoke-static {v2, v1, p0}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    return-object p0
.end method
