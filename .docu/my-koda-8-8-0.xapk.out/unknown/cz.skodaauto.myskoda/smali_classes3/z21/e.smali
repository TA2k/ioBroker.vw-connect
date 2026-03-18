.class public final Lz21/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lz21/c;

.field public final b:Lz21/c;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 5
    sget-object v0, Lz21/d;->c:Lz21/c;

    .line 6
    sget-object v1, Lz21/f;->c:Lz21/c;

    .line 7
    invoke-direct {p0, v0, v1}, Lz21/e;-><init>(Lz21/c;Lz21/c;)V

    return-void
.end method

.method public constructor <init>(Lz21/c;Lz21/c;)V
    .locals 1

    .line 1
    const-string v0, "mslModuleVersion"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "sboModuleVersion"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lz21/e;->a:Lz21/c;

    .line 4
    iput-object p2, p0, Lz21/e;->b:Lz21/c;

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
    instance-of v1, p1, Lz21/e;

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
    check-cast p1, Lz21/e;

    .line 12
    .line 13
    iget-object v1, p1, Lz21/e;->a:Lz21/c;

    .line 14
    .line 15
    sget-object v3, Lz21/d;->b:Ljava/util/List;

    .line 16
    .line 17
    iget-object v3, p0, Lz21/e;->a:Lz21/c;

    .line 18
    .line 19
    if-ne v3, v1, :cond_2

    .line 20
    .line 21
    iget-object p1, p1, Lz21/e;->b:Lz21/c;

    .line 22
    .line 23
    sget-object v1, Lz21/f;->b:Ljava/util/List;

    .line 24
    .line 25
    iget-object p0, p0, Lz21/e;->b:Lz21/c;

    .line 26
    .line 27
    if-ne p0, p1, :cond_2

    .line 28
    .line 29
    return v0

    .line 30
    :cond_2
    return v2
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    sget-object v0, Lz21/d;->b:Ljava/util/List;

    .line 2
    .line 3
    iget-object v0, p0, Lz21/e;->a:Lz21/c;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    mul-int/lit8 v0, v0, 0x1f

    .line 10
    .line 11
    sget-object v1, Lz21/f;->b:Ljava/util/List;

    .line 12
    .line 13
    iget-object p0, p0, Lz21/e;->b:Lz21/c;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    add-int/2addr p0, v0

    .line 20
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 4

    .line 1
    sget-object v0, Lz21/d;->b:Ljava/util/List;

    .line 2
    .line 3
    new-instance v0, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v1, "MslVersion(version="

    .line 6
    .line 7
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object v1, p0, Lz21/e;->a:Lz21/c;

    .line 11
    .line 12
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const-string v1, ")"

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    sget-object v2, Lz21/f;->b:Ljava/util/List;

    .line 25
    .line 26
    new-instance v2, Ljava/lang/StringBuilder;

    .line 27
    .line 28
    const-string v3, "SboVersion(version="

    .line 29
    .line 30
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    iget-object p0, p0, Lz21/e;->b:Lz21/c;

    .line 34
    .line 35
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    const-string v2, "PreferredModuleVersions(mslModuleVersion="

    .line 46
    .line 47
    const-string v3, ", sboModuleVersion="

    .line 48
    .line 49
    invoke-static {v2, v0, v3, p0, v1}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    return-object p0
.end method
