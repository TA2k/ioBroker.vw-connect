.class public final Lz21/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final b:Ljava/util/List;

.field public static final c:Lz21/c;


# instance fields
.field public final a:Lz21/c;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    sget-object v0, Lz21/c;->e:Lz21/c;

    .line 2
    .line 3
    sget-object v1, Lz21/c;->f:Lz21/c;

    .line 4
    .line 5
    sget-object v2, Lz21/c;->g:Lz21/c;

    .line 6
    .line 7
    new-instance v3, Lz21/d;

    .line 8
    .line 9
    invoke-direct {v3, v0}, Lz21/d;-><init>(Lz21/c;)V

    .line 10
    .line 11
    .line 12
    new-instance v0, Lz21/d;

    .line 13
    .line 14
    invoke-direct {v0, v1}, Lz21/d;-><init>(Lz21/c;)V

    .line 15
    .line 16
    .line 17
    new-instance v4, Lz21/d;

    .line 18
    .line 19
    invoke-direct {v4, v2}, Lz21/d;-><init>(Lz21/c;)V

    .line 20
    .line 21
    .line 22
    filled-new-array {v3, v0, v4}, [Lz21/d;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    sput-object v0, Lz21/d;->b:Ljava/util/List;

    .line 31
    .line 32
    sput-object v1, Lz21/d;->c:Lz21/c;

    .line 33
    .line 34
    return-void
.end method

.method public synthetic constructor <init>(Lz21/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lz21/d;->a:Lz21/c;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Lz21/d;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    check-cast p1, Lz21/d;

    .line 7
    .line 8
    iget-object p1, p1, Lz21/d;->a:Lz21/c;

    .line 9
    .line 10
    iget-object p0, p0, Lz21/d;->a:Lz21/c;

    .line 11
    .line 12
    if-eq p0, p1, :cond_1

    .line 13
    .line 14
    :goto_0
    const/4 p0, 0x0

    .line 15
    return p0

    .line 16
    :cond_1
    const/4 p0, 0x1

    .line 17
    return p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lz21/d;->a:Lz21/c;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "MslVersion(version="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lz21/d;->a:Lz21/c;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string p0, ")"

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method
