.class public final Lrd0/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final e:Llx0/l;

.field public static final f:Llx0/l;


# instance fields
.field public final a:Lqr0/l;

.field public final b:Lqr0/l;

.field public final c:Ljava/lang/Boolean;

.field public final d:Ljava/lang/Boolean;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lqr0/l;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lqr0/l;-><init>(I)V

    .line 5
    .line 6
    .line 7
    new-instance v1, Lqr0/l;

    .line 8
    .line 9
    const/16 v2, 0x32

    .line 10
    .line 11
    invoke-direct {v1, v2}, Lqr0/l;-><init>(I)V

    .line 12
    .line 13
    .line 14
    new-instance v3, Llx0/l;

    .line 15
    .line 16
    invoke-direct {v3, v0, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    sput-object v3, Lrd0/s;->e:Llx0/l;

    .line 20
    .line 21
    new-instance v0, Lqr0/l;

    .line 22
    .line 23
    invoke-direct {v0, v2}, Lqr0/l;-><init>(I)V

    .line 24
    .line 25
    .line 26
    new-instance v1, Lqr0/l;

    .line 27
    .line 28
    const/16 v2, 0x64

    .line 29
    .line 30
    invoke-direct {v1, v2}, Lqr0/l;-><init>(I)V

    .line 31
    .line 32
    .line 33
    new-instance v2, Llx0/l;

    .line 34
    .line 35
    invoke-direct {v2, v0, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    sput-object v2, Lrd0/s;->f:Llx0/l;

    .line 39
    .line 40
    return-void
.end method

.method public constructor <init>(Lqr0/l;Lqr0/l;Ljava/lang/Boolean;Ljava/lang/Boolean;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lrd0/s;->a:Lqr0/l;

    .line 5
    .line 6
    iput-object p2, p0, Lrd0/s;->b:Lqr0/l;

    .line 7
    .line 8
    iput-object p3, p0, Lrd0/s;->c:Ljava/lang/Boolean;

    .line 9
    .line 10
    iput-object p4, p0, Lrd0/s;->d:Ljava/lang/Boolean;

    .line 11
    .line 12
    return-void
.end method

.method public static a(Lrd0/s;Lqr0/l;Lqr0/l;Ljava/lang/Boolean;Ljava/lang/Boolean;I)Lrd0/s;
    .locals 1

    .line 1
    and-int/lit8 v0, p5, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lrd0/s;->a:Lqr0/l;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 v0, p5, 0x2

    .line 8
    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lrd0/s;->b:Lqr0/l;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 v0, p5, 0x4

    .line 14
    .line 15
    if-eqz v0, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lrd0/s;->c:Ljava/lang/Boolean;

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p5, p5, 0x8

    .line 20
    .line 21
    if-eqz p5, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Lrd0/s;->d:Ljava/lang/Boolean;

    .line 24
    .line 25
    :cond_3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    new-instance p0, Lrd0/s;

    .line 29
    .line 30
    invoke-direct {p0, p1, p2, p3, p4}, Lrd0/s;-><init>(Lqr0/l;Lqr0/l;Ljava/lang/Boolean;Ljava/lang/Boolean;)V

    .line 31
    .line 32
    .line 33
    return-object p0
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
    instance-of v1, p1, Lrd0/s;

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
    check-cast p1, Lrd0/s;

    .line 12
    .line 13
    iget-object v1, p0, Lrd0/s;->a:Lqr0/l;

    .line 14
    .line 15
    iget-object v3, p1, Lrd0/s;->a:Lqr0/l;

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
    iget-object v1, p0, Lrd0/s;->b:Lqr0/l;

    .line 25
    .line 26
    iget-object v3, p1, Lrd0/s;->b:Lqr0/l;

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
    iget-object v1, p0, Lrd0/s;->c:Ljava/lang/Boolean;

    .line 36
    .line 37
    iget-object v3, p1, Lrd0/s;->c:Ljava/lang/Boolean;

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
    iget-object p0, p0, Lrd0/s;->d:Ljava/lang/Boolean;

    .line 47
    .line 48
    iget-object p1, p1, Lrd0/s;->d:Ljava/lang/Boolean;

    .line 49
    .line 50
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    if-nez p0, :cond_5

    .line 55
    .line 56
    return v2

    .line 57
    :cond_5
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Lrd0/s;->a:Lqr0/l;

    .line 3
    .line 4
    if-nez v1, :cond_0

    .line 5
    .line 6
    move v1, v0

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    iget v1, v1, Lqr0/l;->d:I

    .line 9
    .line 10
    invoke-static {v1}, Ljava/lang/Integer;->hashCode(I)I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    :goto_0
    mul-int/lit8 v1, v1, 0x1f

    .line 15
    .line 16
    iget-object v2, p0, Lrd0/s;->b:Lqr0/l;

    .line 17
    .line 18
    if-nez v2, :cond_1

    .line 19
    .line 20
    move v2, v0

    .line 21
    goto :goto_1

    .line 22
    :cond_1
    iget v2, v2, Lqr0/l;->d:I

    .line 23
    .line 24
    invoke-static {v2}, Ljava/lang/Integer;->hashCode(I)I

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    :goto_1
    add-int/2addr v1, v2

    .line 29
    mul-int/lit8 v1, v1, 0x1f

    .line 30
    .line 31
    iget-object v2, p0, Lrd0/s;->c:Ljava/lang/Boolean;

    .line 32
    .line 33
    if-nez v2, :cond_2

    .line 34
    .line 35
    move v2, v0

    .line 36
    goto :goto_2

    .line 37
    :cond_2
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    :goto_2
    add-int/2addr v1, v2

    .line 42
    mul-int/lit8 v1, v1, 0x1f

    .line 43
    .line 44
    iget-object p0, p0, Lrd0/s;->d:Ljava/lang/Boolean;

    .line 45
    .line 46
    if-nez p0, :cond_3

    .line 47
    .line 48
    goto :goto_3

    .line 49
    :cond_3
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    :goto_3
    add-int/2addr v1, v0

    .line 54
    return v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "ChargingProfileSettings(minBatteryChargedState="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lrd0/s;->a:Lqr0/l;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", targetChargedState="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lrd0/s;->b:Lqr0/l;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", isReducedCurrentActive="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lrd0/s;->c:Ljava/lang/Boolean;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", isCableLockActive="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object p0, p0, Lrd0/s;->d:Ljava/lang/Boolean;

    .line 39
    .line 40
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string p0, ")"

    .line 44
    .line 45
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0
.end method
