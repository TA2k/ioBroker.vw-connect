.class public final Lgs/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lgs/s;

.field public final b:I

.field public final c:I


# direct methods
.method public constructor <init>(IILjava/lang/Class;)V
    .locals 0

    .line 1
    invoke-static {p3}, Lgs/s;->a(Ljava/lang/Class;)Lgs/s;

    move-result-object p3

    invoke-direct {p0, p3, p1, p2}, Lgs/k;-><init>(Lgs/s;II)V

    return-void
.end method

.method public constructor <init>(Lgs/s;II)V
    .locals 1

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    const-string v0, "Null dependency anInterface."

    invoke-static {p1, v0}, Lkp/o9;->a(Ljava/lang/Object;Ljava/lang/String;)V

    iput-object p1, p0, Lgs/k;->a:Lgs/s;

    .line 4
    iput p2, p0, Lgs/k;->b:I

    .line 5
    iput p3, p0, Lgs/k;->c:I

    return-void
.end method

.method public static a(Ljava/lang/Class;)Lgs/k;
    .locals 3

    .line 1
    new-instance v0, Lgs/k;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    invoke-direct {v0, v1, v2, p0}, Lgs/k;-><init>(IILjava/lang/Class;)V

    .line 6
    .line 7
    .line 8
    return-object v0
.end method

.method public static b(Lgs/s;)Lgs/k;
    .locals 3

    .line 1
    new-instance v0, Lgs/k;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, p0, v1, v2}, Lgs/k;-><init>(Lgs/s;II)V

    .line 6
    .line 7
    .line 8
    return-object v0
.end method

.method public static c(Ljava/lang/Class;)Lgs/k;
    .locals 3

    .line 1
    new-instance v0, Lgs/k;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v1, v2, p0}, Lgs/k;-><init>(IILjava/lang/Class;)V

    .line 6
    .line 7
    .line 8
    return-object v0
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    instance-of v0, p1, Lgs/k;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, Lgs/k;

    .line 6
    .line 7
    iget-object v0, p0, Lgs/k;->a:Lgs/s;

    .line 8
    .line 9
    iget-object v1, p1, Lgs/k;->a:Lgs/s;

    .line 10
    .line 11
    invoke-virtual {v0, v1}, Lgs/s;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    iget v0, p0, Lgs/k;->b:I

    .line 18
    .line 19
    iget v1, p1, Lgs/k;->b:I

    .line 20
    .line 21
    if-ne v0, v1, :cond_0

    .line 22
    .line 23
    iget p0, p0, Lgs/k;->c:I

    .line 24
    .line 25
    iget p1, p1, Lgs/k;->c:I

    .line 26
    .line 27
    if-ne p0, p1, :cond_0

    .line 28
    .line 29
    const/4 p0, 0x1

    .line 30
    return p0

    .line 31
    :cond_0
    const/4 p0, 0x0

    .line 32
    return p0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lgs/k;->a:Lgs/s;

    .line 2
    .line 3
    invoke-virtual {v0}, Lgs/s;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const v1, 0xf4243

    .line 8
    .line 9
    .line 10
    xor-int/2addr v0, v1

    .line 11
    mul-int/2addr v0, v1

    .line 12
    iget v2, p0, Lgs/k;->b:I

    .line 13
    .line 14
    xor-int/2addr v0, v2

    .line 15
    mul-int/2addr v0, v1

    .line 16
    iget p0, p0, Lgs/k;->c:I

    .line 17
    .line 18
    xor-int/2addr p0, v0

    .line 19
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "Dependency{anInterface="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lgs/k;->a:Lgs/s;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", type="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget v1, p0, Lgs/k;->b:I

    .line 19
    .line 20
    const/4 v2, 0x1

    .line 21
    if-ne v1, v2, :cond_0

    .line 22
    .line 23
    const-string v1, "required"

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    if-nez v1, :cond_1

    .line 27
    .line 28
    const-string v1, "optional"

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_1
    const-string v1, "set"

    .line 32
    .line 33
    :goto_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    const-string v1, ", injection="

    .line 37
    .line 38
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    iget p0, p0, Lgs/k;->c:I

    .line 42
    .line 43
    if-eqz p0, :cond_4

    .line 44
    .line 45
    if-eq p0, v2, :cond_3

    .line 46
    .line 47
    const/4 v1, 0x2

    .line 48
    if-ne p0, v1, :cond_2

    .line 49
    .line 50
    const-string p0, "deferred"

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_2
    new-instance v0, Ljava/lang/AssertionError;

    .line 54
    .line 55
    const-string v1, "Unsupported injection: "

    .line 56
    .line 57
    invoke-static {p0, v1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    invoke-direct {v0, p0}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    throw v0

    .line 65
    :cond_3
    const-string p0, "provider"

    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_4
    const-string p0, "direct"

    .line 69
    .line 70
    :goto_1
    const-string v1, "}"

    .line 71
    .line 72
    invoke-static {v0, p0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    return-object p0
.end method
