.class public final Lw71/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final c:Lmb/e;


# instance fields
.field public final a:Lw71/c;

.field public final b:D


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lmb/e;

    .line 2
    .line 3
    const/16 v1, 0x19

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lmb/e;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lw71/a;->c:Lmb/e;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(Lw71/c;D)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw71/a;->a:Lw71/c;

    .line 5
    .line 6
    iput-wide p2, p0, Lw71/a;->b:D

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a()D
    .locals 6

    .line 1
    sget v0, Lw71/d;->b:I

    .line 2
    .line 3
    const-string v0, "<this>"

    .line 4
    .line 5
    iget-object p0, p0, Lw71/a;->a:Lw71/c;

    .line 6
    .line 7
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-wide v0, p0, Lw71/c;->b:D

    .line 11
    .line 12
    iget-wide v2, p0, Lw71/c;->a:D

    .line 13
    .line 14
    invoke-static {v0, v1, v2, v3}, Ljava/lang/Math;->atan2(DD)D

    .line 15
    .line 16
    .line 17
    move-result-wide v0

    .line 18
    const-wide/16 v2, 0x0

    .line 19
    .line 20
    cmpg-double p0, v2, v0

    .line 21
    .line 22
    const-wide v4, 0x401921fb54442d18L    # 6.283185307179586

    .line 23
    .line 24
    .line 25
    .line 26
    .line 27
    if-gtz p0, :cond_0

    .line 28
    .line 29
    cmpg-double p0, v0, v4

    .line 30
    .line 31
    if-gtz p0, :cond_0

    .line 32
    .line 33
    return-wide v0

    .line 34
    :cond_0
    sub-double/2addr v0, v2

    .line 35
    rem-double/2addr v0, v4

    .line 36
    add-double/2addr v0, v2

    .line 37
    cmpg-double p0, v0, v2

    .line 38
    .line 39
    if-gez p0, :cond_1

    .line 40
    .line 41
    add-double/2addr v0, v4

    .line 42
    :cond_1
    return-wide v0
.end method

.method public final b(Lw71/a;)Lw71/c;
    .locals 14

    .line 1
    iget-object v0, p0, Lw71/a;->a:Lw71/c;

    .line 2
    .line 3
    iget-wide v1, v0, Lw71/c;->a:D

    .line 4
    .line 5
    iget-object v3, p1, Lw71/a;->a:Lw71/c;

    .line 6
    .line 7
    iget-wide v4, v3, Lw71/c;->b:D

    .line 8
    .line 9
    iget-wide v6, v0, Lw71/c;->b:D

    .line 10
    .line 11
    neg-double v8, v6

    .line 12
    iget-wide v10, v3, Lw71/c;->a:D

    .line 13
    .line 14
    sget v0, Lw71/d;->b:I

    .line 15
    .line 16
    mul-double v12, v1, v4

    .line 17
    .line 18
    mul-double/2addr v8, v10

    .line 19
    add-double/2addr v8, v12

    .line 20
    const-wide/16 v12, 0x0

    .line 21
    .line 22
    cmpg-double v0, v8, v12

    .line 23
    .line 24
    if-nez v0, :cond_0

    .line 25
    .line 26
    const/4 p0, 0x0

    .line 27
    return-object p0

    .line 28
    :cond_0
    neg-double v0, v1

    .line 29
    iget-wide v2, p1, Lw71/a;->b:D

    .line 30
    .line 31
    iget-wide p0, p0, Lw71/a;->b:D

    .line 32
    .line 33
    mul-double/2addr v10, p0

    .line 34
    mul-double/2addr v0, v2

    .line 35
    add-double/2addr v0, v10

    .line 36
    div-double/2addr v0, v8

    .line 37
    neg-double v6, v6

    .line 38
    mul-double/2addr v4, p0

    .line 39
    mul-double/2addr v6, v2

    .line 40
    add-double/2addr v6, v4

    .line 41
    div-double/2addr v6, v8

    .line 42
    new-instance p0, Lw71/c;

    .line 43
    .line 44
    invoke-direct {p0, v0, v1, v6, v7}, Lw71/c;-><init>(DD)V

    .line 45
    .line 46
    .line 47
    return-object p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_1

    .line 4
    :cond_0
    instance-of v0, p1, Lw71/a;

    .line 5
    .line 6
    if-nez v0, :cond_1

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_1
    check-cast p1, Lw71/a;

    .line 10
    .line 11
    iget-object v0, p0, Lw71/a;->a:Lw71/c;

    .line 12
    .line 13
    iget-object v1, p1, Lw71/a;->a:Lw71/c;

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Lw71/c;->equals(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-nez v0, :cond_2

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_2
    iget-wide v0, p0, Lw71/a;->b:D

    .line 23
    .line 24
    iget-wide p0, p1, Lw71/a;->b:D

    .line 25
    .line 26
    invoke-static {v0, v1, p0, p1}, Ljava/lang/Double;->compare(DD)I

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    if-eqz p0, :cond_3

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_3
    const-wide p0, 0x3eb0c6f7a0b5ed8dL    # 1.0E-6

    .line 34
    .line 35
    .line 36
    .line 37
    .line 38
    invoke-static {p0, p1, p0, p1}, Ljava/lang/Double;->compare(DD)I

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    if-eqz p0, :cond_4

    .line 43
    .line 44
    :goto_0
    const/4 p0, 0x0

    .line 45
    return p0

    .line 46
    :cond_4
    :goto_1
    const/4 p0, 0x1

    .line 47
    return p0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lw71/a;->a:Lw71/c;

    .line 2
    .line 3
    invoke-virtual {v0}, Lw71/c;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-wide v2, p0, Lw71/a;->b:D

    .line 11
    .line 12
    invoke-static {v2, v3, v0, v1}, Lf2/m0;->a(DII)I

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    const-wide v0, 0x3eb0c6f7a0b5ed8dL    # 1.0E-6

    .line 17
    .line 18
    .line 19
    .line 20
    .line 21
    invoke-static {v0, v1}, Ljava/lang/Double;->hashCode(D)I

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    add-int/2addr v0, p0

    .line 26
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "Line(direction="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lw71/a;->a:Lw71/c;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", originOffset="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-wide v1, p0, Lw71/a;->b:D

    .line 19
    .line 20
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string p0, ", precision=1.0E-6)"

    .line 24
    .line 25
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method
