.class public Lkotlin/jvm/internal/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkotlin/jvm/internal/i;
.implements Ljava/io/Serializable;


# instance fields
.field private final arity:I

.field private final flags:I

.field private final isTopLevel:Z

.field private final name:Ljava/lang/String;

.field private final owner:Ljava/lang/Class;

.field protected final receiver:Ljava/lang/Object;

.field private final signature:Ljava/lang/String;


# direct methods
.method public constructor <init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p4, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 5
    .line 6
    iput-object p3, p0, Lkotlin/jvm/internal/a;->owner:Ljava/lang/Class;

    .line 7
    .line 8
    iput-object p5, p0, Lkotlin/jvm/internal/a;->name:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p6, p0, Lkotlin/jvm/internal/a;->signature:Ljava/lang/String;

    .line 11
    .line 12
    const/4 p3, 0x0

    .line 13
    iput-boolean p3, p0, Lkotlin/jvm/internal/a;->isTopLevel:Z

    .line 14
    .line 15
    iput p1, p0, Lkotlin/jvm/internal/a;->arity:I

    .line 16
    .line 17
    shr-int/lit8 p1, p2, 0x1

    .line 18
    .line 19
    iput p1, p0, Lkotlin/jvm/internal/a;->flags:I

    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public equals(Ljava/lang/Object;)Z
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
    instance-of v1, p1, Lkotlin/jvm/internal/a;

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
    check-cast p1, Lkotlin/jvm/internal/a;

    .line 12
    .line 13
    iget-boolean v1, p0, Lkotlin/jvm/internal/a;->isTopLevel:Z

    .line 14
    .line 15
    iget-boolean v3, p1, Lkotlin/jvm/internal/a;->isTopLevel:Z

    .line 16
    .line 17
    if-ne v1, v3, :cond_2

    .line 18
    .line 19
    iget v1, p0, Lkotlin/jvm/internal/a;->arity:I

    .line 20
    .line 21
    iget v3, p1, Lkotlin/jvm/internal/a;->arity:I

    .line 22
    .line 23
    if-ne v1, v3, :cond_2

    .line 24
    .line 25
    iget v1, p0, Lkotlin/jvm/internal/a;->flags:I

    .line 26
    .line 27
    iget v3, p1, Lkotlin/jvm/internal/a;->flags:I

    .line 28
    .line 29
    if-ne v1, v3, :cond_2

    .line 30
    .line 31
    iget-object v1, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 32
    .line 33
    iget-object v3, p1, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 34
    .line 35
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-eqz v1, :cond_2

    .line 40
    .line 41
    iget-object v1, p0, Lkotlin/jvm/internal/a;->owner:Ljava/lang/Class;

    .line 42
    .line 43
    iget-object v3, p1, Lkotlin/jvm/internal/a;->owner:Ljava/lang/Class;

    .line 44
    .line 45
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    if-eqz v1, :cond_2

    .line 50
    .line 51
    iget-object v1, p0, Lkotlin/jvm/internal/a;->name:Ljava/lang/String;

    .line 52
    .line 53
    iget-object v3, p1, Lkotlin/jvm/internal/a;->name:Ljava/lang/String;

    .line 54
    .line 55
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result v1

    .line 59
    if-eqz v1, :cond_2

    .line 60
    .line 61
    iget-object p0, p0, Lkotlin/jvm/internal/a;->signature:Ljava/lang/String;

    .line 62
    .line 63
    iget-object p1, p1, Lkotlin/jvm/internal/a;->signature:Ljava/lang/String;

    .line 64
    .line 65
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    move-result p0

    .line 69
    if-eqz p0, :cond_2

    .line 70
    .line 71
    return v0

    .line 72
    :cond_2
    return v2
.end method

.method public getArity()I
    .locals 0

    .line 1
    iget p0, p0, Lkotlin/jvm/internal/a;->arity:I

    .line 2
    .line 3
    return p0
.end method

.method public getOwner()Lhy0/f;
    .locals 2

    .line 1
    iget-object v0, p0, Lkotlin/jvm/internal/a;->owner:Ljava/lang/Class;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return-object p0

    .line 7
    :cond_0
    iget-boolean p0, p0, Lkotlin/jvm/internal/a;->isTopLevel:Z

    .line 8
    .line 9
    if-eqz p0, :cond_1

    .line 10
    .line 11
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 12
    .line 13
    const-string v1, ""

    .line 14
    .line 15
    invoke-virtual {p0, v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinPackage(Ljava/lang/Class;Ljava/lang/String;)Lhy0/f;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0

    .line 20
    :cond_1
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 21
    .line 22
    invoke-virtual {p0, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0
.end method

.method public hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    move v0, v1

    .line 12
    :goto_0
    const/16 v2, 0x1f

    .line 13
    .line 14
    mul-int/2addr v0, v2

    .line 15
    iget-object v3, p0, Lkotlin/jvm/internal/a;->owner:Ljava/lang/Class;

    .line 16
    .line 17
    if-eqz v3, :cond_1

    .line 18
    .line 19
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    :cond_1
    add-int/2addr v0, v1

    .line 24
    mul-int/2addr v0, v2

    .line 25
    iget-object v1, p0, Lkotlin/jvm/internal/a;->name:Ljava/lang/String;

    .line 26
    .line 27
    invoke-static {v0, v2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    iget-object v1, p0, Lkotlin/jvm/internal/a;->signature:Ljava/lang/String;

    .line 32
    .line 33
    invoke-static {v0, v2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    iget-boolean v1, p0, Lkotlin/jvm/internal/a;->isTopLevel:Z

    .line 38
    .line 39
    if-eqz v1, :cond_2

    .line 40
    .line 41
    const/16 v1, 0x4cf

    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_2
    const/16 v1, 0x4d5

    .line 45
    .line 46
    :goto_1
    add-int/2addr v0, v1

    .line 47
    mul-int/2addr v0, v2

    .line 48
    iget v1, p0, Lkotlin/jvm/internal/a;->arity:I

    .line 49
    .line 50
    add-int/2addr v0, v1

    .line 51
    mul-int/2addr v0, v2

    .line 52
    iget p0, p0, Lkotlin/jvm/internal/a;->flags:I

    .line 53
    .line 54
    add-int/2addr v0, p0

    .line 55
    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 1

    .line 1
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lkotlin/jvm/internal/h0;->renderLambdaToString(Lkotlin/jvm/internal/i;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
