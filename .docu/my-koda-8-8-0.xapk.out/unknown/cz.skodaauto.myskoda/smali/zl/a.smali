.class public final Lzl/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lzl/a;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lzl/a;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lzl/a;->a:Lzl/a;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Ljava/lang/Object;)Z
    .locals 1

    .line 1
    if-ne p0, p2, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    instance-of p0, p1, Lmm/g;

    .line 5
    .line 6
    if-eqz p0, :cond_3

    .line 7
    .line 8
    instance-of p0, p2, Lmm/g;

    .line 9
    .line 10
    if-nez p0, :cond_1

    .line 11
    .line 12
    goto :goto_1

    .line 13
    :cond_1
    check-cast p1, Lmm/g;

    .line 14
    .line 15
    iget-object p0, p1, Lmm/g;->a:Landroid/content/Context;

    .line 16
    .line 17
    check-cast p2, Lmm/g;

    .line 18
    .line 19
    iget-object v0, p2, Lmm/g;->a:Landroid/content/Context;

    .line 20
    .line 21
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    if-eqz p0, :cond_2

    .line 26
    .line 27
    iget-object p0, p1, Lmm/g;->b:Ljava/lang/Object;

    .line 28
    .line 29
    iget-object v0, p2, Lmm/g;->b:Ljava/lang/Object;

    .line 30
    .line 31
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    if-eqz p0, :cond_2

    .line 36
    .line 37
    iget-object p0, p1, Lmm/g;->d:Ljava/util/Map;

    .line 38
    .line 39
    iget-object v0, p2, Lmm/g;->d:Ljava/util/Map;

    .line 40
    .line 41
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    if-eqz p0, :cond_2

    .line 46
    .line 47
    iget-object p0, p1, Lmm/g;->o:Lnm/i;

    .line 48
    .line 49
    iget-object v0, p2, Lmm/g;->o:Lnm/i;

    .line 50
    .line 51
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result p0

    .line 55
    if-eqz p0, :cond_2

    .line 56
    .line 57
    iget-object p0, p1, Lmm/g;->p:Lnm/g;

    .line 58
    .line 59
    iget-object v0, p2, Lmm/g;->p:Lnm/g;

    .line 60
    .line 61
    if-ne p0, v0, :cond_2

    .line 62
    .line 63
    iget-object p0, p1, Lmm/g;->q:Lnm/d;

    .line 64
    .line 65
    iget-object p1, p2, Lmm/g;->q:Lnm/d;

    .line 66
    .line 67
    if-ne p0, p1, :cond_2

    .line 68
    .line 69
    :goto_0
    const/4 p0, 0x1

    .line 70
    return p0

    .line 71
    :cond_2
    const/4 p0, 0x0

    .line 72
    return p0

    .line 73
    :cond_3
    :goto_1
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    move-result p0

    .line 77
    return p0
.end method

.method public final b(Ljava/lang/Object;)I
    .locals 2

    .line 1
    instance-of p0, p1, Lmm/g;

    .line 2
    .line 3
    if-nez p0, :cond_1

    .line 4
    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    return p0

    .line 14
    :cond_1
    check-cast p1, Lmm/g;

    .line 15
    .line 16
    iget-object p0, p1, Lmm/g;->a:Landroid/content/Context;

    .line 17
    .line 18
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    mul-int/lit8 p0, p0, 0x1f

    .line 23
    .line 24
    iget-object v0, p1, Lmm/g;->b:Ljava/lang/Object;

    .line 25
    .line 26
    const/16 v1, 0x3c1

    .line 27
    .line 28
    invoke-static {p0, v0, v1}, Lp3/m;->b(ILjava/lang/Object;I)I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    iget-object v0, p1, Lmm/g;->d:Ljava/util/Map;

    .line 33
    .line 34
    invoke-static {p0, v1, v0}, Lp3/m;->a(IILjava/util/Map;)I

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    iget-object v0, p1, Lmm/g;->o:Lnm/i;

    .line 39
    .line 40
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    add-int/2addr v0, p0

    .line 45
    mul-int/lit8 v0, v0, 0x1f

    .line 46
    .line 47
    iget-object p0, p1, Lmm/g;->p:Lnm/g;

    .line 48
    .line 49
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    add-int/2addr p0, v0

    .line 54
    mul-int/lit8 p0, p0, 0x1f

    .line 55
    .line 56
    iget-object p1, p1, Lmm/g;->q:Lnm/d;

    .line 57
    .line 58
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    .line 59
    .line 60
    .line 61
    move-result p1

    .line 62
    add-int/2addr p1, p0

    .line 63
    return p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "AsyncImageModelEqualityDelegate.Default"

    .line 2
    .line 3
    return-object p0
.end method
