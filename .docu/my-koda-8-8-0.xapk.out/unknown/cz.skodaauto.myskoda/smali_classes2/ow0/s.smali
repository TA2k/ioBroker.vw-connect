.class public final Low0/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final b:Low0/s;

.field public static final c:Low0/s;

.field public static final d:Low0/s;

.field public static final e:Low0/s;

.field public static final f:Ljava/util/List;


# instance fields
.field public final a:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 8

    .line 1
    new-instance v0, Low0/s;

    .line 2
    .line 3
    const-string v1, "GET"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Low0/s;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Low0/s;->b:Low0/s;

    .line 9
    .line 10
    new-instance v1, Low0/s;

    .line 11
    .line 12
    const-string v2, "POST"

    .line 13
    .line 14
    invoke-direct {v1, v2}, Low0/s;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    sput-object v1, Low0/s;->c:Low0/s;

    .line 18
    .line 19
    new-instance v2, Low0/s;

    .line 20
    .line 21
    const-string v3, "PUT"

    .line 22
    .line 23
    invoke-direct {v2, v3}, Low0/s;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    new-instance v3, Low0/s;

    .line 27
    .line 28
    const-string v4, "PATCH"

    .line 29
    .line 30
    invoke-direct {v3, v4}, Low0/s;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    new-instance v4, Low0/s;

    .line 34
    .line 35
    const-string v5, "DELETE"

    .line 36
    .line 37
    invoke-direct {v4, v5}, Low0/s;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    new-instance v5, Low0/s;

    .line 41
    .line 42
    const-string v6, "HEAD"

    .line 43
    .line 44
    invoke-direct {v5, v6}, Low0/s;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    sput-object v5, Low0/s;->d:Low0/s;

    .line 48
    .line 49
    new-instance v6, Low0/s;

    .line 50
    .line 51
    const-string v7, "OPTIONS"

    .line 52
    .line 53
    invoke-direct {v6, v7}, Low0/s;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    sput-object v6, Low0/s;->e:Low0/s;

    .line 57
    .line 58
    filled-new-array/range {v0 .. v6}, [Low0/s;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    sput-object v0, Low0/s;->f:Ljava/util/List;

    .line 67
    .line 68
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Low0/s;->a:Ljava/lang/String;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Low0/s;

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
    check-cast p1, Low0/s;

    .line 12
    .line 13
    iget-object p0, p0, Low0/s;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object p1, p1, Low0/s;->a:Ljava/lang/String;

    .line 16
    .line 17
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    if-nez p0, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    return v0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Low0/s;->a:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Low0/s;->a:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
