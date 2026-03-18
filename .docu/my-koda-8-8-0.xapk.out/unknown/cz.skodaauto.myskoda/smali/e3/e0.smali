.class public final Le3/e0;
.super Le3/g0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ld3/c;


# direct methods
.method public constructor <init>(Ld3/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Le3/e0;->a:Ld3/c;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a()Ld3/c;
    .locals 0

    .line 1
    iget-object p0, p0, Le3/e0;->a:Ld3/c;

    .line 2
    .line 3
    return-object p0
.end method

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
    instance-of v1, p1, Le3/e0;

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
    check-cast p1, Le3/e0;

    .line 12
    .line 13
    iget-object p1, p1, Le3/e0;->a:Ld3/c;

    .line 14
    .line 15
    iget-object p0, p0, Le3/e0;->a:Ld3/c;

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
    iget-object p0, p0, Le3/e0;->a:Ld3/c;

    .line 2
    .line 3
    invoke-virtual {p0}, Ld3/c;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
