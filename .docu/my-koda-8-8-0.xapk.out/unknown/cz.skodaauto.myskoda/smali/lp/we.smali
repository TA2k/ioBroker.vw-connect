.class public final Llp/we;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Llp/ve;


# direct methods
.method public synthetic constructor <init>(Lh6/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iget-object p1, p1, Lh6/e;->e:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast p1, Llp/ve;

    .line 7
    .line 8
    iput-object p1, p0, Llp/we;->a:Llp/ve;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p1, p0, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Llp/we;

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
    check-cast p1, Llp/we;

    .line 12
    .line 13
    iget-object p0, p0, Llp/we;->a:Llp/ve;

    .line 14
    .line 15
    iget-object p1, p1, Llp/we;->a:Llp/ve;

    .line 16
    .line 17
    invoke-static {p0, p1}, Lno/c0;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    if-eqz p0, :cond_2

    .line 22
    .line 23
    const/4 p0, 0x0

    .line 24
    invoke-static {p0, p0}, Lno/c0;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result p1

    .line 28
    if-eqz p1, :cond_2

    .line 29
    .line 30
    invoke-static {p0, p0}, Lno/c0;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    if-eqz p0, :cond_2

    .line 35
    .line 36
    return v0

    .line 37
    :cond_2
    return v2
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget-object p0, p0, Llp/we;->a:Llp/ve;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    filled-new-array {p0, v0, v0}, [Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    invoke-static {p0}, Ljava/util/Arrays;->hashCode([Ljava/lang/Object;)I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method
