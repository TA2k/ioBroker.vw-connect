.class public final Lt2/g;
.super Lq2/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll2/p1;


# static fields
.field public static final g:Lt2/g;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lt2/g;

    .line 2
    .line 3
    sget-object v1, Lq2/i;->e:Lq2/i;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lq2/b;-><init>(Lq2/i;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lt2/g;->g:Lt2/g;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final bridge containsKey(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Ll2/s1;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return p0

    .line 7
    :cond_0
    check-cast p1, Ll2/s1;

    .line 8
    .line 9
    invoke-super {p0, p1}, Lq2/b;->containsKey(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final bridge containsValue(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Ll2/w2;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return p0

    .line 7
    :cond_0
    check-cast p1, Ll2/w2;

    .line 8
    .line 9
    invoke-super {p0, p1}, Lmx0/f;->containsValue(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final f(Ll2/s1;Ll2/w2;)Lt2/g;
    .locals 3

    .line 1
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    iget-object v2, p0, Lq2/b;->d:Lq2/i;

    .line 7
    .line 8
    invoke-virtual {v2, v0, v1, p1, p2}, Lq2/i;->u(IILjava/lang/Object;Ljava/lang/Object;)Lb11/a;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    if-nez p1, :cond_0

    .line 13
    .line 14
    return-object p0

    .line 15
    :cond_0
    new-instance p2, Lt2/g;

    .line 16
    .line 17
    iget-object v0, p1, Lb11/a;->f:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v0, Lq2/i;

    .line 20
    .line 21
    iget p0, p0, Lq2/b;->e:I

    .line 22
    .line 23
    iget p1, p1, Lb11/a;->e:I

    .line 24
    .line 25
    add-int/2addr p0, p1

    .line 26
    invoke-direct {p2, v0, p0}, Lq2/b;-><init>(Lq2/i;I)V

    .line 27
    .line 28
    .line 29
    return-object p2
.end method

.method public final bridge get(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    instance-of v0, p1, Ll2/s1;

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
    check-cast p1, Ll2/s1;

    .line 8
    .line 9
    invoke-super {p0, p1}, Lq2/b;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ll2/w2;

    .line 14
    .line 15
    return-object p0
.end method

.method public final bridge getOrDefault(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    instance-of v0, p1, Ll2/s1;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    return-object p2

    .line 6
    :cond_0
    check-cast p1, Ll2/s1;

    .line 7
    .line 8
    check-cast p2, Ll2/w2;

    .line 9
    .line 10
    invoke-super {p0, p1, p2}, Ljava/util/Map;->getOrDefault(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ll2/w2;

    .line 15
    .line 16
    return-object p0
.end method
