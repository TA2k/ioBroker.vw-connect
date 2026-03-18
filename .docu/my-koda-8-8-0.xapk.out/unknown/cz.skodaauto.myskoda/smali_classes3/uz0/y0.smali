.class public final Luz0/y0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqz0/a;


# instance fields
.field public final a:Lqz0/a;

.field public final b:Luz0/k1;


# direct methods
.method public constructor <init>(Lqz0/a;)V
    .locals 1

    .line 1
    const-string v0, "serializer"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Luz0/y0;->a:Lqz0/a;

    .line 10
    .line 11
    new-instance v0, Luz0/k1;

    .line 12
    .line 13
    invoke-interface {p1}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    invoke-direct {v0, p1}, Luz0/k1;-><init>(Lsz0/g;)V

    .line 18
    .line 19
    .line 20
    iput-object v0, p0, Luz0/y0;->b:Luz0/k1;

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 1

    .line 1
    invoke-interface {p1}, Ltz0/c;->y()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Luz0/y0;->a:Lqz0/a;

    .line 8
    .line 9
    check-cast p0, Lqz0/a;

    .line 10
    .line 11
    invoke-interface {p1, p0}, Ltz0/c;->d(Lqz0/a;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :cond_0
    const/4 p0, 0x0

    .line 17
    return-object p0
.end method

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
    const/4 v1, 0x0

    .line 6
    if-eqz p1, :cond_3

    .line 7
    .line 8
    const-class v2, Luz0/y0;

    .line 9
    .line 10
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    move-result-object v3

    .line 14
    if-eq v2, v3, :cond_1

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_1
    check-cast p1, Luz0/y0;

    .line 18
    .line 19
    iget-object p0, p0, Luz0/y0;->a:Lqz0/a;

    .line 20
    .line 21
    iget-object p1, p1, Luz0/y0;->a:Lqz0/a;

    .line 22
    .line 23
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    if-nez p0, :cond_2

    .line 28
    .line 29
    return v1

    .line 30
    :cond_2
    return v0

    .line 31
    :cond_3
    :goto_0
    return v1
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Luz0/y0;->b:Luz0/k1;

    .line 2
    .line 3
    return-object p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Luz0/y0;->a:Lqz0/a;

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

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 0

    .line 1
    if-eqz p2, :cond_0

    .line 2
    .line 3
    iget-object p0, p0, Luz0/y0;->a:Lqz0/a;

    .line 4
    .line 5
    check-cast p0, Lqz0/a;

    .line 6
    .line 7
    invoke-interface {p1, p0, p2}, Ltz0/d;->D(Lqz0/a;Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    invoke-interface {p1}, Ltz0/d;->p()V

    .line 12
    .line 13
    .line 14
    return-void
.end method
