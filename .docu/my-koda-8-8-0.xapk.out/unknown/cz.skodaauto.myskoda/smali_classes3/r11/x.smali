.class public final Lr11/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lr11/w;


# instance fields
.field public final d:Lr11/w;


# direct methods
.method public constructor <init>(Lr11/w;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lr11/x;->d:Lr11/w;

    .line 5
    .line 6
    return-void
.end method

.method public static b(Lr11/w;)Lr11/x;
    .locals 1

    .line 1
    instance-of v0, p0, Lr11/t;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p0, Lr11/t;

    .line 6
    .line 7
    iget-object p0, p0, Lr11/t;->d:Lr11/x;

    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    instance-of v0, p0, Lr11/x;

    .line 11
    .line 12
    if-eqz v0, :cond_1

    .line 13
    .line 14
    check-cast p0, Lr11/x;

    .line 15
    .line 16
    return-object p0

    .line 17
    :cond_1
    if-nez p0, :cond_2

    .line 18
    .line 19
    const/4 p0, 0x0

    .line 20
    return-object p0

    .line 21
    :cond_2
    new-instance v0, Lr11/x;

    .line 22
    .line 23
    invoke-direct {v0, p0}, Lr11/x;-><init>(Lr11/w;)V

    .line 24
    .line 25
    .line 26
    return-object v0
.end method


# virtual methods
.method public final a()I
    .locals 0

    .line 1
    iget-object p0, p0, Lr11/x;->d:Lr11/w;

    .line 2
    .line 3
    invoke-interface {p0}, Lr11/w;->a()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final d(Lr11/s;Ljava/lang/CharSequence;I)I
    .locals 0

    .line 1
    iget-object p0, p0, Lr11/x;->d:Lr11/w;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2, p3}, Lr11/w;->d(Lr11/s;Ljava/lang/CharSequence;I)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    if-ne p1, p0, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    return p0

    .line 5
    :cond_0
    instance-of v0, p1, Lr11/x;

    .line 6
    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    check-cast p1, Lr11/x;

    .line 10
    .line 11
    iget-object p0, p0, Lr11/x;->d:Lr11/w;

    .line 12
    .line 13
    iget-object p1, p1, Lr11/x;->d:Lr11/w;

    .line 14
    .line 15
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    :cond_1
    const/4 p0, 0x0

    .line 21
    return p0
.end method
