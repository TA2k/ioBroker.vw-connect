.class public final Lm2/o;
.super Lm2/j0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final c:Lm2/o;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lm2/o;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    invoke-direct {v0, v1, v2, v2}, Lm2/j0;-><init>(III)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lm2/o;->c:Lm2/o;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Landroidx/collection/h;Ll2/c;Ll2/i2;Ljp/uf;Lm2/k0;)V
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    invoke-virtual {p1, p0}, Landroidx/collection/h;->g(I)Ljava/lang/Object;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    check-cast p0, Ll2/u1;

    .line 7
    .line 8
    iget-object p1, p4, Ljp/uf;->h:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p1, Landroidx/collection/q0;

    .line 11
    .line 12
    if-eqz p1, :cond_1

    .line 13
    .line 14
    invoke-virtual {p1, p0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p2

    .line 18
    check-cast p2, Lt2/e;

    .line 19
    .line 20
    if-eqz p2, :cond_1

    .line 21
    .line 22
    iget-object p2, p4, Ljp/uf;->i:Ljava/io/Serializable;

    .line 23
    .line 24
    check-cast p2, Ljava/util/ArrayList;

    .line 25
    .line 26
    if-eqz p2, :cond_0

    .line 27
    .line 28
    invoke-virtual {p2}, Ljava/util/ArrayList;->size()I

    .line 29
    .line 30
    .line 31
    move-result p3

    .line 32
    add-int/lit8 p3, p3, -0x1

    .line 33
    .line 34
    invoke-virtual {p2, p3}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p2

    .line 38
    check-cast p2, Ln2/b;

    .line 39
    .line 40
    if-eqz p2, :cond_0

    .line 41
    .line 42
    iput-object p2, p4, Ljp/uf;->e:Ljava/lang/Object;

    .line 43
    .line 44
    :cond_0
    invoke-virtual {p1, p0}, Landroidx/collection/q0;->k(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    :cond_1
    return-void
.end method
