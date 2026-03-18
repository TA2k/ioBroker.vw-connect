.class public final Lm2/x;
.super Lm2/j0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final c:Lm2/x;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lm2/x;

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
    sput-object v0, Lm2/x;->c:Lm2/x;

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
    iget-object p1, p4, Ljp/uf;->a:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p1, Ljava/util/Set;

    .line 11
    .line 12
    if-nez p1, :cond_0

    .line 13
    .line 14
    return-void

    .line 15
    :cond_0
    new-instance p2, Lt2/e;

    .line 16
    .line 17
    invoke-direct {p2, p1}, Lt2/e;-><init>(Ljava/util/Set;)V

    .line 18
    .line 19
    .line 20
    iget-object p1, p4, Ljp/uf;->h:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast p1, Landroidx/collection/q0;

    .line 23
    .line 24
    if-nez p1, :cond_1

    .line 25
    .line 26
    sget-object p1, Landroidx/collection/y0;->a:[J

    .line 27
    .line 28
    new-instance p1, Landroidx/collection/q0;

    .line 29
    .line 30
    invoke-direct {p1}, Landroidx/collection/q0;-><init>()V

    .line 31
    .line 32
    .line 33
    iput-object p1, p4, Ljp/uf;->h:Ljava/lang/Object;

    .line 34
    .line 35
    :cond_1
    invoke-virtual {p1, p0, p2}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    iget-object p0, p4, Ljp/uf;->e:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast p0, Ln2/b;

    .line 41
    .line 42
    new-instance p1, Ll2/a2;

    .line 43
    .line 44
    const/4 p3, 0x0

    .line 45
    invoke-direct {p1, p2, p3}, Ll2/a2;-><init>(Ll2/z1;Ll2/a;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p0, p1}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    return-void
.end method
