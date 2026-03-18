.class public final Lrn/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lon/f;


# instance fields
.field public final a:Ljava/util/Set;

.field public final b:Lrn/j;

.field public final c:Lrn/r;


# direct methods
.method public constructor <init>(Ljava/util/Set;Lrn/j;Lrn/r;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lrn/p;->a:Ljava/util/Set;

    .line 5
    .line 6
    iput-object p2, p0, Lrn/p;->b:Lrn/j;

    .line 7
    .line 8
    iput-object p3, p0, Lrn/p;->c:Lrn/r;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;Lon/c;Lon/e;)Lrn/q;
    .locals 8

    .line 1
    iget-object v0, p0, Lrn/p;->a:Ljava/util/Set;

    .line 2
    .line 3
    invoke-interface {v0, p2}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    new-instance v2, Lrn/q;

    .line 10
    .line 11
    iget-object v3, p0, Lrn/p;->b:Lrn/j;

    .line 12
    .line 13
    iget-object v7, p0, Lrn/p;->c:Lrn/r;

    .line 14
    .line 15
    move-object v4, p1

    .line 16
    move-object v5, p2

    .line 17
    move-object v6, p3

    .line 18
    invoke-direct/range {v2 .. v7}, Lrn/q;-><init>(Lrn/j;Ljava/lang/String;Lon/c;Lon/e;Lrn/r;)V

    .line 19
    .line 20
    .line 21
    return-object v2

    .line 22
    :cond_0
    move-object v5, p2

    .line 23
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 24
    .line 25
    const-string p1, "%s is not supported byt this factory. Supported encodings are: %s."

    .line 26
    .line 27
    filled-new-array {v5, v0}, [Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p2

    .line 31
    invoke-static {p1, p2}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw p0
.end method
