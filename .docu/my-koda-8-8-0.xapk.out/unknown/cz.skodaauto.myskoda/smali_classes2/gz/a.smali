.class public abstract Lgz/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkj0/b;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/util/Set;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lgz/a;->a:Ljava/lang/String;

    .line 5
    .line 6
    new-instance p1, Llx0/l;

    .line 7
    .line 8
    const-string v0, "event_category"

    .line 9
    .line 10
    const-string v1, "Rating"

    .line 11
    .line 12
    invoke-direct {p1, v0, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    new-instance v0, Llx0/l;

    .line 16
    .line 17
    const-string v1, "event_owner"

    .line 18
    .line 19
    const-string v2, "mobile"

    .line 20
    .line 21
    invoke-direct {v0, v1, v2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    new-instance v1, Llx0/l;

    .line 25
    .line 26
    const-string v2, "matrix_id"

    .line 27
    .line 28
    const-string v3, "27"

    .line 29
    .line 30
    invoke-direct {v1, v2, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    filled-new-array {p1, v0, v1}, [Llx0/l;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    invoke-static {p1}, Ljp/m1;->g([Ljava/lang/Object;)Ljava/util/Set;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    if-eqz p2, :cond_0

    .line 42
    .line 43
    new-instance v0, Llx0/l;

    .line 44
    .line 45
    const-string v1, "event_action"

    .line 46
    .line 47
    invoke-direct {v0, v1, p2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    invoke-interface {p1, v0}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    :cond_0
    iput-object p1, p0, Lgz/a;->b:Ljava/util/Set;

    .line 54
    .line 55
    return-void
.end method


# virtual methods
.method public final getName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lgz/a;->a:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getParams()Ljava/util/Set;
    .locals 0

    .line 1
    iget-object p0, p0, Lgz/a;->b:Ljava/util/Set;

    .line 2
    .line 3
    return-object p0
.end method
