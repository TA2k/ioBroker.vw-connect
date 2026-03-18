.class public final Lhu/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lgt/b;


# direct methods
.method public constructor <init>(Lgt/b;)V
    .locals 1

    .line 1
    const-string v0, "transportFactoryProvider"

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
    iput-object p1, p0, Lhu/l;->a:Lgt/b;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final a(Lhu/k0;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lhu/l;->a:Lgt/b;

    .line 2
    .line 3
    invoke-interface {v0}, Lgt/b;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lon/f;

    .line 8
    .line 9
    new-instance v1, Lon/c;

    .line 10
    .line 11
    const-string v2, "json"

    .line 12
    .line 13
    invoke-direct {v1, v2}, Lon/c;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    new-instance v2, Lf3/d;

    .line 17
    .line 18
    invoke-direct {v2, p0}, Lf3/d;-><init>(Lhu/l;)V

    .line 19
    .line 20
    .line 21
    check-cast v0, Lrn/p;

    .line 22
    .line 23
    const-string p0, "FIREBASE_APPQUALITY_SESSION"

    .line 24
    .line 25
    invoke-virtual {v0, p0, v1, v2}, Lrn/p;->a(Ljava/lang/String;Lon/c;Lon/e;)Lrn/q;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    new-instance v0, Lon/a;

    .line 30
    .line 31
    sget-object v1, Lon/d;->d:Lon/d;

    .line 32
    .line 33
    const/4 v2, 0x0

    .line 34
    invoke-direct {v0, p1, v1, v2}, Lon/a;-><init>(Ljava/lang/Object;Lon/d;Lon/b;)V

    .line 35
    .line 36
    .line 37
    new-instance p1, Lj9/d;

    .line 38
    .line 39
    const/16 v1, 0x19

    .line 40
    .line 41
    invoke-direct {p1, v1}, Lj9/d;-><init>(I)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {p0, v0, p1}, Lrn/q;->a(Lon/a;Lon/g;)V

    .line 45
    .line 46
    .line 47
    return-void
.end method
