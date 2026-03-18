.class public final Lhz0/s1;
.super Lhz0/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljz0/d;


# direct methods
.method public constructor <init>(Ljz0/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lhz0/s1;->a:Ljz0/d;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a()Ljz0/d;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/s1;->a:Ljz0/d;

    .line 2
    .line 3
    return-object p0
.end method

.method public final b()Llz0/c;
    .locals 0

    .line 1
    sget-object p0, Lhz0/u1;->d:Lhz0/k0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final d(Llz0/c;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lhz0/k0;

    .line 2
    .line 3
    const-string p0, "intermediate"

    .line 4
    .line 5
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p1}, Lhz0/k0;->d()Lgz0/d0;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0
.end method
