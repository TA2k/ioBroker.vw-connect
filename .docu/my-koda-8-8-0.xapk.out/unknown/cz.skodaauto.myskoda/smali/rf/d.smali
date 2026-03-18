.class public final Lrf/d;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Ljava/lang/String;

.field public final e:Luf/n;

.field public final f:Ljd/b;

.field public final g:Ljd/b;

.field public final h:Ljd/b;

.field public final i:Lyj/b;

.field public final j:Lyy0/c2;

.field public final k:Lyy0/c2;

.field public l:Z


# direct methods
.method public constructor <init>(Ljava/lang/String;Luf/n;Ljd/b;Ljd/b;Ljd/b;Lyj/b;)V
    .locals 1

    .line 1
    const-string v0, "vin"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "plugAndChargeStatus"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lrf/d;->d:Ljava/lang/String;

    .line 15
    .line 16
    iput-object p2, p0, Lrf/d;->e:Luf/n;

    .line 17
    .line 18
    iput-object p3, p0, Lrf/d;->f:Ljd/b;

    .line 19
    .line 20
    iput-object p4, p0, Lrf/d;->g:Ljd/b;

    .line 21
    .line 22
    iput-object p5, p0, Lrf/d;->h:Ljd/b;

    .line 23
    .line 24
    iput-object p6, p0, Lrf/d;->i:Lyj/b;

    .line 25
    .line 26
    new-instance p1, Lrf/b;

    .line 27
    .line 28
    const/4 p2, 0x0

    .line 29
    invoke-direct {p1, p2}, Lrf/b;-><init>(Z)V

    .line 30
    .line 31
    .line 32
    new-instance p2, Llc/q;

    .line 33
    .line 34
    invoke-direct {p2, p1}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    iput-object p1, p0, Lrf/d;->j:Lyy0/c2;

    .line 42
    .line 43
    iput-object p1, p0, Lrf/d;->k:Lyy0/c2;

    .line 44
    .line 45
    return-void
.end method
