.class public final Lrg/d;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lkg/p0;

.field public final e:Lyj/b;

.field public final f:Lxh/e;

.field public final g:Lh2/d6;

.field public final h:Lyy0/c2;


# direct methods
.method public constructor <init>(Lkg/p0;Lyj/b;Lxh/e;Lh2/d6;)V
    .locals 1

    .line 1
    const-string v0, "tariff"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lrg/d;->d:Lkg/p0;

    .line 10
    .line 11
    iput-object p2, p0, Lrg/d;->e:Lyj/b;

    .line 12
    .line 13
    iput-object p3, p0, Lrg/d;->f:Lxh/e;

    .line 14
    .line 15
    iput-object p4, p0, Lrg/d;->g:Lh2/d6;

    .line 16
    .line 17
    const/4 p2, 0x1

    .line 18
    invoke-static {p1, p2}, Llp/p1;->d(Lkg/p0;Z)Lug/b;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    iput-object p1, p0, Lrg/d;->h:Lyy0/c2;

    .line 27
    .line 28
    return-void
.end method
